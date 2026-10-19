//! Control-plane startup, HTTP routing, and the enrollment/revocation flow.

use crate::metrics::Metrics;
use crate::store::{NodeRecord, Store};
use crate::tls::{self, TrustMaterial};
use crate::ServerArgs;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use fleet_pki::{Ca, CrlStore, IssuedCert, LeafIdentity, LeafSpec, LeafUsage};
use fleet_proto::{
    ApiError, ChallengeResponse, CreateTokenRequest, CreateTokenResponse, EnrollRequest,
    EnrollResponse, HeartbeatRequest, HeartbeatResponse, NodeSummary, NodesResponse, RenewRequest,
    RevokeRequest, WhoAmI,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use rand::RngCore;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

/// Runtime configuration for an embedded control plane (tests and fleetd).
#[derive(Debug, Clone)]
pub struct ControlConfig {
    pub state_dir: PathBuf,
    pub listen: SocketAddr,
    pub enroll_listen: SocketAddr,
    pub operator_listen: SocketAddr,
    pub token_key: Option<PathBuf>,
    pub site: String,
}

impl ControlConfig {
    pub fn from_args(args: &ServerArgs) -> Self {
        Self {
            state_dir: args.state_dir.clone(),
            listen: args.listen,
            enroll_listen: args.enroll_listen,
            operator_listen: args.operator_listen,
            token_key: args.token_key.clone(),
            site: "dc1".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Challenge {
    nonce: String,
    expires_at: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub ca: Arc<Mutex<Ca>>,
    pub crl: Arc<RwLock<CrlStore>>,
    pub metrics: Arc<Metrics>,
    pub trust: Arc<TrustMaterial>,
    pub challenges: Arc<Mutex<BTreeMap<String, Challenge>>>,
    pub site: String,
}

/// A running control plane. Drop the value or call [`shutdown`](Self::shutdown)
/// to stop all listeners.
pub struct RunningControlPlane {
    pub mtls_addr: SocketAddr,
    pub enroll_addr: SocketAddr,
    pub operator_addr: SocketAddr,
    pub ca_pem: String,
    pub state: AppState,
    tx: watch::Sender<bool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl RunningControlPlane {
    pub async fn shutdown(mut self) {
        let _ = self.tx.send(true);
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }
}

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

pub async fn start(config: ControlConfig) -> anyhow::Result<RunningControlPlane> {
    install_crypto_provider();
    std::fs::create_dir_all(&config.state_dir)?;

    let mut ca = Ca::load(&config.state_dir).map_err(|e| {
        anyhow::anyhow!(
            "CA not initialized in {} ({e}); run `fleetctl --state-dir {} ca init`",
            config.state_dir.display(),
            config.state_dir.display()
        )
    })?;
    let trust = Arc::new(TrustMaterial::from_pem(&ca.trust_bundle_pem())?);
    let crl = Arc::new(RwLock::new(ca.crl_store()?));
    let store = Store::load(&config.state_dir, config.token_key.as_deref())?;
    let metrics = Arc::new(Metrics::new());

    let (server_chain, server_key) = ensure_server_cert(&mut ca, &config.state_dir, &config.site)?;
    let mtls_config = tls::mtls_server_config(
        trust.clone(),
        crl.clone(),
        metrics.clone(),
        server_chain.clone(),
        server_key.clone_key(),
    )?;
    let operator_config = tls::mtls_server_config(
        trust.clone(),
        crl.clone(),
        metrics.clone(),
        server_chain.clone(),
        server_key.clone_key(),
    )?;
    let enroll_config = tls::server_auth_config(server_chain, server_key)?;

    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        ca: Arc::new(Mutex::new(ca)),
        crl,
        metrics,
        trust: trust.clone(),
        challenges: Arc::new(Mutex::new(BTreeMap::new())),
        site: config.site.clone(),
    };

    let mtls_app = node_router(state.clone());
    let enroll_app = enroll_router(state.clone());
    let operator_app = operator_router(state.clone());

    let mtls_listener = TcpListener::bind(config.listen).await?;
    let enroll_listener = TcpListener::bind(config.enroll_listen).await?;
    let operator_listener = TcpListener::bind(config.operator_listen).await?;
    let mtls_addr = mtls_listener.local_addr()?;
    let enroll_addr = enroll_listener.local_addr()?;
    let operator_addr = operator_listener.local_addr()?;

    let (tx, rx) = watch::channel(false);
    let handles = vec![
        tokio::spawn(serve_tls(
            mtls_listener,
            TlsAcceptor::from(mtls_config),
            mtls_app,
            true,
            state.metrics.clone(),
            rx.clone(),
        )),
        tokio::spawn(serve_tls(
            enroll_listener,
            TlsAcceptor::from(enroll_config),
            enroll_app,
            false,
            state.metrics.clone(),
            rx.clone(),
        )),
        tokio::spawn(serve_tls(
            operator_listener,
            TlsAcceptor::from(operator_config),
            operator_app,
            true,
            state.metrics.clone(),
            rx,
        )),
    ];

    info!(%mtls_addr, %enroll_addr, %operator_addr, "control plane listening");
    Ok(RunningControlPlane {
        mtls_addr,
        enroll_addr,
        operator_addr,
        ca_pem: trust.pem.clone(),
        state,
        tx,
        handles,
    })
}

fn ensure_server_cert(
    ca: &mut Ca,
    state_dir: &FsPath,
    site: &str,
) -> anyhow::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let dir = state_dir.join("server");
    std::fs::create_dir_all(&dir)?;
    let cert_path = dir.join("fleetd.crt.pem");
    let key_path = dir.join("fleetd.key.pem");
    let chain_path = dir.join("fleetd-chain.pem");
    if cert_path.exists() && key_path.exists() && chain_path.exists() {
        let chain = tls::pem_certs(&std::fs::read_to_string(&chain_path)?)?;
        let key = tls::pem_private_key(&std::fs::read_to_string(&key_path)?)?;
        return Ok((chain, key));
    }
    let spec = LeafSpec::for_node(site, "fleetd")
        .with_usage(LeafUsage::Server)
        .with_hostname("fleetd")
        .with_extra_dns("localhost")
        .with_extra_ip("127.0.0.1")
        .with_extra_ip("::1");
    let issued = ca.issue_leaf(&spec)?;
    let key = issued
        .key_pem
        .clone()
        .ok_or_else(|| anyhow::anyhow!("CA did not return a server key"))?;
    std::fs::write(&cert_path, &issued.cert_pem)?;
    std::fs::write(&chain_path, &issued.chain_pem)?;
    std::fs::write(&key_path, &key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok((
        tls::pem_certs(&issued.chain_pem)?,
        tls::pem_private_key(&key)?,
    ))
}

fn node_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/whoami", get(whoami))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/renew", post(renew_self))
        .route("/v1/crl", get(crl))
        .with_state(state)
}

fn enroll_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/attest/challenge", post(challenge))
        .route("/v1/enroll", post(enroll))
        .with_state(state)
}

fn operator_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/tokens", post(create_token))
        .route("/v1/nodes", get(list_nodes))
        .route("/v1/nodes/{node_id}", get(describe_node))
        .route("/v1/nodes/{node_id}/revoke", post(revoke_node))
        .route("/v1/nodes/{node_id}/renew", post(renew_node_admin))
        .with_state(state)
}

async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router,
    peer_auth: bool,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (tcp, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        warn!(error = %err, "tcp accept failed");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    match acceptor.accept(tcp).await {
                        Ok(stream) => {
                            let identity = if peer_auth {
                                tls::peer_from_certs(
                                    stream.get_ref().1.peer_certificates(),
                                )
                            } else {
                                None
                            };
                            let router = app.layer(Extension(identity));
                            let service = TowerToHyperService::new(router);
                            let io = TokioIo::new(stream);
                            if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                                TokioExecutor::new(),
                            )
                            .serve_connection_with_upgrades(io, service)
                            .await
                            {
                                let _ = err;
                            }
                        }
                        Err(err) => {
                            if err.to_string().contains("peer sent no certificates") {
                                metrics.handshake_failure("no_client_cert");
                            }
                            warn!(error = %err, "tls handshake rejected");
                        }
                    }
                });
            }
        }
    }
}

#[derive(Debug)]
struct ApiFailure {
    status: StatusCode,
    body: ApiError,
}

impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

fn failure(status: StatusCode, code: &str, message: impl Into<String>) -> ApiFailure {
    ApiFailure {
        status,
        body: ApiError::new(code, message),
    }
}

fn require_operator(peer: &Option<LeafIdentity>) -> Result<LeafIdentity, ApiFailure> {
    let identity = peer.clone().ok_or_else(|| {
        failure(
            StatusCode::UNAUTHORIZED,
            "no_identity",
            "client cert required",
        )
    })?;
    if !identity.node_id.starts_with("operator-") {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "machine_credential",
            "node certificates cannot call operator endpoints",
        ));
    }
    Ok(identity)
}

fn require_node(peer: &Option<LeafIdentity>, node_id: &str) -> Result<LeafIdentity, ApiFailure> {
    let identity = peer.clone().ok_or_else(|| {
        failure(
            StatusCode::UNAUTHORIZED,
            "no_identity",
            "client cert required",
        )
    })?;
    if identity.node_id.starts_with("operator-") {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "operator_credential",
            "operator identities cannot call node endpoints",
        ));
    }
    if identity.node_id != node_id {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "identity_mismatch",
            format!(
                "certificate identity {} does not match request identity {node_id}",
                identity.node_id
            ),
        ));
    }
    Ok(identity)
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let crl_number = state
        .crl
        .read()
        .expect("crl lock poisoned")
        .crl()
        .crl_number();
    Json(serde_json::json!({
        "status": "ok",
        "crl_number": crl_number,
        "challenge_count": state.challenges.lock().await.len(),
    }))
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let expiries = state.store.lock().await.expiries();
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(&expiries),
    )
}

async fn whoami(
    State(_state): State<AppState>,
    Extension(peer): Extension<Option<LeafIdentity>>,
) -> Result<Json<WhoAmI>, ApiFailure> {
    let identity = peer.ok_or_else(|| {
        failure(
            StatusCode::UNAUTHORIZED,
            "no_identity",
            "client cert required",
        )
    })?;
    if identity.node_id.starts_with("operator-") {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "operator_credential",
            "operator identities cannot call node endpoints",
        ));
    }
    Ok(Json(WhoAmI {
        node_id: identity.node_id,
        site: identity.site,
        hostname: identity.hostname,
        serial_hex: identity.serial_hex,
        role: "node".into(),
    }))
}

async fn crl(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.crl.read().expect("crl lock poisoned");
    (
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        store.to_pem(),
    )
}

async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<fleet_proto::ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiFailure> {
    let store = state.store.lock().await;
    let payload = store
        .tokens
        .peek(&req.token)
        .map_err(|e| token_failure(&e))?;
    drop(store);

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let nonce = hex::encode(bytes);
    let expires_at = crate::unix_now() + 300;
    state.challenges.lock().await.insert(
        payload.id.clone(),
        Challenge {
            nonce: nonce.clone(),
            expires_at,
        },
    );
    Ok(Json(ChallengeResponse { nonce, expires_at }))
}

fn token_failure(err: &crate::tokens::TokenError) -> ApiFailure {
    use crate::tokens::TokenError::*;
    match err {
        Replayed => failure(
            StatusCode::CONFLICT,
            "token_replayed",
            "bootstrap token has already been used",
        ),
        Expired => failure(
            StatusCode::UNAUTHORIZED,
            "token_expired",
            "bootstrap token has expired",
        ),
        InvalidSignature => failure(
            StatusCode::UNAUTHORIZED,
            "token_invalid_signature",
            "bootstrap token signature is invalid",
        ),
        Unknown => failure(
            StatusCode::UNAUTHORIZED,
            "token_unknown",
            "bootstrap token is not known to this control plane",
        ),
        IdentityMismatch => failure(
            StatusCode::FORBIDDEN,
            "token_identity_mismatch",
            "bootstrap token was issued for another node",
        ),
        Malformed => failure(
            StatusCode::BAD_REQUEST,
            "token_malformed",
            "bootstrap token is malformed",
        ),
        Io(_) | Json(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "token_store_error",
            "bootstrap token store failed",
        ),
    }
}

async fn enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiFailure> {
    if req.node_id.starts_with("operator-") {
        state.metrics.rejection("reserved_identity");
        return Err(failure(
            StatusCode::FORBIDDEN,
            "reserved_identity",
            "operator- prefix is reserved for human identities",
        ));
    }

    let mut store = state.store.lock().await;
    let payload = match store.tokens.peek(&req.token) {
        Ok(payload) => payload,
        Err(err) => {
            state.metrics.rejection(token_reason(&err));
            return Err(token_failure(&err));
        }
    };
    if payload.node_id != req.node_id || payload.site != req.site {
        state.metrics.rejection("identity_mismatch");
        return Err(failure(
            StatusCode::FORBIDDEN,
            "token_identity_mismatch",
            "token does not match the requested node identity",
        ));
    }
    if let Some(existing) = store.get(&req.node_id) {
        if existing.state == fleet_proto::NodeState::Revoked {
            state.metrics.rejection("revoked");
            return Err(failure(
                StatusCode::FORBIDDEN,
                "node_revoked",
                "revoked nodes cannot re-enroll with the same identity",
            ));
        }
    }

    // Step 4 replaces this with full attestation evaluation. Until then the
    // nonce binding is still enforced when a challenge was requested.
    if let Some(nonce) = req.attestation.get("nonce").and_then(|v| v.as_str()) {
        let challenges = state.challenges.lock().await;
        match challenges.get(&payload.id) {
            Some(challenge)
                if challenge.nonce == nonce && challenge.expires_at > crate::unix_now() => {}
            Some(_) => {
                state.metrics.rejection("nonce_mismatch");
                return Err(failure(
                    StatusCode::FORBIDDEN,
                    "nonce_mismatch",
                    "attestation nonce does not match the issued challenge",
                ));
            }
            None => {
                state.metrics.rejection("missing_challenge");
                return Err(failure(
                    StatusCode::FORBIDDEN,
                    "missing_challenge",
                    "no attestation challenge was issued for this token",
                ));
            }
        }
    }

    let mut record = store
        .get(&req.node_id)
        .cloned()
        .unwrap_or_else(|| NodeRecord::pending(&req.node_id, &req.site, &req.hostname));
    record.hostname = req.hostname.clone();
    if record.state != fleet_proto::NodeState::Enrolled {
        record.state = fleet_proto::NodeState::Attested;
    }
    record.attestation_passed = true;
    record.violations.clear();
    if let Err(err) = store.upsert(record.clone()) {
        return Err(failure(
            StatusCode::CONFLICT,
            "state_transition",
            err.to_string(),
        ));
    }
    drop(store);

    let spec = LeafSpec::for_node(req.site.clone(), req.node_id.clone())
        .with_hostname(req.hostname.clone())
        .with_csr(req.csr_pem.clone());
    let issued = {
        let mut ca = state.ca.lock().await;
        match ca.issue_leaf(&spec) {
            Ok(issued) => issued,
            Err(err) => {
                state.metrics.rejection("csr_invalid");
                return Err(failure(
                    StatusCode::BAD_REQUEST,
                    "csr_invalid",
                    format!("certificate issuance failed: {err}"),
                ));
            }
        }
    };

    let mut store = state.store.lock().await;
    record.state = fleet_proto::NodeState::Enrolled;
    record.serial_hex = Some(issued.serial_hex.clone());
    record.cert_pem = Some(issued.cert_pem.clone());
    record.not_after = Some(issued.identity.not_after);
    record.vlan = Some(666);
    record.last_seen = crate::unix_now();
    if let Err(err) = store.upsert(record.clone()) {
        return Err(failure(
            StatusCode::CONFLICT,
            "state_transition",
            err.to_string(),
        ));
    }
    store.tokens.consume(&payload.id);
    if let Err(err) = store.save() {
        return Err(failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_persist",
            err.to_string(),
        ));
    }
    state.challenges.lock().await.remove(&payload.id);
    drop(store);
    state.metrics.enrollment_ok();
    info!(node_id = %req.node_id, serial = %issued.serial_hex, "node enrolled");
    Ok(Json(enroll_response(&state, &req, issued)))
}

fn token_reason(err: &crate::tokens::TokenError) -> &'static str {
    use crate::tokens::TokenError::*;
    match err {
        Replayed => "token_replayed",
        Expired => "token_expired",
        InvalidSignature => "token_invalid_signature",
        Unknown => "token_unknown",
        IdentityMismatch => "token_identity_mismatch",
        Malformed => "token_malformed",
        Io(_) | Json(_) => "token_store_error",
    }
}

fn enroll_response(state: &AppState, req: &EnrollRequest, issued: IssuedCert) -> EnrollResponse {
    EnrollResponse {
        node_id: req.node_id.clone(),
        state: fleet_proto::NodeState::Enrolled,
        cert_pem: issued.cert_pem,
        chain_pem: issued.chain_pem,
        trust_bundle_pem: state.trust.pem.clone(),
        serial_hex: issued.serial_hex,
        not_after: issued.identity.not_after,
    }
}

async fn heartbeat(
    State(state): State<AppState>,
    Extension(peer): Extension<Option<LeafIdentity>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiFailure> {
    require_node(&peer, &req.node_id)?;
    let crl_number = state
        .crl
        .read()
        .expect("crl lock poisoned")
        .crl()
        .crl_number();
    let mut store = state.store.lock().await;
    let record = store
        .get(&req.node_id)
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "not_found", "unknown node"))?
        .clone();
    if record.state == fleet_proto::NodeState::Revoked {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "node_revoked",
            "node is revoked",
        ));
    }
    store
        .touch(&req.node_id)
        .map_err(|e| failure(StatusCode::INTERNAL_SERVER_ERROR, "state", e.to_string()))?;
    state.metrics.heartbeat();
    Ok(Json(HeartbeatResponse {
        ok: true,
        server_time: crate::unix_now(),
        crl_number,
        state: record.state,
    }))
}

async fn renew_self(
    State(state): State<AppState>,
    Extension(peer): Extension<Option<LeafIdentity>>,
    Json(req): Json<RenewRequest>,
) -> Result<Json<EnrollResponse>, ApiFailure> {
    let identity = peer.clone().ok_or_else(|| {
        failure(
            StatusCode::UNAUTHORIZED,
            "no_identity",
            "client cert required",
        )
    })?;
    if identity.node_id.starts_with("operator-") {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "operator_credential",
            "operator identities cannot renew node certificates",
        ));
    }
    let response = renew_for(&state, &identity.node_id, &req.csr_pem).await?;
    state.metrics.renewal();
    Ok(Json(response))
}

async fn renew_for(
    state: &AppState,
    node_id: &str,
    csr_pem: &str,
) -> Result<EnrollResponse, ApiFailure> {
    let store = state.store.lock().await;
    let mut record = store
        .get(node_id)
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "not_found", "unknown node"))?
        .clone();
    if record.state == fleet_proto::NodeState::Revoked {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "node_revoked",
            "revoked nodes cannot renew",
        ));
    }
    let old_serial = record.serial_hex.clone();
    drop(store);

    let spec = LeafSpec::for_node(record.site.clone(), record.node_id.clone())
        .with_hostname(record.hostname.clone())
        .with_csr(csr_pem.to_string());
    let issued = {
        let mut ca = state.ca.lock().await;
        let issued = ca
            .issue_leaf(&spec)
            .map_err(|e| failure(StatusCode::BAD_REQUEST, "csr_invalid", e.to_string()))?;
        if let Some(old) = &old_serial {
            let _ = ca.revoke(old, "superseded");
        }
        issued
    };
    {
        let ca = state.ca.lock().await;
        let store = ca
            .crl_store()
            .map_err(|e| failure(StatusCode::INTERNAL_SERVER_ERROR, "crl", e.to_string()))?;
        *state.crl.write().expect("crl lock poisoned") = store;
    }

    record.serial_hex = Some(issued.serial_hex.clone());
    record.cert_pem = Some(issued.cert_pem.clone());
    record.not_after = Some(issued.identity.not_after);
    record.renewal_count += 1;
    record.updated_at = crate::unix_now();
    let mut store = state.store.lock().await;
    store
        .upsert(record.clone())
        .map_err(|e| failure(StatusCode::CONFLICT, "state", e.to_string()))?;
    info!(node_id = %record.node_id, serial = %issued.serial_hex, "certificate renewed");
    Ok(EnrollResponse {
        node_id: record.node_id.clone(),
        state: record.state,
        cert_pem: issued.cert_pem,
        chain_pem: issued.chain_pem,
        trust_bundle_pem: state.trust.pem.clone(),
        serial_hex: issued.serial_hex,
        not_after: issued.identity.not_after,
    })
}

async fn create_token(
    State(state): State<AppState>,
    Extension(peer): Extension<Option<LeafIdentity>>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, ApiFailure> {
    require_operator(&peer)?;
    if req.node_id.starts_with("operator-") {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "reserved_identity",
            "operator- prefix is reserved",
        ));
    }
    let ttl = req.ttl_seconds.clamp(30, 86_400);
    let mut store = state.store.lock().await;
    let (token, expires_at) = store.tokens.issue(&req.node_id, &req.site, ttl);
    store.tokens.save().map_err(|e| {
        failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "token_store",
            e.to_string(),
        )
    })?;
    Ok(Json(CreateTokenResponse {
        token,
        node_id: req.node_id,
        site: req.site,
        expires_at,
    }))
}

async fn list_nodes(
    State(state): State<AppState>,
    Extension(peer): Extension<Option<LeafIdentity>>,
) -> Result<Json<NodesResponse>, ApiFailure> {
    require_operator(&peer)?;
    let store = state.store.lock().await;
    let nodes = store.list();
    Ok(Json(NodesResponse {
        count: nodes.len(),
        nodes,
    }))
}

async fn describe_node(
    State(state): State<AppState>,
    Extension(peer): Extension<Option<LeafIdentity>>,
    Path(node_id): Path<String>,
) -> Result<Json<NodeSummary>, ApiFailure> {
    require_operator(&peer)?;
    let store = state.store.lock().await;
    store
        .get(&node_id)
        .map(|record| Json(record.summary()))
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "not_found", "unknown node"))
}

async fn revoke_node(
    State(state): State<AppState>,
    Extension(peer): Extension<Option<LeafIdentity>>,
    Path(node_id): Path<String>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<NodeSummary>, ApiFailure> {
    require_operator(&peer)?;
    let mut store = state.store.lock().await;
    let mut record = store
        .get(&node_id)
        .cloned()
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "not_found", "unknown node"))?;
    if let Some(serial) = record.serial_hex.clone() {
        let mut ca = state.ca.lock().await;
        ca.revoke(&serial, &req.reason)
            .map_err(|e| failure(StatusCode::BAD_REQUEST, "revoke_failed", e.to_string()))?;
        let crl = ca
            .crl_store()
            .map_err(|e| failure(StatusCode::INTERNAL_SERVER_ERROR, "crl", e.to_string()))?;
        *state.crl.write().expect("crl lock poisoned") = crl;
    }
    record.state = fleet_proto::NodeState::Revoked;
    record.vlan = Some(666);
    record.updated_at = crate::unix_now();
    store
        .upsert(record.clone())
        .map_err(|e| failure(StatusCode::CONFLICT, "state", e.to_string()))?;
    info!(node_id = %node_id, reason = %req.reason, "node revoked");
    Ok(Json(record.summary()))
}

async fn renew_node_admin(
    State(state): State<AppState>,
    Extension(peer): Extension<Option<LeafIdentity>>,
    Path(node_id): Path<String>,
    Json(req): Json<RenewRequest>,
) -> Result<Json<EnrollResponse>, ApiFailure> {
    require_operator(&peer)?;
    let response = renew_for(&state, &node_id, &req.csr_pem).await?;
    state.metrics.renewal();
    Ok(Json(response))
}

/// Register a `LeafUsage` for tests and tooling that need the server identity.
pub fn server_leaf_usage() -> LeafUsage {
    LeafUsage::Server
}

/// Duration used by the systemd timer: renew after two thirds of the certificate
/// lifetime has elapsed.
pub fn renewal_threshold(lifetime: Duration) -> Duration {
    lifetime.mul_f64(2.0 / 3.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_threshold_is_two_thirds() {
        let lifetime = Duration::from_secs(90 * 24 * 3600);
        assert_eq!(
            renewal_threshold(lifetime).as_secs(),
            (90 * 24 * 3600) * 2 / 3
        );
    }

    #[test]
    fn operator_and_node_credentials_are_separated() {
        let operator = LeafIdentity {
            node_id: "operator-admin".into(),
            site: "dc1".into(),
            hostname: "operator-admin".into(),
            dns_name: "operator-admin.fleet.internal".into(),
            uri: "fleet://dc1/operator-admin".into(),
            serial_hex: "01".into(),
            not_before: 0,
            not_after: 0,
            usage: LeafUsage::Client,
        };
        assert!(require_operator(&Some(operator.clone())).is_ok());
        assert!(require_node(&Some(operator), "n1").is_err());

        let node = LeafIdentity {
            node_id: "n1".into(),
            site: "dc1".into(),
            hostname: "n1".into(),
            dns_name: "n1.fleet.internal".into(),
            uri: "fleet://dc1/n1".into(),
            serial_hex: "02".into(),
            not_before: 0,
            not_after: 0,
            usage: LeafUsage::Client,
        };
        assert!(require_node(&Some(node.clone()), "n1").is_ok());
        assert!(require_operator(&Some(node)).is_err());
    }
}
