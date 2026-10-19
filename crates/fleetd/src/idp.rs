//! Mock OIDC identity provider with the device-authorization grant.
//!
//! Shipped for local development and tests (`fleet-sim idp`). It signs real
//! RS256 JWTs and exposes real discovery and JWKS documents, but it
//! auto-approves device codes so the flow is non-interactive.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::RngCore;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceRequest {
    #[serde(default = "default_client_id")]
    pub client_id: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default = "default_subject")]
    pub subject: String,
}

fn default_client_id() -> String {
    "fleetctl".into()
}

fn default_subject() -> String {
    "operator@fleet.internal".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub device_code: String,
    #[serde(default)]
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Debug, Clone)]
struct Grant {
    subject: String,
    groups: Vec<String>,
    nonce: Option<String>,
    scopes: String,
    expires_at: i64,
}

#[derive(Clone)]
struct IdpState {
    issuer: String,
    audience: String,
    kid: String,
    encoding_key: EncodingKey,
    modulus: String,
    exponent: String,
    token_ttl: i64,
    grants: Arc<Mutex<HashMap<String, Grant>>>,
}

pub struct RunningIdp {
    pub addr: SocketAddr,
    pub issuer: String,
    pub kid: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningIdp {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }

    /// Sign an arbitrary token with the IdP key. Tests use this to exercise
    /// expired/wrong-audience/unknown-kid/tampered-signature paths.
    pub fn sign_token(
        &self,
        subject: &str,
        groups: Vec<String>,
        audience: &str,
        expires_in: i64,
        kid: &str,
        nonce: Option<String>,
    ) -> String {
        let now = unix_now();
        let claims = Claims {
            iss: self.issuer.clone(),
            sub: subject.into(),
            aud: audience.into(),
            exp: now + expires_in,
            nbf: now - 5,
            iat: now,
            nonce,
            groups,
            scope: Some("openid".into()),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn start() -> anyhow::Result<RunningIdp> {
    start_at("127.0.0.1:0".parse()?).await
}

pub async fn start_at(addr: SocketAddr) -> anyhow::Result<RunningIdp> {
    let private = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
    let private_key_pem = private.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let public_key_pem = private.to_public_key().to_public_key_pem(LineEnding::LF)?;
    let public = private.to_public_key();
    let modulus = b64url(&public.n().to_bytes_be());
    let exponent = b64url(&public.e().to_bytes_be());

    let listener = TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;
    let issuer = format!("http://{addr}");
    let kid = "fleet-idp-1".to_string();

    let state = IdpState {
        issuer: issuer.clone(),
        audience: "fleetd".into(),
        kid: kid.clone(),
        encoding_key: EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?,
        modulus,
        exponent,
        token_ttl: 3600,
        grants: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/device_authorization", post(device_authorization))
        .route("/token", post(token))
        .route("/jwks", get(jwks))
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({"status":"ok"})) }),
        )
        .with_state(state.clone());

    let (shutdown, mut rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = rx.changed().await;
        });
        let _ = server.await;
    });

    Ok(RunningIdp {
        addr,
        issuer,
        kid,
        private_key_pem,
        public_key_pem,
        shutdown,
        handle,
    })
}

async fn discovery(State(state): State<IdpState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.issuer,
        "device_authorization_endpoint": format!("{}/device_authorization", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "jwks_uri": format!("{}/jwks", state.issuer),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": ["urn:ietf:params:oauth:grant-type:device_code"],
        "scopes_supported": ["openid", "profile", "groups"]
    }))
}

async fn device_authorization(
    State(state): State<IdpState>,
    Json(req): Json<DeviceRequest>,
) -> Json<DeviceResponse> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let device_code = hex::encode(bytes);
    let user_code = format!(
        "{:04X}-{:04X}",
        rand::random::<u16>(),
        rand::random::<u16>()
    );
    let groups = if req.groups.is_empty() {
        vec!["fleet-operator".to_string()]
    } else {
        req.groups.clone()
    };
    state.grants.lock().expect("idp mutex").insert(
        device_code.clone(),
        Grant {
            subject: req.subject,
            groups,
            nonce: req.nonce,
            scopes: if req.scope.is_empty() {
                "openid".into()
            } else {
                req.scope
            },
            expires_at: unix_now() + 600,
        },
    );
    Json(DeviceResponse {
        device_code,
        user_code: user_code.clone(),
        verification_uri: format!("{}/device", state.issuer),
        verification_uri_complete: format!("{}/device?user_code={user_code}", state.issuer),
        expires_in: 600,
        interval: 1,
    })
}

async fn token(
    State(state): State<IdpState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if req.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"unsupported_grant_type"})),
        ));
    }
    let grant = {
        let mut grants = state.grants.lock().expect("idp mutex");
        let grant = grants.remove(&req.device_code).ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_grant"})),
            )
        })?;
        if grant.expires_at <= unix_now() {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"expired_token"})),
            ));
        }
        grant
    };
    let now = unix_now();
    let claims = Claims {
        iss: state.issuer.clone(),
        sub: grant.subject,
        aud: state.audience.clone(),
        exp: now + state.token_ttl,
        nbf: now - 5,
        iat: now,
        nonce: grant.nonce,
        groups: grant.groups,
        scope: Some(grant.scopes.clone()),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(state.kid.clone());
    let access_token = encode(&header, &claims, &state.encoding_key).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: state.token_ttl,
        scope: grant.scopes,
    }))
}

async fn jwks(State(state): State<IdpState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": state.kid,
            "use": "sig",
            "alg": "RS256",
            "n": state.modulus,
            "e": state.exponent
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn device_flow_returns_a_real_jwt() {
        let idp = start().await.unwrap();
        let http = reqwest::Client::new();
        let device: DeviceResponse = http
            .post(format!("{}/device_authorization", idp.issuer))
            .json(&serde_json::json!({
                "client_id": "fleetctl",
                "groups": ["fleet-admin"],
                "nonce": "abc123"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(device.user_code.contains('-'));
        let token: TokenResponse = http
            .post(format!("{}/token", idp.issuer))
            .json(&serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.device_code,
                "client_id": "fleetctl"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(token.token_type, "Bearer");
        let header = jsonwebtoken::decode_header(&token.access_token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("fleet-idp-1"));
        let jwks: serde_json::Value = http
            .get(format!("{}/jwks", idp.issuer))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(jwks["keys"][0]["alg"], "RS256");
        idp.shutdown().await;
    }

    #[tokio::test]
    async fn signed_tokens_can_be_forged_for_negative_tests() {
        let idp = start().await.unwrap();
        let token = idp.sign_token(
            "alice",
            vec!["fleet-admin".into()],
            "fleetd",
            60,
            &idp.kid,
            None,
        );
        let payload = token.split('.').nth(1).unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let claims: Claims = serde_json::from_slice(&raw).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.groups, vec!["fleet-admin"]);
        idp.shutdown().await;
    }
}
