//! Minimal but real DHCP, TFTP, DNS, and HTTP provisioning services.
//!
//! These bind real sockets. DHCP/TFTP/DNS run over UDP (the provisioning VLAN
//! is isolated, so unicast replies to the requesting address are sufficient),
//! HTTP runs over TCP with axum.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out waiting for a response")]
    Timeout,
    #[error("malformed packet: {0}")]
    Malformed(String),
    #[error("DHCP NAK: {0}")]
    Nak(String),
    #[error("TFTP file not found: {0}")]
    FileNotFound(String),
    #[error("TFTP error {code}: {message}")]
    Tftp { code: u16, message: String },
    #[error("HTTP {status} for {path}")]
    Http { status: u16, path: String },
    #[error("HTTP client error: {0}")]
    Client(#[from] reqwest::Error),
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub filename: String,
    pub hostname: String,
}

#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub leases: HashMap<String, Lease>,
    pub subnet_mask: Ipv4Addr,
    pub router: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub next_server: Ipv4Addr,
    pub lease_seconds: u32,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            leases: HashMap::new(),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 168, 50, 1),
            dns: Ipv4Addr::new(192, 168, 50, 2),
            next_server: Ipv4Addr::new(192, 168, 50, 2),
            lease_seconds: 600,
        }
    }
}

pub struct RunningDhcp {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningDhcp {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

struct DhcpRequest {
    xid: [u8; 4],
    mac: String,
    message_type: u8,
}

fn parse_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_dhcp(packet: &[u8]) -> Result<DhcpRequest, NetError> {
    if packet.len() < 240 {
        return Err(NetError::Malformed("short DHCP packet".into()));
    }
    if packet[236..240] != DHCP_MAGIC {
        return Err(NetError::Malformed("bad DHCP magic".into()));
    }
    let hlen = packet[2] as usize;
    if hlen < 6 || packet.len() < 28 + hlen {
        return Err(NetError::Malformed("bad chaddr length".into()));
    }
    let mut xid = [0u8; 4];
    xid.copy_from_slice(&packet[4..8]);
    let mac = parse_mac(&packet[28..28 + 6]);
    let mut message_type = 0u8;
    let mut i = 240;
    while i < packet.len() {
        let code = packet[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= packet.len() {
            break;
        }
        let len = packet[i + 1] as usize;
        let value = packet.get(i + 2..i + 2 + len).unwrap_or_default();
        if code == 53 && !value.is_empty() {
            message_type = value[0];
        }
        i += 2 + len;
    }
    Ok(DhcpRequest {
        xid,
        mac,
        message_type,
    })
}

fn option(buf: &mut Vec<u8>, code: u8, value: &[u8]) {
    buf.push(code);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

fn build_reply(
    request: &DhcpRequest,
    message_type: u8,
    lease: Option<&Lease>,
    config: &DhcpConfig,
    nak_message: Option<&str>,
) -> Vec<u8> {
    let mut packet = vec![0u8; 240];
    packet[0] = 2; // BOOTREPLY
    packet[1] = 1;
    packet[2] = 6;
    packet[4..8].copy_from_slice(&request.xid);
    packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast
    if let Some(lease) = lease {
        packet[16..20].copy_from_slice(&lease.ip.octets());
        packet[20..24].copy_from_slice(&config.next_server.octets());
        let filename = lease.filename.as_bytes();
        let len = filename.len().min(127);
        packet[108..108 + len].copy_from_slice(&filename[..len]);
    }
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    for (idx, byte) in request.mac.split(':').enumerate() {
        if let Ok(value) = u8::from_str_radix(byte, 16) {
            if idx < 16 {
                packet[28 + idx] = value;
            }
        }
    }
    let mut options = Vec::new();
    option(&mut options, 53, &[message_type]);
    option(&mut options, 54, &config.dns.octets());
    if message_type == 6 {
        option(
            &mut options,
            56,
            nak_message.unwrap_or("request refused").as_bytes(),
        );
    } else {
        option(&mut options, 51, &config.lease_seconds.to_be_bytes());
        option(&mut options, 1, &config.subnet_mask.octets());
        option(&mut options, 3, &config.router.octets());
        option(&mut options, 6, &config.dns.octets());
        option(&mut options, 66, config.next_server.to_string().as_bytes());
        if let Some(lease) = lease {
            option(&mut options, 67, lease.filename.as_bytes());
        }
    }
    options.push(255);
    packet.extend_from_slice(&options);
    packet
}

pub async fn start_dhcp(config: DhcpConfig) -> Result<RunningDhcp, NetError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let (shutdown, mut rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() || *rx.borrow() {
                        break;
                    }
                }
                received = socket.recv_from(&mut buf) => {
                    let Ok((len, peer)) = received else { break };
                    let Ok(request) = parse_dhcp(&buf[..len]) else { continue };
                    if request.message_type != 1 && request.message_type != 3 {
                        continue;
                    }
                    let lease = config.leases.get(&request.mac);
                    let reply = match (request.message_type, lease) {
                        (1, Some(lease)) => build_reply(&request, 2, Some(lease), &config, None),
                        (1, None) => build_reply(&request, 6, None, &config, Some("unknown mac")),
                        (3, Some(lease)) => build_reply(&request, 5, Some(lease), &config, None),
                        _ => build_reply(&request, 6, None, &config, Some("unknown mac")),
                    };
                    let _ = socket.send_to(&reply, peer).await;
                }
            }
        }
    });
    Ok(RunningDhcp {
        addr,
        shutdown,
        handle,
    })
}

pub async fn dhcp_acquire(server: SocketAddr, mac: &str) -> Result<Lease, NetError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(server).await?;
    let xid: u32 = rand::random();
    let mac_bytes = mac
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).map_err(|_| NetError::Malformed("bad mac".into())))
        .collect::<Result<Vec<_>, _>>()?;

    for message_type in [1u8, 3u8] {
        let mut packet = vec![0u8; 240];
        packet[0] = 1;
        packet[1] = 1;
        packet[2] = 6;
        packet[4..8].copy_from_slice(&xid.to_be_bytes());
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        packet[28..34].copy_from_slice(&mac_bytes);
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        let mut options = Vec::new();
        option(&mut options, 53, &[message_type]);
        option(&mut options, 55, &[1, 3, 6, 51, 66, 67]);
        options.push(255);
        packet.extend_from_slice(&options);
        socket.send(&packet).await?;

        let mut buf = [0u8; 1500];
        let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .map_err(|_| NetError::Timeout)??;
        if len < 240 {
            return Err(NetError::Malformed("short DHCP reply".into()));
        }
        let reply_type = reply_message_type(&buf[..len]);
        if reply_type == Some(6) {
            return Err(NetError::Nak(
                reply_option_string(&buf[..len], 56).unwrap_or_else(|| "refused".into()),
            ));
        }
        let expected = if message_type == 1 { 2 } else { 5 };
        if reply_type != Some(expected) {
            return Err(NetError::Malformed(format!(
                "expected DHCP type {expected}, got {reply_type:?}"
            )));
        }
        if message_type == 3 {
            let ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
            let filename = reply_option_string(&buf[..len], 67).unwrap_or_default();
            let hostname = reply_option_string(&buf[..len], 12).unwrap_or_default();
            return Ok(Lease {
                ip,
                filename,
                hostname,
            });
        }
    }
    Err(NetError::Malformed("DHCP exchange ended early".into()))
}

fn reply_message_type(packet: &[u8]) -> Option<u8> {
    let mut i = 240;
    while i + 1 < packet.len() {
        let code = packet[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = packet[i + 1] as usize;
        if code == 53 {
            return packet.get(i + 2).copied();
        }
        i += 2 + len;
    }
    None
}

fn reply_option_string(packet: &[u8], wanted: u8) -> Option<String> {
    let mut i = 240;
    while i + 1 < packet.len() {
        let code = packet[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = packet[i + 1] as usize;
        if code == wanted {
            return packet.get(i + 2..i + 2 + len).map(|v| {
                String::from_utf8_lossy(v)
                    .trim_end_matches('\0')
                    .to_string()
            });
        }
        i += 2 + len;
    }
    None
}

// ---------------------------------------------------------------------------
// TFTP
// ---------------------------------------------------------------------------

pub struct RunningTftp {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningTftp {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

pub async fn start_tftp(root: PathBuf) -> Result<RunningTftp, NetError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let (shutdown, mut rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() || *rx.borrow() { break; }
                }
                received = socket.recv_from(&mut buf) => {
                    let Ok((len, peer)) = received else { break };
                    if len < 4 || buf[..2] != [0, 1] { continue; }
                    let request = &buf[2..len];
                    let Some(end) = request.iter().position(|b| *b == 0) else { continue };
                    let filename = String::from_utf8_lossy(&request[..end]).to_string();
                    let root = root.clone();
                    tokio::spawn(async move {
                        let _ = serve_tftp_request(root, peer, filename).await;
                    });
                }
            }
        }
    });
    Ok(RunningTftp {
        addr,
        shutdown,
        handle,
    })
}

async fn serve_tftp_request(
    root: PathBuf,
    peer: SocketAddr,
    filename: String,
) -> Result<(), NetError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(peer).await?;
    let safe = !filename.contains("..") && !filename.starts_with('/');
    let path = root.join(&filename);
    let canonical_root = root.canonicalize().unwrap_or(root.clone());
    let canonical = path.canonicalize();
    let allowed = safe
        && canonical
            .as_ref()
            .map(|p| p.starts_with(&canonical_root))
            .unwrap_or(false);
    if !allowed {
        let mut err = vec![0u8, 5];
        err.extend_from_slice(&1u16.to_be_bytes());
        err.extend_from_slice(b"File not found\0");
        let _ = socket.send(&err).await;
        return Ok(());
    }
    let data = std::fs::read(&path)?;
    let mut block = 1u16;
    for chunk in data.chunks(512) {
        let mut packet = vec![0u8, 3];
        packet.extend_from_slice(&block.to_be_bytes());
        packet.extend_from_slice(chunk);
        socket.send(&packet).await?;
        let mut ack = [0u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut ack))
            .await
            .map_err(|_| NetError::Timeout)??;
        if n < 4 || ack[..2] != [0, 4] {
            return Err(NetError::Malformed("expected TFTP ACK".into()));
        }
        block = block.wrapping_add(1);
    }
    Ok(())
}

pub async fn tftp_get(server: SocketAddr, filename: &str) -> Result<Vec<u8>, NetError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut packet = vec![0u8, 1];
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0);
    packet.extend_from_slice(b"octet\0");
    socket.send_to(&packet, server).await?;
    let mut out = Vec::new();
    let mut expected_block = 1u16;
    loop {
        let mut buf = [0u8; 516];
        let (len, peer) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .map_err(|_| NetError::Timeout)??;
        match buf[1] {
            3 => {
                if len < 4 {
                    return Err(NetError::Malformed("short DATA".into()));
                }
                let block = u16::from_be_bytes([buf[2], buf[3]]);
                if block != expected_block {
                    return Err(NetError::Malformed(format!(
                        "expected block {expected_block}, got {block}"
                    )));
                }
                out.extend_from_slice(&buf[4..len]);
                let mut ack = vec![0u8, 4];
                ack.extend_from_slice(&block.to_be_bytes());
                socket.send_to(&ack, peer).await?;
                if len - 4 < 512 {
                    return Ok(out);
                }
                expected_block = expected_block.wrapping_add(1);
            }
            5 => {
                let code = u16::from_be_bytes([buf[2], buf[3]]);
                let message = String::from_utf8_lossy(&buf[4..len])
                    .trim_end_matches('\0')
                    .to_string();
                if code == 1 {
                    return Err(NetError::FileNotFound(message));
                }
                return Err(NetError::Tftp { code, message });
            }
            other => {
                return Err(NetError::Malformed(format!(
                    "unexpected TFTP opcode {other}"
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

pub struct RunningDns {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningDns {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

pub async fn start_dns(records: HashMap<String, Ipv4Addr>) -> Result<RunningDns, NetError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let records = Arc::new(
        records
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect::<HashMap<_, _>>(),
    );
    let (shutdown, mut rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() || *rx.borrow() { break; }
                }
                received = socket.recv_from(&mut buf) => {
                    let Ok((len, peer)) = received else { break };
                    if let Some(response) = answer_dns(&buf[..len], &records) {
                        let _ = socket.send_to(&response, peer).await;
                    }
                }
            }
        }
    });
    Ok(RunningDns {
        addr,
        shutdown,
        handle,
    })
}

fn answer_dns(query: &[u8], records: &HashMap<String, Ipv4Addr>) -> Option<Vec<u8>> {
    if query.len() < 17 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    while pos < query.len() && query[pos] != 0 {
        let len = query[pos] as usize;
        pos += 1;
        if pos + len > query.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&query[pos..pos + len]).to_string());
        pos += len;
    }
    pos += 1;
    if pos + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    let name = labels.join(".").to_ascii_lowercase();
    let question_end = pos + 4;

    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]); // ID
    response.extend_from_slice(&[0x81, 0x80]); // standard response, recursion available
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let answer = records.get(&name).filter(|_| qtype == 1);
    let ancount = u16::from(answer.is_some());
    response.extend_from_slice(&ancount.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    if response.len() < 12 {
        return None;
    }
    response[3] = if answer.is_some() { 0x80 } else { 0x83 };
    response.extend_from_slice(&query[12..question_end]);
    if let Some(ip) = answer {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes()); // A
        response.extend_from_slice(&1u16.to_be_bytes()); // IN
        response.extend_from_slice(&60u32.to_be_bytes()); // TTL
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&ip.octets());
    }
    Some(response)
}

pub async fn dns_lookup(server: SocketAddr, name: &str) -> Result<Ipv4Addr, NetError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let id: u16 = rand::random();
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    socket.send_to(&query, server).await?;
    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .map_err(|_| NetError::Timeout)??;
    if len < 12 {
        return Err(NetError::Malformed("short DNS response".into()));
    }
    let rcode = buf[3] & 0x0f;
    if rcode == 3 {
        return Err(NetError::Malformed(format!("NXDOMAIN for {name}")));
    }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 {
        return Err(NetError::Malformed(format!("no A record for {name}")));
    }
    // The answer starts with a compression pointer (2), type/class/ttl/rdlen.
    let answer_start = len.saturating_sub(16);
    if buf[answer_start..answer_start + 2] != [0xc0, 0x0c] {
        return Err(NetError::Malformed("unexpected answer encoding".into()));
    }
    let rdlen = u16::from_be_bytes([buf[answer_start + 10], buf[answer_start + 11]]) as usize;
    if rdlen != 4 || answer_start + 16 > len {
        return Err(NetError::Malformed("not an IPv4 answer".into()));
    }
    Ok(Ipv4Addr::new(
        buf[answer_start + 12],
        buf[answer_start + 13],
        buf[answer_start + 14],
        buf[answer_start + 15],
    ))
}

// ---------------------------------------------------------------------------
// HTTP provisioning
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct HttpState {
    root: PathBuf,
}

pub struct RunningHttp {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningHttp {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

async fn serve_file(state: &HttpState, relative: &str) -> Response {
    let path = state.root.join(relative);
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [(
                axum::http::header::CONTENT_TYPE,
                if relative.ends_with(".ipxe") {
                    "text/plain"
                } else {
                    "text/plain; charset=utf-8"
                },
            )],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, format!("not found: {relative}")).into_response(),
    }
}

async fn ipxe_file(State(state): State<HttpState>, Path(name): Path<String>) -> Response {
    if name.contains("..") || name.contains('/') {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    }
    serve_file(&state, &format!("ipxe/{name}")).await
}

async fn boot_file(State(state): State<HttpState>, Path(node): Path<String>) -> Response {
    if node.contains("..") || node.contains('/') {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    }
    for candidate in [
        format!("kickstart/{node}.ks"),
        format!("cloud-init/{node}.yaml"),
    ] {
        let path = state.root.join(&candidate);
        if path.exists() {
            return serve_file(&state, &candidate).await;
        }
    }
    (StatusCode::NOT_FOUND, format!("no boot file for {node}")).into_response()
}

async fn token_file(State(state): State<HttpState>, Path(name): Path<String>) -> Response {
    if name.contains("..") || name.contains('/') {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    }
    serve_file(&state, &format!("tokens/{name}")).await
}

async fn ca_file(State(state): State<HttpState>) -> Response {
    serve_file(&state, "ca.pem").await
}

pub async fn start_http(root: PathBuf) -> Result<RunningHttp, NetError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let state = HttpState { root };
    let app = Router::new()
        .route("/ipxe/{name}", get(ipxe_file))
        .route("/boot/{node}", get(boot_file))
        .route("/tokens/{name}", get(token_file))
        .route("/ca.pem", get(ca_file))
        .with_state(state);
    let (shutdown, mut rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = rx.changed().await;
        });
        let _ = server.await;
    });
    Ok(RunningHttp {
        addr,
        shutdown,
        handle,
    })
}

pub async fn http_get(addr: SocketAddr, path: &str) -> Result<(u16, String), NetError> {
    let url = format!("http://{addr}{path}");
    let response = reqwest::get(&url).await?;
    let status = response.status().as_u16();
    let body = response.text().await?;
    if status != 200 {
        return Err(NetError::Http {
            status,
            path: path.into(),
        });
    }
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dhcp_offers_and_acks_a_known_mac() {
        let mut config = DhcpConfig::default();
        config.leases.insert(
            "52:54:00:5f:6c:01".into(),
            Lease {
                ip: Ipv4Addr::new(192, 168, 50, 11),
                filename: "boot.ipxe".into(),
                hostname: "n1".into(),
            },
        );
        let server = start_dhcp(config).await.unwrap();
        let lease = dhcp_acquire(server.addr, "52:54:00:5f:6c:01")
            .await
            .unwrap();
        assert_eq!(lease.ip, Ipv4Addr::new(192, 168, 50, 11));
        assert_eq!(lease.filename, "boot.ipxe");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn dhcp_unknown_mac_fails_closed_with_nak() {
        let server = start_dhcp(DhcpConfig::default()).await.unwrap();
        let err = dhcp_acquire(server.addr, "52:54:00:5f:6c:ff")
            .await
            .unwrap_err();
        assert!(
            matches!(err, NetError::Nak(ref m) if m.contains("unknown mac")),
            "{err}"
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn tftp_serves_and_reports_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("boot.ipxe"), "#!ipxe\nchain http://x\n").unwrap();
        let server = start_tftp(dir.path().to_path_buf()).await.unwrap();
        let body = tftp_get(server.addr, "boot.ipxe").await.unwrap();
        assert!(String::from_utf8(body).unwrap().contains("chain"));
        let err = tftp_get(server.addr, "nope.ipxe").await.unwrap_err();
        assert!(matches!(err, NetError::FileNotFound(_)), "{err}");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn tftp_rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_tftp(dir.path().to_path_buf()).await.unwrap();
        let err = tftp_get(server.addr, "../etc/passwd").await.unwrap_err();
        assert!(matches!(err, NetError::FileNotFound(_)), "{err}");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn dns_answers_fleet_names_and_nxdomain() {
        let mut records = HashMap::new();
        records.insert("n1.fleet.internal".into(), Ipv4Addr::new(192, 168, 50, 11));
        let server = start_dns(records).await.unwrap();
        assert_eq!(
            dns_lookup(server.addr, "n1.fleet.internal").await.unwrap(),
            Ipv4Addr::new(192, 168, 50, 11)
        );
        assert!(dns_lookup(server.addr, "n9.fleet.internal").await.is_err());
        server.shutdown().await;
    }

    #[tokio::test]
    async fn http_serves_boot_files_and_404s() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("cloud-init")).unwrap();
        std::fs::write(dir.path().join("cloud-init/n1.yaml"), "#cloud-config\n").unwrap();
        let server = start_http(dir.path().to_path_buf()).await.unwrap();
        let (_, body) = http_get(server.addr, "/boot/n1").await.unwrap();
        assert!(body.contains("cloud-config"));
        let err = http_get(server.addr, "/boot/missing").await.unwrap_err();
        assert!(matches!(err, NetError::Http { status: 404, .. }), "{err}");
        server.shutdown().await;
    }
}
