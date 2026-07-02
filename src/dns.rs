//! DNS-over-HTTPS / DNS-over-TLS resolver.
//! Adapted from android-tether's dns_proxy.rs

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsMode {
    DoH,
    DoT,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsProvider {
    Cloudflare,
    Google,
    Quad9,
}

pub const ALL_PROVIDERS: [DnsProvider; 3] = [
    DnsProvider::Cloudflare,
    DnsProvider::Google,
    DnsProvider::Quad9,
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsStrategy {
    Single,
    RoundRobin,
    Failover,
}

static RR_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn next_round_robin() -> DnsProvider {
    let idx = RR_COUNTER.fetch_add(1, Ordering::Relaxed) % ALL_PROVIDERS.len();
    ALL_PROVIDERS[idx]
}

// ── Public API ──

pub fn create_doh_agent() -> Result<ureq::Agent, String> {
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("tls init: {e}"))?;
    Ok(ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(DNS_QUERY_TIMEOUT)
        .timeout_write(Duration::from_secs(2))
        .resolver(static_dns_resolver)
        .tls_connector(Arc::new(tls))
        .build())
}

pub fn doh_resolve_fallible(agent: &ureq::Agent, provider: DnsProvider, query: &[u8]) -> Result<Vec<u8>, String> {
    doh_query_with_agent(agent, provider, query)
}

pub fn create_dot_conn(provider: DnsProvider) -> Result<DotConn, String> {
    let (addr, hostname) = dot_target(provider);
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("tcp connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set_read_to: {e}"))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set_write_to: {e}"))?;
    let connector = native_tls::TlsConnector::new().map_err(|e| format!("tls init: {e}"))?;
    let tls = connector.connect(hostname, stream).map_err(|e| format!("tls handshake: {e}"))?;
    Ok(DotConn { stream: tls })
}

pub struct DotConn {
    stream: native_tls::TlsStream<TcpStream>,
}

pub fn dot_query(conn: &mut DotConn, query: &[u8]) -> Result<Vec<u8>, String> {
    let len_be = (query.len() as u16).to_be_bytes();
    conn.stream.write_all(&len_be).map_err(|e| format!("write: {e}"))?;
    conn.stream.write_all(query).map_err(|e| format!("write: {e}"))?;
    let mut len_buf = [0u8; 2];
    conn.stream.read_exact(&mut len_buf).map_err(|e| format!("read: {e}"))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len > 4096 {
        return Err("response too large".into());
    }
    let mut resp = vec![0u8; resp_len];
    conn.stream.read_exact(&mut resp).map_err(|e| format!("read: {e}"))?;
    Ok(resp)
}

// ── DoH implementation ──

fn static_dns_resolver(netloc: &str) -> io::Result<Vec<SocketAddr>> {
    let (host, port_str) = netloc.split_once(':')
        .map(|(h, p)| (h, p.parse::<u16>().unwrap_or(443)))
        .unwrap_or((netloc, 443));
    let ip: [u8; 4] = match host {
        "cloudflare-dns.com" => [1, 1, 1, 1],
        "dns.google" => [8, 8, 8, 8],
        "dns.quad9.net" => [9, 9, 9, 9],
        _ => return Err(io::Error::new(io::ErrorKind::NotFound, format!("unknown: {netloc}"))),
    };
    Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port_str)])
}

fn doh_query_with_agent(agent: &ureq::Agent, provider: DnsProvider, query: &[u8]) -> Result<Vec<u8>, String> {
    let url = doh_url(provider);
    match agent
        .post(url)
        .set("Content-Type", "application/dns-message")
        .set("Accept", "application/dns-message")
        .send_bytes(query)
    {
        Ok(resp) => {
            let mut body = Vec::new();
            resp.into_reader().read_to_end(&mut body).map_err(|e| format!("read: {e}"))?;
            Ok(body)
        }
        Err(ureq::Error::Status(503, _)) => Err("server 503".into()),
        Err(e) => Err(format!("{e}")),
    }
}

fn doh_url(p: DnsProvider) -> &'static str {
    match p {
        DnsProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
        DnsProvider::Google => "https://dns.google/dns-query",
        DnsProvider::Quad9 => "https://dns.quad9.net/dns-query",
    }
}

fn dot_target(p: DnsProvider) -> (SocketAddr, &'static str) {
    match p {
        DnsProvider::Cloudflare => ("1.1.1.1:853".parse().unwrap(), "cloudflare-dns.com"),
        DnsProvider::Google => ("8.8.8.8:853".parse().unwrap(), "dns.google"),
        DnsProvider::Quad9 => ("9.9.9.9:853".parse().unwrap(), "dns.quad9.net"),
    }
}
