//! DNS-over-HTTPS / DNS-over-TLS resolver.
//! Adapted from android-tether's dns_proxy.rs

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use bytes::Bytes;

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum size of a DNS message we accept over UDP (EDNS0-sized queries).
pub const MAX_UDP_DNS: usize = 4096;

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
    Ok(DotConn { stream: tls, provider })
}

pub struct DotConn {
    stream: native_tls::TlsStream<TcpStream>,
    pub provider: DnsProvider,
}

pub fn dot_query(conn: &mut DotConn, query: &[u8]) -> Result<Vec<u8>, String> {
    let len_be = (query.len() as u16).to_be_bytes();
    conn.stream.write_all(&len_be).map_err(|e| format!("write: {e}"))?;
    conn.stream.write_all(query).map_err(|e| format!("write: {e}"))?;
    let mut len_buf = [0u8; 2];
    conn.stream.read_exact(&mut len_buf).map_err(|e| format!("read: {e}"))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 {
        return Err("empty response".into());
    }
    let mut resp = vec![0u8; resp_len];
    conn.stream.read_exact(&mut resp).map_err(|e| format!("read: {e}"))?;
    Ok(resp)
}

// ── DoT connection pool ────────────────────────────────────────────────
//
// DoT queries over a single TLS connection are inherently serialised
// (one in-flight query per connection). A small pool of independent
// connections lets concurrent workers/connections resolve in parallel.
// Connections are recreated lazily when the provider changes (hot-swap)
// or after a failure.

pub struct DotPool {
    slots: Vec<parking_lot::Mutex<Option<DotConn>>>,
    next: AtomicUsize,
}

impl DotPool {
    pub fn new(size: usize) -> Self {
        let mut slots = Vec::with_capacity(size);
        for _ in 0..size {
            slots.push(parking_lot::Mutex::new(None));
        }
        Self { slots, next: AtomicUsize::new(0) }
    }

    pub fn query(&self, provider: DnsProvider, query: &[u8]) -> Result<Vec<u8>, String> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let mut slot = self.slots[idx].lock();

        if slot.as_ref().map(|c| c.provider) != Some(provider) {
            *slot = Some(create_dot_conn(provider)?);
        }

        match dot_query(slot.as_mut().unwrap(), query) {
            Ok(r) => Ok(r),
            Err(e) => {
                // Drop the broken connection so the next query reconnects.
                *slot = None;
                Err(e)
            }
        }
    }
}

// ── Response cache ─────────────────────────────────────────────────────
//
// Keyed by the query with its 2-byte transaction ID stripped, so queries
// from different clients share entries. Responses are re-ID'd on hit.
// TTLs are parsed from the answer records (covers positive + negative
// SOA caching); unparseable or empty responses are not cached.

const CACHE_MAX_ENTRIES: usize = 2048;
const CACHE_MAX_TTL: u64 = 3600;

type CacheEntry = (Instant, Vec<u8>);

pub struct DnsCache {
    map: parking_lot::Mutex<HashMap<Vec<u8>, CacheEntry>>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self { map: parking_lot::Mutex::new(HashMap::new()) }
    }

    pub fn get(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 2 {
            return None;
        }
        let key = &query[2..];
        let mut map = self.map.lock();
        match map.get(key) {
            Some((expires, resp)) if *expires > Instant::now() => Some(resp.clone()),
            _ => {
                map.remove(key);
                None
            }
        }
    }

    pub fn put(&self, query: &[u8], resp: &[u8], ttl: u32) {
        if query.len() < 2 {
            return;
        }
        if ttl == 0 {
            return;
        }
        let ttl = (ttl as u64).min(CACHE_MAX_TTL);
        let key = query[2..].to_vec();
        let mut map = self.map.lock();
        if map.len() >= CACHE_MAX_ENTRIES {
            // Crude full eviction; entries are cheap to refetch.
            map.clear();
        }
        map.insert(key, (Instant::now() + Duration::from_secs(ttl), resp.to_vec()));
    }
}

// ── DNS wire-format helpers ────────────────────────────────────────────

/// Skip a (possibly compressed) name in a DNS message, returning the
/// position just past it. Returns None on malformed input.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        match len & 0xC0 {
            0xC0 => return Some(pos + 2), // compression pointer
            0x40 | 0x80 => return None,   // extended labels: unsupported
            _ => {
                if len == 0 {
                    return Some(pos + 1);
                }
                pos += 1 + len as usize;
                if pos > msg.len() {
                    return None;
                }
            }
        }
    }
}

/// Minimum TTL across all answer/authority/additional records. Returns
/// None when there are no records (don't cache such responses).
pub fn response_ttl(resp: &[u8]) -> Option<u32> {
    if resp.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
    let arcount = u16::from_be_bytes([resp[10], resp[11]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        pos += 4; // type + class
        if pos > resp.len() {
            return None;
        }
    }

    let mut min = u32::MAX;
    let mut seen = 0usize;
    for _ in 0..(ancount + nscount + arcount) {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        min = min.min(ttl);
        seen += 1;
        pos += 10 + rdlen;
        if pos > resp.len() {
            return None;
        }
    }

    if seen == 0 {
        None
    } else {
        Some(min)
    }
}

/// Overwrite the transaction ID in `resp` with the one from `query`.
/// Needed when serving a cached response to a different query.
pub fn patch_id(resp: &mut [u8], query: &[u8]) {
    if resp.len() >= 2 && query.len() >= 2 {
        resp[0] = query[0];
        resp[1] = query[1];
    }
}

/// Truncate a response to `max` bytes and set the TC (truncated) bit so
/// the client retries over TCP. Matches RFC 2181 behaviour.
pub fn set_tc(resp: &mut Vec<u8>, max: usize) {
    if resp.len() > max {
        resp.truncate(max);
        if resp.len() >= 3 {
            resp[2] |= 0x02;
        }
    }
}

/// Build a SERVFAIL response that echoes the query's ID + question,
/// so the client doesn't wait for the full timeout.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let mut resp = Vec::with_capacity(64);
    resp.extend_from_slice(&query[..12.min(query.len())]);
    if resp.len() == 12 {
        resp[2] = (query[2] & 0x01) | 0x80; // QR=1, preserve RD
        resp[3] = 0x82;                    // RA=1, RCODE=2 (SERVFAIL)
        if let Some(qend) = skip_name(query, 12) {
            if qend + 4 <= query.len() {
                resp.extend_from_slice(&query[12..qend + 4]);
            }
        }
    }
    resp
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

// Quad9's DoH endpoint requires HTTP/2 (it resets plain HTTP/1.1
// connections), so it gets its own persistent h2 client that connects to
// the static 9.9.9.9 anycast with ALPN "h2" and SNI dns.quad9.net.
// Connections are pooled so repeated queries reuse a live h2 stream.

const QUAD9_IP: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
const QUAD9_CONN_MAX_IDLE: Duration = Duration::from_secs(15);

struct Quad9Conn {
    send: h2::client::SendRequest<Bytes>,
    created: Instant,
}

pub struct Quad9Pool {
    handle: tokio::runtime::Handle,
    conns: parking_lot::Mutex<VecDeque<Quad9Conn>>,
}

fn quad9_connect(handle: &tokio::runtime::Handle) -> Result<Quad9Conn, String> {
    let send = handle.block_on(async {
        let tcp = tokio::net::TcpStream::connect((QUAD9_IP, 443))
            .await
            .map_err(|e| format!("tcp connect: {e}"))?;
        let connector = tokio_native_tls::TlsConnector::from(
            native_tls::TlsConnector::builder()
                .request_alpns(&["h2"])
                .build()
                .map_err(|e| format!("tls init: {e}"))?,
        );
        let tls = connector
            .connect("dns.quad9.net", tcp)
            .await
            .map_err(|e| format!("tls handshake: {e}"))?;
        let (send, conn) = h2::client::handshake(tls)
            .await
            .map_err(|e| format!("h2 handshake: {e}"))?;
        handle.spawn(async move {
            if let Err(e) = conn.await {
                log::warn!("Quad9 h2 connection task ended: {e}");
            }
        });
        Ok::<_, String>(send)
    })?;
    Ok(Quad9Conn {
        send,
        created: Instant::now(),
    })
}

impl Quad9Pool {
    /// Must be called from a thread inside the tokio runtime context
    /// (e.g. run_doh, which runs on the block_on thread).
    pub fn new() -> Option<Quad9Pool> {
        let handle = tokio::runtime::Handle::try_current().ok()?;
        Some(Quad9Pool {
            handle,
            conns: parking_lot::Mutex::new(VecDeque::new()),
        })
    }

    fn take(&self) -> Result<Quad9Conn, String> {
        let mut conns = self.conns.lock();
        while let Some(conn) = conns.pop_front() {
            // Quad9 closes idle HTTP/2 connections within ~30-60s, so a
            // conn that sat in the pool is likely dead — drop it and use a
            // fresh one instead of failing on a stale handle.
            if conn.created.elapsed() < QUAD9_CONN_MAX_IDLE {
                return Ok(conn);
            }
        }
        drop(conns);
        quad9_connect(&self.handle)
    }

    pub fn query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        // Quad9 closes idle HTTP/2 connections (GOAWAY / broken pipe), so a
        // pooled connection can be dead on pickup. Retry once with a fresh
        // connection before giving up — DNS queries are idempotent.
        let mut last_err = String::new();
        for attempt in 0..2 {
            let conn = self.take()?;
            match self.run(conn, query) {
                Ok((body, send)) => {
                    self.conns.lock().push_back(Quad9Conn {
                        send,
                        created: Instant::now(),
                    });
                    return Ok(body);
                }
                Err(e) => {
                    last_err = e;
                    if attempt == 0 {
                        // A stale pooled connection means the rest are
                        // probably stale too — drop them all.
                        self.conns.lock().clear();
                        log::debug!("Quad9 h2 failed ({last_err}); retrying on a fresh connection");
                    }
                }
            }
        }
        Err(last_err)
    }

    fn run(&self, conn: Quad9Conn, query: &[u8]) -> Result<(Vec<u8>, h2::client::SendRequest<Bytes>), String> {
        let fut = async {
            let mut send = conn.send.ready().await.map_err(|e| format!("h2 ready: {e}"))?;
            let req = http::Request::builder()
                .method("POST")
                .uri("https://dns.quad9.net/dns-query")
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(())
                .map_err(|e| format!("req build: {e}"))?;
            let (resp, mut stream) = send
                .send_request(req, false)
                .map_err(|e| format!("send: {e}"))?;
            stream
                .send_data(Bytes::from(query.to_vec()), true)
                .map_err(|e| format!("send body: {e}"))?;
            let resp = resp.await.map_err(|e| format!("resp: {e}"))?;
            let body_stream = resp.into_body();
            futures_util::pin_mut!(body_stream);
            let mut body = Vec::new();
            while let Some(chunk) = body_stream.next().await {
                body.extend_from_slice(&chunk.map_err(|e| format!("body: {e}"))?);
            }
            Ok::<(Vec<u8>, h2::client::SendRequest<Bytes>), String>((body, send))
        };
        self.handle.block_on(async {
            match tokio::time::timeout(DNS_QUERY_TIMEOUT, fut).await {
                Ok(r) => r,
                Err(_) => Err("quad9 timeout".into()),
            }
        })
    }
}

fn dot_target(p: DnsProvider) -> (SocketAddr, &'static str) {
    match p {
        DnsProvider::Cloudflare => ("1.1.1.1:853".parse().unwrap(), "cloudflare-dns.com"),
        DnsProvider::Google => ("8.8.8.8:853".parse().unwrap(), "dns.google"),
        DnsProvider::Quad9 => ("9.9.9.9:853".parse().unwrap(), "dns.quad9.net"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Minimal response: header + question + one A record with a
    /// compressed owner name (pointer to the question name at offset 12).
    fn sample_response(ttl: u32) -> Vec<u8> {
        let qname = encode_name("www.example.com");
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        msg.extend_from_slice(&qname);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        msg.extend_from_slice(&[0xC0, 0x0C]);             // pointer → question name
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x04]);             // rdlength
        msg.extend_from_slice(&[93, 184, 216, 34]);       // 93.184.216.34
        msg
    }

    #[test]
    fn ttl_parses_compressed_names() {
        let msg = sample_response(300);
        assert_eq!(response_ttl(&msg), Some(300));
    }

    #[test]
    fn ttl_takes_minimum_across_records() {
        let mut msg = sample_response(300);
        // Append a second answer record with a lower TTL (offset: 12 qname
        // len 17 + 4 + answer(2+10+4) = header+question+first answer).
        let qname = encode_name("www.example.com");
        let mut second = Vec::new();
        second.extend_from_slice(&qname);
        second.extend_from_slice(&[0x00, 0x05, 0x00, 0x01]); // CNAME, IN
        second.extend_from_slice(&50u32.to_be_bytes());
        second.extend_from_slice(&[0x00, 0x02]);
        second.extend_from_slice(&[0x00, 0x01]);
        msg[6..8].copy_from_slice(&[0x00, 0x02]); // ANCOUNT = 2
        msg.extend_from_slice(&second);
        assert_eq!(response_ttl(&msg), Some(50));
    }

    #[test]
    fn ttl_none_when_no_records() {
        let mut msg = sample_response(300);
        msg[6..8].copy_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        assert_eq!(response_ttl(&msg), None);
    }

    #[test]
    fn ttl_none_on_garbage() {
        assert_eq!(response_ttl(&[0x00, 0x01]), None);
        assert_eq!(response_ttl(&[0u8; 8]), None);
    }

    #[test]
    fn patch_id_rewrites_transaction_id() {
        let mut resp = sample_response(300);
        let query = [0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        patch_id(&mut resp, &query);
        assert_eq!(&resp[0..2], &[0xAB, 0xCD]);
    }

    #[test]
    fn set_tc_truncates_and_sets_bit() {
        let mut resp = sample_response(300);
        set_tc(&mut resp, 20);
        assert_eq!(resp.len(), 20);
        assert_ne!(resp[2] & 0x02, 0);       // TC set
        assert_eq!(resp[2] & 0xFD, 0x81);    // other flags intact (QR|RD)
    }

    #[test]
    fn servfail_echoes_id_and_question() {
        let mut query = vec![0x42, 0x69, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        query.extend_from_slice(&encode_name("example.com"));
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let resp = servfail(&query);
        assert_eq!(&resp[0..2], &[0x42, 0x69]);
        assert_eq!(resp[2] & 0x80, 0x80);      // QR set
        assert_eq!(resp[3] & 0x0F, 0x02);      // RCODE = SERVFAIL
        assert_eq!(resp[3] & 0x80, 0x80);      // RA set
        assert_eq!(&resp[12..], &query[12..]); // question echoed
    }

    #[test]
    fn cache_round_trip_and_id_rewrite() {
        let cache = DnsCache::new();
        let q1 = [0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let q2 = [0x02, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut resp = sample_response(300);
        resp[0] = 0x01;
        resp[1] = 0x01;

        cache.put(&q1, &resp, 300);
        let mut hit = cache.get(&q2).expect("cached hit");
        assert_eq!(&hit[0..2], &[0x01, 0x01]); // stored ID, not q2's
        patch_id(&mut hit, &q2);
        assert_eq!(&hit[0..2], &[0x02, 0x02]); // requester's ID after patch
    }

    #[test]
    fn cache_respects_ttl_and_zero() {
        let cache = DnsCache::new();
        let q = [0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let resp = sample_response(300);

        cache.put(&q, &resp, 0);
        assert!(cache.get(&q).is_none(), "ttl 0 must not be cached");

        cache.put(&q, &resp, 300);
        assert!(cache.get(&q).is_some());

        // Simulate expiry by inserting an already-expired entry directly.
        {
            let mut map = cache.map.lock();
            map.insert(q[2..].to_vec(), (Instant::now() - Duration::from_secs(1), resp.clone()));
        }
        assert!(cache.get(&q).is_none(), "expired entry must miss and be removed");
    }

    fn query_bytes(id: u16, name: &str) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // RD
        q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        q.extend_from_slice(&encode_name(name));
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        q
    }

    /// End-to-end: real DoH query + real TTL parsing + cache round trip.
    /// Ignored by default (needs network); run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires network"]
    fn real_doh_query_and_cache() {
        let agent = create_doh_agent().expect("agent");
        let cache = DnsCache::new();
        let q = query_bytes(0x1337, "example.com");

        let resp = doh_resolve_fallible(&agent, DnsProvider::Cloudflare, &q)
            .expect("doh query");
        assert!(resp.len() > 12);
        assert_eq!(&resp[0..2], &[0x13, 0x37], "upstream echoes ID");
        let ttl = response_ttl(&resp).expect("parses TTL from real response");

        cache.put(&q, &resp, ttl);
        let mut hit = cache.get(&q).expect("cache hit");
        patch_id(&mut hit, &query_bytes(0x9999, "example.com"));
        assert_eq!(&hit[0..2], &[0x99, 0x99], "cached hit re-ID'd");
    }
}
