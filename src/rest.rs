//! Local REST API (JSON over localhost TCP) — an agent-friendly mirror
//! of the gRPC service. Serves the OpenAPI spec at /openapi.yaml so
//! tools (and AI agents) can discover the whole API without prior
//! knowledge.
//!
//! Binds 127.0.0.1:8090 by default. Override with DNS_GUARD_HTTP_PORT;
//! disable entirely with DNS_GUARD_HTTP=0. Local-only by design — the
//! same trust boundary as any localhost service.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, KeepAliveStream, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Request;

use crate::grpc::proto::dns_guard_server::DnsGuard;
use crate::grpc::{proto, ProxyService};

const DEFAULT_PORT: u16 = 8090;

pub fn serve(service: Arc<ProxyService>) {
    if std::env::var("DNS_GUARD_HTTP").as_deref() == Ok("0") {
        return;
    }
    let port = std::env::var("DNS_GUARD_HTTP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    let app = Router::new()
        .route("/openapi.yaml", get(openapi))
        .route("/api/v1/status", get(api_status))
        .route("/api/v1/start", post(api_start))
        .route("/api/v1/stop", post(api_stop))
        .route("/api/v1/config", post(api_config))
        .route("/api/v1/policy", get(api_get_policy).put(api_set_policy))
        .route("/api/v1/stats", get(api_stats))
        .route("/api/v1/queries", get(api_queries))
        .route("/api/v1/queries/stream", get(api_queries_stream))
        .route("/api/v1/logs", get(api_logs))
        .route("/api/v1/logs/stream", get(api_logs_stream))
        .with_state(service);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("REST API bind {addr}: {e} — REST API disabled");
            return;
        }
    };
    let _ = listener.set_nonblocking(true);
    let listener = match tokio::net::TcpListener::from_std(listener) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("REST API setup: {e}");
            return;
        }
    };
    tokio::spawn(async move {
        log::info!("REST API on http://{addr}/openapi.yaml");
        if let Err(e) = axum::serve(listener, app).await {
            log::warn!("REST API error: {e}");
        }
    });
}

// ── Helpers ────────────────────────────────────────────────────────────

fn query_record_json(rec: &proto::QueryRecord) -> serde_json::Value {
    json!({
        "domain": rec.domain,
        "provider": rec.provider,
        "mode": rec.mode,
        "strategy": rec.strategy,
        "rtt_ms": rec.rtt_ms,
        "cached": rec.cached,
        "blocked": rec.blocked,
        "error": rec.error,
        "ts_ms": rec.ts_ms,
    })
}

fn error_body(e: tonic::Status) -> Json<serde_json::Value> {
    Json(json!({ "ok": false, "message": e.to_string() }))
}

async fn openapi() -> &'static str {
    include_str!("../docs/openapi.yaml")
}

// ── Handlers ───────────────────────────────────────────────────────────

async fn api_status(
    State(svc): State<Arc<ProxyService>>,
) -> Json<serde_json::Value> {
    match svc.status(Request::new(proto::StatusRequest {})).await {
        Ok(r) => {
            let s = r.into_inner();
            Json(json!({
                "running": s.running,
                "pid": s.pid,
                "mode": s.mode,
                "provider": s.provider,
                "strategy": s.strategy,
            }))
        }
        Err(e) => error_body(e),
    }
}

#[derive(serde::Deserialize)]
struct ConfigBody {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    strategy: String,
}

async fn api_start(
    State(svc): State<Arc<ProxyService>>,
    Json(body): Json<ConfigBody>,
) -> Json<serde_json::Value> {
    let req = proto::StartRequest {
        mode: body.mode,
        provider: body.provider,
        strategy: body.strategy,
    };
    match svc.start(Request::new(req)).await {
        Ok(r) => {
            let s = r.into_inner();
            Json(json!({ "ok": s.ok, "message": s.message }))
        }
        Err(e) => error_body(e),
    }
}

async fn api_stop(
    State(svc): State<Arc<ProxyService>>,
) -> Json<serde_json::Value> {
    match svc.stop(Request::new(proto::StopRequest {})).await {
        Ok(r) => {
            let s = r.into_inner();
            Json(json!({ "ok": s.ok, "message": s.message }))
        }
        Err(e) => error_body(e),
    }
}

async fn api_config(
    State(svc): State<Arc<ProxyService>>,
    Json(body): Json<ConfigBody>,
) -> Json<serde_json::Value> {
    let req = proto::ConfigRequest {
        mode: body.mode,
        provider: body.provider,
        strategy: body.strategy,
    };
    match svc.set_config(Request::new(req)).await {
        Ok(r) => {
            let s = r.into_inner();
            Json(json!({ "ok": s.ok }))
        }
        Err(e) => error_body(e),
    }
}

async fn api_get_policy(
    State(svc): State<Arc<ProxyService>>,
) -> Json<serde_json::Value> {
    match svc.get_policy(Request::new(proto::GetPolicyRequest {})).await {
        Ok(r) => {
            let p = r.into_inner();
            let rules: Vec<serde_json::Value> = p
                .rules
                .iter()
                .map(|r| {
                    json!({
                        "pattern": r.pattern,
                        "action": if r.action == 1 { "block" } else { "allow" },
                    })
                })
                .collect();
            Json(json!({ "rules": rules }))
        }
        Err(e) => error_body(e),
    }
}

#[derive(serde::Deserialize)]
struct PolicyBody {
    #[serde(default)]
    rules: Vec<PolicyRuleBody>,
}

#[derive(serde::Deserialize)]
struct PolicyRuleBody {
    pattern: String,
    #[serde(default)]
    action: String,
}

async fn api_set_policy(
    State(svc): State<Arc<ProxyService>>,
    Json(body): Json<PolicyBody>,
) -> Json<serde_json::Value> {
    let req = proto::Policy {
        rules: body
            .rules
            .into_iter()
            .map(|r| proto::policy::Rule {
                pattern: r.pattern,
                action: if r.action == "block" { 1 } else { 0 },
            })
            .collect(),
    };
    match svc.set_policy(Request::new(req)).await {
        Ok(r) => {
            let s = r.into_inner();
            Json(json!({ "ok": s.ok, "message": s.message }))
        }
        Err(e) => error_body(e),
    }
}

async fn api_stats(
    State(svc): State<Arc<ProxyService>>,
) -> Json<serde_json::Value> {
    let s = svc.stats_snapshot();
    Json(json!({
        "queries_total": s.queries_total,
        "cached_total": s.cached_total,
        "blocked_total": s.blocked_total,
        "errors_total": s.errors_total,
        "per_provider": s.per_provider,
        "top_domains": s.top_domains,
    }))
}

async fn api_queries(
    State(svc): State<Arc<ProxyService>>,
) -> Json<serde_json::Value> {
    let history: Vec<serde_json::Value> = svc
        .query_history_snapshot()
        .iter()
        .map(query_record_json)
        .collect();
    Json(json!({ "queries": history }))
}

async fn api_logs(
    State(svc): State<Arc<ProxyService>>,
) -> Json<serde_json::Value> {
    Json(json!({ "lines": svc.log_history_snapshot() }))
}

fn sse<S>(stream: S) -> Sse<KeepAliveStream<S>>
where
    S: futures_util::Stream<Item = Result<Event, Infallible>> + Send + 'static,
{
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn api_queries_stream(
    State(svc): State<Arc<ProxyService>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>> + Send> {
    let rx = svc.query_tx_subscribe();
    let stream = BroadcastStream::new(rx).map(|item| match item {
        Ok(rec) => Ok(Event::default()
            .event("query")
            .data(query_record_json(&rec).to_string())),
        Err(_) => Ok(Event::default().event("error").data("stream lagged")),
    });
    sse(stream)
}

async fn api_logs_stream(
    State(svc): State<Arc<ProxyService>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>> + Send> {
    let rx = svc.log_tx_subscribe();
    let stream = BroadcastStream::new(rx).map(|item| match item {
        Ok(line) => Ok(Event::default().event("log").data(line)),
        Err(_) => Ok(Event::default().event("error").data("stream lagged")),
    });
    sse(stream)
}
