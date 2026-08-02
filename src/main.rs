mod dns;
mod grpc;
mod rest;
mod state;

use clap::{Parser, Subcommand};
use dns::{DnsCache, DnsMode, DnsProvider, DnsStrategy};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use state as guard_state;

// ── Re-exported for grpc.rs ────────────────────────────────────────────

pub const LISTEN_ADDR: &str = "127.0.0.2";
pub const LISTEN_PORT: u16 = 53;

// ── CLI ────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "dns-guard", about = "System-wide encrypted DNS proxy")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// DNS mode (doh, dot) — standalone mode only
    #[arg(long = "mode")]
    mode: Option<String>,

    /// DNS provider (cloudflare, google, quad9)
    #[arg(long = "provider")]
    provider: Option<String>,

    /// Provider selection strategy (single, round-robin, failover)
    #[arg(long = "strategy")]
    strategy: Option<String>,

    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    #[arg(long = "install", help = "Set system DNS to 127.0.0.2")]
    install: bool,

    #[arg(long = "uninstall", help = "Restore default DNS servers")]
    uninstall: bool,

    /// Run the proxy as a background daemon (direct mode only)
    #[arg(long = "background")]
    background: bool,

    /// Override the state directory (~/.config/dns-guard) — used by the
    /// GUI to point a root-spawned proxy at the user's config dir.
    #[arg(long = "state-dir")]
    state_dir: Option<String>,

    /// Output start/stop/status responses as JSON
    #[arg(long = "json", global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the silent gRPC server (for GUI / remote control)
    Serve {
        #[arg(long)]
        listen: Option<String>,

        /// Detach into the background and write a pidfile
        #[arg(long)]
        daemon: bool,
    },
    /// CLI client: tell a running server to start the proxy
    Start {
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        strategy: Option<String>,
        #[arg(long)]
        addr: Option<String>,
    },
    /// CLI client: tell a running server to stop the proxy
    Stop {
        #[arg(long)]
        addr: Option<String>,
    },
    /// CLI client: get status from a running server
    Status {
        #[arg(long)]
        addr: Option<String>,
    },
    /// CLI client: tail logs from a running server
    Logs {
        #[arg(long)]
        addr: Option<String>,
    },
    /// CLI client: send the sudo password to a running server
    SetPassword {
        #[arg(long)]
        password: String,
        #[arg(long)]
        addr: Option<String>,
    },
    /// CLI client: query live stats from a running server
    Stats {
        #[arg(long)]
        addr: Option<String>,
    },
    /// CLI client: list or modify the block/allow policy
    Policy {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long, help = "Block a domain (and its subdomains)")]
        block: Option<String>,
        #[arg(long, help = "Allow a domain (overrides an earlier block)")]
        allow: Option<String>,
        #[arg(long, help = "Remove all rules")]
        clear: bool,
    },
}

/// Default Unix socket path (shared with the GUI): lives in the user's
/// config dir so only the owner can reach the daemon.
fn default_socket() -> String {
    guard_state::socket_path().display().to_string()
}

// ── Config file ─────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    strategy: String,
    #[serde(default)]
    policy: Vec<PolicyRule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "doh".into(),
            provider: "cloudflare".into(),
            strategy: "single".into(),
            policy: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PolicyRule {
    pattern: String,
    action: String,
}

/// Block/allow rules evaluated per-query. Any ALLOW match overrides all
/// BLOCK matches (allowlists win); the default is allow. Patterns match
/// the domain itself and any subdomain ("example.com" matches
/// "example.com" + "a.example.com").
#[derive(Clone, Default)]
struct Policy {
    rules: Vec<PolicyRule>,
}

impl Policy {
    fn from_config(cfg: &Config) -> Self {
        Policy { rules: cfg.policy.clone() }
    }

    fn blocked(&self, domain: &str) -> bool {
        let mut blocked = false;
        for r in &self.rules {
            if pattern_matches(&r.pattern, domain) {
                if r.action == "allow" {
                    return false;
                }
                blocked = true;
            }
        }
        blocked
    }
}

fn pattern_matches(pattern: &str, domain: &str) -> bool {
    let pat = pattern.trim().trim_start_matches('.').to_ascii_lowercase();
    if pat.is_empty() || domain.is_empty() {
        return false;
    }
    domain == pat || domain.ends_with(&format!(".{pat}"))
}

impl Config {
    fn path() -> PathBuf {
        // Same directory as all other state files, so DNS_GUARD_DIR /
        // --state-dir (root-spawned proxies) and the daemon agree on
        // where config.json lives.
        guard_state::dir().join("config.json")
    }

    fn load() -> Self {
        let path = Self::path();
        match std::fs::read_to_string(&path) {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(c) => c,
                Err(e) => {
                    error!("failed to parse config: {e}, using defaults");
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    fn save(&self) {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(self) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&path, &s) {
                    error!("failed to save config: {e}");
                } else {
                    info!("config saved to {}", path.display());
                }
            }
            Err(e) => error!("failed to serialize config: {e}"),
        }
    }
}

// ── Main ───────────────────────────────────────────────────────────────

/// When spawned via AppleScript's `do shell script ... with administrator
/// privileges`, the privileged spawn context (launchd/securityd) leaves
/// the child with SIGINT/SIGTERM blocked (and possibly ignored), so the
/// ctrlc handler never fires and `kill -INT` cannot stop the proxy.
/// Reset the mask and dispositions so graceful shutdown works.
#[cfg(target_os = "macos")]
fn reset_signal_state() {
    unsafe {
        let mut set = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
}

/// The daemonize fork() aborts with `objc_initializeAfterForkError`
/// ("+[NSNumber initialize] may have been in progress in another thread
/// when fork() was called ... Crashing instead") unless
/// OBJC_DISABLE_INITIALIZE_FORK_SAFETY is in the environment BEFORE the
/// ObjC runtime initializes (the guard is read during libobjc's dyld
/// init, so `std::env::set_var` inside main() is too late). Spawners
/// (sudo, osascript, launchd) generally don't set it, so re-exec
/// ourselves with it set — pid and argv are preserved, and this must
/// run before ANY framework (SystemConfiguration, tokio) is touched.
#[cfg(target_os = "macos")]
fn ensure_objc_fork_safety() {
    use std::os::unix::process::CommandExt;

    if std::env::var_os("OBJC_DISABLE_INITIALIZE_FORK_SAFETY").is_some() {
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mut cmd = std::process::Command::new(&exe);
    let _ = cmd
        .args(&args)
        .env("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES")
        .exec();
    // exec() only returns on error — fall through and let the crash happen.
}

fn main() {
    #[cfg(target_os = "macos")]
    {
        reset_signal_state();
        ensure_objc_fork_safety();
    }

    let cli = Cli::parse();

    // Point all state/config/log paths at an explicit directory if asked
    // (the GUI passes this so a root-spawned proxy uses the user's dir).
    if let Some(ref d) = cli.state_dir {
        std::env::set_var("DNS_GUARD_DIR", d);
    }

    // Daemonize BEFORE the tokio runtime starts — otherwise the child
    // inherits a broken I/O driver and bind() returns EBADF.
    if let Some(Commands::Serve { daemon: true, .. }) = &cli.command {
        let dir = guard_state::dir();
        let _ = std::fs::create_dir_all(&dir);
        daemonize(&guard_state::server_log_path()).unwrap_or_else(|e| {
            eprintln!("daemonize: {e}");
            std::process::exit(1);
        });
        let _ = std::fs::write(guard_state::server_pid_path(), std::process::id().to_string());
    }

    // Same for the standalone `--background` path: fork before the runtime
    // so the daemonized proxy doesn't inherit a broken I/O driver (which
    // panics with EBADF on shutdown).
    if cli.command.is_none() && cli.background && !cli.install && !cli.uninstall {
        let dir = guard_state::dir();
        let _ = std::fs::create_dir_all(&dir);
        daemonize(&guard_state::proxy_log_path()).unwrap_or_else(|e| {
            eprintln!("daemonize: {e}");
            std::process::exit(1);
        });
    }

    env_logger::Builder::new()
        .filter_level(if cli.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .format_timestamp_secs()
        .init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async_main(cli));
}

async fn async_main(cli: Cli) {
    let json = cli.json;
    let background = cli.background;

    match cli.command {
        Some(Commands::Serve { listen, daemon }) => {
            let sock = listen.unwrap_or_else(default_socket);
            cmd_serve(&sock, daemon).await;
        }
        Some(Commands::Start { mode, provider, strategy, addr }) => {
            let sock = addr.unwrap_or_else(default_socket);
            cmd_client_start(&sock, mode, provider, strategy, json).await;
        }
        Some(Commands::Stop { addr }) => {
            let sock = addr.unwrap_or_else(default_socket);
            cmd_client_stop(&sock, json).await;
        }
        Some(Commands::Status { addr }) => {
            let sock = addr.unwrap_or_else(default_socket);
            cmd_client_status(&sock, json).await;
        }
        Some(Commands::Logs { addr }) => {
            let sock = addr.unwrap_or_else(default_socket);
            cmd_client_logs(&sock).await;
        }
        Some(Commands::SetPassword { password, addr }) => {
            let sock = addr.unwrap_or_else(default_socket);
            cmd_client_set_password(&sock, &password, json).await;
        }
        Some(Commands::Stats { addr }) => {
            let sock = addr.unwrap_or_else(default_socket);
            cmd_client_stats(&sock, json).await;
        }
        Some(Commands::Policy { addr, block, allow, clear }) => {
            let sock = addr.unwrap_or_else(default_socket);
            cmd_client_policy(&sock, block, allow, clear, json).await;
        }
        None => {
            cmd_standalone(cli, background);
        }
    }
}

// ── daemonize helper ───────────────────────────────────────────────────

#[cfg(unix)]
fn daemonize(log_path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;

    // NB: can NOT use log::info! here — env_logger isn't initialised yet.

    unsafe {
        let pid = libc::fork();
        if pid < 0 { return Err("fork failed".into()); }
        if pid > 0 { std::process::exit(0); }

        if libc::setsid() < 0 { return Err("setsid failed".into()); }
    }

    let file = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(log_path)
        .unwrap_or_else(|_| std::fs::File::create("/dev/null").unwrap());

    // World-readable so a user-level daemon can tail logs written by a
    // root-spawned proxy (AuthorizationExecuteWithPrivileges).
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(log_path, std::fs::Permissions::from_mode(0o644));
    }

    unsafe {
        let fd = file.as_raw_fd();
        libc::dup2(fd, 0);
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
        if fd > 2 { libc::close(fd); }
    }

    Ok(())
}

#[cfg(windows)]
fn daemonize(_log_path: &std::path::Path) -> Result<(), String> {
    Err("daemonization is not supported on Windows. Use --background with a process manager.".into())
}

// ── serve command ──────────────────────────────────────────────────────

async fn cmd_serve(socket_path: &str, daemon: bool) {
    if daemon {
        // Daemonization already handled before the tokio runtime started.
        // stdout/stderr are redirected to the server log file.
    }

    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    info!("starting gRPC server on {socket_path}");
    let _ = std::fs::remove_file(socket_path);

    let service = Arc::new(grpc::ProxyService::load_or_new());
    let svc = grpc::proto::dns_guard_server::DnsGuardServer::new(service.clone());
    rest::serve(service);

    let listener = match tokio::net::UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => { error!("bind {socket_path}: {e}"); std::process::exit(1); }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Owner-only so other local users cannot reach the gRPC API
        // (which controls DNS + stores the sudo password).
        if let Err(e) = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)) {
            warn!("chmod {socket_path}: {e}");
        }
    }

    let sock_cleanup = socket_path.to_string();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate()
            ).expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        info!("received signal, shutting down daemon...");
        let _ = std::fs::remove_file(guard_state::server_pid_path());
        let _ = std::fs::remove_file(&sock_cleanup);
        std::process::exit(0);
    });

    if let Err(e) = tonic::transport::Server::builder()
        .add_service(svc)
        .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
        .await
    {
        error!("gRPC server error: {e}");
    }

    let _ = std::fs::remove_file(guard_state::server_pid_path());
    let _ = std::fs::remove_file(socket_path);
}

// ── CLI client commands ────────────────────────────────────────────────

use std::pin::Pin;
use std::future::Future;
use tower::Service;

#[derive(Clone)]
struct UdsConnector {
    path: String,
}

impl Service<tonic::transport::Uri> for UdsConnector {
    type Response = hyper_util::rt::TokioIo<tokio::net::UnixStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: tonic::transport::Uri) -> Self::Future {
        let path = self.path.clone();
        Box::pin(async move {
            let stream = tokio::net::UnixStream::connect(&path).await?;
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

fn client_channel(path: &str) -> tonic::transport::Channel {
    tonic::transport::Endpoint::try_from("http://[::]:0")
        .expect("invalid endpoint")
        .connect_with_connector_lazy(UdsConnector { path: path.to_string() })
}

async fn cmd_client_start(
    addr: &str,
    mode: Option<String>,
    provider: Option<String>,
    strategy: Option<String>,
    json: bool,
) {
    use grpc::proto::dns_guard_client::DnsGuardClient;
    use grpc::proto::StartRequest;

    let channel = client_channel(addr);
    let mut client = DnsGuardClient::new(channel);

    match client.start(tonic::Request::new(StartRequest {
        mode: mode.unwrap_or_default(),
        provider: provider.unwrap_or_default(),
        strategy: strategy.unwrap_or_default(),
    })).await {
        Ok(r) => {
            let resp = r.into_inner();
            if json {
                println!("{}", serde_json::json!({"ok": resp.ok, "message": resp.message}));
            } else if resp.ok {
                println!("proxy started");
            } else {
                eprintln!("{}", resp.message);
            }
            if !resp.ok { std::process::exit(1); }
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"ok": false, "message": format!("{e}")}));
            } else {
                eprintln!("error: {e}");
            }
            std::process::exit(1);
        }
    }
}

async fn cmd_client_stop(addr: &str, json: bool) {
    use grpc::proto::dns_guard_client::DnsGuardClient;
    use grpc::proto::StopRequest;

    let channel = client_channel(addr);
    let mut client = DnsGuardClient::new(channel);

    match client.stop(tonic::Request::new(StopRequest {})).await {
        Ok(r) => {
            let resp = r.into_inner();
            let msg = if resp.message.is_empty() {
                if resp.ok { "proxy stopped".to_string() } else { "stop failed".to_string() }
            } else {
                resp.message.clone()
            };
            if json {
                println!("{}", serde_json::json!({"ok": resp.ok, "message": msg}));
            } else if resp.ok {
                println!("proxy stopped");
            } else {
                eprintln!("{}", resp.message);
            }
            if !resp.ok { std::process::exit(1); }
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"ok": false, "message": format!("{e}")}));
            } else {
                eprintln!("error: {e}");
            }
            std::process::exit(1);
        }
    }
}

async fn cmd_client_status(addr: &str, json: bool) {
    use grpc::proto::dns_guard_client::DnsGuardClient;
    use grpc::proto::StatusRequest;

    let channel = client_channel(addr);
    let mut client = DnsGuardClient::new(channel);

    match client.status(tonic::Request::new(StatusRequest {})).await {
        Ok(r) => {
            let s = r.into_inner();
            if json {
                println!("{}", serde_json::json!({
                    "running": s.running,
                    "pid": s.pid,
                    "mode": s.mode,
                    "provider": s.provider,
                    "strategy": s.strategy,
                }));
            } else {
                println!("running: {}", s.running);
                println!("pid: {}", s.pid);
                println!("mode: {}", s.mode);
                println!("provider: {}", s.provider);
                println!("strategy: {}", s.strategy);
            }
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"running": false, "pid": 0, "mode": "", "provider": "", "strategy": ""}));
            } else {
                eprintln!("error: {e}");
            }
            std::process::exit(1);
        }
    }
}

async fn cmd_client_logs(addr: &str) {
    use grpc::proto::dns_guard_client::DnsGuardClient;
    use grpc::proto::LogsRequest;
    use tokio_stream::StreamExt;

    let channel = client_channel(addr);
    let mut client = DnsGuardClient::new(channel);

    let mut stream = match client.logs(tonic::Request::new(LogsRequest {})).await {
        Ok(r) => r.into_inner(),
        Err(e) => { eprintln!("error: {e}"); return; }
    };

    while let Some(entry) = stream.next().await {
        match entry {
            Ok(e) => println!("{}", e.line),
            Err(e) => eprintln!("stream error: {e}"),
        }
    }
}

async fn cmd_client_set_password(addr: &str, password: &str, json: bool) {
    use grpc::proto::dns_guard_client::DnsGuardClient;
    use grpc::proto::PasswordRequest;

    let channel = client_channel(addr);
    let mut client = DnsGuardClient::new(channel);

    match client.set_password(tonic::Request::new(PasswordRequest {
        password: password.to_string(),
    })).await {
        Ok(r) => {
            let resp = r.into_inner();
            if json {
                println!("{}", serde_json::json!({"ok": resp.ok, "message": resp.message}));
            } else if resp.ok {
                println!("authenticated");
            } else {
                eprintln!("{}", resp.message);
            }
            if !resp.ok { std::process::exit(1); }
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"ok": false, "message": format!("{e}")}));
            } else {
                eprintln!("error: {e}");
            }
            std::process::exit(1);
        }
    }
}

async fn cmd_client_stats(addr: &str, json: bool) {
    use grpc::proto::dns_guard_client::DnsGuardClient;
    use grpc::proto::GetStatsRequest;

    let channel = client_channel(addr);
    let mut client = DnsGuardClient::new(channel);

    match client.get_stats(tonic::Request::new(GetStatsRequest {})).await {
        Ok(r) => {
            let s = r.into_inner();
            if json {
                println!("{}", serde_json::json!({
                    "queries_total": s.queries_total,
                    "cached_total": s.cached_total,
                    "blocked_total": s.blocked_total,
                    "errors_total": s.errors_total,
                    "per_provider": s.per_provider,
                    "top_domains": s.top_domains,
                }));
            } else {
                println!("queries: {}", s.queries_total);
                println!("cached:  {}", s.cached_total);
                println!("blocked: {}", s.blocked_total);
                println!("errors:  {}", s.errors_total);
                println!("per provider:");
                for (p, n) in &s.per_provider {
                    println!("  {p}: {n}");
                }
                println!("top domains:");
                for (d, n) in &s.top_domains {
                    println!("  {d}: {n}");
                }
            }
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"error": format!("{e}")}));
            } else {
                eprintln!("error: {e}");
            }
            std::process::exit(1);
        }
    }
}

async fn cmd_client_policy(
    addr: &str,
    block: Option<String>,
    allow: Option<String>,
    clear: bool,
    json: bool,
) {
    use grpc::proto::dns_guard_client::DnsGuardClient;
    use grpc::proto::{GetPolicyRequest, Policy};

    let channel = client_channel(addr);
    let mut client = DnsGuardClient::new(channel);

    let current = match client.get_policy(tonic::Request::new(GetPolicyRequest {})).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"ok": false, "message": format!("{e}")}));
            } else {
                eprintln!("error: {e}");
            }
            std::process::exit(1);
        }
    };

    // No mutation flags: just print the current policy.
    if block.is_none() && allow.is_none() && !clear {
        if json {
            let rules: Vec<serde_json::Value> = current
                .rules
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "pattern": r.pattern,
                        "action": if r.action == 1 { "block" } else { "allow" },
                    })
                })
                .collect();
            println!("{}", serde_json::json!({"rules": rules}));
        } else if current.rules.is_empty() {
            println!("policy: no rules (allow all)");
        } else {
            for r in &current.rules {
                let action = if r.action == 1 { "block" } else { "allow" };
                println!("{action} {}", r.pattern);
            }
        }
        return;
    }

    let mut rules = current.rules;
    if clear {
        rules.clear();
    }
    if let Some(pat) = block {
        rules.push(grpc::proto::policy::Rule { pattern: pat, action: 1 });
    }
    if let Some(pat) = allow {
        rules.push(grpc::proto::policy::Rule { pattern: pat, action: 0 });
    }

    match client
        .set_policy(tonic::Request::new(Policy { rules }))
        .await
    {
        Ok(r) => {
            let resp = r.into_inner();
            if json {
                println!("{}", serde_json::json!({"ok": resp.ok, "message": resp.message}));
            } else if resp.ok {
                println!("policy updated");
            } else {
                eprintln!("{}", resp.message);
            }
            if !resp.ok {
                std::process::exit(1);
            }
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"ok": false, "message": format!("{e}")}));
            } else {
                eprintln!("error: {e}");
            }
            std::process::exit(1);
        }
    }
}

// ── Standalone mode (existing behaviour) ───────────────────────────────

fn cmd_standalone(cli: Cli, background: bool) {
    if cli.uninstall {
        check_root();
        uninstall_system_dns();
        return;
    }
    if cli.install {
        check_root();
        install_system_dns();
        return;
    }

    let mut config = Config::load();
    info!("loaded config from {}", Config::path().display());

    if let Some(ref m) = cli.mode { config.mode = m.clone(); }
    if let Some(ref p) = cli.provider { config.provider = p.clone(); }
    if let Some(ref s) = cli.strategy { config.strategy = s.clone(); }

    if background {
        // Daemonize already happened in main() before the tokio runtime was
        // created; nothing to do here.
    } else {
        check_root();
    }

    info!("proxy boot pid={} mode={} provider={} strategy={}",
        std::process::id(), config.mode, config.provider, config.strategy);

    setup_loopback();
    info!("loopback alias configured");
    install_system_dns();
    info!("system DNS configured");

    let pid = std::process::id();
    guard_state::save(&guard_state::State {
        running: true,
        pid,
        mode: config.mode.clone(),
        provider: config.provider.clone(),
        strategy: config.strategy.clone(),
    });

    info!("dns-guard starting pid={pid}");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("failed to set Ctrl-C handler");

    start_network_watcher(running.clone());

    let policy = Arc::new(parking_lot::RwLock::new(Policy::from_config(&config)));
    let events = Arc::new(QueryEvents::open().unwrap_or_else(QueryEvents::disabled));

    // Hot-swap loop: run_doh/run_dot return Some(cfg) when mode changes
    while running.load(Ordering::SeqCst) {
        let mode = parse_mode(&config.mode);
        let provider = parse_provider(&config.provider);
        let strategy = parse_strategy(&config.strategy);

        info!("listening on {LISTEN_ADDR}:{LISTEN_PORT} ({mode:?} → {provider:?} / {strategy:?})");

        let changed = match mode {
            DnsMode::DoH => run_doh(strategy, provider, policy.clone(), events.clone(), &running),
            DnsMode::DoT => run_dot(strategy, provider, policy.clone(), events.clone(), &running),
        };

        if let Some(c) = changed {
            config = c;
            guard_state::save(&guard_state::State {
                running: true,
                pid,
                mode: config.mode.clone(),
                provider: config.provider.clone(),
                strategy: config.strategy.clone(),
            });
            info!("config hot-swapped to {} {} {}", config.mode, config.provider, config.strategy);
        }
    }

    config.save();

    info!("restoring system DNS...");
    uninstall_system_dns();
    teardown_loopback();
    guard_state::clear();
    info!("dns-guard stopped");
}

// ── DNS proxy core ────────────────────────────────────────────────────
//
// The proxy is a multi-threaded relay:
//   - One UDP dispatch thread (the caller of run_proxy_loop) receives
//     datagrams and hands each query to a bounded worker pool. Workers
//     resolve via DoH/DoT and reply out of order (safe: DNS matches
//     replies by transaction ID).
//   - A TCP listener on :53 handles clients retrying truncated (TC=1)
//     responses, resolving inline per connection.
//   - Responses are cached by question (TTL-aware); cached replies are
//     re-ID'd to the requester.
//   - Failover state is shared and thread-safe; round-robin is an
//     atomic counter.

type Resolver = dyn Fn(&[u8], DnsProvider) -> Result<Vec<u8>, String> + Send + Sync;

const UPLINK_WORKERS: usize = 8;
const TCP_MAX_CONNS: usize = 32;

struct Job {
    query: Vec<u8>,
    src: SocketAddr,
    target: DnsProvider,
    strategy: DnsStrategy,
}

/// Sticky provider index used by the failover strategy. Whether it is
/// consulted is decided per-query by the current strategy (which can
/// hot-swap), so the state itself is strategy-agnostic.
struct FailoverState {
    current: parking_lot::Mutex<usize>,
}

impl FailoverState {
    fn new(base: DnsProvider) -> Self {
        let current = dns::ALL_PROVIDERS
            .iter()
            .position(|p| *p == base)
            .unwrap_or(0);
        Self { current: parking_lot::Mutex::new(current) }
    }

    fn target(&self) -> DnsProvider {
        dns::ALL_PROVIDERS[*self.current.lock()]
    }

    fn on_failure(&self, p: DnsProvider, strategy: DnsStrategy) {
        if strategy != DnsStrategy::Failover {
            return;
        }
        let mut c = self.current.lock();
        if dns::ALL_PROVIDERS[*c] == p {
            *c = (*c + 1) % dns::ALL_PROVIDERS.len();
            info!("failing over to {:?}", dns::ALL_PROVIDERS[*c]);
        }
    }
}

fn pick_target(
    strategy: DnsStrategy,
    provider: DnsProvider,
    failover: &FailoverState,
) -> DnsProvider {
    match strategy {
        DnsStrategy::RoundRobin => dns::next_round_robin(),
        DnsStrategy::Failover => failover.target(),
        DnsStrategy::Single => provider,
    }
}

// ── Per-query event log ────────────────────────────────────────────────
//
// The proxy appends one JSON line per query to query.log (world-readable,
// truncated at proxy start). The daemon tails it and serves WatchQueries /
// GetStats, so both supervision models (CLI child pipes and GUI-adopted
// file tailing) produce the same query feed.

#[derive(Serialize)]
struct QueryRecordData {
    domain: String,
    provider: String,
    mode: String,
    strategy: String,
    rtt_ms: u64,
    cached: bool,
    blocked: bool,
    error: bool,
    ts_ms: u64,
}

pub struct QueryEvents {
    inner: parking_lot::Mutex<Option<std::io::BufWriter<std::fs::File>>>,
}

impl QueryEvents {
    /// Create (truncating) query.log in the state dir. Returns None when
    /// the file cannot be opened — event logging is best-effort.
    fn open() -> Option<Self> {
        let dir = guard_state::dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = guard_state::query_log_path();
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        }
        Some(QueryEvents {
            inner: parking_lot::Mutex::new(Some(std::io::BufWriter::new(f))),
        })
    }

    /// Null emitter for tests and when logging is unavailable.
    fn disabled() -> Self {
        QueryEvents { inner: parking_lot::Mutex::new(None) }
    }

    fn emit(&self, rec: &QueryRecordData) {
        let Ok(line) = serde_json::to_string(rec) else { return };
        let mut w = self.inner.lock();
        if let Some(w) = w.as_mut() {
            use std::io::Write;
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
            let _ = w.flush();
        }
    }
}

fn provider_str(p: DnsProvider) -> &'static str {
    match p {
        DnsProvider::Cloudflare => "cloudflare",
        DnsProvider::Google => "google",
        DnsProvider::Quad9 => "quad9",
    }
}

fn mode_str(m: DnsMode) -> &'static str {
    match m {
        DnsMode::DoH => "doh",
        DnsMode::DoT => "dot",
    }
}

fn strategy_str(s: DnsStrategy) -> &'static str {
    match s {
        DnsStrategy::Single => "single",
        DnsStrategy::RoundRobin => "round-robin",
        DnsStrategy::Failover => "failover",
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Resolve a query (policy check, then cache), returning a full response
/// with the requester's transaction ID patched in. Never fails: on
/// upstream error it returns SERVFAIL so the client doesn't hang; blocked
/// domains get NXDOMAIN. Every query is emitted to the event log.
#[allow(clippy::too_many_arguments)]
fn resolve(
    query: &[u8],
    target: DnsProvider,
    strategy: DnsStrategy,
    mode: DnsMode,
    resolver: &Arc<Resolver>,
    failover: &FailoverState,
    cache: &DnsCache,
    policy: &Arc<parking_lot::RwLock<Policy>>,
    events: &Arc<QueryEvents>,
) -> Vec<u8> {
    let started = Instant::now();
    let domain = dns::extract_qname(query).unwrap_or_default();

    let emit = |blocked: bool, error: bool, cached: bool, rtt: u64| {
        events.emit(&QueryRecordData {
            domain: domain.clone(),
            provider: provider_str(target).to_string(),
            mode: mode_str(mode).to_string(),
            strategy: strategy_str(strategy).to_string(),
            rtt_ms: rtt,
            cached,
            blocked,
            error,
            ts_ms: now_ms(),
        });
    };

    if policy.read().blocked(&domain) {
        emit(true, false, false, 0);
        return dns::nxdomain(query);
    }

    if let Some(mut resp) = cache.get(query) {
        dns::patch_id(&mut resp, query);
        emit(false, false, true, 0);
        return resp;
    }

    let resp = match (*resolver)(query, target) {
        Ok(r) => {
            if let Some(ttl) = dns::response_ttl(&r) {
                cache.put(query, &r, ttl);
            }
            emit(false, false, false, started.elapsed().as_millis() as u64);
            r
        }
        Err(e) => {
            failover.on_failure(target, strategy);
            warn!("{target:?} failed: {e}");
            emit(false, true, false, started.elapsed().as_millis() as u64);
            dns::servfail(query)
        }
    };
    resp
}

#[allow(clippy::too_many_arguments)]
fn spawn_udp_workers(
    sock: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
    failover: Arc<FailoverState>,
    cache: Arc<DnsCache>,
    policy: Arc<parking_lot::RwLock<Policy>>,
    events: Arc<QueryEvents>,
    mode: DnsMode,
    n: usize,
) -> (Vec<SyncSender<Job>>, Vec<JoinHandle<()>>) {
    let mut txs = Vec::with_capacity(n);
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let (tx, rx) = sync_channel::<Job>(64);
        let s = sock.clone();
        let r = resolver.clone();
        let f = failover.clone();
        let c = cache.clone();
        let p = policy.clone();
        let e = events.clone();
        handles.push(std::thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                let mut resp = resolve(
                    &job.query,
                    job.target,
                    job.strategy,
                    mode,
                    &r,
                    &f,
                    &c,
                    &p,
                    &e,
                );
                if resp.len() > dns::MAX_UDP_DNS {
                    dns::set_tc(&mut resp, dns::MAX_UDP_DNS);
                }
                let _ = s.send_to(&resp, job.src);
            }
        }));
        txs.push(tx);
    }
    (txs, handles)
}

/// Dispatch a UDP query to a worker, applying backpressure. Returns
/// false if the proxy should stop (shutdown requested or workers gone).
fn dispatch_udp(
    txs: &[SyncSender<Job>],
    rr: &AtomicUsize,
    query: Vec<u8>,
    src: SocketAddr,
    target: DnsProvider,
    strategy: DnsStrategy,
    running: &AtomicBool,
) -> bool {
    loop {
        let tx = &txs[rr.fetch_add(1, Ordering::Relaxed) % txs.len()];
        match tx.try_send(Job { query: query.clone(), src, target, strategy }) {
            Ok(()) => return true,
            Err(TrySendError::Full(_)) => {
                std::thread::sleep(Duration::from_millis(10));
                if !running.load(Ordering::SeqCst) {
                    return false;
                }
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

/// Read exactly `buf.len()` bytes from a TCP stream, retrying on
/// Interrupted and translating EOF/errors cleanly.
fn read_exact(stream: &mut TcpStream, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => buf = &mut buf[n..],
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_tcp_conn(
    stream: TcpStream,
    strategy: DnsStrategy,
    provider: DnsProvider,
    mode: DnsMode,
    resolver: Arc<Resolver>,
    failover: Arc<FailoverState>,
    cache: Arc<DnsCache>,
    policy: Arc<parking_lot::RwLock<Policy>>,
    events: Arc<QueryEvents>,
) {
    let mut stream = stream;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut len_buf = [0u8; 2];
    while let Ok(()) = read_exact(&mut stream, &mut len_buf) {
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return;
        }
        let mut query = vec![0u8; len];
        if read_exact(&mut stream, &mut query).is_err() {
            return;
        }
        if query.len() < 12 {
            continue;
        }
        let target = pick_target(strategy, provider, &failover);
        let resp = resolve(
            &query,
            target,
            strategy,
            mode,
            &resolver,
            &failover,
            &cache,
            &policy,
            &events,
        );
        if resp.len() > u16::MAX as usize {
            continue;
        }
        let len_be = (resp.len() as u16).to_be_bytes();
        if stream.write_all(&len_be).is_err() || stream.write_all(&resp).is_err() {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_tcp_thread(
    running: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    resolver: Arc<Resolver>,
    failover: Arc<FailoverState>,
    cache: Arc<DnsCache>,
    policy: Arc<parking_lot::RwLock<Policy>>,
    events: Arc<QueryEvents>,
    cfg_tx: std::sync::mpsc::Sender<Config>,
    expected_mode: DnsMode,
    mut provider: DnsProvider,
    mut strategy: DnsStrategy,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(format!("{LISTEN_ADDR}:{LISTEN_PORT}")) {
            Ok(l) => l,
            Err(e) => {
                error!("tcp bind {LISTEN_ADDR}:{LISTEN_PORT}: {e}");
                return;
            }
        };
        if let Err(e) = listener.set_nonblocking(true) {
            error!("tcp set_nonblocking: {e}");
            return;
        }

        let conns = Arc::new(AtomicUsize::new(0));
        let mut last_check = Instant::now();

        while running.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
            if last_check.elapsed() >= Duration::from_millis(500) {
                last_check = Instant::now();
                if let Some(cfg) = check_reload(
                    expected_mode,
                    &mut provider,
                    &mut strategy,
                    &policy,
                ) {
                    let _ = cfg_tx.send(cfg);
                    break;
                }
            }

            match listener.accept() {
                Ok((stream, _)) => {
                    if conns.load(Ordering::SeqCst) >= TCP_MAX_CONNS {
                        drop(stream);
                        continue;
                    }
                    conns.fetch_add(1, Ordering::SeqCst);
                    let (r, f, c, p, e) = (
                        resolver.clone(),
                        failover.clone(),
                        cache.clone(),
                        policy.clone(),
                        events.clone(),
                    );
                    let conns = conns.clone();
                    std::thread::spawn(move || {
                        handle_tcp_conn(stream, strategy, provider, expected_mode, r, f, c, p, e);
                        conns.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    error!("tcp accept: {e}");
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    })
}

/// Shared relay loop for both DoH and DoT. Returns Some(new_config)
/// when the mode changed (hot-swap) and None on shutdown.
fn run_proxy_loop(
    mode: DnsMode,
    resolver: Arc<Resolver>,
    mut strategy: DnsStrategy,
    mut provider: DnsProvider,
    policy: Arc<parking_lot::RwLock<Policy>>,
    events: Arc<QueryEvents>,
    running: &Arc<AtomicBool>,
) -> Option<Config> {
    let sock = Arc::new(create_udp_socket().unwrap_or_else(|e| {
        panic!("bind {LISTEN_ADDR}:{LISTEN_PORT}: {e}. Is another instance running?");
    }));
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();

    let failover = Arc::new(FailoverState::new(provider));
    let cache = Arc::new(DnsCache::new());

    let (txs, workers) = spawn_udp_workers(
        sock.clone(),
        resolver.clone(),
        failover.clone(),
        cache.clone(),
        policy.clone(),
        events.clone(),
        mode,
        UPLINK_WORKERS,
    );

    let stop_tcp = Arc::new(AtomicBool::new(false));
    let (cfg_tx, cfg_rx) = channel::<Config>();
    let tcp_thread = spawn_tcp_thread(
        running.clone(),
        stop_tcp.clone(),
        resolver,
        failover.clone(),
        cache,
        policy.clone(),
        events.clone(),
        cfg_tx,
        mode,
        provider,
        strategy,
    );

    let rr = AtomicUsize::new(0);
    let mut buf = [0u8; dns::MAX_UDP_DNS];
    let mut last_check = Instant::now();

    // One non-None return from this loop tears down workers + TCP.
    let mut mode_changed: Option<Config> = None;

    while mode_changed.is_none() {
        if last_check.elapsed() >= Duration::from_millis(500) {
            last_check = Instant::now();
            if let Some(cfg) = check_reload(mode, &mut provider, &mut strategy, &policy) {
                mode_changed = Some(cfg);
                break;
            }
        }
        if let Ok(cfg) = cfg_rx.try_recv() {
            mode_changed = Some(cfg);
            break;
        }
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if n < 12 {
                    continue;
                }
                let target = pick_target(strategy, provider, &failover);
                if !dispatch_udp(
                    &txs,
                    &rr,
                    buf[..n].to_vec(),
                    src,
                    target,
                    strategy,
                    running,
                ) {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                if running.load(Ordering::SeqCst) {
                    error!("recv: {e}");
                }
            }
        }
    }

    stop_tcp.store(true, Ordering::SeqCst);
    drop(txs);
    for w in workers {
        let _ = w.join();
    }
    let _ = tcp_thread.join();

    mode_changed
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    /// Build a response with one A record (TTL 300) that echoes the
    /// query's ID — mirrors what a real upstream does.
    fn fake_response(query: &[u8]) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&query[..12]);
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[6..8].copy_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        // question (assume the caller supplied exactly one A question)
        resp.extend_from_slice(&query[12..]);
        // answer: pointer to question name + A record
        resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x04, 93, 184, 216, 34]);
        resp
    }

    fn a_query(id: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        q.extend_from_slice(&[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        q
    }

    /// Send a query through the real dispatch + worker pool + cache
    /// machinery and receive the reply on the same socket.
    fn relay_roundtrip(
        sock: &Arc<UdpSocket>,
        txs: &[SyncSender<Job>],
        rr: &AtomicUsize,
        query: &[u8],
        target: DnsProvider,
        strategy: DnsStrategy,
    ) -> Vec<u8> {
        assert!(dispatch_udp(
            txs,
            rr,
            query.to_vec(),
            sock.local_addr().unwrap(),
            target,
            strategy,
            &AtomicBool::new(true),
        ));
        let mut buf = [0u8; 512];
        let (n, _) = sock.recv_from(&mut buf).expect("reply");
        buf[..n].to_vec()
    }

    #[test]
    fn worker_pool_cache_and_servfail() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        sock.set_read_timeout(Some(Duration::from_millis(2000))).unwrap();

        let resolver: Arc<Resolver> = Arc::new(|query, _p| Ok(fake_response(query)));
        let failover = Arc::new(FailoverState::new(DnsProvider::Cloudflare));
        let cache = Arc::new(DnsCache::new());
        let policy = Arc::new(parking_lot::RwLock::new(Policy::default()));
        let events = Arc::new(QueryEvents::disabled());
        let (txs, handles) = spawn_udp_workers(
            sock.clone(),
            resolver,
            failover.clone(),
            cache.clone(),
            policy,
            events,
            DnsMode::DoH,
            2,
        );
        let rr = AtomicUsize::new(0);

        // Miss: direct resolve, answer carries the requester's ID.
        let q1 = a_query(0x1111);
        let resp = relay_roundtrip(&sock, &txs, &rr, &q1, DnsProvider::Cloudflare, DnsStrategy::Single);
        assert_eq!(&resp[..2], &[0x11, 0x11]);
        assert!(dns::response_ttl(&resp).is_some());

        // Hit: same question, different ID → served from cache, re-ID'd.
        let q2 = a_query(0x2222);
        let resp = relay_roundtrip(&sock, &txs, &rr, &q2, DnsProvider::Cloudflare, DnsStrategy::Single);
        assert_eq!(&resp[..2], &[0x22, 0x22], "cached response re-ID'd for requester");

        drop(txs);
        for h in handles {
            let _ = h.join();
        }
    }

    #[test]
    fn worker_failure_returns_servfail_and_advances_failover() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        sock.set_read_timeout(Some(Duration::from_millis(2000))).unwrap();

        // All upstreams fail.
        let resolver: Arc<Resolver> = Arc::new(|_q, _p| Err("upstream down".into()));
        let failover = Arc::new(FailoverState::new(DnsProvider::Cloudflare));
        let cache = Arc::new(DnsCache::new());
        let policy = Arc::new(parking_lot::RwLock::new(Policy::default()));
        let events = Arc::new(QueryEvents::disabled());
        let (txs, handles) = spawn_udp_workers(
            sock.clone(),
            resolver,
            failover.clone(),
            cache,
            policy,
            events,
            DnsMode::DoH,
            2,
        );
        let rr = AtomicUsize::new(0);

        let q = a_query(0x4242);
        let resp = relay_roundtrip(&sock, &txs, &rr, &q, DnsProvider::Cloudflare, DnsStrategy::Failover);
        assert_eq!(resp[3] & 0x0F, 0x02, "SERVFAIL RCODE");
        assert_eq!(&resp[..2], &[0x42, 0x42], "servfail echoes requester ID");
        assert_eq!(failover.target(), DnsProvider::Google, "failover advanced past Cloudflare");

        drop(txs);
        for h in handles {
            let _ = h.join();
        }
    }

    #[test]
    fn blocked_domain_gets_nxdomain() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        sock.set_read_timeout(Some(Duration::from_millis(2000))).unwrap();

        let resolver: Arc<Resolver> = Arc::new(|_q, _p| Ok(fake_response(_q)));
        let failover = Arc::new(FailoverState::new(DnsProvider::Cloudflare));
        let cache = Arc::new(DnsCache::new());
        let policy = Arc::new(parking_lot::RwLock::new(Policy {
            rules: vec![PolicyRule {
                pattern: "example.com".into(),
                action: "block".into(),
            }],
        }));
        let events = Arc::new(QueryEvents::disabled());
        let (txs, handles) = spawn_udp_workers(
            sock.clone(),
            resolver,
            failover,
            cache,
            policy,
            events,
            DnsMode::DoH,
            2,
        );
        let rr = AtomicUsize::new(0);

        let q = a_query(0x5151);
        let resp = relay_roundtrip(&sock, &txs, &rr, &q, DnsProvider::Cloudflare, DnsStrategy::Single);
        assert_eq!(resp[3] & 0x0F, 0x03, "blocked query answered NXDOMAIN");
        assert_eq!(&resp[..2], &[0x51, 0x51], "echoes requester ID");

        drop(txs);
        for h in handles {
            let _ = h.join();
        }
    }

    #[test]
    fn policy_allow_overrides_block() {
        let p = Policy {
            rules: vec![
                PolicyRule { pattern: "example.com".into(), action: "block".into() },
                PolicyRule { pattern: "www.example.com".into(), action: "allow".into() },
            ],
        };
        assert!(p.blocked("example.com"), "blocked domain stays blocked");
        assert!(!p.blocked("www.example.com"), "allow overrides block regardless of order");
        assert!(!p.blocked("google.com"), "unmatched is allowed");
    }

    #[test]
    fn policy_suffix_and_dot_forms() {
        let p = Policy {
            rules: vec![PolicyRule { pattern: ".ads.com".into(), action: "block".into() }],
        };
        assert!(p.blocked("ads.com"));
        assert!(p.blocked("cdn.ads.com"));
        assert!(!p.blocked("notads.com"), "label boundary respected");
        assert!(!p.blocked(""), "empty domain never matches");
    }
}

fn run_doh(
    strategy: DnsStrategy,
    provider: DnsProvider,
    policy: Arc<parking_lot::RwLock<Policy>>,
    events: Arc<QueryEvents>,
    running: &Arc<AtomicBool>,
) -> Option<Config> {
    let agent = match dns::create_doh_agent() {
        Ok(a) => {
            info!("DoH agent ready");
            Arc::new(a)
        }
        Err(e) => {
            error!("DoH agent init: {e}");
            return None;
        }
    };
    let quad9 = dns::Quad9Pool::new();
    if quad9.is_some() {
        info!("Quad9 h2 pool ready");
    }
    let resolver: Arc<Resolver> = Arc::new(move |query, target| {
        if target == DnsProvider::Quad9 {
            match &quad9 {
                Some(pool) => pool.query(query),
                None => dns::doh_resolve_fallible(&agent, target, query),
            }
        } else {
            dns::doh_resolve_fallible(&agent, target, query)
        }
    });
    run_proxy_loop(DnsMode::DoH, resolver, strategy, provider, policy, events, running)
}

fn run_dot(
    strategy: DnsStrategy,
    provider: DnsProvider,
    policy: Arc<parking_lot::RwLock<Policy>>,
    events: Arc<QueryEvents>,
    running: &Arc<AtomicBool>,
) -> Option<Config> {
    let pool = Arc::new(dns::DotPool::new(4));
    let resolver: Arc<Resolver> = Arc::new(move |query, target| pool.query(target, query));
    run_proxy_loop(DnsMode::DoT, resolver, strategy, provider, policy, events, running)
}

fn create_udp_socket() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr: std::net::SocketAddr = format!("{LISTEN_ADDR}:{LISTEN_PORT}").parse().unwrap();
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(false)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Check config.json every 500 ms. If mode changed, return the new config
/// so the caller can re-enter the correct loop. Otherwise update
/// provider/strategy. The policy is refreshed from config.json every
/// check, so SetPolicy hot-swaps live.
fn check_reload(
    expected: DnsMode,
    provider: &mut DnsProvider,
    strategy: &mut DnsStrategy,
    policy: &parking_lot::RwLock<Policy>,
) -> Option<Config> {
    let cfg = Config::load();
    let mode = parse_mode(&cfg.mode);
    *policy.write() = Policy::from_config(&cfg);
    if mode != expected {
        return Some(cfg);
    }
    *provider = parse_provider(&cfg.provider);
    *strategy = parse_strategy(&cfg.strategy);
    None
}

// ── Platform: root check ───────────────────────────────────────────────

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("error: must run as root (sudo)");
        std::process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn check_root() {
    use std::ffi::c_void;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: u32 = 20;

    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn OpenProcessToken(
            hProcess: *mut c_void,
            DesiredAccess: u32,
            TokenHandle: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            TokenHandle: *mut c_void,
            TokenInformationClass: u32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
        fn CloseHandle(hObject: *mut c_void) -> i32;
    }

    unsafe {
        let mut token: *mut c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            eprintln!("error: must run as Administrator");
            std::process::exit(1);
        }
        let mut elevated: u32 = 0;
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION,
            &mut elevated as *mut _ as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        if ok == 0 || elevated == 0 {
            eprintln!("error: must run as Administrator");
            std::process::exit(1);
        }
    }
}

// ── Platform: loopback (public for grpc.rs) ────────────────────────────

#[cfg(target_os = "macos")]
pub fn setup_loopback() {
    let _ = Command::new("ifconfig")
        .args(["lo0", "alias", LISTEN_ADDR, "255.255.255.255"])
        .status();
}

#[cfg(target_os = "macos")]
pub fn teardown_loopback() {
    let _ = Command::new("ifconfig")
        .args(["lo0", "inet", LISTEN_ADDR, "-alias"])
        .status();
}

#[cfg(target_os = "linux")]
pub fn setup_loopback() {
    let _ = Command::new("ip")
        .args(["addr", "add", "127.0.0.2/32", "dev", "lo"])
        .status();
}

#[cfg(target_os = "linux")]
pub fn teardown_loopback() {
    let _ = Command::new("ip")
        .args(["addr", "del", "127.0.0.2/32", "dev", "lo"])
        .status();
}

#[cfg(target_os = "windows")]
pub fn setup_loopback() {}

#[cfg(target_os = "windows")]
pub fn teardown_loopback() {}

// ── Platform: DNS operations (public for grpc.rs) ─────────────────────

#[cfg(target_os = "macos")]
fn get_network_services() -> Vec<String> {
    let output = match Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter(|line| {
            !line.is_empty()
                && !line.contains("asterisk")
                && !line.contains("denotes")
        })
        .map(|s| s.trim_start_matches('*').trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(target_os = "macos")]
fn for_each_service<F: Fn(&str)>(f: F) {
    let services = get_network_services();
    if services.is_empty() {
        for name in &["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN", "Thunderbolt Bridge"] {
            f(name);
        }
    } else {
        for name in &services {
            f(name);
        }
    }
}

#[cfg(target_os = "macos")]
pub fn install_system_dns() {
    info!("configuring system DNS → {LISTEN_ADDR}");
    for_each_service(|service| {
        let _ = Command::new("networksetup")
            .args(["-setdnsservers", service, LISTEN_ADDR])
            .status();
    });
    // NB: /etc/resolv.conf is generated by mDNSResponder from the
    // networksetup configuration — never write/delete it directly.
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("DNS set to {LISTEN_ADDR}");
}

#[cfg(target_os = "macos")]
pub fn uninstall_system_dns() {
    for_each_service(|service| {
        let _ = Command::new("networksetup")
            .args(["-setdnsservers", service, "Empty"])
            .status();
    });
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("system DNS restored");
}

#[cfg(target_os = "linux")]
pub fn install_system_dns() {
    info!("configuring system DNS → {LISTEN_ADDR}");
    let _ = std::fs::write("/etc/resolv.conf", format!("nameserver {LISTEN_ADDR}\n"));
    info!("DNS set to {LISTEN_ADDR}");
}

#[cfg(target_os = "linux")]
pub fn uninstall_system_dns() {
    let _ = std::fs::remove_file("/etc/resolv.conf");
    info!("system DNS restored");
}

#[cfg(target_os = "windows")]
fn get_windows_adapters() -> Vec<String> {
    let output = match Command::new("netsh")
        .args(["interface", "ip", "show", "interfaces"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut adapters = Vec::new();
    for line in stdout.lines().skip(3) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(name) = trimmed.split("  ").last() {
            let name = name.trim();
            if !name.is_empty() && !name.contains("Loopback") {
                adapters.push(name.to_string());
            }
        }
    }
    adapters
}

#[cfg(target_os = "windows")]
pub fn install_system_dns() {
    info!("configuring system DNS → {LISTEN_ADDR}");
    for adapter in &get_windows_adapters() {
        let _ = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", adapter, "static", LISTEN_ADDR])
            .status();
    }
    info!("DNS set to {LISTEN_ADDR}");
}

#[cfg(target_os = "windows")]
pub fn uninstall_system_dns() {
    for adapter in &get_windows_adapters() {
        let _ = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", adapter, "dhcp"])
            .status();
    }
    info!("system DNS restored");
}

// ── Platform: network watcher ──────────────────────────────────────────

#[cfg(target_os = "macos")]
fn start_network_watcher(running: Arc<AtomicBool>) {
    use core_foundation::{
        array::CFArray,
        runloop::{kCFRunLoopCommonModes, kCFRunLoopDefaultMode, CFRunLoop},
        string::CFString,
    };
    use system_configuration::dynamic_store::{
        SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
    };

    fn on_network_change(
        _store: SCDynamicStore,
        _changed_keys: CFArray<CFString>,
        _info: &mut (),
    ) {
        info!("network configuration changed, reapplying DNS...");
        install_system_dns();
    }

    std::thread::Builder::new()
        .name("network-watcher".into())
        .spawn(move || {
            let callback_context = SCDynamicStoreCallBackContext {
                callout: on_network_change,
                info: (),
            };

            let store = match SCDynamicStoreBuilder::new("dns-guard")
                .callback_context(callback_context)
                .build()
            {
                Some(s) => s,
                None => {
                    error!("failed to create SCDynamicStore");
                    return;
                }
            };

            let watch_keys: CFArray<CFString> = CFArray::from_CFTypes(&[]);
            let watch_patterns = CFArray::from_CFTypes(&[
                CFString::from("State:/Network/Service/"),
            ]);

            if !store.set_notification_keys(&watch_keys, &watch_patterns) {
                error!("failed to set SCDynamicStore notification keys");
                return;
            }

            let run_loop_source = match store.create_run_loop_source() {
                Some(s) => s,
                None => {
                    error!("failed to create run loop source");
                    return;
                }
            };

            let run_loop = CFRunLoop::get_current();
            run_loop.add_source(&run_loop_source, unsafe { kCFRunLoopCommonModes });

            info!("network change watcher ready");
            while running.load(Ordering::SeqCst) {
                CFRunLoop::run_in_mode(
                    unsafe { kCFRunLoopDefaultMode },
                    std::time::Duration::from_secs(1),
                    true,
                );
            }
            info!("network change watcher stopped");
        })
        .expect("failed to spawn network watcher thread");
}

#[cfg(target_os = "linux")]
fn start_network_watcher(running: Arc<AtomicBool>) {
    use std::os::unix::io::RawFd;

    fn create_netlink_sock() -> RawFd {
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            );
            if fd < 0 {
                return -1;
            }

            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as u16;
            addr.nl_groups = libc::RTMGRP_LINK as u32
                | libc::RTMGRP_IPV4_IFADDR as u32
                | libc::RTMGRP_IPV6_IFADDR as u32;

            let ret = libc::bind(
                fd,
                &addr as *const _ as *const _,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            );
            if ret < 0 {
                libc::close(fd);
                return -1;
            }
            fd
        }
    }

    std::thread::Builder::new()
        .name("network-watcher".into())
        .spawn(move || {
            let fd = create_netlink_sock();
            if fd < 0 {
                error!("failed to create netlink socket");
                return;
            }

            let mut poll_fds = [libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            }];

            info!("network change watcher ready");
            while running.load(Ordering::SeqCst) {
                let ret = unsafe {
                    libc::poll(poll_fds.as_mut_ptr(), 1, 1000)
                };
                if ret < 0 { break; }
                if ret > 0 && (poll_fds[0].revents & libc::POLLIN) != 0 {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = unsafe {
                            libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len())
                        };
                        if n <= 0 { break; }
                    }
                    info!("network change detected, reapplying DNS...");
                    install_system_dns();
                }
            }
            unsafe { libc::close(fd); }
            info!("network change watcher stopped");
        })
        .expect("failed to spawn network watcher thread");
}

#[cfg(target_os = "windows")]
fn start_network_watcher(running: Arc<AtomicBool>) {
    mod ffi {
        #![allow(non_snake_case, dead_code, unused, non_camel_case_types)]

        use std::ffi::c_void;

        const AF_UNSPEC: u16 = 0;

        type NotifyCallback = unsafe extern "system" fn(
            *mut c_void,
            *mut c_void,
            i32,
        );

        #[link(name = "iphlpapi")]
        extern "system" {
            fn NotifyIpInterfaceChange(
                Family: u16,
                Callback: Option<NotifyCallback>,
                CallerContext: *mut c_void,
                InitialNotification: u8,
                NotificationHandle: *mut *mut c_void,
            ) -> u32;

            fn CancelMibChangeNotify2(
                NotificationHandle: *mut c_void,
            ) -> u32;
        }

        pub fn register(callback: NotifyCallback) -> Result<*mut c_void, u32> {
            let mut handle: *mut c_void = std::ptr::null_mut();
            let ret = unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(callback),
                    std::ptr::null_mut(),
                    0,
                    &mut handle,
                )
            };
            if ret == 0 {
                Ok(handle)
            } else {
                Err(ret)
            }
        }

        pub fn unregister(handle: *mut c_void) {
            if !handle.is_null() {
                unsafe { CancelMibChangeNotify2(handle); }
            }
        }
    }

    unsafe extern "system" fn on_network_change_windows(
        _context: *mut std::ffi::c_void,
        _row: *mut std::ffi::c_void,
        _notif_type: i32,
    ) {
        info!("network configuration changed, reapplying DNS...");
        install_system_dns();
    }

    std::thread::Builder::new()
        .name("network-watcher".into())
        .spawn(move || {
            let handle = match ffi::register(on_network_change_windows) {
                Ok(h) => h,
                Err(e) => {
                    error!("NotifyIpInterfaceChange failed: {e}");
                    return;
                }
            };

            info!("network change watcher ready");
            while running.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }

            ffi::unregister(handle);
            info!("network change watcher stopped");
        })
        .expect("failed to spawn network watcher thread");
}

// ── Parse helpers ─────────────────────────────────────────────────────

fn parse_mode(s: &str) -> DnsMode {
    match s.to_lowercase().as_str() {
        "dot" => DnsMode::DoT,
        _ => DnsMode::DoH,
    }
}

fn parse_provider(s: &str) -> DnsProvider {
    match s.to_lowercase().as_str() {
        "google" => DnsProvider::Google,
        "quad9" => DnsProvider::Quad9,
        _ => DnsProvider::Cloudflare,
    }
}

fn parse_strategy(s: &str) -> DnsStrategy {
    match s.to_lowercase().as_str() {
        "round-robin" => DnsStrategy::RoundRobin,
        "failover" => DnsStrategy::Failover,
        _ => DnsStrategy::Single,
    }
}
