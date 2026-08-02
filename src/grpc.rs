pub mod proto {
    tonic::include_proto!("dns_guard");
}

use std::collections::VecDeque;
use std::io::BufRead;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use log::{info, warn};
use parking_lot::Mutex;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use proto::dns_guard_server::DnsGuard;
use proto::*;

// ── Running proxy ──────────────────────────────────────────────────────

/// Tracked proxy process. `Managed` wraps the sudo child handle +
/// the real proxy PID (read from state.json after the proxy writes it).
pub enum RunningProxy {
    Managed { child: Child, proxy_pid: u32 },
    Adopted(u32),
}

impl RunningProxy {
    /// The actual dns-guard proxy PID (not sudo).
    pub fn proxy_pid(&self) -> u32 {
        match self {
            RunningProxy::Managed { proxy_pid, .. } => *proxy_pid,
            RunningProxy::Adopted(pid) => *pid,
        }
    }
}

// ── Shared state ──────────────────────────────────────────────────────

#[derive(Clone)]
struct GuardConfig {
    mode: String,
    provider: String,
    strategy: String,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self { mode: "doh".into(), provider: "cloudflare".into(), strategy: "single".into() }
    }
}

pub struct ProxyService {
    pub child: Mutex<Option<RunningProxy>>,
    config: RwLock<GuardConfig>,
    /// Fan-out of log lines to all connected Logs subscribers. Lines are
    /// dropped when no subscriber exists (the GUI keeps its own buffer).
    log_tx: broadcast::Sender<String>,
    /// Ring buffer of recent lines so a newly connected GUI gets history.
    log_history: Arc<Mutex<VecDeque<String>>>,
    password: parking_lot::Mutex<String>,
    /// Stop flag for the proxy.log tail thread (adopted proxies).
    log_tail_stop: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

const LOG_HISTORY_CAP: usize = 500;
const LOG_CHANNEL_CAP: usize = 1024;

/// Helper: write password to stdin and wait for sudo to finish.
fn sudo_with_password(
    password: &str,
    args: &[&str],
) -> std::io::Result<std::process::ExitStatus> {
    use std::io::Write;
    let mut child = std::process::Command::new("sudo")
        .arg("-S")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(format!("{}\n", password).as_bytes());
    }
    child.wait()
}

impl ProxyService {
    pub fn load_or_new() -> Self {
        let state = crate::state::load();

        let adopted = if state.running && state.pid != 0 {
            if crate::state::is_process_alive(state.pid) {
                info!("adopted existing proxy pid={}", state.pid);
                Some(RunningProxy::Adopted(state.pid))
            } else {
                info!("stale state found — no proxy live at pid={}", state.pid);
                crate::state::clear();
                None
            }
        } else {
            None
        };

        let config = GuardConfig {
            mode: state.mode,
            provider: state.provider,
            strategy: state.strategy,
        };

        let (log_tx, _rx) = broadcast::channel::<String>(LOG_CHANNEL_CAP);

        let service = Self {
            child: Mutex::new(adopted),
            config: RwLock::new(config),
            log_tx,
            log_history: Arc::new(Mutex::new(VecDeque::with_capacity(LOG_HISTORY_CAP))),
            password: parking_lot::Mutex::new(String::new()),
            log_tail_stop: Arc::new(Mutex::new(None)),
        };

        if service.child.lock().is_some() {
            service.start_log_tail();
        }

        service
    }

    fn self_path() -> String {
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "dns-guard".into())
    }

    fn spawn_proxy_child(cfg: &GuardConfig, password: &str) -> std::io::Result<Child> {
        use std::io::Write;
        let bin = ProxyService::self_path();
        let mut child = Command::new("sudo")
            .arg("-S")
            .args([&bin, "--mode", &cfg.mode, "--provider", &cfg.provider, "--strategy", &cfg.strategy])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(format!("{}\n", password).as_bytes());
        }
        Ok(child)
    }

    /// Check if the child exited within 200ms — indicates a startup failure.
    /// Async so it doesn't block the tokio worker thread.
    async fn check_early_exit(child: &mut Child) -> Option<(std::process::ExitStatus, String)> {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(Some(status)) = child.try_wait() {
            let mut err = String::new();
            if let Some(ref mut stderr) = child.stderr {
                use std::io::Read;
                let _ = stderr.read_to_string(&mut err);
            }
            Some((status, err))
        } else {
            None
        }
    }

    /// Poll state.json until the proxy writes its PID (up to `timeout`).
    /// Async: uses tokio sleeps, never blocks a worker thread.
    async fn wait_for_proxy_pid(timeout: Duration) -> Option<u32> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let state = crate::state::load();
            if state.running && state.pid != 0 {
                return Some(state.pid);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Send a signal to the proxy process. Tries the sudo credential
    /// cache first (`sudo -n`, no password over stdin); falls back to
    /// `sudo -S` with the stored password only when the cache expired.
    fn signal_proxy(pid: u32, signal: &str, password: &str) -> bool {
        if Command::new("sudo")
            .arg("-n")
            .args(["kill", signal, &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return true;
        }
        sudo_with_password(password, &["kill", signal, &pid.to_string()])
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Adopt a proxy that is running but wasn't spawned by this daemon
    /// (GUI-supervised: the GUI spawned it as root via the macOS
    /// Authorization framework). Called lazily from status() so adoption
    /// happens on the first poll after the proxy starts.
    fn adopt_if_present(&self) {
        let mut guard = self.child.lock();
        if guard.is_some() {
            return;
        }
        let state = crate::state::load();
        if !state.running || state.pid == 0 {
            return;
        }
        if !crate::state::is_process_alive(state.pid) {
            info!("stale state found — no proxy live at pid={}", state.pid);
            crate::state::clear();
            return;
        }
        info!("adopted proxy pid={} (spawned outside daemon)", state.pid);
        *guard = Some(RunningProxy::Adopted(state.pid));
        drop(guard);
        self.start_log_tail();
    }

    /// Tail proxy.log (append-only, world-readable) into the log
    /// broadcast + history ring. Starts from the current end of the file
    /// so previous sessions' lines are not replayed.
    fn start_log_tail(&self) {
        if let Some(stop) = self.log_tail_stop.lock().as_ref() {
            stop.store(true, Ordering::SeqCst);
        }
        let stop = Arc::new(AtomicBool::new(false));
        *self.log_tail_stop.lock() = Some(stop.clone());

        let logs = self.log_tx.clone();
        let history = self.log_history.clone();
        let path = crate::state::proxy_log_path();

        std::thread::spawn(move || {
            use std::io::{Read, Seek, SeekFrom};
            let mut offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            while !stop.load(Ordering::SeqCst) {
                match std::fs::OpenOptions::new().read(true).open(&path) {
                    Ok(mut f) => {
                        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
                        if len < offset {
                            offset = 0; // rotated/truncated
                        }
                        if len > offset {
                            let _ = f.seek(SeekFrom::Start(offset));
                            let mut buf = String::new();
                            if f.read_to_string(&mut buf).is_ok() {
                                offset = len;
                                for line in buf.lines() {
                                    let _ = logs.send(line.to_string());
                                    let mut h = history.lock();
                                    h.push_back(line.to_string());
                                    if h.len() > LOG_HISTORY_CAP {
                                        h.pop_front();
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
    }

    fn stop_log_tail(&self) {
        if let Some(stop) = self.log_tail_stop.lock().as_ref() {
            stop.store(true, Ordering::SeqCst);
        }
    }
}

fn spawn_log_thread(
    logs: broadcast::Sender<String>,
    history: Arc<Mutex<VecDeque<String>>>,
    stdout: Option<impl std::io::Read + Send + 'static>,
) {
    if let Some(reader) = stdout {
        std::thread::spawn(move || {
            let buf = std::io::BufReader::new(reader);
            for line in buf.lines().map_while(Result::ok) {
                let _ = logs.send(line.clone());
                let mut h = history.lock();
                h.push_back(line);
                if h.len() > LOG_HISTORY_CAP {
                    h.pop_front();
                }
            }
        });
    }
}

// ── gRPC service impl ────────────────────────────────────────────────

#[tonic::async_trait]
impl DnsGuard for Arc<ProxyService> {
    async fn start(
        &self,
        request: Request<StartRequest>,
    ) -> Result<Response<StartResponse>, Status> {
        let req = request.into_inner();

        // A previously adopted proxy's log tail must not fight with the
        // new child's piped stdout.
        self.stop_log_tail();

        {
            let mut guard = self.child.lock();
            if let Some(ref mut proxy) = *guard {
                if proxy.proxy_pid() != 0 && crate::state::is_process_alive(proxy.proxy_pid()) {
                    return Ok(Response::new(StartResponse {
                        ok: false,
                        message: "proxy already running".into(),
                    }));
                }
                // Discarded a dead proxy — make sure wait_for_proxy_pid
                // can't pick up its stale PID from state.json.
                guard.take();
                crate::state::clear();
            }
        }

        let cfg = GuardConfig {
            mode: if req.mode.is_empty() { self.config.read().mode.clone() } else { req.mode },
            provider: if req.provider.is_empty() { self.config.read().provider.clone() } else { req.provider },
            strategy: if req.strategy.is_empty() { self.config.read().strategy.clone() } else { req.strategy },
        };
        *self.config.write() = cfg.clone();

        let pw = self.password.lock().clone();
        if pw.is_empty() {
            return Ok(Response::new(StartResponse {
                ok: false,
                message: "no sudo password set — click Authenticate first".into(),
            }));
        }

        let mut child = ProxyService::spawn_proxy_child(&cfg, &pw)
            .map_err(|e| Status::internal(format!("spawn: {e}")))?;

        if let Some((status, err)) = ProxyService::check_early_exit(&mut child).await {
            if !status.success() {
                return Ok(Response::new(StartResponse {
                    ok: false,
                    message: if err.contains("password") {
                        "wrong password — click Authenticate".into()
                    } else {
                        format!("proxy failed: {err}")
                    },
                }));
            }
        }

        let proxy_pid = match ProxyService::wait_for_proxy_pid(Duration::from_secs(3)).await {
            Some(pid) => pid,
            None => {
                let _ = child.kill();
                return Ok(Response::new(StartResponse {
                    ok: false,
                    message: "proxy did not start in time".into(),
                }));
            }
        };

        info!("proxy started pid={}", proxy_pid);

        let logs = self.log_tx.clone();
        let history = self.log_history.clone();
        spawn_log_thread(logs.clone(), history.clone(), child.stdout.take());
        spawn_log_thread(logs, history, child.stderr.take());

        *self.child.lock() = Some(RunningProxy::Managed { child, proxy_pid });

        Ok(Response::new(StartResponse { ok: true, message: "proxy started".into() }))
    }

    async fn stop(
        &self,
        _request: Request<StopRequest>,
    ) -> Result<Response<StopResponse>, Status> {
        let pw = self.password.lock().clone();
        let child = self.child.lock().take();
        if let Some(proxy) = child {
            let real_pid = proxy.proxy_pid();
            info!("stopping proxy (pid {real_pid})");

            // Signal via sudo only when a password is stored (CLI flow).
            // GUI-supervised proxies are signalled by the GUI itself via
            // its AuthorizationRef; here we still verify death and clean up.
            if !pw.is_empty() {
                let pw = pw.clone();
                let signaled = tokio::task::spawn_blocking(move || {
                    ProxyService::signal_proxy(real_pid, "-INT", &pw)
                })
                .await
                .unwrap_or(false);
                if !signaled {
                    warn!("failed to signal proxy {real_pid} (credentials expired?)");
                }
            } else {
                warn!("no stored password — proxy {real_pid} must be signalled externally (GUI)");
            }

            let dead = match proxy {
                RunningProxy::Managed { child: c, proxy_pid: _ } => {
                    let exited = match tokio::task::spawn_blocking(move || {
                        let mut c = c;
                        for _ in 0..30 {
                            match c.try_wait() {
                                Ok(Some(_)) => return (true, Some(c)),
                                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                                Err(_) => break,
                            }
                        }
                        (false, Some(c))
                    }).await {
                        Ok((exited, remaining)) => {
                            if !exited && !pw.is_empty() {
                                info!("force killing proxy {real_pid}");
                                let pw = pw.clone();
                                let force = tokio::task::spawn_blocking(move || {
                                    ProxyService::signal_proxy(real_pid, "-KILL", &pw)
                                })
                                .await
                                .unwrap_or(false);
                                if force {
                                    if let Some(mut c) = remaining { let _ = c.wait(); }
                                    !crate::state::is_process_alive(real_pid)
                                } else {
                                    // Couldn't even SIGKILL — re-adopt below.
                                    false
                                }
                            } else {
                                exited
                            }
                        }
                        Err(_) => false,
                    };
                    exited
                }
                RunningProxy::Adopted(real_pid) => {
                    for _ in 0..30 {
                        if !crate::state::is_process_alive(real_pid) { break; }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    if crate::state::is_process_alive(real_pid) && !pw.is_empty() {
                        info!("force killing adopted proxy {real_pid}");
                        let pw = pw.clone();
                        let force = tokio::task::spawn_blocking(move || {
                            ProxyService::signal_proxy(real_pid, "-KILL", &pw)
                        })
                        .await
                        .unwrap_or(false);
                        if force {
                            for _ in 0..10 {
                                if !crate::state::is_process_alive(real_pid) { break; }
                                std::thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                    !crate::state::is_process_alive(real_pid)
                }
            };

            if !dead {
                warn!("proxy {real_pid} is still alive after stop attempt");
                let cfg = self.config.read();
                crate::state::save(&crate::state::State {
                    running: true,
                    pid: real_pid,
                    mode: cfg.mode.clone(),
                    provider: cfg.provider.clone(),
                    strategy: cfg.strategy.clone(),
                });
                self.child.lock().replace(RunningProxy::Adopted(real_pid));
                return Ok(Response::new(StopResponse {
                    ok: false,
                    message: "proxy still running — authorize in the app to stop it".into(),
                }));
            }
        }

        crate::state::clear();
        self.stop_log_tail();

        Ok(Response::new(StopResponse {
            ok: true,
            message: "proxy stopped".into(),
        }))
    }

    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        // A proxy may have been started outside the daemon (GUI-supervised
        // via the macOS Authorization framework) — adopt it on first poll.
        self.adopt_if_present();

        let (running, pid) = {
            let mut guard = self.child.lock();
            if let Some(ref mut proxy) = *guard {
                let actual_pid = proxy.proxy_pid();
                if actual_pid != 0 && crate::state::is_process_alive(actual_pid) {
                    (true, actual_pid)
                } else {
                    guard.take();
                    crate::state::clear();
                    (false, 0)
                }
            } else {
                (false, 0)
            }
        };

        if !running {
            self.stop_log_tail();
        }

        let cfg = self.config.read();

        Ok(Response::new(StatusResponse {
            running,
            pid,
            mode: cfg.mode.clone(),
            provider: cfg.provider.clone(),
            strategy: cfg.strategy.clone(),
        }))
    }

    async fn set_config(
        &self,
        request: Request<ConfigRequest>,
    ) -> Result<Response<ConfigResponse>, Status> {
        let req = request.into_inner();
        let new_cfg = {
            let mut cfg = self.config.write();
            if !req.mode.is_empty() { cfg.mode = req.mode.clone(); }
            if !req.provider.is_empty() { cfg.provider = req.provider.clone(); }
            if !req.strategy.is_empty() { cfg.strategy = req.strategy.clone(); }
            cfg.clone()
        };

        // Save to disk so the running proxy can hot-reload it
        crate::state::save_config(&new_cfg.mode, &new_cfg.provider, &new_cfg.strategy);

        // Best-effort nudge for daemon-supervised proxies (CLI flow with a
        // stored password). GUI-supervised proxies are nudged by the GUI
        // itself via its AuthorizationRef; the 500ms config poll covers it.
        let signal_pid = {
            let guard = self.child.lock();
            guard.as_ref().map(|p| p.proxy_pid())
        };
        if let Some(pid) = signal_pid {
            let pw = self.password.lock().clone();
            if !pw.is_empty() {
                let _ = tokio::task::spawn_blocking(move || {
                    ProxyService::signal_proxy(pid, "-HUP", &pw)
                })
                .await;
            } else {
                info!("config saved — skipping SIGHUP to pid {pid} (GUI-supervised)");
            }
        }

        Ok(Response::new(ConfigResponse { ok: true }))
    }

    async fn set_password(
        &self,
        request: Request<PasswordRequest>,
    ) -> Result<Response<PasswordResponse>, Status> {
        let pw = request.into_inner().password;

        // Verify the password by refreshing the sudo credential cache
        // (`sudo -S -v`). Also validates the password itself.
        let ok = tokio::task::spawn_blocking({
            let pw = pw.clone();
            move || sudo_with_password(&pw, &["-v"]).map(|s| s.success()).unwrap_or(false)
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if ok {
            *self.password.lock() = pw;
            Ok(Response::new(PasswordResponse {
                ok: true,
                message: "authenticated".into(),
            }))
        } else {
            Ok(Response::new(PasswordResponse {
                ok: false,
                message: "wrong password".into(),
            }))
        }
    }

    async fn shutdown(
        &self,
        _request: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        // Reuse the stop logic to gracefully shut down the proxy
        let stop_resp = self
            .stop(Request::new(StopRequest {}))
            .await?;
        let ok = stop_resp.into_inner().ok;

        // Only clear state if the proxy actually stopped — otherwise the
        // next daemon launch must be able to re-adopt the live proxy.
        if ok {
            crate::state::clear();
        }
        let _ = std::fs::remove_file(crate::state::server_pid_path());

        // Schedule exit after the response is sent
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            std::process::exit(0);
        });

        Ok(Response::new(ShutdownResponse { ok }))
    }

    type LogsStream =
        Pin<Box<dyn Stream<Item = Result<LogEntry, Status>> + Send>>;

    async fn logs(
        &self,
        _request: Request<LogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        use tokio_stream::StreamExt;

        // Snapshot history first, then subscribe, so the snapshot is a
        // strict prefix of what the subscriber will see.
        let history: Vec<String> = self.log_history.lock().iter().cloned().collect();
        let live = self.log_tx.subscribe();

        let history_stream = tokio_stream::iter(history).map(|line| Ok(LogEntry { line }));
        let live_stream = tokio_stream::wrappers::BroadcastStream::new(live).map(|item| {
            match item {
                Ok(line) => Ok(LogEntry { line }),
                Err(e) => Err(Status::aborted(format!("log stream lagged: {e}"))),
            }
        });

        let combined = history_stream.chain(live_stream);
        Ok(Response::new(Box::pin(combined)))
    }
}
