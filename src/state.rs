//! Persistent runtime state for dns-guard.
//!
//! Allows the gRPC server and the GUI to survive crashes/restarts while still
//! knowing whether a proxy process is running, what mode it is in, and its PID.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct State {
    pub running: bool,
    pub pid: u32,
    pub mode: String,
    pub provider: String,
    pub strategy: String,
}

impl State {
    pub fn new() -> Self {
        Self {
            running: false,
            pid: 0,
            mode: "doh".into(),
            provider: "cloudflare".into(),
            strategy: "single".into(),
        }
    }
}

/// Configuration/state directory for dns-guard.
///
/// Overridable via DNS_GUARD_DIR so a root-spawned proxy (GUI's
/// AuthorizationExecuteWithPrivileges) can be pointed at the user's
/// config dir regardless of what HOME it sees.
pub fn dir() -> PathBuf {
    if let Ok(d) = std::env::var("DNS_GUARD_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(home).join("dns-guard")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config").join("dns-guard")
        } else {
            PathBuf::from("/etc/dns-guard")
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            PathBuf::from(appdata).join("dns-guard")
        } else {
            PathBuf::from("C:\\ProgramData\\dns-guard")
        }
    }
}

pub fn path() -> PathBuf {
    dir().join("state.json")
}

pub fn server_pid_path() -> PathBuf {
    dir().join("server.pid")
}

/// Unix socket used by the gRPC daemon. Lives in the user's config dir
/// (not /tmp) so it is only reachable by the owner, and is chmod 0o600
/// after bind. Overridable via DNS_GUARD_SOCKET for testing.
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("DNS_GUARD_SOCKET") {
        return PathBuf::from(p);
    }
    dir().join("dns-guard.sock")
}

pub fn server_log_path() -> PathBuf {
    dir().join("server.log")
}

pub fn proxy_log_path() -> PathBuf {
    dir().join("proxy.log")
}

/// Per-query event log written by the proxy (root) and tailed by the
/// daemon for WatchQueries / GetStats. Truncated by the proxy at start.
pub fn query_log_path() -> PathBuf {
    dir().join("query.log")
}

pub fn load() -> State {
    let _ = std::fs::create_dir_all(dir());
    match std::fs::read_to_string(path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| State::new()),
        Err(_) => State::new(),
    }
}

pub fn save(state: &State) {
    let _ = std::fs::create_dir_all(dir());
    let p = path();
    let _ = std::fs::remove_file(&p);
    if let Ok(s) = serde_json::to_string_pretty(state) {
        let _ = std::fs::write(&p, s);
    }
}

pub fn clear() {
    save(&State::new());
}

/// Read the current config.json as JSON (defaults to `{}` when missing).
/// Used by save_config/save_policy so unrelated sections are preserved.
pub fn load_config_json() -> serde_json::Value {
    match std::fs::read_to_string(dir().join("config.json")) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    }
}

/// Save the runtime proxy configuration to disk so a running proxy can
/// hot-reload it without being restarted (used by `set_config` RPC).
/// Preserves the `policy` section if present.
///
/// Removes the file first so it works even if the previous file is root-owned
/// (written by the proxy running under sudo).
pub fn save_config(mode: &str, provider: &str, strategy: &str) {
    let mut cfg = load_config_json();
    cfg["mode"] = serde_json::json!(mode);
    cfg["provider"] = serde_json::json!(provider);
    cfg["strategy"] = serde_json::json!(strategy);
    write_config_json(&cfg);
}

/// Save the block/allow policy (JSON array of {pattern, action}) to
/// config.json, preserving the mode/provider/strategy sections.
pub fn save_policy(policy: &serde_json::Value) {
    let mut cfg = load_config_json();
    cfg["policy"] = policy.clone();
    write_config_json(&cfg);
}

fn write_config_json(cfg: &serde_json::Value) {
    let _ = std::fs::create_dir_all(dir());
    let path = dir().join("config.json");
    let _ = std::fs::remove_file(&path);
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(&path, s);
    }
}

/// Check whether a process with the given PID is still alive.
///
/// Uses `kill(pid, 0)` which returns 0 if the process exists AND we have
/// permission to signal it.  If the process is owned by root (started via sudo)
/// `kill` returns -1 with EPERM — we treat that as alive since the PID is valid.
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    let ret = unsafe { libc::kill(pid as i32, 0) };
    if ret == 0 {
        return true;
    }
    // ESRCH = no such process; anything else (e.g. EPERM) means it exists
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    use std::ffi::c_void;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
        fn CloseHandle(hObject: *mut c_void) -> i32;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
        if handle.is_null() {
            false
        } else {
            CloseHandle(handle);
            true
        }
    }
}
