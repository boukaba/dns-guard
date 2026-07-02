mod dns;

use clap::Parser;
use dns::{DnsMode, DnsProvider};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ── Platform-specific imports ──────────────────────────────────────────

#[cfg(target_os = "macos")]
use core_foundation::{
    array::CFArray,
    runloop::{kCFRunLoopCommonModes, kCFRunLoopDefaultMode, CFRunLoop},
    string::CFString,
};
#[cfg(target_os = "macos")]
use system_configuration::dynamic_store::{
    SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
};

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

// ── Constants ──────────────────────────────────────────────────────────

const LISTEN_ADDR: &str = "127.0.0.2";
const LISTEN_PORT: u16 = 53;

// ── CLI ────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "dns-guard", about = "System-wide encrypted DNS proxy")]
struct Cli {
    #[arg(long = "mode", help = "DNS mode (doh, dot)")]
    mode: Option<String>,

    #[arg(long = "provider", help = "DNS provider (cloudflare, google, quad9)")]
    provider: Option<String>,

    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    #[arg(long = "install", help = "Set system DNS to 127.0.0.2")]
    install: bool,

    #[arg(long = "uninstall", help = "Restore default DNS servers")]
    uninstall: bool,
}

// ── Config file ─────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Config {
    mode: String,
    provider: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "doh".into(),
            provider: "cloudflare".into(),
        }
    }
}

impl Config {
    fn path() -> PathBuf {
        #[cfg(unix)]
        {
            if let Ok(home) = std::env::var("XDG_CONFIG_HOME") {
                PathBuf::from(home).join("dns-guard").join("config.json")
            } else if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home).join(".config").join("dns-guard").join("config.json")
            } else {
                PathBuf::from("/etc/dns-guard/config.json")
            }
        }
        #[cfg(windows)]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                PathBuf::from(appdata).join("dns-guard").join("config.json")
            } else {
                PathBuf::from("C:\\ProgramData\\dns-guard\\config.json")
            }
        }
    }

    fn load() -> Self {
        let path = Self::path();
        match std::fs::read_to_string(&path) {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(c) => {
                    info!("loaded config from {}", path.display());
                    c
                }
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

fn main() {
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(if cli.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .format_timestamp_secs()
        .init();

    check_root();

    if cli.uninstall {
        uninstall_system_dns();
        return;
    }
    if cli.install {
        install_system_dns();
        return;
    }

    let config = Config::load();

    let mode_str = cli.mode.as_deref().unwrap_or(&config.mode);
    let provider_str = cli.provider.as_deref().unwrap_or(&config.provider);

    setup_loopback();

    install_system_dns();

    let mode = parse_mode(mode_str);
    let provider = parse_provider(provider_str);

    info!("dns-guard starting (mode={mode:?}, provider={provider:?})");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("failed to set Ctrl-C handler");

    start_network_watcher(running.clone());

    match mode {
        DnsMode::DoH => run_doh(provider, &running),
        DnsMode::DoT => run_dot(provider, &running),
    }

    Config {
        mode: mode_str.to_string(),
        provider: provider_str.to_string(),
    }
    .save();

    info!("restoring system DNS...");
    uninstall_system_dns();
    teardown_loopback();
    info!("dns-guard stopped");
}

// ── DNS proxy loops (shared) ───────────────────────────────────────────

fn run_doh(provider: DnsProvider, running: &AtomicBool) {
    let agent = match dns::create_doh_agent() {
        Ok(a) => { info!("DoH agent ready"); a }
        Err(e) => { error!("DoH agent init: {e}"); return; }
    };

    let addr = format!("{LISTEN_ADDR}:{LISTEN_PORT}");
    let sock = UdpSocket::bind(&addr).unwrap_or_else(|e| {
        panic!("bind {addr}: {e}. Is another instance running?");
    });
    sock.set_read_timeout(Some(std::time::Duration::from_millis(500))).ok();

    let mut buf = [0u8; 512];
    info!("listening on {addr} (DoH → {provider:?})");

    while running.load(Ordering::SeqCst) {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if n < 12 { continue; }
                if let Some(resp) = dns::doh_resolve(&agent, provider, &buf[..n]) {
                    let _ = sock.send_to(&resp, src);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                if running.load(Ordering::SeqCst) { error!("recv: {e}"); }
            }
        }
    }
}

fn run_dot(provider: DnsProvider, running: &AtomicBool) {
    let mut conn = match dns::create_dot_conn(provider) {
        Ok(c) => { info!("DoT connection established"); c }
        Err(e) => { error!("DoT connect: {e}"); return; }
    };

    let addr = format!("{LISTEN_ADDR}:{LISTEN_PORT}");
    let sock = UdpSocket::bind(&addr).unwrap_or_else(|e| {
        panic!("bind {addr}: {e}");
    });
    sock.set_read_timeout(Some(std::time::Duration::from_millis(500))).ok();

    let mut buf = [0u8; 512];
    info!("listening on {addr} (DoT → {provider:?})");

    while running.load(Ordering::SeqCst) {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if n < 12 { continue; }
                match dns::dot_query(&mut conn, &buf[..n]) {
                    Ok(resp) => { let _ = sock.send_to(&resp, src); }
                    Err(e) => {
                        log::warn!("DoT query failed: {e}, reconnecting...");
                        match dns::create_dot_conn(provider) {
                            Ok(c) => conn = c,
                            Err(e2) => error!("DoT reconnect: {e2}"),
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                if running.load(Ordering::SeqCst) { error!("recv: {e}"); }
            }
        }
    }
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

// ── Platform: loopback ─────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn setup_loopback() {
    let _ = Command::new("ifconfig")
        .args(["lo0", "alias", LISTEN_ADDR, "255.255.255.255"])
        .status();
}

#[cfg(target_os = "macos")]
fn teardown_loopback() {
    let _ = Command::new("ifconfig")
        .args(["lo0", "inet", LISTEN_ADDR, "-alias"])
        .status();
}

#[cfg(target_os = "linux")]
fn setup_loopback() {
    let _ = Command::new("ip")
        .args(["addr", "add", "127.0.0.2/32", "dev", "lo"])
        .status();
}

#[cfg(target_os = "linux")]
fn teardown_loopback() {
    let _ = Command::new("ip")
        .args(["addr", "del", "127.0.0.2/32", "dev", "lo"])
        .status();
}

#[cfg(target_os = "windows")]
fn setup_loopback() {
    // 127.0.0.2 is available on the loopback interface by default on Windows
}

#[cfg(target_os = "windows")]
fn teardown_loopback() {
}

// ── Platform: DNS operations ───────────────────────────────────────────

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
fn install_system_dns() {
    info!("configuring system DNS → {LISTEN_ADDR}");

    for_each_service(|service| {
        let _ = Command::new("networksetup")
            .args(["-setdnsservers", service, LISTEN_ADDR])
            .status();
    });

    let _ = std::fs::write("/etc/resolv.conf", format!("nameserver {LISTEN_ADDR}\n"));
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("DNS set to {LISTEN_ADDR}");
}

#[cfg(target_os = "macos")]
fn uninstall_system_dns() {
    for_each_service(|service| {
        let _ = Command::new("networksetup")
            .args(["-setdnsservers", service, "Empty"])
            .status();
    });
    let _ = std::fs::remove_file("/etc/resolv.conf");
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("system DNS restored");
}

#[cfg(target_os = "linux")]
fn install_system_dns() {
    info!("configuring system DNS → {LISTEN_ADDR}");
    let _ = std::fs::write("/etc/resolv.conf", format!("nameserver {LISTEN_ADDR}\n"));
    info!("DNS set to {LISTEN_ADDR}");
}

#[cfg(target_os = "linux")]
fn uninstall_system_dns() {
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
        // Format: "  XX  XX  XX  XX  Name"
        // The adapter name is after the last set of spaces
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
fn install_system_dns() {
    info!("configuring system DNS → {LISTEN_ADDR}");
    for adapter in &get_windows_adapters() {
        let _ = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", adapter, "static", LISTEN_ADDR])
            .status();
    }
    info!("DNS set to {LISTEN_ADDR}");
}

#[cfg(target_os = "windows")]
fn uninstall_system_dns() {
    for adapter in &get_windows_adapters() {
        let _ = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", adapter, "dhcp"])
            .status();
    }
    info!("system DNS restored");
}

// ── Platform: network watcher ──────────────────────────────────────────

#[cfg(target_os = "macos")]
fn on_network_change(
    _store: SCDynamicStore,
    _changed_keys: CFArray<CFString>,
    _info: &mut (),
) {
    info!("network configuration changed, reapplying DNS...");
    install_system_dns();
}

#[cfg(target_os = "macos")]
fn start_network_watcher(running: Arc<AtomicBool>) {
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
unsafe extern "system" fn on_network_change_windows(
    _context: *mut std::ffi::c_void,
    _row: *mut std::ffi::c_void,
    _notif_type: i32,
) {
    info!("network configuration changed, reapplying DNS...");
    install_system_dns();
}

#[cfg(target_os = "windows")]
fn start_network_watcher(running: Arc<AtomicBool>) {
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

// ── Parse helpers (shared) ─────────────────────────────────────────────

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
