mod dns;

use clap::Parser;
use dns::{DnsMode, DnsProvider};
use log::{error, info};
use std::net::UdpSocket;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const LISTEN_ADDR: &str = "127.0.0.2";
const LISTEN_PORT: u16 = 53;

#[derive(Parser)]
#[command(name = "dns-guard", about = "System-wide encrypted DNS proxy for macOS")]
struct Cli {
    #[arg(long = "mode", default_value = "doh")]
    mode: String,

    #[arg(long = "provider", default_value = "cloudflare")]
    provider: String,

    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    #[arg(long = "install", help = "Set system DNS to 127.0.0.2")]
    install: bool,

    #[arg(long = "uninstall", help = "Restore default DNS servers")]
    uninstall: bool,
}

fn main() {
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(if cli.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .format_timestamp_secs()
        .init();

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("error: must run as root (sudo)");
        std::process::exit(1);
    }

    if cli.uninstall {
        uninstall_system_dns();
        return;
    }
    if cli.install {
        install_system_dns();
        return;
    }

    let mode = parse_mode(&cli.mode);
    let provider = parse_provider(&cli.provider);

    info!("dns-guard starting (mode={mode:?}, provider={provider:?})");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("failed to set Ctrl-C handler");

    match mode {
        DnsMode::DoH => run_doh(provider, &running),
        DnsMode::DoT => run_dot(provider, &running),
    }

    info!("dns-guard stopped");
}

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

fn install_system_dns() {
    info!("configuring system DNS → {LISTEN_ADDR}");

    // Create loopback alias
    let _ = Command::new("ifconfig")
        .args(["lo0", "alias", LISTEN_ADDR, "255.255.255.255"])
        .status();

    // Set DNS on all active network services
    for service in &["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN", "Thunderbolt Bridge"] {
        let _ = Command::new("networksetup")
            .args(["-setdnsservers", service, LISTEN_ADDR])
            .status();
    }

    let _ = std::fs::write("/etc/resolv.conf", format!("nameserver {LISTEN_ADDR}\n"));
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("DNS set to {LISTEN_ADDR} — run 'sudo dns-guard --mode doh' to start");
}

fn uninstall_system_dns() {
    // Remove loopback alias
    let _ = Command::new("ifconfig")
        .args(["lo0", "alias", LISTEN_ADDR, "-alias"])
        .status();

    // Restore DNS on all network services to DHCP default (empty = automatic)
    for service in &["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN", "Thunderbolt Bridge"] {
        let _ = Command::new("networksetup")
            .args(["-setdnsservers", service, "Empty"])
            .status();
    }

    let _ = std::fs::remove_file("/etc/resolv.conf");
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("system DNS restored");
}

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
