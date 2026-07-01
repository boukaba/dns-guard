mod dns;

use clap::Parser;
use dns::{DnsMode, DnsProvider};
use log::{error, info};
use std::net::UdpSocket;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const LISTEN_PORT: u16 = 5300;

#[derive(Parser)]
#[command(name = "dns-guard", about = "System-wide encrypted DNS proxy for macOS")]
struct Cli {
    #[arg(long = "mode", default_value = "doh")]
    mode: String,

    #[arg(long = "provider", default_value = "cloudflare")]
    provider: String,

    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    #[arg(long = "install", help = "Set system DNS to 127.0.0.1 + pf redirect")]
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

    let addr = format!("127.0.0.1:{LISTEN_PORT}");
    let sock = UdpSocket::bind(&addr).unwrap_or_else(|e| {
        panic!("bind {addr}: {e} (is port {LISTEN_PORT} free?)");
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

    let addr = format!("127.0.0.1:{LISTEN_PORT}");
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
    info!("installing system DNS → 127.0.0.1:{LISTEN_PORT}");

    // 1. Set system DNS to 127.0.0.1
    scutil("d.init\nd.add ServerAddresses * 127.0.0.1\nset State:/Network/Global/DNS\nquit\n");
    let _ = std::fs::write("/etc/resolv.conf", "nameserver 127.0.0.1\n");

    // 2. pf redirect: 127.0.0.1:53 → 127.0.0.1:5300
    let pf_rule = format!(
        "rdr pass on lo0 inet proto udp from any to 127.0.0.1 port 53 -> 127.0.0.1 port {LISTEN_PORT}\n"
    );
    let _ = std::fs::write("/etc/pf.anchors/dns-guard", &pf_rule);

    // Insert our anchor into main pf.conf if not already there
    let anchor_line = "dns-guard";
    let pf_conf_path = "/etc/pf.conf";
    let existing = std::fs::read_to_string(pf_conf_path).unwrap_or_default();
    if !existing.contains(&format!("anchor \"{anchor_line}\"")) {
        let new_conf = format!("{existing}\nanchor \"{anchor_line}\"\nload anchor \"{anchor_line}\" from \"/etc/pf.anchors/dns-guard\"\n");
        let _ = std::fs::write(pf_conf_path, new_conf);
    }

    // Reload pf
    let _ = Command::new("pfctl").args(["-E"]).status();
    let _ = Command::new("pfctl").args(["-f", "/etc/pf.conf"]).status();

    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("system DNS configured — run 'sudo dns-guard --mode doh' to start");
}

fn uninstall_system_dns() {
    // Remove pf anchor
    let _ = Command::new("pfctl").args(["-a", "dns-guard", "-F", "all"]).status();
    let _ = std::fs::remove_file("/etc/pf.anchors/dns-guard");

    // Remove anchor line from pf.conf
    if let Ok(conf) = std::fs::read_to_string("/etc/pf.conf") {
        let cleaned: Vec<&str> = conf.lines()
            .filter(|l| !l.contains("anchor \"dns-guard\"") && !l.contains("load anchor \"dns-guard\""))
            .collect();
        let _ = std::fs::write("/etc/pf.conf", cleaned.join("\n") + "\n");
        let _ = Command::new("pfctl").args(["-f", "/etc/pf.conf"]).status();
    }

    scutil("remove State:/Network/Global/DNS\nquit\n");
    let _ = std::fs::remove_file("/etc/resolv.conf");
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("system DNS restored");
}

fn scutil(script: &str) {
    if let Ok(mut child) = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }
        let _ = child.wait();
    }
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
