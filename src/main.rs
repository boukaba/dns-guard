mod dns;

use clap::Parser;
use dns::{DnsMode, DnsProvider};
use log::{error, info};
use std::net::UdpSocket;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "dns-guard", about = "System-wide encrypted DNS proxy for macOS")]
struct Cli {
    #[arg(long = "mode", default_value = "doh")]
    mode: String,

    #[arg(long = "provider", default_value = "cloudflare")]
    provider: String,

    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    #[arg(long = "install", help = "Set system DNS to 127.0.0.1 (localhost)")]
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
        eprintln!("error: must run as root (sudo) — required to listen on port 53 and configure DNS");
        std::process::exit(1);
    }

    if cli.uninstall {
        uninstall_system_dns();
        return;
    }
    if cli.install {
        install_system_dns();
        info!("system DNS set to 127.0.0.1 — run dns-guard in another terminal to start resolving");
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
        Ok(a) => {
            info!("DoH agent ready");
            a
        }
        Err(e) => {
            error!("DoH agent init failed: {e}");
            return;
        }
    };

    let sock = UdpSocket::bind("127.0.0.1:53").expect("bind :53 (are you root?)");
    sock.set_read_timeout(Some(std::time::Duration::from_millis(500))).ok();

    let mut buf = [0u8; 512];
    info!("listening on 127.0.0.1:53 (DoH to {:?})", provider);

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
        Ok(c) => {
            info!("DoT connection established");
            c
        }
        Err(e) => {
            error!("DoT connect failed: {e}");
            return;
        }
    };

    let sock = UdpSocket::bind("127.0.0.1:53").expect("bind :53");
    sock.set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .ok();

    let mut buf = [0u8; 512];
    info!("listening on 127.0.0.1:53 (DoT to {:?})", provider);

    while running.load(Ordering::SeqCst) {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if n < 12 {
                    continue;
                }
                match dns::dot_query(&mut conn, &buf[..n]) {
                    Ok(resp) => {
                        let _ = sock.send_to(&resp, src);
                    }
                    Err(e) => {
                        log::warn!("DoT query failed: {e}, reconnecting...");
                        match dns::create_dot_conn(provider) {
                            Ok(c) => conn = c,
                            Err(e2) => error!("DoT reconnect failed: {e2}"),
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                if running.load(Ordering::SeqCst) {
                    error!("recv error: {e}");
                }
            }
        }
    }
}

fn install_system_dns() {
    scutil(&format!(
        "d.init\nd.add ServerAddresses * 127.0.0.1\nset State:/Network/Global/DNS\nquit\n"
    ));
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
}

fn uninstall_system_dns() {
    scutil("remove State:/Network/Global/DNS\nquit\n");
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    let _ = Command::new("killall").arg("-HUP").arg("mDNSResponder").status();
    info!("system DNS restored to default");
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
