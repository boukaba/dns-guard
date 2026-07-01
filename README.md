# dns-guard

System-wide encrypted DNS proxy for macOS. Routes all DNS traffic through DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) to Cloudflare, Google, or Quad9.

## Quick Start

```bash
sudo ./target/release/dns-guard --install     # once: set system DNS to 127.0.0.2
sudo ./target/release/dns-guard --mode doh    # start DoH proxy
# Ctrl+C to stop — DNS auto-restores
```

In another terminal: `dig google.com` → resolves via encrypted DoH. DNS leak tests show only Cloudflare.

## How It Works

1. `--install` sets DNS to `127.0.0.2` via `networksetup` (WiFi, Ethernet, etc.)
2. Proxy creates `127.0.0.2` loopback alias and binds to port 53
3. Every DNS query is forwarded via DoH/DoT to the chosen provider
4. On exit (Ctrl+C, kill, crash), DNS auto-restores to DHCP defaults

No pf, no scutil, no kernel extensions. Pure userspace.

## Usage

```
dns-guard [OPTIONS]

Options:
  --mode <MODE>        doh or dot [default: doh]
  --provider <NAME>    cloudflare, google, or quad9 [default: cloudflare]
  --install            Set system DNS to 127.0.0.2 (run once)
  --uninstall          Restore DNS to DHCP defaults
  -v, --verbose        Enable debug logging
```

## DNS Modes

| Mode | Transport | Speed |
|------|-----------|-------|
| `doh` | HTTPS POST to provider | Fast (TLS connection pooling) |
| `dot` | TLS to port 853 | Good (auto-reconnect) |

## Requirements

- macOS 11+
- Root privileges (`sudo`) — required for port 53, loopback alias, `networksetup`

## License

MIT
