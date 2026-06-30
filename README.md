# dns-guard

System-wide encrypted DNS proxy for macOS. Routes all DNS traffic through DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) to Cloudflare, Google, or Quad9.

## Quick Start

```bash
cargo build --release
sudo ./target/release/dns-guard --install   # once — sets system DNS to 127.0.0.1
sudo ./target/release/dns-guard --mode doh  # start DoH proxy
```

## Usage

```
dns-guard [OPTIONS]

Options:
  --mode <MODE>        doh or dot [default: doh]
  --provider <NAME>    cloudflare, google, or quad9 [default: cloudflare]
  --install            Set system DNS to 127.0.0.1
  --uninstall          Restore default DNS servers
  -v, --verbose        Enable debug logging
```

## How It Works

1. `--install` configures macOS to use `127.0.0.1` as the DNS server via `scutil`
2. `dns-guard` listens on UDP `127.0.0.1:53`
3. Every DNS query is forwarded to the chosen encrypted DNS provider
4. Responses are returned to the requesting application

No DNS leaks — all queries go through encrypted transport.

## Requirements

- macOS 11+
- Root privileges (sudo) — required for port 53 and scutil

## License

MIT
