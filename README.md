# dns-guard

System-wide encrypted DNS proxy. Routes all DNS traffic through DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) to Cloudflare, Google, or Quad9. One binary, no dependencies.

**macOS** · **Linux** · **Windows**

## Install

### Homebrew (macOS)

```bash
brew tap boukaba/tap
brew install dns-guard
```

### One-liner (any platform)

```bash
curl -fsSL https://github.com/boukaba/dns-guard/raw/main/install.sh | sh
```

Downloads the latest binary for your OS/arch to `/usr/local/bin`.

### Manual

Download the archive for your platform from the [releases page](https://github.com/boukaba/dns-guard/releases), extract, and move the binary to your `PATH`:

```bash
# macOS (universal: Intel + Apple Silicon)
curl -fsSL https://github.com/boukaba/dns-guard/releases/download/v1.0.0/dns-guard-v1.0.0-apple-darwin.tar.gz | tar xz
sudo mv dns-guard /usr/local/bin/

# Linux x86_64
curl -fsSL https://github.com/boukaba/dns-guard/releases/download/v1.0.0/dns-guard-v1.0.0-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv dns-guard /usr/local/bin/

# Windows x86_64
curl -fsSL -o dns-guard.zip https://github.com/boukaba/dns-guard/releases/download/v1.0.0/dns-guard-v1.0.0-x86_64-pc-windows-gnu.zip
unzip dns-guard.zip
mv dns-guard.exe C:\Windows\System32\
```

## Usage

```bash
sudo dns-guard [OPTIONS]
```

| Option | Description |
|---|---|
| `--mode <MODE>` | `doh` or `dot` (default: `doh`, saved to config) |
| `--provider <NAME>` | `cloudflare`, `google`, or `quad9` (saved to config) |
| `-v, --verbose` | Enable debug logging |
| `--install` | Set system DNS to `127.0.0.2` and exit |
| `--uninstall` | Restore system DNS to defaults |

**Examples:**

```bash
# Start with defaults (reads ~/.config/dns-guard/config.json)
sudo dns-guard

# Switch to Google DoH (saved for next run)
sudo dns-guard --mode doh --provider google

# One-shot: just set DNS and exit
sudo dns-guard --install
```

Press `Ctrl+C` to stop — DNS restores automatically.

## How It Works

1. **DNS install** — Sets system DNS to `127.0.0.2` using the native API per platform
2. **Proxy** — Listens on port 53, forwards every query via DoH/DoT to the chosen provider
3. **Config** — Saves last-used `mode` + `provider` to `~/.config/dns-guard/config.json`
4. **Watcher** — Monitors network changes and re-applies DNS automatically on interface changes
5. **Cleanup** — Restores original DNS and removes loopback alias on exit

### Per-platform

| | DNS management | Network watcher | Loopback |
|---|---|---|---|
| **macOS** | `networksetup` + `/etc/resolv.conf` | `SCDynamicStore` | `ifconfig lo0 alias` |
| **Linux** | `/etc/resolv.conf` | netlink socket (`RTMGRP_LINK`) | `ip addr add dev lo` |
| **Windows** | `netsh interface ip set dns` | `NotifyIpInterfaceChange` | Default loopback |

## Providers

| Provider | DoH | DoT |
|---|---|---|
| Cloudflare | `https://cloudflare-dns.com/dns-query` | `1.1.1.1:853` |
| Google | `https://dns.google/dns-query` | `8.8.8.8:853` |
| Quad9 | `https://dns.quad9.net/dns-query` | `9.9.9.9:853` |

## Config

Settings persist to `~/.config/dns-guard/config.json`:

```json
{
  "mode": "doh",
  "provider": "cloudflare"
}
```

CLI flags override the config. Run `sudo dns-guard --mode dot` once, and subsequent runs without flags keep using DoT.

## Requirements

- **macOS 11+ / Linux / Windows**
- **Root privileges** — required for port 53 and DNS configuration
- **Rust** only needed if building from source

## Build from source

```bash
git clone https://github.com/boukaba/dns-guard.git
cd dns-guard
cargo build --release
sudo ./target/release/dns-guard --mode doh
```

## License

MIT
