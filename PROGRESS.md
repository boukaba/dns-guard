# PROGRESS.md — dns-guard

## Goal
Build a cross-platform encrypted DNS proxy (DoH/DoT) with a Tauri GUI, controllable via gRPC, with system DNS integration on macOS/Linux/Windows.

## Done

### CLI (dns-guard)
- [x] DoH and DoT DNS resolution (Cloudflare, Google, Quad9)
- [x] Round-robin, failover, single provider strategies
- [x] System DNS install/uninstall per platform (macOS networksetup, Linux resolv.conf, Windows netsh)
- [x] Loopback alias 127.0.0.2 for port 53 listener
- [x] Cross-platform build (macOS universal binary, Linux/Windows via zigbuild)
- [x] Network change watchers: macOS SCDynamicStore, Linux netlink, Windows NotifyIpInterfaceChange
- [x] JSON config auto-save/restore at `~/.config/dns-guard/config.json`
- [x] **gRPC server** on Unix socket `/tmp/dns-guard.sock` (tonic + prost)
  - `serve` subcommand starts daemon (runs as **user**, no sudo)
  - `start`/`stop`/`status`/`logs`/`setConfig` CLI client commands
  - Start handler spawns `sudo dns-guard` standalone (root) for DNS ops
  - Stop handler sends `sudo kill -INT` for graceful DNS restoration
  - Log streaming via gRPC server-side streaming
- [x] Published Homebrew formula (v1.1.0) at `boukaba/homebrew-tap`
- [x] Cross-platform install script

### GUI (dns-guard-gui, Tauri v2 + Svelte 5)
- [x] Svelte 5 UI: StatusBar, Controls (mode/provider/strategy), ActionButtons, LogViewer, PreferencesDrawer
- [x] `dns-guard serve` auto-starts on app launch via Tauri `setup()` hook (no auth needed)
- [x] Auth dialog: `sudo -S -v` caches credentials
- [x] Start: calls `dns-guard start --addr /tmp/dns-guard.sock` → gRPC → spawns proxy
- [x] Stop: calls `dns-guard stop --addr /tmp/dns-guard.sock` → gRPC → `sudo kill -INT`
- [x] Status polling every 2s via `dns-guard status`
- [x] Log capture from gRPC daemon stdout/stderr
- [x] Window close handler kills gRPC daemon process
- [x] macOS .app bundle: PkgInfo, ad-hoc signing, custom Info.plist, bundled binary
- [x] Config persistence with 500ms debounce to `~/.config/dns-guard/config.json`
- [x] 3-second timeout on all gRPC client commands (no more freezing)

### macOS packaging
- [x] Ad-hoc codesigning (`codesign -f -s - --deep dns-guard.app`)
- [x] PkgInfo file (`APPL????`) to ensure Finder shows as app
- [x] `NSHighResolutionCapable` in Info.plist
- [x] Bundled `dns-guard` binary in Resources/binaries/

## Architecture decisions

| Decision | Rationale |
|---|---|
| Unix socket (`/tmp/dns-guard.sock`) vs TCP | No IP conflicts, no port conflicts, simpler permissions |
| gRPC daemon runs as user | No sudo required to start app, auth only needed for proxy start |
| gRPC server spawns `sudo dns-guard` standalone | Standalone binary handles DNS/loopback/port53; server just manages lifecycle |
| Tauri `setup()` hook starts serve | Service boots before any user action, Start/Stop are instant |
| `sudo kill -INT` for stop | Triggers ctrlc handler → uninstall_system_dns() → graceful shutdown |
| tonic 0.12 with `connect_with_connector_lazy` | Lazier connection; Works with custom UdsConnector for Unix sockets |
| parking_lot Mutex/RwLock | Faster than std; used in gRPC server shared state |

## File structure

```
dns_proxy/
  src/main.rs          # CLI, subcommands, platform-specific DNS/watchers
  src/dns.rs           # DoH/DoT resolvers, Provider/Mode/Strategy
  src/grpc.rs          # gRPC server, ProxyService, UdsConnector
  proto/dns_guard.proto # gRPC service definition
  Cargo.toml

dns-guard-gui/
  src-tauri/
    src/commands.rs    # Tauri commands, run_client helper with timeout
    src/lib.rs         # App builder, setup hook, window event handler
    src/main.rs        # Entry
    binaries/dns-guard # Bundled CLI binary
    tauri.conf.json
    Info.plist         # Custom macOS plist
  src/
    App.svelte         # Main UI
    lib/api.ts         # Tauri invoke wrappers
    lib/types.ts       # TS types
    lib/components/    # Svelte components
```

## Next steps

- [ ] Fix `setConfig` to properly persist config and restart proxy
- [ ] Live log streaming in GUI (currently polls, should gRPC stream)
- [ ] System tray icon for background operation
- [ ] Windows and Linux GUI builds
- [ ] Code signing with Apple Developer cert for distribution
- [ ] Add `dns-guard` to PATH on install for CLI client commands
- [ ] Auto-start on login option
- [ ] Custom DNS provider support (user-specified DoH/DoT endpoints)
- [ ] DNS blocklists / ad blocking
- [ ] IPv6 support
