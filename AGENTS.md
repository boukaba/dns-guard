# AGENTS.md — dns-guard

## Build commands

```bash
# DNS proxy CLI
cd ~/dns_proxy
cargo build --release

# Tauri GUI (requires proxy binary built first)
cd ~/dns-guard-gui
cp ../dns_proxy/target/release/dns-guard src-tauri/binaries/dns-guard
npm install
cargo tauri build
```

## Deploy for testing

```bash
# Clean stale processes and state first
pkill -x dns-guard 2>/dev/null; sudo pkill -x dns-guard 2>/dev/null
rm -f ~/.config/dns-guard/dns-guard.sock ~/.config/dns-guard/state.json ~/.config/dns-guard/server.pid
rm -f /tmp/dns-guard.sock  # legacy socket location from pre-1.2 builds

# Copy fresh bundle to Desktop
rm -rf ~/Desktop/dns-guard.app
cp -R ~/dns-guard-gui/src-tauri/target/release/bundle/macos/dns-guard.app ~/Desktop/dns-guard.app
echo "APPL????" | tr -d '\n' > ~/Desktop/dns-guard.app/Contents/PkgInfo
codesign -f -s - --deep ~/Desktop/dns-guard.app

# Launch (or just open from Finder)
open ~/Desktop/dns-guard.app
```

## Offline builds

If crates.io is unreachable:
```bash
CARGO_NET_OFFLINE=true cargo build --release
```

## Next Steps

1. Test full flow: Start (native panel/Touch ID) → verify DNS resolves → change provider/strategy → verify live hot-swap → change mode → verify hot-swap → Stop → close GUI → verify DNS restored
2. Add hover-over/disable for Controls when proxy not running (UX polish)

## Architecture

```
dns_proxy/                    CLI binary (dns-guard)
  src/main.rs                 CLI args, daemonize, platform code (DNS, loopback, watchers)
  src/dns.rs                  DoH/DoT resolvers, Provider/Mode/Strategy enums
  src/grpc.rs                 gRPC server (tonic, Unix socket), ProxyService + RunningProxy
  src/state.rs                Persistent runtime state (pidfile, state.json, config.json)
  proto/dns_guard.proto       Service definition
  Cargo.toml                  tonic, prost, tokio, parking_lot, tower, hyper-util

dns-guard-gui/                Tauri v2 + Svelte 5 GUI
  src-tauri/
    src/commands.rs           Tauri commands using direct gRPC client (tonic + prost)
    src/lib.rs                App builder, setup hook (daemon retry loop + log stream), close cleanup
    src/main.rs               Entry point
    src/build.rs              Compiles proto via tonic-build at build time
    binaries/dns-guard        Bundled CLI binary (copied before build)
    Info.plist                Custom macOS Info.plist (Tauri picks it up)
    tauri.conf.json           Bundle config, window size, resources
  src/
    App.svelte                Main UI: auth dialog, start/stop flow, log viewer, config controls
    lib/api.ts                Tauri invoke wrappers
    lib/components/           StatusBar, Controls, ActionButtons, LogViewer, PreferencesDrawer
```

## Modes

dns-guard has two independent run modes:

**Silent gRPC server** (`dns-guard serve`)
- Listens on a Unix socket at `~/.config/dns-guard/dns-guard.sock` (chmod 0o600, owner-only; override with `DNS_GUARD_SOCKET`), waits for start/stop/status/logs commands.
- `--daemon` flag double-forks into background, writes server.pid, redirects logs to `~/.config/dns-guard/server.log`.
- On startup, reads `~/.config/dns-guard/state.json` — if a proxy PID is recorded and alive, it **adopts** it (also adopts lazily on every `status()` call, so GUI-supervised proxies are picked up on the first poll).
- Spawns proxy as foreground child (via sudo with password from `SetPassword`) — the **CLI-only** flow; captures stdout/stderr for log streaming.
- Adopted proxies (GUI-supervised, root-spawned via AuthorizationServices) are not children — the daemon **tails `proxy.log`** (world-readable 0o644) from its current end into the log broadcast.
- **Per-query events** — the proxy appends one JSON line per query to `query.log` (world-readable, truncated at proxy start). The daemon tails it like proxy.log: on tail start it replays the whole current file into **stats only** (GetStats), then broadcasts new records live (WatchQueries, 500-record history ring). A truncation (new proxy session) resets stats and replays again.
- **Block/allow policy** — lives in `config.json` under `"policy": [{"pattern", "action"}]`. The proxy refreshes it every 500ms alongside provider/strategy (hot-swap). Semantics: patterns match the domain + subdomains (`"example.com"` → `example.com`, `*.example.com`); allow overrides block; default allow; blocked queries get NXDOMAIN (well-formed: section counts zeroed, unlike the echoed EDNS0-carrying question header). `SetPolicy`/`GetPolicy` RPCs need no password. `state::save_config`/`save_policy` are read-modify-write over config.json so sections never clobber each other.
- **REST API** — the daemon also binds `http://127.0.0.1:8090` (axum, `src/rest.rs`): JSON mirror of the gRPC service + SSE streams (`/api/v1/queries/stream`, `/api/v1/logs/stream`) + `/openapi.yaml` (embedded from `docs/openapi.yaml`) for agent discovery. `DNS_GUARD_HTTP_PORT` overrides, `DNS_GUARD_HTTP=0` disables. Note: TCP 127.0.0.1 is weaker isolation than the 0600 unix socket (any local user).
- Persists proxy state to disk on every start/stop.
- Supports config hot-swap: `set_config` RPC always writes `config.json` (no password needed); SIGHUP is best-effort and only for password-managed children — the GUI sends its own SIGHUP via its AuthorizationRef, and the proxy polls every 500ms regardless.
- Logs fan out via a broadcast channel + 500-line history ring; every `Logs` subscriber gets history then live lines. New subscribers never steal the stream from existing ones.

**Direct mode** (`dns-guard --mode doh`)
- No gRPC. Starts DNS proxy immediately (foreground by default).
- `--background` double-forks into a daemon, writes pid + mode to state.json, logs to `proxy.log` (chmod 0o644 so a user-level daemon can tail it).
- `--state-dir DIR` overrides the state/config/log directory (GUI passes it so a root-spawned proxy writes to the user's dir; also honored via `DNS_GUARD_DIR`).
- `--install` / `--uninstall` configure system DNS.
- Loops on mode change: when `run_doh` returns `Some(new_config)`, re-enters with `run_dot` (or vice versa).
- Multi-threaded relay: UDP dispatch thread + 8-worker resolution pool (DoH) / 4-connection DoT pool, plus a TCP :53 fallback listener for truncated responses. Responses are TTL-cached (2048 entries) and re-ID'd per client.
- Strategy is per-query: failover advances only when the current strategy is Failover, so provider/strategy hot-swap live (no restart).

**Client commands** (`dns-guard start|stop|status|logs|set-password|stats|policy --addr SOCKET`)
- Talk to a running gRPC server via CLI.
- `--json` outputs machine-parseable JSON for GUI integration.

## Flow (GUI)

```
App opens → setup thread → ensure_server()
           → if socket dead: spawns `dns-guard serve --daemon`
           → polls status for 2s until daemon is responsive
           → starts background log stream thread (dedicated tokio runtime)
           → UI polls getStatus + getLogs every 2s
User clicks Start → authorize (first time: native macOS admin panel — password or
  Touch ID via AuthorizationCreate/CopyRights; macOS caches the grant ~5 min,
  so later calls don't re-prompt)
  → AuthorizationExecuteWithPrivileges spawns `dns-guard --mode doh --provider X
    --strategy Y --background --state-dir ~/.config/dns-guard` as ROOT (daemonizes)
  → proxy writes state.json, sets DNS to 127.0.0.2, listens on 127.0.0.2:53
  → GUI polls status → daemon's status() adopts the proxy + starts tailing proxy.log
User changes config → saveConfig Tauri command → gRPC set_config (daemon writes
  config.json) + SIGHUP via AuthorizationRef (root kill -HUP <pid>)
  → provider/strategy switches instantly, no restart; mode change re-enters loop
User changes mode → similar path; proxy returns Some(config) → cmd_standalone re-enters with new mode
User clicks Stop → kill -INT <real_pid> via AuthorizationRef (no sudo wrapper)
  → proxy catches SIGINT → cleanup → exit → daemon clears state.json on next poll
Close app → cleanup() (no prompt): if a grant is cached, kill -INT proxy → wait
  for DNS restore → gRPC Shutdown (daemon stops proxy if it can, removes
  server.pid, exits) → fallback SIGTERM daemon via server.pid
  → proxy (if still running) becomes orphan, continues running
Restart app → reconnects to existing daemon (or spawns new one)
  → load_or_new() picks up state.json → adopts live proxy + tails its log
```

The password-based CLI flow is unchanged: `dns-guard set-password` → daemon stores
the password in memory and spawns `sudo -S dns-guard ...` as a foreground child
(CLI supervision), with `sudo -n` first / `sudo -S` fallback for signals.

## Key rules

- **Daemonize BEFORE tokio runtime** — fork + setsid in `fn main()`, not in async context. Otherwise the child inherits a broken kqueue I/O driver and `bind()` returns EBADF.
- **Stop targets the real proxy PID**, not a wrapper PID. The daemon reads state.json (written by the proxy itself) to find the real PID; the GUI signals it directly via `AuthorizationExecuteWithPrivileges("/bin/kill", ...)`.
- **On stop failure**, `state.json` is NOT cleared — the proxy is re-adopted so the GUI can retry after re-auth.
- **`ensure_server` is mutex-guarded** in `ProxyState::server_lock` to prevent setup thread and Tauri commands from racing to spawn the daemon.
- **Log stream is started on every `ensure_server` success path** (new server OR reconnecting to existing server). `start_log_stream()` kills any previous log child before spawning a new one.
- **Native macOS auth (GUI)** — the GUI holds one `AuthorizationRef` (Security framework): `AuthorizationCreate` + `AuthorizationCopyRights` (kAuthorizationRightExecute, interaction allowed) show the system admin panel (password or Touch ID); macOS caches the grant ~5 min so Start/Stop rarely re-prompt. `AuthorizationExecuteWithPrivileges` runs the proxy / `/bin/kill` as root — no password is ever stored. Deprecated-but-functional API; do not use it to launch anything other than dns-guard and /bin/kill.
- **sudo (CLI flow only)** — `sudo -n` first, `sudo -S` fallback for daemon-spawned (password-managed) children; `set_password` uses `sudo -S -v` to validate AND refresh the cache.
- **Never use `sudo kill <pid>` from user context** — use `sudo pkill -x` or `sudo kill` to signal root-owned processes
- **GUI-supervised proxies are never daemon children** — the daemon adopts them lazily on `status()` and tails `proxy.log` from its current end (no replay of previous sessions). The proxy `--background` logs to `proxy.log` chmod 0o644 (root writes, user daemon reads).
- **`--state-dir DIR` / `DNS_GUARD_DIR`** — root-spawned proxies must be pointed at the user's state dir (HOME may differ under root). The GUI always passes `--state-dir`.
- **macOS .app needs PkgInfo** file in Contents/ and ad-hoc codesigning to avoid Terminal launch
- **Linux cross-compile requires `openssl-sys` with vendored feature`
- **Standalone CLI mode still works** — `sudo dns-guard --mode doh` runs with no gRPC
- **start_proxy / stop_proxy never spawn the daemon themselves** — `ensure_server` is called up front; the daemon is only started by the setup thread or authorize/start. Prevents accidental dual-daemon.
- **Config hot-swap via file polling** — proxy checks `config.json` every 500ms in event loop. Provider/strategy changes take effect without restart. Mode changes cause loop function to return and `cmd_standalone` re-enters with correct mode.
- **Failover state is strategy-agnostic** — `FailoverState` tracks the sticky provider index only; `on_failure` advances only when the current per-query strategy is Failover, so hot-swapping INTO failover engages it live.
- **`state::save_config` removes file before writing** — because previous write by root-owned proxy leaves file root-owned, preventing non-root daemon from overwriting.
- **config.json lives in `state::dir()`** — the proxy's `Config::path()` uses `guard_state::dir()`, NOT HOME, so `--state-dir`/`DNS_GUARD_DIR` and the daemon agree on the file. Both writers (proxy hot-swap poll, daemon save_config/save_policy) are read-modify-write; `Config` fields are all `#[serde(default)]` so a partial file (e.g. policy-only) parses.
- **SERVFAIL/NXDOMAIN responses zero the section counts (bytes 6..12)** — dig queries carry EDNS0 OPT records; echoing the header ARCOUNT without the OPT makes clients report "malformed message packet".

## Known limitations

- **Native auth grant caching** — macOS caches the admin grant ~5 min; Stop/Start after the window re-shows the system panel (password or Touch ID). No password is stored anywhere.
- **No proxy adoption on macOS after system sleep** — if the proxy is killed while the machine sleeps, the daemon will detect a stale PID on wake and clear state.json. Next status poll returns `running: false`.
- **Closing the app without a cached grant leaves the proxy running** — cleanup never prompts; the proxy keeps running (DNS stays on 127.0.0.2) and is adopted on the next launch.
- **gRPC logs come from the proxy child's stdout (CLI flow) or `proxy.log` tail (GUI flow)** — the log tail starts at the current end of the file, so lines from a previous session aren't replayed. The daemon keeps a 500-line history ring for new subscribers.
