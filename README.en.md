# fairlead

[中文](README.md) · **English**

[![ci](https://github.com/hustfyb/fairlead/actions/workflows/ci.yml/badge.svg)](https://github.com/hustfyb/fairlead/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/hustfyb/fairlead?sort=semver)](https://github.com/hustfyb/fairlead/releases)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)

A single-node, self-hosted reverse TCP tunnel: machines on the inside dial out, and the public entry point routes each request to a local port by its `Host` header. No inbound ports to open, no Nginx edit for every new domain.

```
                               ┌── Host: admin.example.com   ──> admin console
client/agent ──:9000 (one port)┼── Host: tunnel.example.com + Upgrade ──> tunnel control plane
                               └── any other Host ──────────> forwarded by the route table

fairlead host ──yamux (2 per agent)──> agent A / agent B ──> 127.0.0.1:7884 / :7885
```

One port is the data plane, the control plane and the admin plane at once: **each request says which plane it belongs to** (`Host`, plus an `Upgrade` for tunnels). TLS is not done here. For HTTPS, put Nginx in front; all it has to do is pass `Host` and `Upgrade` through untouched.

- **One binary**, and the first word picks the role: `host` / `agent` / `admin` / `token` / `gen-nginx` / `doctor` / `demo`.
- **Mac / Linux / Windows** from one source tree and one wire protocol. The Linux builds are static musl with no glibc dependency; the Windows build needs no VC++ runtime.
- Design tradeoffs are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), the reasoning behind the choices in [`docs/DECISIONS.md`](docs/DECISIONS.md), release rules in [`docs/RELEASE.md`](docs/RELEASE.md).

## Installation

Every release ships binaries for five platforms, all cross-compiled from the same source with `cargo zigbuild`:

| Platform | Artifact |
| --- | --- |
| macOS Apple Silicon | `fairlead-<ver>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `fairlead-<ver>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (static, runs on glibc or musl) | `fairlead-<ver>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 (static) | `fairlead-<ver>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `fairlead-<ver>-x86_64-pc-windows-gnu.zip` |

```bash
# Linux / macOS
curl -LO https://github.com/hustfyb/fairlead/releases/download/v0.1.2/fairlead-0.1.2-x86_64-unknown-linux-musl.tar.gz
sha256sum -c <(grep x86_64-unknown-linux-musl SHA256SUMS)   # verify first
tar -xzf fairlead-0.1.2-x86_64-unknown-linux-musl.tar.gz
sudo install -m755 fairlead-0.1.2-x86_64-unknown-linux-musl/fairlead /usr/local/bin/fairlead
```

```powershell
# Windows (PowerShell)
Expand-Archive fairlead-0.1.2-x86_64-pc-windows-gnu.zip .
.\fairlead-0.1.2-x86_64-pc-windows-gnu\fairlead.exe --version
```

On macOS the first run is blocked by Gatekeeper (the binaries are not notarized):

```bash
xattr -d com.apple.quarantine ./fairlead
```

You can also build from source instead of downloading binaries (stable Rust):

```bash
cargo install --path crates/fairlead --locked
```

Build the release artifacts yourself:

```bash
./scripts/build-dist.sh      # cross-compiles all five targets (needs zig)
./scripts/package.sh all     # produces dist/*.tar.gz, dist/*.zip and SHA256SUMS
```

## See it run in 30 seconds (no Nginx needed)

```bash
cargo run -- demo
```

This starts a host, an agent and two demo origins on loopback, **everything on one random port**, and prints curl commands you can paste as they are:

```bash
curl -H 'Host: a1.relay.test' http://127.0.0.1:<port>/
curl -N -H 'Host: a1.relay.test' http://127.0.0.1:<port>/stream      # arrives chunk by chunk, unbuffered
curl -H 'Host: a2.relay.test' http://127.0.0.1:<port>/big?mb=64      # 64MB
curl -H 'Host: a1.relay.test' http://127.0.0.1:<port>/echo           # shows the headers the origin received
curl -o /dev/null -w '%{http_code}\n' -H 'Host: nope.relay.test' http://127.0.0.1:<port>/  # 404
curl -H 'Host: admin.relay.test' http://127.0.0.1:<port>/login       # admin console, same port
```

The admin console has a single password (printed when the demo starts) and no username. Put `admin.relay.test` and `tunnel.relay.test` into `/etc/hosts` and you can open it in a browser.

## Deployment

### 1. Host (the public entry machine)

Installing the relay itself uses the same script:

```bash
curl -fsSLO https://app.relay.example.com/install.sh   # any relay will do
sh install.sh host                                     # binary + host.toml + fairlead-host service
fairlead admin passwd --config ~/.config/fairlead/host.toml
$EDITOR ~/.config/fairlead/host.toml                   # listen, tunnel_host, allowed_suffixes
fairlead doctor --config ~/.config/fairlead/host.toml
```

Add `--no-service` if you do not want a service. Or install by hand, for the same result:

```bash
cp deploy/host.toml /etc/fairlead/host.toml
$EDITOR /etc/fairlead/host.toml      # listen, admin_host, tunnel_host, allowed_suffixes

export FAIRLEAD_ADMIN_PASSWORD='at least ten characters'          # admin password, read at startup
fairlead doctor --config /etc/fairlead/host.toml            # runs its checks and prints a paste-ready agent config
fairlead host   --config /etc/fairlead/host.toml
```

The password is not in the config file. Either use the environment variable (in systemd: `Environment=` / `EnvironmentFile=`) or write it into the database with `fairlead admin passwd --config /etc/fairlead/host.toml`. Neither one touches the TOML.

Nginx needs one server block (HTTP or HTTPS) whose `proxy_pass` points at `server.listen`. `Host` and `Upgrade` pass through untouched and the host splits the three planes itself:

```bash
fairlead gen-nginx --config /etc/fairlead/host.toml > /etc/nginx/conf.d/fairlead.conf
nginx -t && nginx -s reload
```

Or just use `deploy/docker-compose.yml`.

**The lines you must keep** (`gen-nginx` already writes them):

```nginx
proxy_set_header Host $host;                     # on the merged port this is the plane selector
proxy_set_header Upgrade $http_upgrade;          # this is how an agent upgrades into a tunnel
proxy_set_header Connection $fairlead_connection_upgrade;
proxy_set_header X-Forwarded-For $remote_addr;   # overwrite it; do not use $proxy_add_x_forwarded_for
proxy_buffering off; proxy_request_buffering off; # SSE and large files
```

#### Putting HTTPS in front (recommended, no port 80 needed)

The public side is usually a single high port with no 80, so the certificate comes from a **Let's Encrypt wildcard via DNS-01**: the challenge goes into DNS, so nothing has to be reachable inbound. On Cloudflare, create an API token with `Zone → DNS → Edit`:

```bash
export CF_Token=...                       # Zone / DNS / Edit, scoped to the zone
acme.sh --issue --dns dns_cf -d relay.example.com -d '*.relay.example.com'
acme.sh --install-cert -d relay.example.com --ecc \
  --fullchain-file /etc/nginx/ssl/relay.example.com.fullchain.pem \
  --key-file       /etc/nginx/ssl/relay.example.com.key.pem \
  --reloadcmd      "nginx -s reload"      # renews every 60 days and reloads itself
```

Then move the host onto loopback — `listen = "127.0.0.1:9003"`, `admin_listen = "127.0.0.1:9004"`, `public_scheme = "https"` — and let nginx own the public port. The full example is **`deploy/nginx/fairlead-tls.conf`** (two servers in `http{}`, plus the splitter in `stream{}`).

Three things hold on that one port at once:

- **HTTPS**: the `stream` layer spots TLS with `$ssl_preread_protocol` and hands it to 9101, which terminates it and speaks HTTP/1.1 to the host;
- **plaintext keeps working**: non-TLS bytes are passed through untouched, so `curl -H 'Host: a1.…'`, the forward proxy and older agents need no change;
- **agents use `tls://relay.example.com:29001`**: the agent sends ALPN `fairlead/1`, which goes to 9102 (`ssl_alpn fairlead/1`) and is forwarded raw after termination. This cannot live in `http{}` — that only offers h2/http1.1 and the handshake dies with `NoApplicationProtocol`.

The admin console works the same way (9002 all TLS, back to 9004). Browsing `https://<IP>:9002` warns about the name — the certificate only covers `*.relay.example.com`, so use the domain or click through.

### 2. Agent (the internal machine)

Start by minting a one-time token. The easiest place is the admin console: log in, then **Token → issue a one-time token**, and pick a suffix and a lifetime (30 minutes / 1 hour / 24 hours / 7 days / never). The string is **shown exactly once**. The same page carries an `install.sh` command and an `agent.toml` snippet with the token already filled in; just copy them.

If you would rather not open a browser, run this on the host instead:

```bash
# only *.relay.example.com can be registered; expires unused after 24 hours
fairlead token --config /etc/fairlead/host.toml --suffix relay.example.com --ttl 24h
```

The token goes to stdout (the two explanatory lines go to stderr) and the database keeps only its SHA-256, so nothing can show it to you afterwards; lose it and you mint another. `/tokens` shows whether it was used and by which agent, and lets you revoke it. With two machines, carry it across rather than copying by hand:

```bash
TOKEN=$(ssh relay 'fairlead token --config /etc/fairlead/host.toml --suffix relay.example.com --ttl 24h')
ssh agent "curl -fsSLO https://app.relay.example.com/install.sh && sh install.sh"
ssh agent "~/.local/bin/fairlead agent enroll $TOKEN && ~/.local/bin/fairlead agent add a1.relay.example.com 8080"
```

```bash
curl -fsSLO https://app.relay.example.com/install.sh
sh install.sh                             # installs the binary, writes config, installs the service
fairlead agent enroll <TOKEN>             # hands the token over; the service connects within two seconds
fairlead agent add a1.relay.example.com 8080
```

`install.sh` **only installs**: it picks the right archive, verifies it, installs the binary, writes a config with no routes, then installs a service (systemd on Linux, launchd on macOS, a scheduled task on Windows) and starts it. The service starts at boot and outlives the terminal. Right after installing it just waits — with no token it does not exit and does not spam the error log. `enroll` writes the token into the config, the running service reads it and connects, no restart needed. `--no-service` writes config without installing a service, `--start` runs in the foreground. Running the script again leaves your token and routes alone (an existing config is kept as is), so it is safe to repeat.

Installing the host is the same script: `sh install.sh host` gives you the binary, `host.toml` and a `fairlead-host` service, and you set the password afterwards with `fairlead admin passwd`.

**Do not add `sudo`** (unless you really do want a system-wide service). Run it as your own account: the binary goes to `~/.local/bin/fairlead`, config to `~/.config/fairlead/agent.toml`, state to `~/.local/state/fairlead`, and the service runs as you, so later `fairlead agent add` needs no password. If `~/.local/bin` is not on PATH the script prints a line to add it; the service starts by absolute path, so boot start works either way. `sudo sh install.sh …` still works and installs system-wide, into `/usr/local/bin`, `/etc/fairlead` and `/var/lib/fairlead` (config and state are chown'd back to you when `SUDO_USER` is set). Before anything else the script checks whether the target directory is writable; if it is not, it stops there and tells you which `--prefix` / `--config` to use, instead of pulling 20 MB first.

From then on **do not edit the TOML by hand**; use the commands:

```bash
fairlead agent list                     # what this machine publishes, and whether each route is serving or rejected
fairlead agent add 8080                 # publishes 127.0.0.1:8080 as a8080.<suffix>
fairlead agent add a3.relay.example.com 3000
fairlead agent rm a3.relay.example.com
fairlead agent status                   # service state, tunnel count, last error
sudo fairlead agent service restart     # also start / stop / uninstall / status
```

`add` and `rm` only edit the route table in the config file. The running service re-reads it within two seconds and re-declares, without a restart and without dropping tunnels; the relay adds and removes routes to match (whatever the agent declares is the truth). So adding a port mapping is one terminal command, and it survives closing the terminal and rebooting the machine.

The first connection trades the token for a long-lived credential, stored in `state_file` (mode 0600, default `/var/lib/fairlead/agent-state.json`). Reconnects use only the credential; the token is never used a second time.

### 3. Start on boot

Nothing to do for the agent: `install.sh` already installed it as a service, and `fairlead agent service status|restart|uninstall` is all you need. Same for the host (`install.sh host` installs `fairlead-host`, `fairlead host service status|restart|uninstall`). The unit in the repo is for installing by hand:

```bash
install -m0644 deploy/systemd/fairlead-host.service /etc/systemd/system/
systemctl enable --now fairlead-host
```

## Configuration

Two files, both `deny_unknown_fields`: a misspelled key fails at startup instead of quietly falling back to a default.

| Host | Notes |
| --- | --- |
| `server.listen` | **The merged port.** Set it and one socket serves all three planes. Leave it empty to fall back to the three separate listeners below (split mode, where the tunnel carries its own TLS) |
| `server.admin_host` | The subdomain that selects the admin plane on the merged port, e.g. `admin.relay.example.com` |
| `server.tunnel_host` | The subdomain that selects the tunnel plane on the merged port, e.g. `tunnel.relay.example.com` |
| `server.edge_listen` | Split mode: the Nginx upstream, default `127.0.0.1:9000` (a non-loopback address refuses to start) |
| `server.tunnel_listen` | Split mode: the port agents connect to, default `0.0.0.0:9443` |
| `server.admin_listen` | The admin console's own socket. Set it and the admin plane is served on this port instead (split mode default `127.0.0.1:9001`; on a merged port the admin plane then leaves `listen`). Leave it empty and the admin plane stays on `server.listen`, selected by `admin_host`. A non-loopback address needs `admin.allow_remote = true` |
| `server.allowed_suffixes` | Domain suffixes that may be registered; an empty list refuses to start |
| `landing.dir` | Artifact directory for the install page (the output of `scripts/package.sh`). Empty means off, and unknown Hosts keep getting 400/404 |
| `landing.host` | Gives the install page a fixed name, usually `app.<suffix>` (the wildcard record already points there). Once set, this Host always returns the install page even if it looks like a site, and a route of the same name is overridden by it. Requires `landing.dir` |
| `proxy.route` | Lets **the same port** act as a forward proxy: it answers `CONNECT host:port` and absolute-form requests (`GET http://host/ ...`). A short name `muse` means `muse.<first allowed suffix>`. Empty disables it |
| `proxy.auth` | `user:password`, which a client sends as `Proxy-Authorization: Basic`. Set this or `allow_from`; when both are empty the host refuses to start |
| `proxy.allow_from` | Only these client addresses may use the proxy: `10.0.0.0/8`, `203.0.113.7`, `::1` |
| `proxy.idle_timeout_secs` | Idle limit for a proxy stream. `0` (the default) means a quiet CONNECT tunnel is never dropped for being quiet |
| `tls.cert` / `tls.key` | The tunnel listener certificate in split mode; for development use `tls.dev_self_signed = true`. The merged port does no TLS and ignores both keys |
| `limits.*` | Header limits, concurrent streams, heartbeat, idle timeouts |
| `admin.password_hash` | Legacy compatibility only: it seeds the database once, when the database holds no password yet. New deployments should use `FAIRLEAD_ADMIN_PASSWORD` or `fairlead admin passwd` |
| `admin.session_ttl_secs` | Admin session lifetime, default 12h |
| `admin.allow_remote` | Allow the admin console to listen on a non-loopback address (refused by default, so a slip cannot expose the backend to the internet) |
| `admin.trust_forwarded_for` | Take the client IP from `X-Real-IP` / `X-Forwarded-For` (only behind your own proxy) |
| `admin.secure_cookie` | Set true when the admin console is behind HTTPS; adds `Secure` to the cookie |

**When you can map only one port** (no public IP from your ISP, a router that gives you a single mapping, or you simply want fewer holes):

```toml
[server]
listen = "0.0.0.0:9000"                    # the only socket; map this one
admin_host = "admin.relay.example.com"     # browsers open the admin console on this name
tunnel_host = "tunnel.relay.example.com"   # agents connect the tunnel on this name
allowed_suffixes = ["relay.example.com"]
public_port = 29001                        # only used by gen-nginx / doctor
```

Each plane gets its own subdomain and every other Host goes to the route table. In DNS (or your local `hosts`) point all three names at the same IP. **There is no TLS at this layer**: the admin session cookie and the login password travel in clear text. Put Nginx in front before exposing it, and turn on `admin.secure_cookie`.

**If you do not want the admin console on the public port**: add an `admin_listen` line and the admin plane moves to an internal port, leaving `listen` for tunnels and site traffic:

```toml
[server]
listen = "0.0.0.0:9000"          # mapped: agents (tunnel_host) and sites
admin_listen = "0.0.0.0:9001"    # reachable on the LAN only; do not port-map it
tunnel_host = "tunnel.relay.example.com"
```

Now `admin_host` is no longer needed: on the public side, any Host hitting `listen` (including the old admin name) goes to the route table. The admin plane never sees site traffic, and sites never see the admin console.

**Using that same port as a forward proxy** (no second port): here `Host` is the *destination*, so no route can match it — `CONNECT example.com:443` and `GET http://example.com/ ...` used to be answered as "no such route". `[proxy] route` names the one route that answers them instead:

```toml
[proxy]
route = "muse"                    # = muse.relay.example.com, and a real route
auth = "user:password"            # or allow_from = ["192.168.1.0/24"]
idle_timeout_secs = 0             # never drop a quiet tunnel
```

```bash
# A real forward proxy runs on the agent's machine (xray / mihomo / squid / privoxy):
fairlead agent add muse 7890      # point that route at it

# Client: plain HTTP and HTTPS both go through the one port
curl --proxy http://user:password@relay.example.com:9000 http://example.com/
curl --proxy http://user:password@relay.example.com:9000 https://example.com/
# Browser: proxy host relay.example.com, port 9000, user / password in the dialog
```

The point is that **the relay does not implement the proxy protocol**: it puts the request head into the tunnel byte for byte, and the `200`, the TLS, the destination lookup are all done by the proxy on the agent's machine. That is why `CONNECT` needs nothing from us, and why HTTPS, `ssh -o ProxyCommand` and gRPC work too. The price is that this route turns your public port into an egress, so `proxy.auth` or `proxy.allow_from` is mandatory — with both empty the host refuses to start.

| Agent | Notes |
| --- | --- |
| `server` | `http://relay.example.com:9000` (clear text, merged port) / `tls://relay.example.com:443` (Nginx terminates TLS) / `tls://…:9443` (split mode; the old form without a scheme is treated as TLS too) |
| `tunnel_host` | The `Host` on the upgrade request; must equal `server.tunnel_host` on the host. When omitted, the hostname from `server` is used |
| `tls.mode` | `system` (system roots + bundled Mozilla roots) / `pin` (certificate fingerprint) / `insecure` (development only); applies to `tls://` only |
| `tunnels` | Number of physical tunnels, default 2, so one large download does not slow the same agent's other requests |
| `allow_public_targets` | Default `false`: loopback and private targets only |
| `state_file` | Where the long-lived credential lives, default `/var/lib/fairlead/agent-state.json`; the `agent.status.json` state file sits next to it |
| `[[routes]]` | `host` plus `target` (`127.0.0.1:7884`). **Change these with `fairlead agent add` / `rm`, do not write them by hand** — the service re-reads the file on its own |

## The install page (an agent in one command)

Open the port by bare IP, or with a Host that could never be a route, and you get a static page instead of a 404: archives for five platforms, `SHA256SUMS`, and an `install.sh`.

There is exactly one prerequisite: a wildcard A record for `*.<suffix>` pointing at the relay. Every route is a subdomain, so this one wildcard means no DNS work when you add a service later; the tunnel entry `tunnel.<suffix>` falls under it too. Configure only the apex, or one A record per subdomain, and every new route turns into a DNS change.

```toml
[landing]
dir = "/var/lib/fairlead/dist"       # output directory of scripts/package.sh; omit this section and it is off
host = "app.relay.example.com"       # optional: a fixed address for this page
```

With `host` set, the page no longer relies on someone mistyping a name: `app.<suffix>` is its address, ready to go into docs for the next colleague. This name wins over the route table — a route of the same name does not override it, and the reverse holds too, so do not use it as a business domain. Without `host` it behaves as before: only the bare IP, the apex of the suffix, and Hosts outside every suffix see it.

```bash
./scripts/package.sh all
rsync -a dist/ /var/lib/fairlead/dist/
fairlead doctor --config host.toml
# ✓ landing page                 /var/lib/fairlead/dist (5 downloads + install.sh, on app.relay.example.com, plus unrouted hosts)
```

| Path | Contents |
| --- | --- |
| `/` | Download page: platform, file name, size, SHA-256, install commands |
| `/install.sh` | Install script: picks the archive by `uname`, verifies SHA-256, installs the binary, writes config, installs the service (run as yourself it installs into `~/.local/bin`; with `sudo` into `/usr/local/bin`). `sh install.sh host` installs the relay itself |
| `/download/<file>` | An artifact from `dir`, matched exactly by file name |
| `/SHA256SUMS` | The checksum list |

```bash
sh install.sh                  # agent: binary + config + fairlead-agent service
sh install.sh host             # host: binary + host.toml + fairlead-host service
# defaults (non-root): --prefix ~/.local/bin, --config ~/.config/fairlead/agent.toml, --state ~/.local/state/fairlead
# optional: --server / --tunnel-host / --tunnels / --name / --prefix / --config
#           --no-config / --no-service / --start / --refresh
```

By default it installs a service (`systemctl status fairlead-agent` / `launchctl print system/com.fairlead.agent`) that runs as the user who ran the install, so later `fairlead agent add` needs no sudo.

The boundaries, and why it cannot make things worse: only Hosts that **could never be a route** see this page. A misspelled subdomain like `nope.relay.example.com` is still a 404, and a disabled or deleted route is still 503/404, so the page never hides a real problem. The page holds no credentials at all — tokens are issued on the admin **Token** page (or with `fairlead token` on the host). Downloads match file names exactly, within `dir` only: no decoding, no `..`, no directory listing. It is not a static file server.

## Admin password

There is **one** admin identity and **no username**: the password is the whole credential. The login page has a single input.

```bash
export FAIRLEAD_ADMIN_PASSWORD='at least ten characters'      # option one: environment variable, applied on every start
fairlead admin passwd --config /etc/fairlead/host.toml   # option two: write it into the database (prompts, or reads two lines from stdin)
fairlead admin status --config /etc/fairlead/host.toml   # password set or not, when it changed, last login
```

- **Precedence**: environment variable over database. If `FAIRLEAD_ADMIN_PASSWORD` is set at startup it is written into the database; if it already matches the stored password nothing happens — so a restart does not log you out, and only an actual password change invalidates every session. If you manage the password through the environment, do not change it in the web UI (the next start overwrites it, and the `/account` page warns you).
- The password is stored only as argon2id 哈希 (not reversible, so forgetting it means resetting it). The clear text exists only in the environment variable or at the moment you type it.
- Failed logins are rate limited per client IP (10 in 5 minutes), and the message does not distinguish "no password set" from "wrong password".
- **Tokens**: `/tokens` issues one-time enrollment tokens — pick a suffix, a lifetime (30 minutes / 1 hour / 24 hours / 7 days / never) and a note. After issuing, that page shows the clear text once (with a "copy token" button next to it; clicking the token box also selects the whole string, and the command and the snippet each have their own copy button), together with an `install.sh` command and an `agent.toml` snippet that already carry the token. The list keeps only the suffix, the note, the state (live / used / expired / revoked) and which agent used it, and any token can be revoked at any time. The CLI equivalent is still `fairlead token`.
- Sessions live in SQLite (`admin_sessions`). The browser cookie is a random session key and only its SHA-256 is stored; changing the password immediately invalidates every admin session. Restarting the host does not log you out.
- On a merged port the admin plane is selected only by the `server.admin_host` Host: site routes cannot reach the console, and guessing a Host will not drop you on a login page. With `server.admin_listen` set, the admin plane moves to that port entirely and on the merged port even the admin console name returns 404. For remote access, put Nginx in front and set `admin.secure_cookie = true`; listening on a non-loopback address requires an explicit `admin.allow_remote = true` and logs a warning at startup.
- With no password set the console does not pretend to work: the login page explains how to set one, and every login attempt is refused.
- Deleting a route leaves a tombstone (the name stays taken, so a reconnecting agent cannot bring it back), which is why deleted routes do not appear in the overview or the route list by default. To recover one deleted by mistake, open `/routes?deleted=1` and click "restore".

## Operations

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` (admin plane) | JSON: db, agents online, tunnel count, route count, dropped log lines |
| `GET /metrics` (admin plane) | Prometheus text |
| Admin `/diagnostics?host=...` | Four-step link diagnosis; the last step really sends a `GET /` through the edge |

- **Error semantics**: no route 404, agent offline or route disabled 503, agent cannot reach its target 502, timeout 504, target refused by policy 403.
- **Logs**: one structured record per request (request id / host / route / agent / status code / duration / bytes up and down), in a bounded queue that drops and counts records when full. It never applies backpressure to the data plane.
- **Upgrades**: back up with `VACUUM INTO` first, then swap the binary. A rollback has to roll back the binary and the database together (see `docs/RELEASE.md`).

## Development

```bash
cargo test --workspace          # 140 in all: unit tests + 48 end-to-end acceptance tests
cargo run -- demo               # play with it by hand
RUST_LOG=info,fairlead_host::edge=debug cargo run -- demo
```

Code layout:

```
crates/fairlead-proto/   wire protocol, Host sniffing, frames, stream preamble, target policy, yamux driver
crates/fairlead-host/    edge / tunnel / admin / db / registry / metrics
crates/fairlead-agent/   tunnel pool, registration, heartbeat, local dial, forwarding
crates/fairlead-testkit/ in-process e2e harness + acceptance tests
crates/fairlead/         CLI
```

## Release process

```bash
./scripts/build-dist.sh          # cross-compiles all five targets (zig)
./scripts/package.sh all         # dist/*.tar.gz, *.zip, SHA256SUMS
```

After `git tag v0.1.2 && git push --tags`, CI (`.github/workflows/release.yml`) runs the same two steps and attaches the artifacts to the Release. Release gates and rollback steps are in [`docs/RELEASE.md`](docs/RELEASE.md).

Load test (needs `ulimit -n 65535`):

```bash
cargo test -p fairlead-testkit --test load -- --ignored --nocapture --test-threads=1
```

## Explicitly out of scope

Multi-node and HA, a Kubernetes operator, Cloudflare's orange cloud, ACME auto-issuance, UDP, non-HTTP protocols on the shared port, multi-tenancy and billing. One machine is one point of failure, and it is not dressed up as high availability.

## License

MIT
