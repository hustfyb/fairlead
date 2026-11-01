//! The public landing page.
//!
//! A request that names no route — by IP, or on a host name that is not a site
//! under an allowed suffix — used to end in a 400 or a 404. With `[landing]
//! dir` set it ends here instead: a static page with the agent downloads and an
//! install script, built from the artifacts `scripts/package.sh` left on disk.
//!
//! Three rules keep this from growing teeth:
//!
//! * It is only reachable for hosts that can never be a route, plus the one name
//!   `[landing] host` reserves. A typo on `a1.<suffix>` still answers 404, so an
//!   operator never debugs a typo against a friendly page.
//! * Nothing here is secret. The token that enrolls an agent is issued by
//!   in the admin console's Token page (or by `fairlead token` on the relay
//!   host), never by this page.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fairlead_proto::Sniffed;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::HostConfig;
use crate::db::RequestLogRow;
use crate::metrics::now_unix_ms;
use crate::HostState;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const ARTIFACT_PREFIX: &str = "fairlead-";

/// `host` is a site address: a proper subdomain of one allowed suffix.
///
/// The apex (`relay.example.com` itself) is *not* one: it has no route of its
/// own, and it is the natural name for a landing page.
pub fn is_site_host(host: &str, suffixes: &[String]) -> bool {
    suffixes
        .iter()
        .any(|s| host.len() > s.len() + 1 && host.ends_with(&format!(".{s}")))
}

/// A name the operator pointed at the page on purpose: `[landing] host`.
///
/// It is the one site-shaped name that answers the page instead of 404, and it
/// wins over a route of the same name — a route named like the download page is
/// a configuration mistake, not something to serve through a tunnel.
///
/// `host` is expected to be normalized (lowercase, no port, no trailing dot);
/// both sides are normalized when the config is loaded, so a plain comparison
/// is enough here.
pub fn is_landing_host(host: &str, cfg: &HostConfig) -> bool {
    cfg.landing.host.as_deref() == Some(host)
}

/// One release artifact found in `landing.dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub platform: String,
}

/// Artifacts in `dir`, sorted by name. Reads `SHA256SUMS` next to them so the
/// page can show the hashes the installer checks.
///
/// Blocking on purpose: one `read_dir` of a handful of entries, on a path that
/// only gets traffic when someone opens the bare relay address.
pub fn scan(dir: &Path) -> io::Result<Vec<Artifact>> {
    let sums = read_sums(&dir.join("SHA256SUMS"));
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_artifact_name(&name) {
            continue;
        }
        let sha256 = sums.get(&name).cloned();
        let platform = platform_of(&name);
        out.push(Artifact { name, size: meta.len(), sha256, platform });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn is_artifact_name(name: &str) -> bool {
    name.starts_with(ARTIFACT_PREFIX) && (name.ends_with(".tar.gz") || name.ends_with(".zip"))
}

fn read_sums(path: &Path) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(hash), Some(name)) = (parts.next(), parts.next()) {
            if hash.len() == 64 {
                out.insert(name.trim_start_matches('*').to_string(), hash.to_ascii_lowercase());
            }
        }
    }
    out
}

fn platform_of(name: &str) -> String {
    const TRIPLES: &[(&str, &str)] = &[
        ("aarch64-apple-darwin", "macOS · Apple Silicon"),
        ("x86_64-apple-darwin", "macOS · Intel"),
        ("aarch64-unknown-linux-musl", "Linux · arm64"),
        ("x86_64-unknown-linux-musl", "Linux · x86_64"),
        ("x86_64-pc-windows-gnu", "Windows · x86_64"),
    ];
    TRIPLES
        .iter()
        .find(|(triple, _)| name.contains(triple))
        .map(|(_, label)| (*label).to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn human_size(bytes: u64) -> String {
    const K: f64 = 1024.0;
    let f = bytes as f64;
    if f >= K * K * K {
        format!("{:.1} GiB", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.1} MiB", f / (K * K))
    } else if f >= K {
        format!("{:.0} KiB", f / K)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// serving
// ---------------------------------------------------------------------------

enum Body {
    Bytes(Vec<u8>),
    File { path: PathBuf, size: u64 },
    Empty,
}

struct Reply {
    code: u16,
    reason: &'static str,
    ctype: &'static str,
    body: Body,
    cache: &'static str,
    note: &'static str,
}

impl Reply {
    fn text(code: u16, reason: &'static str, body: &str, note: &'static str) -> Self {
        Self {
            code,
            reason,
            ctype: "text/plain; charset=utf-8",
            body: Body::Bytes(body.as_bytes().to_vec()),
            cache: "no-store",
            note,
        }
    }
}

pub(crate) fn serve_enabled(state: &HostState) -> bool {
    state.cfg.landing.dir.is_some()
}

/// Answer a request that matched no route with the landing page.
pub(crate) async fn serve<W>(
    state: &HostState,
    client: &mut W,
    sniffed: &Sniffed,
    host_raw: Option<&str>,
    request_id: &str,
    started: Instant,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let base = base_url(&state.cfg, sniffed);
    let reply = match state.cfg.landing.dir.as_deref() {
        Some(dir) => plan(&state.cfg, dir, sniffed, &base, request_id),
        None => Reply::text(404, "Not Found", "no route for this host\n", "landing_off"),
    };
    let head_only = sniffed.head.method.eq_ignore_ascii_case("HEAD");
    let written = send(client, &reply, request_id, head_only).await;

    let down = written.as_ref().copied().unwrap_or(0);
    state.metrics().status(reply.code);
    state.metrics().bytes_down.fetch_add(down, std::sync::atomic::Ordering::Relaxed);
    state.db.log(RequestLogRow {
        ts: now_unix_ms() / 1000,
        request_id: request_id.to_string(),
        host: host_raw.map(|h| h.trim().to_string()),
        route_id: None,
        agent_id: None,
        status: reply.code as i64,
        duration_ms: started.elapsed().as_millis() as i64,
        bytes_up: 0,
        bytes_down: down as i64,
        error: Some(reply.note.to_string()),
    });
    written?;
    Ok(())
}

fn plan(cfg: &HostConfig, dir: &Path, sniffed: &Sniffed, base: &str, request_id: &str) -> Reply {
    let method = sniffed.head.method.as_str();
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return Reply::text(405, "Method Not Allowed", "the landing page only answers GET and HEAD\n", "landing_method");
    }
    let path = sniffed.head.target.split(['?', '#']).next().unwrap_or("/");
    match path {
        "/" | "/index.html" => Reply {
            code: 200,
            reason: "OK",
            ctype: "text/html; charset=utf-8",
            body: Body::Bytes(page(cfg, dir, base, request_id)),
            cache: "no-store",
            note: "landing",
        },
        "/install.sh" => Reply {
            code: 200,
            reason: "OK",
            ctype: "text/x-shellscript; charset=utf-8",
            body: Body::Bytes(install_script(cfg, base).into_bytes()),
            cache: "no-store",
            note: "landing_install_sh",
        },
        "/favicon.ico" => Reply {
            code: 204,
            reason: "No Content",
            ctype: "text/plain",
            body: Body::Empty,
            cache: "public, max-age=86400",
            note: "landing_favicon",
        },
        other => {
            let name = if let Some(n) = other.strip_prefix("/download/") {
                n
            } else if other == "/SHA256SUMS" {
                "SHA256SUMS"
            } else {
                ""
            };
            // One flat directory, exact names only: no decoding, no `..`, no
            // subdirectories. Anything else is a 404, not a filesystem probe.
            let allowed = !name.is_empty()
                && !name.starts_with('.')
                && !name.contains('/')
                && !name.contains('\\')
                && !name.contains("..");
            let meta = allowed.then(|| std::fs::metadata(dir.join(name)).ok()).flatten();
            match meta {
                Some(m) if m.is_file() => Reply {
                    code: 200,
                    reason: "OK",
                    ctype: content_type(name),
                    body: Body::File { path: dir.join(name), size: m.len() },
                    cache: "public, max-age=60",
                    note: "landing_download",
                },
                _ => Reply::text(
                    404,
                    "Not Found",
                    "no such page on the relay landing page\n",
                    "landing_404",
                ),
            }
        }
    }
}

fn content_type(name: &str) -> &'static str {
    if name.ends_with(".tar.gz") {
        "application/gzip"
    } else if name.ends_with(".zip") {
        "application/zip"
    } else if name == "SHA256SUMS" || name.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else if name.ends_with(".sh") {
        "text/x-shellscript; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

async fn send<W>(client: &mut W, reply: &Reply, request_id: &str, head_only: bool) -> anyhow::Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let len = match &reply.body {
        Body::Bytes(b) => b.len() as u64,
        Body::File { size, .. } => *size,
        Body::Empty => 0,
    };
    let mut head = if reply.code == 204 {
        format!(
            "HTTP/1.1 204 No Content\r\n\
             Connection: close\r\n\
             Cache-Control: {}\r\n\
             x-fairlead-request-id: {request_id}\r\n\r\n",
            reply.cache
        )
    } else {
        format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {len}\r\n\
             Cache-Control: {}\r\n\
             Connection: close\r\n\
             x-fairlead-request-id: {request_id}\r\n\r\n",
            reply.code, reply.reason, reply.ctype, reply.cache
        )
    };
    client.write_all(head.as_bytes()).await?;
    head.clear();
    if head_only {
        let _ = client.flush().await;
        let _ = client.shutdown().await;
        return Ok(0);
    }
    let written = match &reply.body {
        Body::Bytes(b) => {
            client.write_all(b).await?;
            b.len() as u64
        }
        Body::File { path, .. } => {
            let mut file = tokio::fs::File::open(path).await?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n]).await?;
                total += n as u64;
            }
            total
        }
        Body::Empty => 0,
    };
    let _ = client.flush().await;
    let _ = client.shutdown().await;
    Ok(written)
}

fn base_url(cfg: &HostConfig, sniffed: &Sniffed) -> String {
    let scheme = sniffed
        .head
        .header("x-forwarded-proto")
        .map(|v| String::from_utf8_lossy(v).trim().to_ascii_lowercase())
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| cfg.server.public_scheme.clone());
    let host = sniffed
        .head
        .host_raw
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("127.0.0.1:{}", cfg.server.public_port));
    format!("{scheme}://{host}")
}

// ---------------------------------------------------------------------------
// render
// ---------------------------------------------------------------------------

fn page(cfg: &HostConfig, dir: &Path, base: &str, request_id: &str) -> Vec<u8> {
    let artifacts = scan(dir).unwrap_or_default();
    let mut rows = String::new();
    for a in &artifacts {
        rows.push_str(&format!(
            "<a class=\"dl\" href=\"/download/{name}\"><span class=\"plat\">{platform}</span>\
             <span class=\"file\">{name}</span><span class=\"size\">{size}</span></a>\n",
            name = esc(&a.name),
            platform = esc(&a.platform),
            size = human_size(a.size),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<div class=\"empty\">这个中继还没有发布构建产物。</div>\n");
    }

    let sums = std::fs::read_to_string(dir.join("SHA256SUMS"))
        .map(|s| esc(s.trim_end()))
        .unwrap_or_else(|_| "SHA256SUMS is not on this relay".to_string());

    let suffix = cfg
        .server
        .allowed_suffixes
        .first()
        .cloned()
        .unwrap_or_else(|| "relay.example.com".to_string());
    let tunnel = cfg.server.tunnel_host.clone();
    let tunnel_line = if tunnel.is_empty() {
        String::new()
    } else {
        format!("tunnel_host = \"{}\"\n", esc(&tunnel))
    };

    let win = artifacts.iter().find(|a| a.name.ends_with("-windows-gnu.zip"));
    let win_file = win.map(|a| a.name.clone()).unwrap_or_else(|| {
        format!("fairlead-{VERSION}-x86_64-pc-windows-gnu.zip")
    });
    let win_dir = win_file.trim_end_matches(".zip").to_string();

    let rendered = LANDING_HTML
        .replace("@VERSION@", VERSION)
        .replace("@ROWS@", &rows)
        .replace("@SUMS@", &sums)
        .replace("@WINFILE@", &esc(&win_file))
        .replace("@TRIPLEWIN@", &esc(&win_dir))
        .replace("@TUNNEL_LINE@", &tunnel_line)
        .replace("@TUNNEL@", &esc(if tunnel.is_empty() { &suffix } else { &tunnel }))
        .replace("@SUFFIX@", &esc(&suffix))
        .replace("@REQID@", &esc(request_id))
        .replace("@BASE@", &esc(base))
        .replace("@COPYJS@", crate::clipboard::COPY_JS);
    rendered.into_bytes()
}

fn install_script(cfg: &HostConfig, base: &str) -> String {
    let suffix = cfg
        .server
        .allowed_suffixes
        .first()
        .cloned()
        .unwrap_or_else(|| "relay.example.com".to_string());
    INSTALL_SH
        .replace("@BASE@", base)
        .replace("@TUNNEL@", &cfg.server.tunnel_host)
        .replace("@SUFFIX@", &suffix)
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// templates
// ---------------------------------------------------------------------------

const LANDING_HTML: &str = r##"<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>fairlead · 安装 Agent</title>
<style>
:root{--bg:#f4f6f9;--fg:#111418;--muted:#6a7280;--card:#fff;--line:#e3e7ed;--accent:#1d4ed8;--soft:#eef3ff;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--term:#0b1020;--termfg:#dbe2f0}
@media (prefers-color-scheme:dark){:root{--bg:#0a0c10;--fg:#e7e9ee;--muted:#8b93a1;--card:#12161d;--line:#212936;--accent:#7aa2ff;--soft:#101a2c}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:14.5px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:900px;margin:0 auto;padding:26px 22px 64px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
code{font:12.5px/1.5 var(--mono);background:var(--soft);border-radius:4px;padding:1px 5px;overflow-wrap:anywhere}
.top{display:flex;align-items:center;gap:12px;margin-bottom:30px}
.brand{font-weight:700;font-size:16px;letter-spacing:-.02em;display:flex;align-items:center}
.brand::before{content:"";display:inline-block;width:9px;height:9px;border-radius:2px;background:var(--accent);margin-right:8px}
.chip{margin-left:auto;font:11px/1 var(--mono);color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:5px 9px;background:var(--card)}
.hero{background:linear-gradient(180deg,var(--soft),var(--card) 62%);border:1px solid var(--line);border-radius:14px;padding:26px 26px 22px}
h1{font-size:clamp(22px,3.6vw,30px);line-height:1.25;letter-spacing:-.02em;margin:0 0 10px}
.lede{color:var(--muted);margin:0 0 20px;max-width:60ch}
.pre{display:flex;gap:10px;align-items:flex-start;background:#fff8e6;border:1px solid #f0d9a8;border-radius:10px;padding:11px 13px;margin:0 0 14px}
.pre .tag{flex:none;font-weight:600;font-size:11px;color:#7a4d00;background:#ffe9b8;border-radius:5px;padding:1px 7px;margin-top:2px;white-space:nowrap}
.pre p{margin:0;font-size:12.5px;line-height:1.7;color:#5c4313;overflow-wrap:anywhere}
.pre code{background:#ffefc9;color:#5c4313;font-size:12px}
@media (prefers-color-scheme:dark){.pre{background:#241c08;border-color:#4a3708}.pre .tag{background:#3a2c07;color:#f0c86a}.pre p{color:#e6d2a2}.pre code{background:#33270a;color:#f3d99a}}
.cmdwrap{position:relative}
.term{margin:0;background:var(--term);color:var(--termfg);border-radius:10px;padding:14px 16px;font:12.5px/1.95 var(--mono);overflow-x:auto;white-space:pre}
.pr{color:#5eead4}.ph{color:#fbbf24}
.copy{position:absolute;top:8px;right:8px;font:11px/1 var(--mono);background:#1b2438;color:#cbd5e1;border:1px solid #2a3550;border-radius:6px;padding:5px 9px;cursor:pointer}
.copy:hover{border-color:#3c4a6b;color:#fff}
.hint{color:var(--muted);font-size:12px;margin:10px 0 0}
.steps{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:16px 0 0}
.step{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 15px}
.step .n{display:inline-flex;width:20px;height:20px;align-items:center;justify-content:center;border-radius:6px;background:var(--soft);color:var(--accent);font:600 11px var(--mono);margin-bottom:8px}
.step b{display:block;font-size:13.5px;margin-bottom:4px}
.step p{margin:0;color:var(--muted);font-size:12.5px;line-height:1.6}
h2{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:36px 0 10px;font-weight:600}
.sub{color:var(--muted);font-size:13px;margin:0 0 12px}
.dls{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--card)}
.dl{display:grid;grid-template-columns:200px minmax(0,1fr) 84px;gap:14px;align-items:center;padding:11px 16px;border-bottom:1px solid var(--line);color:inherit}
.dl:last-child{border-bottom:none}
.dl:hover{background:var(--soft);text-decoration:none}
.dl .plat{font-weight:600;font-size:13px}
.dl .file{font:11.5px/1.4 var(--mono);color:var(--muted);overflow-wrap:anywhere}
.dl .size{font:11.5px var(--mono);color:var(--muted);text-align:right;white-space:nowrap}
.empty{padding:16px;color:var(--muted);font-size:13px}
details{border:1px solid var(--line);border-radius:10px;background:var(--card);margin-top:10px}
details+details{margin-top:8px}
summary{cursor:pointer;padding:10px 14px;font-weight:600;font-size:13px;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸";display:inline-block;width:14px;color:var(--muted);font-weight:400}
details[open] summary::before{content:"▾"}
details>div{padding:0 14px 14px}
.code{margin:0;background:var(--term);color:var(--termfg);border-radius:8px;padding:12px 14px;font:12px/1.85 var(--mono);overflow-x:auto;white-space:pre}
.code+.code{margin-top:8px}
.sums{color:#9fb0cc;font-size:11px;white-space:pre-wrap;overflow-wrap:anywhere}
.sum-link{font-weight:400;font-size:12px;margin-left:6px}
.note{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.note p{margin:0 0 10px}.note p:last-child{margin-bottom:0}
.foot{margin-top:44px;padding-top:14px;border-top:1px solid var(--line);display:flex;gap:8px;flex-wrap:wrap;color:var(--muted);font-size:11.5px}
.foot code{font-size:11px;background:transparent;padding:0}
@media (max-width:720px){.steps{grid-template-columns:minmax(0,1fr)}}
@media (max-width:680px){
.wrap{padding:20px 16px 48px}
.hero{padding:20px 16px 18px;border-radius:12px}
.dl{grid-template-columns:minmax(0,1fr) auto;gap:4px 10px}
.dl .file{grid-column:1/-1;order:3;font-size:11px}
.term{font-size:11px;padding:12px;white-space:pre-wrap;overflow-wrap:break-word}
.copy{position:static;display:block;margin:8px 0 0 auto}
.pre{flex-direction:column;gap:7px;padding:11px 12px}
.pre .tag{align-self:flex-start;margin-top:0}
}
</style>
</head><body>
<div class="wrap">

<div class="top"><span class="brand">fairlead</span><span class="chip">v@VERSION@</span></div>

<section class="hero">
<h1>把内网服务，接到自己的域名上</h1>
<p class="lede">在这台中继的 <code>@SUFFIX@</code> 下，每个 <code>a1.@SUFFIX@</code> 这样的名字都可以指向一台内网机器上的端口。装一个 Agent，它从内网主动连出来——不用公网 IP，也不用动路由器。</p>
<div class="pre"><span class="tag">先决条件</span><p><b>一条通配符 DNS 记录：</b><code>*.@SUFFIX@</code> 指向这台中继的 IP。之后每个新服务只要在 Agent 里写 <code>名字.@SUFFIX@</code> 就直接可用，不用再动 DNS——隧道入口 <code>@TUNNEL@</code> 也落在这条通配里。没有通配，就得一条路由配一条 A 记录，每加一个子域名改一次 DNS。</p></div>
<div class="cmdwrap">
<pre class="term" id="cmds"><span class="pr">$</span> curl -fsSLO @BASE@/install.sh
<span class="pr">$</span> sh install.sh
<span class="pr">$</span> fairlead agent enroll <span class="ph">&lt;TOKEN&gt;</span>
<span class="pr">$</span> fairlead agent add a1.@SUFFIX@ 8080</pre>
<button class="copy" type="button" data-text="curl -fsSLO @BASE@/install.sh&#10;sh install.sh&#10;fairlead agent enroll &lt;TOKEN&gt;&#10;fairlead agent add a1.@SUFFIX@ 8080">复制</button>
</div>
<p class="hint">脚本只做安装：认 <code>uname</code> 选包、按 <code>SHA256SUMS</code> 校验、装二进制、写一份没有路由的配置、装成服务。用你自己的账号跑：二进制进 <code>~/.local/bin</code>，配置进 <code>~/.config/fairlead/</code>，服务也以你的身份运行，不用 sudo；<code>sudo</code> 跑则进 <code>/usr/local/bin</code> 与 <code>/etc/fairlead</code>。<code>~/.local/bin</code> 不在 PATH 上时脚本会说明怎么加。</p>
</section>

<div class="steps">
<div class="step"><span class="n">1</span><b>领一个 token</b><p>在管理台 <b>Token → 签发</b>，选后缀和有效期，签出来的串只显示这一遍。（中继机上 <code>fairlead token --suffix @SUFFIX@</code> 也行。）</p></div>
<div class="step"><span class="n">2</span><b>装 Agent</b><p><code>sh install.sh</code>：挑包、校验、装二进制、写配置、装成服务（开机自启）。它此时在等 token。</p></div>
<div class="step"><span class="n">3</span><b>给凭据、加路由</b><p><code>fairlead agent enroll &lt;TOKEN&gt;</code> 让服务连上来；<code>fairlead agent add 8080</code> 加一条映射。两条命令随时可再用，不用重装。</p></div>
</div>

<h2>下载</h2>
<p class="sub">每个包里是 <code>fairlead</code> 二进制、README、CHANGELOG 和 <code>deploy/</code> 示例（nginx / systemd / docker）。</p>
<div class="dls">@ROWS@</div>
<p class="hint">没有匹配的系统？<a href="/install.sh">install.sh</a> 会说明它支持哪几个目标。</p>

<h2>校验</h2>
<details open>
<summary>SHA256SUMS 与校验命令 <a class="sum-link" href="/SHA256SUMS">下载</a></summary>
<div>
<pre class="code">shasum -a 256 -c SHA256SUMS    # macOS
sha256sum -c SHA256SUMS        # Linux</pre>
<pre class="code sums">@SUMS@</pre>
</div>
</details>

<h2>Windows</h2>
<div class="note">
<p>Windows 上没有 <code>sh</code>，直接下 zip 解包：</p>
<pre class="code">$u = "@BASE@/download/@WINFILE@"
Invoke-WebRequest $u -OutFile fairlead.zip
Expand-Archive fairlead.zip -DestinationPath .
.\@TRIPLEWIN@\fairlead.exe --version</pre>
<p class="hint">配置文件与下面相同，存成 <code>agent.toml</code> 后运行 <code>fairlead.exe agent --config agent.toml</code>。</p>
</div>

<h2>agent.toml</h2>
<details>
<summary>手写配置（脚本没写成功时用这个）</summary>
<div>
<pre class="code">server = "@BASE@"
@TUNNEL_LINE@name = "agent-a"
token = "&lt;上一步的 TOKEN&gt;"
tunnels = 2

[[routes]]
host = "a1.@SUFFIX@"
target = "127.0.0.1:8080"</pre>
<p class="hint">一台 Agent 可以声明多条路由；<code>target</code> 是 Agent 那台机器上能访问到的地址，默认只允许内网与回环。</p>
</div>
</details>

<h2>这个页面</h2>
<div class="note">
<p>它只在一个请求没有匹配任何路由时出现：直接用 IP 打开，或者用一个不属于这些域名的 <code>Host</code>。页面里没有任何凭据——token 在管理台「Token」页签发，或者在中继机上用 <code>fairlead token</code> 生成。</p>
</div>

<div class="foot"><span>fairlead v@VERSION@</span><span>·</span><span>request <code>@REQID@</code></span><span>·</span><span>@TUNNEL@</span></div>

</div>
@COPYJS@
</body></html>"##;

const INSTALL_SH: &str = r##"#!/bin/sh
# fairlead installer — generated by the relay at @BASE@
#
#   sh install.sh              # this machine publishes ports through the relay
#   sh install.sh host         # this machine is the relay itself
#
# It installs the binary and, unless told otherwise, the service that keeps it
# running. It publishes nothing: routes are added afterwards with
# `fairlead agent add`, and the agent gets its token with `fairlead agent
# enroll`. Nothing here is secret, so the same command can be run again later.
set -eu

BASE="@BASE@"
TUNNEL_HOST="@TUNNEL@"
SUFFIX="@SUFFIX@"
WHAT="agent"
NAME=""
TUNNELS="2"
PREFIX=""
CFGDIR=""
CONFIG=""
STATEDIR=""
WRITE_CONFIG="1"
SERVICE="1"
START="0"
REFRESH="0"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Where it goes depends on who runs it. As root (or under sudo): system-wide,
# the same paths the systemd units and the docs use. As yourself: under $HOME
# — an agent only dials local ports, so it has no reason to need root, and
# then `fairlead agent add` never asks for a password afterwards either.
uid=$(id -u 2>/dev/null || echo 0)
if [ "$uid" = "0" ]; then
	PREFIX="/usr/local/bin"
	CFGDIR="/etc/fairlead"
	STATEDIR="/var/lib/fairlead"
else
	[ -n "${HOME:-}" ] || die "HOME is not set: pass --prefix and --config explicitly"
	PREFIX="$HOME/.local/bin"
	CFGDIR="${XDG_CONFIG_HOME:-$HOME/.config}/fairlead"
	STATEDIR="${XDG_STATE_HOME:-$HOME/.local/state}/fairlead"
fi

usage() {
	cat <<EOF
fairlead installer — one binary, two roles

  sh install.sh                install the agent on this machine
  sh install.sh host           install the relay host itself

It installs the binary and the service. It does not publish anything: after
this, routes are added with 'fairlead agent add'.

  agent options:
  --server URL         relay base URL (default $BASE)
  --tunnel-host HOST   Host that selects the tunnel plane (default $TUNNEL_HOST)
  --tunnels N          physical tunnels, 1..4 (default 2)
  --name NAME          agent name in the console (default: this machine's name)

  both:
  --prefix DIR         where to put the binary (default $PREFIX)
  --config PATH        config to write (default $CFGDIR/agent.toml or host.toml)
  --no-config          install the binary only
  --no-service         do not install the service
  --start              run in the foreground instead of as a service
  --refresh            download and reinstall the binary even if this version is already there
  -h, --help           this text

No token is needed here: 'fairlead agent enroll <TOKEN>' writes it later.
Mint one in the admin console (Token -> 签发), or on the relay with
'fairlead token --suffix $SUFFIX'.

Run it as $(id -un), not with sudo: the binary, the config and the credential
land under your home, the service runs as you, and 'fairlead agent add' needs
no password later. Under sudo it installs system-wide instead
(/usr/local/bin, /etc/fairlead, service user = you).
EOF
}

need_two() { [ $# -ge 2 ] || die "missing value for $1"; }

while [ $# -gt 0 ]; do
	case $1 in
		agent|host) WHAT=$1; shift ;;
		--server) need_two "$@"; BASE=$2; shift 2 ;;
		--server=*) BASE=${1#*=}; shift ;;
		--tunnel-host) need_two "$@"; TUNNEL_HOST=$2; shift 2 ;;
		--tunnel-host=*) TUNNEL_HOST=${1#*=}; shift ;;
		--tunnels) need_two "$@"; TUNNELS=$2; shift 2 ;;
		--tunnels=*) TUNNELS=${1#*=}; shift ;;
		--name) need_two "$@"; NAME=$2; shift 2 ;;
		--name=*) NAME=${1#*=}; shift ;;
		--prefix) need_two "$@"; PREFIX=$2; shift 2 ;;
		--prefix=*) PREFIX=${1#*=}; shift ;;
		--config) need_two "$@"; CONFIG=$2; shift 2 ;;
		--config=*) CONFIG=${1#*=}; shift ;;
		--no-config) WRITE_CONFIG="0"; shift ;;
		--no-service) SERVICE="0"; shift ;;
		--start) SERVICE="0"; START="1"; shift ;;
		--refresh) REFRESH="1"; shift ;;
		-h|--help) usage; exit 0 ;;
		*) die "unknown option: $1 — 'sh install.sh agent' or 'sh install.sh host' (try --help)" ;;
	esac
done

if [ "$WHAT" = "host" ] && { [ -n "$NAME" ] || [ "$TUNNELS" != "2" ]; }; then
	die "--name and --tunnels describe an agent; they do not apply to host"
fi

BASE=${BASE%/}
if [ -z "$CONFIG" ]; then
	if [ "$WHAT" = "host" ]; then
		CONFIG="$CFGDIR/host.toml"
	else
		CONFIG="$CFGDIR/agent.toml"
	fi
fi

# --- what are we running on ------------------------------------------------
os=$(uname -s 2>/dev/null || echo unknown)
arch=$(uname -m 2>/dev/null || echo unknown)
case $os in
	Darwin) triple_os="apple-darwin" ;;
	Linux) triple_os="unknown-linux-musl" ;;
	*) die "unsupported OS '$os'. Windows: download the .zip from $BASE/ by hand. Other unixes need a source build." ;;
esac
case $arch in
	arm64|aarch64) triple_arch="aarch64" ;;
	x86_64|amd64) triple_arch="x86_64" ;;
	*) die "unsupported architecture '$arch'" ;;
esac
triple="$triple_arch-$triple_os"

# --- where it goes: say it, and check it, before the download --------------
# The first build noticed an unwritable /usr/local/bin only after fetching and
# unpacking the archive, then told you to re-run as root — a different install
# (system-wide, config in /etc) than the one you asked for. Fail early here,
# with the flag that actually fixes it.
if ! mkdir -p "$PREFIX" 2>/dev/null || [ ! -w "$PREFIX" ]; then
	die "cannot write to $PREFIX (running as $(id -un)). Put the binary somewhere you own:
       --prefix \"\$HOME/.local/bin\"
     sudo would install system-wide instead: /usr/local/bin + /etc/fairlead"
fi
if [ "$WRITE_CONFIG" = "1" ]; then
	cfgdir=$(dirname "$CONFIG")
	if ! mkdir -p "$cfgdir" 2>/dev/null || [ ! -w "$cfgdir" ]; then
		die "cannot write to $cfgdir (running as $(id -un)). Put the config somewhere you own:
       --config \"\$HOME/.config/fairlead/$WHAT.toml\""
	fi
fi
say "→ $(id -un): $PREFIX/fairlead"

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --retry 2 --connect-timeout 10 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "need curl or wget to download the build"
fi
command -v tar >/dev/null 2>&1 || die "need tar to unpack the build"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t fairlead)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

say "→ $triple: reading $BASE/SHA256SUMS"
fetch "$BASE/SHA256SUMS" "$tmp/SHA256SUMS" || die "cannot download $BASE/SHA256SUMS"

file=$(awk -v t="-${triple}.tar.gz" '{ n=$2; if (substr(n, length(n)-length(t)+1) == t) { print n; exit } }' "$tmp/SHA256SUMS")
[ -n "$file" ] || die "this relay has no build for $triple"
want=$(awk -v n="$file" '$2 == n { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || die "no checksum for $file"

# Running it again is the normal case — to install the other role, to repair, to
# upgrade. If this version is already there, the download is 20 MB of nothing:
# skip it, but only when the version in the file name is exactly the one the
# local binary reports, so an upgrade is never skipped by accident.
stem=${file%.tar.gz}
remote_ver=""
case $stem in
	fairlead-*-"$triple") remote_ver=${stem#fairlead-}; remote_ver=${remote_ver%-"$triple"} ;;
esac
have_ver=""
if [ -x "$PREFIX/fairlead" ]; then
	have_ver=$("$PREFIX/fairlead" --version 2>/dev/null | awk 'NR == 1 { print $2 }')
fi

if [ "$REFRESH" != "1" ] && [ -n "$have_ver" ] && [ "$have_ver" = "$remote_ver" ]; then
	say "✓ $PREFIX/fairlead is already $have_ver — skipping $file (--refresh reinstalls it)"
else
	say "→ downloading $file"
	fetch "$BASE/download/$file" "$tmp/$file" || die "cannot download $BASE/download/$file"

	if command -v shasum >/dev/null 2>&1; then
		have=$(shasum -a 256 "$tmp/$file" | awk '{print $1}')
	elif command -v sha256sum >/dev/null 2>&1; then
		have=$(sha256sum "$tmp/$file" | awk '{print $1}')
	elif command -v openssl >/dev/null 2>&1; then
		have=$(openssl dgst -sha256 "$tmp/$file" | awk '{print $NF}')
	else
		die "need shasum, sha256sum or openssl to verify the download"
	fi
	[ "$have" = "$want" ] || die "checksum mismatch for $file: expected $want, got $have"
	say "✓ checksum $have"

	tar -xzf "$tmp/$file" -C "$tmp" || die "cannot unpack $file"
	src=$(ls -1 "$tmp"/fairlead-*/fairlead 2>/dev/null | head -1)
	[ -n "$src" ] || die "$file does not contain the fairlead binary"

	if ! install -m 0755 "$src" "$PREFIX/fairlead" 2>/dev/null; then
		die "cannot write $PREFIX/fairlead — pass --prefix with a directory you own, e.g. --prefix \"\$HOME/.local/bin\""
	fi
	say "✓ installed $("$PREFIX/fairlead" --version 2>/dev/null || echo fairlead) at $PREFIX/fairlead"
fi

# ~/.local/bin is not on PATH by default on most systems. Say it once, with
# the line that fixes it, rather than letting 'fairlead: command not found'
# explain it a minute later.
on_path="0"
case ":$PATH:" in *":$PREFIX:"*) on_path="1" ;; esac
if [ "$on_path" = "0" ]; then
	say ""
	say "note: $PREFIX is not on your PATH. Add it once, then 'fairlead' works in a new shell:"
	say "      echo 'export PATH=\"$PREFIX:\$PATH\"' >> ~/.profile     # or ~/.bashrc / ~/.zshrc"
	say "      (the service starts by full path, so it runs either way)"
fi

if [ "$WRITE_CONFIG" != "1" ]; then
	say "done (--no-config): binary only"
	exit 0
fi

# --- the config: written once, never overwritten ---------------------------
cfgdir=$(dirname "$CONFIG")
mkdir -p "$cfgdir" 2>/dev/null || true

owner=${SUDO_USER:-}
[ -n "$owner" ] || owner=$(id -un 2>/dev/null || echo root)
statedir=$STATEDIR
mkdir -p "$statedir" 2>/dev/null || statedir=$cfgdir
if [ "$uid" = "0" ] && [ "$owner" != "root" ]; then
	chown "$owner" "$statedir" 2>/dev/null || true
fi

if [ -e "$CONFIG" ]; then
	# Re-running the installer must never wipe a token or a route somebody
	# added: the file belongs to the user from here on.
	say "✓ config already at $CONFIG (left alone)"
else
	if [ "$WHAT" = "host" ]; then
		base_port=80
		case $BASE in
			*:*) base_port=$(printf '%s' "$BASE" | sed -n 's|^[A-Za-z][A-Za-z0-9+.-]*://[^/:]*:\([0-9][0-9]*\).*|\1|p') ;;
		esac
		[ -n "$base_port" ] || base_port=80
		{
			printf '# fairlead host — written by install.sh\n'
			printf '# Edit, then check it with `fairlead doctor --config %s`.\n\n' "$CONFIG"
			printf '[server]\n'
			printf '# The port agents dial. Behind nginx, keep 9001 here and let nginx\n'
			printf '# listen on public_port below.\n'
			printf 'listen = "0.0.0.0:9001"\n'
			printf 'admin_listen = "0.0.0.0:9002"\n'
			printf 'tunnel_host = "%s"\n' "$TUNNEL_HOST"
			printf 'allowed_suffixes = ["%s"]\n' "$SUFFIX"
			printf 'database = "%s/fairlead.db"\n' "$statedir"
			printf 'public_port = %s\n' "$base_port"
			printf 'public_scheme = "http"\n\n'
			printf '[admin]\n'
			printf '# One admin, no username: the password is the whole credential.\n'
			printf '#   fairlead admin passwd --config %s   (or FAIRLEAD_ADMIN_PASSWORD)\n' "$CONFIG"
			printf 'allow_remote = true\n'
			printf 'session_ttl_secs = 43200\n'
			printf '# set true once TLS is in front of the admin port\n'
			printf 'secure_cookie = false\n\n'
			printf '# Release artifacts for the download page (install.sh + builds).\n'
			printf '# [landing]\n'
			printf '# dir = "%s/dist"\n' "$statedir"
			printf '# host = "app.%s"\n' "$SUFFIX"
		} > "$CONFIG" 2>/dev/null || die "cannot write $CONFIG — pass --config with a path you own"
	else
		[ -n "$NAME" ] || NAME=$(uname -n 2>/dev/null || echo agent)
		{
			printf '# fairlead agent — written by install.sh\n'
			printf '# Routes are not written here by hand: add them with fairlead agent add\n'
			printf '# (each one becomes a [[routes]] table).\n'
			printf 'server = "%s"\n' "$BASE"
			if [ -n "$TUNNEL_HOST" ]; then printf 'tunnel_host = "%s"\n' "$TUNNEL_HOST"; fi
			printf 'name = "%s"\n' "$NAME"
			printf 'tunnels = %s\n' "$TUNNELS"
			printf '# The token goes below, written by `fairlead agent enroll <TOKEN>`;\n'
			printf '# until then the agent waits instead of failing. After it enrolls,\n'
			printf '# the credential is cached in state_file and the token is spent.\n'
			printf 'state_file = "%s/agent-state.json"\n' "$statedir"
		} > "$CONFIG" 2>/dev/null || die "cannot write $CONFIG — pass --config with a path you own"
	fi
	chmod 600 "$CONFIG" 2>/dev/null || true
	if [ "$uid" = "0" ] && [ "$owner" != "root" ]; then
		chown "$owner" "$CONFIG" 2>/dev/null || true
	fi
	say "✓ config written to $CONFIG"
fi

# --- the service -----------------------------------------------------------
if [ "$SERVICE" = "1" ]; then
	say ""
	say "→ installing the $WHAT service: it starts now, and again at every boot"
	failed=0
	if [ "$uid" = "0" ]; then
		"$PREFIX/fairlead" "$WHAT" service install --config "$CONFIG" --user "$owner" || failed=1
	elif command -v sudo >/dev/null 2>&1; then
		sudo "$PREFIX/fairlead" "$WHAT" service install --config "$CONFIG" --user "$owner" || failed=1
	else
		failed=1
	fi
	if [ "$failed" = "1" ]; then
		say ""
		say "could not install the service here. Do it by hand with:"
		say "  sudo $PREFIX/fairlead $WHAT service install --config $CONFIG"
	fi
fi

say ""
fl=fairlead
[ "$on_path" = "1" ] || fl="$PREFIX/fairlead"
say "next:"
if [ "$WHAT" = "host" ]; then
	say "  $fl admin passwd --config $CONFIG   the one admin password"
	say "  $fl doctor --config $CONFIG         check ports, database, landing page"
	say "  $fl host --config $CONFIG           run it in this terminal"
	say ""
	say "and point DNS at this machine: *.@SUFFIX@, plus the names in $CONFIG."
else
	say "  $fl agent enroll <TOKEN>        token from the admin console (Token -> 签发)"
	say "  $fl agent add 8080              publish 127.0.0.1:8080 as a8080.$SUFFIX"
	say "  $fl agent list                  what this machine publishes, and its state"
	say ""
	say "a token can also be minted on the relay: fairlead token --suffix $SUFFIX"
fi

if [ "$START" = "1" ]; then
	say ""
	say "→ running in the foreground (no service was installed)"
	if [ "$WHAT" = "host" ]; then
		exec "$PREFIX/fairlead" host --config "$CONFIG"
	else
		exec "$PREFIX/fairlead" agent run --config "$CONFIG"
	fi
fi
"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fairlead-landing-{tag}-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn site_host_excludes_the_apex() {
        let suffixes = vec!["relay.test".to_string()];
        assert!(is_site_host("a1.relay.test", &suffixes));
        assert!(is_site_host("deep.a1.relay.test", &suffixes));
        assert!(!is_site_host("relay.test", &suffixes), "the apex is the landing page");
        assert!(!is_site_host("nope.test", &suffixes));
        assert!(!is_site_host("203.0.113.10", &suffixes));
    }

    #[test]
    fn scan_reads_artifacts_and_hashes() {
        let dir = temp_dir("scan");
        let a = "fairlead-0.1.0-aarch64-apple-darwin.tar.gz";
        let b = "fairlead-0.1.0-x86_64-pc-windows-gnu.zip";
        std::fs::write(dir.join(a), b"one").unwrap();
        std::fs::write(dir.join(b), b"two").unwrap();
        std::fs::write(dir.join("README.md"), b"not an artifact").unwrap();
        std::fs::write(
            dir.join("SHA256SUMS"),
            format!("{hash}  {a}\n{hash2}  {b}\n", hash = "a".repeat(64), hash2 = "b".repeat(64)),
        )
        .unwrap();

        let found = scan(&dir).unwrap();
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].name, a);
        assert_eq!(found[0].platform, "macOS · Apple Silicon");
        assert_eq!(found[0].size, 3);
        assert_eq!(found[0].sha256.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!(found[1].platform, "Windows · x86_64");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sizes_are_human() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
        assert_eq!(human_size(1536), "2 KiB");
    }

    #[test]
    fn install_script_carries_the_relay() {
        let cfg = test_cfg();
        let text = install_script(&cfg, "http://203.0.113.10:29001");
        assert!(text.contains(r#"BASE="http://203.0.113.10:29001""#), "{text}");
        assert!(text.contains(r#"SUFFIX="relay.test""#));
        assert!(text.contains(r#"TUNNEL_HOST="tunnel.relay.test""#));
        assert!(text.starts_with("#!/bin/sh"));
        // The manifest lookup has to match the triple it just computed.
        assert!(text.contains("-${triple}.tar.gz"));
    }

    #[test]
    fn install_script_installs_a_service_and_names_the_cli() {
        let cfg = test_cfg();
        let text = install_script(&cfg, "http://relay.test:29001");
        assert!(text.contains("service install --config"), "{text}");
        assert!(text.contains("--no-service"), "the service can be skipped");
        assert!(text.contains("agent add 8080"), "the CLI is how routes are added");
        assert!(text.contains("fl=fairlead"), "the binary name is spelled out when PATH lacks it");
        assert!(text.contains("agent run --config"), "the foreground path uses `agent run`");
        assert!(text.contains("state_file = \"%s/agent-state.json\""), "state lives where the service user can write");
    }

    #[test]
    fn install_script_installs_and_leaves_configuring_to_the_cli() {
        // Installing and configuring are two different jobs: the installer
        // installs, `agent enroll` hands over the credential, `agent add`
        // publishes a port. Re-running the installer must be harmless, which
        // is why it takes no token and writes no [[routes]].
        let cfg = test_cfg();
        let text = install_script(&cfg, "http://relay.test:29001");
        assert!(!text.contains("--token"), "no token flag: enroll does that: {text}");
        assert!(!text.contains("--route"), "no route flag: `agent add` does that");
        assert!(text.contains("agent enroll <TOKEN>"), "the token is handed over afterwards");
        assert!(text.contains("[[routes]]"), "the skeleton says where routes go");
        assert!(
            text.contains("config already at $CONFIG (left alone)"),
            "a second run must not wipe an enrolled config"
        );
    }

    #[test]
    fn install_script_takes_a_role() {
        // One binary, two jobs: `install.sh` is the agent, `install.sh host`
        // is the relay itself, and the units differ.
        let cfg = test_cfg();
        let text = install_script(&cfg, "http://relay.test:29001");
        assert!(text.contains("WHAT=\"agent\""), "{text}");
        assert!(text.contains("agent|host) WHAT=$1"), "the role is the first word");
        assert!(text.contains("\"$PREFIX/fairlead\" \"$WHAT\" service install"), "{text}");
        assert!(text.contains("sh install.sh host"), "the help names the host install");
        assert!(text.contains("host.toml"), "the host gets its own config file");
        assert!(text.contains("admin_listen"), "the host skeleton is a real host config");
        assert!(text.contains("admin passwd"), "the host skeleton says how to set the password");
    }

    #[test]
    fn install_script_goes_under_home_unless_root() {
        // Running it as yourself must not need root: `/usr/local/bin` and
        // `/etc/fairlead` are root's, and the old script only said so after
        // downloading and unpacking the archive.
        let cfg = test_cfg();
        let text = install_script(&cfg, "http://relay.test:29001");
        assert!(text.contains(r#"PREFIX="$HOME/.local/bin""#), "{text}");
        assert!(
            text.contains(r#"CFGDIR="${XDG_CONFIG_HOME:-$HOME/.config}/fairlead""#),
            "the config follows XDG and lives under the user's home"
        );
        assert!(text.contains(r#"PREFIX="/usr/local/bin""#), "root still installs system-wide");
        assert!(
            text.contains("cannot write to $PREFIX (running as"),
            "an unwritable prefix is reported before the download, with the user named"
        );
        assert!(
            !text.contains("re-run with sudo"),
            "sudo is a different install, not the fix for a non-root one"
        );
        assert!(text.contains("is not on your PATH"), "a home install says how to reach the binary");
        assert!(text.contains("--refresh"), "a second run can force the download");
        assert!(
            text.contains("skipping $file"),
            "the same version is not downloaded again just to write a config"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_script_help_is_text_not_commands() {
        // The usage block used to sit in an unquoted heredoc with backticks
        // around `fairlead token`, so `--help` ran it ("not found") and the
        // words vanished from the output.
        let cfg = test_cfg();
        let dir = temp_dir("help");
        let path = dir.join("install.sh");
        std::fs::write(&path, install_script(&cfg, "http://relay.test:29001")).unwrap();
        let out = std::process::Command::new("sh").arg(&path).arg("--help").output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(stdout.contains("sh install.sh host"), "{stdout}");
        assert!(stdout.contains("fairlead token"), "the word survives: {stdout}");
        assert!(stderr.trim().is_empty(), "nothing is executed while printing help: {stderr}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn page_lists_the_artifacts_it_found() {
        let dir = temp_dir("page");
        std::fs::write(dir.join("fairlead-0.1.0-x86_64-unknown-linux-musl.tar.gz"), b"x").unwrap();
        std::fs::write(dir.join("SHA256SUMS"), "deadbeef  fairlead-0.1.0-x86_64-unknown-linux-musl.tar.gz\n").unwrap();
        let cfg = test_cfg();
        let html = String::from_utf8(page(&cfg, &dir, "http://127.0.0.1:29001", "abc123")).unwrap();
        assert!(html.contains("Linux · x86_64"));
        assert!(html.contains("/download/fairlead-0.1.0-x86_64-unknown-linux-musl.tar.gz"));
        assert!(html.contains("abc123"));
        assert!(html.contains("http://127.0.0.1:29001/install.sh"));
        assert!(!html.contains("@ROWS@"), "every placeholder must be replaced");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_copy_button_is_wired() {
        // The install command lives in a `data-text` attribute, so the shared
        // handler has to look for that too: it used to look for `[data-copy]`
        // only, and this page's one copy button did nothing at all.
        let dir = temp_dir("copy");
        std::fs::write(dir.join("fairlead-0.1.0-x86_64-unknown-linux-musl.tar.gz"), b"x").unwrap();
        std::fs::write(
            dir.join("SHA256SUMS"),
            "deadbeef  fairlead-0.1.0-x86_64-unknown-linux-musl.tar.gz\n",
        )
        .unwrap();
        let cfg = test_cfg();
        let html = String::from_utf8(page(&cfg, &dir, "http://127.0.0.1:29001", "abc123")).unwrap();
        assert!(html.contains("data-text=\"curl -fsSLO"), "the button carries its text");
        assert!(
            html.contains("[data-copy],[data-text]"),
            "the handler matches both kinds of copy button"
        );
        assert!(!html.contains("@COPYJS@"), "the handler placeholder is replaced");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn test_cfg() -> HostConfig {
        HostConfig::from_toml(
            "[server]\nallowed_suffixes = [\"relay.test\"]\ntunnel_host = \"tunnel.relay.test\"\nlisten = \"127.0.0.1:9000\"\nadmin_host = \"admin.relay.test\"\n[admin]\nallow_remote = true\n",
        )
        .unwrap()
    }
}
