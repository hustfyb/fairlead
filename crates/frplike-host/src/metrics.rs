//! Process-wide counters rendered as Prometheus text.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug, Default)]
pub struct Metrics {
    pub started: AtomicU64,
    pub requests: AtomicU64,
    pub c_1xx: AtomicU64,
    pub c_2xx: AtomicU64,
    pub c_3xx: AtomicU64,
    pub c_4xx: AtomicU64,
    pub c_5xx: AtomicU64,
    pub c_other: AtomicU64,
    pub no_route: AtomicU64,
    pub route_offline: AtomicU64,
    pub upstream_refused: AtomicU64,
    pub upstream_timeout: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub active_streams: AtomicU64,
    pub agents_connected: AtomicU64,
    pub tunnels_open: AtomicU64,
    pub tunnels_rejected: AtomicU64,
    pub log_dropped: AtomicU64,
}

static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

impl Metrics {
    pub fn mark_start(&self) {
        START.get_or_init(Instant::now);
        self.started.store(now_unix(), Ordering::Relaxed);
    }

    pub fn status(&self, code: u16) {
        let c = match code / 100 {
            1 => &self.c_1xx,
            2 => &self.c_2xx,
            3 => &self.c_3xx,
            4 => &self.c_4xx,
            5 => &self.c_5xx,
            _ => &self.c_other,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self, agents_online: usize, routes_active: usize) -> String {
        let up = START.get().map(|s| s.elapsed().as_secs()).unwrap_or(0);
        let mut out = String::with_capacity(2048);
        out.push_str("# HELP frplike_up_seconds Seconds since the host started.\n# TYPE frplike_up_seconds gauge\n");
        out.push_str(&format!("frplike_up_seconds {up}\n"));
        out.push_str("# HELP frplike_requests_total HTTP requests handled by the edge.\n# TYPE frplike_requests_total counter\n");
        out.push_str(&format!("frplike_requests_total {}\n", self.requests.load(Ordering::Relaxed)));
        for (name, c) in [
            ("1xx", &self.c_1xx),
            ("2xx", &self.c_2xx),
            ("3xx", &self.c_3xx),
            ("4xx", &self.c_4xx),
            ("5xx", &self.c_5xx),
            ("other", &self.c_other),
        ] {
            out.push_str(&format!(
                "frplike_responses_total{{class=\"{name}\"}} {}\n",
                c.load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP frplike_no_route_total Requests with a host that has no route.\n# TYPE frplike_no_route_total counter\n");
        out.push_str(&format!("frplike_no_route_total {}\n", self.no_route.load(Ordering::Relaxed)));
        out.push_str("# HELP frplike_route_offline_total Requests for a route whose agent is offline.\n# TYPE frplike_route_offline_total counter\n");
        out.push_str(&format!("frplike_route_offline_total {}\n", self.route_offline.load(Ordering::Relaxed)));
        out.push_str("# HELP frplike_upstream_refused_total Agent could not connect to the local target.\n# TYPE frplike_upstream_refused_total counter\n");
        out.push_str(&format!("frplike_upstream_refused_total {}\n", self.upstream_refused.load(Ordering::Relaxed)));
        out.push_str("# HELP frplike_upstream_timeout_total Agent dial timed out or never answered.\n# TYPE frplike_upstream_timeout_total counter\n");
        out.push_str(&format!("frplike_upstream_timeout_total {}\n", self.upstream_timeout.load(Ordering::Relaxed)));
        out.push_str("# HELP frplike_bytes_total Bytes forwarded by the edge.\n# TYPE frplike_bytes_total counter\n");
        out.push_str(&format!("frplike_bytes_total{{dir=\"up\"}} {}\n", self.bytes_up.load(Ordering::Relaxed)));
        out.push_str(&format!("frplike_bytes_total{{dir=\"down\"}} {}\n", self.bytes_down.load(Ordering::Relaxed)));
        out.push_str("# HELP frplike_active_streams In-flight data streams.\n# TYPE frplike_active_streams gauge\n");
        out.push_str(&format!("frplike_active_streams {}\n", self.active_streams.load(Ordering::Relaxed)));
        out.push_str("# HELP frplike_agents_online Agents with at least one live tunnel.\n# TYPE frplike_agents_online gauge\n");
        out.push_str(&format!("frplike_agents_online {agents_online}\n"));
        out.push_str("# HELP frplike_routes_active Routes currently routable.\n# TYPE frplike_routes_active gauge\n");
        out.push_str(&format!("frplike_routes_active {routes_active}\n"));
        out.push_str("# HELP frplike_tunnels_open Physical agent tunnels.\n# TYPE frplike_tunnels_open gauge\n");
        out.push_str(&format!("frplike_tunnels_open {}\n", self.tunnels_open.load(Ordering::Relaxed)));
        out.push_str("# HELP frplike_tunnels_rejected_total Rejected agent handshakes.\n# TYPE frplike_tunnels_rejected_total counter\n");
        out.push_str(&format!("frplike_tunnels_rejected_total {}\n", self.tunnels_rejected.load(Ordering::Relaxed)));
        out.push_str("# HELP frplike_request_log_dropped_total Request log entries dropped under backpressure.\n# TYPE frplike_request_log_dropped_total counter\n");
        out.push_str(&format!("frplike_request_log_dropped_total {}\n", self.log_dropped.load(Ordering::Relaxed)));
        out
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn fmt_ts(secs: i64) -> String {
    use time::macros::format_description;
    const FMT: &[time::format_description::FormatItem<'static>] =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| t.format(FMT).ok())
        .unwrap_or_else(|| secs.to_string())
}
