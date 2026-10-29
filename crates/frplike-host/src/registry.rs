//! In-memory routing snapshots.
//!
//! The data path reads two `ArcSwap`s and never takes a lock or touches SQLite.
//! Mutations (agent registration, admin actions) run under a small mutex and
//! republish both snapshots.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use frplike_proto::control::{AcceptedRoute, HostMsg};
use tokio::sync::Mutex;

use crate::config::HostConfig;
use crate::db::{AgentRow, Db, RouteRow};
use crate::metrics::Metrics;
use crate::tunnel::Tunnel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteStatus {
    Active,
    Offline,
    Disabled,
    /// Tombstone: an administrator deleted it. Externally indistinguishable
    /// from "never existed" (404), but it stops the agent from re-declaring it.
    Deleted,
}

impl RouteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RouteStatus::Active => "active",
            RouteStatus::Offline => "offline",
            RouteStatus::Disabled => "disabled",
            RouteStatus::Deleted => "deleted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteView {
    pub route_id: String,
    pub agent_id: String,
    pub target: String,
    pub status: RouteStatus,
}

#[derive(Debug, Default)]
pub struct RouteTable {
    map: HashMap<String, RouteView>,
}

impl RouteTable {
    pub fn get(&self, host: &str) -> Option<&RouteView> {
        self.map.get(host)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn active_count(&self) -> usize {
        self.map.values().filter(|r| r.status == RouteStatus::Active).count()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &RouteView)> {
        self.map.iter()
    }
}

pub struct AgentView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub tunnels: Vec<Arc<Tunnel>>,
    pub declared: HashSet<String>,
    rr: AtomicUsize,
}

impl AgentView {
    pub fn is_online(&self) -> bool {
        !self.tunnels.is_empty()
    }

    pub fn next_tunnel(&self) -> Option<Arc<Tunnel>> {
        if self.tunnels.is_empty() {
            return None;
        }
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.tunnels.len();
        self.tunnels.get(i).cloned()
    }
}

#[derive(Default)]
pub struct AgentIndex {
    map: HashMap<String, Arc<AgentView>>,
}

impl AgentIndex {
    pub fn get(&self, id: &str) -> Option<&Arc<AgentView>> {
        self.map.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<AgentView>> {
        self.map.values()
    }

    pub fn online_count(&self) -> usize {
        self.map.values().filter(|a| a.is_online()).count()
    }

    pub fn tunnel_count(&self) -> usize {
        self.map.values().map(|a| a.tunnels.len()).sum()
    }
}

struct AgentRuntime {
    id: String,
    name: String,
    version: String,
    tunnels: HashMap<String, Arc<Tunnel>>,
    declared: HashSet<String>,
}

#[derive(Default)]
struct Inner {
    agents: HashMap<String, AgentRuntime>,
}

pub struct Registry {
    inner: Mutex<Inner>,
    /// Serializes publish so a slow rebuild cannot overwrite a newer one.
    publish_lock: Mutex<()>,
    routes: ArcSwap<RouteTable>,
    agents: ArcSwap<AgentIndex>,
    pub db: Arc<Db>,
    cfg: Arc<HostConfig>,
    metrics: Arc<Metrics>,
}

impl Registry {
    pub fn new(cfg: Arc<HostConfig>, db: Arc<Db>, metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            publish_lock: Mutex::new(()),
            routes: ArcSwap::from_pointee(RouteTable::default()),
            agents: ArcSwap::from_pointee(AgentIndex::default()),
            db,
            cfg,
            metrics,
        })
    }

    pub fn routes(&self) -> Arc<RouteTable> {
        self.routes.load_full()
    }

    pub fn agents(&self) -> Arc<AgentIndex> {
        self.agents.load_full()
    }

    /// Load persisted routes at startup: every route is `offline` because no
    /// agent has connected yet.
    pub async fn load_initial(&self) -> anyhow::Result<()> {
        self.publish().await
    }

    pub async fn register_tunnel(
        &self,
        tunnel: Arc<Tunnel>,
        agent_name: &str,
        agent_version: &str,
        accepted: &[AcceptedRoute],
        all_declared: &HashSet<String>,
    ) -> anyhow::Result<()> {
        {
            let mut inner = self.inner.lock().await;
            let rt = inner.agents.entry(tunnel.agent_id.clone()).or_insert_with(|| AgentRuntime {
                id: tunnel.agent_id.clone(),
                name: agent_name.to_string(),
                version: agent_version.to_string(),
                tunnels: HashMap::new(),
                declared: HashSet::new(),
            });
            rt.name = agent_name.to_string();
            rt.version = agent_version.to_string();
            rt.tunnels.insert(tunnel.id.clone(), tunnel.clone());
            // A tunnel's handshake declares the full set; keep it as truth.
            rt.declared = all_declared.clone();
            let _ = accepted;
        }
        self.metrics.tunnels_open.fetch_add(1, Ordering::Relaxed);
        self.db.set_agent_online(&tunnel.agent_id, true).await?;
        self.publish().await
    }

    pub async fn remove_tunnel(&self, agent_id: &str, tunnel_id: &str) {
        let last_one = {
            let mut inner = self.inner.lock().await;
            match inner.agents.get_mut(agent_id) {
                Some(rt) => {
                    if rt.tunnels.remove(tunnel_id).is_some() {
                        self.metrics.tunnels_open.fetch_sub(1, Ordering::Relaxed);
                    }
                    if rt.tunnels.is_empty() {
                        inner.agents.remove(agent_id);
                        true
                    } else {
                        false
                    }
                }
                None => false,
            }
        };
        if last_one {
            let _ = self.db.set_agent_online(agent_id, false).await;
        }
        let _ = self.publish().await;
    }

    pub async fn set_declared(&self, agent_id: &str, declared: HashSet<String>) {
        {
            let mut inner = self.inner.lock().await;
            if let Some(rt) = inner.agents.get_mut(agent_id) {
                rt.declared = declared;
            }
        }
        let _ = self.publish().await;
    }

    /// Broadcast a control message to every live tunnel of an agent.
    pub async fn send_to_agent(&self, agent_id: &str, msg: HostMsg) {
        let tunnels: Vec<Arc<Tunnel>> = {
            let inner = self.inner.lock().await;
            inner
                .agents
                .get(agent_id)
                .map(|a| a.tunnels.values().cloned().collect())
                .unwrap_or_default()
        };
        for t in tunnels {
            let _ = t.control(msg.clone()).await;
        }
    }

    /// Close every tunnel of an agent (revocation, admin action).
    pub async fn disconnect_agent(&self, agent_id: &str) {
        let tunnels: Vec<Arc<Tunnel>> = {
            let inner = self.inner.lock().await;
            inner
                .agents
                .get(agent_id)
                .map(|a| a.tunnels.values().cloned().collect())
                .unwrap_or_default()
        };
        for t in tunnels {
            t.shutdown();
        }
    }

    pub async fn publish(&self) -> anyhow::Result<()> {
        let _guard = self.publish_lock.lock().await;
        // Snapshot the runtime state first, then read the database.
        let snapshot: Vec<(String, String, String, Vec<Arc<Tunnel>>, HashSet<String>)> = {
            let inner = self.inner.lock().await;
            inner
                .agents
                .values()
                .map(|a| {
                    (
                        a.id.clone(),
                        a.name.clone(),
                        a.version.clone(),
                        a.tunnels.values().cloned().collect(),
                        a.declared.clone(),
                    )
                })
                .collect()
        };
        let rows: Vec<RouteRow> = self.db.routes().await?;

        let mut agent_index = AgentIndex::default();
        for (id, name, version, tunnels, declared) in snapshot {
            agent_index.map.insert(
                id.clone(),
                Arc::new(AgentView {
                    id,
                    name,
                    version,
                    tunnels,
                    declared,
                    rr: AtomicUsize::new(0),
                }),
            );
        }

        let mut table = RouteTable::default();
        for row in rows {
            let agent = agent_index.get(&row.agent_id);
            let status = if row.deleted_at.is_some() {
                RouteStatus::Deleted
            } else if !row.enabled {
                RouteStatus::Disabled
            } else {
                match agent {
                    Some(a) if a.is_online() && a.declared.contains(&row.public_host) => RouteStatus::Active,
                    _ => RouteStatus::Offline,
                }
            };
            table.map.insert(
                row.public_host.clone(),
                RouteView {
                    route_id: row.id,
                    agent_id: row.agent_id,
                    target: row.target,
                    status,
                },
            );
        }

        self.routes.store(Arc::new(table));
        self.agents.store(Arc::new(agent_index));
        Ok(())
    }

    pub fn cfg(&self) -> &HostConfig {
        &self.cfg
    }

    pub async fn live_tunnel_count(&self, agent_id: &str) -> usize {
        let inner = self.inner.lock().await;
        inner.agents.get(agent_id).map(|a| a.tunnels.len()).unwrap_or(0)
    }

    pub fn max_tunnels_per_agent(&self) -> u8 {
        self.cfg.limits.max_tunnels_per_agent.max(1)
    }

    pub fn heartbeat_secs(&self) -> u64 {
        self.cfg.limits.heartbeat_secs.max(1)
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub async fn agent_rows(&self) -> anyhow::Result<Vec<AgentRow>> {
        self.db.agents().await
    }
}
