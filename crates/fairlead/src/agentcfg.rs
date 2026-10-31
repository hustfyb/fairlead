//! Editing the agent config from the CLI.
//!
//! The config file is the agent's single source of truth, but nobody should
//! have to hand-maintain TOML: `fairlead agent add` / `rm` rewrite only the
//! `[[routes]]` tables and leave every comment and every other key exactly as
//! it was (toml_edit keeps the document's formatting).

use std::path::Path;

use anyhow::{anyhow, bail, Context};
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

/// What changed, for the message the CLI prints.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Added,
    Updated { from: String },
    Unchanged,
}

#[cfg(test)]
pub fn routes(text: &str) -> anyhow::Result<Vec<fairlead_proto::control::RouteDecl>> {
    let cfg = fairlead_agent::AgentConfig::from_toml(text)?;
    Ok(cfg.routes)
}

/// Add `host -> target`, or point an existing `host` at a new target.
pub fn add_or_update(text: &str, host: &str, target: &str) -> anyhow::Result<(String, Change)> {
    let mut doc: DocumentMut = text.parse().context("config is not valid TOML")?;
    let change = {
        let aot = routes_table(&mut doc)?;
        let want = normalize(host);
        let found = aot
            .iter()
            .position(|t| host_of(t).as_deref().map(normalize) == Some(want.clone()));
        match found {
            Some(i) => {
                let from = aot
                    .get(i)
                    .and_then(|t| t.get("target"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if from == target {
                    Change::Unchanged
                } else {
                    let t = aot.get_mut(i).expect("index from iter");
                    t["target"] = value(target);
                    t["host"] = value(host);
                    Change::Updated { from }
                }
            }
            None => {
                let mut t = Table::new();
                t.insert("host", value(host));
                t.insert("target", value(target));
                t.set_implicit(false);
                // One blank line between tables, the way a human writes them.
                t.decor_mut().set_prefix("\n");
                aot.push(t);
                Change::Added
            }
        }
    };
    Ok((doc.to_string(), change))
}

/// Remove `host`. `Ok(None)` when it was not there to begin with.
pub fn remove(text: &str, host: &str) -> anyhow::Result<Option<String>> {
    let mut doc: DocumentMut = text.parse().context("config is not valid TOML")?;
    let aot = routes_table(&mut doc)?;
    let want = normalize(host);
    let Some(idx) = aot
        .iter()
        .position(|t| host_of(t).as_deref().map(normalize) == Some(want.clone()))
    else {
        return Ok(None);
    };
    aot.remove(idx);
    Ok(Some(doc.to_string()))
}

fn routes_table(doc: &mut DocumentMut) -> anyhow::Result<&mut ArrayOfTables> {
    if doc.get("routes").is_none() {
        doc.insert("routes", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    match doc.get_mut("routes") {
        Some(Item::ArrayOfTables(a)) => Ok(a),
        Some(_) => bail!("`routes` in the config is not a list of [[routes]] tables"),
        None => unreachable!("inserted above"),
    }
}

fn host_of(t: &Table) -> Option<String> {
    t.get("host")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn normalize(host: &str) -> String {
    fairlead_proto::hostname::normalize(host).unwrap_or_else(|_| host.trim().to_ascii_lowercase())
}

/// Write the config back atomically, keeping the mode and the owner of the
/// original file: the service often runs as the user who installed it, while
/// `add` may be run with sudo.
pub fn write(path: &Path, text: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)
        .with_context(|| format!("write {} (try sudo, or pass --config)", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = std::fs::metadata(path) {
            let _ = std::fs::set_permissions(&tmp, md.permissions());
            let _ = std::os::unix::fs::chown(&tmp, Some(md.uid()), Some(md.gid()));
        }
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

/// `8080`, `:8080`, `127.0.0.1:8080`, `localhost:8080` -> a `host:port` target.
pub fn normalize_target(raw: &str) -> anyhow::Result<String> {
    let raw = raw.trim();
    let target = if raw.is_empty() {
        return Err(anyhow!("target is empty"));
    } else if raw.chars().all(|c| c.is_ascii_digit()) {
        format!("127.0.0.1:{raw}")
    } else if let Some(port) = raw.strip_prefix(':') {
        format!("127.0.0.1:{port}")
    } else {
        raw.to_string()
    };
    fairlead_proto::control::validate_target(&target).map_err(|e| anyhow!("{e}: {target}"))?;
    Ok(target)
}

/// `a1.relay.example.com` from user input, or a clear error.
pub fn normalize_host(raw: &str) -> anyhow::Result<String> {
    fairlead_proto::hostname::normalize(raw.trim())
        .map_err(|e| anyhow!("not a host name: {raw} ({e})"))
}

/// `tunnel.relay.example.com` -> `relay.example.com`: the suffix the install
/// script would publish under, so `fairlead agent add 8080` can name itself.
pub fn suffix_from_tunnel_host(tunnel_host: &str) -> Option<String> {
    let host = fairlead_proto::hostname::normalize(tunnel_host).ok()?;
    let (_label, rest) = host.split_once('.')?;
    // Require at least two labels left: "relay.example.com", not "example.com"
    // guessed out of "example.com" itself.
    if rest.matches('.').count() < 2 {
        return None;
    }
    Some(rest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"# fairlead agent — written by install.sh
server = "http://tunnel.relay.test:29001"
tunnel_host = "tunnel.relay.test"
name = "agent-a"

# first run only
token = "abc"

[[routes]]
host = "a1.relay.test"
target = "127.0.0.1:7884"
"#;

    #[test]
    fn adding_a_route_keeps_every_comment() {
        let (out, change) = add_or_update(CONFIG, "a2.relay.test", "127.0.0.1:7885").unwrap();
        assert_eq!(change, Change::Added);
        assert!(
            out.contains("# fairlead agent — written by install.sh"),
            "{out}"
        );
        assert!(out.contains("# first run only"));
        assert!(out.contains("[[routes]]\nhost = \"a2.relay.test\"\ntarget = \"127.0.0.1:7885\""));
        // and the file still parses into what we meant
        let routes = routes(&out).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[1].host, "a2.relay.test");
        assert_eq!(routes[1].target, "127.0.0.1:7885");
    }

    #[test]
    fn adding_the_same_route_twice_is_a_no_op() {
        let (out, change) = add_or_update(CONFIG, "a1.relay.test", "127.0.0.1:7884").unwrap();
        assert_eq!(change, Change::Unchanged);
        assert_eq!(out, CONFIG);
    }

    #[test]
    fn adding_an_existing_host_moves_it() {
        let (out, change) = add_or_update(CONFIG, "a1.relay.test", "127.0.0.1:9000").unwrap();
        assert_eq!(
            change,
            Change::Updated {
                from: "127.0.0.1:7884".into()
            }
        );
        let routes = routes(&out).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].target, "127.0.0.1:9000");
    }

    #[test]
    fn a_config_without_routes_gets_them() {
        let bare = "server = \"http://relay.test:9000\"\nname = \"a\"\n";
        let (out, change) = add_or_update(bare, "a1.relay.test", "127.0.0.1:8080").unwrap();
        assert_eq!(change, Change::Added);
        assert_eq!(routes(&out).unwrap().len(), 1);
    }

    #[test]
    fn removing_takes_the_whole_table_and_nothing_else() {
        let (two, _) = add_or_update(CONFIG, "a2.relay.test", "127.0.0.1:7885").unwrap();
        let out = remove(&two, "a1.relay.test").unwrap().expect("was there");
        assert!(!out.contains("a1.relay.test"));
        assert!(out.contains("a2.relay.test"));
        assert!(out.contains("name = \"agent-a\""));
        assert_eq!(routes(&out).unwrap().len(), 1);
    }

    #[test]
    fn removing_the_last_route_leaves_a_valid_config() {
        let out = remove(CONFIG, "a1.relay.test").unwrap().expect("was there");
        assert!(routes(&out).unwrap().is_empty());
        assert!(out.contains("server ="));
        assert!(fairlead_agent::AgentConfig::from_toml(&out).is_ok());
    }

    #[test]
    fn removing_something_that_is_not_there_says_so() {
        assert!(remove(CONFIG, "nope.relay.test").unwrap().is_none());
    }

    #[test]
    fn hosts_are_matched_case_insensitively() {
        let (out, change) = add_or_update(CONFIG, "A1.Relay.Test", "127.0.0.1:7884").unwrap();
        assert_eq!(change, Change::Unchanged);
        assert_eq!(out, CONFIG);
    }

    #[test]
    fn an_inline_array_of_routes_is_refused_clearly() {
        let bad = "server = \"http://x:1\"\nroutes = []\n";
        let err = add_or_update(bad, "a1.relay.test", "127.0.0.1:1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("[[routes]]"), "{err}");
    }

    #[test]
    fn targets_accept_the_shapes_people_type() {
        assert_eq!(normalize_target("8080").unwrap(), "127.0.0.1:8080");
        assert_eq!(normalize_target(":8080").unwrap(), "127.0.0.1:8080");
        assert_eq!(
            normalize_target("127.0.0.1:8080").unwrap(),
            "127.0.0.1:8080"
        );
        assert_eq!(
            normalize_target("localhost:8080").unwrap(),
            "localhost:8080"
        );
        assert!(normalize_target("http://127.0.0.1:8080").is_err());
        assert!(normalize_target("0").is_err());
    }

    #[test]
    fn the_suffix_comes_from_the_tunnel_host() {
        assert_eq!(
            suffix_from_tunnel_host("tunnel.relay.027mango.com").as_deref(),
            Some("relay.027mango.com")
        );
        assert_eq!(suffix_from_tunnel_host("relay.example.com"), None);
    }
}
