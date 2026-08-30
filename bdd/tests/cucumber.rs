//! Cucumber step definitions and runner for the straw BDD suite.
//!
//! Topology and hygiene steps (namespaces, veths, the clean-environment
//! sweep, ping, wait) come from the zebra-rs harness this was ported from.
//! The rest drive straw's binaries: start the proxy and the client daemon
//! inside namespaces, and assert on what they did to the kernel, on their
//! logs, and on traffic through the tunnel.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bdd::{feature_tag, netns};
use cucumber::tag::Ext as _;
use cucumber::writer::Stats as _;
use cucumber::{World as CucumberWorld, WriterExt, cli, given, then, when, writer};
use futures::stream::{self, StreamExt};

#[derive(Debug, Default, CucumberWorld)]
pub struct World {
    feature_tag: String,
}

/// Byte length of each `logs/<scoped>_<role>.log` when this process last
/// started that daemon. Daemon logs append across runs, so the log-content
/// steps only look past this offset — a line from an earlier run must never
/// satisfy an assertion about the daemon started now.
///
/// Process-global, NOT in `World`: cucumber builds a fresh `World` per
/// scenario, and daemons start in an earlier scenario than the assertions
/// about their logs. Keeping the offsets in `World` silently reset them to
/// 0 between scenarios, so `should eventually contain` matched stale lines
/// from previous runs — a converge gate that never gated anything.
fn log_offsets() -> &'static Mutex<HashMap<String, u64>> {
    static OFFSETS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    OFFSETS.get_or_init(|| Mutex::new(HashMap::new()))
}

impl World {
    fn short_id(&self) -> String {
        let mut hash: u32 = 0x811c_9dc5;
        for byte in self.feature_tag.as_bytes() {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(0x0100_0193);
        }
        format!("{:08x}", hash)
    }

    fn ns(&self, logical: &str) -> String {
        format!("{}_{}", self.feature_tag, logical)
    }

    fn bridge(&self, _logical: &str) -> String {
        format!("br_{}", self.short_id())
    }

    /// One process per (namespace, role): the proxy namespace runs `straw`,
    /// the client namespace `strawc`, a server namespace an HTTP origin.
    fn pid_file(&self, logical: &str, role: &str) -> String {
        format!("/tmp/{}_{}.pid", self.ns(logical), role)
    }

    fn log_file(&self, logical: &str, role: &str) -> String {
        format!("logs/{}_{}.log", self.ns(logical), role)
    }

    fn mark_log_start(&mut self, log_file: &str) {
        let len = fs::metadata(log_file).map(|m| m.len()).unwrap_or(0);
        log_offsets()
            .lock()
            .unwrap()
            .insert(log_file.to_string(), len);
    }

    fn log_since_start(&self, log_file: &str) -> String {
        let content = fs::read_to_string(log_file).unwrap_or_default();
        let offset = log_offsets()
            .lock()
            .unwrap()
            .get(log_file)
            .copied()
            .unwrap_or(0) as usize;
        content.get(offset..).unwrap_or("").to_string()
    }

    /// Resource-name prefixes belonging to feature tags that *extend* this
    /// one's — for `tunnel_basic`, those of `tunnel_basic_v6`. Every
    /// per-feature resource is named `<feature-tag>_<logical>`, so a sibling
    /// whose tag extends this one's shares this feature's prefix and a bare
    /// prefix scan would mistake its live resources for this feature's
    /// leaked ones. Read from the sibling's *tag*, not its file name.
    fn sibling_prefixes(&self) -> Vec<String> {
        let own = format!("{}_", self.feature_tag);
        let Ok(entries) = fs::read_dir("tests/features") else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("feature"))
            .filter_map(|p| fs::read_to_string(&p).ok())
            .filter_map(|text| feature_tag::parse(&text))
            .filter(|tag| tag.len() > self.feature_tag.len() && tag.starts_with(&own))
            .map(|tag| format!("{tag}_"))
            .collect()
    }
}

fn owned_by_sibling(name: &str, siblings: &[String]) -> bool {
    siblings.iter().any(|p| name.starts_with(p.as_str()))
}

/// `BDD_KEEP=1` skips every teardown step and the clean-environment
/// assertion, leaving namespaces and daemons up for inspection.
fn keep_topology() -> bool {
    std::env::var_os("BDD_KEEP").is_some()
}

/// Marker left by a `BDD_KEEP` run so the next run can tell its live
/// daemons apart from a genuinely concurrent run of the same feature: the
/// former is swept, the latter refused (see `clean_test_environment`).
fn kept_marker(tag: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/{tag}.bdd-kept"))
}

// ── Environment hygiene ─────────────────────────────────────────────────

#[given("a clean test environment")]
async fn clean_test_environment(world: &mut World) {
    assert!(
        !world.feature_tag.is_empty(),
        "feature must declare a tag (e.g. @tunnel_basic) for parallel-safe scoping"
    );
    let ns_prefix = format!("{}_", world.feature_tag);
    let bridge_name = world.bridge("");
    let siblings = world.sibling_prefixes();

    // Detect a concurrent run of the same feature: a live pid file under
    // this feature's prefix means another process owns these resources.
    // Only the feature's first clean in this process refuses; afterwards a
    // live pid can only be our own leftover from a scenario whose failed
    // step skipped its teardown, and sweeping it beats wedging every later
    // scenario of the feature.
    static FEATURES_CLEANED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let first_clean_in_process = FEATURES_CLEANED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap()
        .insert(world.feature_tag.clone());
    // A previous `BDD_KEEP` run left its daemons up on purpose; those are
    // ours to sweep, not another run's to respect.
    let kept = kept_marker(&world.feature_tag);
    let previously_kept = kept.exists();
    let _ = fs::remove_file(&kept);
    if let Ok(pidfiles) = netns::list_pidfiles(Path::new("/tmp"), &ns_prefix).await {
        let pidfiles: Vec<PathBuf> = pidfiles
            .into_iter()
            .filter(|p| {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                !owned_by_sibling(&name, &siblings)
            })
            .collect();
        for path in &pidfiles {
            if first_clean_in_process && !previously_kept && netns::pidfile_alive(path).await {
                panic!(
                    "another run of feature {} is in progress (live pid file {:?}); refusing to clobber its resources",
                    world.feature_tag, path
                );
            }
        }
        for path in pidfiles {
            let _ = netns::kill_pidfile(&path).await;
        }
    }

    // `ip netns del` returns in-namespace interfaces to the host rather than
    // destroying them, so host-side veths are swept separately below.
    if let Ok(stale) = netns::list_netns_with_prefix(&ns_prefix).await {
        for ns in stale {
            if owned_by_sibling(&ns, &siblings) {
                continue;
            }
            let _ = netns::delete_netns(&ns).await;
        }
    }
    if let Ok(stale) = netns::list_bridges_with_prefix(&bridge_name).await {
        for br in stale {
            let _ = netns::delete_bridge(&br).await;
        }
    }
    let veth_suffix = format!("_{}", world.short_id());
    if let Ok(stale) = netns::list_veths_with_suffix(&veth_suffix).await {
        for veth in stale {
            let _ = netns::delete_veth(&veth).await;
        }
    }
    println!(
        "✓ Test environment cleaned for feature {}",
        world.feature_tag
    );
}

#[then("the test environment should be clean")]
async fn verify_clean_environment(world: &mut World) {
    if keep_topology() {
        let _ = fs::write(kept_marker(&world.feature_tag), b"");
        println!("⏭  BDD_KEEP set — skipping clean-environment check (topology left up)");
        return;
    }
    let ns_prefix = format!("{}_", world.feature_tag);
    let siblings = world.sibling_prefixes();
    let leftover_ns: Vec<String> = netns::list_netns_with_prefix(&ns_prefix)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|ns| !owned_by_sibling(ns, &siblings))
        .collect();
    assert!(
        leftover_ns.is_empty(),
        "Namespaces still exist: {:?}",
        leftover_ns
    );
    let leftover_br = netns::list_bridges_with_prefix(&world.bridge(""))
        .await
        .unwrap_or_default();
    assert!(
        leftover_br.is_empty(),
        "Bridges still exist: {:?}",
        leftover_br
    );
    let leftover_pid: Vec<PathBuf> = netns::list_pidfiles(Path::new("/tmp"), &ns_prefix)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            !owned_by_sibling(&name, &siblings)
        })
        .collect();
    assert!(
        leftover_pid.is_empty(),
        "PID files still exist: {:?}",
        leftover_pid
    );
    println!("✓ Test environment is clean");
}

// ── Topology ────────────────────────────────────────────────────────────

#[given(expr = "I create namespace {string}")]
#[when(expr = "I create namespace {string}")]
async fn create_namespace(world: &mut World, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::create_netns(&scoped)
        .await
        .expect("Failed to create namespace");
    println!("✓ Namespace {} created", scoped);
}

#[given(
    expr = "I connect namespace {string} interface {string} to namespace {string} interface {string}"
)]
#[when(
    expr = "I connect namespace {string} interface {string} to namespace {string} interface {string}"
)]
async fn connect_two_namespaces(
    world: &mut World,
    ns_a: String,
    iface_a: String,
    ns_b: String,
    iface_b: String,
) {
    let a = world.ns(&ns_a);
    let b = world.ns(&ns_b);
    let short = world.short_id();
    netns::connect_netns_pair(&short, &a, &iface_a, &b, &iface_b)
        .await
        .expect("Failed to connect namespace pair");
    println!("✓ Linked {}:{} <-> {}:{}", a, iface_a, b, iface_b);
}

#[given(expr = "I assign address {string} to interface {string} in namespace {string}")]
#[when(expr = "I assign address {string} to interface {string} in namespace {string}")]
async fn assign_address(world: &mut World, addr: String, iface: String, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(&scoped, "ip", &["addr", "add", &addr, "dev", &iface])
        .await
        .expect("Failed to assign address");
    println!("✓ {} on {}:{}", addr, scoped, iface);
}

#[given(expr = "I add route {string} via {string} in namespace {string}")]
#[when(expr = "I add route {string} via {string} in namespace {string}")]
async fn add_route(world: &mut World, prefix: String, via: String, namespace: String) {
    let scoped = world.ns(&namespace);
    netns::exec_in_netns(&scoped, "ip", &["route", "add", &prefix, "via", &via])
        .await
        .expect("Failed to add route");
    println!("✓ route {} via {} in {}", prefix, via, scoped);
}

#[when(expr = "I delete namespace {string}")]
async fn delete_namespace(world: &mut World, namespace: String) {
    if keep_topology() {
        println!(
            "⏭  BDD_KEEP set — leaving namespace {} up",
            world.ns(&namespace)
        );
        return;
    }
    let scoped = world.ns(&namespace);
    netns::delete_netns(&scoped)
        .await
        .expect("Failed to delete namespace");
    println!("✓ Namespace {} deleted", scoped);
}

#[given(expr = "I wait {int} seconds")]
#[when(expr = "I wait {int} seconds")]
#[then(expr = "I wait {int} seconds")]
async fn wait_seconds(_world: &mut World, seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

// ── Daemons ─────────────────────────────────────────────────────────────

/// Start `role` (`straw`, `strawc`, …) inside a namespace with the pid
/// recorded and output appended to the role's log file.
///
/// The binaries have no `--daemon`/`--pid-file`, so a shell writes its own
/// pid and then `exec`s the binary: `ip netns exec`, `env` and `sh` all
/// exec in place, so the recorded pid is the daemon's own. That is what
/// `terminate_pidfile` signals later, from a different scenario (cucumber
/// creates a fresh `World` per scenario, so a `Child` handle cannot carry
/// over).
async fn start_daemon(world: &mut World, namespace: &str, role: &str, args: &str) {
    let scoped = world.ns(namespace);
    let pid_file = world.pid_file(namespace, role);
    let log_file = world.log_file(namespace, role);
    world.mark_log_start(&log_file);

    let script = format!("echo $$ > {pid_file}; exec {role} {args}");
    let _child = netns::spawn_in_netns_logged(
        &scoped,
        // Debug level: the MTU and route decisions the scenarios assert on
        // are logged at debug.
        &[("RUST_LOG", "straw=debug,strawc=debug")],
        "sh",
        &["-c", &script],
        Path::new(&log_file),
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to start {role}: {e}"));
    println!("✓ {} started in namespace {} ({})", role, scoped, log_file);
}

/// Poll `log_file` (from this run's start mark) for `needle`.
async fn log_eventually_contains(
    world: &World,
    log_file: &str,
    needle: &str,
    attempts: u32,
) -> bool {
    for _ in 0..attempts {
        if world.log_since_start(log_file).contains(needle) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

#[given(expr = "I start straw in namespace {string} with args {string}")]
#[when(expr = "I start straw in namespace {string} with args {string}")]
async fn start_straw(world: &mut World, namespace: String, args: String) {
    start_daemon(world, &namespace, "straw", &args).await;
    let log_file = world.log_file(&namespace, "straw");
    // Ready once it is accepting QUIC; a client started before that only
    // sees connection refused.
    if !log_eventually_contains(world, &log_file, "straw proxy listening", 60).await {
        panic!(
            "straw did not start listening; log:\n{}",
            world.log_since_start(&log_file)
        );
    }
}

#[given(expr = "I start strawc in namespace {string} with args {string}")]
#[when(expr = "I start strawc in namespace {string} with args {string}")]
async fn start_strawc(world: &mut World, namespace: String, args: String) {
    start_daemon(world, &namespace, "strawc", &args).await;
}

#[given(expr = "I serve a {int} MiB file over HTTP in namespace {string} on {string}")]
#[when(expr = "I serve a {int} MiB file over HTTP in namespace {string} on {string}")]
async fn serve_http(world: &mut World, mib: u64, namespace: String, bind: String) {
    // An origin behind the proxy, so TCP tests need no internet. Served
    // from a per-feature directory so concurrent features cannot swap
    // payloads under each other; the file is random so a truncated or
    // corrupted transfer cannot pass by accident.
    let dir = format!("/tmp/{}_http", world.ns(&namespace));
    fs::create_dir_all(&dir).expect("create http dir");
    let payload = fs::File::create(format!("{dir}/payload")).expect("create payload");
    let mut out = std::io::BufWriter::new(payload);
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15 ^ mib;
    let mut chunk = vec![0u8; 4096];
    for _ in 0..(mib * 256) {
        for b in chunk.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = seed as u8;
        }
        out.write_all(&chunk).expect("write payload");
    }
    out.flush().expect("flush payload");

    let (addr, port) = bind.rsplit_once(':').expect("bind must be addr:port");
    let args = format!("-m http.server {port} --bind {addr} --directory {dir}");
    start_daemon(world, &namespace, "python3", &args).await;
    // Give the listener a moment; the download steps also retry.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[when(expr = "I stop {word} in namespace {string}")]
async fn stop_daemon(world: &mut World, role: String, namespace: String) {
    if keep_topology() {
        println!(
            "⏭  BDD_KEEP set — leaving {} running in namespace {}",
            role,
            world.ns(&namespace)
        );
        return;
    }
    let pid_file = world.pid_file(&namespace, &role);
    netns::terminate_pidfile(Path::new(&pid_file), Duration::from_secs(10))
        .await
        .expect("Failed to stop daemon");
    println!("✓ {} stopped in namespace {}", role, world.ns(&namespace));
}

#[then(expr = "the {word} log in namespace {string} should contain {string}")]
async fn log_should_contain(world: &mut World, role: String, namespace: String, needle: String) {
    let log_file = world.log_file(&namespace, &role);
    let contents = world.log_since_start(&log_file);
    assert!(
        contents.contains(&needle),
        "{} log {} does not contain {:?}; log:\n{}",
        role,
        log_file,
        needle,
        contents
    );
    println!("✓ {} log contains {:?}", role, needle);
}

#[then(expr = "the {word} log in namespace {string} should eventually contain {string}")]
async fn log_should_eventually_contain(
    world: &mut World,
    role: String,
    namespace: String,
    needle: String,
) {
    let log_file = world.log_file(&namespace, &role);
    if !log_eventually_contains(world, &log_file, &needle, 120).await {
        panic!(
            "{} log {} never contained {:?}; log:\n{}",
            role,
            log_file,
            needle,
            world.log_since_start(&log_file)
        );
    }
    println!("✓ {} log eventually contains {:?}", role, needle);
}

// ── Kernel state ────────────────────────────────────────────────────────

async fn interface_exists(scoped: &str, iface: &str) -> bool {
    netns::exec_in_netns(scoped, "ip", &["link", "show", iface])
        .await
        .is_ok()
}

#[then(expr = "interface {string} in namespace {string} should eventually exist")]
async fn interface_eventually_exists(world: &mut World, iface: String, namespace: String) {
    let scoped = world.ns(&namespace);
    for _ in 0..60 {
        if interface_exists(&scoped, &iface).await {
            println!("✓ {}:{} exists", scoped, iface);
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("interface {} never appeared in namespace {}", iface, scoped);
}

#[then(expr = "interface {string} in namespace {string} should eventually be gone")]
async fn interface_eventually_gone(world: &mut World, iface: String, namespace: String) {
    let scoped = world.ns(&namespace);
    for _ in 0..60 {
        if !interface_exists(&scoped, &iface).await {
            println!("✓ {}:{} is gone", scoped, iface);
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("interface {} still present in namespace {}", iface, scoped);
}

#[then(expr = "interface {string} in namespace {string} should eventually have address {string}")]
async fn interface_eventually_has_address(
    world: &mut World,
    iface: String,
    namespace: String,
    addr: String,
) {
    let scoped = world.ns(&namespace);
    let mut last = String::new();
    for _ in 0..60 {
        if let Ok(out) = netns::exec_in_netns(&scoped, "ip", &["-o", "addr", "show", &iface]).await
        {
            if out.split_whitespace().any(|t| t == addr) {
                println!("✓ {}:{} has {}", scoped, iface, addr);
                return;
            }
            last = out;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "interface {} in {} never had address {}; last output:\n{}",
        iface, scoped, addr, last
    );
}

/// Route table of `scoped` for the family of `prefix`, one route per line.
async fn routes(scoped: &str, prefix: &str) -> String {
    let family = if prefix.contains(':') { "-6" } else { "-4" };
    netns::exec_in_netns(scoped, "ip", &[family, "route", "show"])
        .await
        .unwrap_or_default()
}

fn has_route(table: &str, prefix: &str, dev: &str) -> bool {
    table.lines().any(|l| {
        let toks: Vec<&str> = l.split_whitespace().collect();
        toks.first() == Some(&prefix) && toks.windows(2).any(|w| w[0] == "dev" && w[1] == dev)
    })
}

#[then(
    expr = "route {string} via interface {string} should eventually exist in namespace {string}"
)]
async fn route_eventually_exists(
    world: &mut World,
    prefix: String,
    dev: String,
    namespace: String,
) {
    let scoped = world.ns(&namespace);
    let mut last = String::new();
    for _ in 0..60 {
        last = routes(&scoped, &prefix).await;
        if has_route(&last, &prefix, &dev) {
            println!("✓ route {} dev {} in {}", prefix, dev, scoped);
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "route {} dev {} never appeared in {}; table:\n{}",
        prefix, dev, scoped, last
    );
}

#[then(expr = "route {string} should not exist in namespace {string}")]
async fn route_should_not_exist(world: &mut World, prefix: String, namespace: String) {
    let scoped = world.ns(&namespace);
    let table = routes(&scoped, &prefix).await;
    let present = table
        .lines()
        .any(|l| l.split_whitespace().next() == Some(prefix.as_str()));
    assert!(
        !present,
        "route {} still present in {}; table:\n{}",
        prefix, scoped, table
    );
    println!("✓ no route {} in {}", prefix, scoped);
}

#[then(
    expr = "route {string} via interface {string} should eventually be gone in namespace {string}"
)]
async fn route_eventually_gone(world: &mut World, prefix: String, dev: String, namespace: String) {
    let scoped = world.ns(&namespace);
    let mut last = String::new();
    for _ in 0..60 {
        last = routes(&scoped, &prefix).await;
        if !has_route(&last, &prefix, &dev) {
            println!("✓ route {} dev {} gone from {}", prefix, dev, scoped);
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "route {} dev {} still present in {}; table:\n{}",
        prefix, dev, scoped, last
    );
}

// ── Traffic ─────────────────────────────────────────────────────────────

#[then(expr = "ping from {string} to {string} should succeed")]
async fn ping_should_succeed(world: &mut World, namespace: String, target: String) {
    let scoped = world.ns(&namespace);
    let success = if target.contains(':') {
        netns::ping6(&scoped, &target, 3, 2).await
    } else {
        netns::ping4(&scoped, &target, 3, 2).await
    }
    .expect("ping failed to run");
    assert!(
        success,
        "ping from {} to {} did not succeed",
        scoped, target
    );
    println!("✓ ping from {} to {} succeeded", scoped, target);
}

#[then(expr = "ping from {string} to {string} should eventually succeed")]
async fn ping_eventually_succeeds(world: &mut World, namespace: String, target: String) {
    let scoped = world.ns(&namespace);
    const ATTEMPTS: u32 = 30;
    for i in 0..ATTEMPTS {
        let ok = if target.contains(':') {
            netns::ping6(&scoped, &target, 1, 1).await
        } else {
            netns::ping4(&scoped, &target, 1, 1).await
        }
        .unwrap_or(false);
        if ok {
            println!(
                "✓ ping from {} to {} succeeded (attempt {})",
                scoped,
                target,
                i + 1
            );
            return;
        }
        if i + 1 < ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "ping from {} to {} did not succeed within {} attempts",
        scoped, target, ATTEMPTS
    );
}

#[then(expr = "ping from {string} to {string} should fail")]
async fn ping_should_fail(world: &mut World, namespace: String, target: String) {
    let scoped = world.ns(&namespace);
    let ok = if target.contains(':') {
        netns::ping6(&scoped, &target, 2, 1).await
    } else {
        netns::ping4(&scoped, &target, 2, 1).await
    }
    .expect("ping failed to run");
    assert!(
        !ok,
        "ping from {} to {} unexpectedly succeeded",
        scoped, target
    );
    println!("✓ ping from {} to {} failed (as expected)", scoped, target);
}

/// `ping -M do` with a payload sized so the IP packet is exactly `size`.
///
/// Polled: a full-MTU packet only fits once the session MTU has ramped to
/// the configured value (quinn's path-MTU discovery raises it in steps,
/// slower under concurrent load), so early attempts can be dropped at the
/// tunnel with the drop counted — not a failure, just not converged yet.
#[then(expr = "a {int} byte unfragmentable ping from {string} to {string} should succeed")]
async fn sized_ping_should_succeed(
    world: &mut World,
    size: u32,
    namespace: String,
    target: String,
) {
    let scoped = world.ns(&namespace);
    let header = if target.contains(':') { 48 } else { 28 };
    let payload = (size - header).to_string();
    let family = if target.contains(':') { "-6" } else { "-4" };
    const ATTEMPTS: u32 = 15;
    let mut last = String::new();
    for i in 0..ATTEMPTS {
        match netns::exec_in_netns(
            &scoped,
            "ping",
            &[
                family, "-c", "1", "-W", "2", "-M", "do", "-s", &payload, &target,
            ],
        )
        .await
        {
            Ok(_) => {
                println!(
                    "✓ {} byte ping from {} to {} succeeded (attempt {})",
                    size,
                    scoped,
                    target,
                    i + 1
                );
                return;
            }
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("{size} byte ping from {scoped} to {target} never succeeded: {last}");
}

#[then(
    expr = "a {int} byte unfragmentable ping from {string} to {string} should be refused as too long"
)]
async fn sized_ping_too_long(world: &mut World, size: u32, namespace: String, target: String) {
    let scoped = world.ns(&namespace);
    let header = if target.contains(':') { 48 } else { 28 };
    let payload = (size - header).to_string();
    let family = if target.contains(':') { "-6" } else { "-4" };
    // Refused by the sender's own kernel (device MTU), so ping exits
    // non-zero with the reason on stderr — a silent drop times out instead.
    let err = netns::exec_in_netns(
        &scoped,
        "ping",
        &[
            family, "-c", "1", "-W", "2", "-M", "do", "-s", &payload, &target,
        ],
    )
    .await
    .err()
    .map(|e| e.to_string())
    .unwrap_or_else(|| panic!("{size} byte ping was delivered instead of refused"));
    let lower = err.to_lowercase();
    assert!(
        lower.contains("message too long") || lower.contains("frag needed"),
        "{} byte ping was not refused as too long: {}",
        size,
        err
    );
    println!("✓ {} byte ping refused as too long", size);
}

#[then(
    expr = "downloading {string} from namespace {string} should match the file served by {string}"
)]
async fn download_matches(world: &mut World, url: String, namespace: String, origin: String) {
    let scoped = world.ns(&namespace);
    let served = format!("/tmp/{}_http/payload", world.ns(&origin));
    let got = format!("/tmp/{}_download", scoped);
    let mut last_err = String::new();
    for _ in 0..5 {
        match netns::exec_in_netns(
            &scoped,
            "curl",
            &["-sS", "--max-time", "60", "-o", &got, &url],
        )
        .await
        {
            Ok(_) => break,
            Err(e) => {
                last_err = e.to_string();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    // The download ran as root; compare through sudo for the same reason.
    let cmp = netns::exec_in_netns(&scoped, "cmp", &[&served, &got]).await;
    let _ = netns::exec_in_netns(&scoped, "rm", &["-f", &got]).await;
    assert!(
        cmp.is_ok(),
        "download of {} from {} does not match the served file ({}; last curl error: {})",
        url,
        scoped,
        cmp.err().map(|e| e.to_string()).unwrap_or_default(),
        last_err
    );
    println!("✓ {} downloaded from {} and verified", url, scoped);
}

#[then(
    expr = "test_client in namespace {string} via proxy {string} should ping {string} successfully"
)]
async fn test_client_ping(world: &mut World, namespace: String, proxy: String, target: String) {
    let scoped = world.ns(&namespace);
    let mut args = vec![
        "--server-addr",
        proxy.as_str(),
        "--insecure",
        "--count",
        "3",
    ];
    if target != "self" {
        args.extend(["--target", target.as_str()]);
    }
    let out = netns::exec_in_netns(&scoped, "test_client", &args)
        .await
        .unwrap_or_else(|e| panic!("test_client failed: {e}"));
    assert!(
        out.contains("3/3 packets received"),
        "test_client did not receive every reply:\n{}",
        out
    );
    println!(
        "✓ test_client in {} pinged {} via {}",
        scoped, target, proxy
    );
}

#[then(expr = "command {string} in namespace {string} should succeed")]
async fn command_should_succeed(world: &mut World, command: String, namespace: String) {
    let scoped = world.ns(&namespace);
    let out = netns::exec_in_netns(&scoped, "sh", &["-c", &command]).await;
    assert!(
        out.is_ok(),
        "`{}` failed in {}: {}",
        command,
        scoped,
        out.err().map(|e| e.to_string()).unwrap_or_default()
    );
    println!("✓ `{}` succeeded in {}", command, scoped);
}

#[then(expr = "command {string} in namespace {string} should fail")]
async fn command_should_fail(world: &mut World, command: String, namespace: String) {
    let scoped = world.ns(&namespace);
    let out = netns::exec_in_netns(&scoped, "sh", &["-c", &command]).await;
    assert!(
        out.is_err(),
        "`{}` unexpectedly succeeded in {}",
        command,
        scoped
    );
    println!("✓ `{}` failed in {} (as expected)", command, scoped);
}

// ── Runner ──────────────────────────────────────────────────────────────

/// Output sink for a single feature's console report: the terminal when
/// features run one at a time, a per-feature log otherwise so concurrent
/// features do not interleave.
enum FeatureOut {
    Stdout(std::io::Stdout),
    File(fs::File),
}

impl Write for FeatureOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Stdout(o) => o.write(buf),
            Self::File(f) => f.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Stdout(o) => o.flush(),
            Self::File(f) => f.flush(),
        }
    }
}

struct FeatureOutcome {
    name: String,
    /// Scenarios that passed the `--tags` / `--name` filter (0 ⇒ skipped).
    matched: usize,
    failed: bool,
    failed_steps: usize,
}

#[tokio::main]
async fn main() {
    let _ = fs::create_dir_all("logs");
    let _ = fs::create_dir_all("allure-results");

    // Say which binaries this run executes: a failure caused by a stale or
    // foreign build is otherwise indistinguishable from a product bug.
    println!("{}", bdd::toolchain::describe());

    // Each feature runs in its own cucumber instance with scenarios serial
    // and in declaration order; *different* features run concurrently, so
    // `--concurrency=N` means N features at a time. Safe because every
    // feature scopes its namespaces, veths and pid files by its tag.
    type CliOpts = cli::Opts<
        cucumber::parser::basic::Cli,
        cucumber::runner::basic::Cli,
        cucumber::writer::basic::Cli,
        cli::Empty,
    >;
    let opts = CliOpts::parsed();
    let feature_concurrency = opts.runner.concurrency.unwrap_or(1).max(1);
    let tags_filter = opts.tags_filter;
    let re_filter = opts.re_filter;

    let mut features: Vec<PathBuf> = fs::read_dir("tests/features")
        .expect("read tests/features directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("feature"))
        .collect();
    features.sort();

    let pid = std::process::id();
    let outcomes: Vec<FeatureOutcome> = stream::iter(features)
        .map(|path| {
            let tags_filter = tags_filter.clone();
            let re_filter = re_filter.clone();
            async move {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("feature")
                    .to_owned();

                // Allure output scoped by PID and feature so concurrent
                // features and concurrent `cargo test`s never clobber.
                let json_path = format!("allure-results/results-{pid}-{name}.json");
                let log_path = format!("logs/{name}.cucumber.log");
                let json_file = fs::File::create(&json_path).expect("create Allure results file");

                let (out, coloring) = if feature_concurrency > 1 {
                    let log = fs::File::create(&log_path).expect("create cucumber log file");
                    (FeatureOut::File(log), writer::Coloring::Never)
                } else {
                    (
                        FeatureOut::Stdout(std::io::stdout()),
                        writer::Coloring::Auto,
                    )
                };

                let matched = Arc::new(AtomicUsize::new(0));
                let counter = Arc::clone(&matched);

                let writer = World::cucumber()
                    .max_concurrent_scenarios(1)
                    .before(|feature, _rule, _scenario, world| {
                        Box::pin(async move {
                            world.feature_tag = feature
                                .tags
                                .iter()
                                .find(|t| {
                                    *t != "serial" && *t != "allow.skipped" && *t != "disabled"
                                })
                                .cloned()
                                .unwrap_or_default();
                        })
                    })
                    .with_writer(
                        writer::Basic::new(out, coloring, writer::Verbosity::Default)
                            .summarized()
                            .tee::<World, _>(writer::Json::for_tee(json_file))
                            .normalized(),
                    )
                    // A step whose phrasing matches no definition is silently
                    // skipped by cucumber, and a skipped wait or assertion
                    // reads as a pass. Fail loudly at the unmatched step
                    // instead; `@allow.skipped` opts a scenario out.
                    .fail_on_skipped()
                    .with_default_cli()
                    .filter_run(path, move |feat, rule, scenario| {
                        let disabled = feat
                            .tags
                            .iter()
                            .chain(rule.iter().flat_map(|r| &r.tags))
                            .chain(scenario.tags.iter())
                            .any(|t| t == "disabled");
                        if disabled {
                            return false;
                        }
                        let pass = match &re_filter {
                            Some(re) => re.is_match(&scenario.name),
                            None => match &tags_filter {
                                Some(tags) => tags.eval(
                                    feat.tags
                                        .iter()
                                        .chain(rule.iter().flat_map(|r| &r.tags))
                                        .chain(scenario.tags.iter()),
                                ),
                                None => true,
                            },
                        };
                        if pass {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        pass
                    })
                    .await;

                let matched = matched.load(Ordering::Relaxed);
                let outcome = FeatureOutcome {
                    name,
                    matched,
                    failed: writer.execution_has_failed(),
                    failed_steps: writer.failed_steps(),
                };
                drop(writer);
                if matched == 0 {
                    let _ = fs::remove_file(&json_path);
                    if feature_concurrency > 1 {
                        let _ = fs::remove_file(&log_path);
                    }
                }
                outcome
            }
        })
        .buffer_unordered(feature_concurrency)
        .collect()
        .await;

    let mut ran: Vec<&FeatureOutcome> = outcomes.iter().filter(|o| o.matched > 0).collect();
    ran.sort_by(|a, b| a.name.cmp(&b.name));
    let failed = ran.iter().filter(|o| o.failed).count();

    println!("\n──── cucumber summary ({feature_concurrency}-way feature concurrency) ────");
    for o in &ran {
        let mark = if o.failed { "✗" } else { "✓" };
        let detail = if o.failed {
            format!(" — {} step(s) failed", o.failed_steps)
        } else {
            String::new()
        };
        println!("  {mark} {} ({} scenario(s){detail})", o.name, o.matched);
    }
    println!(
        "{} feature(s) ran, {} passed, {} failed",
        ran.len(),
        ran.len() - failed,
        failed,
    );
    // Unlike the original harness, a failed run fails the process so `make`
    // and CI notice.
    if failed > 0 {
        std::process::exit(1);
    }
}
