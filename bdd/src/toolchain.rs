//! Which straw build a BDD run executes.
//!
//! Every binary the harness launches inside a namespace would otherwise be
//! resolved by bare name through root's PATH — `/usr/local/bin/straw`,
//! `/usr/local/bin/strawc`. Those are host-global: an `install` from one
//! git worktree overwrites them for every other, so a run in worktree A
//! silently exercises whichever binary worktree B installed last. That
//! reads as an inexplicable product regression.
//!
//! A *staged prefix* removes the host from the picture. `make -C bdd stage`
//! builds this worktree's binaries and copies them into a private tree:
//!
//! ```text
//! <worktree>/bdd/.stage/
//!   bin/{straw,strawc,test_client}
//! ```
//!
//! The harness then prepends `bin/` to PATH for every in-namespace command,
//! so a run reads nothing under `/usr` at all.
//!
//! Staged binaries are *copies*, not symlinks into `target/`: cargo rewrites
//! `target/release/straw` in place, so a rebuild in the same worktree would
//! otherwise swap the binary out from under a run already in flight. Copying
//! pins the whole toolchain for the duration.
//!
//! Resolution order:
//!   1. `$STRAW_BDD_PREFIX`, if set and non-empty
//!   2. `<bdd crate>/.stage`, if it exists
//!   3. nothing — fall back to the host PATH, so a bare
//!      `cargo test -p bdd --test cucumber` still runs against an installed
//!      straw.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Staging root for this worktree. Baked at compile time from the `bdd`
/// crate's own directory, so a test binary built in worktree A can never
/// pick up worktree B's stage no matter where it is invoked from.
const STAGE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/.stage");

/// PATH tail appended after the staged `bin/`. Deliberately a fixed list
/// rather than the harness process's own PATH: the commands run as root
/// under `sudo`, which would normally confine them to `secure_path`, and
/// splicing the invoking user's PATH into a root command would both widen
/// that and make resolution differ from machine to machine.
const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Binaries a complete stage holds. `straw` and `strawc` are the two halves
/// of a tunnel; `test_client` drives the data plane without a TUN device.
pub const STAGE_BINS: [&str; 3] = ["straw", "strawc", "test_client"];

/// A resolved staging prefix: binaries under `bin/`.
#[derive(Debug, Clone)]
pub struct Prefix {
    root: PathBuf,
}

impl Prefix {
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory holding the staged binaries.
    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// `PATH=…` assignment to hand to `env` ahead of an in-namespace
    /// command, so `straw` / `strawc` resolve to this worktree's copies
    /// while system tools (`ip`, `ping`, `curl`) keep resolving as before.
    pub fn path_env(&self) -> String {
        format!("PATH={}:{}", self.bin_dir().display(), SYSTEM_PATH)
    }
}

/// The staging prefix for this run, or `None` when the harness should use
/// whatever is on the host PATH.
///
/// Resolved once per process. Panics if a prefix is present but incomplete —
/// a half-populated stage would otherwise silently fall through to `/usr`,
/// which is the failure mode staging exists to prevent.
pub fn prefix() -> Option<&'static Prefix> {
    static PREFIX: OnceLock<Option<Prefix>> = OnceLock::new();
    PREFIX.get_or_init(resolve).as_ref()
}

fn resolve() -> Option<Prefix> {
    if let Ok(raw) = std::env::var("STRAW_BDD_PREFIX")
        && !raw.trim().is_empty()
    {
        return Some(check(PathBuf::from(raw.trim()), "$STRAW_BDD_PREFIX"));
    }

    let stage = PathBuf::from(STAGE_DIR);
    if !stage.exists() {
        return None;
    }
    Some(check(stage, "the staged toolchain"))
}

/// Reject a prefix that is missing any binary. `make stage` builds into a
/// scratch directory and renames it into place, so an incomplete `.stage`
/// means an interrupted or hand-edited stage rather than a race — and the
/// only safe response is to say so instead of quietly testing `/usr`.
fn check(root: PathBuf, what: &str) -> Prefix {
    let prefix = Prefix { root };
    for bin in STAGE_BINS {
        let path = prefix.bin_dir().join(bin);
        assert!(
            path.is_file(),
            "{what} at {} is incomplete (missing {}); re-run `make -C bdd stage`",
            prefix.root.display(),
            path.display(),
        );
    }
    prefix
}

/// One-line description of the resolved toolchain, printed in the run
/// header. A run that fails for a stale-binary reason should be able to
/// prove it from its own log.
pub fn describe() -> String {
    match prefix() {
        Some(p) => {
            let straw = p.bin_dir().join("straw");
            let size = std::fs::metadata(&straw).map(|m| m.len()).unwrap_or(0);
            format!(
                "toolchain: staged at {} (straw {size} bytes)",
                p.root().display()
            )
        }
        None => {
            "toolchain: host PATH — run `make -C bdd stage` to isolate this worktree".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_dir_sits_under_the_prefix() {
        let p = Prefix {
            root: PathBuf::from("/w/bdd/.stage"),
        };
        assert_eq!(p.bin_dir(), PathBuf::from("/w/bdd/.stage/bin"));
    }

    #[test]
    fn path_env_puts_the_stage_first() {
        let p = Prefix {
            root: PathBuf::from("/w/bdd/.stage"),
        };
        assert_eq!(
            p.path_env(),
            format!("PATH=/w/bdd/.stage/bin:{}", SYSTEM_PATH)
        );
    }
}
