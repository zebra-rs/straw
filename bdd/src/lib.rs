//! BDD harness for straw: cucumber scenarios driven against real Linux
//! network namespaces.
//!
//! Ported from the zebra-rs BDD framework. The pieces here are the parts
//! that are not about any one product: namespace and veth topology
//! management ([`netns`]), per-worktree binary staging ([`toolchain`]), and
//! the feature-tag scoping every scenario names its resources from
//! ([`feature_tag`]). The straw-specific steps live in
//! `tests/cucumber.rs`.

pub mod feature_tag;
pub mod netns;
pub mod toolchain;
