//! Fallback for platforms with no interface-configuration backend yet.

use std::net::IpAddr;

use ipnet::IpNet;

use super::Cmd;
use crate::error::ProxyError;

fn unsupported() -> Cmd {
    Cmd::new("false", ["unsupported-platform".to_string()])
}

pub fn addr_cmd(_action: &str, _dev: &str, _addr: IpAddr, _prefix_len: u8) -> Cmd {
    unsupported()
}

pub fn route_cmd(_action: &str, _prefix: IpNet, _dev: &str) -> Cmd {
    unsupported()
}

pub fn pin_cmd(_action: &str, _proxy: IpAddr, _gateway: Option<IpAddr>, _dev: &str) -> Cmd {
    unsupported()
}

pub fn mtu_cmd(_dev: &str, _mtu: u16) -> Cmd {
    unsupported()
}

pub fn path_to(_dst: IpAddr) -> Result<(Option<IpAddr>, String), ProxyError> {
    Err(ProxyError::Config(
        "interface configuration is supported on Linux and macOS only".to_string(),
    ))
}
