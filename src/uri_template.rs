use std::net::IpAddr;

use crate::error::ProxyError;

/// Parsed scope from the CONNECT-IP request URI template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestScope {
    /// Target host/prefix or None for wildcard (*).
    pub target: Option<Target>,
    /// IP protocol number or None for wildcard (*).
    pub ip_proto: Option<u8>,
}

/// The target component of a CONNECT-IP URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Hostname(String),
    Prefix(IpAddr, u8),
}

const PATH_PREFIX: &str = "/.well-known/masque/ip/";

/// Parse a CONNECT-IP request path into a `RequestScope`.
///
/// Expected format: `/.well-known/masque/ip/{target}/{ipproto}/`
///
/// The `{target}` field is either `*` (wildcard), an IP address with optional
/// prefix length (percent-encoded `/` as `%2F`), or a hostname.
///
/// The `{ipproto}` field is either `*` (wildcard) or a decimal protocol number.
pub fn parse_connect_ip_path(path: &str) -> Result<RequestScope, ProxyError> {
    let rest = path
        .strip_prefix(PATH_PREFIX)
        .ok_or_else(|| ProxyError::InvalidRequest(format!("path must start with {PATH_PREFIX}")))?;

    // Split remaining into segments; expect exactly "{target}/{ipproto}/"
    // or "{target}/{ipproto}" (trailing slash optional).
    let rest = rest.strip_suffix('/').unwrap_or(rest);

    let (target_raw, ipproto_raw) = rest
        .rsplit_once('/')
        .ok_or_else(|| ProxyError::InvalidRequest("expected {target}/{ipproto}".to_string()))?;

    if target_raw.is_empty() {
        return Err(ProxyError::InvalidRequest(
            "target must not be empty".to_string(),
        ));
    }
    if ipproto_raw.is_empty() {
        return Err(ProxyError::InvalidRequest(
            "ipproto must not be empty".to_string(),
        ));
    }

    let target = parse_target(target_raw)?;
    let ip_proto = parse_ipproto(ipproto_raw)?;

    Ok(RequestScope { target, ip_proto })
}

fn parse_target(raw: &str) -> Result<Option<Target>, ProxyError> {
    if raw == "*" {
        return Ok(None);
    }

    // Percent-decode %2F → /  and %25 → % for prefix notation
    let decoded = percent_decode(raw);

    // Try to parse as IP/prefix (e.g. "192.168.1.0/24")
    if let Some((ip_str, prefix_str)) = decoded.split_once('/') {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| ProxyError::InvalidRequest(format!("invalid IP in target: {e}")))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|e| ProxyError::InvalidRequest(format!("invalid prefix length: {e}")))?;

        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(ProxyError::InvalidRequest(format!(
                "prefix length {prefix} exceeds maximum {max_prefix}"
            )));
        }

        return Ok(Some(Target::Prefix(ip, prefix)));
    }

    // Try to parse as bare IP address (no prefix)
    if let Ok(ip) = decoded.parse::<IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return Ok(Some(Target::Prefix(ip, prefix)));
    }

    // Otherwise treat as hostname
    Ok(Some(Target::Hostname(decoded)))
}

fn parse_ipproto(raw: &str) -> Result<Option<u8>, ProxyError> {
    if raw == "*" {
        return Ok(None);
    }

    let proto: u8 = raw
        .parse()
        .map_err(|e| ProxyError::InvalidRequest(format!("invalid ipproto: {e}")))?;

    Ok(Some(proto))
}

/// Simple percent-decoding for URI template values.
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2
                && let Ok(byte) = u8::from_str_radix(&hex, 16)
            {
                result.push(byte as char);
                continue;
            }
            // Malformed percent-encoding, pass through
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_wildcard_both() {
        let scope = parse_connect_ip_path("/.well-known/masque/ip/*/*/").unwrap();
        assert_eq!(scope.target, None);
        assert_eq!(scope.ip_proto, None);
    }

    #[test]
    fn test_wildcard_no_trailing_slash() {
        let scope = parse_connect_ip_path("/.well-known/masque/ip/*/*").unwrap();
        assert_eq!(scope.target, None);
        assert_eq!(scope.ip_proto, None);
    }

    #[test]
    fn test_specific_ip_and_protocol() {
        let scope =
            parse_connect_ip_path("/.well-known/masque/ip/192.168.1.1/6/").unwrap();
        assert_eq!(
            scope.target,
            Some(Target::Prefix(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 32))
        );
        assert_eq!(scope.ip_proto, Some(6));
    }

    #[test]
    fn test_ip_prefix_percent_encoded() {
        let scope =
            parse_connect_ip_path("/.well-known/masque/ip/192.168.1.0%2F24/0/").unwrap();
        assert_eq!(
            scope.target,
            Some(Target::Prefix(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24))
        );
        assert_eq!(scope.ip_proto, Some(0));
    }

    #[test]
    fn test_ipv6_target() {
        let scope =
            parse_connect_ip_path("/.well-known/masque/ip/2001%3Adb8%3A%3A1/17/").unwrap();
        assert_eq!(
            scope.target,
            Some(Target::Prefix(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                128
            ))
        );
        assert_eq!(scope.ip_proto, Some(17));
    }

    #[test]
    fn test_ipv6_prefix_percent_encoded() {
        let scope =
            parse_connect_ip_path("/.well-known/masque/ip/2001%3Adb8%3A%3A%2F48/*/").unwrap();
        assert_eq!(
            scope.target,
            Some(Target::Prefix(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                48
            ))
        );
        assert_eq!(scope.ip_proto, None);
    }

    #[test]
    fn test_hostname_target() {
        let scope =
            parse_connect_ip_path("/.well-known/masque/ip/example.com/0/").unwrap();
        assert_eq!(
            scope.target,
            Some(Target::Hostname("example.com".to_string()))
        );
        assert_eq!(scope.ip_proto, Some(0));
    }

    #[test]
    fn test_hostname_wildcard_proto() {
        let scope =
            parse_connect_ip_path("/.well-known/masque/ip/vpn.example.org/*/").unwrap();
        assert_eq!(
            scope.target,
            Some(Target::Hostname("vpn.example.org".to_string()))
        );
        assert_eq!(scope.ip_proto, None);
    }

    #[test]
    fn test_invalid_prefix_too_short() {
        let result = parse_connect_ip_path("/.well-known/masque/ip/");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_wrong_prefix() {
        let result = parse_connect_ip_path("/wrong/path/*/*/");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_missing_ipproto() {
        let result = parse_connect_ip_path("/.well-known/masque/ip/*/");
        // This would parse as target="" ipproto="*" which fails on empty target
        // Actually: rest="*", no '/' found → error
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ipproto_not_a_number() {
        let result = parse_connect_ip_path("/.well-known/masque/ip/*/abc/");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ipproto_overflow() {
        let result = parse_connect_ip_path("/.well-known/masque/ip/*/256/");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_prefix_length_v4() {
        let result = parse_connect_ip_path("/.well-known/masque/ip/10.0.0.0%2F33/*/");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_prefix_length_v6() {
        let result = parse_connect_ip_path("/.well-known/masque/ip/2001%3Adb8%3A%3A%2F129/*/");
        assert!(result.is_err());
    }

    #[test]
    fn test_protocol_zero_all() {
        let scope = parse_connect_ip_path("/.well-known/masque/ip/*/0/").unwrap();
        assert_eq!(scope.target, None);
        assert_eq!(scope.ip_proto, Some(0));
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("%3A"), ":");
        assert_eq!(percent_decode("no%change"), "no%change"); // malformed, passthrough
    }
}
