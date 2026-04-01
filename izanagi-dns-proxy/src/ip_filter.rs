//! DNS リバインディング対策用の IP アドレスフィルタ。
//!
//! upstream DNS 応答に含まれる A/AAAA レコードがプライベート/ループバック/
//! リンクローカルアドレスでないことを検証する。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP アドレスがプライベート・ループバック・リンクローカル等の
/// 内部ネットワークアドレスかどうかを判定する。
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()   // 169.254.0.0/16
        || ip.is_unspecified()  // 0.0.0.0
        || ip.is_broadcast()    // 255.255.255.255
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    // IPv4-mapped IPv6 アドレス (::ffff:x.x.x.x) をチェック
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(v4);
    }

    ip.is_loopback()            // ::1
        || ip.is_unspecified()  // ::
        // fe80::/10 (link-local)
        || (ip.segments()[0] & 0xffc0) == 0xfe80
        // fc00::/7 (unique local address)
        || (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv4() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));
        assert!(is_private_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn public_ipv4() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn private_ipv6() {
        assert!(is_private_ip("::1".parse().unwrap()));
        assert!(is_private_ip("::".parse().unwrap()));
        assert!(is_private_ip("fe80::1".parse().unwrap()));
        assert!(is_private_ip("fc00::1".parse().unwrap()));
        assert!(is_private_ip("fd12::1".parse().unwrap()));
    }

    #[test]
    fn public_ipv6() {
        assert!(!is_private_ip("2001:db8::1".parse().unwrap()));
        assert!(!is_private_ip("2607:f8b0:4004::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 は IPv4-mapped IPv6 でプライベート
        assert!(is_private_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:192.168.1.1".parse().unwrap()));
        // ::ffff:8.8.8.8 はパブリック
        assert!(!is_private_ip("::ffff:8.8.8.8".parse().unwrap()));
    }
}
