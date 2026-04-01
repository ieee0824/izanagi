use std::collections::HashSet;
use std::net::IpAddr;

/// allowed_hosts に基づくドメインマッチャー。
/// 完全一致とワイルドカード（`*.example.com`）をサポートする。
pub struct DomainAllowlist {
    /// 完全一致ドメイン（小文字正規化済み）
    exact: HashSet<String>,
    /// ワイルドカードのサフィックス（`*.foo.com` → `foo.com`）
    wildcard_suffixes: Vec<String>,
}

impl DomainAllowlist {
    /// `allowed_hosts` から allowlist を構築する。
    /// IP アドレスのエントリは無視する（DNS ドメインではないため）。
    pub fn new(allowed_hosts: &[String]) -> Self {
        let mut exact = HashSet::new();
        let mut wildcard_suffixes = Vec::new();

        for host in allowed_hosts {
            let host = host.trim();
            if host.is_empty() {
                continue;
            }

            // IP アドレスはスキップ
            if host.parse::<IpAddr>().is_ok() {
                continue;
            }
            // IP:port 形式もスキップ
            if host.contains(':') && host.split(':').next().is_some_and(|ip| ip.parse::<IpAddr>().is_ok()) {
                continue;
            }

            if let Some(suffix) = host.strip_prefix("*.") {
                let suffix = normalize_domain(suffix);
                if !suffix.is_empty() {
                    wildcard_suffixes.push(suffix);
                }
            } else {
                let domain = normalize_domain(host);
                if !domain.is_empty() {
                    exact.insert(domain);
                }
            }
        }

        Self {
            exact,
            wildcard_suffixes,
        }
    }

    /// ドメインが許可リストに含まれるか判定する。
    /// allowed_hosts が空の場合はすべて拒否（deny-by-default）。
    pub fn is_allowed(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return false;
        }

        // 完全一致
        if self.exact.contains(&domain) {
            return true;
        }

        // ワイルドカード: domain が suffix と一致、または .suffix で終わる
        for suffix in &self.wildcard_suffixes {
            if domain == *suffix || domain.ends_with(&format!(".{}", suffix)) {
                return true;
            }
        }

        false
    }

    /// 許可リストが空かどうか（全拒否モード）。
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard_suffixes.is_empty()
    }
}

/// ドメイン名を正規化する: 小文字化 + 末尾ドット除去。
fn normalize_domain(domain: &str) -> String {
    let d = domain.to_ascii_lowercase();
    d.strip_suffix('.').unwrap_or(&d).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let al = DomainAllowlist::new(&[
            "registry.npmjs.org".to_string(),
            "github.com".to_string(),
        ]);
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(al.is_allowed("github.com"));
        assert!(!al.is_allowed("evil.example.com"));
    }

    #[test]
    fn case_insensitive() {
        let al = DomainAllowlist::new(&["GitHub.COM".to_string()]);
        assert!(al.is_allowed("github.com"));
        assert!(al.is_allowed("GITHUB.COM"));
        assert!(al.is_allowed("GitHub.Com"));
    }

    #[test]
    fn trailing_dot() {
        let al = DomainAllowlist::new(&["example.com.".to_string()]);
        assert!(al.is_allowed("example.com"));
        assert!(al.is_allowed("example.com."));
    }

    #[test]
    fn wildcard_match() {
        let al = DomainAllowlist::new(&["*.npmjs.org".to_string()]);
        assert!(al.is_allowed("registry.npmjs.org"));
        assert!(al.is_allowed("www.registry.npmjs.org"));
        // ワイルドカードのルート自体もマッチする
        assert!(al.is_allowed("npmjs.org"));
        assert!(!al.is_allowed("evil.com"));
    }

    #[test]
    fn wildcard_does_not_partial_match() {
        let al = DomainAllowlist::new(&["*.example.com".to_string()]);
        // "notexample.com" は ".example.com" で終わらないのでマッチしない
        assert!(!al.is_allowed("notexample.com"));
    }

    #[test]
    fn ip_addresses_ignored() {
        let al = DomainAllowlist::new(&[
            "192.168.1.1".to_string(),
            "::1".to_string(),
            "10.0.0.1:8080".to_string(),
            "example.com".to_string(),
        ]);
        // IP はスキップされるので exact には example.com のみ
        assert!(al.is_allowed("example.com"));
        assert!(!al.is_allowed("192.168.1.1"));
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let al = DomainAllowlist::new(&[]);
        assert!(al.is_empty());
        assert!(!al.is_allowed("anything.com"));
    }

    #[test]
    fn empty_and_whitespace_entries_skipped() {
        let al = DomainAllowlist::new(&[
            "".to_string(),
            "  ".to_string(),
            "example.com".to_string(),
        ]);
        assert!(al.is_allowed("example.com"));
        assert!(!al.is_allowed(""));
    }

    #[test]
    fn mixed_exact_and_wildcard() {
        let al = DomainAllowlist::new(&[
            "specific.host.com".to_string(),
            "*.cdn.example.com".to_string(),
        ]);
        assert!(al.is_allowed("specific.host.com"));
        assert!(al.is_allowed("img.cdn.example.com"));
        assert!(al.is_allowed("cdn.example.com"));
        assert!(!al.is_allowed("other.host.com"));
        assert!(!al.is_allowed("example.com"));
    }
}
