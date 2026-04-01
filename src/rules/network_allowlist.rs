use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use crate::detector::{AlertLevel, Rule, RuleMatch};
use crate::event::{Syscall, SyscallArg, SyscallEvent};

/// connect, sendto の宛先が allowed_hosts に含まれない場合に検知する。
///
/// IP アドレスは即座に `HashSet<IpAddr>` に格納する。
/// ドメイン名は `Vec<String>` として保持し、`resolve_hosts()` で非同期に解決できる。
/// `check()` 時は解決済み IP セットのみで許可判定する。未解決ドメインがある場合は許可されず警告対象となる。
pub struct NetworkAllowlistRule {
    allowed_ips: HashSet<IpAddr>,
    /// 未解決のドメイン名
    unresolved_hosts: Vec<String>,
    /// allowed_hosts が空（全通信を警告するモード）かどうか
    warn_all: bool,
}

impl NetworkAllowlistRule {
    pub fn new(allowed_hosts: &[String]) -> Self {
        let warn_all = allowed_hosts.is_empty();
        let mut allowed_ips = HashSet::new();
        let mut unresolved_hosts = Vec::new();

        for host in allowed_hosts {
            // まず IP アドレスとして直接パースを試みる
            if let Ok(ip) = host.parse::<IpAddr>() {
                allowed_ips.insert(ip);
                continue;
            }

            // IP:port 形式を試みる
            if let Ok(addr) = host.parse::<SocketAddr>() {
                allowed_ips.insert(addr.ip());
                continue;
            }

            // ドメイン名として保持（DNS 解決は行わない）
            unresolved_hosts.push(host.clone());
        }

        Self {
            allowed_ips,
            unresolved_hosts,
            warn_all,
        }
    }

    /// 未解決のドメイン名を DNS 解決し、結果を `allowed_ips` に追加する。
    /// 解決に成功したドメインは `unresolved_hosts` から除去される。
    /// 解決に失敗したドメインは `unresolved_hosts` に残り、`check()` 時はブロック扱いとなる。
    ///
    /// 警告が不要な場合はこちらを使用する。警告を取得したい場合は
    /// `resolve_hosts_with_warnings` を使用すること。
    pub fn resolve_hosts(&mut self) {
        let _warnings = self.resolve_hosts_with_warnings();
    }

    /// `resolve_hosts` と同じだが、DNS 解決失敗時の警告メッセージも返す。
    pub fn resolve_hosts_with_warnings(&mut self) -> Vec<String> {
        use std::net::ToSocketAddrs;

        let mut still_unresolved = Vec::new();
        let mut warnings = Vec::new();
        for host in &self.unresolved_hosts {
            match (host.as_str(), 0u16).to_socket_addrs() {
                Ok(addrs) => {
                    for addr in addrs {
                        self.allowed_ips.insert(addr.ip());
                    }
                }
                Err(e) => {
                    warnings.push(format!(
                        "警告: ホスト \"{}\" の DNS 解決に失敗しました: {}",
                        host, e
                    ));
                    still_unresolved.push(host.clone());
                }
            }
        }
        self.unresolved_hosts = still_unresolved;
        warnings
    }

    /// DNS 解決にタイムアウトを設定した非同期版。
    /// 全ホストの DNS 解決を `JoinSet` で並行実行し、全体に対して1つのタイムアウトをかける。
    /// タイムアウト内に完了しなかったホストは未解決として残る。
    pub async fn resolve_hosts_with_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Vec<String> {
        let hosts = std::mem::take(&mut self.unresolved_hosts);
        if hosts.is_empty() {
            return Vec::new();
        }

        // 全ホストの DNS 解決を並行に spawn
        let mut join_set = tokio::task::JoinSet::new();
        for host in &hosts {
            let host_clone = host.clone();
            join_set.spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                let result = (host_clone.as_str(), 0u16).to_socket_addrs();
                (host_clone, result)
            });
        }

        let mut resolved_hosts = std::collections::HashSet::new();
        let mut still_unresolved = Vec::new();
        let mut warnings = Vec::new();

        // 全体に対して1つのタイムアウト
        let timed_out = tokio::time::timeout(timeout, async {
            while let Some(res) = join_set.join_next().await {
                match res {
                    Ok((host, Ok(addrs))) => {
                        for addr in addrs {
                            self.allowed_ips.insert(addr.ip());
                        }
                        resolved_hosts.insert(host);
                    }
                    Ok((host, Err(e))) => {
                        warnings.push(format!(
                            "警告: ホスト \"{}\" の DNS 解決に失敗しました: {}",
                            host, e
                        ));
                        still_unresolved.push(host);
                    }
                    Err(e) => {
                        warnings.push(format!("警告: DNS 解決タスクがパニックしました: {}", e));
                    }
                }
            }
        })
        .await
        .is_err();

        if timed_out {
            join_set.abort_all();
            // 注意: abort_all() は spawn_blocking タスクを実際には停止できない（tokio の制約）。
            // blocking スレッドプール内の DNS 解決は OS のタイムアウトまで継続する。
            // 大量のホストが未解決の場合、blocking スレッドプール (デフォルト 512 スレッド) が
            // 枯渇するリスクがあるが、allowed_hosts の数は通常数十件以下のため実用上問題ない。
            // (#112)
            // タイムアウトで処理できなかったホストを未解決に追加
            let mut processed = std::collections::HashSet::new();
            for s in &resolved_hosts {
                processed.insert(s.as_str());
            }
            for s in &still_unresolved {
                processed.insert(s.as_str());
            }
            let mut timed_out_hosts = Vec::new();
            for host in &hosts {
                if !processed.contains(host.as_str()) {
                    warnings.push(format!(
                        "警告: ホスト \"{}\" の DNS 解決がタイムアウトしました ({:?})",
                        host, timeout
                    ));
                    timed_out_hosts.push(host.clone());
                }
            }
            still_unresolved.extend(timed_out_hosts);
        }

        self.unresolved_hosts = still_unresolved;
        warnings
    }

    /// 指定アドレスが許可リストに含まれるか判定する。
    /// 未解決ドメインがある場合は許可されず警告対象となる。
    /// `resolve_hosts()` / `resolve_hosts_with_timeout()` を事前に呼んで解決しておくこと。
    fn is_allowed(&self, addr: &SocketAddr) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WARNED: AtomicBool = AtomicBool::new(false);

        if self.warn_all {
            return false;
        }
        if !self.unresolved_hosts.is_empty()
            && !self.allowed_ips.contains(&addr.ip())
            && !WARNED.swap(true, Ordering::Relaxed)
        {
            eprintln!(
                "警告: 未解決ドメインが {} 件残っています（{:?}）。resolve_hosts() を事前に呼んでください。",
                self.unresolved_hosts.len(),
                self.unresolved_hosts,
            );
        }
        self.allowed_ips.contains(&addr.ip())
    }
}

impl Rule for NetworkAllowlistRule {
    fn name(&self) -> &str {
        "network-allowlist"
    }

    fn check(&self, event: &SyscallEvent) -> Option<RuleMatch> {
        match event.syscall {
            Syscall::Connect | Syscall::SendTo => {}
            _ => return None,
        }

        for arg in &event.args {
            if let SyscallArg::Addr(addr) = arg
                && !self.is_allowed(addr)
            {
                return Some(RuleMatch {
                    level: AlertLevel::Warn,
                    message: format!("Network access to non-allowlisted host: {}", addr),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::detector::{AlertLevel, Rule};
    use crate::event::{Syscall, SyscallArg, SyscallEvent, SyscallResult};

    use super::*;

    fn make_event(syscall: Syscall, args: Vec<SyscallArg>) -> Arc<SyscallEvent> {
        Arc::new(SyscallEvent {
            timestamp: SystemTime::now(),
            pid: 1234,
            tgid: 0,
            process_name: "test".into(),
            syscall,
            args: args.into(),
            result: SyscallResult::Ok(0),
        })
    }

    #[test]
    fn blocks_unknown_host() {
        let rule = NetworkAllowlistRule::new(&["10.0.0.1".to_string()]);
        let event = make_event(
            Syscall::Connect,
            vec![SyscallArg::Addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                443,
            ))],
        );
        let m = rule.check(&event);
        assert!(m.is_some());
        assert_eq!(m.unwrap().level, AlertLevel::Warn);
    }

    #[test]
    fn allows_known_host() {
        let rule = NetworkAllowlistRule::new(&["192.168.1.1".to_string()]);
        let event = make_event(
            Syscall::Connect,
            vec![SyscallArg::Addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                443,
            ))],
        );
        assert!(rule.check(&event).is_none());
    }

    #[test]
    fn empty_warns_all() {
        let rule = NetworkAllowlistRule::new(&[]);
        let event = make_event(
            Syscall::Connect,
            vec![SyscallArg::Addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                53,
            ))],
        );
        assert!(
            rule.check(&event).is_some(),
            "空の allowed_hosts では全通信を警告すべき"
        );
    }

    #[test]
    fn ignores_non_network_syscall() {
        let rule = NetworkAllowlistRule::new(&["10.0.0.1".to_string()]);
        let event = make_event(
            Syscall::Open,
            vec![SyscallArg::Addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                443,
            ))],
        );
        assert!(rule.check(&event).is_none());
    }
}
