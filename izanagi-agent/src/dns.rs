use std::net::SocketAddr;

static UPSTREAM: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

pub fn status() -> Option<String> {
    let upstream = *UPSTREAM.get()?;
    let expected = izanagi::guest_dns::resolver_config(upstream);
    let nss_ready = match std::fs::read_to_string("/etc/nsswitch.conf") {
        Ok(content) => hosts_use_dns(&content),
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    };
    (nss_ready && std::fs::read_to_string("/etc/resolv.conf").ok()? == expected)
        .then(|| upstream.to_string())
}

pub async fn start() -> anyhow::Result<Option<tokio::task::JoinHandle<anyhow::Result<()>>>> {
    let endpoint =
        match std::fs::read_to_string("/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.dns/raw") {
            Ok(value) => Some(value.trim_end_matches('\0').trim().to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::env::var("IZANAGI_DNS_PROXY").ok()
            }
            Err(error) => return Err(error.into()),
        };
    let Some(endpoint) = endpoint else {
        return Ok(None);
    };
    let upstream: SocketAddr = endpoint.parse()?;
    let relay = izanagi::guest_dns::DnsRelay::bind("127.0.0.1:53".parse()?, upstream).await?;
    configure_resolver(
        std::path::Path::new("/etc/resolv.conf"),
        std::path::Path::new("/etc/nsswitch.conf"),
        upstream,
    )?;
    eprintln!("guest DNS relay ready: 127.0.0.1:53 -> {upstream}");
    let _ = UPSTREAM.set(upstream);
    Ok(Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        let serving = relay.run();
        tokio::pin!(serving);
        loop {
            tokio::select! {
                result = &mut serving => return result,
                _ = tick.tick() => {
                    if status().is_none() {
                        anyhow::bail!("guest resolver changed while DNS filtering was enabled");
                    }
                }
            }
        }
    })))
}

fn hosts_use_dns(content: &str) -> bool {
    let entries: Vec<_> = content
        .lines()
        .filter(|line| line.trim_start().starts_with("hosts:"))
        .collect();
    entries.len() == 1
        && entries[0].split_whitespace().collect::<Vec<_>>() == ["hosts:", "files", "dns"]
}

fn configure_resolver(
    resolv: &std::path::Path,
    nss: &std::path::Path,
    upstream: SocketAddr,
) -> anyhow::Result<()> {
    // QEMU images may symlink to systemd-resolved's DHCP-managed file. Detach
    // that link; retain regular files because container runtimes bind-mount them.
    if std::fs::symlink_metadata(resolv)?.file_type().is_symlink() {
        std::fs::remove_file(resolv)?;
    }
    std::fs::write(resolv, izanagi::guest_dns::resolver_config(upstream))?;
    match std::fs::read_to_string(nss) {
        Ok(content) => {
            let mut lines: Vec<_> = content
                .lines()
                .filter(|line| !line.trim_start().starts_with("hosts:"))
                .collect();
            lines.push("hosts: files dns");
            std::fs::write(nss, lines.join("\n") + "\n")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {} // musl/default libc uses resolv.conf
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_detaches_managed_resolver_and_removes_nss_bypass_without_changing_accounts() {
        let directory =
            std::env::temp_dir().join(format!("izanagi-agent-dns-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let managed = directory.join("systemd-resolv.conf");
        let resolv = directory.join("resolv.conf");
        let nss = directory.join("nsswitch.conf");
        std::fs::write(&managed, "nameserver 10.0.2.3\n").unwrap();
        std::os::unix::fs::symlink(&managed, &resolv).unwrap();
        std::fs::write(
            &nss,
            "passwd: files systemd\nhosts: files resolve [!UNAVAIL=return] dns\nnetworks: files\n",
        )
        .unwrap();
        let upstream = "10.0.2.2:15353".parse().unwrap();
        configure_resolver(&resolv, &nss, upstream).unwrap();
        assert!(!resolv.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_to_string(&managed).unwrap(),
            "nameserver 10.0.2.3\n"
        );
        assert_eq!(
            std::fs::read_to_string(&resolv).unwrap(),
            izanagi::guest_dns::resolver_config(upstream)
        );
        let content = std::fs::read_to_string(nss).unwrap();
        assert!(hosts_use_dns(&content));
        assert!(content.contains("passwd: files systemd\n"));
        assert!(content.contains("networks: files\n"));
        assert!(!hosts_use_dns("hosts: files resolve dns\n"));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
