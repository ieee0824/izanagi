use std::path::Path;

use anyhow::Context;
use dialoguer::{Confirm, Input};
use izanagi::config::{Config, DnsProxySection, HttpCaptureSection};

use super::ConfigAction;

pub fn cmd_config(action: ConfigAction, config: &Config, config_path: &Path) -> anyhow::Result<u8> {
    match action {
        ConfigAction::Show => {
            // secret_maps の REAL 側をマスクしてから出力
            let mut display_config = config.clone();
            if let Some(ref mut hc) = display_config.http_capture {
                hc.secret_maps = hc
                    .secret_maps
                    .iter()
                    .map(|m| {
                        if let Some(pos) = m.find('=') {
                            format!("{}=***", &m[..pos])
                        } else {
                            m.clone()
                        }
                    })
                    .collect();
            }
            let toml_str = toml::to_string_pretty(&display_config)
                .context("設定の TOML シリアライズに失敗")?;
            println!("{}", toml_str);
        }
        ConfigAction::Path => {
            unreachable!("path is handled before config loading");
        }
        ConfigAction::Mitm => {
            return cmd_config_mitm(config, config_path);
        }
    }
    Ok(0)
}

/// パケット検閲 (DNS プロキシ + HTTP キャプチャ) を対話的に設定する。
fn cmd_config_mitm(config: &Config, config_path: &Path) -> anyhow::Result<u8> {
    let mut config = config.clone();

    // DNS プロキシ設定
    let dns_enabled = Confirm::new()
        .with_prompt("DNS プロキシを有効にしますか？")
        .default(true)
        .interact()?;

    let dns_listen = if dns_enabled {
        let current = config
            .dns_proxy
            .as_ref()
            .map(|d| d.listen.clone())
            .unwrap_or_else(|| "127.0.0.1:15353".to_string());
        Input::new()
            .with_prompt("DNS プロキシのリッスンアドレス")
            .default(current)
            .validate_with(|input: &String| -> Result<(), String> {
                input
                    .parse::<std::net::SocketAddr>()
                    .map(|_| ())
                    .map_err(|_| "無効なアドレスです (例: 127.0.0.1:15353)".to_string())
            })
            .interact_text()?
    } else {
        "127.0.0.1:15353".to_string()
    };

    config.dns_proxy = Some(DnsProxySection {
        enabled: dns_enabled,
        listen: dns_listen,
    });

    // HTTP キャプチャ設定
    let http_enabled = Confirm::new()
        .with_prompt("HTTP キャプチャ (TLS MITM) を有効にしますか？")
        .default(true)
        .interact()?;

    if http_enabled {
        let current_http = config
            .http_capture
            .as_ref()
            .map(|h| h.listen_http.to_string())
            .unwrap_or_else(|| "127.0.0.1:18080".to_string());
        let listen_http_str: String = Input::new()
            .with_prompt("HTTP リッスンアドレス")
            .default(current_http)
            .interact_text()?;
        let listen_http: std::net::SocketAddr =
            listen_http_str.parse().context("無効なアドレスです")?;

        let current_https = config
            .http_capture
            .as_ref()
            .map(|h| h.listen_https.to_string())
            .unwrap_or_else(|| "127.0.0.1:18443".to_string());
        let listen_https_str: String = Input::new()
            .with_prompt("HTTPS (TLS MITM) リッスンアドレス")
            .default(current_https)
            .interact_text()?;
        let listen_https: std::net::SocketAddr =
            listen_https_str.parse().context("無効なアドレスです")?;

        let current_ca = config
            .http_capture
            .as_ref()
            .and_then(|h| h.ca_cert_out.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "/tmp/izanagi-ca.pem".to_string());
        let ca_cert_out: String = Input::new()
            .with_prompt("CA 証明書の出力先パス")
            .default(current_ca)
            .interact_text()?;

        // シークレットマッピング
        let mut secret_maps: Vec<String> = config
            .http_capture
            .as_ref()
            .map(|h| h.secret_maps.clone())
            .unwrap_or_default();

        if !secret_maps.is_empty() {
            println!("現在のシークレットマッピング:");
            for m in &secret_maps {
                if let Some(pos) = m.find('=') {
                    println!("  {}=***", &m[..pos]);
                } else {
                    println!("  {}", m);
                }
            }
        }

        println!("シークレットマッピングを追加 (DUMMY=REAL 形式、空行で終了):");
        loop {
            let input: String = Input::new()
                .with_prompt("追加するマッピング")
                .allow_empty(true)
                .interact_text()?;
            if input.is_empty() {
                break;
            }
            if !input.contains('=') {
                eprintln!("形式が正しくありません。DUMMY=REAL の形式で入力してください。");
                continue;
            }
            secret_maps.push(input);
        }

        config.http_capture = Some(HttpCaptureSection {
            enabled: true,
            listen_http,
            listen_https,
            ca_cert_out: Some(ca_cert_out.into()),
            secret_maps,
        });
    } else {
        config.http_capture = Some(HttpCaptureSection {
            enabled: false,
            listen_http: "127.0.0.1:18080".parse().unwrap(),
            listen_https: "127.0.0.1:18443".parse().unwrap(),
            ca_cert_out: None,
            secret_maps: vec![],
        });
    }

    // 許可するホスト
    let current_hosts = config.detect.allowed_hosts.join(", ");
    let hosts_input: String = Input::new()
        .with_prompt("許可するホスト (カンマ区切り)")
        .default(current_hosts)
        .allow_empty(true)
        .interact_text()?;
    config.detect.allowed_hosts = hosts_input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // 設定ファイルに書き戻し
    write_config(config_path, &config)?;

    println!("設定を保存しました: {}", config_path.display());
    Ok(0)
}

/// Config を TOML として設定ファイルに書き出す。
/// パーミッションは作成時に 0o600 を設定し、TOCTOU を防止する。
fn write_config(path: &Path, config: &Config) -> anyhow::Result<()> {
    let toml_str = toml::to_string_pretty(config).context("設定の TOML シリアライズに失敗")?;

    if let Some(parent) = path.parent() {
        let parent_existed = parent.exists();
        std::fs::create_dir_all(parent)
            .with_context(|| format!("ディレクトリの作成に失敗: {:?}", parent))?;
        #[cfg(unix)]
        if !parent_existed {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("設定ファイルの書き込みに失敗: {:?}", path))?;
        file.write_all(toml_str.as_bytes())?;
        // 既存ファイルの場合に備えてパーミッションを強制
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, toml_str)
            .with_context(|| format!("設定ファイルの書き込みに失敗: {:?}", path))?;
    }

    Ok(())
}
