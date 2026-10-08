use std::path::{Path, PathBuf};

use anyhow::Result;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use izanagi::config::settings_path_for_pwd;

/// 出力パスを正規化する。
///
/// - 既存ディレクトリ → `izanagi.toml` を付加
/// - 末尾が `/` または `\` の未作成パス → `izanagi.toml` を付加
/// - それ以外（ファイルパス） → そのまま返す
fn normalize_output_path(p: &Path) -> PathBuf {
    let path_str = p.to_string_lossy();
    let looks_like_dir = p.is_dir() || path_str.ends_with('/') || path_str.ends_with('\\');
    if looks_like_dir {
        p.join("izanagi.toml")
    } else {
        p.to_path_buf()
    }
}

/// `izanagi init` — 対話形式で izanagi.toml を生成する。
///
/// `explicit_path` が `Some` の場合はそのパスに出力する（`-c` 指定時）。
/// `None` の場合は `settings_path_for_pwd()` で自動決定する。
pub fn cmd_init(explicit_path: Option<&PathBuf>) -> Result<u8> {
    let output = match explicit_path {
        Some(p) => normalize_output_path(p),
        None => settings_path_for_pwd()?,
    };

    println!("izanagi.toml を対話形式で生成します。");
    println!("出力先: {}\n", output.display());

    // --- Sandbox backend ---
    let backends = &["native", "qemu", "apple-container"];
    let backend_idx = Select::new()
        .with_prompt("Sandbox backend")
        .items(backends)
        .default(0)
        .interact()?;
    let backend = backends[backend_idx];

    // --- QEMU 設定 (backend=qemu の場合のみ) ---
    let qemu_section = if backend == "qemu" {
        let cpus: u32 = Input::new()
            .with_prompt("QEMU CPUs")
            .default(2)
            .interact_text()?;
        let memory: String = Input::new()
            .with_prompt("QEMU メモリ")
            .default("4G".to_string())
            .interact_text()?;
        let image: String = Input::new()
            .with_prompt("QEMU イメージ (\"default\" で組み込みイメージを使用)")
            .default("default".to_string())
            .interact_text()?;
        Some((cpus, memory, image))
    } else {
        None
    };

    // --- Tracer ---
    // backend に応じて適切なデフォルトを選択
    let tracers = &["auto", "none", "ebpf", "dtrace", "vm-agent"];
    let tracer_default = match backend {
        "qemu" => 4,            // vm-agent
        "apple-container" => 1, // none
        _ => 0,                 // auto
    };
    let tracer_idx = Select::new()
        .with_prompt("Tracer backend")
        .items(tracers)
        .default(tracer_default)
        .interact()?;
    let tracer = tracers[tracer_idx];

    // --- 認証 ---
    let require_auth = Confirm::new()
        .with_prompt("HMAC 認証を必須にしますか？ (シークレット設定が必要)")
        .default(false)
        .interact()?;

    // --- Share ---
    let share_paths: String = Input::new()
        .with_prompt("共有するホストパス (カンマ区切り)")
        .default(".".to_string())
        .interact_text()?;
    let mount_point: String = Input::new()
        .with_prompt("ゲスト側マウントポイント")
        .default("/workspace".to_string())
        .interact_text()?;

    // --- Monitor syscalls ---
    let syscall_options = &["file", "network", "process", "env"];
    let syscall_defaults = &[true, true, true, false];
    let selected_syscalls = MultiSelect::new()
        .with_prompt("監視する syscall カテゴリ (Space で選択/解除)")
        .items(syscall_options)
        .defaults(syscall_defaults)
        .interact()?;
    let syscalls: Vec<String> = selected_syscalls
        .iter()
        .map(|&i| syscall_options[i].to_string())
        .collect();

    // --- Detect: suspicious paths ---
    let use_default_paths = Confirm::new()
        .with_prompt("デフォルトの機密パス検知を使用しますか？")
        .default(true)
        .interact()?;

    let suspicious_paths: Vec<String> = if use_default_paths {
        [
            "/etc/passwd",
            "/etc/shadow",
            "~/.ssh/*",
            "~/.aws/*",
            "~/.gnupg/*",
            "~/.config/gh/*",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    } else {
        let input: String = Input::new()
            .with_prompt("検知する機密パス (カンマ区切り)")
            .default(String::new())
            .interact_text()?;
        input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // --- Detect: allowed hosts ---
    let allowed_hosts_input: String = Input::new()
        .with_prompt("許可するホスト (カンマ区切り、空でスキップ)")
        .default(String::new())
        .interact_text()?;
    let allowed_hosts: Vec<String> = allowed_hosts_input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // --- パケット検閲 (MITM) ---
    let enable_mitm = Confirm::new()
        .with_prompt("パケット検閲 (DNS プロキシ + HTTP キャプチャ) を有効にしますか？")
        .default(false)
        .interact()?;

    let mitm_config = if enable_mitm {
        let dns_listen: String = Input::new()
            .with_prompt("DNS プロキシのリッスンアドレス")
            .default("127.0.0.1:15353".to_string())
            .validate_with(|input: &String| -> Result<(), String> {
                input
                    .parse::<std::net::SocketAddr>()
                    .map(|_| ())
                    .map_err(|_| "無効なアドレスです (例: 127.0.0.1:15353)".to_string())
            })
            .interact_text()?;
        let http_listen: String = Input::new()
            .with_prompt("HTTP リッスンアドレス")
            .default("127.0.0.1:18080".to_string())
            .validate_with(|input: &String| -> Result<(), String> {
                input
                    .parse::<std::net::SocketAddr>()
                    .map(|_| ())
                    .map_err(|_| "無効なアドレスです (例: 127.0.0.1:18080)".to_string())
            })
            .interact_text()?;
        let https_listen: String = Input::new()
            .with_prompt("HTTPS (TLS MITM) リッスンアドレス")
            .default("127.0.0.1:18443".to_string())
            .validate_with(|input: &String| -> Result<(), String> {
                input
                    .parse::<std::net::SocketAddr>()
                    .map(|_| ())
                    .map_err(|_| "無効なアドレスです (例: 127.0.0.1:18443)".to_string())
            })
            .interact_text()?;
        let ca_cert_out: String = Input::new()
            .with_prompt("CA 証明書の出力先パス")
            .default("/tmp/izanagi-ca.pem".to_string())
            .interact_text()?;

        let mut secret_maps = Vec::new();
        println!("シークレットマッピング (DUMMY=REAL 形式、空行で終了):");
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

        Some(MitmConfig {
            dns_listen,
            http_listen,
            https_listen,
            ca_cert_out,
            secret_maps,
        })
    } else {
        None
    };

    // --- 上書き確認 ---
    if output.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} は既に存在します。上書きしますか？",
                output.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            println!("キャンセルしました。");
            return Ok(0);
        }
    }

    // --- TOML 生成 ---
    let toml = generate_toml(
        backend,
        qemu_section.as_ref(),
        tracer,
        require_auth,
        &share_paths,
        &mount_point,
        &syscalls,
        &suspicious_paths,
        &allowed_hosts,
        mitm_config.as_ref(),
    );

    // 親ディレクトリを作成 (パーミッション 0o700)
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    // ファイル書き込み (パーミッション 0o600)
    // OpenOptions + mode で新規作成時は 0o600 が適用される。
    // 既存ファイル上書き時はパーミッションが維持されるため、追加で set_permissions を呼ぶ。
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
            .open(&output)?;
        file.write_all(toml.as_bytes())?;
        // 既存ファイルの場合に備えてパーミッションを強制
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&output, &toml)?;
    }
    println!("\n{} を生成しました。", output.display());

    Ok(0)
}

/// ユーザー入力を TOML 文字列としてエスケープする。
/// `toml` クレートの Value::String シリアライズを利用して
/// `"`, `\`, 改行等を安全にエスケープする。
fn escape_toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// MITM (DNS プロキシ + HTTP キャプチャ) の設定値。
struct MitmConfig {
    dns_listen: String,
    http_listen: String,
    https_listen: String,
    ca_cert_out: String,
    secret_maps: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn generate_toml(
    backend: &str,
    qemu: Option<&(u32, String, String)>,
    tracer: &str,
    require_auth: bool,
    share_paths: &str,
    mount_point: &str,
    syscalls: &[String],
    suspicious_paths: &[String],
    allowed_hosts: &[String],
    mitm: Option<&MitmConfig>,
) -> String {
    let mut out = String::new();

    // [sandbox]
    out.push_str("[sandbox]\n");
    out.push_str(&format!("backend = {}\n", escape_toml_string(backend)));
    out.push_str(&format!("tracer = {}\n", escape_toml_string(tracer)));
    out.push_str(&format!("require_auth = {require_auth}\n"));

    // [sandbox.qemu]
    if let Some((cpus, memory, image)) = qemu {
        out.push_str("\n[sandbox.qemu]\n");
        out.push_str(&format!("cpus = {cpus}\n"));
        out.push_str(&format!("memory = {}\n", escape_toml_string(memory)));
        out.push_str(&format!("image = {}\n", escape_toml_string(image)));
    }

    // [share]
    out.push_str("\n[share]\n");
    let paths: Vec<String> = share_paths
        .split(',')
        .map(|s| escape_toml_string(s.trim()))
        .collect();
    out.push_str(&format!("paths = [{}]\n", paths.join(", ")));
    out.push_str(&format!(
        "mount_point = {}\n",
        escape_toml_string(mount_point)
    ));

    // [monitor]
    out.push_str("\n[monitor]\n");
    let sc: Vec<String> = syscalls.iter().map(|s| escape_toml_string(s)).collect();
    out.push_str(&format!("syscalls = [{}]\n", sc.join(", ")));

    // [detect]
    out.push_str("\n[detect]\n");
    if suspicious_paths.is_empty() {
        out.push_str("suspicious_paths = []\n");
    } else {
        out.push_str("suspicious_paths = [\n");
        for p in suspicious_paths {
            out.push_str(&format!("    {},\n", escape_toml_string(p)));
        }
        out.push_str("]\n");
    }
    if allowed_hosts.is_empty() {
        out.push_str("allowed_hosts = []\n");
    } else {
        out.push_str("allowed_hosts = [\n");
        for h in allowed_hosts {
            out.push_str(&format!("    {},\n", escape_toml_string(h)));
        }
        out.push_str("]\n");
    }

    // MITM セクション
    if let Some(m) = mitm {
        out.push_str("\n[dns_proxy]\n");
        out.push_str("enabled = true\n");
        out.push_str(&format!("listen = {}\n", escape_toml_string(&m.dns_listen)));

        out.push_str("\n[http_capture]\n");
        out.push_str("enabled = true\n");
        out.push_str(&format!(
            "listen_http = {}\n",
            escape_toml_string(&m.http_listen)
        ));
        out.push_str(&format!(
            "listen_https = {}\n",
            escape_toml_string(&m.https_listen)
        ));
        out.push_str(&format!(
            "ca_cert_out = {}\n",
            escape_toml_string(&m.ca_cert_out)
        ));
        if m.secret_maps.is_empty() {
            out.push_str("secret_maps = []\n");
        } else {
            out.push_str("secret_maps = [\n");
            for s in &m.secret_maps {
                out.push_str(&format!("    {},\n", escape_toml_string(s)));
            }
            out.push_str("]\n");
        }
    } else {
        out.push_str("\n# --- 高度な設定 (必要に応じてコメントを外してください) ---\n");
        out.push_str("\n# [dns_proxy]\n");
        out.push_str("# enabled = true\n");
        out.push_str("# listen = \"127.0.0.1:15353\"\n");
        out.push_str("\n# [http_capture]\n");
        out.push_str("# enabled = true\n");
        out.push_str("# listen_http = \"127.0.0.1:18080\"\n");
        out.push_str("# listen_https = \"127.0.0.1:18443\"\n");
        out.push_str("# ca_cert_out = \"/tmp/izanagi-ca.pem\"\n");
        out.push_str("# secret_maps = []\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_toml_default() {
        let toml = generate_toml(
            "native",
            None,
            "auto",
            false,
            ".",
            "/workspace",
            &["file".into(), "network".into(), "process".into()],
            &["/etc/passwd".into(), "~/.ssh/*".into()],
            &[],
            None,
        );
        assert!(toml.contains("backend = \"native\""));
        assert!(toml.contains("tracer = \"auto\""));
        assert!(toml.contains("paths = [\".\"]"));
        assert!(toml.contains("mount_point = \"/workspace\""));
        assert!(toml.contains("\"file\", \"network\", \"process\""));
        assert!(toml.contains("\"/etc/passwd\""));
        assert!(toml.contains("\"~/.ssh/*\""));
        assert!(toml.contains("allowed_hosts = []"));
        // TOML としてパース可能であることを確認
        let _: toml::Value = toml::from_str(&toml).expect("generated TOML should be valid");
    }

    #[test]
    fn generate_toml_with_qemu() {
        let toml = generate_toml(
            "qemu",
            Some(&(4, "8G".into(), "custom.qcow2".into())),
            "vm-agent",
            true,
            "src, tests",
            "/workspace",
            &["file".into()],
            &[],
            &["registry.npmjs.org".into()],
            None,
        );
        assert!(toml.contains("[sandbox.qemu]"));
        assert!(toml.contains("cpus = 4"));
        assert!(toml.contains("memory = \"8G\""));
        assert!(toml.contains("image = \"custom.qcow2\""));
        assert!(toml.contains("paths = [\"src\", \"tests\"]"));
        assert!(toml.contains("\"registry.npmjs.org\""));
        let _: toml::Value = toml::from_str(&toml).expect("generated TOML should be valid");
    }

    #[test]
    fn generate_toml_escapes_injection() {
        // ダブルクォート、バックスラッシュ、改行を含む入力でも
        // 有効な TOML が生成されることを確認
        let toml = generate_toml(
            "native",
            None,
            "auto",
            false,
            ".",
            "/workspace",
            &["file".into()],
            &["path/with\"quote".into()],
            &["evil.com\"\n[sandbox]\nbackend = \"native".into()],
            None,
        );
        // TOML としてパース可能であること（インジェクションが無効化されている）
        let config = izanagi::config::Config::from_toml(&toml)
            .expect("TOML with special chars should still be valid");
        // インジェクションで backend が上書きされていないこと
        assert_eq!(
            config.sandbox.backend,
            izanagi::config::SandboxBackend::Native,
            "injection must not overwrite backend"
        );
    }

    #[test]
    fn escape_toml_string_handles_special_chars() {
        // 特殊文字を含む入力が有効な TOML 文字列になること（ラウンドトリップ検証）
        for input in &[
            "hello",
            "a\"b",
            "a\\b",
            "line\nnewline",
            "tab\there",
            "\0",
            "a\\\"b",
        ] {
            let escaped = escape_toml_string(input);
            let toml_str = format!("key = {escaped}");
            let parsed: toml::Value =
                toml::from_str(&toml_str).expect("escaped string should be valid TOML");
            assert_eq!(parsed["key"].as_str().unwrap(), *input);
        }
    }

    #[test]
    fn generate_toml_deserializes_into_config() {
        use izanagi::config::Config;
        let toml = generate_toml(
            "native",
            None,
            "auto",
            false,
            ".",
            "/workspace",
            &["file".into(), "network".into()],
            &["/etc/passwd".into()],
            &["example.com".into()],
            None,
        );
        let _config =
            Config::from_toml(&toml).expect("generated TOML should deserialize into Config");
    }

    #[test]
    fn generate_toml_with_qemu_deserializes_into_config() {
        use izanagi::config::Config;
        let toml = generate_toml(
            "qemu",
            Some(&(4, "8G".into(), "default".into())),
            "vm-agent",
            true,
            "src, tests",
            "/workspace",
            &["file".into()],
            &[],
            &["registry.npmjs.org".into()],
            None,
        );
        let _config = Config::from_toml(&toml)
            .expect("generated TOML with qemu should deserialize into Config");
    }

    #[test]
    fn normalize_output_path_existing_dir() {
        // 既存ディレクトリには izanagi.toml が付加される
        let tmp = std::env::temp_dir();
        assert!(tmp.is_dir());
        let result = normalize_output_path(&tmp);
        assert_eq!(result, tmp.join("izanagi.toml"));
    }

    #[test]
    fn normalize_output_path_trailing_slash() {
        // 末尾スラッシュ付き未作成パスにも izanagi.toml が付加される
        let p = PathBuf::from("/nonexistent/dir/");
        let result = normalize_output_path(&p);
        assert_eq!(result, PathBuf::from("/nonexistent/dir/izanagi.toml"));

        // バックスラッシュでも同様 (Windows パス)
        let p2 = PathBuf::from("C:\\Users\\test\\");
        let result2 = normalize_output_path(&p2);
        assert!(
            result2.to_string_lossy().ends_with("izanagi.toml"),
            "backslash-terminated path should get izanagi.toml appended"
        );
    }

    #[test]
    fn normalize_output_path_file_path() {
        // ファイルパスはそのまま返る
        let p = PathBuf::from("/some/path/config.toml");
        let result = normalize_output_path(&p);
        assert_eq!(result, p);
    }
}
