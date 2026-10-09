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

    let backend = prompt_backend()?;
    let qemu_section = prompt_qemu(backend)?;
    let tracer = prompt_tracer(backend)?;
    let require_auth = Confirm::new()
        .with_prompt("HMAC 認証を必須にしますか？ (シークレット設定が必要)")
        .default(false)
        .interact()?;
    let (share_paths, mount_point) = prompt_share()?;
    let syscalls = prompt_syscalls()?;
    let suspicious_paths = prompt_suspicious_paths()?;
    let allowed_hosts = prompt_allowed_hosts()?;
    let mitm_config = prompt_mitm()?;
    if !confirm_overwrite(&output)? {
        return Ok(0);
    }
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
    write_private_config(&output, &toml)?;
    println!("\n{} を生成しました。", output.display());
    Ok(0)
}

fn prompt_backend() -> Result<&'static str> {
    // --- Sandbox backend ---
    let backends = &["native", "qemu", "apple-container"];
    let backend_idx = Select::new()
        .with_prompt("Sandbox backend")
        .items(backends)
        .default(0)
        .interact()?;
    Ok(backends[backend_idx])
}

fn prompt_qemu(backend: &str) -> Result<Option<(u32, String, String)>> {
    if backend != "qemu" {
        return Ok(None);
    }
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
    Ok(Some((cpus, memory, image)))
}

fn prompt_tracer(backend: &str) -> Result<&'static str> {
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
    Ok(tracers[tracer_idx])
}

fn prompt_share() -> Result<(String, String)> {
    // --- Share ---
    let share_paths: String = Input::new()
        .with_prompt("共有するホストパス (カンマ区切り)")
        .default(".".to_string())
        .interact_text()?;
    let mount_point: String = Input::new()
        .with_prompt("ゲスト側マウントポイント")
        .default("/workspace".to_string())
        .interact_text()?;

    Ok((share_paths, mount_point))
}

fn prompt_syscalls() -> Result<Vec<String>> {
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

    Ok(syscalls)
}

fn prompt_suspicious_paths() -> Result<Vec<String>> {
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

    Ok(suspicious_paths)
}

fn prompt_allowed_hosts() -> Result<Vec<String>> {
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

    Ok(allowed_hosts)
}

fn prompt_mitm() -> Result<Option<MitmConfig>> {
    let enable = Confirm::new()
        .with_prompt("パケット検閲 (DNS プロキシ + HTTP キャプチャ) を有効にしますか？")
        .default(false)
        .interact()?;
    if !enable {
        return Ok(None);
    }
    let dns_listen = prompt_address("DNS プロキシのリッスンアドレス", "127.0.0.1:15353")?;
    let http_listen = prompt_address("HTTP リッスンアドレス", "127.0.0.1:18080")?;
    let https_listen = prompt_address("HTTPS (TLS MITM) リッスンアドレス", "127.0.0.1:18443")?;
    let ca_cert_out = Input::new()
        .with_prompt("CA 証明書の出力先パス")
        .default("/tmp/izanagi-ca.pem".to_string())
        .interact_text()?;
    let secret_maps = prompt_secret_maps()?;
    Ok(Some(MitmConfig {
        dns_listen,
        http_listen,
        https_listen,
        ca_cert_out,
        secret_maps,
    }))
}

fn prompt_address(prompt: &str, default: &str) -> Result<String> {
    Ok(Input::new()
        .with_prompt(prompt)
        .default(default.to_string())
        .validate_with(|input: &String| -> Result<(), String> {
            input
                .parse::<std::net::SocketAddr>()
                .map(|_| ())
                .map_err(|_| format!("無効なアドレスです (例: {default})"))
        })
        .interact_text()?)
}

fn prompt_secret_maps() -> Result<Vec<String>> {
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
    Ok(secret_maps)
}

fn confirm_overwrite(output: &Path) -> Result<bool> {
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
            return Ok(false);
        }
    }

    Ok(true)
}

fn write_private_config(output: &Path, toml: &str) -> Result<()> {
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
            .open(output)?;
        file.write_all(toml.as_bytes())?;
        // 既存ファイルの場合に備えてパーミッションを強制
        std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(output, toml)?;
    }
    Ok(())
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
    append_sandbox(&mut out, backend, qemu, tracer, require_auth);
    append_share(&mut out, share_paths, mount_point);
    append_monitor(&mut out, syscalls);
    out.push_str("\n[detect]\n");
    append_array(&mut out, "suspicious_paths", suspicious_paths);
    append_array(&mut out, "allowed_hosts", allowed_hosts);
    if let Some(mitm) = mitm {
        append_mitm(&mut out, mitm);
    } else {
        append_advanced_comments(&mut out);
    }
    out
}

fn append_sandbox(
    out: &mut String,
    backend: &str,
    qemu: Option<&(u32, String, String)>,
    tracer: &str,
    require_auth: bool,
) {
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
}

fn append_share(out: &mut String, share_paths: &str, mount_point: &str) {
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
}

fn append_monitor(out: &mut String, syscalls: &[String]) {
    // [monitor]
    out.push_str("\n[monitor]\n");
    let sc: Vec<String> = syscalls.iter().map(|s| escape_toml_string(s)).collect();
    out.push_str(&format!("syscalls = [{}]\n", sc.join(", ")));
}

fn append_array(out: &mut String, name: &str, values: &[String]) {
    if values.is_empty() {
        out.push_str(&format!("{name} = []\n"));
    } else {
        out.push_str(&format!("{name} = [\n"));
        for value in values {
            out.push_str(&format!("    {},\n", escape_toml_string(value)));
        }
        out.push_str("]\n");
    }
}

fn append_mitm(out: &mut String, m: &MitmConfig) {
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
    append_array(out, "secret_maps", &m.secret_maps);
}

fn append_advanced_comments(out: &mut String) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn config_creation_and_overwrite_enforce_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("izanagi-init-{:032x}", rand::random::<u128>()));
        let output = directory.join("nested/izanagi.toml");
        write_private_config(&output, "first = true\n").unwrap();
        assert_eq!(
            std::fs::metadata(output.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_config(&output, "x=1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "x=1\n");
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn mitm_sections_preserve_empty_and_escaped_mapping_arrays() {
        for secret_maps in [vec![], vec!["DUMMY=quote\"\\\nvalue".into()]] {
            let mitm = MitmConfig {
                dns_listen: "127.0.0.1:15353".into(),
                http_listen: "127.0.0.1:18080".into(),
                https_listen: "127.0.0.1:18443".into(),
                ca_cert_out: "/tmp/test-ca.pem".into(),
                secret_maps: secret_maps.clone(),
            };
            let text = generate_toml(
                "qemu",
                Some(&(2, "4G".into(), "default".into())),
                "vm-agent",
                true,
                ".",
                "/workspace",
                &[],
                &[],
                &[],
                Some(&mitm),
            );
            let parsed: toml::Value = toml::from_str(&text).unwrap();
            assert_eq!(parsed["dns_proxy"]["enabled"].as_bool(), Some(true));
            assert_eq!(
                parsed["http_capture"]["listen_https"].as_str(),
                Some("127.0.0.1:18443")
            );
            let actual: Vec<_> = parsed["http_capture"]["secret_maps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(actual, secret_maps);
            assert!(!text.contains("# --- 高度な設定"));
        }
    }

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
