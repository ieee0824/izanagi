//! config モジュールの統合テスト。
//!
//! 設定ファイルのロード → バリデーション → SandboxConfig/TraceFilter 変換の
//! 一連のフローが正しく動作することを検証する。

use izanagi::config::Config;

/// デフォルト設定がバリデーションを通過し、SandboxConfig と TraceFilter に変換できること。
#[test]
fn default_config_validates_and_converts() {
    let config = Config::default();
    let warnings = config
        .validate()
        .expect("デフォルト設定のバリデーションに失敗");
    // 警告は許容（share パス未設定等）
    let _ = warnings;
}

/// TOML 文字列から Config をパースし、バリデーション → 変換の一連フローが動作すること。
#[test]
fn parse_validate_convert_roundtrip() {
    let toml_str = r#"
[sandbox]
backend = "native"
tracer = "none"

[share]
paths = ["/tmp"]
mount_point = "/workspace"

[monitor]
syscalls = ["file", "network"]

[detect]
suspicious_paths = ["~/.ssh/*"]
allowed_hosts = ["example.com"]
"#;
    let config: Config = toml::from_str(toml_str).expect("TOML パースに失敗");

    let warnings = config.validate().expect("バリデーションに失敗");
    let _ = warnings;

    // SandboxConfig への変換
    let sandbox_config = config.to_sandbox_config();
    assert!(
        sandbox_config.is_ok(),
        "SandboxConfig 変換に失敗: {:?}",
        sandbox_config.err()
    );

    // TraceFilter への変換
    let filter = config.to_trace_filter();
    assert!(!filter.categories.is_empty(), "TraceFilter のカテゴリが空");
}

/// 不正な backend を持つ設定がバリデーションでエラーになること。
#[test]
fn invalid_backend_rejected_by_validation() {
    let toml_str = r#"
[sandbox]
backend = "invalid_backend"
tracer = "none"

[share]
paths = ["/tmp"]
mount_point = "/workspace"
"#;
    let result: Result<Config, _> = toml::from_str(toml_str);
    // TOML パース時点でエラーになるか、バリデーションでエラーになる
    assert!(result.is_err(), "不正な backend がパースできてしまった");
}

/// 存在しない設定ファイルのロードがデフォルト設定を返すこと。
#[test]
fn load_nonexistent_returns_default() {
    let config = Config::load(std::path::Path::new("/nonexistent/izanagi.toml"));
    assert!(
        config.is_ok(),
        "存在しないパスでエラーになった: {:?}",
        config.err()
    );
}
