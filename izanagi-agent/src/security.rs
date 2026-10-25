use std::collections::HashMap;

/// 危険な環境変数のデニーリスト。
/// ライブラリインジェクション、デバッグ、シェル初期化時の任意コード実行を防止する。
pub(crate) const DENIED_ENV_VARS: &[&str] = &[
    // ライブラリインジェクション
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FORCE_FLAT_NAMESPACE",
    "LD_AUDIT",
    "LD_DEBUG",
    // シェル初期化時の任意コード実行 (su -c 経由で読まれる)
    "ENV",
    "BASH_ENV",
    // ランタイムインジェクション
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
];

pub(crate) fn is_denied_env_var(key: &str) -> bool {
    key.starts_with("IZANAGI_") || DENIED_ENV_VARS.contains(&key)
}

/// 環境変数から危険なエントリを除外する。
pub(crate) fn sanitize_env(env: &HashMap<String, String>) -> HashMap<String, String> {
    let mut sanitized = env.clone();
    sanitized.retain(|key, _| {
        let allowed = !is_denied_env_var(key);
        if !allowed {
            eprintln!("WARNING: rejected dangerous env var: {}", key);
        }
        allowed
    });
    sanitized
}

/// Resolve only explicitly allowed variables from the image/agent environment.
/// Configured values take precedence, and internal or injection-capable names are never exposed.
pub(crate) fn resolve_environment(
    env: &HashMap<String, String>,
    inherit: &[String],
) -> HashMap<String, String> {
    let mut resolved = HashMap::new();
    for key in inherit {
        if is_denied_env_var(key) {
            eprintln!("WARNING: rejected dangerous inherited env var: {}", key);
            continue;
        }
        if let Ok(value) = std::env::var(key) {
            resolved.insert(key.clone(), value);
        }
    }
    resolved.extend(sanitize_env(env));
    resolved
}

/// クライアントに返すエラーメッセージの共通プレフィクス。
pub(crate) const EXEC_ERROR_PREFIX: &str = "command execution failed";

/// anyhow::Error を抽象的なメッセージに変換する。
/// `EXEC_ERROR_PREFIX` で始まるメッセージはクライアント向けと判断しそのまま通す。
/// それ以外は内部パス等を含む可能性があるため汎用メッセージに置換する。
pub(crate) fn sanitize_anyhow_error(err: &anyhow::Error) -> String {
    let msg = format!("{}", err);
    if msg.starts_with(EXEC_ERROR_PREFIX) {
        msg
    } else {
        eprintln!("sanitized error detail: {}", msg);
        EXEC_ERROR_PREFIX.to_string()
    }
}

/// IO エラーを抽象的なメッセージに変換する。
/// 内部パスやシステム詳細をクライアントに漏らさない。
pub(crate) fn sanitize_exec_error(err: &std::io::Error) -> anyhow::Error {
    // 詳細はサーバーログに記録
    eprintln!("exec spawn error: {}", err);

    let kind = match err.kind() {
        std::io::ErrorKind::NotFound => "not found",
        std::io::ErrorKind::PermissionDenied => "permission denied",
        _ => "unknown",
    };
    anyhow::anyhow!("{}: {}", EXEC_ERROR_PREFIX, kind)
}

/// シェルエスケープ（簡易版）。シングルクォートで囲む。
pub(crate) fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_env_removes_ld_preload() {
        let mut env = std::collections::HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        env.insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
        let sanitized = sanitize_env(&env);
        assert!(!sanitized.contains_key("LD_PRELOAD"));
        assert!(sanitized.contains_key("PATH"));
    }

    #[test]
    fn sanitize_env_preserves_safe_vars() {
        let mut env = std::collections::HashMap::new();
        env.insert("HOME".to_string(), "/home/user".to_string());
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        let sanitized = sanitize_env(&env);
        assert_eq!(sanitized.len(), 2);
    }

    #[test]
    fn shell_escape_basic() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn shell_escape_with_quote() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    // --- Task 357: comprehensive env denylist test ---

    #[test]
    fn sanitize_env_removes_all_denied_vars() {
        let mut env = std::collections::HashMap::new();
        // Add all denied vars
        for key in DENIED_ENV_VARS {
            env.insert(key.to_string(), "malicious_value".to_string());
        }
        // Add a safe var
        env.insert("SAFE_VAR".to_string(), "safe_value".to_string());

        let sanitized = sanitize_env(&env);

        // Verify every denied var is removed
        for key in DENIED_ENV_VARS {
            assert!(
                !sanitized.contains_key(*key),
                "denied env var '{}' was not removed",
                key
            );
        }
        // Verify safe var is preserved
        assert_eq!(sanitized.get("SAFE_VAR").unwrap(), "safe_value");
        assert_eq!(sanitized.len(), 1);
    }

    #[test]
    fn sanitize_env_covers_all_injection_categories() {
        // Verify specific dangerous vars from each category are in the denylist
        let library_injection = [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "LD_AUDIT",
            "LD_DEBUG",
        ];
        let shell_init = ["ENV", "BASH_ENV"];
        let runtime_injection = [
            "PYTHONSTARTUP",
            "PYTHONPATH",
            "NODE_OPTIONS",
            "NODE_PATH",
            "PERL5OPT",
            "PERL5LIB",
            "RUBYOPT",
            "RUBYLIB",
            "CLASSPATH",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "DOTNET_STARTUP_HOOKS",
        ];

        for var in library_injection
            .iter()
            .chain(shell_init.iter())
            .chain(runtime_injection.iter())
        {
            assert!(
                DENIED_ENV_VARS.contains(var),
                "expected '{}' to be in DENIED_ENV_VARS",
                var
            );
        }
    }

    #[test]
    fn sanitize_env_empty_input() {
        let env = std::collections::HashMap::new();
        let sanitized = sanitize_env(&env);
        assert!(sanitized.is_empty());
    }

    #[test]
    fn sanitize_env_removes_internal_agent_variables() {
        let env = HashMap::from([
            ("IZANAGI_SHARED_SECRET".into(), "secret".into()),
            ("SAFE_VAR".into(), "safe".into()),
        ]);
        let sanitized = sanitize_env(&env);
        assert!(!sanitized.contains_key("IZANAGI_SHARED_SECRET"));
        assert_eq!(sanitized.get("SAFE_VAR").map(String::as_str), Some("safe"));
    }

    #[test]
    fn configured_values_override_inherited_values() {
        let inherited_path = std::env::var("PATH").expect("test process must have PATH");
        let resolved = resolve_environment(
            &HashMap::from([("PATH".into(), "/configured/bin".into())]),
            &["PATH".into(), "IZANAGI_SHARED_SECRET".into()],
        );
        assert_ne!(inherited_path, "");
        assert_eq!(
            resolved.get("PATH").map(String::as_str),
            Some("/configured/bin")
        );
        assert!(!resolved.contains_key("IZANAGI_SHARED_SECRET"));
    }

    #[test]
    fn sanitize_anyhow_error_preserves_exec_prefix() {
        let err = anyhow::anyhow!("{}: not found", EXEC_ERROR_PREFIX);
        let msg = sanitize_anyhow_error(&err);
        assert!(msg.starts_with(EXEC_ERROR_PREFIX));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn sanitize_anyhow_error_hides_internal_details() {
        let err = anyhow::anyhow!("internal: /usr/local/secret/path leaked");
        let msg = sanitize_anyhow_error(&err);
        assert_eq!(msg, EXEC_ERROR_PREFIX);
        assert!(!msg.contains("secret"));
    }
}
