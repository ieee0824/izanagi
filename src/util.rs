use anyhow::bail;

/// SHA256 ハッシュを16進文字列で返す。
///
/// この関数は [`crate::crypto::sha256_hex`] に移動しました。
/// 既存の呼び出し元との後方互換のために re-export しています。
#[doc(inline)]
pub use crate::crypto::sha256_hex;

/// `~` をホームディレクトリに展開する。
/// `~` で始まるパスで HOME 環境変数が未設定の場合はエラーを返す。
pub fn expand_tilde(path: &str) -> anyhow::Result<String> {
    if let Some(rest) = path.strip_prefix('~') {
        match std::env::var_os("HOME") {
            Some(home) => Ok(format!("{}{}", home.to_string_lossy(), rest)),
            None => bail!(
                "HOME 環境変数が設定されていないため、チルダ展開ができません: \"{}\"",
                path
            ),
        }
    } else {
        Ok(path.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn expand_tilde_no_tilde() {
        assert_eq!(expand_tilde("/etc/passwd").unwrap(), "/etc/passwd");
    }

    #[test]
    #[serial(env)]
    fn expand_tilde_with_home() {
        // HOME が設定されている環境でのテスト
        if std::env::var_os("HOME").is_some() {
            let result = expand_tilde("~/.ssh").unwrap();
            assert!(!result.starts_with('~'));
            assert!(result.ends_with("/.ssh"));
        }
    }

    #[test]
    #[serial(env)]
    fn expand_tilde_without_home() {
        // HOME 環境変数を一時的に除去してエラーを返すことを検証
        let original_home = std::env::var_os("HOME");

        // SAFETY: serial(env) により他テストと排他実行される
        unsafe {
            std::env::remove_var("HOME");
        }

        let result = expand_tilde("~/some/path");
        assert!(result.is_err(), "HOME 未設定時にエラーを返すべき");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("HOME"),
            "エラーメッセージに HOME が含まれるべき: {}",
            err_msg
        );

        // HOME を元に戻す
        if let Some(home) = original_home {
            unsafe {
                std::env::set_var("HOME", home);
            }
        }
    }

    #[test]
    #[serial(env)]
    fn expand_tilde_without_home_no_tilde_prefix() {
        // チルダなしのパスは HOME が未設定でもエラーにならない
        let original_home = std::env::var_os("HOME");

        unsafe {
            std::env::remove_var("HOME");
        }

        let result = expand_tilde("/absolute/path");
        assert!(result.is_ok(), "チルダなしパスは HOME 未設定でも成功すべき");
        assert_eq!(result.unwrap(), "/absolute/path");

        if let Some(home) = original_home {
            unsafe {
                std::env::set_var("HOME", home);
            }
        }
    }
}
