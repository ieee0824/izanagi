//! ログインジェクション防止用の文字列サニタイズユーティリティ。
//!
//! 制御文字（改行、タブ、ANSI エスケープシーケンス等）をエスケープし、
//! ログ出力に安全な文字列に変換する。
//!
//! `log_formatter` 等から呼び出される共通ロジック。

/// 制御文字（改行、タブ、ANSI エスケープシーケンス等）をエスケープする。
/// ログインジェクション防止のため、ログに書き込む文字列に適用する。
pub fn escape_control_chars(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ANSI エスケープシーケンスをエスケープ（ESC を \x1b に置換、CSI 本体は保持）
            result.push_str("\\x1b");
            // CSI シーケンス: ESC [ ... 終端文字
            if chars.peek() == Some(&'[') {
                chars.next();
                result.push('[');
                while let Some(&next) = chars.peek() {
                    chars.next();
                    result.push(next);
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if c == '\n' {
            result.push_str("\\n");
        } else if c == '\r' {
            result.push_str("\\r");
        } else if c == '\t' {
            result.push_str("\\t");
        } else if c.is_control() {
            use std::fmt::Write;
            let _ = write!(result, "\\x{:02x}", c as u32);
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_string_unchanged() {
        assert_eq!(escape_control_chars("hello world"), "hello world");
    }

    #[test]
    fn escape_newline() {
        assert_eq!(escape_control_chars("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn escape_carriage_return() {
        assert_eq!(escape_control_chars("a\rb"), "a\\rb");
    }

    #[test]
    fn escape_tab() {
        assert_eq!(escape_control_chars("a\tb"), "a\\tb");
    }

    #[test]
    fn escape_null_byte() {
        assert_eq!(escape_control_chars("a\0b"), "a\\x00b");
    }

    #[test]
    fn escape_ansi_csi() {
        // ESC [ 31m (赤色) → \x1b[31m
        assert_eq!(
            escape_control_chars("\x1b[31mred\x1b[0m"),
            "\\x1b[31mred\\x1b[0m"
        );
    }

    #[test]
    fn escape_ansi_without_csi() {
        // ESC の後に [ がない場合
        assert_eq!(escape_control_chars("\x1bX"), "\\x1bX");
    }

    #[test]
    fn empty_string() {
        assert_eq!(escape_control_chars(""), "");
    }

    #[test]
    fn mixed_control_chars() {
        assert_eq!(escape_control_chars("a\n\r\t\x01b"), "a\\n\\r\\t\\x01b");
    }

    #[test]
    fn unicode_preserved() {
        assert_eq!(escape_control_chars("日本語テスト"), "日本語テスト");
    }
}
