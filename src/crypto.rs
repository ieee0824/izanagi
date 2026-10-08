//! 暗号ユーティリティ。
//!
//! SHA256 ハッシュ計算等の暗号関連ヘルパー関数を集約する。
//! `protocol.rs` 内部の HMAC 関数は protocol に密結合のため移動しない。

/// SHA256 ハッシュを16進文字列で返す。
///
/// トークンの比較やセッション識別に使用される。
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_value() {
        // echo -n "hello" | sha256sum
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_hex_empty_string() {
        // echo -n "" | sha256sum
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_deterministic() {
        let hash1 = sha256_hex("test");
        let hash2 = sha256_hex("test");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn sha256_hex_different_inputs() {
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }
    #[test]
    fn sha256_hex_utf8_known_value() {
        assert_eq!(
            sha256_hex("日本語🔐"),
            "8a6863f8e5f6f6c176ad7063d583d5fb42fc7817198f34b0f7f356ac583e51cc"
        );
    }
}
