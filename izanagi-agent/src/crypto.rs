pub(crate) use izanagi::crypto::sha256_hex;

/// SHA256 ダイジェストの定数時間比較。秘密鍵・固定鍵は不要。
/// ハッシュ計算時間は入力長に依存するが、比較は内容による早期終了をしない。
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let digest_a = Sha256::digest(a);
    let digest_b = Sha256::digest(b);
    bool::from(digest_a.as_slice().ct_eq(digest_b.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_value() {
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_hex_empty() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn constant_time_eq_same_input() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different_input() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"short", b"longer string"));
    }

    #[test]
    fn constant_time_eq_rejects_changes_at_every_position() {
        let input = [42u8; 64];
        for index in 0..input.len() {
            let mut changed = input;
            changed[index] ^= 1;
            assert!(!constant_time_eq(&input, &changed));
        }
    }
    #[test]
    fn shared_sha256_hex_utf8_known_value() {
        assert_eq!(
            sha256_hex("日本語🔐"),
            "8a6863f8e5f6f6c176ad7063d583d5fb42fc7817198f34b0f7f356ac583e51cc"
        );
    }
}
