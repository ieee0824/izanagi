/// SHA256 ハッシュを16進文字列で返す。
pub(crate) fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// HMAC ベースの定数時間比較。
/// 両方の入力を HMAC に通して結果を比較することで、
/// タイミング攻撃を防ぐ。
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    // 固定キーで a の HMAC を計算し、b の HMAC と verify で比較する。
    // verify は内部で subtle::ConstantTimeEq を使い、定数時間比較を保証する。
    let key = b"izanagi-constant-time-compare";
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(a);

    let mut mac_b = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac_b.update(b);
    let tag_b = mac_b.finalize().into_bytes();

    mac.verify(&tag_b).is_ok()
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
}
