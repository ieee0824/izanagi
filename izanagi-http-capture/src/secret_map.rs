/// ダミー値 → 本物のシークレットのマッピング。
/// リクエスト body やヘッダー内のダミー値を本物に置換する。
#[derive(Clone)]
pub struct SecretMap {
    /// ダミー値の長い順にソート済み（部分文字列の誤置換を防ぐ）。
    sorted_mappings: Vec<(String, String)>,
}

// Debug 実装: シークレットの中身をマスクする
impl std::fmt::Debug for SecretMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretMap")
            .field("entries", &self.sorted_mappings.len())
            .finish()
    }
}

impl SecretMap {
    pub fn new() -> Self {
        Self {
            sorted_mappings: Vec::new(),
        }
    }

    /// "DUMMY=REAL" 形式の文字列からマッピングを追加する。
    pub fn add_from_str(&mut self, s: &str) -> anyhow::Result<()> {
        let (dummy, real) = s.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("無効な secret-map 形式: '{}' (DUMMY=REAL が必要)", s)
        })?;
        if dummy.is_empty() {
            anyhow::bail!("ダミー値が空です: '{}'", s);
        }
        if real.is_empty() {
            anyhow::bail!("本物のシークレットが空です: '{}'", s);
        }
        self.sorted_mappings
            .push((dummy.to_string(), real.to_string()));
        // 長い順にソート（部分文字列の誤置換を防ぐ: "KEY_LONG" を "KEY" より先に置換）
        // 同じ長さの場合は辞書順で決定的に並べる
        self.sorted_mappings
            .sort_by(|a, b| match b.0.len().cmp(&a.0.len()) {
                std::cmp::Ordering::Equal => a.0.cmp(&b.0),
                other => other,
            });
        Ok(())
    }

    /// body 内の全ダミー値を本物に置換して返す。
    /// 非 UTF-8 の body はそのまま返す（バイナリ body の破壊を防ぐ）。
    pub fn substitute(&self, body: &[u8]) -> Vec<u8> {
        if self.sorted_mappings.is_empty() {
            return body.to_vec();
        }
        let Ok(mut s) = String::from_utf8(body.to_vec()) else {
            return body.to_vec();
        };
        for (dummy, real) in &self.sorted_mappings {
            s = s.replace(dummy.as_str(), real.as_str());
        }
        s.into_bytes()
    }

    /// 文字列内の全ダミー値を本物に置換して返す。
    pub fn substitute_str(&self, s: &str) -> String {
        if self.sorted_mappings.is_empty() {
            return s.to_string();
        }
        let mut result = s.to_string();
        for (dummy, real) in &self.sorted_mappings {
            result = result.replace(dummy.as_str(), real.as_str());
        }
        result
    }

    /// マッピングが空かどうか。
    pub fn is_empty(&self) -> bool {
        self.sorted_mappings.is_empty()
    }

    /// 登録されているダミー値のいずれかが含まれているかチェックする。
    pub fn contains_dummy(&self, s: &str) -> bool {
        self.sorted_mappings
            .iter()
            .any(|(dummy, _)| s.contains(dummy.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_substitute_body() {
        let mut map = SecretMap::new();
        map.add_from_str("DUMMY_TOKEN=real-api-key-abc123").unwrap();

        let body = b"{\"token\":\"DUMMY_TOKEN\"}";
        let result = map.substitute(body);
        assert_eq!(
            String::from_utf8(result).unwrap(),
            "{\"token\":\"real-api-key-abc123\"}"
        );
    }

    #[test]
    fn substitute_multiple() {
        let mut map = SecretMap::new();
        map.add_from_str("KEY1=secret1").unwrap();
        map.add_from_str("KEY2=secret2").unwrap();

        let body = b"a=KEY1&b=KEY2";
        let result = map.substitute(body);
        assert_eq!(String::from_utf8(result).unwrap(), "a=secret1&b=secret2");
    }

    #[test]
    fn substitute_str_works() {
        let mut map = SecretMap::new();
        map.add_from_str("DUMMY=real").unwrap();

        assert_eq!(map.substitute_str("Bearer DUMMY"), "Bearer real");
    }

    #[test]
    fn empty_map_passthrough() {
        let map = SecretMap::new();
        assert!(map.is_empty());

        let body = b"no changes";
        assert_eq!(map.substitute(body), b"no changes");
    }

    #[test]
    fn no_match_passthrough() {
        let mut map = SecretMap::new();
        map.add_from_str("DUMMY=real").unwrap();

        let body = b"no dummy here";
        assert_eq!(map.substitute(body), b"no dummy here");
    }

    #[test]
    fn add_from_str_invalid() {
        let mut map = SecretMap::new();
        assert!(map.add_from_str("no-equals").is_err());
        assert!(map.add_from_str("=real").is_err());
        assert!(map.add_from_str("dummy=").is_err());
    }

    #[test]
    fn contains_dummy_check() {
        let mut map = SecretMap::new();
        map.add_from_str("TOKEN=real-value-xyz").unwrap();

        assert!(map.contains_dummy("Authorization: Bearer TOKEN"));
        assert!(!map.contains_dummy("no match here"));
    }
}
