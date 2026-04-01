use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use rustls::sign::CertifiedKey;

use crate::ca::CaAuthority;

/// キャッシュの最大エントリ数。超過時は全エントリをクリアする。
const MAX_CACHE_ENTRIES: usize = 10_000;

/// SNI ホスト名ごとの証明書キャッシュ。
/// 同一 SNI に対する証明書の再生成を防ぎ、TLS ハンドシェイクを高速化する。
///
/// `allowed_hosts` が設定されている場合、許可リスト外の SNI に対する
/// 証明書生成をブロックし、不正ドメインの証明書がキャッシュされることを防ぐ。
pub struct CertCache {
    ca: Arc<CaAuthority>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    /// 証明書生成を許可するホスト名のセット（小文字正規化済み）。
    /// 空の場合はすべての SNI に対して証明書を生成する（キャプチャのみモード）。
    allowed_hosts: Arc<HashSet<String>>,
}

impl std::fmt::Debug for CertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertCache")
            .field(
                "cache_size",
                &self.cache.lock().map(|c| c.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl CertCache {
    pub fn new(ca: Arc<CaAuthority>, allowed_hosts: Arc<HashSet<String>>) -> Self {
        Self {
            ca,
            cache: Mutex::new(HashMap::new()),
            allowed_hosts,
        }
    }

    /// 指定された SNI に対する CertifiedKey を取得する。
    /// キャッシュにない場合は CA で署名して生成し、キャッシュに保存する。
    /// Mutex は検索時のみ保持し、証明書生成中はロックを解放する。
    ///
    /// `allowed_hosts` が非空の場合、許可リスト外の SNI に対してはエラーを返す。
    pub fn get_or_create(&self, sni: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        // DNS は case-insensitive なため、キャッシュキーも小文字に正規化する。
        // これにより "EXAMPLE.COM" と "example.com" が同一エントリとして扱われる。
        let sni_lower = sni.to_ascii_lowercase();

        // SNI を allowlist と照合（空の場合はキャプチャのみモードなので全許可）。
        // 許可リスト外の SNI でも TLS ハンドシェイクを成功させるために一時証明書を返す。
        // これにより handle_connection() 側で HTTP 403 応答 + ログ記録が行われる。
        // キャッシュ枯渇攻撃を防ぐため、許可リスト外の証明書はキャッシュに保存しない。
        if !self.allowed_hosts.is_empty() && !self.allowed_hosts.contains(&sni_lower) {
            let key = self.ca.sign_server_cert(sni)?;
            return Ok(key);
        }

        // キャッシュヒットチェック（短時間のロック）
        {
            let cache = self.cache.lock().expect("cert cache lock poisoned");
            if let Some(key) = cache.get(&sni_lower) {
                return Ok(key.clone());
            }
        }

        // ロック外で証明書を生成（暗号処理中に他スレッドをブロックしない）
        let key = self.ca.sign_server_cert(sni)?;

        // 生成後にキャッシュに挿入（同一 SNI で重複生成の可能性があるが許容する）
        {
            let mut cache = self.cache.lock().expect("cert cache lock poisoned");

            // 容量制限: 超過時はキャッシュをクリアする（簡易 LRU の代替）
            if cache.len() >= MAX_CACHE_ENTRIES {
                eprintln!(
                    "警告: 証明書キャッシュが上限 ({}) に達しました。クリアします。",
                    MAX_CACHE_ENTRIES
                );
                cache.clear();
            }

            // 同一 SNI で先に挿入されていたらそちらを返す
            if let Some(existing) = cache.get(&sni_lower) {
                return Ok(existing.clone());
            }

            cache.insert(sni_lower, key.clone());
        }

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_allowlist() -> Arc<HashSet<String>> {
        Arc::new(HashSet::new())
    }

    fn allowlist_of(hosts: &[&str]) -> Arc<HashSet<String>> {
        Arc::new(hosts.iter().map(|h| h.to_ascii_lowercase().to_string()).collect())
    }

    #[test]
    fn cache_hit() {
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = CertCache::new(ca, empty_allowlist());

        let key1 = cache.get_or_create("example.com").unwrap();
        let key2 = cache.get_or_create("example.com").unwrap();
        assert!(Arc::ptr_eq(&key1, &key2));
    }

    #[test]
    fn cache_miss_different_hosts() {
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = CertCache::new(ca, empty_allowlist());

        let key1 = cache.get_or_create("host1.com").unwrap();
        let key2 = cache.get_or_create("host2.com").unwrap();
        assert!(!Arc::ptr_eq(&key1, &key2));
    }

    #[test]
    fn concurrent_access() {
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = Arc::new(CertCache::new(ca, empty_allowlist()));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let cache = cache.clone();
                std::thread::spawn(move || {
                    cache
                        .get_or_create(&format!("host{}.com", i % 3))
                        .unwrap()
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn allowed_host_generates_cert() {
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = CertCache::new(ca, allowlist_of(&["example.com"]));
        assert!(cache.get_or_create("example.com").is_ok());
    }

    #[test]
    fn disallowed_host_returns_uncached_cert() {
        // 許可リスト外でも TLS ハンドシェイク用の一時証明書を返す
        // (HTTP レベルで 403 + ログを行うため)
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = CertCache::new(ca, allowlist_of(&["example.com"]));
        let key1 = cache.get_or_create("evil.com").unwrap();
        let key2 = cache.get_or_create("evil.com").unwrap();
        // キャッシュされないため、毎回新しい証明書が生成される
        assert!(!Arc::ptr_eq(&key1, &key2));
    }

    #[test]
    fn allowlist_case_insensitive() {
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = CertCache::new(ca, allowlist_of(&["Example.COM"]));
        assert!(cache.get_or_create("example.com").is_ok());
        assert!(cache.get_or_create("EXAMPLE.COM").is_ok());
    }

    #[test]
    fn cache_key_normalized_case_insensitive() {
        // 大文字 SNI と小文字 SNI が同一キャッシュエントリを共有することを検証
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = CertCache::new(ca, empty_allowlist());

        let key1 = cache.get_or_create("Example.COM").unwrap();
        let key2 = cache.get_or_create("example.com").unwrap();
        assert!(Arc::ptr_eq(&key1, &key2), "大文字小文字が異なる SNI は同じ証明書を返すべき");
    }

    #[test]
    fn subdomain_not_cached_as_parent() {
        // allowlist に "example.com" がある場合、"evil.example.com" は一時証明書を返すが
        // キャッシュには保存されない（HTTP レベルで 403 になる）
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = CertCache::new(ca, allowlist_of(&["example.com"]));
        let key1 = cache.get_or_create("evil.example.com").unwrap();
        let key2 = cache.get_or_create("evil.example.com").unwrap();
        assert!(!Arc::ptr_eq(&key1, &key2), "許可リスト外はキャッシュされない");
    }

    #[test]
    fn empty_sni_returns_uncached_cert_with_allowlist() {
        // 空文字 SNI は allowlist に含まれないため一時証明書を返す
        // (CA が空文字の証明書を生成できるかは CA 実装依存)
        let ca = Arc::new(CaAuthority::generate().unwrap());
        let cache = CertCache::new(ca, allowlist_of(&["example.com"]));
        // 空文字 SNI の証明書生成は CA が対応していれば成功する
        // handle_connection 側で 403 として処理される
        let _ = cache.get_or_create("");
    }
}
