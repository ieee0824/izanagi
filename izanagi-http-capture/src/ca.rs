use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// 自己署名 CA。サーバー証明書のオンデマンド生成に使用する。
// Debug は意図的に実装しない（秘密鍵を表示しないため）。
pub struct CaAuthority {
    /// CA 証明書の PEM 文字列。
    cert_pem: String,
    /// CA 証明書の DER バイト列（証明書チェーンに含める）。
    cert_der: CertificateDer<'static>,
    /// CA のキーペア（rcgen で証明書署名に使用）。
    key_pair: KeyPair,
    /// rcgen の CA 証明書オブジェクト（sign_server_cert で再利用）。
    ca_cert: rcgen::Certificate,
}

impl CaAuthority {
    /// エフェメラル（一時的な）自己署名 CA を生成する。
    pub fn generate() -> anyhow::Result<Self> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("CA キーペアの生成に失敗")?;

        let ca_cert = Self::ca_params()
            .self_signed(&key_pair)
            .context("CA 自己署名証明書の生成に失敗")?;

        let cert_pem = ca_cert.pem();
        let cert_der = CertificateDer::from(ca_cert.der().to_vec());

        Ok(Self {
            cert_pem,
            cert_der,
            key_pair,
            ca_cert,
        })
    }

    /// PEM ファイルから CA 秘密鍵を読み込み、同じ鍵で CA 証明書を再生成する。
    ///
    /// **注意**: 読み込んだ CA 証明書ファイルの内容は使用されない。
    /// 同じ秘密鍵で新しい CA 証明書を生成するため、サンドボックスの信頼ストアには
    /// `--ca-cert-out` で出力した証明書を注入する必要がある。
    /// これは rcgen が既存の証明書 DER をそのまま署名に使用する API を提供していないための制約。
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        let _cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("CA 証明書の読み込みに失敗: {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("CA 秘密鍵の読み込みに失敗: {}", key_path.display()))?;

        let key_pair = KeyPair::from_pem(&key_pem).context("CA 秘密鍵の PEM パースに失敗")?;

        // 同じキーペアで CA 証明書を再構築する。
        // cert_pem / cert_der / ca_cert の一貫性を保証する。
        let ca_cert = Self::ca_params()
            .self_signed(&key_pair)
            .context("CA 証明書の再構築に失敗")?;
        let cert_der = CertificateDer::from(ca_cert.der().to_vec());
        let cert_pem = ca_cert.pem();

        Ok(Self {
            cert_pem,
            cert_der,
            key_pair,
            ca_cert,
        })
    }

    /// CA 証明書の PEM 文字列を返す。
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// CA 証明書を PEM ファイルとして書き出す。
    pub fn write_cert_pem(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, &self.cert_pem)
            .with_context(|| format!("CA 証明書の書き出しに失敗: {}", path.display()))
    }

    /// 指定されたホスト名に対するサーバー証明書を生成し、rustls 用の CertifiedKey を返す。
    pub fn sign_server_cert(
        &self,
        hostname: &str,
    ) -> anyhow::Result<Arc<rustls::sign::CertifiedKey>> {
        let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("サーバーキーペアの生成に失敗")?;

        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .context("サーバー証明書パラメータの生成に失敗")?;
        // クロックスキュー吸収: クライアント側の時刻が数分遅れていても検証が通るよう、
        // not_before を 5 分前に設定する。
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(1);

        // 保持した CA 証明書オブジェクトで署名（毎回の再構築を回避）
        let cert = params
            .signed_by(&server_key, &self.ca_cert, &self.key_pair)
            .context("サーバー証明書の署名に失敗")?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(server_key.serialize_der());

        let signing_key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der))
            .map_err(|e| anyhow::anyhow!("ECDSA 署名鍵の変換に失敗: {}", e))?;

        Ok(Arc::new(rustls::sign::CertifiedKey::new(
            vec![cert_der, self.cert_der.clone()],
            signing_key,
        )))
    }

    /// CA 証明書のパラメータを返す。
    fn ca_params() -> CertificateParams {
        let mut params = CertificateParams::default();
        // Constrained(0): エンドエンティティ証明書のみ署名可能（中間 CA 発行を防止）
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params
            .distinguished_name
            .push(DnType::CommonName, "izanagi MITM CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "izanagi");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca() {
        let ca = CaAuthority::generate().unwrap();
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn sign_server_cert_basic() {
        let ca = CaAuthority::generate().unwrap();
        let certified_key = ca.sign_server_cert("example.com").unwrap();
        assert!(!certified_key.cert.is_empty());
    }

    #[test]
    fn sign_server_cert_different_hosts() {
        let ca = CaAuthority::generate().unwrap();
        let cert1 = ca.sign_server_cert("host1.com").unwrap();
        let cert2 = ca.sign_server_cert("host2.com").unwrap();
        assert_ne!(cert1.cert[0].as_ref(), cert2.cert[0].as_ref());
    }

    #[test]
    fn cert_chain_ca_is_consistent() {
        let ca = CaAuthority::generate().unwrap();
        let cert1 = ca.sign_server_cert("a.com").unwrap();
        let cert2 = ca.sign_server_cert("b.com").unwrap();
        // 証明書チェーンの CA 部分（2番目）が同一であること
        assert_eq!(cert1.cert[1].as_ref(), cert2.cert[1].as_ref());
        // かつ cert_der と一致すること
        assert_eq!(cert1.cert[1].as_ref(), ca.cert_der.as_ref());
    }

    #[test]
    fn write_and_read_ca_pem() {
        let ca = CaAuthority::generate().unwrap();
        let path = std::env::temp_dir().join("izanagi-test-ca.pem");
        ca.write_cert_pem(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("BEGIN CERTIFICATE"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cert_chain_includes_ca() {
        let ca = CaAuthority::generate().unwrap();
        let certified_key = ca.sign_server_cert("test.com").unwrap();
        assert_eq!(certified_key.cert.len(), 2);
    }

    #[test]
    fn from_pem_roundtrip() {
        let ca = CaAuthority::generate().unwrap();
        let cert_path = std::env::temp_dir().join("izanagi-test-ca-rt.pem");
        let key_path = std::env::temp_dir().join("izanagi-test-ca-rt.key");

        ca.write_cert_pem(&cert_path).unwrap();
        std::fs::write(&key_path, ca.key_pair.serialize_pem()).unwrap();

        let ca2 = CaAuthority::from_pem_files(&cert_path, &key_path).unwrap();
        // ロードした CA で署名できること
        let cert = ca2.sign_server_cert("roundtrip.com").unwrap();
        assert_eq!(cert.cert.len(), 2);

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }
}
