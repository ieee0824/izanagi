//! Secrets may be substituted only in Authorization for one exact HTTPS host.
#[derive(Clone)]
struct Mapping {
    host: String,
    dummy: String,
    real: String,
}

#[derive(Clone)]
pub struct SecretMap {
    mappings: Vec<Mapping>,
}

impl std::fmt::Debug for SecretMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretMap")
            .field("entries", &self.mappings.len())
            .finish()
    }
}

impl SecretMap {
    pub fn new() -> Self {
        Self {
            mappings: Vec::new(),
        }
    }

    /// Parse HOST:Authorization:DUMMY=REAL. Never include mapping content in errors.
    pub fn add_from_str(&mut self, value: &str) -> anyhow::Result<()> {
        let invalid = || anyhow::anyhow!("secret-map requires HOST:Authorization:DUMMY=REAL");
        let mut parts = value.splitn(3, ':');
        let host = parts.next().ok_or_else(invalid)?;
        let header = parts.next().ok_or_else(invalid)?;
        let (dummy, real) = parts
            .next()
            .and_then(|part| part.split_once('='))
            .ok_or_else(invalid)?;
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || !header.eq_ignore_ascii_case("Authorization")
            || dummy.is_empty()
            || real.is_empty()
            || dummy.chars().any(char::is_control)
            || real.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        let host = host.to_ascii_lowercase();
        if self
            .mappings
            .iter()
            .any(|entry| entry.host == host && entry.dummy == dummy)
        {
            anyhow::bail!("duplicate secret-map scope and dummy value");
        }
        self.mappings.push(Mapping {
            host,
            dummy: dummy.to_owned(),
            real: real.to_owned(),
        });
        self.mappings.sort_by(|a, b| {
            b.dummy
                .len()
                .cmp(&a.dummy.len())
                .then_with(|| a.dummy.cmp(&b.dummy))
        });
        Ok(())
    }

    pub fn substitute_header(&self, host: &str, port: u16, header: &str, value: &str) -> String {
        if port != 443 || !header.eq_ignore_ascii_case("Authorization") {
            return value.to_owned();
        }
        // Scan the original once; inserted real values are never interpreted as dummy values.
        let mut remaining = value;
        let mut result = String::new();
        while !remaining.is_empty() {
            if let Some(entry) = self.mappings.iter().find(|entry| {
                entry.host.eq_ignore_ascii_case(host) && remaining.starts_with(&entry.dummy)
            }) {
                result.push_str(&entry.real);
                remaining = &remaining[entry.dummy.len()..];
            } else {
                let ch = remaining.chars().next().expect("nonempty");
                result.push(ch);
                remaining = &remaining[ch.len_utf8()..];
            }
        }
        result
    }

    pub fn safe_response<'a>(&self, response: &'a [u8]) -> &'a [u8] {
        if self.mappings.iter().any(|entry| {
            response
                .windows(entry.real.len())
                .any(|window| window == entry.real.as_bytes())
        }) {
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        } else {
            response
        }
    }

    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> SecretMap {
        let mut map = SecretMap::new();
        map.add_from_str("api.example.com:Authorization:DUMMY=CANARY_REAL")
            .unwrap();
        map
    }

    #[test]
    fn mapping_is_limited_to_exact_host_authorization_and_default_tls_port() {
        let map = mapping();
        assert_eq!(
            map.substitute_header("API.EXAMPLE.COM", 443, "authorization", "Bearer DUMMY"),
            "Bearer CANARY_REAL"
        );
        for (host, port, header) in [
            ("other.example.com", 443, "Authorization"),
            ("api.example.com.attacker.test", 443, "Authorization"),
            ("api.example.com", 8443, "Authorization"),
            ("api.example.com", 443, "X-Fixture"),
            ("api.example.com", 443, "Host"),
        ] {
            assert_eq!(
                map.substitute_header(host, port, header, "Bearer DUMMY"),
                "Bearer DUMMY"
            );
        }
    }

    #[test]
    fn reflected_secret_in_body_or_headers_is_not_returned() {
        let map = mapping();
        for response in [
            b"HTTP/1.1 200 OK\r\n\r\nCANARY_REAL".as_slice(),
            b"HTTP/1.1 200 OK\r\nX-Fixture: CANARY_REAL\r\n\r\n",
        ] {
            assert!(map.safe_response(response).starts_with(b"HTTP/1.1 502"));
            assert!(
                !map.safe_response(response)
                    .windows(11)
                    .any(|w| w == b"CANARY_REAL")
            );
        }
        let harmless = b"HTTP/1.1 200 OK\r\n\r\nDUMMY";
        assert_eq!(map.safe_response(harmless), harmless);
    }

    #[test]
    fn invalid_and_unscoped_mappings_fail_without_echoing_values() {
        for value in [
            "DUMMY=SECRET_CANARY",
            "api.example.com:Host:DUMMY=SECRET_CANARY",
            "*.example.com:Authorization:DUMMY=SECRET_CANARY",
            "api.example.com:Authorization:DUMMY=SECRET_CANARY\r\nInjected: value",
            "api.example.com:Authorization:DUMMY=",
        ] {
            let error = SecretMap::new()
                .add_from_str(value)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("SECRET_CANARY"));
        }
    }

    #[test]
    fn replacement_does_not_cascade_between_mappings() {
        let mut map = mapping();
        map.add_from_str("api.example.com:Authorization:CANARY_REAL=SECOND_SECRET")
            .unwrap();
        assert_eq!(
            map.substitute_header("api.example.com", 443, "Authorization", "DUMMY"),
            "CANARY_REAL"
        );
        assert!(
            map.add_from_str("api.example.com:Authorization:DUMMY=another")
                .is_err()
        );
    }
}
