//! Opt-in behavior configuration. Credentials are environment variable names, never values.
use crate::behavior_classifier::{ClassifierConfig, JevProfile};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BehaviorSection {
    pub enabled: bool,
    pub proxy_listen: String,
    pub fixture_endpoint: Option<String>,
    pub baseline_hosts: Vec<String>,
    pub classifier: BehaviorClassifierSection,
    pub limits: BehaviorLimits,
}
impl Default for BehaviorSection {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy_listen: "127.0.0.1:18080".into(),
            fixture_endpoint: None,
            baseline_hosts: vec![],
            classifier: Default::default(),
            limits: Default::default(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BehaviorLimits {
    pub queue_windows: usize,
    pub telemetry_queue: usize,
    pub max_queue_age_secs: u64,
    pub max_result_age_secs: u64,
    pub shutdown_secs: u64,
    pub max_store_bytes: u64,
    pub retention_days: u64,
}
impl Default for BehaviorLimits {
    fn default() -> Self {
        Self {
            queue_windows: 32,
            telemetry_queue: 4096,
            max_queue_age_secs: 15,
            max_result_age_secs: 90,
            shutdown_secs: 2,
            max_store_bytes: 100 * 1024 * 1024,
            retention_days: 7,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BehaviorClassifierSection {
    pub provider: String,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub credential_env: String,
    pub model: String,
    pub mcp_commit: Option<String>,
    pub profile: JevProfile,
    pub deadline_secs: u64,
    pub min_confidence: f64,
    pub allow_export: bool,
}
impl Default for BehaviorClassifierSection {
    fn default() -> Self {
        Self {
            provider: "mock".into(),
            command: "jev-mcp".into(),
            args: vec![],
            credential_env: "TYPESAFE_API_KEY".into(),
            model: "jev-1.13.0".into(),
            mcp_commit: None,
            profile: JevProfile::Reliable,
            deadline_secs: 65,
            min_confidence: 0.6,
            allow_export: false,
        }
    }
}
impl BehaviorClassifierSection {
    pub fn runtime(&self) -> ClassifierConfig {
        ClassifierConfig {
            command: self.command.clone(),
            args: self.args.clone(),
            credential_env: self.credential_env.clone(),
            model: self.model.clone(),
            mcp_commit: self.mcp_commit.clone(),
            profile: self.profile,
            deadline: Duration::from_secs(self.deadline_secs),
            min_confidence: self.min_confidence,
            ..Default::default()
        }
    }
}
impl BehaviorSection {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_classifier()?;
        let listen: std::net::SocketAddr = self
            .proxy_listen
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid behavior proxy listen address"))?;
        if !listen.ip().is_loopback() || listen.port() == 0 {
            anyhow::bail!("behavior proxy must listen on an exact loopback endpoint");
        }
        if let Some(endpoint) = &self.fixture_endpoint {
            let endpoint: std::net::SocketAddr = endpoint
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid behavior fixture endpoint"))?;
            if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
                anyhow::bail!("behavior fixture endpoint must be exact loopback");
            }
        }
        let l = &self.limits;
        if l.queue_windows == 0
            || l.queue_windows > 32
            || l.telemetry_queue == 0
            || l.telemetry_queue > 4096
            || l.max_queue_age_secs == 0
            || l.max_queue_age_secs > 15
            || l.max_result_age_secs == 0
            || l.max_result_age_secs > 90
            || l.shutdown_secs == 0
            || l.shutdown_secs > 2
            || l.max_store_bytes < 128 * 1024
            || l.max_store_bytes > 100 * 1024 * 1024
            || l.retention_days == 0
            || l.retention_days > 7
        {
            anyhow::bail!("behavior limits are outside bounded PoC ranges");
        }
        Ok(())
    }

    fn validate_classifier(&self) -> anyhow::Result<()> {
        if !matches!(self.classifier.provider.as_str(), "mock" | "jev-mcp") {
            anyhow::bail!("behavior.classifier.provider must be mock or jev-mcp");
        }
        let runtime = self.classifier.runtime();
        runtime
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid behavior classifier configuration"))?;
        if self.classifier.provider == "jev-mcp" {
            runtime.validate_mcp_command().map_err(|_| {
                anyhow::anyhow!(
                    "behavior.classifier.command must be a trusted absolute path for jev-mcp"
                )
            })?;
        }
        Ok(())
    }
}
