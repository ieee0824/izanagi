//! Versioned, metadata-only behavior telemetry shared by host and guest.
pub mod correlation;
pub mod privacy;
pub mod schema;
pub mod store;

pub use correlation::*;
pub use privacy::*;
pub use schema::*;
pub use store::*;

pub const SCHEMA_VERSION: u16 = 1;
pub const FEATURE_VERSION: u16 = 1;
pub const MAX_PROJECTION_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryError {
    InvalidEvent,
    Oversize,
    InvalidConfiguration,
    Io,
    MalformedRecord,
}
impl std::fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidEvent => "invalid telemetry event",
            Self::Oversize => "telemetry size limit exceeded",
            Self::InvalidConfiguration => "invalid telemetry configuration",
            Self::Io => "telemetry storage I/O failed",
            Self::MalformedRecord => "malformed telemetry record",
        })
    }
}
impl std::error::Error for TelemetryError {}
