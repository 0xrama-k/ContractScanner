// ConfigError variants are defined ahead of the milestones that use them.
#![allow(dead_code)]

use std::env;

/// Process configuration, loaded once from the environment at startup.
///
/// Only the fields needed for the current milestone are present. DB, LLM, and
/// payment fields are added as their milestones land (see `.env.example`).
#[derive(Debug, Clone)]
pub struct Config {
    /// Socket address the HTTP server binds to, e.g. `127.0.0.1:8080`.
    pub bind_addr: String,
    /// PostgreSQL connection string (`DATABASE_URL`).
    pub database_url: String,

    // --- Payment gate (Section 21) ---
    /// Required scan price in wei, as a decimal string. Must equal the contract's
    /// immutable `PRICE` (10 MON). Kept as a string to preserve full 256-bit range.
    pub scan_price_wei: String,
    /// EVM chain id (Monad testnet = 10143).
    pub chain_id: i64,
    /// Deployed `ScanPayments` address. Optional while developing under bypass.
    pub payment_contract_address: Option<String>,
    /// Seconds a scan may sit in `awaiting_payment` before it expires.
    pub payment_window_secs: i64,
    /// DEV ONLY: skip the on-chain gate and start scans immediately. Must never be
    /// enabled in production (guarded at startup below).
    pub payment_bypass: bool,

    // --- Slither sandbox (Section 15) ---
    /// Docker executable (full path if not on PATH for the server process).
    pub docker_bin: String,
    /// Slither sandbox image tag.
    pub slither_image: String,
    /// Wall-clock timeout for a single Slither run, in seconds.
    pub slither_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let payment_bypass = parse_bool("PAYMENT_BYPASS", false)?;

        let config = Self {
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            database_url: require("DATABASE_URL")?,
            scan_price_wei: env::var("SCAN_PRICE_WEI")
                .unwrap_or_else(|_| "10000000000000000000".to_string()),
            chain_id: parse_int("CHAIN_ID", 10143)?,
            payment_contract_address: env::var("PAYMENT_CONTRACT_ADDRESS")
                .ok()
                .filter(|s| !s.is_empty()),
            payment_window_secs: parse_int("PAYMENT_WINDOW_SECS", 1800)?,
            payment_bypass,
            docker_bin: env::var("DOCKER_BIN").unwrap_or_else(|_| "docker".to_string()),
            slither_image: env::var("SLITHER_IMAGE")
                .unwrap_or_else(|_| "contract-scanner-slither:latest".to_string()),
            slither_timeout_secs: parse_int("SLITHER_TIMEOUT_SECS", 60)?.max(1) as u64,
        };

        Ok(config)
    }
}

/// Read a required environment variable or fail with a clear error.
fn require(var: &str) -> Result<String, ConfigError> {
    env::var(var).map_err(|_| ConfigError::MissingVar(var.to_string()))
}

fn parse_int(var: &str, default: i64) -> Result<i64, ConfigError> {
    match env::var(var) {
        Ok(v) => v.parse().map_err(|_| ConfigError::InvalidVar {
            var: var.to_string(),
            reason: "expected an integer".to_string(),
        }),
        Err(_) => Ok(default),
    }
}

fn parse_bool(var: &str, default: bool) -> Result<bool, ConfigError> {
    match env::var(var) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::InvalidVar {
                var: var.to_string(),
                reason: "expected a boolean".to_string(),
            }),
        },
        Err(_) => Ok(default),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingVar(String),
    #[error("invalid value for {var}: {reason}")]
    InvalidVar { var: String, reason: String },
}
