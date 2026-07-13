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
    /// Required scan price in native USDC base units (18 dp), as a decimal string.
    /// Must equal the contract's immutable `PRICE` (10 USDC). Kept as a string to
    /// preserve full 256-bit range.
    pub scan_price_wei: String,
    /// EVM chain id (Circle Arc testnet = 5042002).
    pub chain_id: i64,
    /// Deployed `ScanPayments` address. Optional while developing under bypass.
    pub payment_contract_address: Option<String>,
    /// Arc JSON-RPC HTTP endpoint for the payment watcher.
    pub arc_rpc_http_url: Option<String>,
    /// Confirmations to wait before trusting a payment log.
    pub payment_confirmations: u64,
    /// Watcher poll interval, seconds.
    pub payment_poll_interval_secs: u64,
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

    // --- Abuse prevention (Section 15) ---
    /// Max scans accepted per client IP per hour.
    pub rate_limit_per_hour: u32,
    /// Max sandbox scans allowed to run simultaneously (global).
    pub max_concurrent_scans: usize,
    /// Window for deduping identical resubmissions (ip_hash + source_hash).
    pub idempotency_window_secs: i32,
    /// Salt for hashing client IPs (never store raw IP). Set a real value in prod.
    pub ip_hash_salt: String,

    // --- LLM explanation layer (Section 4) ---
    /// API key; when absent the LLM layer is disabled (Slither-only report text).
    pub llm_api_key: Option<String>,
    /// OpenAI-compatible base URL (e.g. io.net IO Intelligence).
    pub llm_base_url: String,
    pub llm_model: String,
    /// If source exceeds this many chars, send windowed excerpts, not full source.
    pub llm_source_char_limit: usize,
    pub llm_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let payment_bypass = parse_bool("PAYMENT_BYPASS", false)?;

        let config = Self {
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            database_url: require("DATABASE_URL")?,
            scan_price_wei: env::var("SCAN_PRICE_WEI")
                .unwrap_or_else(|_| "10000000000000000000".to_string()),
            chain_id: parse_int("CHAIN_ID", 5042002)?,
            payment_contract_address: env::var("PAYMENT_CONTRACT_ADDRESS")
                .ok()
                .filter(|s| !s.is_empty()),
            arc_rpc_http_url: env::var("ARC_RPC_HTTP_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            payment_confirmations: parse_int("PAYMENT_CONFIRMATIONS", 2)?.max(0) as u64,
            payment_poll_interval_secs: parse_int("PAYMENT_POLL_INTERVAL_SECS", 5)?.max(1) as u64,
            payment_window_secs: parse_int("PAYMENT_WINDOW_SECS", 1800)?,
            payment_bypass,
            docker_bin: env::var("DOCKER_BIN").unwrap_or_else(|_| "docker".to_string()),
            slither_image: env::var("SLITHER_IMAGE")
                .unwrap_or_else(|_| "contract-scanner-slither:latest".to_string()),
            slither_timeout_secs: parse_int("SLITHER_TIMEOUT_SECS", 60)?.max(1) as u64,
            rate_limit_per_hour: parse_int("RATE_LIMIT_PER_HOUR", 5)?.max(1) as u32,
            max_concurrent_scans: parse_int("MAX_CONCURRENT_SCANS", 4)?.max(1) as usize,
            idempotency_window_secs: parse_int("IDEMPOTENCY_WINDOW_SECS", 60)?.max(0) as i32,
            ip_hash_salt: env::var("IP_HASH_SALT")
                .unwrap_or_else(|_| "dev-salt-change-me".to_string()),
            llm_api_key: env::var("LLM_API_KEY").ok().filter(|s| !s.is_empty()),
            llm_base_url: env::var("LLM_BASE_URL")
                .unwrap_or_else(|_| "https://api.intelligence.io.solutions/api/v1".to_string()),
            llm_model: env::var("LLM_MODEL")
                .unwrap_or_else(|_| "meta-llama/Llama-3.3-70B-Instruct".to_string()),
            llm_source_char_limit: parse_int("LLM_SOURCE_CHAR_LIMIT", 45000)?.max(1000) as usize,
            llm_timeout_secs: parse_int("LLM_TIMEOUT_SECS", 30)?.max(1) as u64,
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
