//! Payment watcher (Section 21). Polls the Arc RPC for `ScanPaid` logs, and on
//! a confirmed event flips the scan from `awaiting_payment` to `queued` and
//! starts analysis. Restart-safe via `chain_watcher_state.last_processed_block`.
//! The USDC payment settles as native value on Arc, so `ScanPaid.amount` is the
//! attached `msg.value` in 18-decimal USDC.
//!
//! Dependency-light: raw JSON-RPC over reqwest + manual log decoding (no eth lib).

use std::time::Duration;

use serde_json::{json, Value};
use uuid::Uuid;

use crate::app::AppState;
use crate::repositories::scan_repository;
use crate::services::scan_service;

/// keccak256("ScanPaid(bytes32,address,uint256)").
const SCANPAID_TOPIC: &str =
    "0x639125ad78269da16d3149917eed2cce099067510fdea86de32c6a9b8757bb00";
/// Cap per getLogs query at a 100-block range (`from..=from+99`). Conservative
/// window that stays within common public-RPC `eth_getLogs` limits on Arc.
const MAX_BLOCK_RANGE: u64 = 99;

pub fn spawn(state: AppState) {
    tokio::spawn(async move { run(state).await });
}

async fn run(state: AppState) {
    let (contract, rpc) = match (
        state.config.payment_contract_address.clone(),
        state.config.arc_rpc_http_url.clone(),
    ) {
        (Some(c), Some(r)) => (c, r),
        _ => {
            tracing::info!("payment watcher disabled (no contract address or RPC URL)");
            return;
        }
    };

    let price: u128 = state.config.scan_price_wei.parse().unwrap_or(u128::MAX);
    let confirmations = state.config.payment_confirmations;
    let interval = Duration::from_secs(state.config.payment_poll_interval_secs);
    let http = reqwest::Client::new();

    tracing::info!(%contract, "payment watcher started");

    loop {
        if let Err(e) = poll_once(&state, &http, &rpc, &contract, price, confirmations).await {
            tracing::warn!(error = %e, "payment watcher poll failed");
        }
        tokio::time::sleep(interval).await;
    }
}

async fn poll_once(
    state: &AppState,
    http: &reqwest::Client,
    rpc: &str,
    contract: &str,
    price: u128,
    confirmations: u64,
) -> Result<(), String> {
    let latest = rpc_u64(http, rpc, "eth_blockNumber", json!([])).await?;
    let safe_to = latest.saturating_sub(confirmations);

    let last = scan_repository::get_last_processed_block(&state.db)
        .await
        .map_err(|e| e.to_string())? as u64;

    // First run: start from the chain head (contract is newly deployed; no prior
    // relevant events) — avoids backfilling from genesis.
    let mut cursor = if last == 0 {
        safe_to.saturating_add(1)
    } else {
        last.saturating_add(1)
    };

    // If far behind (e.g. after downtime), fast-forward: payments older than the
    // window are expired anyway, so don't replay ancient history.
    const LOOKBACK_MAX: u64 = 5000;
    if safe_to > cursor && safe_to - cursor > LOOKBACK_MAX {
        cursor = safe_to - LOOKBACK_MAX;
    }

    if cursor > safe_to {
        if last == 0 {
            scan_repository::set_last_processed_block(&state.db, safe_to as i64)
                .await
                .map_err(|e| e.to_string())?;
            tracing::info!(block = safe_to, "payment watcher cursor initialized to chain head");
        }
        return Ok(());
    }

    // Walk forward in <=100-block windows, several per poll, to catch up quickly
    // on a fast chain (bounded so one poll can't run unboundedly).
    let mut windows = 0;
    while cursor <= safe_to && windows < 200 {
        let to = cursor.saturating_add(MAX_BLOCK_RANGE).min(safe_to);
        let params = json!([{
            "address": contract,
            "fromBlock": format!("0x{cursor:x}"),
            "toBlock": format!("0x{to:x}"),
            "topics": [SCANPAID_TOPIC],
        }]);
        let result = rpc_call(http, rpc, "eth_getLogs", params).await?;
        for log in result.as_array().cloned().unwrap_or_default().iter() {
            handle_log(state, log, price).await;
        }
        scan_repository::set_last_processed_block(&state.db, to as i64)
            .await
            .map_err(|e| e.to_string())?;
        cursor = to.saturating_add(1);
        windows += 1;
    }
    Ok(())
}

/// Decode one ScanPaid log and, if valid, start the paid scan.
async fn handle_log(state: &AppState, log: &Value, price: u128) {
    let topics = log
        .get("topics")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if topics.len() < 3 {
        return; // need topic0(sig) + scanId + payer
    }
    let Some(scan_id) = scan_id_from_topic(topics[1].as_str().unwrap_or("")) else {
        return;
    };
    let payer = address_from_topic(topics[2].as_str().unwrap_or(""));
    let amount = u128_from_hex(log.get("data").and_then(Value::as_str).unwrap_or(""));
    let tx_hash = log
        .get("transactionHash")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Contract enforces msg.value >= PRICE, but verify defensively.
    if amount < price {
        tracing::warn!(%scan_id, amount, "ScanPaid below price; ignoring");
        return;
    }
    scan_service::on_payment_observed(state, scan_id, &payer, &tx_hash).await;
}

async fn rpc_call(
    http: &reqwest::Client,
    rpc: &str,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = http
        .post(rpc)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let v: Value = resp.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = v.get("error") {
        return Err(format!("rpc error: {err}"));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

async fn rpc_u64(
    http: &reqwest::Client,
    rpc: &str,
    method: &str,
    params: Value,
) -> Result<u64, String> {
    let r = rpc_call(http, rpc, method, params).await?;
    let s = r.as_str().ok_or("expected hex string")?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

/// Decode the indexed `scanId` (bytes32) back to a UUID (low 16 bytes).
fn scan_id_from_topic(topic: &str) -> Option<Uuid> {
    let h = topic.trim_start_matches("0x");
    if h.len() != 64 {
        return None;
    }
    let bytes = hex::decode(h).ok()?;
    Uuid::from_slice(&bytes[16..32]).ok()
}

/// Decode an indexed address (right-most 20 bytes of the 32-byte topic).
fn address_from_topic(topic: &str) -> String {
    let h = topic.trim_start_matches("0x");
    if h.len() == 64 {
        format!("0x{}", &h[24..64])
    } else {
        topic.to_string()
    }
}

/// Decode a uint256 amount from log data into u128 (amounts here fit easily).
fn u128_from_hex(data: &str) -> u128 {
    let h = data.trim_start_matches("0x");
    if h.is_empty() {
        return 0;
    }
    let slice = if h.len() > 32 { &h[h.len() - 32..] } else { h };
    u128::from_str_radix(slice, 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_scan_id_and_address_and_amount() {
        let id = Uuid::new_v4();
        // bytes32 = 16 zero bytes + 16 uuid bytes
        let topic = format!("0x{}{}", "00".repeat(16), hex::encode(id.as_bytes()));
        assert_eq!(scan_id_from_topic(&topic), Some(id));

        let addr_topic = "0x000000000000000000000000abcdef0000000000000000000000000000001234";
        assert_eq!(
            address_from_topic(addr_topic),
            "0xabcdef0000000000000000000000000000001234"
        );

        // 10 USDC = 10e18 native base units (18 dp) on Arc
        let ten_usdc = "0x0000000000000000000000000000000000000000000000008ac7230489e80000";
        assert_eq!(u128_from_hex(ten_usdc), 10_000_000_000_000_000_000u128);
    }
}
