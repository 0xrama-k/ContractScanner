use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::scan::ScanStatus;

/// Fields needed to insert a new scan row.
pub struct NewScan<'a> {
    pub status: ScanStatus,
    pub input_type: &'a str,
    pub filename: Option<&'a str>,
    pub source_hash: &'a str,
    pub ip_hash: Option<&'a str>,
    /// Required price in wei, as a decimal string (cast to NUMERIC in SQL).
    pub price_wei: &'a str,
    /// Source held transiently until analysis runs (cleared afterwards).
    pub pending_source: &'a str,
}

pub struct CreatedScan {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
}

pub async fn create_scan(pool: &PgPool, new: NewScan<'_>) -> Result<CreatedScan, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO scans (status, input_type, filename, source_hash, ip_hash,
                            price_amount, pending_source)
         VALUES ($1, $2, $3, $4, $5, $6::numeric, $7)
         RETURNING id, created_at",
    )
    .bind(new.status.as_str())
    .bind(new.input_type)
    .bind(new.filename)
    .bind(new.source_hash)
    .bind(new.ip_hash)
    .bind(new.price_wei)
    .bind(new.pending_source)
    .fetch_one(pool)
    .await?;

    Ok(CreatedScan {
        id: row.get("id"),
        created_at: row.get("created_at"),
    })
}

pub struct ScanStatusRow {
    pub status: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub price_wei: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn get_status(pool: &PgPool, id: Uuid) -> Result<Option<ScanStatusRow>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT status, error_code, error_message, price_amount::text AS price_wei,
                created_at, updated_at
         FROM scans WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| ScanStatusRow {
        status: r.get("status"),
        error_code: r.get("error_code"),
        error_message: r.get("error_message"),
        price_wei: r.get("price_wei"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }))
}

pub struct RecentScan {
    pub id: Uuid,
    pub status: String,
    pub price_wei: String,
    pub created_at: DateTime<Utc>,
}

/// Idempotency lookup: most recent scan with the same ip_hash + source_hash
/// created within the last `window_secs` (Section 15). Used to dedupe resubmits.
pub async fn find_recent_by_hash(
    pool: &PgPool,
    ip_hash: &str,
    source_hash: &str,
    window_secs: i32,
) -> Result<Option<RecentScan>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, status, price_amount::text AS price_wei, created_at
         FROM scans
         WHERE ip_hash = $1 AND source_hash = $2
           AND created_at > now() - ($3 * interval '1 second')
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(ip_hash)
    .bind(source_hash)
    .bind(window_secs)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| RecentScan {
        id: r.get("id"),
        status: r.get("status"),
        price_wei: r.get("price_wei"),
        created_at: r.get("created_at"),
    }))
}

pub async fn set_overall_risk(pool: &PgPool, id: Uuid, risk: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE scans SET overall_risk = $2 WHERE id = $1")
        .bind(id)
        .bind(risk)
        .execute(pool)
        .await?;
    Ok(())
}

pub struct PendingScan {
    pub filename: Option<String>,
    pub source: Option<String>,
}

/// Load the transiently-stored source + filename for analysis.
pub async fn load_pending_source(pool: &PgPool, id: Uuid) -> Result<Option<PendingScan>, sqlx::Error> {
    let row = sqlx::query("SELECT filename, pending_source FROM scans WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| PendingScan {
        filename: r.get("filename"),
        source: r.get("pending_source"),
    }))
}

/// Clear the transient source once analysis is done (privacy; Section 15).
pub async fn clear_pending_source(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE scans SET pending_source = NULL WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Mark a scan paid and move it to `queued`, only if it is still
/// `awaiting_payment`. Returns true if this call performed the transition
/// (guards against duplicate payment events / reorgs).
pub async fn mark_paid(
    pool: &PgPool,
    id: Uuid,
    payer_address: &str,
    payment_tx_hash: &str,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE scans
         SET status = 'queued', payer_address = $2, payment_tx_hash = $3, paid_at = now()
         WHERE id = $1 AND status = 'awaiting_payment'",
    )
    .bind(id)
    .bind(payer_address)
    .bind(payment_tx_hash)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn get_last_processed_block(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("SELECT last_processed_block FROM chain_watcher_state WHERE id = 1")
        .fetch_one(pool)
        .await?;
    Ok(row.get("last_processed_block"))
}

pub async fn set_last_processed_block(pool: &PgPool, block: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE chain_watcher_state SET last_processed_block = $1, updated_at = now() WHERE id = 1")
        .bind(block)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_status(pool: &PgPool, id: Uuid, status: ScanStatus) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE scans SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

/// Move into `running` and stamp `started_at` (Section 12: started_at = leaving queued).
pub async fn begin_running(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE scans SET status = $2, started_at = now() WHERE id = $1")
        .bind(id)
        .bind(ScanStatus::Running.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

/// Terminal transition: set `finished_at` and derive `duration_ms`.
pub async fn finish(
    pool: &PgPool,
    id: Uuid,
    status: ScanStatus,
    error_code: Option<&str>,
    error_message: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE scans
         SET status = $2,
             error_code = $3,
             error_message = $4,
             finished_at = now(),
             duration_ms = CASE
                 WHEN started_at IS NOT NULL
                 THEN (EXTRACT(EPOCH FROM (now() - started_at)) * 1000)::bigint
                 ELSE NULL
             END
         WHERE id = $1",
    )
    .bind(id)
    .bind(status.as_str())
    .bind(error_code)
    .bind(error_message)
    .execute(pool)
    .await?;
    Ok(())
}
