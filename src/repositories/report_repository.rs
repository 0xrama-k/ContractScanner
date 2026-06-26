//! Persistence for generated reports (Section 12 `reports` table).

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Insert or replace the stored report for a scan.
pub async fn upsert_report(
    pool: &PgPool,
    scan_id: Uuid,
    json_report: &str,
    markdown_report: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO reports (scan_id, json_report, markdown_report)
         VALUES ($1, $2::jsonb, $3)
         ON CONFLICT (scan_id)
         DO UPDATE SET json_report = EXCLUDED.json_report,
                       markdown_report = EXCLUDED.markdown_report",
    )
    .bind(scan_id)
    .bind(json_report)
    .bind(markdown_report)
    .execute(pool)
    .await?;
    Ok(())
}

pub struct StoredReport {
    pub json_report: String,
    pub markdown_report: String,
}

pub async fn load_report(pool: &PgPool, scan_id: Uuid) -> Result<Option<StoredReport>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT json_report::text AS json_report, markdown_report
         FROM reports WHERE scan_id = $1",
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| StoredReport {
        json_report: r.get("json_report"),
        markdown_report: r.get("markdown_report"),
    }))
}
