//! Persistence for normalized findings (Section 12 `findings` table).

use sqlx::PgPool;
use uuid::Uuid;

use crate::models::finding::Finding;

/// Insert all findings for a scan. `sources`/`evidence`/`score` are stored as
/// jsonb via `::jsonb` casts on serialized text (no extra sqlx feature needed).
pub async fn insert_findings(
    pool: &PgPool,
    scan_id: Uuid,
    findings: &[Finding],
) -> Result<(), sqlx::Error> {
    for f in findings {
        let sources = serde_json::to_string(&f.sources).unwrap_or_else(|_| "[]".to_string());
        let evidence = serde_json::to_string(&f.evidence).unwrap_or_else(|_| "[]".to_string());
        let score = serde_json::to_string(&f.score).unwrap_or_else(|_| "null".to_string());

        sqlx::query(
            "INSERT INTO findings (
                scan_id, finding_ref, title, category, severity, confidence, status,
                sources, finding_fingerprint, contract_name, function_name,
                line_start, line_end, summary, technical_details, exploit_scenario,
                fix_suggestion, false_positive_note, evidence, score
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8::jsonb, $9, $10, $11,
                $12, $13, $14, $15, $16,
                $17, $18, $19::jsonb, $20::jsonb
             )",
        )
        .bind(scan_id)
        .bind(&f.id)
        .bind(&f.title)
        .bind(&f.category)
        .bind(f.severity.as_str())
        .bind(f.confidence.as_str())
        .bind(&f.status)
        .bind(sources)
        .bind(&f.finding_fingerprint)
        .bind(f.location.contract.as_deref())
        .bind(f.location.function.as_deref())
        .bind(f.location.line_start)
        .bind(f.location.line_end)
        .bind(&f.summary)
        .bind(&f.technical_details)
        .bind(&f.exploit_scenario)
        .bind(&f.fix_suggestion)
        .bind(&f.false_positive_note)
        .bind(evidence)
        .bind(score)
        .execute(pool)
        .await?;
    }
    Ok(())
}
