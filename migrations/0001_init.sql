-- Initial schema for ContractScanner (Sections 12 & 21 of PROJECT_BLUEPRINT.md).
-- The FULL schema is created here in the first migration: UUID ids, ip_hash,
-- timing columns, and the payment columns are present from day one, not retrofitted.

-- gen_random_uuid() is built into PostgreSQL 13+ (no extension needed on PG17),
-- and produces UUID v4 values, satisfying the "unguessable, never sequential" rule.

-- Auto-maintain updated_at on row updates.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- scans
-- ---------------------------------------------------------------------------
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status          TEXT NOT NULL,
    input_type      TEXT NOT NULL,
    filename        TEXT,
    source_hash     TEXT NOT NULL,
    overall_risk    TEXT,

    -- Hashed (salted) client IP for rate limiting / abuse tracking. Never the raw IP.
    ip_hash         TEXT,

    -- Payment gate (Section 21). price_amount is wei; 2^256 fits in NUMERIC(78,0).
    -- Snapshotted at creation so verification is independent of later config changes.
    price_amount    NUMERIC(78, 0) NOT NULL,
    payer_address   TEXT,
    payment_tx_hash TEXT,
    paid_at         TIMESTAMPTZ,

    -- Timing. started_at = leaving `queued`; finished_at = report_ready/failed.
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    duration_ms     BIGINT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    error_message   TEXT,

    CONSTRAINT scans_status_chk CHECK (status IN (
        'awaiting_payment', 'queued', 'running', 'analyzing_slither',
        'analyzing_llm', 'scoring', 'report_ready', 'failed'
    )),
    CONSTRAINT scans_input_type_chk CHECK (input_type IN ('pasted_code', 'uploaded_file'))
);

CREATE TRIGGER scans_set_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Reaper / status queries.
CREATE INDEX scans_status_idx ON scans (status);
-- Per-IP rate limiting (count recent scans by ip_hash).
CREATE INDEX scans_ip_created_idx ON scans (ip_hash, created_at DESC);
-- Idempotency: dedupe accidental double-submits (ip_hash + source_hash, recent window).
CREATE INDEX scans_ip_source_idx ON scans (ip_hash, source_hash);

-- ---------------------------------------------------------------------------
-- findings (common finding model, Section 6)
-- ---------------------------------------------------------------------------
CREATE TABLE findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,

    -- Per-scan display id like "FIND-001" (the model's `id`); the DB PK is the UUID above.
    finding_ref         TEXT NOT NULL,

    title               TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL,
    confidence          TEXT NOT NULL,
    status              TEXT NOT NULL,

    -- sources/evidence/score are structured -> jsonb (seam decision: Section "open items").
    sources             JSONB NOT NULL DEFAULT '["slither"]'::jsonb,
    finding_fingerprint TEXT NOT NULL,

    contract_name       TEXT,
    function_name       TEXT,
    line_start          INTEGER,
    line_end            INTEGER,

    summary             TEXT,
    technical_details   TEXT,
    exploit_scenario    TEXT,
    fix_suggestion      TEXT,
    false_positive_note TEXT,

    evidence            JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- score holds base_severity / confidence / exploitability / asset_impact / final_score.
    score               JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT findings_ref_unique UNIQUE (scan_id, finding_ref)
);

CREATE INDEX findings_scan_idx ON findings (scan_id);

-- ---------------------------------------------------------------------------
-- reports (one per scan)
-- ---------------------------------------------------------------------------
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    json_report     JSONB NOT NULL,
    markdown_report TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT reports_scan_unique UNIQUE (scan_id)
);

-- ---------------------------------------------------------------------------
-- chain_watcher_state (Section 21): single-row cursor for the PaymentWatcher.
-- ---------------------------------------------------------------------------
CREATE TABLE chain_watcher_state (
    id                   INTEGER PRIMARY KEY DEFAULT 1,
    last_processed_block BIGINT NOT NULL DEFAULT 0,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chain_watcher_singleton CHECK (id = 1)
);

INSERT INTO chain_watcher_state (id, last_processed_block) VALUES (1, 0);
