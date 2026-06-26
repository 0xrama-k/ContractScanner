-- Store a structured error code (Section 13) alongside the human error_message
-- so the status API can return the precise failure code.
ALTER TABLE scans ADD COLUMN error_code TEXT;
