-- Transiently hold the submitted source between scan creation (awaiting_payment)
-- and analysis start, so the payment-gated flow can run the pipeline when payment
-- is observed. Cleared (set NULL) once analysis completes. Never logged (Section 15).
ALTER TABLE scans ADD COLUMN pending_source TEXT;
