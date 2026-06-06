-- Persist sanitized audit reasons for risk-control review records.
ALTER TABLE content_moderation_logs
    ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';
