-- Complete HTTP2WS error payload capture for short-lived production diagnostics.
-- Payload bytes are stored separately from ops_error_logs so normal error list
-- queries never read or materialize large user request bodies.

CREATE TABLE IF NOT EXISTS ops_error_payload_blobs (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    payload_kind VARCHAR(16) NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    payload_bytes BIGINT NOT NULL,
    payload_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ops_error_payload_blobs_kind_check CHECK (payload_kind IN ('http', 'ws')),
    CONSTRAINT ops_error_payload_blobs_size_check CHECK (payload_bytes >= 0),
    CONSTRAINT ops_error_payload_blobs_request_kind_sha_key UNIQUE (request_id, payload_kind, payload_sha256)
);

CREATE TABLE IF NOT EXISTS ops_error_payload_attempts (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    sequence_no INT NOT NULL,
    payload_id BIGINT NOT NULL REFERENCES ops_error_payload_blobs(id) ON DELETE CASCADE,
    attempt_no INT NOT NULL,
    account_id BIGINT,
    conn_id VARCHAR(128),
    connection_reused BOOLEAN NOT NULL DEFAULT false,
    write_succeeded BOOLEAN NOT NULL DEFAULT false,
    write_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ops_error_payload_attempts_sequence_check CHECK (sequence_no > 0),
    CONSTRAINT ops_error_payload_attempts_attempt_check CHECK (attempt_no > 0),
    CONSTRAINT ops_error_payload_attempts_request_sequence_key UNIQUE (request_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_ops_error_payload_blobs_request_id
    ON ops_error_payload_blobs (request_id);

CREATE INDEX IF NOT EXISTS idx_ops_error_payload_blobs_created_at
    ON ops_error_payload_blobs (created_at);

CREATE INDEX IF NOT EXISTS idx_ops_error_payload_attempts_payload_id
    ON ops_error_payload_attempts (payload_id, sequence_no);

COMMENT ON TABLE ops_error_payload_blobs IS
    'Short-lived, administrator-only full HTTP2WS request payloads captured only after final request failure.';
COMMENT ON COLUMN ops_error_payload_blobs.payload_data IS
    'Exact untruncated request bytes. PostgreSQL may transparently TOAST-compress this value.';
