INSERT INTO settings (key, value, updated_at)
VALUES
    ('risk_control_provider', 'legacy_moderation', NOW()),
    ('audit_base_url', 'https://api.openai.com', NOW()),
    ('audit_path', '/v1/responses', NOW()),
    ('audit_model', '', NOW()),
    ('audit_api_keys', '[]', NOW()),
    ('audit_timeout_ms', '3000', NOW()),
    ('audit_fail_closed', 'false', NOW()),
    ('audit_block_confidence_threshold', '0.7', NOW()),
    ('session_audit_interval_seconds', '300', NOW()),
    ('session_blacklist_ttl_seconds', '0', NOW()),
    ('session_audit_enabled_protocols', '["anthropic_messages"]', NOW()),
    ('audit_max_input_chars', '12000', NOW()),
    ('audit_prompt_template', '', NOW())
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS risk_session_blacklists (
    id BIGSERIAL PRIMARY KEY,
    session_hash TEXT NOT NULL,
    user_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
    api_key_id BIGINT NULL REFERENCES api_keys(id) ON DELETE SET NULL,
    group_id BIGINT NULL REFERENCES groups(id) ON DELETE SET NULL,
    reason TEXT NOT NULL DEFAULT '',
    categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    audit_model TEXT NOT NULL DEFAULT '',
    audit_response_id TEXT NOT NULL DEFAULT '',
    source_protocol TEXT NOT NULL DEFAULT '',
    source_model TEXT NOT NULL DEFAULT '',
    first_blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_session_blacklists_session_hash
    ON risk_session_blacklists (session_hash);
CREATE INDEX IF NOT EXISTS idx_risk_session_blacklists_user_id
    ON risk_session_blacklists (user_id);
CREATE INDEX IF NOT EXISTS idx_risk_session_blacklists_api_key_id
    ON risk_session_blacklists (api_key_id);
CREATE INDEX IF NOT EXISTS idx_risk_session_blacklists_group_id
    ON risk_session_blacklists (group_id);
CREATE INDEX IF NOT EXISTS idx_risk_session_blacklists_expires_at
    ON risk_session_blacklists (expires_at);
CREATE INDEX IF NOT EXISTS idx_risk_session_blacklists_last_seen_at
    ON risk_session_blacklists (last_seen_at DESC);
