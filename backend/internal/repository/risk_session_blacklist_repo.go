package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *contentModerationRepository) GetRiskSessionBlacklist(ctx context.Context, sessionHash string) (*service.RiskSessionBlacklist, error) {
	if r == nil || r.db == nil || sessionHash == "" {
		return nil, nil
	}
	row := r.db.QueryRowContext(ctx, `
SELECT
    id, session_hash, user_id, api_key_id, group_id, reason, categories, confidence,
    audit_model, audit_response_id, source_protocol, source_model, first_blocked_at,
    last_seen_at, expires_at, created_at, updated_at
FROM risk_session_blacklists
WHERE session_hash = $1
`, sessionHash)
	var entry service.RiskSessionBlacklist
	var userID, apiKeyID, groupID sql.NullInt64
	var expiresAt sql.NullTime
	var categoriesRaw []byte
	if err := row.Scan(
		&entry.ID,
		&entry.SessionHash,
		&userID,
		&apiKeyID,
		&groupID,
		&entry.Reason,
		&categoriesRaw,
		&entry.Confidence,
		&entry.AuditModel,
		&entry.AuditResponseID,
		&entry.SourceProtocol,
		&entry.SourceModel,
		&entry.FirstBlockedAt,
		&entry.LastSeenAt,
		&expiresAt,
		&entry.CreatedAt,
		&entry.UpdatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get risk session blacklist: %w", err)
	}
	if userID.Valid {
		v := userID.Int64
		entry.UserID = &v
	}
	if apiKeyID.Valid {
		v := apiKeyID.Int64
		entry.APIKeyID = &v
	}
	if groupID.Valid {
		v := groupID.Int64
		entry.GroupID = &v
	}
	if expiresAt.Valid {
		v := expiresAt.Time.UTC()
		entry.ExpiresAt = &v
	}
	_ = json.Unmarshal(categoriesRaw, &entry.Categories)
	return &entry, nil
}

func (r *contentModerationRepository) UpsertRiskSessionBlacklist(ctx context.Context, entry *service.RiskSessionBlacklist) error {
	if r == nil || r.db == nil || entry == nil {
		return nil
	}
	categories, err := json.Marshal(entry.Categories)
	if err != nil {
		return fmt.Errorf("marshal risk session blacklist categories: %w", err)
	}
	var userID any
	if entry.UserID != nil {
		userID = *entry.UserID
	}
	var apiKeyID any
	if entry.APIKeyID != nil {
		apiKeyID = *entry.APIKeyID
	}
	var groupID any
	if entry.GroupID != nil {
		groupID = *entry.GroupID
	}
	var expiresAt any
	if entry.ExpiresAt != nil {
		expiresAt = *entry.ExpiresAt
	}
	if entry.FirstBlockedAt.IsZero() {
		entry.FirstBlockedAt = time.Now().UTC()
	}
	if entry.LastSeenAt.IsZero() {
		entry.LastSeenAt = entry.FirstBlockedAt
	}
	err = r.db.QueryRowContext(ctx, `
INSERT INTO risk_session_blacklists (
    session_hash, user_id, api_key_id, group_id, reason, categories, confidence,
    audit_model, audit_response_id, source_protocol, source_model, first_blocked_at,
    last_seen_at, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6::jsonb, $7,
    $8, $9, $10, $11, $12,
    $13, $14
)
ON CONFLICT (session_hash) DO UPDATE SET
    user_id = EXCLUDED.user_id,
    api_key_id = EXCLUDED.api_key_id,
    group_id = EXCLUDED.group_id,
    reason = EXCLUDED.reason,
    categories = EXCLUDED.categories,
    confidence = EXCLUDED.confidence,
    audit_model = EXCLUDED.audit_model,
    audit_response_id = EXCLUDED.audit_response_id,
    source_protocol = EXCLUDED.source_protocol,
    source_model = EXCLUDED.source_model,
    first_blocked_at = LEAST(risk_session_blacklists.first_blocked_at, EXCLUDED.first_blocked_at),
    last_seen_at = EXCLUDED.last_seen_at,
    expires_at = EXCLUDED.expires_at,
    updated_at = NOW()
RETURNING id, created_at, updated_at
`,
		entry.SessionHash,
		userID,
		apiKeyID,
		groupID,
		entry.Reason,
		string(categories),
		entry.Confidence,
		entry.AuditModel,
		entry.AuditResponseID,
		entry.SourceProtocol,
		entry.SourceModel,
		entry.FirstBlockedAt.UTC(),
		entry.LastSeenAt.UTC(),
		expiresAt,
	).Scan(&entry.ID, &entry.CreatedAt, &entry.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert risk session blacklist: %w", err)
	}
	return nil
}

func (r *contentModerationRepository) TouchRiskSessionBlacklist(ctx context.Context, sessionHash string, lastSeenAt time.Time) error {
	if r == nil || r.db == nil || sessionHash == "" {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
UPDATE risk_session_blacklists
SET last_seen_at = $2, updated_at = NOW()
WHERE session_hash = $1
`, sessionHash, lastSeenAt.UTC())
	if err != nil {
		return fmt.Errorf("touch risk session blacklist: %w", err)
	}
	return nil
}

func (r *contentModerationRepository) DeleteRiskSessionBlacklist(ctx context.Context, sessionHash string) error {
	if r == nil || r.db == nil || sessionHash == "" {
		return nil
	}
	if _, err := r.db.ExecContext(ctx, `DELETE FROM risk_session_blacklists WHERE session_hash = $1`, sessionHash); err != nil {
		return fmt.Errorf("delete risk session blacklist: %w", err)
	}
	return nil
}
