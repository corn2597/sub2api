package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestContentModerationRepository_GetRiskSessionBlacklist(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	now := time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta("FROM risk_session_blacklists")).
		WithArgs("hash-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "session_hash", "user_id", "api_key_id", "group_id", "reason", "categories", "confidence",
			"audit_model", "audit_response_id", "source_protocol", "source_model", "first_blocked_at",
			"last_seen_at", "expires_at", "created_at", "updated_at",
		}).AddRow(
			int64(1), "hash-1", int64(2), int64(3), int64(4), "reason", `["aup"]`, 0.9,
			"gpt-5-mini", "resp_1", service.ContentModerationProtocolAnthropicMessages, "claude", now,
			now, now.Add(time.Hour), now, now,
		))

	entry, err := repo.GetRiskSessionBlacklist(context.Background(), "hash-1")
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, "hash-1", entry.SessionHash)
	require.Equal(t, []string{"aup"}, entry.Categories)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestContentModerationRepository_UpsertTouchDeleteRiskSessionBlacklist(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	now := time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC)
	entry := &service.RiskSessionBlacklist{
		SessionHash:     "hash-1",
		UserID:          serviceInt64Ptr(2),
		APIKeyID:        serviceInt64Ptr(3),
		GroupID:         serviceInt64Ptr(4),
		Reason:          "reason",
		Categories:      []string{"aup"},
		Confidence:      0.9,
		AuditModel:      "gpt-5-mini",
		AuditResponseID: "resp_1",
		SourceProtocol:  service.ContentModerationProtocolAnthropicMessages,
		SourceModel:     "claude",
		FirstBlockedAt:  now,
		LastSeenAt:      now,
	}
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO risk_session_blacklists")).
		WithArgs(
			entry.SessionHash,
			*entry.UserID,
			*entry.APIKeyID,
			*entry.GroupID,
			entry.Reason,
			`["aup"]`,
			entry.Confidence,
			entry.AuditModel,
			entry.AuditResponseID,
			entry.SourceProtocol,
			entry.SourceModel,
			entry.FirstBlockedAt,
			entry.LastSeenAt,
			nil,
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(int64(1), now, now))
	require.NoError(t, repo.UpsertRiskSessionBlacklist(context.Background(), entry))

	mock.ExpectExec(regexp.QuoteMeta("UPDATE risk_session_blacklists")).
		WithArgs(entry.SessionHash, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, repo.TouchRiskSessionBlacklist(context.Background(), entry.SessionHash, now))

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM risk_session_blacklists WHERE session_hash = $1")).
		WithArgs(entry.SessionHash).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, repo.DeleteRiskSessionBlacklist(context.Background(), entry.SessionHash))
	require.NoError(t, mock.ExpectationsWereMet())
}

func serviceInt64Ptr(v int64) *int64 {
	return &v
}
