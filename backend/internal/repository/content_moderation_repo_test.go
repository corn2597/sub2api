package repository

import (
	"context"
	"database/sql/driver"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestContentModerationRepositoryCreateAndListLogs_IncludesReason(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	ctx := context.Background()
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	latency := 123
	queueDelay := 7
	userID := int64(1001)
	apiKeyID := int64(2002)
	groupID := int64(3003)
	log := &service.ContentModerationLog{
		RequestID:         "req-1",
		UserID:            &userID,
		UserEmail:         "user@example.com",
		APIKeyID:          &apiKeyID,
		APIKeyName:        "key-name",
		GroupID:           &groupID,
		GroupName:         "group-name",
		Endpoint:          "/v1/messages",
		Provider:          "anthropic",
		Model:             "claude-sonnet-4-5",
		Mode:              service.ContentModerationModePreBlock,
		Action:            service.ContentModerationActionBlock,
		Flagged:           true,
		HighestCategory:   "unauthorized_access",
		HighestScore:      0.98,
		CategoryScores:    map[string]float64{"unauthorized_access": 0.98},
		ThresholdSnapshot: map[string]float64{"unauthorized_access": 0.7},
		InputExcerpt:      "session_hash: hash-1",
		Reason:            "relay access violation",
		UpstreamLatencyMS: &latency,
		QueueDelayMS:      &queueDelay,
	}

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO content_moderation_logs")).
		WithArgs(
			log.RequestID,
			*log.UserID,
			log.UserEmail,
			*log.APIKeyID,
			log.APIKeyName,
			*log.GroupID,
			log.GroupName,
			log.Endpoint,
			log.Provider,
			log.Model,
			log.Mode,
			log.Action,
			log.Flagged,
			log.HighestCategory,
			log.HighestScore,
			jsonStringArg(`{"unauthorized_access":0.98}`),
			jsonStringArg(`{"unauthorized_access":0.7}`),
			log.InputExcerpt,
			log.Reason,
			latency,
			log.Error,
			log.ViolationCount,
			log.AutoBanned,
			log.EmailSent,
			queueDelay,
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(int64(55), now))
	require.NoError(t, repo.CreateLog(ctx, log))
	require.Equal(t, int64(55), log.ID)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM content_moderation_logs l WHERE l.id IS NOT NULL AND (l.request_id ILIKE $1 OR l.user_email ILIKE $2 OR l.api_key_name ILIKE $3 OR l.model ILIKE $4 OR l.input_excerpt ILIKE $5 OR l.reason ILIKE $6)")).
		WithArgs("%relay%", "%relay%", "%relay%", "%relay%", "%relay%", "%relay%").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	mock.ExpectQuery(regexp.QuoteMeta("FROM content_moderation_logs l")).
		WithArgs("%relay%", "%relay%", "%relay%", "%relay%", "%relay%", "%relay%", 20, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "user_id", "user_email", "api_key_id", "api_key_name", "group_id", "group_name",
			"endpoint", "provider", "model", "mode", "action", "flagged", "highest_category", "highest_score",
			"category_scores", "threshold_snapshot", "input_excerpt", "reason", "upstream_latency_ms", "error",
			"violation_count", "auto_banned", "email_sent", "user_status", "queue_delay_ms", "created_at",
		}).AddRow(
			int64(55), "req-1", userID, "user@example.com", apiKeyID, "key-name", groupID, "group-name",
			"/v1/messages", "anthropic", "claude-sonnet-4-5", service.ContentModerationModePreBlock,
			service.ContentModerationActionBlock, true, "unauthorized_access", 0.98,
			[]byte(`{"unauthorized_access":0.98}`), []byte(`{"unauthorized_access":0.7}`),
			"session_hash: hash-1", "relay access violation", latency, "",
			1, false, false, "active", queueDelay, now,
		))

	items, page, err := repo.ListLogs(ctx, service.ContentModerationLogFilter{
		Search: "relay",
		Pagination: pagination.PaginationParams{
			Page:     1,
			PageSize: 20,
		},
	})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "relay access violation", items[0].Reason)
	require.Equal(t, int64(1), page.Total)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestBuildContentModerationLogWhere_BlockedIncludesAllBlockActions(t *testing.T) {
	where, args := buildContentModerationLogWhere(service.ContentModerationLogFilter{Result: "blocked"})

	require.Empty(t, args)
	sql := strings.Join(where, " AND ")
	require.Contains(t, sql, "l.action IN ('block', 'keyword_block', 'hash_block')")
	require.NotContains(t, sql, "l.action = 'block'")
}

type jsonStringArg string

func (j jsonStringArg) Match(v driver.Value) bool {
	actual, ok := v.(string)
	if !ok {
		return false
	}
	return jsonEqualString(actual, string(j))
}

func jsonEqualString(a, b string) bool {
	return strings.ReplaceAll(a, " ", "") == strings.ReplaceAll(b, " ", "")
}

func TestContentModerationRepositoryCountFlaggedByUserSince_ExcludesHashBlock(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	since := time.Now().Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("AND action <> 'hash_block'")).
		WithArgs(int64(1001), since).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	count, err := repo.CountFlaggedByUserSince(context.Background(), 1001, since)

	require.NoError(t, err)
	require.Equal(t, 2, count)
	require.NoError(t, mock.ExpectationsWereMet())
}
