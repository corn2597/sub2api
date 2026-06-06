//go:build unit

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestContentModerationHashCache_SessionAuditState(t *testing.T) {
	cache, _ := newMiniRedisCache(t)
	hashCache := &contentModerationHashCache{rdb: cache.rdb}
	ctx := context.Background()

	now := time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC)
	require.NoError(t, hashCache.SetRiskSessionLastSuccessAudit(ctx, "hash-1", now, time.Minute))
	gotSuccess, err := hashCache.GetRiskSessionLastSuccessAudit(ctx, "hash-1")
	require.NoError(t, err)
	require.NotNil(t, gotSuccess)
	require.True(t, gotSuccess.Equal(now))

	require.NoError(t, hashCache.SetRiskSessionLastAttempt(ctx, "hash-1", now.Add(time.Second), time.Minute))
	gotAttempt, err := hashCache.GetRiskSessionLastAttempt(ctx, "hash-1")
	require.NoError(t, err)
	require.NotNil(t, gotAttempt)
	require.True(t, gotAttempt.Equal(now.Add(time.Second)))

	ok, err := hashCache.AcquireRiskSessionAuditLock(ctx, "hash-1", "token-1", time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = hashCache.AcquireRiskSessionAuditLock(ctx, "hash-1", "token-2", time.Minute)
	require.NoError(t, err)
	require.False(t, ok)
	locked, err := hashCache.HasRiskSessionAuditLock(ctx, "hash-1")
	require.NoError(t, err)
	require.True(t, locked)
	require.NoError(t, hashCache.ReleaseRiskSessionAuditLock(ctx, "hash-1", "token-1"))
	locked, err = hashCache.HasRiskSessionAuditLock(ctx, "hash-1")
	require.NoError(t, err)
	require.False(t, locked)

	entry := &service.RiskSessionBlacklistCacheEntry{
		SessionHash:    "hash-1",
		Reason:         "reason",
		Categories:     []string{"aup"},
		Confidence:     0.9,
		SourceProtocol: service.ContentModerationProtocolAnthropicMessages,
		SourceModel:    "claude-sonnet-4-5",
		FirstBlockedAt: now,
		LastSeenAt:     now,
	}
	require.NoError(t, hashCache.SetRiskSessionBlacklistCache(ctx, "hash-1", entry, time.Minute))
	gotEntry, err := hashCache.GetRiskSessionBlacklistCache(ctx, "hash-1")
	require.NoError(t, err)
	require.NotNil(t, gotEntry)
	require.Equal(t, entry.SessionHash, gotEntry.SessionHash)
	require.Equal(t, entry.Categories, gotEntry.Categories)
	require.NoError(t, hashCache.DeleteRiskSessionBlacklistCache(ctx, "hash-1"))
	gotEntry, err = hashCache.GetRiskSessionBlacklistCache(ctx, "hash-1")
	require.NoError(t, err)
	require.Nil(t, gotEntry)
}
