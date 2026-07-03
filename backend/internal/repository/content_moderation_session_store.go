package repository

import (
	"context"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

const (
	contentModerationSessionBlockedPrefix  = "content_moderation:session_blocked:"
	contentModerationSessionAllowPrefix    = "content_moderation:session_allow:"
	contentModerationSessionInflightPrefix = "content_moderation:session_inflight:"
)

type contentModerationSessionStore struct {
	rdb *redis.Client
}

func NewContentModerationSessionStore(rdb *redis.Client) service.ContentModerationSessionStore {
	return &contentModerationSessionStore{rdb: rdb}
}

func (s *contentModerationSessionStore) IsBlocked(ctx context.Context, scope string) (bool, error) {
	return contentModerationSessionKeyExists(ctx, s.rdb, contentModerationSessionBlockedPrefix, scope)
}

func (s *contentModerationSessionStore) MarkBlocked(ctx context.Context, scope string, ttl time.Duration) error {
	return contentModerationSessionSet(ctx, s.rdb, contentModerationSessionBlockedPrefix, scope, ttl)
}

func (s *contentModerationSessionStore) HasAllowWindow(ctx context.Context, scope string) (bool, error) {
	return contentModerationSessionKeyExists(ctx, s.rdb, contentModerationSessionAllowPrefix, scope)
}

func (s *contentModerationSessionStore) MarkAllowWindow(ctx context.Context, scope string, ttl time.Duration) error {
	return contentModerationSessionSet(ctx, s.rdb, contentModerationSessionAllowPrefix, scope, ttl)
}

func (s *contentModerationSessionStore) AcquireInflight(ctx context.Context, scope string, ttl time.Duration) (bool, error) {
	scope = strings.TrimSpace(scope)
	if s == nil || s.rdb == nil || scope == "" || ttl <= 0 {
		return true, nil
	}
	return s.rdb.SetNX(ctx, contentModerationSessionInflightPrefix+scope, "1", ttl).Result()
}

func (s *contentModerationSessionStore) ClearInflight(ctx context.Context, scope string) error {
	scope = strings.TrimSpace(scope)
	if s == nil || s.rdb == nil || scope == "" {
		return nil
	}
	return s.rdb.Del(ctx, contentModerationSessionInflightPrefix+scope).Err()
}

func contentModerationSessionSet(ctx context.Context, rdb *redis.Client, prefix string, scope string, ttl time.Duration) error {
	scope = strings.TrimSpace(scope)
	if rdb == nil || scope == "" || ttl <= 0 {
		return nil
	}
	return rdb.Set(ctx, prefix+scope, "1", ttl).Err()
}

func contentModerationSessionKeyExists(ctx context.Context, rdb *redis.Client, prefix string, scope string) (bool, error) {
	scope = strings.TrimSpace(scope)
	if rdb == nil || scope == "" {
		return false, nil
	}
	n, err := rdb.Exists(ctx, prefix+scope).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
