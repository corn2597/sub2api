package repository

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

const (
	riskSessionBlacklistPrefix       = "risk:session:blacklist:"
	riskSessionLastSuccessAuditPrefx = "risk:session:last_success_audit:"
	riskSessionLastAttemptPrefix     = "risk:session:last_attempt:"
	riskSessionAuditLockPrefix       = "risk:session:audit_lock:"
)

var riskSessionAuditUnlockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0
`)

func (c *contentModerationHashCache) GetRiskSessionLastSuccessAudit(ctx context.Context, sessionHash string) (*time.Time, error) {
	return c.getRiskSessionTime(ctx, riskSessionLastSuccessAuditPrefx, sessionHash)
}

func (c *contentModerationHashCache) SetRiskSessionLastSuccessAudit(ctx context.Context, sessionHash string, at time.Time, ttl time.Duration) error {
	return c.setRiskSessionTime(ctx, riskSessionLastSuccessAuditPrefx, sessionHash, at, ttl)
}

func (c *contentModerationHashCache) GetRiskSessionLastAttempt(ctx context.Context, sessionHash string) (*time.Time, error) {
	return c.getRiskSessionTime(ctx, riskSessionLastAttemptPrefix, sessionHash)
}

func (c *contentModerationHashCache) SetRiskSessionLastAttempt(ctx context.Context, sessionHash string, at time.Time, ttl time.Duration) error {
	return c.setRiskSessionTime(ctx, riskSessionLastAttemptPrefix, sessionHash, at, ttl)
}

func (c *contentModerationHashCache) AcquireRiskSessionAuditLock(ctx context.Context, sessionHash string, token string, ttl time.Duration) (bool, error) {
	sessionHash = strings.TrimSpace(sessionHash)
	token = strings.TrimSpace(token)
	if c == nil || c.rdb == nil || sessionHash == "" || token == "" {
		return false, nil
	}
	return c.rdb.SetNX(ctx, riskSessionAuditLockPrefix+sessionHash, token, ttl).Result()
}

func (c *contentModerationHashCache) HasRiskSessionAuditLock(ctx context.Context, sessionHash string) (bool, error) {
	sessionHash = strings.TrimSpace(sessionHash)
	if c == nil || c.rdb == nil || sessionHash == "" {
		return false, nil
	}
	count, err := c.rdb.Exists(ctx, riskSessionAuditLockPrefix+sessionHash).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (c *contentModerationHashCache) ReleaseRiskSessionAuditLock(ctx context.Context, sessionHash string, token string) error {
	sessionHash = strings.TrimSpace(sessionHash)
	token = strings.TrimSpace(token)
	if c == nil || c.rdb == nil || sessionHash == "" || token == "" {
		return nil
	}
	_, err := riskSessionAuditUnlockScript.Run(ctx, c.rdb, []string{riskSessionAuditLockPrefix + sessionHash}, token).Result()
	return err
}

func (c *contentModerationHashCache) GetRiskSessionBlacklistCache(ctx context.Context, sessionHash string) (*service.RiskSessionBlacklistCacheEntry, error) {
	sessionHash = strings.TrimSpace(sessionHash)
	if c == nil || c.rdb == nil || sessionHash == "" {
		return nil, nil
	}
	raw, err := c.rdb.Get(ctx, riskSessionBlacklistPrefix+sessionHash).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var entry service.RiskSessionBlacklistCacheEntry
	if err := jsonUnmarshalString(raw, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (c *contentModerationHashCache) SetRiskSessionBlacklistCache(ctx context.Context, sessionHash string, entry *service.RiskSessionBlacklistCacheEntry, ttl time.Duration) error {
	sessionHash = strings.TrimSpace(sessionHash)
	if c == nil || c.rdb == nil || sessionHash == "" || entry == nil {
		return nil
	}
	raw, err := jsonMarshalToString(entry)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, riskSessionBlacklistPrefix+sessionHash, raw, ttl).Err()
}

func (c *contentModerationHashCache) DeleteRiskSessionBlacklistCache(ctx context.Context, sessionHash string) error {
	sessionHash = strings.TrimSpace(sessionHash)
	if c == nil || c.rdb == nil || sessionHash == "" {
		return nil
	}
	return c.rdb.Del(ctx, riskSessionBlacklistPrefix+sessionHash).Err()
}

func (c *contentModerationHashCache) getRiskSessionTime(ctx context.Context, prefix string, sessionHash string) (*time.Time, error) {
	sessionHash = strings.TrimSpace(sessionHash)
	if c == nil || c.rdb == nil || sessionHash == "" {
		return nil, nil
	}
	raw, err := c.rdb.Get(ctx, prefix+sessionHash).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	unixSeconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return nil, err
	}
	at := time.Unix(unixSeconds, 0).UTC()
	return &at, nil
}

func (c *contentModerationHashCache) setRiskSessionTime(ctx context.Context, prefix string, sessionHash string, at time.Time, ttl time.Duration) error {
	sessionHash = strings.TrimSpace(sessionHash)
	if c == nil || c.rdb == nil || sessionHash == "" {
		return nil
	}
	return c.rdb.Set(ctx, prefix+sessionHash, strconv.FormatInt(at.UTC().Unix(), 10), ttl).Err()
}

func jsonMarshalToString(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func jsonUnmarshalString(raw string, dst any) error {
	return json.Unmarshal([]byte(raw), dst)
}
