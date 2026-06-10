package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type contentModerationTestSettingRepo struct {
	values map[string]string
}

func (r *contentModerationTestSettingRepo) Get(ctx context.Context, key string) (*Setting, error) {
	if value, ok := r.values[key]; ok {
		return &Setting{Key: key, Value: value}, nil
	}
	return nil, ErrSettingNotFound
}

func (r *contentModerationTestSettingRepo) GetValue(ctx context.Context, key string) (string, error) {
	if value, ok := r.values[key]; ok {
		return value, nil
	}
	return "", ErrSettingNotFound
}

func (r *contentModerationTestSettingRepo) Set(ctx context.Context, key, value string) error {
	if r.values == nil {
		r.values = map[string]string{}
	}
	r.values[key] = value
	return nil
}

func (r *contentModerationTestSettingRepo) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	out := map[string]string{}
	for _, key := range keys {
		if value, ok := r.values[key]; ok {
			out[key] = value
		}
	}
	return out, nil
}

func (r *contentModerationTestSettingRepo) SetMultiple(ctx context.Context, settings map[string]string) error {
	if r.values == nil {
		r.values = map[string]string{}
	}
	for key, value := range settings {
		r.values[key] = value
	}
	return nil
}

func (r *contentModerationTestSettingRepo) GetAll(ctx context.Context) (map[string]string, error) {
	out := make(map[string]string, len(r.values))
	for key, value := range r.values {
		out[key] = value
	}
	return out, nil
}

func (r *contentModerationTestSettingRepo) Delete(ctx context.Context, key string) error {
	delete(r.values, key)
	return nil
}

type contentModerationTestRepo struct {
	mu         sync.Mutex
	logs       []ContentModerationLog
	blacklists map[string]RiskSessionBlacklist
}

func (r *contentModerationTestRepo) CreateLog(ctx context.Context, log *ContentModerationLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if log != nil {
		r.logs = append(r.logs, *log)
	}
	return nil
}

func (r *contentModerationTestRepo) ListLogs(ctx context.Context, filter ContentModerationLogFilter) ([]ContentModerationLog, *pagination.PaginationResult, error) {
	return nil, nil, nil
}

func (r *contentModerationTestRepo) CountFlaggedByUserSince(ctx context.Context, userID int64, since time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, log := range r.logs {
		if log.UserID == nil || *log.UserID != userID || !log.Flagged || log.Action == ContentModerationActionHashBlock {
			continue
		}
		if log.CreatedAt.IsZero() || log.CreatedAt.Before(since) {
			continue
		}
		count++
	}
	return count, nil
}

func (r *contentModerationTestRepo) CleanupExpiredLogs(ctx context.Context, hitBefore time.Time, nonHitBefore time.Time) (*ContentModerationCleanupResult, error) {
	return &ContentModerationCleanupResult{}, nil
}

func (r *contentModerationTestRepo) GetRiskSessionBlacklist(ctx context.Context, sessionHash string) (*RiskSessionBlacklist, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blacklists == nil {
		return nil, nil
	}
	entry, ok := r.blacklists[sessionHash]
	if !ok {
		return nil, nil
	}
	clone := entry
	clone.Categories = append([]string(nil), entry.Categories...)
	clone.ExpiresAt = cloneTimePtr(entry.ExpiresAt)
	return &clone, nil
}

func (r *contentModerationTestRepo) UpsertRiskSessionBlacklist(ctx context.Context, entry *RiskSessionBlacklist) error {
	if entry == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blacklists == nil {
		r.blacklists = map[string]RiskSessionBlacklist{}
	}
	clone := *entry
	clone.Categories = append([]string(nil), entry.Categories...)
	clone.ExpiresAt = cloneTimePtr(entry.ExpiresAt)
	r.blacklists[entry.SessionHash] = clone
	return nil
}

func (r *contentModerationTestRepo) TouchRiskSessionBlacklist(ctx context.Context, sessionHash string, lastSeenAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blacklists == nil {
		return nil
	}
	entry, ok := r.blacklists[sessionHash]
	if !ok {
		return nil
	}
	entry.LastSeenAt = lastSeenAt
	r.blacklists[sessionHash] = entry
	return nil
}

func (r *contentModerationTestRepo) DeleteRiskSessionBlacklist(ctx context.Context, sessionHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blacklists != nil {
		delete(r.blacklists, sessionHash)
	}
	return nil
}

func (r *contentModerationTestRepo) snapshotLogs() []ContentModerationLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ContentModerationLog, len(r.logs))
	copy(out, r.logs)
	return out
}

func requireContentModerationLogCount(t *testing.T, repo *contentModerationTestRepo, want int) []ContentModerationLog {
	t.Helper()
	var logs []ContentModerationLog
	require.Eventually(t, func() bool {
		logs = repo.snapshotLogs()
		return len(logs) == want
	}, time.Second, 10*time.Millisecond)
	return logs
}

func requireRecordedHashCount(t *testing.T, cache *contentModerationTestHashCache, want int) []string {
	t.Helper()
	var hashes []string
	require.Eventually(t, func() bool {
		hashes = cache.snapshotRecorded()
		return len(hashes) == want
	}, time.Second, 10*time.Millisecond)
	return hashes
}

type contentModerationTestHashCache struct {
	mu            sync.Mutex
	hashes        map[string]struct{}
	recorded      []string
	checked       []string
	deleted       []string
	hasResult     bool
	hasResultUsed bool
	lastSuccess   map[string]time.Time
	lastAttempt   map[string]time.Time
	locks         map[string]string
	blacklists    map[string]RiskSessionBlacklistCacheEntry
}

type contentModerationTestUserRepo struct {
	user    *User
	updated []User
}

func (r *contentModerationTestUserRepo) Create(ctx context.Context, user *User) error {
	panic("unexpected Create call")
}

func (r *contentModerationTestUserRepo) GetByID(ctx context.Context, id int64) (*User, error) {
	if r.user == nil {
		return nil, ErrUserNotFound
	}
	clone := *r.user
	return &clone, nil
}

func (r *contentModerationTestUserRepo) GetByEmail(ctx context.Context, email string) (*User, error) {
	panic("unexpected GetByEmail call")
}

func (r *contentModerationTestUserRepo) GetFirstAdmin(ctx context.Context) (*User, error) {
	panic("unexpected GetFirstAdmin call")
}

func (r *contentModerationTestUserRepo) Update(ctx context.Context, user *User) error {
	if user == nil {
		return nil
	}
	clone := *user
	r.updated = append(r.updated, clone)
	r.user = &clone
	return nil
}

func (r *contentModerationTestUserRepo) Delete(ctx context.Context, id int64) error {
	panic("unexpected Delete call")
}

func (r *contentModerationTestUserRepo) GetUserAvatar(ctx context.Context, userID int64) (*UserAvatar, error) {
	panic("unexpected GetUserAvatar call")
}

func (r *contentModerationTestUserRepo) UpsertUserAvatar(ctx context.Context, userID int64, input UpsertUserAvatarInput) (*UserAvatar, error) {
	panic("unexpected UpsertUserAvatar call")
}

func (r *contentModerationTestUserRepo) DeleteUserAvatar(ctx context.Context, userID int64) error {
	panic("unexpected DeleteUserAvatar call")
}

func (r *contentModerationTestUserRepo) List(ctx context.Context, params pagination.PaginationParams) ([]User, *pagination.PaginationResult, error) {
	panic("unexpected List call")
}

func (r *contentModerationTestUserRepo) ListWithFilters(ctx context.Context, params pagination.PaginationParams, filters UserListFilters) ([]User, *pagination.PaginationResult, error) {
	panic("unexpected ListWithFilters call")
}

func (r *contentModerationTestUserRepo) GetLatestUsedAtByUserIDs(ctx context.Context, userIDs []int64) (map[int64]*time.Time, error) {
	panic("unexpected GetLatestUsedAtByUserIDs call")
}

func (r *contentModerationTestUserRepo) GetLatestUsedAtByUserID(ctx context.Context, userID int64) (*time.Time, error) {
	panic("unexpected GetLatestUsedAtByUserID call")
}

func (r *contentModerationTestUserRepo) UpdateUserLastActiveAt(ctx context.Context, userID int64, activeAt time.Time) error {
	panic("unexpected UpdateUserLastActiveAt call")
}

func (r *contentModerationTestUserRepo) UpdateBalance(ctx context.Context, id int64, amount float64) error {
	panic("unexpected UpdateBalance call")
}

func (r *contentModerationTestUserRepo) DeductBalance(ctx context.Context, id int64, amount float64) error {
	panic("unexpected DeductBalance call")
}

func (r *contentModerationTestUserRepo) UpdateConcurrency(ctx context.Context, id int64, amount int) error {
	panic("unexpected UpdateConcurrency call")
}

func (r *contentModerationTestUserRepo) BatchSetConcurrency(ctx context.Context, userIDs []int64, value int) (int, error) {
	panic("unexpected BatchSetConcurrency call")
}

func (r *contentModerationTestUserRepo) BatchAddConcurrency(ctx context.Context, userIDs []int64, delta int) (int, error) {
	panic("unexpected BatchAddConcurrency call")
}

func (r *contentModerationTestUserRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	panic("unexpected ExistsByEmail call")
}

func (r *contentModerationTestUserRepo) RemoveGroupFromAllowedGroups(ctx context.Context, groupID int64) (int64, error) {
	panic("unexpected RemoveGroupFromAllowedGroups call")
}

func (r *contentModerationTestUserRepo) AddGroupToAllowedGroups(ctx context.Context, userID int64, groupID int64) error {
	panic("unexpected AddGroupToAllowedGroups call")
}

func (r *contentModerationTestUserRepo) RemoveGroupFromUserAllowedGroups(ctx context.Context, userID int64, groupID int64) error {
	panic("unexpected RemoveGroupFromUserAllowedGroups call")
}

func (r *contentModerationTestUserRepo) ListUserAuthIdentities(ctx context.Context, userID int64) ([]UserAuthIdentityRecord, error) {
	panic("unexpected ListUserAuthIdentities call")
}

func (r *contentModerationTestUserRepo) UnbindUserAuthProvider(ctx context.Context, userID int64, provider string) error {
	panic("unexpected UnbindUserAuthProvider call")
}

func (r *contentModerationTestUserRepo) UpdateTotpSecret(ctx context.Context, userID int64, encryptedSecret *string) error {
	panic("unexpected UpdateTotpSecret call")
}

func (r *contentModerationTestUserRepo) EnableTotp(ctx context.Context, userID int64) error {
	panic("unexpected EnableTotp call")
}

func (r *contentModerationTestUserRepo) DisableTotp(ctx context.Context, userID int64) error {
	panic("unexpected DisableTotp call")
}

func (r *contentModerationTestUserRepo) GetByIDIncludeDeleted(ctx context.Context, id int64) (*User, error) {
	return r.GetByID(ctx, id)
}

type contentModerationTestAuthCacheInvalidator struct {
	userIDs []int64
}

func (i *contentModerationTestAuthCacheInvalidator) InvalidateAuthCacheByKey(ctx context.Context, key string) {
}

func (i *contentModerationTestAuthCacheInvalidator) InvalidateAuthCacheByUserID(ctx context.Context, userID int64) {
	i.userIDs = append(i.userIDs, userID)
}

func (i *contentModerationTestAuthCacheInvalidator) InvalidateAuthCacheByGroupID(ctx context.Context, groupID int64) {
}

func (c *contentModerationTestHashCache) RecordFlaggedInputHash(ctx context.Context, inputHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hashes == nil {
		c.hashes = map[string]struct{}{}
	}
	c.hashes[inputHash] = struct{}{}
	c.recorded = append(c.recorded, inputHash)
	return nil
}

func (c *contentModerationTestHashCache) HasFlaggedInputHash(ctx context.Context, inputHash string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checked = append(c.checked, inputHash)
	if c.hasResultUsed {
		return c.hasResult, nil
	}
	_, ok := c.hashes[inputHash]
	return ok, nil
}

func (c *contentModerationTestHashCache) DeleteFlaggedInputHash(ctx context.Context, inputHash string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleted = append(c.deleted, inputHash)
	if c.hashes == nil {
		return false, nil
	}
	if _, ok := c.hashes[inputHash]; !ok {
		return false, nil
	}
	delete(c.hashes, inputHash)
	return true, nil
}

func (c *contentModerationTestHashCache) ClearFlaggedInputHashes(ctx context.Context) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deleted := int64(len(c.hashes))
	c.hashes = map[string]struct{}{}
	return deleted, nil
}

func (c *contentModerationTestHashCache) CountFlaggedInputHashes(ctx context.Context) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int64(len(c.hashes)), nil
}

func (c *contentModerationTestHashCache) GetRiskSessionLastSuccessAudit(ctx context.Context, sessionHash string) (*time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastSuccess == nil {
		return nil, nil
	}
	at, ok := c.lastSuccess[sessionHash]
	if !ok {
		return nil, nil
	}
	v := at
	return &v, nil
}

func (c *contentModerationTestHashCache) SetRiskSessionLastSuccessAudit(ctx context.Context, sessionHash string, at time.Time, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastSuccess == nil {
		c.lastSuccess = map[string]time.Time{}
	}
	c.lastSuccess[sessionHash] = at
	return nil
}

func (c *contentModerationTestHashCache) GetRiskSessionLastAttempt(ctx context.Context, sessionHash string) (*time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastAttempt == nil {
		return nil, nil
	}
	at, ok := c.lastAttempt[sessionHash]
	if !ok {
		return nil, nil
	}
	v := at
	return &v, nil
}

func (c *contentModerationTestHashCache) SetRiskSessionLastAttempt(ctx context.Context, sessionHash string, at time.Time, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastAttempt == nil {
		c.lastAttempt = map[string]time.Time{}
	}
	c.lastAttempt[sessionHash] = at
	return nil
}

func (c *contentModerationTestHashCache) AcquireRiskSessionAuditLock(ctx context.Context, sessionHash string, token string, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.locks == nil {
		c.locks = map[string]string{}
	}
	if _, ok := c.locks[sessionHash]; ok {
		return false, nil
	}
	c.locks[sessionHash] = token
	return true, nil
}

func (c *contentModerationTestHashCache) HasRiskSessionAuditLock(ctx context.Context, sessionHash string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.locks == nil {
		return false, nil
	}
	_, ok := c.locks[sessionHash]
	return ok, nil
}

func (c *contentModerationTestHashCache) ReleaseRiskSessionAuditLock(ctx context.Context, sessionHash string, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.locks == nil {
		return nil
	}
	if existing, ok := c.locks[sessionHash]; ok && existing == token {
		delete(c.locks, sessionHash)
	}
	return nil
}

func (c *contentModerationTestHashCache) GetRiskSessionBlacklistCache(ctx context.Context, sessionHash string) (*RiskSessionBlacklistCacheEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blacklists == nil {
		return nil, nil
	}
	entry, ok := c.blacklists[sessionHash]
	if !ok {
		return nil, nil
	}
	clone := entry
	clone.Categories = append([]string(nil), entry.Categories...)
	clone.ExpiresAt = cloneTimePtr(entry.ExpiresAt)
	return &clone, nil
}

func (c *contentModerationTestHashCache) SetRiskSessionBlacklistCache(ctx context.Context, sessionHash string, entry *RiskSessionBlacklistCacheEntry, ttl time.Duration) error {
	if entry == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blacklists == nil {
		c.blacklists = map[string]RiskSessionBlacklistCacheEntry{}
	}
	clone := *entry
	clone.Categories = append([]string(nil), entry.Categories...)
	clone.ExpiresAt = cloneTimePtr(entry.ExpiresAt)
	c.blacklists[sessionHash] = clone
	return nil
}

func (c *contentModerationTestHashCache) DeleteRiskSessionBlacklistCache(ctx context.Context, sessionHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blacklists != nil {
		delete(c.blacklists, sessionHash)
	}
	return nil
}

type sessionAuditClientStub struct {
	calls   atomic.Int32
	handler func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error)
}

func (s *sessionAuditClientStub) Audit(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
	s.calls.Add(1)
	if s.handler == nil {
		return &OpenAIResponsesSessionAuditResult{RecommendedAction: ContentModerationActionAllow}, nil
	}
	return s.handler(ctx, cfg, req)
}

func (s *sessionAuditClientStub) callCount() int {
	return int(s.calls.Load())
}

type fakeAuditClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeAuditClock(start time.Time) *fakeAuditClock {
	return &fakeAuditClock{now: start.UTC()}
}

func (c *fakeAuditClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeAuditClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *contentModerationTestHashCache) snapshotRecorded() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.recorded))
	copy(out, c.recorded)
	return out
}

func (c *contentModerationTestHashCache) snapshotChecked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.checked))
	copy(out, c.checked)
	return out
}

func (c *contentModerationTestHashCache) hasHash(inputHash string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.hashes[inputHash]
	return ok
}

func (c *contentModerationTestHashCache) snapshotDeleted() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.deleted))
	copy(out, c.deleted)
	return out
}

func TestBuildContentModerationLog_RedactsInputExcerpt(t *testing.T) {
	svc := &ContentModerationService{}
	cfg := defaultContentModerationConfig()
	input := ContentModerationCheckInput{
		RequestID: "req-1",
		Endpoint:  "/v1/chat/completions",
		Provider:  "openai",
	}

	log := svc.buildLog(input, cfg, ContentModerationActionAllow, true, "sexual", 0.8, map[string]float64{"sexual": 0.8}, "hello sk-proj-1234567890abcdef", nil, nil, "")

	require.NotContains(t, log.InputExcerpt, "sk-proj-1234567890abcdef")
	require.Contains(t, log.InputExcerpt, "[已脱敏]")
}

func TestRedactContentModerationSecrets_LongHexAndTokens(t *testing.T) {
	input := "你哈市多大事cf5bbdc4cd508f3aaf0d2070d529d4a4ac29099f8ecc357f696df28e1df91554 token=abc123456789xyz Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart https://example.com/private/path?token=abc123"

	out := redactContentModerationSecrets(input)

	require.NotContains(t, out, "cf5bbdc4cd508f3aaf0d2070d529d4a4ac29099f8ecc357f696df28e1df91554")
	require.NotContains(t, out, "abc123456789xyz")
	require.NotContains(t, out, "eyJhbGciOiJIUzI1NiJ9")
	require.NotContains(t, out, "https://example.com/private/path")
	require.Contains(t, out, "[已脱敏]")
}

func TestContentModerationConfigNormalize_NonHitRetentionMaxThreeDays(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.NonHitRetentionDays = 30

	cfg.normalize()

	require.Equal(t, 3, cfg.NonHitRetentionDays)
}

func TestNormalizeBlockedKeywords_TrimsDedupesAndCaps(t *testing.T) {
	out := normalizeBlockedKeywords([]string{"  foo ", "FOO", "", "bar", "baz", "bar"})
	require.Equal(t, []string{"foo", "bar", "baz"}, out)
}

func TestMatchBlockedKeyword_CaseInsensitiveSubstring(t *testing.T) {
	keyword, hit := matchBlockedKeyword("Please ignore the BadWord here", []string{"badword"})
	require.True(t, hit)
	require.Equal(t, "badword", keyword)

	_, hit = matchBlockedKeyword("clean prompt", []string{"badword"})
	require.False(t, hit)

	_, hit = matchBlockedKeyword("anything", nil)
	require.False(t, hit)
}

func TestContentModerationCheck_PreBlockKeywordHitSkipsUpstreamCall(t *testing.T) {
	upstreamCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{Results: []moderationAPIResult{{}}})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.BlockedKeywords = []string{"secret-token"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	body := []byte(`{"messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`)
	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Body:     body,
	})

	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionKeywordBlock, decision.Action)
	require.False(t, upstreamCalled, "keyword block must short-circuit upstream moderation call")
	logs := requireContentModerationLogCount(t, repo, 1)
	require.True(t, logs[0].Flagged)
	require.Equal(t, ContentModerationActionKeywordBlock, logs[0].Action)
	require.Equal(t, contentModerationKeywordCategory, logs[0].HighestCategory)
}

func TestSessionAuditExtractSessionHashPriority(t *testing.T) {
	svc := NewContentModerationService(nil, nil, &contentModerationTestHashCache{}, nil, nil, nil, nil)
	body := []byte(`{"metadata":{"user_id":"{\"device_id\":\"dev\",\"account_uuid\":\"\",\"session_id\":\"meta-session\"}","session_id":"body-session"}}`)

	hash, source, err := svc.extractSessionAuditHash(ContentModerationCheckInput{
		Headers: http.Header{
			"session_id":   []string{"header-session"},
			"x-session-id": []string{"header-session-2"},
		},
		Body: body,
	})
	require.NoError(t, err)
	require.Equal(t, sha256HexString("header-session"), hash)
	require.Equal(t, "header", source)

	hash, source, err = svc.extractSessionAuditHash(ContentModerationCheckInput{
		Headers: http.Header{},
		Body:    body,
	})
	require.NoError(t, err)
	require.Equal(t, sha256HexString("meta-session"), hash)
	require.Equal(t, "metadata.user_id", source)

	hash, source, err = svc.extractSessionAuditHash(ContentModerationCheckInput{
		Headers: http.Header{},
		Body:    []byte(`{"metadata":{"user_id":{"device_id":"dev","session_id":"object-session"}}}`),
	})
	require.NoError(t, err)
	require.Equal(t, sha256HexString("object-session"), hash)
	require.Equal(t, "metadata.user_id", source)
}

func TestContentModerationCheck_SessionAuditFirstAuditAndInterval(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	settingRepo := &contentModerationTestSettingRepo{values: map[string]string{
		SettingKeyRiskControlEnabled:            "true",
		SettingKeyContentModerationConfig:       string(rawCfg),
		SettingKeyRiskControlProvider:           RiskControlProviderOpenAIResponsesSessionAudit,
		SettingKeyAuditModel:                    "gpt-5-mini",
		SettingKeyAuditAPIKeys:                  `["sk-audit"]`,
		SettingKeySessionAuditEnabledProtocols:  `["anthropic_messages"]`,
		SettingKeySessionAuditIntervalSeconds:   "300",
		SettingKeyAuditBlockConfidenceThreshold: "0.7",
		SettingKeyAuditTimeoutMS:                "3000",
	}}
	repo := &contentModerationTestRepo{}
	cache := &contentModerationTestHashCache{}
	clock := newFakeAuditClock(time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC))
	client := &sessionAuditClientStub{
		handler: func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
			return &OpenAIResponsesSessionAuditResult{
				Violates:          false,
				Confidence:        0.1,
				Categories:        nil,
				Reason:            "",
				RecommendedAction: ContentModerationActionAllow,
			}, nil
		},
	}
	svc := NewContentModerationService(settingRepo, repo, cache, nil, nil, nil, nil)
	svc.sessionAuditClient = client
	svc.now = clock.Now
	svc.sleep = func(ctx context.Context, d time.Duration) error { return nil }

	input := ContentModerationCheckInput{
		UserID:   7,
		APIKeyID: 9,
		GroupID:  int64PtrForAuditTest(12),
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Headers:  http.Header{"session_id": []string{"sess-1"}},
		Body:     []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hello"}]}`),
	}

	decision, err := svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.Equal(t, 1, client.callCount())

	decision, err = svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.Equal(t, 1, client.callCount(), "within interval should reuse success audit")

	clock.Add(5 * time.Minute)
	decision, err = svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.Equal(t, 2, client.callCount(), "after interval should re-audit")
}

func TestContentModerationCheck_SessionAuditViolationBlacklists(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	settingRepo := &contentModerationTestSettingRepo{values: map[string]string{
		SettingKeyRiskControlEnabled:            "true",
		SettingKeyContentModerationConfig:       string(rawCfg),
		SettingKeyRiskControlProvider:           RiskControlProviderOpenAIResponsesSessionAudit,
		SettingKeyAuditModel:                    "gpt-5-mini",
		SettingKeyAuditAPIKeys:                  `["sk-audit"]`,
		SettingKeySessionAuditEnabledProtocols:  `["anthropic_messages"]`,
		SettingKeyAuditBlockConfidenceThreshold: "0.7",
	}}
	repo := &contentModerationTestRepo{}
	cache := &contentModerationTestHashCache{}
	client := &sessionAuditClientStub{
		handler: func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
			return &OpenAIResponsesSessionAuditResult{
				Violates:          true,
				Confidence:        0.91,
				Categories:        []string{"aup_fraud"},
				Reason:            "violation because token=secret-token-123 and api_key=should-redact were present",
				RecommendedAction: ContentModerationActionBlock,
			}, nil
		},
	}
	svc := NewContentModerationService(settingRepo, repo, cache, nil, nil, nil, nil)
	svc.sessionAuditClient = client

	input := ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Headers:  http.Header{"session_id": []string{"sess-block"}},
		Body:     []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"do bad thing"}]}`),
	}

	decision, err := svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, sessionAuditBlockMessage, decision.Message)
	require.Equal(t, 1, client.callCount())
	logs := requireContentModerationLogCount(t, repo, 1)
	require.Equal(t, ContentModerationActionBlock, logs[0].Action)
	require.Equal(t, "aup_fraud", logs[0].HighestCategory)
	require.Equal(t, 0.91, logs[0].HighestScore)
	require.Contains(t, logs[0].Reason, "violation because")
	require.NotContains(t, logs[0].Reason, "secret-token-123")
	require.NotContains(t, logs[0].Reason, "should-redact")

	decision, err = svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, 1, client.callCount(), "blacklisted session should not call audit again")
}

func TestContentModerationCheck_SessionAuditConcurrentFirstRequestAuditsOnce(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	settingRepo := &contentModerationTestSettingRepo{values: map[string]string{
		SettingKeyRiskControlEnabled:            "true",
		SettingKeyContentModerationConfig:       string(rawCfg),
		SettingKeyRiskControlProvider:           RiskControlProviderOpenAIResponsesSessionAudit,
		SettingKeyAuditModel:                    "gpt-5-mini",
		SettingKeyAuditAPIKeys:                  `["sk-audit"]`,
		SettingKeySessionAuditEnabledProtocols:  `["anthropic_messages"]`,
		SettingKeyAuditBlockConfidenceThreshold: "0.7",
	}}
	cache := &contentModerationTestHashCache{}
	clientStarted := make(chan struct{}, 1)
	releaseClient := make(chan struct{})
	client := &sessionAuditClientStub{
		handler: func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
			select {
			case clientStarted <- struct{}{}:
			default:
			}
			<-releaseClient
			return &OpenAIResponsesSessionAuditResult{
				RecommendedAction: ContentModerationActionAllow,
				Confidence:        0.2,
			}, nil
		},
	}
	svc := NewContentModerationService(settingRepo, &contentModerationTestRepo{}, cache, nil, nil, nil, nil)
	svc.sessionAuditClient = client
	svc.sleep = func(ctx context.Context, d time.Duration) error {
		return contentModerationSleepWithContext(ctx, time.Millisecond)
	}

	input := ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Headers:  http.Header{"session_id": []string{"sess-concurrent"}},
		Body:     []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	}

	results := make(chan *ContentModerationDecision, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			decision, checkErr := svc.Check(context.Background(), input)
			results <- decision
			errs <- checkErr
		}()
	}

	<-clientStarted
	close(releaseClient)
	for i := 0; i < 2; i++ {
		require.NoError(t, <-errs)
		require.True(t, (<-results).Allowed)
	}
	require.Equal(t, 1, client.callCount(), "concurrent first request should audit once")
}

func TestContentModerationCheck_SessionAuditFailOpenFailClosedAndThreshold(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	newSvc := func(extra map[string]string, handler func(context.Context, *SessionAuditProviderConfig, *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error)) *ContentModerationService {
		values := map[string]string{
			SettingKeyRiskControlEnabled:            "true",
			SettingKeyContentModerationConfig:       string(rawCfg),
			SettingKeyRiskControlProvider:           RiskControlProviderOpenAIResponsesSessionAudit,
			SettingKeyAuditModel:                    "gpt-5-mini",
			SettingKeyAuditAPIKeys:                  `["sk-audit"]`,
			SettingKeySessionAuditEnabledProtocols:  `["anthropic_messages"]`,
			SettingKeyAuditBlockConfidenceThreshold: "0.7",
		}
		for k, v := range extra {
			values[k] = v
		}
		svc := NewContentModerationService(&contentModerationTestSettingRepo{values: values}, &contentModerationTestRepo{}, &contentModerationTestHashCache{}, nil, nil, nil, nil)
		svc.sessionAuditClient = &sessionAuditClientStub{handler: handler}
		return svc
	}
	input := ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Headers:  http.Header{"session_id": []string{"sess-test"}},
		Body:     []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	}

	svc := newSvc(nil, func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
		return nil, fmt.Errorf("malformed json")
	})
	decision, err := svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Allowed, "fail-open should allow")

	svc = newSvc(map[string]string{SettingKeyAuditFailClosed: "true"}, func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
		return nil, fmt.Errorf("timeout")
	})
	decision, err = svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Blocked, "fail-closed should block on audit error")

	svc = newSvc(nil, func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
		return &OpenAIResponsesSessionAuditResult{
			Violates:          true,
			Confidence:        0.69,
			Categories:        []string{"uncertain"},
			Reason:            "low confidence",
			RecommendedAction: ContentModerationActionBlock,
		}, nil
	})
	decision, err = svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Allowed, "below threshold should allow")
}

func TestContentModerationCheck_SessionAuditFailClosedMissingConfigBlocksWithoutBlacklist(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	client := &sessionAuditClientStub{
		handler: func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
			t.Fatal("missing audit config should block before calling audit client")
			return nil, nil
		},
	}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
			SettingKeyRiskControlProvider:     RiskControlProviderOpenAIResponsesSessionAudit,
			SettingKeyAuditFailClosed:         "true",
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)
	svc.sessionAuditClient = client

	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Headers:  http.Header{"session_id": []string{"sess-missing-config"}},
		Body:     []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	})

	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionError, decision.Action)
	require.Equal(t, sessionAuditBlockMessage, decision.Message)
	require.Equal(t, 0, client.callCount())

	entry, err := repo.GetRiskSessionBlacklist(context.Background(), sha256HexString("sess-missing-config"))
	require.NoError(t, err)
	require.Nil(t, entry, "fail-closed config errors must not blacklist")
}

func TestContentModerationCheck_SessionAuditProviderDisabledKeepsLegacyModeration(t *testing.T) {
	upstreamCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		require.Equal(t, "/v1/moderations", r.URL.Path)
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{Results: []moderationAPIResult{{CategoryScores: map[string]float64{"sexual": 0.1}}}})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-legacy"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	sessionClient := &sessionAuditClientStub{
		handler: func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
			t.Fatal("session audit must not run when provider is legacy_moderation")
			return nil, nil
		},
	}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
			SettingKeyRiskControlProvider:     RiskControlProviderLegacyModeration,
			SettingKeyAuditModel:              "gpt-5-mini",
			SettingKeyAuditAPIKeys:            `["sk-audit"]`,
		}},
		&contentModerationTestRepo{},
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)
	svc.sessionAuditClient = sessionClient

	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Headers:  http.Header{"session_id": []string{"sess-legacy"}},
		Body:     []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	})

	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.True(t, upstreamCalled, "legacy moderation API should still be used")
	require.Equal(t, 0, sessionClient.callCount())
}

func TestContentModerationCheck_SessionAuditModeOffSkipsAudit(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModeOff
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	client := &sessionAuditClientStub{
		handler: func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
			t.Fatal("session audit must not run in mode=off")
			return nil, nil
		},
	}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
			SettingKeyRiskControlProvider:     RiskControlProviderOpenAIResponsesSessionAudit,
			SettingKeyAuditModel:              "gpt-5-mini",
			SettingKeyAuditAPIKeys:            `["sk-audit"]`,
		}},
		&contentModerationTestRepo{},
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)
	svc.sessionAuditClient = client

	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Headers:  http.Header{"session_id": []string{"sess-off"}},
		Body:     []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	})

	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.Equal(t, 0, client.callCount())
}

func TestContentModerationCheck_SessionAuditObserveAuditsButDoesNotBlacklist(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModeObserve
	cfg.RecordNonHits = true
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	cache := &contentModerationTestHashCache{}
	client := &sessionAuditClientStub{
		handler: func(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
			return &OpenAIResponsesSessionAuditResult{
				Violates:          true,
				Confidence:        0.99,
				Categories:        []string{"aup_fraud"},
				Reason:            "clear violation",
				RecommendedAction: ContentModerationActionBlock,
			}, nil
		},
	}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:            "true",
			SettingKeyContentModerationConfig:       string(rawCfg),
			SettingKeyRiskControlProvider:           RiskControlProviderOpenAIResponsesSessionAudit,
			SettingKeyAuditModel:                    "gpt-5-mini",
			SettingKeyAuditAPIKeys:                  `["sk-audit"]`,
			SettingKeyAuditBlockConfidenceThreshold: "0.7",
		}},
		repo,
		cache,
		nil,
		nil,
		nil,
		nil,
	)
	svc.sessionAuditClient = client

	input := ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Headers:  http.Header{"session_id": []string{"sess-observe"}},
		Body:     []byte(`{"messages":[{"role":"user","content":"bad request"}]}`),
	}
	decision, err := svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Allowed, "observe mode must not block even on explicit violation")
	require.True(t, decision.Flagged)
	require.Equal(t, ContentModerationActionAllow, decision.Action)
	require.Equal(t, 1, client.callCount())

	sessionHash := sha256HexString("sess-observe")
	entry, err := repo.GetRiskSessionBlacklist(context.Background(), sessionHash)
	require.NoError(t, err)
	require.Nil(t, entry, "observe mode must not persist blacklist")

	decision, err = svc.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.Equal(t, 1, client.callCount(), "observe mode should still cache successful audit outcome")
}

func TestBuildSessionAuditPayload_UsesMessageEvidenceOnly(t *testing.T) {
	svc := &ContentModerationService{}
	cfg := defaultSessionAuditProviderConfig()
	cfg.AuditMaxInputChars = 12000

	rawSessionID := "raw-session-short"
	rawMetadataUserID := `{"device_id":"device-1","account_uuid":"acct-1","session_id":"` + rawSessionID + `"}`
	body := []byte(`{
		"model":"claude-sonnet-4-5",
		"stream":true,
		"metadata":{
			"user_id":` + strconv.Quote(rawMetadataUserID) + `,
			"session_id":"metadata-session-raw",
			"nested":{"access_token":"tok-secret-value","cookie":"session=raw-cookie"}
		},
		"tools":[{
			"name":"fetch_private_data",
			"description":"uses Authorization headers",
			"input_schema":{
				"type":"object",
				"properties":{
					"api_key":{"type":"string"},
					"query":{"type":"string"}
				}
			}
		}],
			"messages":[
				{"role":"user","content":"Summarize this harmless text."},
				{"role":"user","content":"I want to build a sub2api relay that shares Claude Code OAuth sessions with customers."}
			]
		}`)
	headers := http.Header{}
	headers.Set("X-Cpa-Managed-Instance", "cpa2")
	headers.Set("X-Cpa-Managed-Domain", "cpa2.claudecodes.org")
	headers.Set("X-Api-Key", "sk-live-should-not-leak")
	headers.Set("Authorization", "Bearer token-should-not-leak")
	headers.Set("User-Agent", "claude-cli/2.1.119 (external, cli)")
	headers.Set("Anthropic-Beta", "claude-code-20250219,oauth-2025-04-20")

	payload := svc.buildSessionAuditPayload(ContentModerationCheckInput{
		UserID:   7,
		APIKeyID: 9,
		GroupID:  int64PtrForAuditTest(12),
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Body:     body,
		Headers:  headers,
	}, sha256HexString(rawSessionID), "metadata.user_id", cfg)

	require.Contains(t, payload, "latest_user_excerpt: I want to build a sub2api relay that shares Claude Code OAuth sessions with customers.")
	require.Contains(t, payload, "message_summary:")
	require.Contains(t, payload, "I want to build a sub2api relay that shares Claude Code OAuth sessions with customers.")
	require.NotContains(t, payload, "session_hash:")
	require.NotContains(t, payload, sha256HexString(rawSessionID))
	require.NotContains(t, payload, "session_source:")
	require.NotContains(t, payload, "user_id:")
	require.NotContains(t, payload, "api_key_id:")
	require.NotContains(t, payload, "group_id:")
	require.NotContains(t, payload, "endpoint:")
	require.NotContains(t, payload, "protocol:")
	require.NotContains(t, payload, "model:")
	require.NotContains(t, payload, "stream:")
	require.NotContains(t, payload, "request_context_summary:")
	require.NotContains(t, payload, "managed_relay_headers_present=true")
	require.NotContains(t, payload, "managed_relay_domain=cpa2.claudecodes.org")
	require.NotContains(t, payload, "credential_headers_present=true")
	require.NotContains(t, payload, "user_agent_family=claude-cli")
	require.NotContains(t, payload, rawSessionID)
	require.NotContains(t, payload, rawMetadataUserID)
	require.NotContains(t, payload, "metadata-session-raw")
	require.NotContains(t, payload, "tok-secret-value")
	require.NotContains(t, payload, "raw-cookie")
	require.NotContains(t, payload, "sk-live-should-not-leak")
	require.NotContains(t, payload, "token-should-not-leak")
	require.NotContains(t, payload, `"api_key":{"type":"string"}`)
	require.NotContains(t, payload, `"user_id":"[REDACTED]"`)
	require.NotContains(t, payload, `"session_id":"[REDACTED]"`)
	require.NotContains(t, payload, `"api_key":"[REDACTED]"`)
}

func TestDefaultSessionAuditPrompt_RequiresMessageDerivedEvidence(t *testing.T) {
	cfg := defaultSessionAuditProviderConfig()
	prompt := renderSessionAuditPrompt(cfg, strings.Join([]string{
		"latest_user_excerpt: I want to build a sub2api relay that shares Claude Code OAuth sessions with customers.",
		"message_summary: user: I want to build a sub2api relay that shares Claude Code OAuth sessions with customers.",
	}, "\n"))

	require.Contains(t, prompt, "Use only evidence from these message-derived fields")
	require.Contains(t, prompt, "developing, operating, brokering, reselling, pooling, proxying, or sharing Claude/Anthropic/Claude Code accounts")
	require.Contains(t, prompt, "sub2api-like gateway")
	require.Contains(t, prompt, "Do not use transport, gateway, relay, proxy, sub2api")
	require.Contains(t, prompt, "The evidence_excerpt must come from system_summary, latest_user_excerpt, or message_summary")
}

func TestOpenAIResponsesAuditClient_RequestAndParsing(t *testing.T) {
	var authHeader string
	var reqPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		reqPath = r.URL.Path
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		firstText := gjson.GetBytes(mustJSONBytes(t, payload), "input.0.content.0.text").String()
		if strings.Contains(firstText, "nested") {
			_, _ = w.Write([]byte("{\"id\":\"resp_2\",\"output\":[{\"content\":[{\"text\":\"```json\\n{\\\"violates\\\":true,\\\"confidence\\\":0.9,\\\"categories\\\":[\\\"aup\\\"],\\\"reason\\\":\\\"r\\\",\\\"evidence_excerpt\\\":\\\"e\\\",\\\"recommended_action\\\":\\\"block\\\"}\\n```\"}]}]}"))
			return
		}
		if strings.Contains(firstText, "multiple text blocks") {
			_, _ = w.Write([]byte("{\"id\":\"resp_3\",\"output\":[{\"content\":[{\"text\":\"I will return the classification JSON next.\"},{\"text\":\"{\\\"violates\\\":true,\\\"confidence\\\":0.95,\\\"categories\\\":[\\\"aup\\\"],\\\"reason\\\":\\\"r\\\",\\\"evidence_excerpt\\\":\\\"e\\\",\\\"recommended_action\\\":\\\"Block\\\"}\"}]}]}"))
			return
		}
		_, _ = w.Write([]byte("{\"id\":\"resp_1\",\"output_text\":\"{\\\"violates\\\":false,\\\"confidence\\\":0.1,\\\"categories\\\":[],\\\"reason\\\":\\\"\\\",\\\"evidence_excerpt\\\":\\\"\\\",\\\"recommended_action\\\":\\\"allow\\\"}\"}"))
	}))
	defer server.Close()

	client := NewOpenAIResponsesAuditClient(server.Client())
	cfg := defaultSessionAuditProviderConfig()
	cfg.Provider = RiskControlProviderOpenAIResponsesSessionAudit
	cfg.BaseURL = server.URL + "/v1/"
	cfg.Path = "/v1/responses"
	cfg.Model = "gpt-5-mini"
	cfg.APIKeys = []string{"sk-audit-1", "sk-audit-2"}

	result, err := client.Audit(context.Background(), cfg, &OpenAIResponsesSessionAuditRequest{
		SessionHash: "hash-1",
		Prompt:      "prompt",
		Payload:     "payload",
	})
	require.NoError(t, err)
	require.Equal(t, "Bearer sk-audit-1", authHeader)
	require.Equal(t, "/v1/responses", reqPath)
	require.False(t, result.Violates)

	cfg.Path = "/v1/responses"
	result, err = client.Audit(context.Background(), cfg, &OpenAIResponsesSessionAuditRequest{
		SessionHash: "hash-2",
		Prompt:      "nested prompt",
		Payload:     "payload",
	})
	require.NoError(t, err)
	require.True(t, result.Violates)

	result, err = client.Audit(context.Background(), cfg, &OpenAIResponsesSessionAuditRequest{
		SessionHash: "hash-3",
		Prompt:      "multiple text blocks prompt",
		Payload:     "payload",
	})
	require.NoError(t, err)
	require.True(t, result.Violates)
	require.Equal(t, ContentModerationActionBlock, result.RecommendedAction)
}

func TestEvaluateSessionAuditResult_NormalizesRecommendedAction(t *testing.T) {
	cfg := defaultSessionAuditProviderConfig()
	cfg.BlockConfidenceThreshold = 0.7
	result := &OpenAIResponsesSessionAuditResult{
		Violates:          false,
		Confidence:        0.95,
		Categories:        []string{"aup"},
		RecommendedAction: " BLOCK ",
	}

	flagged, blocked, highestCategory, highestScore, _ := evaluateSessionAuditResult(result, cfg, ContentModerationModePreBlock)

	require.True(t, flagged)
	require.True(t, blocked)
	require.Equal(t, "aup", highestCategory)
	require.Equal(t, 0.95, highestScore)
	require.Equal(t, ContentModerationActionBlock, result.RecommendedAction)
}

func int64PtrForAuditTest(v int64) *int64 {
	return &v
}

func mustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}

func TestContentModerationCheck_KeywordsIgnoredInObserveMode(t *testing.T) {
	upstreamHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{Results: []moderationAPIResult{{CategoryScores: map[string]float64{"sexual": 0.1}}}})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModeObserve
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.BlockedKeywords = []string{"secret-token"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	body := []byte(`{"messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`)
	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Body:     body,
	})

	require.NoError(t, err)
	require.True(t, decision.Allowed, "observe mode must let the request through even on keyword hit")
	require.Equal(t, ContentModerationActionAllow, decision.Action)
}

func TestContentModerationCheck_KeywordOnlyStrategySkipsAPIOnMiss(t *testing.T) {
	upstreamCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{Results: []moderationAPIResult{{CategoryScores: map[string]float64{"sexual": 0.99}}}})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.BlockedKeywords = []string{"never-matches"}
	cfg.KeywordBlockingMode = ContentModerationKeywordModeKeywordOnly
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	body := []byte(`{"messages":[{"role":"user","content":"absolutely clean prompt"}]}`)
	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Body:     body,
	})

	require.NoError(t, err)
	require.True(t, decision.Allowed, "keyword-only must allow misses without calling the API")
	require.False(t, upstreamCalled, "keyword-only must not call the upstream moderation API")
	require.Len(t, repo.snapshotLogs(), 0)
}

func TestContentModerationCheck_APIOnlyStrategyIgnoresKeywordList(t *testing.T) {
	upstreamCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{Results: []moderationAPIResult{{CategoryScores: map[string]float64{"sexual": 0.1}}}})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.BlockedKeywords = []string{"secret-token"}
	cfg.KeywordBlockingMode = ContentModerationKeywordModeAPIOnly
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	body := []byte(`{"messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`)
	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Endpoint: "/v1/messages",
		Provider: "anthropic",
		Protocol: ContentModerationProtocolAnthropicMessages,
		Body:     body,
	})

	require.NoError(t, err)
	require.True(t, decision.Allowed, "api-only must let the request through when API does not flag it")
	require.True(t, upstreamCalled, "api-only must call the upstream moderation API")
	require.NotEqual(t, ContentModerationActionKeywordBlock, decision.Action)
}

func TestNormalizeKeywordBlockingMode_UnknownFallsBackToDefault(t *testing.T) {
	require.Equal(t, ContentModerationKeywordModeKeywordAndAPI, normalizeKeywordBlockingMode(""))
	require.Equal(t, ContentModerationKeywordModeKeywordAndAPI, normalizeKeywordBlockingMode("bogus"))
	require.Equal(t, ContentModerationKeywordModeKeywordOnly, normalizeKeywordBlockingMode("keyword_only"))
	require.Equal(t, ContentModerationKeywordModeAPIOnly, normalizeKeywordBlockingMode("api_only"))
}

func TestContentModerationCheck_ModelFilterAllAuditsEveryModel(t *testing.T) {
	cfg := defaultContentModerationModelFilterTestConfig()
	cfg.ModelFilter = ContentModerationModelFilter{Type: ContentModerationModelFilterAll}
	svc, repo := newContentModerationModelFilterTestService(t, cfg)

	for _, model := range []string{"gpt-5.5", "gpt-5.4"} {
		decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
			Model:    model,
			Protocol: ContentModerationProtocolOpenAIChat,
			Body:     []byte(`{"messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`),
		})
		require.NoError(t, err)
		require.True(t, decision.Blocked)
		require.Equal(t, ContentModerationActionKeywordBlock, decision.Action)
	}
	requireContentModerationLogCount(t, repo, 2)
}

func TestContentModerationCheck_ModelFilterIncludeOnlyAuditsListedModels(t *testing.T) {
	cfg := defaultContentModerationModelFilterTestConfig()
	cfg.ModelFilter = ContentModerationModelFilter{Type: ContentModerationModelFilterInclude, Models: []string{"gpt-5.5"}}
	svc, repo := newContentModerationModelFilterTestService(t, cfg)

	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Model:    "gpt-5.5",
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     []byte(`{"messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`),
	})
	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionKeywordBlock, decision.Action)

	decision, err = svc.Check(context.Background(), ContentModerationCheckInput{
		Model:    "gpt-5.4",
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     []byte(`{"messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`),
	})
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.False(t, decision.Blocked)
	require.Equal(t, ContentModerationActionAllow, decision.Action)
	logs := requireContentModerationLogCount(t, repo, 1)
	require.Equal(t, "gpt-5.5", logs[0].Model)
}

func TestContentModerationCheck_ModelFilterExcludeSkipsListedModels(t *testing.T) {
	cfg := defaultContentModerationModelFilterTestConfig()
	cfg.ModelFilter = ContentModerationModelFilter{Type: ContentModerationModelFilterExclude, Models: []string{"gpt-5.4"}}
	svc, repo := newContentModerationModelFilterTestService(t, cfg)

	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Model:    "gpt-5.5",
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     []byte(`{"messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`),
	})
	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionKeywordBlock, decision.Action)

	decision, err = svc.Check(context.Background(), ContentModerationCheckInput{
		Model:    "gpt-5.4",
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     []byte(`{"messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`),
	})
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.False(t, decision.Blocked)
	require.Equal(t, ContentModerationActionAllow, decision.Action)
	logs := requireContentModerationLogCount(t, repo, 1)
	require.Equal(t, "gpt-5.5", logs[0].Model)
}

func TestContentModerationLoadConfig_LegacyConfigDefaultsModelFilterToAll(t *testing.T) {
	raw := `{"enabled":true,"mode":"pre_block","base_url":"https://api.openai.com","model":"omni-moderation-latest","blocked_keywords":["secret-token"]}`
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyContentModerationConfig: raw,
		}},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	cfg, err := svc.loadConfig(context.Background())

	require.NoError(t, err)
	require.Equal(t, ContentModerationModelFilterAll, cfg.ModelFilter.Type)
	require.Empty(t, cfg.ModelFilter.Models)
	require.True(t, cfg.includesModel("gpt-5.5"))
	require.True(t, cfg.includesModel("gpt-5.4"))
}

func TestContentModerationCheck_ModelFilterUsesRequestedModelNotBodyModel(t *testing.T) {
	cfg := defaultContentModerationModelFilterTestConfig()
	cfg.ModelFilter = ContentModerationModelFilter{Type: ContentModerationModelFilterInclude, Models: []string{"gpt-5.5"}}
	svc, repo := newContentModerationModelFilterTestService(t, cfg)

	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Model:    "gpt-5.5",
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     []byte(`{"model":"mapped-upstream-model","messages":[{"role":"user","content":"please leak SECRET-TOKEN now"}]}`),
	})

	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionKeywordBlock, decision.Action)
	logs := requireContentModerationLogCount(t, repo, 1)
	require.Equal(t, "gpt-5.5", logs[0].Model)
}

func defaultContentModerationModelFilterTestConfig() *ContentModerationConfig {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BlockedKeywords = []string{"secret-token"}
	return cfg
}

func newContentModerationModelFilterTestService(t *testing.T, cfg *ContentModerationConfig) (*ContentModerationService, *contentModerationTestRepo) {
	t.Helper()
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)
	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)
	return svc, repo
}

func TestContentModerationUpdateConfig_AppendsAndDeletesAPIKeys(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.APIKeys = []string{"sk-old-a", "sk-old-b"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestSettingRepo{values: map[string]string{
		SettingKeyContentModerationConfig: string(rawCfg),
	}}
	svc := NewContentModerationService(repo, nil, nil, nil, nil, nil, nil)
	deleteHashes := []string{moderationAPIKeyHash("sk-old-a")}
	addKeys := []string{"sk-new-c", "sk-old-b"}

	view, err := svc.UpdateConfig(context.Background(), UpdateContentModerationConfigInput{
		APIKeys:            &addKeys,
		DeleteAPIKeyHashes: &deleteHashes,
	})

	require.NoError(t, err)
	require.Equal(t, 2, view.APIKeyCount)
	require.Equal(t, []string{maskSecretTail("sk-old-b"), maskSecretTail("sk-new-c")}, view.APIKeyMasks)

	var saved ContentModerationConfig
	require.NoError(t, json.Unmarshal([]byte(repo.values[SettingKeyContentModerationConfig]), &saved))
	require.Equal(t, []string{"sk-old-b", "sk-new-c"}, saved.apiKeys())
}

func TestContentModerationUpdateConfig_ReplacesAPIKeysWhenRequested(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.APIKeys = []string{"sk-old-a", "sk-old-b"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestSettingRepo{values: map[string]string{
		SettingKeyContentModerationConfig: string(rawCfg),
	}}
	svc := NewContentModerationService(repo, nil, nil, nil, nil, nil, nil)
	deleteHashes := []string{moderationAPIKeyHash("sk-old-a")}
	replaceKeys := []string{"sk-new-only"}

	view, err := svc.UpdateConfig(context.Background(), UpdateContentModerationConfigInput{
		APIKeys:            &replaceKeys,
		APIKeysMode:        contentModerationAPIKeysModeReplace,
		DeleteAPIKeyHashes: &deleteHashes,
	})

	require.NoError(t, err)
	require.Equal(t, 1, view.APIKeyCount)
	require.Equal(t, []string{maskSecretTail("sk-new-only")}, view.APIKeyMasks)

	var saved ContentModerationConfig
	require.NoError(t, json.Unmarshal([]byte(repo.values[SettingKeyContentModerationConfig]), &saved))
	require.Equal(t, []string{"sk-new-only"}, saved.apiKeys())
}

func TestContentModerationUpdateConfig_SavesCustomThresholds(t *testing.T) {
	cfg := defaultContentModerationConfig()
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestSettingRepo{values: map[string]string{
		SettingKeyContentModerationConfig: string(rawCfg),
	}}
	svc := NewContentModerationService(repo, nil, nil, nil, nil, nil, nil)
	thresholds := map[string]float64{
		"sexual":     0.72,
		"harassment": 1.25,
		"unknown":    0.01,
	}

	view, err := svc.UpdateConfig(context.Background(), UpdateContentModerationConfigInput{
		Thresholds: &thresholds,
	})

	require.NoError(t, err)
	require.Equal(t, 0.72, view.Thresholds["sexual"])
	require.Equal(t, 1.0, view.Thresholds["harassment"])
	require.NotContains(t, view.Thresholds, "unknown")

	var saved ContentModerationConfig
	require.NoError(t, json.Unmarshal([]byte(repo.values[SettingKeyContentModerationConfig]), &saved))
	require.Equal(t, 0.72, saved.Thresholds["sexual"])
	require.Equal(t, 1.0, saved.Thresholds["harassment"])
	require.NotContains(t, saved.Thresholds, "unknown")
}

func TestContentModerationUpdateConfig_SavesSessionAuditProviderSettings(t *testing.T) {
	cfg := defaultContentModerationConfig()
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestSettingRepo{values: map[string]string{
		SettingKeyContentModerationConfig: string(rawCfg),
		SettingKeyAuditAPIKeys:            `["sk-audit-old"]`,
	}}
	svc := NewContentModerationService(repo, nil, nil, nil, nil, nil, nil)

	provider := RiskControlProviderOpenAIResponsesSessionAudit
	baseURL := "https://audit.example.com"
	path := "/v1/responses"
	model := "gpt-5-mini"
	keys := []string{"sk-audit-new"}
	timeoutMS := 4200
	failClosed := true
	threshold := 0.82
	intervalSeconds := 120
	blacklistTTLSeconds := 3600
	protocols := []string{ContentModerationProtocolAnthropicMessages}
	maxInputChars := 15000
	promptTemplate := "Audit the session context"

	view, err := svc.UpdateConfig(context.Background(), UpdateContentModerationConfigInput{
		RiskControlProvider:           &provider,
		AuditBaseURL:                  &baseURL,
		AuditPath:                     &path,
		AuditModel:                    &model,
		AuditAPIKeys:                  &keys,
		AuditTimeoutMS:                &timeoutMS,
		AuditFailClosed:               &failClosed,
		AuditBlockConfidenceThreshold: &threshold,
		SessionAuditIntervalSeconds:   &intervalSeconds,
		SessionBlacklistTTLSeconds:    &blacklistTTLSeconds,
		SessionAuditEnabledProtocols:  &protocols,
		AuditMaxInputChars:            &maxInputChars,
		AuditPromptTemplate:           &promptTemplate,
	})

	require.NoError(t, err)
	require.Equal(t, RiskControlProviderOpenAIResponsesSessionAudit, view.RiskControlProvider)
	require.Equal(t, baseURL, view.AuditBaseURL)
	require.Equal(t, path, view.AuditPath)
	require.Equal(t, model, view.AuditModel)
	require.True(t, view.AuditAPIKeyConfigured)
	require.Equal(t, 2, view.AuditAPIKeyCount)
	require.Equal(t, []string{maskSecretTail("sk-audit-old"), maskSecretTail("sk-audit-new")}, view.AuditAPIKeyMasks)
	require.Equal(t, timeoutMS, view.AuditTimeoutMS)
	require.True(t, view.AuditFailClosed)
	require.Equal(t, threshold, view.AuditBlockConfidenceThreshold)
	require.Equal(t, intervalSeconds, view.SessionAuditIntervalSeconds)
	require.Equal(t, blacklistTTLSeconds, view.SessionBlacklistTTLSeconds)
	require.Equal(t, protocols, view.SessionAuditEnabledProtocols)
	require.Equal(t, maxInputChars, view.AuditMaxInputChars)
	require.Equal(t, promptTemplate, view.AuditPromptTemplate)

	viewRaw, err := json.Marshal(view)
	require.NoError(t, err)
	require.NotContains(t, string(viewRaw), "sk-audit-old")
	require.NotContains(t, string(viewRaw), "sk-audit-new")

	require.Equal(t, provider, repo.values[SettingKeyRiskControlProvider])
	require.Equal(t, baseURL, repo.values[SettingKeyAuditBaseURL])
	require.Equal(t, path, repo.values[SettingKeyAuditPath])
	require.Equal(t, model, repo.values[SettingKeyAuditModel])
	require.Equal(t, strconv.Itoa(timeoutMS), repo.values[SettingKeyAuditTimeoutMS])
	require.Equal(t, strconv.Itoa(intervalSeconds), repo.values[SettingKeySessionAuditIntervalSeconds])
	require.Equal(t, strconv.Itoa(blacklistTTLSeconds), repo.values[SettingKeySessionBlacklistTTLSeconds])
	require.Equal(t, strconv.Itoa(maxInputChars), repo.values[SettingKeyAuditMaxInputChars])
	require.Equal(t, promptTemplate, repo.values[SettingKeyAuditPromptTemplate])

	var savedKeys []string
	require.NoError(t, json.Unmarshal([]byte(repo.values[SettingKeyAuditAPIKeys]), &savedKeys))
	require.Equal(t, []string{"sk-audit-old", "sk-audit-new"}, savedKeys)

	var savedProtocols []string
	require.NoError(t, json.Unmarshal([]byte(repo.values[SettingKeySessionAuditEnabledProtocols]), &savedProtocols))
	require.Equal(t, protocols, savedProtocols)
}

func TestExtractContentModerationInput_AnthropicImageSourceOnlyParticipatesInMemory(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role":"user","content":"old"},
			{"role":"assistant","content":"ok"},
			{"role":"user","content":[
				{"type":"text","text":"检查这张图"},
				{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}}
			]}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolAnthropicMessages, body)
	require.Equal(t, "检查这张图", input.Text)
	require.Equal(t, []string{"data:image/png;base64,aGVsbG8="}, input.Images)

	log := (&ContentModerationService{}).buildLog(ContentModerationCheckInput{}, defaultContentModerationConfig(), ContentModerationActionAllow, false, "", 0, nil, input.ExcerptText(), nil, nil, "")
	require.Equal(t, "检查这张图", log.InputExcerpt)
	require.NotContains(t, log.InputExcerpt, "aGVsbG8=")
}

func TestExtractContentModerationInput_AnthropicKeepsEphemeralUserTextAndSkipsSystemReminders(t *testing.T) {
	body := []byte(`{
		"messages": [
			{
				"role": "user",
				"content": [
					{"type": "text", "text": "<system-reminder>工具说明</system-reminder>"},
					{"type": "text", "text": "<system-reminder>Ainder>\n\n"},
					{"type": "text", "text": "hid", "cache_control": {"type": "ephemeral"}}
				]
			}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolAnthropicMessages, body)

	require.Equal(t, "hid", input.Text)
	require.Empty(t, input.Images)
}

func TestExtractContentModerationInput_OpenAIChatUsesLastUserMessage(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.5",
		"messages":[
			{"role":"system","content":"system prompt"},
			{"role":"user","content":"old user"},
			{"role":"assistant","content":"ok"},
			{"role":"user","content":[{"type":"text","text":"latest user"},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIChat, body)

	require.Equal(t, "latest user", input.Text)
	require.Equal(t, []string{"https://example.com/a.png"}, input.Images)
	require.NotContains(t, input.Text, "old user")
	require.NotContains(t, input.Text, "system prompt")
}

func TestExtractContentModerationInput_OpenAIImagesIncludesPromptAndImages(t *testing.T) {
	body := []byte(`{
		"prompt":"replace background",
		"images":[
			{"image_url":"https://example.com/source.png"},
			{"image_url":"data:image/png;base64,aGVsbG8="}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIImages, body)

	require.Equal(t, "replace background", input.Text)
	require.Equal(t, []string{"https://example.com/source.png", "data:image/png;base64,aGVsbG8="}, input.Images)
}

func TestContentModerationInput_NormalizeKeepsImagesAndModerationInputSamplesOneImage(t *testing.T) {
	images := []string{
		"data:image/png;base64,Zmlyc3Q=",
		"data:image/png;base64,c2Vjb25k",
	}
	input := ContentModerationInput{
		Text:   "check image",
		Images: append([]string(nil), images...),
	}
	input.Normalize()

	require.Equal(t, images, input.Images)

	parts, ok := input.ModerationInput().([]moderationAPIInputPart)
	require.True(t, ok)
	require.Len(t, parts, 2)
	require.Equal(t, "text", parts[0].Type)
	require.Equal(t, "image_url", parts[1].Type)
	require.NotNil(t, parts[1].ImageURL)
	require.Contains(t, images, parts[1].ImageURL.URL)
}

func TestBuildModerationTestInputRejectsMultipleImages(t *testing.T) {
	_, _, err := buildModerationTestInput("check image", []string{
		"data:image/png;base64,Zmlyc3Q=",
		"data:image/png;base64,c2Vjb25k",
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "最多上传 1 张测试图片")
}

func TestExtractContentModerationInput_OpenAIResponsesCodexPayloadUsesLastUserMessage(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.5",
		"instructions":"instructions.....",
		"input":[
			{"type":"message","role":"developer","content":[{"type":"input_text","text":"developer permissions sk-proj-1234567890abcdef"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"first user prompt"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"last user prompt"}]}
		],
		"prompt_cache_key":"cache-key"
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIResponses, body)

	require.Equal(t, "last user prompt", input.Text)
	require.Empty(t, input.Images)
	require.NotContains(t, input.Text, "developer permissions")
	require.NotContains(t, input.Text, "first user prompt")
}

func TestContentModerationCheck_OpenAIResponsesRecordsNonHitForCodexPayload(t *testing.T) {
	var moderationRequest moderationAPIRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/moderations", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&moderationRequest))
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{
			Results: []moderationAPIResult{{
				CategoryScores: map[string]float64{"sexual": 0.01},
			}},
		})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.RecordNonHits = true
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	body := []byte(`{
		"model":"gpt-5.5",
		"input":[
			{"type":"message","role":"developer","content":[{"type":"input_text","text":"developer instructions should not be audited"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"first user prompt"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"last user prompt"}]}
		]
	}`)
	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		UserID:   1001,
		Endpoint: "/responses",
		Provider: "openai",
		Model:    "gpt-5.5",
		Protocol: ContentModerationProtocolOpenAIResponses,
		Body:     body,
	})

	require.NoError(t, err)
	require.False(t, decision.Blocked)
	logs := requireContentModerationLogCount(t, repo, 1)
	require.False(t, logs[0].Flagged)
	require.Equal(t, ContentModerationActionAllow, logs[0].Action)
	require.Equal(t, "/responses", logs[0].Endpoint)
	require.Equal(t, "last user prompt", logs[0].InputExcerpt)
	require.Equal(t, "last user prompt", moderationRequest.Input)
}

func TestContentModerationCheck_PreBlockBlocksCodexResponsesLatestUserInput(t *testing.T) {
	var moderationRequest moderationAPIRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/moderations", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&moderationRequest))
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{
			Results: []moderationAPIResult{{
				CategoryScores: map[string]float64{"sexual": 0.9},
			}},
		})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.BlockStatus = http.StatusUnavailableForLegalReasons
	cfg.BlockMessage = "内容审计测试阻断"
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	body := []byte(`{
		"model":"gpt-5.5",
		"instructions":"instructions.....",
		"input":[
			{"type":"message","role":"developer","content":[{"type":"input_text","text":"developer instructions should not be audited"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"environment context"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"latest blocked prompt"}]}
		]
	}`)
	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		UserID:   1001,
		Endpoint: "/responses",
		Provider: "openai",
		Model:    "gpt-5.5",
		Protocol: ContentModerationProtocolOpenAIResponses,
		Body:     body,
	})

	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionBlock, decision.Action)
	require.Equal(t, http.StatusUnavailableForLegalReasons, decision.StatusCode)
	require.Equal(t, "内容审计测试阻断", decision.Message)
	logs := requireContentModerationLogCount(t, repo, 1)
	require.True(t, logs[0].Flagged)
	require.Equal(t, ContentModerationActionBlock, logs[0].Action)
	require.Equal(t, ContentModerationModePreBlock, logs[0].Mode)
	require.Equal(t, "latest blocked prompt", logs[0].InputExcerpt)
	require.Equal(t, "latest blocked prompt", moderationRequest.Input)
}

func TestContentModerationStatusTracksPreBlockSyncMetrics(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		score := 0.01
		if requestCount == 1 {
			score = 0.9
		}
		time.Sleep(5 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{
			Results: []moderationAPIResult{{
				CategoryScores: map[string]float64{"sexual": score},
			}},
		})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		&contentModerationTestRepo{},
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	for _, prompt := range []string{"blocked prompt", "clean prompt"} {
		_, err := svc.Check(context.Background(), ContentModerationCheckInput{
			UserID:   1001,
			Protocol: ContentModerationProtocolOpenAIChat,
			Body:     []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":%q}]}`, prompt)),
		})
		require.NoError(t, err)
	}

	status, err := svc.GetStatus(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(2), status.PreBlockChecked)
	require.Equal(t, int64(1), status.PreBlockAllowed)
	require.Equal(t, int64(1), status.PreBlockBlocked)
	require.Equal(t, int64(0), status.PreBlockErrors)
	require.Equal(t, 0, status.PreBlockActive)
	require.GreaterOrEqual(t, status.PreBlockAvgLatencyMS, int64(1))
}

func TestContentModerationStatusTracksPreBlockAPIKeyLoad(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{
			Results: []moderationAPIResult{{
				CategoryScores: map[string]float64{"sexual": 0.01},
			}},
		})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-one", "sk-two"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		&contentModerationTestRepo{},
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	for idx := 0; idx < 4; idx++ {
		_, err := svc.Check(context.Background(), ContentModerationCheckInput{
			UserID:   1001,
			Protocol: ContentModerationProtocolOpenAIChat,
			Body:     []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":"prompt %d"}]}`, idx)),
		})
		require.NoError(t, err)
	}

	status, err := svc.GetStatus(context.Background())
	require.NoError(t, err)
	require.Len(t, status.PreBlockAPIKeyLoads, 2)
	require.Equal(t, int64(4), status.PreBlockAPIKeyTotalCalls)
	require.Equal(t, int64(2), status.PreBlockAPIKeyAvailableCount)
	require.Equal(t, int64(0), status.PreBlockAPIKeyActive)
	require.Equal(t, int64(0), status.PreBlockAPIKeyLoads[0].Active)
	require.Equal(t, int64(2), status.PreBlockAPIKeyLoads[0].Total)
	require.Equal(t, int64(2), status.PreBlockAPIKeyLoads[0].Success)
	require.Equal(t, int64(0), status.PreBlockAPIKeyLoads[0].Errors)
	require.Equal(t, int64(2), status.PreBlockAPIKeyLoads[1].Total)
	require.Equal(t, int64(2), status.PreBlockAPIKeyLoads[1].Success)
}

func TestContentModerationStatusTracksPreBlockLocalBlocks(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.KeywordBlockingMode = ContentModerationKeywordModeKeywordOnly
	cfg.BlockedKeywords = []string{"blocked"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		&contentModerationTestRepo{},
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	for _, prompt := range []string{"blocked prompt", "clean prompt"} {
		_, err := svc.Check(context.Background(), ContentModerationCheckInput{
			UserID:   1001,
			Protocol: ContentModerationProtocolOpenAIChat,
			Body:     []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":%q}]}`, prompt)),
		})
		require.NoError(t, err)
	}

	status, err := svc.GetStatus(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(2), status.PreBlockChecked)
	require.Equal(t, int64(1), status.PreBlockAllowed)
	require.Equal(t, int64(1), status.PreBlockBlocked)
	require.Equal(t, int64(0), status.PreBlockErrors)
}

func TestBuildContentModerationTestAuditResult_UsesConfiguredThresholdsOnly(t *testing.T) {
	result := buildContentModerationTestAuditResult(&moderationAPIResult{
		Flagged: true,
		CategoryScores: map[string]float64{
			"harassment": 0.65,
		},
	}, nil)

	require.NotNil(t, result)
	require.False(t, result.Flagged)
	require.Equal(t, "harassment", result.HighestCategory)
	require.Equal(t, 0.65, result.HighestScore)
	require.Equal(t, 0.65, result.CompositeScore)
	require.Equal(t, 0.98, result.Thresholds["harassment"])
}

func TestContentModerationCallModeration_400DoesNotFreezeAPIKey(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"Number of images (5) exceeds maximum of 1","type":"invalid_request_error","param":"input","code":"too_many_images"}}`))
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.RetryCount = 5
	svc := NewContentModerationService(nil, nil, nil, nil, nil, nil, nil)

	_, err := svc.callModeration(context.Background(), cfg, "hello")

	require.Error(t, err)
	require.Equal(t, 1, requestCount)
	status := svc.apiKeyStatusForHash(0, moderationAPIKeyHash("sk-test"), maskSecretTail("sk-test"), true)
	require.Equal(t, "error", status.Status)
	require.Equal(t, http.StatusBadRequest, status.LastHTTPStatus)
	require.Zero(t, status.FailureCount)
	require.Nil(t, status.FrozenUntil)
}

func TestContentModerationCallModeration_FreezesByHTTPStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		minFreeze  time.Duration
		maxFreeze  time.Duration
	}{
		{name: "401 freezes ten minutes", statusCode: http.StatusUnauthorized, minFreeze: 9*time.Minute + 55*time.Second, maxFreeze: 10*time.Minute + time.Second},
		{name: "403 freezes ten minutes", statusCode: http.StatusForbidden, minFreeze: 9*time.Minute + 55*time.Second, maxFreeze: 10*time.Minute + time.Second},
		{name: "429 freezes one minute", statusCode: http.StatusTooManyRequests, minFreeze: 55 * time.Second, maxFreeze: time.Minute + time.Second},
		{name: "529 freezes one minute", statusCode: 529, minFreeze: 55 * time.Second, maxFreeze: time.Minute + time.Second},
		{name: "500 freezes ten seconds", statusCode: http.StatusInternalServerError, minFreeze: 5 * time.Second, maxFreeze: 11 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(`{"error":{"message":"upstream error"}}`))
			}))
			defer server.Close()

			cfg := defaultContentModerationConfig()
			cfg.BaseURL = server.URL
			cfg.APIKeys = []string{"sk-test"}
			cfg.RetryCount = 0
			svc := NewContentModerationService(nil, nil, nil, nil, nil, nil, nil)

			_, err := svc.callModeration(context.Background(), cfg, "hello")

			require.Error(t, err)
			status := svc.apiKeyStatusForHash(0, moderationAPIKeyHash("sk-test"), maskSecretTail("sk-test"), true)
			require.Equal(t, "frozen", status.Status)
			require.Equal(t, tt.statusCode, status.LastHTTPStatus)
			require.Equal(t, 1, status.FailureCount)
			require.NotNil(t, status.FrozenUntil)
			remaining := time.Until(*status.FrozenUntil)
			require.GreaterOrEqual(t, remaining, tt.minFreeze)
			require.LessOrEqual(t, remaining, tt.maxFreeze)
		})
	}
}

func TestContentModerationTestAPIKeys_400DoesNotFreezeAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid moderation request"}}`))
	}))
	defer server.Close()

	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{}},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	result, err := svc.TestAPIKeys(context.Background(), TestContentModerationAPIKeysInput{
		APIKeys: []string{"sk-test"},
		BaseURL: server.URL,
		Prompt:  "hello",
	})

	require.NoError(t, err)
	require.Len(t, result.Items, 1)
	require.Equal(t, "error", result.Items[0].Status)
	require.Equal(t, http.StatusBadRequest, result.Items[0].LastHTTPStatus)
	require.Zero(t, result.Items[0].FailureCount)
	require.Nil(t, result.Items[0].FrozenUntil)
}

func TestContentModerationCheck_PreHashUsesRedisHashCache(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.PreHashCheckEnabled = true
	cfg.APIKeys = []string{"sk-test"}
	cfg.BlockStatus = http.StatusConflict
	cfg.BlockMessage = "命中历史风险输入"
	cfg.AutoBanEnabled = true
	cfg.BanThreshold = 1
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	hashCache := &contentModerationTestHashCache{hashes: map[string]struct{}{}}
	content := ContentModerationInput{Text: "blocked prompt"}
	content.Normalize()
	hashCache.hashes[content.Hash()] = struct{}{}

	repo := &contentModerationTestRepo{}
	userRepo := &contentModerationTestUserRepo{user: &User{ID: 1001, Status: StatusActive}}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		hashCache,
		nil,
		userRepo,
		nil,
		nil,
	)

	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		UserID:   1001,
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     []byte(`{"messages":[{"role":"user","content":"blocked prompt"}]}`),
	})
	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionHashBlock, decision.Action)
	require.Equal(t, http.StatusConflict, decision.StatusCode)
	require.Equal(t, content.Hash(), decision.InputHash)
	require.Contains(t, decision.Message, "命中历史风险输入")
	require.Contains(t, decision.Message, content.Hash())
	require.Len(t, hashCache.snapshotChecked(), 1)
	logs := requireContentModerationLogCount(t, repo, 1)
	require.True(t, logs[0].Flagged)
	require.Equal(t, ContentModerationActionHashBlock, logs[0].Action)
	require.Equal(t, 1.0, logs[0].CategoryScores["hash"])
	require.Equal(t, ContentModerationModePreBlock, logs[0].Mode)
	require.Zero(t, logs[0].ViolationCount)
	require.False(t, logs[0].AutoBanned)
	require.Empty(t, userRepo.updated)
}

func TestContentModerationCheck_HashBlockLogsDoNotIncreaseNextViolationCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{
			Results: []moderationAPIResult{{
				CategoryScores: map[string]float64{"sexual": 0.9},
			}},
		})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.AutoBanEnabled = false
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	userID := int64(1001)
	repo := &contentModerationTestRepo{}
	hashLog := &ContentModerationLog{
		UserID:          &userID,
		Action:          ContentModerationActionHashBlock,
		Flagged:         true,
		HighestCategory: "hash",
		HighestScore:    1,
		CreatedAt:       time.Now(),
	}
	require.NoError(t, repo.CreateLog(context.Background(), hashLog))

	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		&contentModerationTestHashCache{},
		nil,
		nil,
		nil,
		nil,
	)

	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		UserID:   userID,
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     []byte(`{"messages":[{"role":"user","content":"new blocked prompt"}]}`),
	})

	require.NoError(t, err)
	require.True(t, decision.Blocked)
	logs := requireContentModerationLogCount(t, repo, 2)
	require.Equal(t, ContentModerationActionHashBlock, logs[0].Action)
	require.Equal(t, ContentModerationActionBlock, logs[1].Action)
	require.Equal(t, 1, logs[1].ViolationCount)
}

func TestContentModerationAutoBanSkipsAdminAccount(t *testing.T) {
	var slogOutput bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&slogOutput, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
	})

	cfg := defaultContentModerationConfig()
	cfg.BanThreshold = 2
	cfg.ViolationWindowHours = 24

	userID := int64(1001)
	repo := &contentModerationTestRepo{}
	require.NoError(t, repo.CreateLog(context.Background(), newContentModerationFlaggedLog(userID)))
	userRepo := &contentModerationTestUserRepo{user: &User{ID: userID, Role: RoleAdmin, Status: StatusActive}}
	invalidator := &contentModerationTestAuthCacheInvalidator{}
	svc := NewContentModerationService(nil, repo, nil, nil, userRepo, invalidator, nil)

	svc.persistContentModerationLog(context.Background(), cfg, newContentModerationFlaggedLog(userID), "", false, true)

	logs := requireContentModerationLogCount(t, repo, 2)
	require.Equal(t, 2, logs[1].ViolationCount)
	require.False(t, logs[1].AutoBanned)
	require.Equal(t, StatusActive, userRepo.user.Status)
	require.Empty(t, userRepo.updated)
	require.Empty(t, invalidator.userIDs)
	require.Contains(t, slogOutput.String(), "content_moderation.autoban_skipped_admin")
	require.Contains(t, slogOutput.String(), "user_id=1001")
	require.Contains(t, slogOutput.String(), "role=admin")
	require.Contains(t, slogOutput.String(), "count=2")
	require.Contains(t, slogOutput.String(), "threshold=2")
}

func TestContentModerationAutoBanDisablesRegularUserAtThreshold(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.BanThreshold = 2
	cfg.ViolationWindowHours = 24

	userID := int64(1001)
	repo := &contentModerationTestRepo{}
	require.NoError(t, repo.CreateLog(context.Background(), newContentModerationFlaggedLog(userID)))
	userRepo := &contentModerationTestUserRepo{user: &User{ID: userID, Role: RoleUser, Status: StatusActive}}
	invalidator := &contentModerationTestAuthCacheInvalidator{}
	svc := NewContentModerationService(nil, repo, nil, nil, userRepo, invalidator, nil)

	svc.persistContentModerationLog(context.Background(), cfg, newContentModerationFlaggedLog(userID), "", false, true)

	logs := requireContentModerationLogCount(t, repo, 2)
	require.Equal(t, 2, logs[1].ViolationCount)
	require.True(t, logs[1].AutoBanned)
	require.Len(t, userRepo.updated, 1)
	require.Equal(t, StatusDisabled, userRepo.user.Status)
	require.Equal(t, []int64{userID}, invalidator.userIDs)
}

func TestContentModerationAdminBelowBanThresholdRecordsViolationOnly(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.BanThreshold = 2
	cfg.ViolationWindowHours = 24

	userID := int64(1001)
	repo := &contentModerationTestRepo{}
	userRepo := &contentModerationTestUserRepo{user: &User{ID: userID, Role: RoleAdmin, Status: StatusActive}}
	invalidator := &contentModerationTestAuthCacheInvalidator{}
	svc := NewContentModerationService(nil, repo, nil, nil, userRepo, invalidator, nil)

	svc.persistContentModerationLog(context.Background(), cfg, newContentModerationFlaggedLog(userID), "", false, true)

	logs := requireContentModerationLogCount(t, repo, 1)
	require.Equal(t, 1, logs[0].ViolationCount)
	require.False(t, logs[0].AutoBanned)
	require.Equal(t, StatusActive, userRepo.user.Status)
	require.Empty(t, userRepo.updated)
	require.Empty(t, invalidator.userIDs)
}

func newContentModerationFlaggedLog(userID int64) *ContentModerationLog {
	return &ContentModerationLog{
		UserID:          &userID,
		Action:          ContentModerationActionBlock,
		Flagged:         true,
		HighestCategory: "sexual",
		HighestScore:    0.9,
		CreatedAt:       time.Now(),
	}
}

func TestContentModerationCheck_PreBlockFlaggedWritesRedisHashCache(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{
			Results: []moderationAPIResult{{
				CategoryScores: map[string]float64{"sexual": 0.9},
			}},
		})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModePreBlock
	cfg.PreHashCheckEnabled = true
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	cfg.BlockStatus = http.StatusConflict
	cfg.BlockMessage = "命中风险输入"
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	hashCache := &contentModerationTestHashCache{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		hashCache,
		nil,
		nil,
		nil,
		nil,
	)

	body := []byte(`{"messages":[{"role":"user","content":"repeat blocked prompt"}]}`)
	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     body,
	})
	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionBlock, decision.Action)
	require.Equal(t, 1, requestCount)
	recorded := requireRecordedHashCount(t, hashCache, 1)
	requireContentModerationLogCount(t, repo, 1)

	decision, err = svc.Check(context.Background(), ContentModerationCheckInput{
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     body,
	})
	require.NoError(t, err)
	require.True(t, decision.Blocked)
	require.Equal(t, ContentModerationActionHashBlock, decision.Action)
	require.Equal(t, recorded[0], decision.InputHash)
	require.Equal(t, 1, requestCount)
	logs := requireContentModerationLogCount(t, repo, 2)
	require.Equal(t, ContentModerationActionBlock, logs[0].Action)
	require.Equal(t, ContentModerationActionHashBlock, logs[1].Action)
}

func TestContentModerationDeleteFlaggedInputHash_NormalizesAndDeletes(t *testing.T) {
	existingHash := strings.Repeat("a", 64)
	hashCache := &contentModerationTestHashCache{hashes: map[string]struct{}{
		existingHash: {},
	}}
	svc := &ContentModerationService{hashCache: hashCache}

	result, err := svc.DeleteFlaggedInputHash(context.Background(), strings.ToUpper(existingHash))

	require.NoError(t, err)
	require.Equal(t, existingHash, result.InputHash)
	require.True(t, result.Deleted)
	require.False(t, hashCache.hasHash(existingHash))
	require.Equal(t, []string{existingHash}, hashCache.snapshotDeleted())

	result, err = svc.DeleteFlaggedInputHash(context.Background(), existingHash)

	require.NoError(t, err)
	require.Equal(t, existingHash, result.InputHash)
	require.False(t, result.Deleted)
}

func TestContentModerationClearFlaggedInputHashesAndStatusCount(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	hashCache := &contentModerationTestHashCache{hashes: map[string]struct{}{
		strings.Repeat("a", 64): {},
		strings.Repeat("b", 64): {},
	}}
	svc := &ContentModerationService{
		settingRepo: &contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		hashCache: hashCache,
		keyHealth: make(map[string]*contentModerationKeyHealth),
	}

	status, err := svc.GetStatus(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(2), status.FlaggedHashCount)

	result, err := svc.ClearFlaggedInputHashes(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(2), result.Deleted)

	status, err = svc.GetStatus(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(0), status.FlaggedHashCount)
}

func TestContentModerationCheck_AsyncFlaggedWritesRedisHashCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(moderationAPIResponse{
			Results: []moderationAPIResult{{
				CategoryScores: map[string]float64{"sexual": 0.9},
			}},
		})
	}))
	defer server.Close()

	cfg := defaultContentModerationConfig()
	cfg.Enabled = true
	cfg.Mode = ContentModerationModeObserve
	cfg.BaseURL = server.URL
	cfg.APIKeys = []string{"sk-test"}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	repo := &contentModerationTestRepo{}
	hashCache := &contentModerationTestHashCache{}
	svc := NewContentModerationService(
		&contentModerationTestSettingRepo{values: map[string]string{
			SettingKeyRiskControlEnabled:      "true",
			SettingKeyContentModerationConfig: string(rawCfg),
		}},
		repo,
		hashCache,
		nil,
		nil,
		nil,
		nil,
	)

	decision := svc.checkSync(context.Background(), ContentModerationCheckInput{
		Protocol: ContentModerationProtocolOpenAIChat,
		Body:     []byte(`{"messages":[{"role":"user","content":"bad prompt"}]}`),
	}, cfg, ContentModerationInput{Text: "bad prompt"}, strings.Repeat("b", 64), contentModerationIntPtr(25), false)

	require.False(t, decision.Blocked)
	requireRecordedHashCount(t, hashCache, 1)
	requireContentModerationLogCount(t, repo, 1)
}

func TestBuildContentModerationAccountDisabledEmailBody_ContainsBanDetails(t *testing.T) {
	userID := int64(1001)
	cfg := defaultContentModerationConfig()
	cfg.BanThreshold = 10
	body := buildContentModerationAccountDisabledEmailBody("Sub2API <Admin>", &ContentModerationLog{
		UserID:          &userID,
		UserEmail:       "user@example.com",
		GroupName:       "vip_2",
		HighestCategory: "sexual",
		HighestScore:    0.926,
		ViolationCount:  10,
	}, cfg)

	require.Contains(t, body, "账户已被自动禁用")
	require.Contains(t, body, "封禁详情")
	require.Contains(t, body, "账户当前处于封禁状态，所有 API 请求将被拒绝")
	require.Contains(t, body, "10 次（阈值 10）")
	require.Contains(t, body, "sexual / 0.926")
	require.Contains(t, body, "Sub2API &lt;Admin&gt;")
}

func TestContentModerationUnbanUser_ActivatesUserAndInvalidatesAuthCache(t *testing.T) {
	userRepo := &contentModerationTestUserRepo{user: &User{ID: 1001, Email: "user@example.com", Status: StatusDisabled}}
	invalidator := &contentModerationTestAuthCacheInvalidator{}
	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(nil, repo, nil, nil, userRepo, invalidator, nil)

	result, err := svc.UnbanUser(context.Background(), 1001)

	require.NoError(t, err)
	require.Equal(t, int64(1001), result.UserID)
	require.Equal(t, StatusActive, result.Status)
	require.Len(t, userRepo.updated, 1)
	require.Equal(t, StatusActive, userRepo.updated[0].Status)
	require.Equal(t, []int64{1001}, invalidator.userIDs)
}

func TestContentModerationUnbanUser_ActiveUserOnlyInvalidatesAuthCache(t *testing.T) {
	userRepo := &contentModerationTestUserRepo{user: &User{ID: 1001, Email: "user@example.com", Status: StatusActive}}
	invalidator := &contentModerationTestAuthCacheInvalidator{}
	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(nil, repo, nil, nil, userRepo, invalidator, nil)

	result, err := svc.UnbanUser(context.Background(), 1001)

	require.NoError(t, err)
	require.Equal(t, StatusActive, result.Status)
	require.Empty(t, userRepo.updated)
	require.Equal(t, []int64{1001}, invalidator.userIDs)
}

func contentModerationIntPtr(v int) *int {
	return &v
}
