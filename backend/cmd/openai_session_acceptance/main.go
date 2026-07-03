package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	listenAddr        = "127.0.0.1:18082"
	mockBaseURL       = "http://" + listenAddr + "/mock-openai"
	harnessGroupID    = int64(11)
	harnessAPIKeyID   = int64(22)
	harnessUserID     = int64(1001)
	harnessModel      = "gpt-5.5"
	harnessBlockMsg   = "内容审计命中风险规则，请调整输入后重试"
	harnessBlockCode  = http.StatusForbidden
	harnessCleanScore = 0.01
	harnessBlockScore = 0.99
)

type harnessApp struct {
	svc          *service.ContentModerationService
	settings     *memorySettingRepo
	repo         *memoryModerationRepo
	hashCache    *memoryHashCache
	sessionStore *memorySessionStore
	mockHits     atomic.Int64
}

type scenarioResponse struct {
	Name            string                  `json:"name"`
	ModerationHits  int64                   `json:"moderation_hits"`
	Decisions       []decisionSnapshot      `json:"decisions"`
	Logs            []logSnapshot           `json:"logs"`
	SessionSnapshot map[string]sessionState `json:"session_snapshot"`
}

type decisionSnapshot struct {
	Step           string `json:"step"`
	ModerationHits int64  `json:"moderation_hits"`
	Allowed        bool   `json:"allowed"`
	Blocked        bool   `json:"blocked"`
	Flagged        bool   `json:"flagged"`
	Action         string `json:"action"`
	Message        string `json:"message"`
	StatusCode     int    `json:"status_code"`
	AuditAttempted bool   `json:"audit_attempted"`
	AuditSucceeded bool   `json:"audit_succeeded"`
}

type logSnapshot struct {
	Action       string    `json:"action"`
	Flagged      bool      `json:"flagged"`
	Highest      string    `json:"highest_category"`
	Excerpt      string    `json:"input_excerpt"`
	CreatedAt    time.Time `json:"created_at"`
	Matched      string    `json:"matched_keyword"`
	ViolationCnt int       `json:"violation_count"`
}

type sessionState struct {
	Blocked     bool `json:"blocked"`
	AllowWindow bool `json:"allow_window"`
	Inflight    bool `json:"inflight"`
}

type moderationAPIRequest struct {
	Input any `json:"input"`
}

type memorySettingRepo struct {
	mu     sync.Mutex
	values map[string]string
}

type memoryModerationRepo struct {
	mu   sync.Mutex
	logs []service.ContentModerationLog
}

type memoryHashCache struct {
	mu     sync.Mutex
	hashes map[string]struct{}
}

type memorySessionStore struct {
	mu          sync.Mutex
	blocked     map[string]struct{}
	allowWindow map[string]struct{}
	inflight    map[string]struct{}
}

func main() {
	app := newHarnessApp()

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/api/reset", app.handleReset)
	mux.HandleFunc("/api/scenario/session-first-sample", app.handleScenarioSessionFirstSample)
	mux.HandleFunc("/api/scenario/session-block", app.handleScenarioSessionBlock)
	mux.HandleFunc("/api/scenario/all-user-input", app.handleScenarioAllUserInput)
	mux.HandleFunc("/api/scenario/session-cross-key", app.handleScenarioSessionCrossKey)
	mux.HandleFunc("/api/scenario/non-explicit-fallback", app.handleScenarioNonExplicitFallback)
	mux.HandleFunc("/api/scenario/session-inflight-dedupe", app.handleScenarioSessionInflightDedupe)
	mux.HandleFunc("/mock-openai/v1/moderations", app.handleMockModeration)

	log.Printf("OpenAI session acceptance harness listening on http://%s\n", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func newHarnessApp() *harnessApp {
	cfg := service.ContentModerationConfig{
		Enabled:              true,
		Mode:                 service.ContentModerationModeAsyncBlock,
		BaseURL:              mockBaseURL,
		Model:                "omni-moderation-latest",
		APIKeys:              []string{"sk-test"},
		TimeoutMS:            3000,
		SampleRate:           0,
		AllGroups:            true,
		RecordNonHits:        true,
		Thresholds:           service.ContentModerationDefaultThresholds(),
		WorkerCount:          1,
		QueueSize:            128,
		BlockStatus:          harnessBlockCode,
		BlockMessage:         harnessBlockMsg,
		EmailOnHit:           false,
		AutoBanEnabled:       false,
		BanThreshold:         10,
		ViolationWindowHours: 720,
		RetryCount:           0,
		HitRetentionDays:     7,
		NonHitRetentionDays:  3,
		PreHashCheckEnabled:  true,
		BlockedKeywords:      []string{},
		KeywordBlockingMode:  service.ContentModerationKeywordModeKeywordAndAPI,
		ModelFilter: service.ContentModerationModelFilter{
			Type:   service.ContentModerationModelFilterAll,
			Models: []string{},
		},
	}
	rawCfg, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	settings := &memorySettingRepo{values: map[string]string{
		service.SettingKeyRiskControlEnabled:      "true",
		service.SettingKeyContentModerationConfig: string(rawCfg),
	}}
	repo := &memoryModerationRepo{}
	hashCache := &memoryHashCache{hashes: map[string]struct{}{}}
	sessionStore := &memorySessionStore{
		blocked:     map[string]struct{}{},
		allowWindow: map[string]struct{}{},
		inflight:    map[string]struct{}{},
	}
	svc := service.NewContentModerationService(settings, repo, hashCache, nil, nil, nil, nil).SetSessionStore(sessionStore)
	return &harnessApp{
		svc:          svc,
		settings:     settings,
		repo:         repo,
		hashCache:    hashCache,
		sessionStore: sessionStore,
	}
}

func (a *harnessApp) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (a *harnessApp) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.reset()
	writeJSON(w, map[string]any{"ok": true})
}

func (a *harnessApp) handleScenarioSessionFirstSample(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.reset()
	sessionKey := "chat-session-a"

	firstDecision, err := a.checkChat(sessionKey, `{"messages":[{"role":"user","content":"first clean prompt"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}
	secondDecision, err := a.checkChat(sessionKey, `{"messages":[{"role":"user","content":"second clean prompt"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}
	a.sessionStore.ClearAllowWindow(sessionScope(sessionKey))
	thirdDecision, err := a.checkChat(sessionKey, `{"messages":[{"role":"user","content":"third clean prompt"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := scenarioResponse{
		Name:           "session-first-sample",
		ModerationHits: a.mockHits.Load(),
		Decisions: []decisionSnapshot{
			decisionFrom("first clean request", firstDecision, 1),
			decisionFrom("second clean request within 5m window", secondDecision, 1),
			decisionFrom("third clean request after window cleared", thirdDecision, 2),
		},
		Logs:            a.snapshotLogs(),
		SessionSnapshot: a.sessionSnapshot([]string{sessionScope(sessionKey)}),
	}
	writeJSON(w, resp)
}

func (a *harnessApp) handleScenarioSessionBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.reset()
	sessionKey := "chat-session-b"

	blockDecision, err := a.checkChat(sessionKey, `{"messages":[{"role":"user","content":"blocked prompt should be denied"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}
	cleanDecision, err := a.checkChat(sessionKey, `{"messages":[{"role":"user","content":"clean prompt after block"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := scenarioResponse{
		Name:           "session-block",
		ModerationHits: a.mockHits.Load(),
		Decisions: []decisionSnapshot{
			decisionFrom("risky first request is allowed before async audit lands", blockDecision, 1),
			decisionFrom("clean request after async session blacklist", cleanDecision, 1),
		},
		Logs:            a.snapshotLogs(),
		SessionSnapshot: a.sessionSnapshot([]string{sessionScope(sessionKey)}),
	}
	writeJSON(w, resp)
}

func (a *harnessApp) handleScenarioAllUserInput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.reset()
	sessionKey := "responses-session-c"
	body := `{
		"model":"gpt-5.5",
		"instructions":"developer instructions should not be audited",
		"input":[
			{"type":"message","role":"developer","content":[{"type":"input_text","text":"developer instructions should not be audited"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"first user prompt"}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"assistant reply"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"last user prompt"}]}
		]
	}`

	decision, err := a.checkResponses(sessionKey, body)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := scenarioResponse{
		Name:           "all-user-input",
		ModerationHits: a.mockHits.Load(),
		Decisions: []decisionSnapshot{
			decisionFrom("responses request with two user turns", decision, a.mockHits.Load()),
		},
		Logs:            a.snapshotLogs(),
		SessionSnapshot: a.sessionSnapshot([]string{sessionScope(sessionKey)}),
	}
	writeJSON(w, resp)
}

func (a *harnessApp) handleScenarioSessionCrossKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.reset()
	sessionKey := "chat-session-key-rotate"

	blockDecision, err := a.checkChatWithAPIKey(sessionKey, harnessAPIKeyID, `{"messages":[{"role":"user","content":"blocked prompt should be denied"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}
	rotatedKeyDecision, err := a.checkChatWithAPIKey(sessionKey, harnessAPIKeyID+1, `{"messages":[{"role":"user","content":"clean prompt after rotating api key"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := scenarioResponse{
		Name:           "session-cross-key",
		ModerationHits: a.mockHits.Load(),
		Decisions: []decisionSnapshot{
			decisionFrom("risky request with api key A", blockDecision, 1),
			decisionFrom("clean request with api key B in same session", rotatedKeyDecision, 1),
		},
		Logs:            a.snapshotLogs(),
		SessionSnapshot: a.sessionSnapshot([]string{sessionScope(sessionKey)}),
	}
	writeJSON(w, resp)
}

func (a *harnessApp) handleScenarioNonExplicitFallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.reset()
	if err := a.setSampleRate(100); err != nil {
		writeError(w, err)
		return
	}
	defer func() { _ = a.setSampleRate(0) }()

	sessionKey := "fallback-session-hash"
	firstDecision, err := a.checkChatWithOptions(sessionKey, harnessAPIKeyID, false, `{"messages":[{"role":"user","content":"blocked first fallback prompt"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}
	secondDecision, err := a.checkChatWithOptions(sessionKey, harnessAPIKeyID, false, `{"messages":[{"role":"user","content":"blocked second fallback prompt"}]}`)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := scenarioResponse{
		Name:           "non-explicit-fallback",
		ModerationHits: a.mockHits.Load(),
		Decisions: []decisionSnapshot{
			decisionFrom("fallback session request 1", firstDecision, 1),
			decisionFrom("fallback session request 2 still re-audits instead of session ban", secondDecision, 2),
		},
		Logs:            a.snapshotLogs(),
		SessionSnapshot: a.sessionSnapshot([]string{sessionScope(sessionKey)}),
	}
	writeJSON(w, resp)
}

func (a *harnessApp) handleScenarioSessionInflightDedupe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.reset()
	sessionKey := "session-inflight"
	const concurrency = 4
	decisions := make([]*service.ContentModerationDecision, concurrency)
	errs := make([]error, concurrency)
	var wg sync.WaitGroup
	for idx := 0; idx < concurrency; idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			decisions[i], errs[i] = a.checkChatWithOptions(sessionKey, harnessAPIKeyID, true, `{"messages":[{"role":"user","content":"slow clean prompt"}]}`)
		}(idx)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			writeError(w, err)
			return
		}
	}
	a.waitForAsyncLogs()

	snapshots := make([]decisionSnapshot, 0, len(decisions))
	for idx, decision := range decisions {
		snapshots = append(snapshots, decisionFrom(fmt.Sprintf("concurrent request %d", idx+1), decision, a.mockHits.Load()))
	}
	resp := scenarioResponse{
		Name:           "session-inflight-dedupe",
		ModerationHits: a.mockHits.Load(),
		Decisions:      snapshots,
		Logs:           a.snapshotLogs(),
		SessionSnapshot: a.sessionSnapshot([]string{
			sessionScope(sessionKey),
		}),
	}
	writeJSON(w, resp)
}

func (a *harnessApp) handleMockModeration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mockHits.Add(1)

	var req moderationAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	text := moderationInputText(req.Input)
	if strings.Contains(strings.ToLower(text), "slow") {
		time.Sleep(180 * time.Millisecond)
	}
	score := harnessCleanScore
	if strings.Contains(strings.ToLower(text), "blocked") {
		score = harnessBlockScore
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"results": []map[string]any{
			{
				"category_scores": map[string]float64{
					"sexual": score,
				},
			},
		},
	})
}

func (a *harnessApp) checkChat(sessionKey string, body string) (*service.ContentModerationDecision, error) {
	return a.checkChatWithAPIKey(sessionKey, harnessAPIKeyID, body)
}

func (a *harnessApp) checkChatWithAPIKey(sessionKey string, apiKeyID int64, body string) (*service.ContentModerationDecision, error) {
	return a.checkChatWithOptions(sessionKey, apiKeyID, true, body)
}

func (a *harnessApp) checkChatWithOptions(sessionKey string, apiKeyID int64, sessionExplicit bool, body string) (*service.ContentModerationDecision, error) {
	bodyBytes := []byte(body)
	decision, err := a.svc.Check(context.Background(), service.ContentModerationCheckInput{
		UserID:          harnessUserID,
		APIKeyID:        apiKeyID,
		GroupID:         int64Ptr(harnessGroupID),
		GroupName:       "acceptance",
		Endpoint:        "/v1/chat/completions",
		Provider:        service.PlatformOpenAI,
		Model:           harnessModel,
		Protocol:        service.ContentModerationProtocolOpenAIChat,
		SessionKey:      sessionKey,
		SessionExplicit: sessionExplicit,
		Body:            bodyBytes,
	})
	if err != nil {
		return nil, err
	}
	a.waitForAsyncLogs()
	return decision, nil
}

func (a *harnessApp) checkResponses(sessionKey string, body string) (*service.ContentModerationDecision, error) {
	return a.checkResponsesWithAPIKey(sessionKey, harnessAPIKeyID, body)
}

func (a *harnessApp) checkResponsesWithAPIKey(sessionKey string, apiKeyID int64, body string) (*service.ContentModerationDecision, error) {
	return a.checkResponsesWithOptions(sessionKey, apiKeyID, true, body)
}

func (a *harnessApp) checkResponsesWithOptions(sessionKey string, apiKeyID int64, sessionExplicit bool, body string) (*service.ContentModerationDecision, error) {
	bodyBytes := []byte(body)
	decision, err := a.svc.Check(context.Background(), service.ContentModerationCheckInput{
		UserID:          harnessUserID,
		APIKeyID:        apiKeyID,
		GroupID:         int64Ptr(harnessGroupID),
		GroupName:       "acceptance",
		Endpoint:        "/v1/responses",
		Provider:        service.PlatformOpenAI,
		Model:           harnessModel,
		Protocol:        service.ContentModerationProtocolOpenAIResponses,
		SessionKey:      sessionKey,
		SessionExplicit: sessionExplicit,
		Body:            bodyBytes,
	})
	if err != nil {
		return nil, err
	}
	a.waitForAsyncLogs()
	return decision, nil
}

func (a *harnessApp) waitForAsyncLogs() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status, err := a.svc.GetStatus(context.Background())
		if err == nil && status.QueueLength == 0 && status.ActiveWorkers == 0 {
			time.Sleep(40 * time.Millisecond)
			status, err = a.svc.GetStatus(context.Background())
			if err == nil && status.QueueLength == 0 && status.ActiveWorkers == 0 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (a *harnessApp) reset() {
	a.mockHits.Store(0)
	a.repo.Reset()
	a.hashCache.Reset()
	a.sessionStore.Reset()
}

func (a *harnessApp) snapshotLogs() []logSnapshot {
	items := a.repo.Snapshot()
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	out := make([]logSnapshot, 0, len(items))
	for _, item := range items {
		out = append(out, logSnapshot{
			Action:       item.Action,
			Flagged:      item.Flagged,
			Highest:      item.HighestCategory,
			Excerpt:      item.InputExcerpt,
			CreatedAt:    item.CreatedAt,
			Matched:      item.MatchedKeyword,
			ViolationCnt: item.ViolationCount,
		})
	}
	return out
}

func (a *harnessApp) sessionSnapshot(scopes []string) map[string]sessionState {
	return a.sessionStore.Snapshot(scopes)
}

func decisionFrom(step string, decision *service.ContentModerationDecision, moderationHits int64) decisionSnapshot {
	if decision == nil {
		return decisionSnapshot{Step: step, ModerationHits: moderationHits}
	}
	return decisionSnapshot{
		Step:           step,
		ModerationHits: moderationHits,
		Allowed:        decision.Allowed,
		Blocked:        decision.Blocked,
		Flagged:        decision.Flagged,
		Action:         decision.Action,
		Message:        decision.Message,
		StatusCode:     decision.StatusCode,
		AuditAttempted: decision.AuditAttempted,
		AuditSucceeded: decision.AuditSucceeded,
	}
}

func sessionScope(sessionKey string) string {
	return fmt.Sprintf("openai:%d:user:%d:%s", harnessGroupID, harnessUserID, strings.TrimSpace(sessionKey))
}

func (a *harnessApp) setSampleRate(rate int) error {
	cfg, err := a.svc.GetConfig(context.Background())
	if err != nil {
		return err
	}
	view, err := a.svc.UpdateConfig(context.Background(), service.UpdateContentModerationConfigInput{
		SampleRate: &rate,
		Mode:       stringPtr(cfg.Mode),
	})
	if err != nil {
		return err
	}
	if view.SampleRate != rate {
		return fmt.Errorf("expected sample_rate=%d, got %d", rate, view.SampleRate)
	}
	return nil
}

func stringPtr(v string) *string {
	return &v
}

func moderationInputText(input any) string {
	switch v := input.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if typ, _ := obj["type"].(string); typ == "text" {
				if text, _ := obj["text"].(string); text != "" {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

func int64Ptr(v int64) *int64 {
	return &v
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	writeJSON(w, map[string]any{
		"error": err.Error(),
	})
}

func (r *memorySettingRepo) Get(ctx context.Context, key string) (*service.Setting, error) {
	if value, ok := r.values[key]; ok {
		return &service.Setting{Key: key, Value: value}, nil
	}
	return nil, service.ErrSettingNotFound
}

func (r *memorySettingRepo) GetValue(ctx context.Context, key string) (string, error) {
	if value, ok := r.values[key]; ok {
		return value, nil
	}
	return "", service.ErrSettingNotFound
}

func (r *memorySettingRepo) Set(ctx context.Context, key, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.values == nil {
		r.values = map[string]string{}
	}
	r.values[key] = value
	return nil
}

func (r *memorySettingRepo) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(keys))
	for _, key := range keys {
		if value, ok := r.values[key]; ok {
			out[key] = value
		}
	}
	return out, nil
}

func (r *memorySettingRepo) SetMultiple(ctx context.Context, settings map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.values == nil {
		r.values = map[string]string{}
	}
	for key, value := range settings {
		r.values[key] = value
	}
	return nil
}

func (r *memorySettingRepo) GetAll(ctx context.Context) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.values))
	for key, value := range r.values {
		out[key] = value
	}
	return out, nil
}

func (r *memorySettingRepo) Delete(ctx context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.values, key)
	return nil
}

func (r *memoryModerationRepo) CreateLog(ctx context.Context, item *service.ContentModerationLog) error {
	if item == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *item
	if clone.CreatedAt.IsZero() {
		clone.CreatedAt = time.Now()
	}
	r.logs = append(r.logs, clone)
	return nil
}

func (r *memoryModerationRepo) ListLogs(ctx context.Context, filter service.ContentModerationLogFilter) ([]service.ContentModerationLog, *pagination.PaginationResult, error) {
	items := r.Snapshot()
	return items, nil, nil
}

func (r *memoryModerationRepo) CountFlaggedByUserSince(ctx context.Context, userID int64, since time.Time, excludeCyberPolicy bool) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, item := range r.logs {
		if item.UserID == nil || *item.UserID != userID || !item.Flagged {
			continue
		}
		if item.Action == service.ContentModerationActionHashBlock || item.Action == service.ContentModerationActionSessionBlock {
			continue
		}
		if excludeCyberPolicy && item.Action == service.ContentModerationActionCyberPolicy {
			continue
		}
		if item.CreatedAt.Before(since) {
			continue
		}
		count++
	}
	return count, nil
}

func (r *memoryModerationRepo) CleanupExpiredLogs(ctx context.Context, hitBefore time.Time, nonHitBefore time.Time) (*service.ContentModerationCleanupResult, error) {
	return &service.ContentModerationCleanupResult{FinishedAt: time.Now()}, nil
}

func (r *memoryModerationRepo) UpdateLogEmailSent(ctx context.Context, id int64, sent bool) error {
	return nil
}

func (r *memoryModerationRepo) Snapshot() []service.ContentModerationLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]service.ContentModerationLog, len(r.logs))
	copy(out, r.logs)
	return out
}

func (r *memoryModerationRepo) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = nil
}

func (c *memoryHashCache) RecordFlaggedInputHash(ctx context.Context, inputHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hashes == nil {
		c.hashes = map[string]struct{}{}
	}
	c.hashes[inputHash] = struct{}{}
	return nil
}

func (c *memoryHashCache) HasFlaggedInputHash(ctx context.Context, inputHash string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.hashes[inputHash]
	return ok, nil
}

func (c *memoryHashCache) DeleteFlaggedInputHash(ctx context.Context, inputHash string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.hashes[inputHash]
	delete(c.hashes, inputHash)
	return ok, nil
}

func (c *memoryHashCache) ClearFlaggedInputHashes(ctx context.Context) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := int64(len(c.hashes))
	c.hashes = map[string]struct{}{}
	return n, nil
}

func (c *memoryHashCache) CountFlaggedInputHashes(ctx context.Context) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int64(len(c.hashes)), nil
}

func (c *memoryHashCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hashes = map[string]struct{}{}
}

func (s *memorySessionStore) IsBlocked(ctx context.Context, scope string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.blocked[scope]
	return ok, nil
}

func (s *memorySessionStore) MarkBlocked(ctx context.Context, scope string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked == nil {
		s.blocked = map[string]struct{}{}
	}
	s.blocked[scope] = struct{}{}
	return nil
}

func (s *memorySessionStore) HasAllowWindow(ctx context.Context, scope string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.allowWindow[scope]
	return ok, nil
}

func (s *memorySessionStore) MarkAllowWindow(ctx context.Context, scope string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.allowWindow == nil {
		s.allowWindow = map[string]struct{}{}
	}
	s.allowWindow[scope] = struct{}{}
	return nil
}

func (s *memorySessionStore) AcquireInflight(ctx context.Context, scope string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight == nil {
		s.inflight = map[string]struct{}{}
	}
	if _, ok := s.inflight[scope]; ok {
		return false, nil
	}
	s.inflight[scope] = struct{}{}
	return true, nil
}

func (s *memorySessionStore) ClearInflight(ctx context.Context, scope string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, scope)
	return nil
}

func (s *memorySessionStore) ClearAllowWindow(scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.allowWindow, scope)
}

func (s *memorySessionStore) Snapshot(scopes []string) map[string]sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]sessionState, len(scopes))
	for _, scope := range scopes {
		_, blocked := s.blocked[scope]
		_, allow := s.allowWindow[scope]
		_, inflight := s.inflight[scope]
		out[scope] = sessionState{
			Blocked:     blocked,
			AllowWindow: allow,
			Inflight:    inflight,
		}
	}
	return out
}

func (s *memorySessionStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked = map[string]struct{}{}
	s.allowWindow = map[string]struct{}{}
	s.inflight = map[string]struct{}{}
}

const indexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenAI Session 审计验收页</title>
  <style>
    :root {
      --bg: #f4f1ea;
      --panel: #fffdf7;
      --ink: #1f2a2c;
      --muted: #5f6b6d;
      --line: #d7d0c2;
      --accent: #b85c38;
      --ok: #2f7d4c;
      --bad: #b42318;
      --warn: #a15c07;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "SF Pro Text", "PingFang SC", "Helvetica Neue", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(184,92,56,.12), transparent 34%),
        linear-gradient(180deg, #efe6d8 0%, var(--bg) 48%, #f8f6f1 100%);
      min-height: 100vh;
    }
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }
    h1 {
      font-size: 34px;
      margin: 0 0 8px;
      letter-spacing: -.02em;
    }
    .lead {
      color: var(--muted);
      margin-bottom: 24px;
      line-height: 1.6;
      max-width: 880px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
      margin-bottom: 18px;
    }
    .card {
      background: rgba(255,253,247,.88);
      backdrop-filter: blur(8px);
      border: 1px solid rgba(215,208,194,.9);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 18px 46px rgba(31,42,44,.07);
    }
    .card h2 {
      margin: 0 0 10px;
      font-size: 21px;
    }
    .card p {
      color: var(--muted);
      margin-top: 0;
      line-height: 1.55;
    }
    button {
      border: 0;
      border-radius: 999px;
      padding: 11px 18px;
      background: var(--accent);
      color: #fff;
      font-weight: 600;
      cursor: pointer;
      transition: transform .14s ease, opacity .14s ease;
      margin-right: 10px;
      margin-bottom: 10px;
    }
    button.secondary {
      background: #d8d1c4;
      color: #223032;
    }
    button:hover { transform: translateY(-1px); }
    button:disabled { opacity: .55; cursor: wait; transform: none; }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin: 10px 0 0;
      font-size: 14px;
      color: var(--muted);
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 999px;
      padding: 6px 10px;
      background: #efe7da;
    }
    .panel {
      background: #0f1720;
      color: #d6e2f1;
      border-radius: 18px;
      padding: 18px;
      min-height: 220px;
      overflow: auto;
      white-space: pre-wrap;
      line-height: 1.55;
      font-size: 13px;
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.06);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 14px;
      background: rgba(255,255,255,.72);
      border-radius: 14px;
      overflow: hidden;
    }
    th, td {
      text-align: left;
      padding: 12px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      font-size: 14px;
    }
    th {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .08em;
      color: var(--muted);
      background: rgba(239,230,216,.88);
    }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
    }
    .badge.allow { background: rgba(47,125,76,.14); color: var(--ok); }
    .badge.block, .badge.async_block, .badge.session_block { background: rgba(180,35,24,.14); color: var(--bad); }
    .badge.hash_block, .badge.keyword_block { background: rgba(161,92,7,.14); color: var(--warn); }
    .hint {
      margin-top: 14px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }
  </style>
</head>
<body>
  <main>
    <h1>OpenAI Session 审计手工验收页</h1>
    <p class="lead">
      这个页面不是静态 mock。它直接调用本次改过的 Go 风控逻辑，只把外部依赖换成了本地 mock moderation upstream 和内存存储，
      用来手工验证四条核心业务结论：显式 session 首条必审且先放行、异步命中后拉黑 session、无显式 session 时降级为 observe-like、OpenAI 审计文本改成当前 payload 的所有 user input。
    </p>

    <div class="grid">
      <section class="card">
        <h2>场景 1：首条必审 + 5 分钟放行窗</h2>
        <p>配置里 <code>sample_rate=0</code>。第一条显式 session 请求仍然必须打 moderation，但当次请求先放行。第二条同 session 不该再打 moderation，手动清掉放行窗后第三条应重新审计。</p>
        <button data-endpoint="/api/scenario/session-first-sample">运行场景 1</button>
      </section>
      <section class="card">
        <h2>场景 2：异步命中后拉黑 session</h2>
        <p>第一条发风险内容但当次先放行；异步审核落地后，第二条 clean 内容保持同一个 session。预期第二条不再访问 moderation，而是直接 <code>session_block</code>。</p>
        <button data-endpoint="/api/scenario/session-block">运行场景 2</button>
      </section>
      <section class="card">
        <h2>场景 3：所有 user input 都参与审计</h2>
        <p>Responses payload 里放两段 user 文本和一段 developer 文本。预期风控日志的 <code>input_excerpt</code> 只包含两段 user 文本，不包含 developer 文本。</p>
        <button data-endpoint="/api/scenario/all-user-input">运行场景 3</button>
      </section>
      <section class="card">
        <h2>场景 4：同用户换 key 不能绕过 blocked session</h2>
        <p>第一条用 API key A 发风险内容并等待异步拉黑，第二条换 API key B 但保持同一个 user 和 session。预期第二条仍然本地命中 <code>session_block</code>，不会重新访问 moderation。</p>
        <button data-endpoint="/api/scenario/session-cross-key">运行场景 4</button>
      </section>
      <section class="card">
        <h2>场景 5：无显式 session 时只做 fallback sampling</h2>
        <p>把 <code>session_explicit</code> 置为 false，并临时把 <code>sample_rate</code> 提到 100。预期请求仍会异步审核，但不会写 blocked/allow window，第二条还会继续打 moderation。</p>
        <button data-endpoint="/api/scenario/non-explicit-fallback">运行场景 5</button>
      </section>
      <section class="card">
        <h2>场景 6：并发同 session 只审核一次</h2>
        <p>并发发 4 条显式 session 请求，mock moderation 人工延迟 180ms。预期所有请求先放行，但 <code>moderation_hits</code> 只出现 1 次，说明 inflight 去重生效。</p>
        <button data-endpoint="/api/scenario/session-inflight-dedupe">运行场景 6</button>
      </section>
    </div>

    <section class="card">
      <button class="secondary" id="resetBtn">重置状态</button>
      <div class="meta">
        <span class="pill">本地地址: <code>http://127.0.0.1:18082</code></span>
        <span class="pill">mock upstream: <code>/mock-openai/v1/moderations</code></span>
        <span class="pill">session scope: <code>openai:11:user:1001:&lt;session&gt;</code></span>
      </div>
      <div class="hint">人工验收时重点看四列：<code>decisions[].moderation_hits</code> 是否按步骤递增、<code>decisions[].action</code> 是否出现 <code>async_block</code> / <code>session_block</code>、日志里的 <code>input_excerpt</code> 是否是所有 user input，以及 <code>session_snapshot</code> 里 blocked / allow_window / inflight 的变化。</div>
    </section>

    <div class="grid" style="margin-top:18px">
      <section class="card">
        <h2>执行结果</h2>
        <div class="panel" id="resultPanel">点击上面的场景按钮后，这里会显示完整 JSON 返回。</div>
      </section>
      <section class="card">
        <h2>风控日志视图</h2>
        <div id="tableWrap"></div>
      </section>
    </div>
  </main>
  <script>
    const resultPanel = document.getElementById('resultPanel');
    const tableWrap = document.getElementById('tableWrap');
    const buttons = Array.from(document.querySelectorAll('button[data-endpoint]'));
    const resetBtn = document.getElementById('resetBtn');

    function badgeClass(action) {
      return ['block', 'async_block', 'session_block', 'hash_block', 'keyword_block'].includes(action) ? action : 'allow';
    }

    function renderLogs(logs = []) {
      if (!logs.length) {
        tableWrap.innerHTML = '<p class="hint">当前还没有日志。</p>';
        return;
      }
      const rows = logs.map((log) =>
        '<tr>' +
          '<td><span class="badge ' + badgeClass(log.action) + '">' + log.action + '</span></td>' +
          '<td>' + log.flagged + '</td>' +
          '<td>' + (log.highest || '') + '</td>' +
          '<td>' + (log.excerpt || '') + '</td>' +
        '</tr>'
      ).join('');
      tableWrap.innerHTML =
        '<table>' +
          '<thead>' +
            '<tr>' +
              '<th>Action</th>' +
              '<th>Flagged</th>' +
              '<th>Highest</th>' +
              '<th>Input Excerpt</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' + rows + '</tbody>' +
        '</table>';
    }

    async function postJSON(endpoint) {
      const res = await fetch(endpoint, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'request failed');
      return data;
    }

    async function run(endpoint, button) {
      buttons.forEach(btn => btn.disabled = true);
      resetBtn.disabled = true;
      resultPanel.textContent = '运行中...';
      try {
        const data = await postJSON(endpoint);
        resultPanel.textContent = JSON.stringify(data, null, 2);
        renderLogs(data.logs);
      } catch (error) {
        resultPanel.textContent = String(error);
        renderLogs([]);
      } finally {
        buttons.forEach(btn => btn.disabled = false);
        resetBtn.disabled = false;
      }
    }

    buttons.forEach((button) => {
      button.addEventListener('click', () => run(button.dataset.endpoint, button));
    });

    resetBtn.addEventListener('click', async () => {
      resetBtn.disabled = true;
      try {
        await postJSON('/api/reset');
        resultPanel.textContent = '状态已重置。';
        renderLogs([]);
      } catch (error) {
        resultPanel.textContent = String(error);
      } finally {
        resetBtn.disabled = false;
      }
    });
  </script>
</body>
</html>`
