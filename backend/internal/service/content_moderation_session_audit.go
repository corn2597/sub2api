package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/tidwall/gjson"
)

const (
	RiskControlProviderLegacyModeration            = "legacy_moderation"
	RiskControlProviderOpenAIResponsesSessionAudit = "openai_responses_session_audit"
	defaultSessionAuditBaseURL                     = "https://api.openai.com"
	defaultSessionAuditPath                        = "/v1/responses"
	defaultSessionAuditTimeoutMS                   = 3000
	defaultSessionAuditBlockConfidenceThreshold    = 0.7
	defaultSessionAuditIntervalSeconds             = 300
	defaultSessionAuditMaxInputChars               = 12000
	defaultSessionAuditWaitPadding                 = time.Second
	defaultSessionAuditPollInterval                = 25 * time.Millisecond
	defaultSessionAuditPermanentBlacklistCacheTTL  = 24 * time.Hour
	defaultSessionAuditSuccessTTL                  = time.Hour
	defaultSessionAuditAttemptTTL                  = 10 * time.Minute
	sessionAuditBlockMessage                       = "Request blocked by risk control policy."
	sessionAuditDefaultCategory                    = "session_audit"
)

var defaultSessionAuditEnabledProtocols = []string{ContentModerationProtocolAnthropicMessages}

type SessionAuditProviderConfig struct {
	Provider                 string
	BaseURL                  string
	Path                     string
	Model                    string
	APIKeys                  []string
	TimeoutMS                int
	FailClosed               bool
	BlockConfidenceThreshold float64
	SessionAuditInterval     time.Duration
	SessionBlacklistTTL      time.Duration
	EnabledProtocols         []string
	AuditMaxInputChars       int
	PromptTemplate           string

	enabledProtocolSet map[string]struct{}
}

type SessionAuditClient interface {
	Audit(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error)
}

type OpenAIResponsesSessionAuditRequest struct {
	SessionHash string
	Prompt      string
	Payload     string
}

type OpenAIResponsesSessionAuditResult struct {
	ResponseID        string   `json:"-"`
	Violates          bool     `json:"violates"`
	Confidence        float64  `json:"confidence"`
	Categories        []string `json:"categories"`
	Reason            string   `json:"reason"`
	EvidenceExcerpt   string   `json:"evidence_excerpt"`
	RecommendedAction string   `json:"recommended_action"`
}

type RiskSessionBlacklist struct {
	ID              int64
	SessionHash     string
	UserID          *int64
	APIKeyID        *int64
	GroupID         *int64
	Reason          string
	Categories      []string
	Confidence      float64
	AuditModel      string
	AuditResponseID string
	SourceProtocol  string
	SourceModel     string
	FirstBlockedAt  time.Time
	LastSeenAt      time.Time
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type RiskSessionBlacklistCacheEntry struct {
	SessionHash     string     `json:"session_hash"`
	Reason          string     `json:"reason"`
	Categories      []string   `json:"categories"`
	Confidence      float64    `json:"confidence"`
	AuditModel      string     `json:"audit_model"`
	AuditResponseID string     `json:"audit_response_id"`
	SourceProtocol  string     `json:"source_protocol"`
	SourceModel     string     `json:"source_model"`
	FirstBlockedAt  time.Time  `json:"first_blocked_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

func defaultSessionAuditProviderConfig() *SessionAuditProviderConfig {
	cfg := &SessionAuditProviderConfig{
		Provider:                 RiskControlProviderLegacyModeration,
		BaseURL:                  defaultSessionAuditBaseURL,
		Path:                     defaultSessionAuditPath,
		APIKeys:                  []string{},
		TimeoutMS:                defaultSessionAuditTimeoutMS,
		FailClosed:               false,
		BlockConfidenceThreshold: defaultSessionAuditBlockConfidenceThreshold,
		SessionAuditInterval:     defaultSessionAuditIntervalSeconds * time.Second,
		SessionBlacklistTTL:      0,
		EnabledProtocols:         append([]string(nil), defaultSessionAuditEnabledProtocols...),
		AuditMaxInputChars:       defaultSessionAuditMaxInputChars,
		PromptTemplate:           "",
	}
	cfg.normalize()
	return cfg
}

func (cfg *SessionAuditProviderConfig) normalize() {
	if cfg == nil {
		return
	}
	cfg.Provider = normalizeRiskControlProvider(cfg.Provider)
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultSessionAuditBaseURL
	}
	cfg.Path = normalizeAuditPath(cfg.Path)
	cfg.Model = strings.TrimSpace(cfg.Model)
	cfg.APIKeys = normalizeModerationAPIKeys(cfg.APIKeys)
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = defaultSessionAuditTimeoutMS
	}
	if cfg.TimeoutMS > maxContentModerationTimeoutMS {
		cfg.TimeoutMS = maxContentModerationTimeoutMS
	}
	if cfg.BlockConfidenceThreshold < 0 {
		cfg.BlockConfidenceThreshold = 0
	}
	if cfg.BlockConfidenceThreshold > 1 {
		cfg.BlockConfidenceThreshold = 1
	}
	if cfg.SessionAuditInterval < 0 {
		cfg.SessionAuditInterval = 0
	}
	if cfg.SessionBlacklistTTL < 0 {
		cfg.SessionBlacklistTTL = 0
	}
	cfg.EnabledProtocols = normalizeSessionAuditProtocols(cfg.EnabledProtocols)
	cfg.enabledProtocolSet = make(map[string]struct{}, len(cfg.EnabledProtocols))
	for _, protocol := range cfg.EnabledProtocols {
		cfg.enabledProtocolSet[protocol] = struct{}{}
	}
	if cfg.AuditMaxInputChars <= 0 {
		cfg.AuditMaxInputChars = defaultSessionAuditMaxInputChars
	}
	cfg.PromptTemplate = strings.TrimSpace(cfg.PromptTemplate)
}

func (cfg *SessionAuditProviderConfig) UsesSessionAuditForProtocol(protocol string) bool {
	if cfg == nil || cfg.Provider != RiskControlProviderOpenAIResponsesSessionAudit {
		return false
	}
	_, ok := cfg.enabledProtocolSet[strings.TrimSpace(protocol)]
	return ok
}

func (s *ContentModerationService) loadSessionAuditProviderConfig(ctx context.Context) (*SessionAuditProviderConfig, error) {
	cfg := defaultSessionAuditProviderConfig()
	if s == nil || s.settingRepo == nil {
		return cfg, nil
	}
	values, err := s.settingRepo.GetMultiple(ctx, []string{
		SettingKeyRiskControlProvider,
		SettingKeyAuditBaseURL,
		SettingKeyAuditPath,
		SettingKeyAuditModel,
		SettingKeyAuditAPIKeys,
		SettingKeyAuditTimeoutMS,
		SettingKeyAuditFailClosed,
		SettingKeyAuditBlockConfidenceThreshold,
		SettingKeySessionAuditIntervalSeconds,
		SettingKeySessionBlacklistTTLSeconds,
		SettingKeySessionAuditEnabledProtocols,
		SettingKeyAuditMaxInputChars,
		SettingKeyAuditPromptTemplate,
	})
	if err != nil {
		return nil, fmt.Errorf("get session audit settings: %w", err)
	}
	if raw, ok := values[SettingKeyRiskControlProvider]; ok {
		cfg.Provider = raw
	}
	if raw, ok := values[SettingKeyAuditBaseURL]; ok {
		cfg.BaseURL = raw
	}
	if raw, ok := values[SettingKeyAuditPath]; ok {
		cfg.Path = raw
	}
	if raw, ok := values[SettingKeyAuditModel]; ok {
		cfg.Model = raw
	}
	if raw, ok := values[SettingKeyAuditAPIKeys]; ok {
		cfg.APIKeys = parseStringListSetting(raw)
	}
	if raw, ok := values[SettingKeyAuditTimeoutMS]; ok {
		if v, parseErr := strconv.Atoi(strings.TrimSpace(raw)); parseErr == nil {
			cfg.TimeoutMS = v
		}
	}
	if raw, ok := values[SettingKeyAuditFailClosed]; ok {
		cfg.FailClosed = parseBoolSettingValue(raw)
	}
	if raw, ok := values[SettingKeyAuditBlockConfidenceThreshold]; ok {
		if v, parseErr := strconv.ParseFloat(strings.TrimSpace(raw), 64); parseErr == nil {
			cfg.BlockConfidenceThreshold = v
		}
	}
	if raw, ok := values[SettingKeySessionAuditIntervalSeconds]; ok {
		if v, parseErr := strconv.Atoi(strings.TrimSpace(raw)); parseErr == nil {
			cfg.SessionAuditInterval = time.Duration(v) * time.Second
		}
	}
	if raw, ok := values[SettingKeySessionBlacklistTTLSeconds]; ok {
		if v, parseErr := strconv.Atoi(strings.TrimSpace(raw)); parseErr == nil {
			cfg.SessionBlacklistTTL = time.Duration(v) * time.Second
		}
	}
	if raw, ok := values[SettingKeySessionAuditEnabledProtocols]; ok {
		cfg.EnabledProtocols = parseStringListSetting(raw)
	}
	if raw, ok := values[SettingKeyAuditMaxInputChars]; ok {
		if v, parseErr := strconv.Atoi(strings.TrimSpace(raw)); parseErr == nil {
			cfg.AuditMaxInputChars = v
		}
	}
	if raw, ok := values[SettingKeyAuditPromptTemplate]; ok {
		cfg.PromptTemplate = raw
	}
	cfg.normalize()
	return cfg, nil
}

func (s *ContentModerationService) checkSessionAudit(ctx context.Context, input ContentModerationCheckInput, cfg *ContentModerationConfig, sessionCfg *SessionAuditProviderConfig) *ContentModerationDecision {
	allow := &ContentModerationDecision{Allowed: true, Action: ContentModerationActionAllow}
	if s == nil || cfg == nil || sessionCfg == nil {
		return allow
	}
	if strings.TrimSpace(sessionCfg.Model) == "" {
		slog.Warn("content_moderation.session_audit_missing_model",
			"user_id", input.UserID,
			"api_key_id", input.APIKeyID,
			"group_id", contentModerationLogGroupID(input.GroupID),
			"endpoint", input.Endpoint,
			"protocol", input.Protocol)
		if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
			s.recordPreBlockSyncMetric(0, ContentModerationActionError)
			return blockedSessionAuditErrorDecision()
		}
		if cfg.Mode == ContentModerationModePreBlock {
			s.recordPreBlockSyncMetric(0, ContentModerationActionAllow)
		}
		return allow
	}
	if len(sessionCfg.APIKeys) == 0 {
		slog.Warn("content_moderation.session_audit_missing_keys",
			"user_id", input.UserID,
			"api_key_id", input.APIKeyID,
			"group_id", contentModerationLogGroupID(input.GroupID),
			"endpoint", input.Endpoint,
			"protocol", input.Protocol)
		if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
			s.recordPreBlockSyncMetric(0, ContentModerationActionError)
			return blockedSessionAuditErrorDecision()
		}
		if cfg.Mode == ContentModerationModePreBlock {
			s.recordPreBlockSyncMetric(0, ContentModerationActionAllow)
		}
		return allow
	}

	sessionHash, sessionSource, err := s.extractSessionAuditHash(input)
	if err != nil {
		slog.Warn("content_moderation.session_audit_hash_failed",
			"user_id", input.UserID,
			"api_key_id", input.APIKeyID,
			"group_id", contentModerationLogGroupID(input.GroupID),
			"endpoint", input.Endpoint,
			"protocol", input.Protocol,
			"error", err)
		if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
			s.recordPreBlockSyncMetric(0, ContentModerationActionError)
			return blockedSessionAuditErrorDecision()
		}
		if cfg.Mode == ContentModerationModePreBlock {
			s.recordPreBlockSyncMetric(0, ContentModerationActionAllow)
		}
		return allow
	}
	if sessionHash == "" {
		if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
			s.recordPreBlockSyncMetric(0, ContentModerationActionError)
			return blockedSessionAuditErrorDecision()
		}
		if cfg.Mode == ContentModerationModePreBlock {
			s.recordPreBlockSyncMetric(0, ContentModerationActionAllow)
		}
		return allow
	}

	if cfg.Mode == ContentModerationModePreBlock {
		blacklist, blackErr := s.IsSessionBlacklisted(ctx, sessionHash)
		if blackErr != nil {
			slog.Warn("content_moderation.session_blacklist_check_failed",
				"session_hash", sessionHash,
				"endpoint", input.Endpoint,
				"protocol", input.Protocol,
				"error", blackErr)
		} else if blacklist != nil {
			_ = s.TouchBlacklistedSession(ctx, sessionHash)
			slog.Info("content_moderation.session_blacklist_block",
				"session_hash", sessionHash,
				"endpoint", input.Endpoint,
				"protocol", input.Protocol)
			s.recordPreBlockSyncMetric(0, ContentModerationActionBlock)
			return blockedSessionAuditBlacklistDecision(blacklist)
		}
	}

	if auditedRecently, lastSuccessAt := s.hasRecentSessionAuditSuccess(ctx, sessionHash, sessionCfg); auditedRecently {
		slog.Info("content_moderation.session_audit_cache_hit",
			"session_hash", sessionHash,
			"endpoint", input.Endpoint,
			"protocol", input.Protocol,
			"last_success_audit_at", lastSuccessAt.UTC().Format(time.RFC3339))
		if cfg.Mode == ContentModerationModePreBlock {
			s.recordPreBlockSyncMetric(0, ContentModerationActionAllow)
		}
		return allow
	}

	for {
		lockToken, ok, lockErr := s.acquireSessionAuditLock(ctx, sessionHash, sessionCfg)
		if lockErr != nil {
			slog.Warn("content_moderation.session_audit_lock_failed",
				"session_hash", sessionHash,
				"endpoint", input.Endpoint,
				"protocol", input.Protocol,
				"error", lockErr)
			if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
				s.recordPreBlockSyncMetric(0, ContentModerationActionError)
				return blockedSessionAuditErrorDecision()
			}
			if cfg.Mode == ContentModerationModePreBlock {
				s.recordPreBlockSyncMetric(0, ContentModerationActionAllow)
			}
			return allow
		}
		if ok {
			return s.performSessionAuditLocked(ctx, input, cfg, sessionCfg, sessionHash, sessionSource, lockToken)
		}
		decision, retryAcquire := s.waitForSessionAuditOutcome(ctx, input, cfg, sessionCfg, sessionHash)
		if decision != nil {
			return decision
		}
		if !retryAcquire {
			if cfg.Mode == ContentModerationModePreBlock {
				s.recordPreBlockSyncMetric(0, ContentModerationActionAllow)
			}
			return allow
		}
	}
}

func (s *ContentModerationService) waitForSessionAuditOutcome(ctx context.Context, input ContentModerationCheckInput, cfg *ContentModerationConfig, sessionCfg *SessionAuditProviderConfig, sessionHash string) (*ContentModerationDecision, bool) {
	allow := &ContentModerationDecision{Allowed: true, Action: ContentModerationActionAllow}
	if s == nil || sessionCfg == nil {
		return allow, false
	}
	waitStartedAt := s.now()
	deadline := waitStartedAt.Add(time.Duration(sessionCfg.TimeoutMS)*time.Millisecond + defaultSessionAuditWaitPadding)

	for {
		if cfg.Mode == ContentModerationModePreBlock {
			blacklist, blackErr := s.IsSessionBlacklisted(ctx, sessionHash)
			if blackErr == nil && blacklist != nil {
				_ = s.TouchBlacklistedSession(ctx, sessionHash)
				return blockedSessionAuditBlacklistDecision(blacklist), false
			}
		}
		if auditedRecently, _ := s.hasRecentSessionAuditSuccess(ctx, sessionHash, sessionCfg); auditedRecently {
			return allow, false
		}
		hasLock, lockErr := s.hasSessionAuditLock(ctx, sessionHash)
		if lockErr != nil {
			slog.Warn("content_moderation.session_audit_wait_lock_failed",
				"session_hash", sessionHash,
				"endpoint", input.Endpoint,
				"protocol", input.Protocol,
				"error", lockErr)
			if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
				return blockedSessionAuditErrorDecision(), false
			}
			return allow, false
		}
		if !hasLock {
			lastAttemptAt, attemptErr := s.getSessionAuditLastAttempt(ctx, sessionHash)
			if attemptErr == nil && lastAttemptAt != nil && !lastAttemptAt.Before(waitStartedAt) {
				if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
					return blockedSessionAuditErrorDecision(), false
				}
				return allow, false
			}
			return nil, true
		}
		if !s.now().Before(deadline) {
			if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
				return blockedSessionAuditErrorDecision(), false
			}
			return allow, false
		}
		if err := s.sleep(ctx, defaultSessionAuditPollInterval); err != nil {
			if cfg.Mode == ContentModerationModePreBlock && sessionCfg.FailClosed {
				return blockedSessionAuditErrorDecision(), false
			}
			return allow, false
		}
	}
}

func (s *ContentModerationService) performSessionAuditLocked(ctx context.Context, input ContentModerationCheckInput, cfg *ContentModerationConfig, sessionCfg *SessionAuditProviderConfig, sessionHash string, sessionSource string, lockToken string) *ContentModerationDecision {
	allow := &ContentModerationDecision{Allowed: true, Action: ContentModerationActionAllow}
	if s == nil || cfg == nil || sessionCfg == nil {
		return allow
	}
	defer func() {
		if releaseErr := s.releaseSessionAuditLock(ctx, sessionHash, lockToken); releaseErr != nil {
			slog.Warn("content_moderation.session_audit_release_lock_failed",
				"session_hash", sessionHash,
				"endpoint", input.Endpoint,
				"protocol", input.Protocol,
				"error", releaseErr)
		}
	}()

	if cfg.Mode == ContentModerationModePreBlock {
		blacklist, blackErr := s.IsSessionBlacklisted(ctx, sessionHash)
		if blackErr == nil && blacklist != nil {
			_ = s.TouchBlacklistedSession(ctx, sessionHash)
			s.recordPreBlockSyncMetric(0, ContentModerationActionBlock)
			return blockedSessionAuditBlacklistDecision(blacklist)
		}
	}
	if auditedRecently, _ := s.hasRecentSessionAuditSuccess(ctx, sessionHash, sessionCfg); auditedRecently {
		if cfg.Mode == ContentModerationModePreBlock {
			s.recordPreBlockSyncMetric(0, ContentModerationActionAllow)
		}
		return allow
	}

	auditStartedAt := s.now()
	if err := s.setSessionAuditLastAttempt(ctx, sessionHash, auditStartedAt, sessionCfg); err != nil {
		slog.Warn("content_moderation.session_audit_set_last_attempt_failed",
			"session_hash", sessionHash,
			"endpoint", input.Endpoint,
			"protocol", input.Protocol,
			"error", err)
	}
	payload := s.buildSessionAuditPayload(input, sessionHash, sessionSource, sessionCfg)
	prompt := renderSessionAuditPrompt(sessionCfg, payload)
	started := time.Now()
	result, err := s.sessionAuditClient.Audit(ctx, sessionCfg, &OpenAIResponsesSessionAuditRequest{
		SessionHash: sessionHash,
		Prompt:      prompt,
		Payload:     payload,
	})
	latency := int(time.Since(started).Milliseconds())

	if err != nil {
		if cfg.Mode == ContentModerationModePreBlock {
			s.recordPreBlockSyncMetric(latency, ContentModerationActionError)
		}
		redactedErr := redactContentModerationSecrets(err.Error())
		slog.Warn("content_moderation.session_audit_failed",
			"session_hash", sessionHash,
			"endpoint", input.Endpoint,
			"protocol", input.Protocol,
			"latency_ms", latency,
			"error", redactedErr)
		if cfg.RecordNonHits {
			log := s.buildLog(input, cfg, ContentModerationActionError, false, "", 0, nil, payload, &latency, nil, redactedErr)
			s.persistContentModerationLog(ctx, cfg, log, "", false, false)
		}
		if sessionCfg.FailClosed && cfg.Mode == ContentModerationModePreBlock {
			return blockedSessionAuditErrorDecision()
		}
		return allow
	}

	flagged, blocked, highestCategory, highestScore, categoryScores := evaluateSessionAuditResult(result, sessionCfg, cfg.Mode)
	action := ContentModerationActionAllow
	if blocked {
		action = ContentModerationActionBlock
	}
	if cfg.Mode == ContentModerationModePreBlock {
		s.recordPreBlockSyncMetric(latency, action)
	}

	slog.Info("content_moderation.session_audit_done",
		"session_hash", sessionHash,
		"endpoint", input.Endpoint,
		"protocol", input.Protocol,
		"flagged", flagged,
		"blocked", blocked,
		"confidence", result.Confidence,
		"categories", result.Categories,
		"latency_ms", latency)

	if flagged || cfg.RecordNonHits {
		log := s.buildLog(input, cfg, action, flagged, highestCategory, highestScore, categoryScores, payload, &latency, nil, "")
		s.persistContentModerationLog(ctx, cfg, log, "", false, false)
	}

	if !blocked {
		if err := s.setSessionAuditLastSuccess(ctx, sessionHash, s.now(), sessionCfg); err != nil {
			slog.Warn("content_moderation.session_audit_set_last_success_failed",
				"session_hash", sessionHash,
				"endpoint", input.Endpoint,
				"protocol", input.Protocol,
				"error", err)
		}
		return &ContentModerationDecision{
			Allowed:         true,
			Flagged:         flagged,
			HighestCategory: highestCategory,
			HighestScore:    highestScore,
			CategoryScores:  categoryScores,
			Action:          ContentModerationActionAllow,
		}
	}

	blockedAt := s.now().UTC()
	blacklist := &RiskSessionBlacklist{
		SessionHash:     sessionHash,
		UserID:          contentModerationInt64Ptr(input.UserID),
		APIKeyID:        contentModerationInt64Ptr(input.APIKeyID),
		GroupID:         cloneInt64Ptr(input.GroupID),
		Reason:          redactContentModerationSecrets(result.Reason),
		Categories:      append([]string(nil), result.Categories...),
		Confidence:      result.Confidence,
		AuditModel:      sessionCfg.Model,
		AuditResponseID: strings.TrimSpace(result.ResponseID),
		SourceProtocol:  input.Protocol,
		SourceModel:     input.Model,
		FirstBlockedAt:  blockedAt,
		LastSeenAt:      blockedAt,
		ExpiresAt:       sessionAuditExpiry(blockedAt, sessionCfg.SessionBlacklistTTL),
	}
	if err := s.BlacklistSession(ctx, blacklist); err != nil {
		slog.Warn("content_moderation.session_blacklist_persist_failed",
			"session_hash", sessionHash,
			"endpoint", input.Endpoint,
			"protocol", input.Protocol,
			"error", err)
	}
	return blockedSessionAuditBlacklistDecision(blacklist)
}

func (s *ContentModerationService) buildSessionAuditPayload(input ContentModerationCheckInput, sessionHash string, sessionSource string, cfg *SessionAuditProviderConfig) string {
	content := ExtractContentModerationInput(input.Protocol, input.Body)
	parsed := parseSessionAuditParsedRequest(input)
	systemSummary := ""
	messageSummary := ""
	if parsed != nil {
		systemSummary = extractTextFromSystemRaw(parsed.SystemRaw())
		messageSummary = summarizeAuditMessagesRaw(parsed.MessagesRaw())
	}
	toolsSummary := summarizeAuditJSONField(input.Body, "tools")
	metadataSummary := summarizeAuditJSONField(input.Body, "metadata")
	sections := make([]string, 0, 12)
	sections = append(sections, "session_hash: "+sessionHash)
	sections = append(sections, "session_source: "+sessionSource)
	if input.UserID > 0 {
		sections = append(sections, "user_id: "+strconv.FormatInt(input.UserID, 10))
	}
	if input.APIKeyID > 0 {
		sections = append(sections, "api_key_id: "+strconv.FormatInt(input.APIKeyID, 10))
	}
	if input.GroupID != nil {
		sections = append(sections, "group_id: "+strconv.FormatInt(*input.GroupID, 10))
	}
	if endpoint := strings.TrimSpace(input.Endpoint); endpoint != "" {
		sections = append(sections, "endpoint: "+endpoint)
	}
	if protocol := strings.TrimSpace(input.Protocol); protocol != "" {
		sections = append(sections, "protocol: "+protocol)
	}
	if model := strings.TrimSpace(input.Model); model != "" {
		sections = append(sections, "model: "+model)
	}
	if stream := gjson.GetBytes(input.Body, "stream"); stream.Exists() {
		sections = append(sections, "stream: "+stream.Raw)
	}
	if requestContext := summarizeSessionAuditRequestContext(input); requestContext != "" {
		sections = append(sections, "request_context_summary: "+requestContext)
	}
	if systemSummary = trimRunes(redactContentModerationSecrets(strings.TrimSpace(systemSummary)), maxModerationExcerptRunes*2); systemSummary != "" {
		sections = append(sections, "system_summary: "+systemSummary)
	}
	if latestUser := trimRunes(redactContentModerationSecrets(strings.TrimSpace(content.Text)), maxModerationExcerptRunes*2); latestUser != "" {
		sections = append(sections, "latest_user_excerpt: "+latestUser)
	}
	if messageSummary = trimRunes(redactContentModerationSecrets(strings.TrimSpace(messageSummary)), maxModerationExcerptRunes*3); messageSummary != "" {
		sections = append(sections, "message_summary: "+messageSummary)
	}
	if toolsSummary = trimRunes(redactContentModerationSecrets(strings.TrimSpace(toolsSummary)), maxModerationExcerptRunes*2); toolsSummary != "" {
		sections = append(sections, "tools_summary: "+toolsSummary)
	}
	if metadataSummary = trimRunes(redactContentModerationSecrets(strings.TrimSpace(metadataSummary)), maxModerationExcerptRunes*2); metadataSummary != "" {
		sections = append(sections, "metadata_summary: "+metadataSummary)
	}
	payload := strings.Join(filterEmptyStrings(sections), "\n")
	return trimRunes(payload, cfg.AuditMaxInputChars)
}

func summarizeSessionAuditRequestContext(input ContentModerationCheckInput) string {
	if len(input.Headers) == 0 {
		return ""
	}
	fields := map[string]string{}
	addHeaderSummaryField(fields, input.Headers, "User-Agent", "user_agent_family", sessionAuditUserAgentFamily)
	addHeaderSummaryField(fields, input.Headers, "X-App", "client_app", sessionAuditHeaderPlainValue)
	addHeaderSummaryField(fields, input.Headers, "Originator", "originator", sessionAuditHeaderPlainValue)
	addHeaderSummaryField(fields, input.Headers, "X-Cpa-Managed-Instance", "managed_relay_instance", sessionAuditHeaderPlainValue)
	addHeaderSummaryField(fields, input.Headers, "X-Cpa-Managed-Domain", "managed_relay_domain", sessionAuditHeaderDomainValue)
	addHeaderSummaryField(fields, input.Headers, "Anthropic-Dangerous-Direct-Browser-Access", "dangerous_direct_browser_access", sessionAuditHeaderPlainValue)
	addHeaderSummaryField(fields, input.Headers, "Anthropic-Beta", "anthropic_beta", sessionAuditHeaderBetaValue)
	addHeaderSummaryField(fields, input.Headers, "X-Codex-Beta-Features", "codex_beta_features", sessionAuditHeaderBetaValue)
	if hasAnyHeader(input.Headers, "X-Cpa-Managed-Instance", "X-Cpa-Managed-Domain") {
		fields["managed_relay_headers_present"] = "true"
	}
	if hasAnyHeader(input.Headers, "X-Api-Key", "Authorization", "Cookie") {
		fields["credential_headers_present"] = "true"
	}
	if len(fields) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := strings.TrimSpace(fields[key]); value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, "; ")
}

func addHeaderSummaryField(fields map[string]string, headers http.Header, headerName string, fieldName string, normalize func(string) string) {
	if fields == nil || len(headers) == 0 {
		return
	}
	for _, value := range headers.Values(headerName) {
		if normalized := normalize(value); normalized != "" {
			fields[fieldName] = normalized
			return
		}
	}
}

func hasAnyHeader(headers http.Header, names ...string) bool {
	if len(headers) == 0 {
		return false
	}
	for _, name := range names {
		for _, value := range headers.Values(name) {
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}

func sessionAuditHeaderPlainValue(raw string) string {
	return trimRunes(redactContentModerationSecrets(strings.TrimSpace(raw)), maxModerationExcerptRunes)
}

func sessionAuditHeaderDomainValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.Trim(raw, "/")
	return sessionAuditHeaderPlainValue(raw)
}

func sessionAuditHeaderBetaValue(raw string) string {
	values := parseStringListSetting(raw)
	if len(values) == 0 {
		return sessionAuditHeaderPlainValue(raw)
	}
	if len(values) > 8 {
		values = values[:8]
	}
	return sessionAuditHeaderPlainValue(strings.Join(values, ","))
}

func sessionAuditUserAgentFamily(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	for _, family := range []string{"claude-cli", "codex-tui", "claude-code", "anthropic", "curl", "python", "node", "go-http-client"} {
		if strings.Contains(raw, family) {
			return family
		}
	}
	return trimRunes(redactContentModerationSecrets(NormalizeSessionUserAgent(raw)), maxModerationExcerptRunes)
}

func renderSessionAuditPrompt(cfg *SessionAuditProviderConfig, payload string) string {
	template := strings.TrimSpace(sessionAuditDefaultPromptTemplate)
	if cfg != nil && strings.TrimSpace(cfg.PromptTemplate) != "" {
		template = strings.TrimSpace(cfg.PromptTemplate)
	}
	out := strings.ReplaceAll(template, "{{payload}}", payload)
	return strings.ReplaceAll(out, "{{payload_json}}", payload)
}

func evaluateSessionAuditResult(result *OpenAIResponsesSessionAuditResult, cfg *SessionAuditProviderConfig, mode string) (flagged bool, blocked bool, highestCategory string, highestScore float64, categoryScores map[string]float64) {
	if result == nil {
		return false, false, "", 0, nil
	}
	result.Categories = normalizeSessionAuditCategories(result.Categories)
	result.RecommendedAction = normalizeSessionAuditRecommendedAction(result.RecommendedAction)
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 1 {
		result.Confidence = 1
	}
	flagged = result.Violates || result.RecommendedAction == ContentModerationActionBlock
	threshold := defaultSessionAuditBlockConfidenceThreshold
	if cfg != nil {
		threshold = cfg.BlockConfidenceThreshold
	}
	blocked = mode == ContentModerationModePreBlock && flagged && result.Confidence >= threshold
	categoryScores = buildSessionAuditCategoryScores(result.Categories, result.Confidence)
	highestCategory = sessionAuditHighestCategory(result.Categories)
	if highestCategory == "" && flagged {
		highestCategory = sessionAuditDefaultCategory
	}
	highestScore = result.Confidence
	return flagged, blocked, highestCategory, highestScore, categoryScores
}

func (s *ContentModerationService) IsSessionBlacklisted(ctx context.Context, sessionHash string) (*RiskSessionBlacklist, error) {
	sessionHash = strings.TrimSpace(sessionHash)
	if s == nil || sessionHash == "" {
		return nil, nil
	}
	now := s.now()
	if s.hashCache != nil {
		cached, err := s.hashCache.GetRiskSessionBlacklistCache(ctx, sessionHash)
		if err != nil {
			return nil, err
		}
		if cached != nil {
			if cached.ExpiresAt != nil && !cached.ExpiresAt.After(now) {
				_ = s.hashCache.DeleteRiskSessionBlacklistCache(ctx, sessionHash)
				_ = s.UnblacklistSession(ctx, sessionHash)
				return nil, nil
			}
			return cached.toRecord(), nil
		}
	}
	if s.repo == nil {
		return nil, nil
	}
	entry, err := s.repo.GetRiskSessionBlacklist(ctx, sessionHash)
	if err != nil || entry == nil {
		return entry, err
	}
	if entry.ExpiresAt != nil && !entry.ExpiresAt.After(now) {
		if unblackErr := s.UnblacklistSession(ctx, sessionHash); unblackErr != nil {
			return nil, unblackErr
		}
		return nil, nil
	}
	if s.hashCache != nil {
		if cacheErr := s.hashCache.SetRiskSessionBlacklistCache(ctx, sessionHash, riskSessionBlacklistCacheEntryFromRecord(entry), sessionBlacklistCacheTTL(s.now(), entry.ExpiresAt)); cacheErr != nil {
			slog.Warn("content_moderation.session_blacklist_cache_set_failed", "session_hash", sessionHash, "error", cacheErr)
		}
	}
	return entry, nil
}

func (s *ContentModerationService) BlacklistSession(ctx context.Context, entry *RiskSessionBlacklist) error {
	if s == nil || entry == nil {
		return nil
	}
	entry.SessionHash = strings.TrimSpace(entry.SessionHash)
	if entry.SessionHash == "" {
		return nil
	}
	entry.Reason = redactContentModerationSecrets(strings.TrimSpace(entry.Reason))
	entry.Categories = normalizeSessionAuditCategories(entry.Categories)
	if entry.Confidence < 0 {
		entry.Confidence = 0
	}
	if entry.Confidence > 1 {
		entry.Confidence = 1
	}
	if entry.FirstBlockedAt.IsZero() {
		entry.FirstBlockedAt = s.now().UTC()
	}
	if entry.LastSeenAt.IsZero() {
		entry.LastSeenAt = entry.FirstBlockedAt
	}
	if err := s.repo.UpsertRiskSessionBlacklist(ctx, entry); err != nil {
		return err
	}
	if s.hashCache != nil {
		if err := s.hashCache.SetRiskSessionBlacklistCache(ctx, entry.SessionHash, riskSessionBlacklistCacheEntryFromRecord(entry), sessionBlacklistCacheTTL(s.now(), entry.ExpiresAt)); err != nil {
			return err
		}
	}
	return nil
}

func (s *ContentModerationService) TouchBlacklistedSession(ctx context.Context, sessionHash string) error {
	sessionHash = strings.TrimSpace(sessionHash)
	if s == nil || sessionHash == "" {
		return nil
	}
	now := s.now().UTC()
	if s.repo != nil {
		if err := s.repo.TouchRiskSessionBlacklist(ctx, sessionHash, now); err != nil {
			return err
		}
	}
	if s.hashCache != nil {
		entry, err := s.hashCache.GetRiskSessionBlacklistCache(ctx, sessionHash)
		if err != nil {
			return err
		}
		if entry != nil {
			entry.LastSeenAt = now
			if err := s.hashCache.SetRiskSessionBlacklistCache(ctx, sessionHash, entry, sessionBlacklistCacheTTL(now, entry.ExpiresAt)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ContentModerationService) UnblacklistSession(ctx context.Context, sessionHash string) error {
	sessionHash = strings.TrimSpace(sessionHash)
	if s == nil || sessionHash == "" {
		return nil
	}
	if s.repo != nil {
		if err := s.repo.DeleteRiskSessionBlacklist(ctx, sessionHash); err != nil {
			return err
		}
	}
	if s.hashCache != nil {
		if err := s.hashCache.DeleteRiskSessionBlacklistCache(ctx, sessionHash); err != nil {
			return err
		}
	}
	return nil
}

func (s *ContentModerationService) hasRecentSessionAuditSuccess(ctx context.Context, sessionHash string, cfg *SessionAuditProviderConfig) (bool, time.Time) {
	lastSuccessAt, err := s.getSessionAuditLastSuccess(ctx, sessionHash)
	if err != nil || lastSuccessAt == nil {
		return false, time.Time{}
	}
	if cfg == nil || cfg.SessionAuditInterval <= 0 {
		return true, *lastSuccessAt
	}
	return s.now().Sub(*lastSuccessAt) < cfg.SessionAuditInterval, *lastSuccessAt
}

func (s *ContentModerationService) getSessionAuditLastSuccess(ctx context.Context, sessionHash string) (*time.Time, error) {
	if s == nil || s.hashCache == nil {
		return nil, nil
	}
	return s.hashCache.GetRiskSessionLastSuccessAudit(ctx, sessionHash)
}

func (s *ContentModerationService) setSessionAuditLastSuccess(ctx context.Context, sessionHash string, at time.Time, cfg *SessionAuditProviderConfig) error {
	if s == nil || s.hashCache == nil {
		return nil
	}
	return s.hashCache.SetRiskSessionLastSuccessAudit(ctx, sessionHash, at.UTC(), sessionAuditSuccessTTL(cfg))
}

func (s *ContentModerationService) getSessionAuditLastAttempt(ctx context.Context, sessionHash string) (*time.Time, error) {
	if s == nil || s.hashCache == nil {
		return nil, nil
	}
	return s.hashCache.GetRiskSessionLastAttempt(ctx, sessionHash)
}

func (s *ContentModerationService) setSessionAuditLastAttempt(ctx context.Context, sessionHash string, at time.Time, cfg *SessionAuditProviderConfig) error {
	if s == nil || s.hashCache == nil {
		return nil
	}
	return s.hashCache.SetRiskSessionLastAttempt(ctx, sessionHash, at.UTC(), sessionAuditAttemptTTL(cfg))
}

func (s *ContentModerationService) acquireSessionAuditLock(ctx context.Context, sessionHash string, cfg *SessionAuditProviderConfig) (string, bool, error) {
	if s == nil || s.hashCache == nil {
		return "", true, nil
	}
	token, err := newSessionAuditLockToken()
	if err != nil {
		return "", false, err
	}
	ok, err := s.hashCache.AcquireRiskSessionAuditLock(ctx, sessionHash, token, sessionAuditLockTTL(cfg))
	return token, ok, err
}

func (s *ContentModerationService) hasSessionAuditLock(ctx context.Context, sessionHash string) (bool, error) {
	if s == nil || s.hashCache == nil {
		return false, nil
	}
	return s.hashCache.HasRiskSessionAuditLock(ctx, sessionHash)
}

func (s *ContentModerationService) releaseSessionAuditLock(ctx context.Context, sessionHash string, token string) error {
	if s == nil || s.hashCache == nil || strings.TrimSpace(token) == "" {
		return nil
	}
	return s.hashCache.ReleaseRiskSessionAuditLock(ctx, sessionHash, token)
}

func (s *ContentModerationService) extractSessionAuditHash(input ContentModerationCheckInput) (string, string, error) {
	if raw := extractHeaderSessionID(input.Headers); raw != "" {
		return sha256HexString(raw), "header", nil
	}
	if raw, source := extractMetadataSessionID(input.Body); raw != "" {
		return sha256HexString(raw), source, nil
	}
	parsed := parseSessionAuditParsedRequest(input)
	if parsed == nil {
		return "", "", nil
	}
	if fallback := generateGatewayRequestSessionSeed(parsed); fallback != "" {
		return sha256HexString(fallback), "gateway_fallback", nil
	}
	return "", "", nil
}

func parseSessionAuditParsedRequest(input ContentModerationCheckInput) *ParsedRequest {
	if len(input.Body) == 0 || !gjson.ValidBytes(input.Body) {
		return nil
	}
	parsed, err := ParseGatewayRequest(NewRequestBodyRef(input.Body), "")
	if err != nil {
		return nil
	}
	parsed.SessionContext = &SessionContext{
		ClientIP:  strings.TrimSpace(input.ClientIP),
		UserAgent: strings.TrimSpace(input.UserAgent),
		APIKeyID:  input.APIKeyID,
	}
	return parsed
}

func generateGatewayRequestSessionSeed(parsed *ParsedRequest) string {
	if parsed == nil {
		return ""
	}
	if parsed.MetadataUserID != "" {
		if uid := ParseMetadataUserID(parsed.MetadataUserID); uid != nil && uid.SessionID != "" {
			return uid.SessionID
		}
	}
	if cacheableContent := extractGatewayCacheableContent(parsed); cacheableContent != "" {
		return hashGatewaySessionContent(cacheableContent)
	}
	var combined strings.Builder
	if parsed.SessionContext != nil {
		_, _ = combined.WriteString(parsed.SessionContext.ClientIP)
		_, _ = combined.WriteString(":")
		_, _ = combined.WriteString(NormalizeSessionUserAgent(parsed.SessionContext.UserAgent))
		_, _ = combined.WriteString(":")
		_, _ = combined.WriteString(strconv.FormatInt(parsed.SessionContext.APIKeyID, 10))
		_, _ = combined.WriteString("|")
	}
	if systemText := extractTextFromSystemRaw(parsed.SystemRaw()); systemText != "" {
		_, _ = combined.WriteString(systemText)
	}
	appendMessageTextsFromRaw(&combined, parsed.MessagesRaw())
	if combined.Len() == 0 {
		return ""
	}
	return hashGatewaySessionContent(combined.String())
}

func extractGatewayCacheableContent(parsed *ParsedRequest) string {
	if parsed == nil {
		return ""
	}
	systemText := extractCacheableTextFromSystemRaw(parsed.SystemRaw())
	if messageText := extractCacheableTextFromMessagesRaw(parsed.MessagesRaw()); messageText != "" {
		return messageText
	}
	return systemText
}

func hashGatewaySessionContent(content string) string {
	return strconv.FormatUint(xxhash.Sum64String(content), 36)
}

func summarizeAuditMessagesRaw(raw []byte) string {
	messages := parseRawJSONView(raw)
	if !messages.IsArray() {
		return ""
	}
	items := make([]string, 0, 6)
	array := messages.Array()
	start := 0
	if len(array) > 6 {
		start = len(array) - 6
	}
	for _, msg := range array[start:] {
		role := strings.TrimSpace(msg.Get("role").String())
		text := ""
		if content := msg.Get("content"); content.Exists() {
			text = extractTextFromContentRaw(content)
		}
		if text == "" {
			text = extractTextFromContentRaw(msg.Get("parts"))
		}
		text = trimRunes(strings.TrimSpace(text), maxModerationExcerptRunes)
		if text == "" {
			continue
		}
		if role == "" {
			role = "message"
		}
		items = append(items, role+": "+text)
	}
	return strings.Join(items, " | ")
}

func summarizeAuditJSONField(body []byte, path string) string {
	value := gjson.GetBytes(body, path)
	if !value.Exists() {
		return ""
	}
	raw := value.Raw
	if raw == "" {
		raw = value.String()
	}
	if raw == "" {
		return ""
	}
	return trimRunes(strings.TrimSpace(sanitizeSessionAuditJSONSummary(path, raw)), maxModerationExcerptRunes*2)
}

func sanitizeSessionAuditJSONSummary(pathName string, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
		sanitized := sanitizeSessionAuditJSONValue(pathName, decoded)
		if encoded, marshalErr := json.Marshal(sanitized); marshalErr == nil {
			return string(encoded)
		}
	}
	return redactContentModerationSecrets(raw)
}

func sanitizeSessionAuditJSONValue(key string, value any) any {
	if isSessionAuditSensitiveJSONKey(key) {
		return "[REDACTED]"
	}
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for childKey, childValue := range v {
			out[childKey] = sanitizeSessionAuditJSONValue(childKey, childValue)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for idx, item := range v {
			out[idx] = sanitizeSessionAuditJSONValue(key, item)
		}
		return out
	case string:
		return redactContentModerationSecrets(v)
	default:
		return v
	}
}

func isSessionAuditSensitiveJSONKey(key string) bool {
	normalized := normalizeSessionAuditJSONKey(key)
	switch normalized {
	case "authorization", "bearer", "cookie", "setcookie",
		"apikey", "accesskey", "secretkey", "clientsecret", "privatekey",
		"accesstoken", "refreshtoken", "idtoken", "sessiontoken", "token", "secret",
		"password", "passwd", "pwd",
		"session", "sessionid", "userid", "user":
		return true
	default:
		return strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "password") ||
			strings.Contains(normalized, "apikey")
	}
}

func normalizeSessionAuditJSONKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, " ", "")
	key = strings.ReplaceAll(key, ".", "")
	return key
}

func extractHeaderSessionID(headers http.Header) string {
	if len(headers) == 0 {
		return ""
	}
	for _, key := range []string{"session_id", "x-session-id", "Session-Id", "session-id"} {
		for headerKey, values := range headers {
			if !strings.EqualFold(strings.TrimSpace(headerKey), key) {
				continue
			}
			for _, value := range values {
				if trimmed := strings.TrimSpace(value); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}

func extractMetadataSessionID(body []byte) (string, string) {
	if len(body) == 0 || !gjson.ValidBytes(body) {
		return "", ""
	}
	metadata := gjson.GetBytes(body, "metadata")
	if !metadata.Exists() {
		return "", ""
	}
	for _, candidate := range []struct {
		path           string
		allowRawString bool
	}{
		{path: "user_id"},
		{path: "user.session_id", allowRawString: true},
		{path: "user.sessionId", allowRawString: true},
		{path: "user.session", allowRawString: true},
		{path: "session.id", allowRawString: true},
		{path: "session.session_id", allowRawString: true},
		{path: "session.sessionId", allowRawString: true},
		{path: "session_id", allowRawString: true},
		{path: "sessionId", allowRawString: true},
		{path: "session", allowRawString: true},
		{path: "user"},
	} {
		value := metadata.Get(candidate.path)
		if raw := extractMetadataSessionCandidate(value, candidate.allowRawString); raw != "" {
			return raw, "metadata." + candidate.path
		}
	}
	return "", ""
}

func extractMetadataSessionCandidate(value gjson.Result, allowRawString bool) string {
	if !value.Exists() {
		return ""
	}
	if value.IsObject() {
		for _, path := range []string{"session_id", "sessionId", "session.id", "session.session_id", "session.sessionId"} {
			if raw := strings.TrimSpace(value.Get(path).String()); raw != "" {
				return raw
			}
		}
	}
	raw := strings.TrimSpace(value.String())
	if parsed := ParseMetadataUserID(raw); parsed != nil && parsed.SessionID != "" {
		return parsed.SessionID
	}
	if allowRawString {
		return raw
	}
	return ""
}

func blockedSessionAuditErrorDecision() *ContentModerationDecision {
	return &ContentModerationDecision{
		Allowed:    false,
		Blocked:    true,
		Flagged:    false,
		Message:    sessionAuditBlockMessage,
		StatusCode: http.StatusForbidden,
		Action:     ContentModerationActionError,
	}
}

func blockedSessionAuditBlacklistDecision(entry *RiskSessionBlacklist) *ContentModerationDecision {
	highestCategory := sessionAuditHighestCategory(entry.Categories)
	if highestCategory == "" {
		highestCategory = sessionAuditDefaultCategory
	}
	return &ContentModerationDecision{
		Allowed:         false,
		Blocked:         true,
		Flagged:         true,
		Message:         sessionAuditBlockMessage,
		StatusCode:      http.StatusForbidden,
		HighestCategory: highestCategory,
		HighestScore:    entry.Confidence,
		CategoryScores:  buildSessionAuditCategoryScores(entry.Categories, entry.Confidence),
		Action:          ContentModerationActionBlock,
	}
}

func buildSessionAuditCategoryScores(categories []string, confidence float64) map[string]float64 {
	if len(categories) == 0 {
		return nil
	}
	out := make(map[string]float64, len(categories))
	for _, category := range categories {
		out[category] = confidence
	}
	return out
}

func normalizeRiskControlProvider(raw string) string {
	switch strings.TrimSpace(raw) {
	case RiskControlProviderOpenAIResponsesSessionAudit:
		return RiskControlProviderOpenAIResponsesSessionAudit
	case "", RiskControlProviderLegacyModeration:
		return RiskControlProviderLegacyModeration
	default:
		return RiskControlProviderLegacyModeration
	}
}

func normalizeAuditPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultSessionAuditPath
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return raw
}

func normalizeSessionAuditProtocols(in []string) []string {
	if len(in) == 0 {
		return append([]string(nil), defaultSessionAuditEnabledProtocols...)
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		protocol := strings.TrimSpace(raw)
		if protocol == "" {
			continue
		}
		if _, ok := seen[protocol]; ok {
			continue
		}
		seen[protocol] = struct{}{}
		out = append(out, protocol)
	}
	if len(out) == 0 {
		return append([]string(nil), defaultSessionAuditEnabledProtocols...)
	}
	return out
}

func normalizeSessionAuditCategories(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		category := strings.TrimSpace(raw)
		if category == "" {
			continue
		}
		if _, ok := seen[category]; ok {
			continue
		}
		seen[category] = struct{}{}
		out = append(out, category)
	}
	return out
}

func normalizeSessionAuditRecommendedAction(raw string) string {
	if strings.ToLower(strings.TrimSpace(raw)) == ContentModerationActionBlock {
		return ContentModerationActionBlock
	}
	return ContentModerationActionAllow
}

func parseStringListSetting(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "[") {
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err == nil {
			return values
		}
	}
	values := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func parseBoolSettingValue(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "on", "enabled", "yes":
		return true
	default:
		return false
	}
}

func sessionAuditHighestCategory(categories []string) string {
	if len(categories) == 0 {
		return ""
	}
	return strings.TrimSpace(categories[0])
}

func sessionAuditSuccessTTL(cfg *SessionAuditProviderConfig) time.Duration {
	if cfg == nil {
		return defaultSessionAuditSuccessTTL
	}
	if cfg.SessionAuditInterval > defaultSessionAuditSuccessTTL {
		return cfg.SessionAuditInterval * 2
	}
	return defaultSessionAuditSuccessTTL
}

func sessionAuditAttemptTTL(cfg *SessionAuditProviderConfig) time.Duration {
	if cfg == nil {
		return defaultSessionAuditAttemptTTL
	}
	ttl := time.Duration(cfg.TimeoutMS)*time.Millisecond + defaultSessionAuditWaitPadding + time.Minute
	if ttl < defaultSessionAuditAttemptTTL {
		return defaultSessionAuditAttemptTTL
	}
	return ttl
}

func sessionAuditLockTTL(cfg *SessionAuditProviderConfig) time.Duration {
	if cfg == nil {
		return time.Duration(defaultSessionAuditTimeoutMS)*time.Millisecond + defaultSessionAuditWaitPadding
	}
	return time.Duration(cfg.TimeoutMS)*time.Millisecond + defaultSessionAuditWaitPadding
}

func sessionAuditExpiry(now time.Time, ttl time.Duration) *time.Time {
	if ttl <= 0 {
		return nil
	}
	expiresAt := now.Add(ttl).UTC()
	return &expiresAt
}

func sessionBlacklistCacheTTL(now time.Time, expiresAt *time.Time) time.Duration {
	if expiresAt == nil {
		return defaultSessionAuditPermanentBlacklistCacheTTL
	}
	ttl := expiresAt.Sub(now)
	if ttl <= 0 {
		return time.Second
	}
	return ttl
}

func riskSessionBlacklistCacheEntryFromRecord(entry *RiskSessionBlacklist) *RiskSessionBlacklistCacheEntry {
	if entry == nil {
		return nil
	}
	return &RiskSessionBlacklistCacheEntry{
		SessionHash:     entry.SessionHash,
		Reason:          entry.Reason,
		Categories:      append([]string(nil), entry.Categories...),
		Confidence:      entry.Confidence,
		AuditModel:      entry.AuditModel,
		AuditResponseID: entry.AuditResponseID,
		SourceProtocol:  entry.SourceProtocol,
		SourceModel:     entry.SourceModel,
		FirstBlockedAt:  entry.FirstBlockedAt,
		LastSeenAt:      entry.LastSeenAt,
		ExpiresAt:       cloneTimePtr(entry.ExpiresAt),
	}
}

func (entry *RiskSessionBlacklistCacheEntry) toRecord() *RiskSessionBlacklist {
	if entry == nil {
		return nil
	}
	return &RiskSessionBlacklist{
		SessionHash:     entry.SessionHash,
		Reason:          entry.Reason,
		Categories:      append([]string(nil), entry.Categories...),
		Confidence:      entry.Confidence,
		AuditModel:      entry.AuditModel,
		AuditResponseID: entry.AuditResponseID,
		SourceProtocol:  entry.SourceProtocol,
		SourceModel:     entry.SourceModel,
		FirstBlockedAt:  entry.FirstBlockedAt,
		LastSeenAt:      entry.LastSeenAt,
		ExpiresAt:       cloneTimePtr(entry.ExpiresAt),
	}
}

func contentModerationInt64Ptr(v int64) *int64 {
	if v <= 0 {
		return nil
	}
	return &v
}

func cloneTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	cloned := in.UTC()
	return &cloned
}

func newSessionAuditLockToken() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func sha256HexString(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func filterEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func contentModerationSleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

const sessionAuditDefaultPromptTemplate = `You are a risk control auditor for Claude/Anthropic Messages traffic.
Evaluate only whether the provided request violates Claude Terms of Service or the Anthropic Usage Policy.
Do not answer the user's question, do not transform the task, and do not provide advice beyond policy classification.

Block with high confidence when the request or request-context evidence clearly indicates any of these Claude/Anthropic policy violations:
- credential theft, secret extraction, token/cookie/API-key exfiltration, phishing, malware, unauthorized access, evasion, abuse automation, or other disallowed harmful conduct;
- sharing, reselling, brokering, pooling, or proxying Claude/Anthropic/Claude Code accounts, API keys, OAuth sessions, or service access through an unauthorized relay or managed intermediary;
- using Claude/Anthropic traffic to build, train, distill, or run a competing model/service in violation of the Terms.

Treat request_context_summary and risk_signals as policy evidence. For example, managed relay headers/domains for a Claude-Code/Claude CLI client, combined with credential headers or shared-service routing, are evidence of unauthorized sharing/proxying of Claude service access even if the user task itself is ordinary coding.
Do not block ordinary first-party, authorized user requests only because they are software-development tasks.
If the evidence is ambiguous or confidence is low, default to allow.
Return strict JSON only with this schema:
{"violates":bool,"confidence":number,"categories":[],"reason":"...","evidence_excerpt":"...","recommended_action":"allow|block"}

Request payload:
{{payload}}`
