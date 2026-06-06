package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOpenAIResponsesAuditClient_RealLogsSmoke is an opt-in online smoke test
// for captured production logs. It never prints raw session IDs or credentials;
// evidence is reported with session_hash only.
func TestOpenAIResponsesAuditClient_RealLogsSmoke(t *testing.T) {
	if strings.TrimSpace(os.Getenv("SUB2API_REAL_LOGS_AUDIT")) != "1" {
		t.Skip("set SUB2API_REAL_LOGS_AUDIT=1 to audit captured real logs")
	}

	logDir := strings.TrimSpace(os.Getenv("SUB2API_REAL_LOGS_DIR"))
	if logDir == "" {
		t.Fatal("SUB2API_REAL_LOGS_DIR is required")
	}
	baseURL := strings.TrimSpace(os.Getenv("SUB2API_AUDIT_TEST_BASE_URL"))
	apiKey := strings.TrimSpace(os.Getenv("SUB2API_AUDIT_TEST_API_KEY"))
	model := strings.TrimSpace(os.Getenv("SUB2API_AUDIT_TEST_MODEL"))
	if baseURL == "" || apiKey == "" || model == "" {
		t.Fatal("SUB2API_AUDIT_TEST_BASE_URL, SUB2API_AUDIT_TEST_API_KEY, and SUB2API_AUDIT_TEST_MODEL are required")
	}

	cfg := defaultSessionAuditProviderConfig()
	cfg.Provider = RiskControlProviderOpenAIResponsesSessionAudit
	cfg.BaseURL = baseURL
	cfg.Path = strings.TrimSpace(os.Getenv("SUB2API_AUDIT_TEST_PATH"))
	cfg.Model = model
	cfg.APIKeys = []string{apiKey}
	cfg.TimeoutMS = realLogAuditIntEnv("SUB2API_AUDIT_TEST_TIMEOUT_MS", 30000)
	cfg.BlockConfidenceThreshold = realLogAuditFloatEnv("SUB2API_REAL_LOGS_BLOCK_THRESHOLD", defaultSessionAuditBlockConfidenceThreshold)
	cfg.AuditMaxInputChars = realLogAuditIntEnv("SUB2API_REAL_LOGS_MAX_INPUT_CHARS", defaultSessionAuditMaxInputChars)
	cfg.EnabledProtocols = []string{ContentModerationProtocolAnthropicMessages, ContentModerationProtocolOpenAIResponses}
	cfg.normalize()

	archives := realLogAuditStringListEnv("SUB2API_REAL_LOGS_ARCHIVES", []string{"cpa2.tar.gz", "logs.tar.gz"})
	maxRequestsPerArchive := realLogAuditIntEnv("SUB2API_REAL_LOGS_MAX_REQUESTS_PER_ARCHIVE", 30)
	expectBlocks := realLogAuditIntEnv("SUB2API_REAL_LOGS_EXPECT_BLOCKS", 2)
	dedupeSessions := strings.TrimSpace(os.Getenv("SUB2API_REAL_LOGS_DEDUPE_SESSIONS")) != "0"

	requests, err := collectRealLogAuditRequests(logDir, archives, maxRequestsPerArchive, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if dedupeSessions {
		requests = dedupeRealLogAuditRequestsBySession(requests)
	}
	if len(requests) == 0 {
		t.Fatalf("no auditable Anthropic Messages requests found in %s archives=%v", logDir, archives)
	}

	client := NewOpenAIResponsesAuditClient(&http.Client{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutMS+2000)*time.Millisecond*time.Duration(len(requests)+1))
	defer cancel()

	blocked := 0
	for _, req := range requests {
		result, err := client.Audit(ctx, cfg, &OpenAIResponsesSessionAuditRequest{
			SessionHash: req.sessionHash,
			Prompt:      renderSessionAuditPrompt(cfg, req.payload),
			Payload:     req.payload,
		})
		if err != nil {
			t.Fatalf("audit failed for archive=%s file=%s session_hash=%s: %v", req.archive, req.file, req.sessionHash, err)
		}
		flagged, isBlocked, highestCategory, highestScore, _ := evaluateSessionAuditResult(result, cfg, ContentModerationModePreBlock)
		t.Logf(
			"audit archive=%s file=%s session_hash=%s violates=%v flagged=%v blocked=%v confidence=%.3f category=%s action=%s reason=%q evidence=%q",
			req.archive,
			req.file,
			req.sessionHash,
			result.Violates,
			flagged,
			isBlocked,
			highestScore,
			highestCategory,
			result.RecommendedAction,
			result.Reason,
			result.EvidenceExcerpt,
		)
		if isBlocked {
			blocked++
		}
	}
	if blocked < expectBlocks {
		t.Fatalf("expected at least %d blocked real-log requests, got %d from %d audited requests", expectBlocks, blocked, len(requests))
	}
}

type realLogAuditRequest struct {
	archive       string
	file          string
	url           string
	protocol      string
	model         string
	sessionHash   string
	sessionSource string
	payload       string
}

func collectRealLogAuditRequests(logDir string, archives []string, maxPerArchive int, cfg *SessionAuditProviderConfig) ([]realLogAuditRequest, error) {
	svc := &ContentModerationService{}
	var requests []realLogAuditRequest
	for _, archive := range archives {
		archive = strings.TrimSpace(archive)
		if archive == "" {
			continue
		}
		collectedForArchive := 0
		if err := walkRealLogArchive(filepath.Join(logDir, archive), func(file string, text string) error {
			if maxPerArchive > 0 && collectedForArchive >= maxPerArchive {
				return errRealLogAuditArchiveLimit
			}
			url := extractRealLogSingleLineValue(text, "URL:")
			protocol := realLogAuditProtocol(url)
			if !cfg.UsesSessionAuditForProtocol(protocol) {
				return nil
			}
			body := []byte(extractRealLogSection(text, "=== REQUEST BODY ==="))
			if len(body) == 0 || !json.Valid(body) {
				return nil
			}
			headers := extractRealLogHeaders(text)
			model := strings.TrimSpace(gjsonString(body, "model"))
			input := ContentModerationCheckInput{
				UserID:   1,
				APIKeyID: 1,
				Endpoint: realLogAuditEndpoint(url),
				Provider: "real-log-smoke",
				Model:    model,
				Protocol: protocol,
				Body:     body,
				Headers:  headers,
			}
			sessionHash, sessionSource, err := svc.extractSessionAuditHash(input)
			if err != nil {
				return fmt.Errorf("extract session hash for %s/%s: %w", archive, file, err)
			}
			if sessionHash == "" {
				return nil
			}
			payload := svc.buildSessionAuditPayload(input, sessionHash, sessionSource, cfg)
			requests = append(requests, realLogAuditRequest{
				archive:       archive,
				file:          file,
				url:           url,
				protocol:      protocol,
				model:         model,
				sessionHash:   sessionHash,
				sessionSource: sessionSource,
				payload:       payload,
			})
			collectedForArchive++
			return nil
		}); err != nil && !errors.Is(err, errRealLogAuditArchiveLimit) {
			return nil, err
		}
	}
	return requests, nil
}

func dedupeRealLogAuditRequestsBySession(requests []realLogAuditRequest) []realLogAuditRequest {
	if len(requests) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]realLogAuditRequest, 0, len(requests))
	for _, req := range requests {
		if strings.TrimSpace(req.sessionHash) == "" {
			continue
		}
		if _, ok := seen[req.sessionHash]; ok {
			continue
		}
		seen[req.sessionHash] = struct{}{}
		out = append(out, req)
	}
	return out
}

var errRealLogAuditArchiveLimit = errors.New("real log archive request limit reached")

func walkRealLogArchive(path string, visit func(file string, text string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if header == nil || header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".log") {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := visit(header.Name, string(data)); err != nil {
			return err
		}
	}
}

func extractRealLogSingleLineValue(text string, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func extractRealLogHeaders(text string) http.Header {
	headers := make(http.Header)
	for _, line := range strings.Split(extractRealLogSection(text, "=== HEADERS ==="), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			headers.Add(key, value)
		}
	}
	return headers
}

func extractRealLogSection(text string, marker string) string {
	start := strings.Index(text, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	for start < len(text) && (text[start] == '\r' || text[start] == '\n') {
		start++
	}
	end := len(text)
	for _, nextMarker := range []string{
		"\n\n=== REQUEST INFO ===",
		"\n\n=== HEADERS ===",
		"\n\n=== REQUEST BODY ===",
		"\n\n=== API REQUEST",
		"\n\n=== API RESPONSE",
	} {
		if idx := strings.Index(text[start:], nextMarker); idx >= 0 && start+idx < end {
			end = start + idx
		}
	}
	return strings.TrimSpace(text[start:end])
}

func realLogAuditProtocol(url string) string {
	path := realLogAuditEndpoint(url)
	switch {
	case path == "/v1/messages":
		return ContentModerationProtocolAnthropicMessages
	case path == "/v1/responses":
		return ContentModerationProtocolOpenAIResponses
	case path == "/v1/chat/completions":
		return ContentModerationProtocolOpenAIChat
	default:
		return ""
	}
}

func realLogAuditEndpoint(rawURL string) string {
	path, _, _ := strings.Cut(strings.TrimSpace(rawURL), "?")
	return path
}

func gjsonString(body []byte, path string) string {
	if len(body) == 0 {
		return ""
	}
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		return ""
	}
	current := any(value)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = object[part]
		if !ok {
			return ""
		}
	}
	if s, ok := current.(string); ok {
		return s
	}
	return ""
}

func realLogAuditStringListEnv(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return append([]string(nil), fallback...)
	}
	values := parseStringListSetting(raw)
	if len(values) == 0 {
		return append([]string(nil), fallback...)
	}
	return values
}

func realLogAuditIntEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func realLogAuditFloatEnv(key string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return value
}
