package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"
)

type OpenAIResponsesAuditClient struct {
	httpClient *http.Client
	keyCursor  atomic.Uint64
}

func NewOpenAIResponsesAuditClient(httpClient *http.Client) *OpenAIResponsesAuditClient {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &OpenAIResponsesAuditClient{httpClient: httpClient}
}

func (c *OpenAIResponsesAuditClient) Audit(ctx context.Context, cfg *SessionAuditProviderConfig, req *OpenAIResponsesSessionAuditRequest) (*OpenAIResponsesSessionAuditResult, error) {
	if c == nil {
		return nil, errors.New("nil audit client")
	}
	if cfg == nil {
		return nil, errors.New("nil audit config")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("session audit model is required")
	}
	if len(cfg.APIKeys) == 0 {
		return nil, errors.New("session audit api key is required")
	}
	if req == nil {
		return nil, errors.New("nil audit request")
	}

	endpoint, err := joinSessionAuditURL(cfg.BaseURL, cfg.Path)
	if err != nil {
		return nil, err
	}
	payload := openAIResponsesAuditAPIRequest{
		Model: cfg.Model,
		Input: []openAIResponsesAuditInputItem{
			{
				Role: "system",
				Content: []openAIResponsesAuditInputContent{
					{Type: "input_text", Text: strings.TrimSpace(req.Prompt)},
				},
			},
			{
				Role: "user",
				Content: []openAIResponsesAuditInputContent{
					{Type: "input_text", Text: strings.TrimSpace(req.Payload)},
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal session audit request: %w", err)
	}

	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultSessionAuditTimeoutMS * time.Millisecond
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create session audit request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.nextAPIKey(cfg.APIKeys))

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call session audit api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read session audit response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("session audit api status %d: %s", resp.StatusCode, redactContentModerationSecrets(strings.TrimSpace(string(respBody))))
	}

	var parsed openAIResponsesAuditAPIResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshal session audit response: %w", err)
	}
	text := extractOpenAIResponsesAuditText(&parsed)
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("session audit response is empty")
	}
	result, err := parseOpenAIResponsesAuditResult(text)
	if err != nil {
		return nil, err
	}
	result.ResponseID = strings.TrimSpace(parsed.ID)
	return result, nil
}

func (c *OpenAIResponsesAuditClient) nextAPIKey(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	if len(keys) == 1 {
		return keys[0]
	}
	idx := c.keyCursor.Add(1)
	return keys[(idx-1)%uint64(len(keys))]
}

func joinSessionAuditURL(baseURL string, auditPath string) (string, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = defaultSessionAuditBaseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse session audit base url: %w", err)
	}
	if strings.TrimSpace(auditPath) == "" {
		auditPath = defaultSessionAuditPath
	}
	basePath := strings.TrimRight(u.Path, "/")
	nextPath := normalizeAuditPath(auditPath)
	if (strings.EqualFold(basePath, "/v1") || strings.HasSuffix(strings.ToLower(basePath), "/v1")) &&
		(strings.EqualFold(nextPath, "/v1") || strings.HasPrefix(strings.ToLower(nextPath), "/v1/")) {
		nextPath = strings.TrimPrefix(nextPath, "/v1")
		if nextPath == "" {
			nextPath = "/"
		}
	}
	joined := path.Clean(strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(nextPath, "/"))
	if !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}
	if joined == "/." {
		joined = "/"
	}
	u.Path = joined
	u.RawPath = ""
	return u.String(), nil
}

func extractOpenAIResponsesAuditText(resp *openAIResponsesAuditAPIResponse) string {
	if resp == nil {
		return ""
	}
	if text := strings.TrimSpace(resp.OutputText); text != "" {
		return text
	}
	for _, item := range resp.Output {
		for _, content := range item.Content {
			if text := strings.TrimSpace(content.Text); text != "" {
				return text
			}
		}
	}
	return ""
}

func parseOpenAIResponsesAuditResult(text string) (*OpenAIResponsesSessionAuditResult, error) {
	jsonText := extractOpenAIResponsesAuditJSON(text)
	if strings.TrimSpace(jsonText) == "" {
		return nil, errors.New("session audit response does not contain json")
	}
	var result OpenAIResponsesSessionAuditResult
	if err := json.Unmarshal([]byte(jsonText), &result); err != nil {
		return nil, fmt.Errorf("unmarshal session audit json: %w", err)
	}
	result.Categories = normalizeSessionAuditCategories(result.Categories)
	result.Reason = redactContentModerationSecrets(strings.TrimSpace(result.Reason))
	result.EvidenceExcerpt = redactContentModerationSecrets(strings.TrimSpace(result.EvidenceExcerpt))
	result.RecommendedAction = normalizeSessionAuditRecommendedAction(result.RecommendedAction)
	return &result, nil
}

func extractOpenAIResponsesAuditJSON(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if strings.HasPrefix(text, "```") {
		lines := strings.Split(text, "\n")
		if len(lines) >= 2 {
			lines = lines[1:]
			if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "```" {
				lines = lines[:len(lines)-1]
			}
			text = strings.TrimSpace(strings.Join(lines, "\n"))
		}
	}
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		return strings.TrimSpace(text[start : end+1])
	}
	return text
}

type openAIResponsesAuditAPIRequest struct {
	Model string                          `json:"model"`
	Input []openAIResponsesAuditInputItem `json:"input"`
}

type openAIResponsesAuditInputItem struct {
	Role    string                             `json:"role"`
	Content []openAIResponsesAuditInputContent `json:"content"`
}

type openAIResponsesAuditInputContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type openAIResponsesAuditAPIResponse struct {
	ID         string                              `json:"id"`
	OutputText string                              `json:"output_text"`
	Output     []openAIResponsesAuditAPIOutputItem `json:"output"`
}

type openAIResponsesAuditAPIOutputItem struct {
	Content []openAIResponsesAuditAPIOutputContent `json:"content"`
}

type openAIResponsesAuditAPIOutputContent struct {
	Text string `json:"text"`
}
