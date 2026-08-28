package repository

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/opencodeegress"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/imroc/req/v3"
)

// NewOpenAIOAuthClient creates a new OpenAI OAuth client
func NewOpenAIOAuthClient() service.OpenAIOAuthClient {
	return &openaiOAuthService{tokenURL: openai.TokenURL}
}

func NewOpenAIOAuthClientWithConfig(cfg *config.Config) service.OpenAIOAuthClient {
	return &openaiOAuthService{tokenURL: openai.TokenURL, cfg: cfg}
}

type openaiOAuthService struct {
	tokenURL string
	cfg      *config.Config
}

func (s *openaiOAuthService) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, proxyURL, clientID string) (*openai.TokenResponse, error) {
	if err := s.rejectDirectProxyBypass(proxyURL); err != nil {
		return nil, err
	}
	if tokenResp, handled, err := s.exchangeThroughSidecar(ctx, code, codeVerifier, redirectURI, proxyURL, clientID); handled {
		if err == nil || !s.shouldFallbackToDirect() {
			return tokenResp, err
		}
	}
	client, err := createOpenAIReqClient(proxyURL)
	if err != nil {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_CLIENT_INIT_FAILED", "create HTTP client: %v", err)
	}

	if redirectURI == "" {
		redirectURI = openai.DefaultRedirectURI
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		clientID = openai.ClientID
	}

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("client_id", clientID)
	formData.Set("code", code)
	formData.Set("redirect_uri", redirectURI)
	formData.Set("code_verifier", codeVerifier)

	var tokenResp openai.TokenResponse

	authUA, authOriginator := service.CodexCanonicalAuthIdentity()
	resp, err := client.R().
		SetContext(ctx).
		SetHeader("User-Agent", authUA).
		SetHeader("originator", authOriginator).
		SetFormDataFromValues(formData).
		SetSuccessResult(&tokenResp).
		Post(s.tokenURL)

	if err != nil {
		if shouldReturnOpenAINoProxyHint(ctx, proxyURL, err) {
			return nil, newOpenAINoProxyHintError(err)
		}
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_REQUEST_FAILED", "request failed: %v", err)
	}

	if !resp.IsSuccessState() {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_EXCHANGE_FAILED", "token exchange failed: status %d, body: %s", resp.StatusCode, resp.String())
	}

	return &tokenResp, nil
}

func (s *openaiOAuthService) RefreshToken(ctx context.Context, refreshToken, proxyURL string) (*openai.TokenResponse, error) {
	return s.RefreshTokenWithClientID(ctx, refreshToken, proxyURL, "")
}

func (s *openaiOAuthService) RefreshTokenWithClientID(ctx context.Context, refreshToken, proxyURL string, clientID string) (*openai.TokenResponse, error) {
	if err := s.rejectDirectProxyBypass(proxyURL); err != nil {
		return nil, err
	}
	// 调用方应始终传入正确的 client_id；为兼容旧数据，未指定时默认使用 OpenAI ClientID
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		clientID = openai.ClientID
	}
	return s.refreshTokenWithClientID(ctx, refreshToken, proxyURL, clientID)
}

func (s *openaiOAuthService) refreshTokenWithClientID(ctx context.Context, refreshToken, proxyURL, clientID string) (*openai.TokenResponse, error) {
	if tokenResp, handled, err := s.refreshThroughSidecar(ctx, refreshToken, proxyURL, clientID); handled {
		if err == nil || !s.shouldFallbackToDirect() {
			return tokenResp, err
		}
	}
	client, err := createOpenAIReqClient(proxyURL)
	if err != nil {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_CLIENT_INIT_FAILED", "create HTTP client: %v", err)
	}

	formData := url.Values{}
	formData.Set("grant_type", "refresh_token")
	formData.Set("refresh_token", refreshToken)
	formData.Set("client_id", clientID)
	formData.Set("scope", openai.RefreshScopes)

	var tokenResp openai.TokenResponse

	authUA, authOriginator := service.CodexCanonicalAuthIdentity()
	resp, err := client.R().
		SetContext(ctx).
		SetHeader("User-Agent", authUA).
		SetHeader("originator", authOriginator).
		SetFormDataFromValues(formData).
		SetSuccessResult(&tokenResp).
		Post(s.tokenURL)

	if err != nil {
		if shouldReturnOpenAINoProxyHint(ctx, proxyURL, err) {
			return nil, newOpenAINoProxyHintError(err)
		}
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_REQUEST_FAILED", "request failed: %v", err)
	}

	if !resp.IsSuccessState() {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_REFRESH_FAILED", "token refresh failed: status %d, body: %s", resp.StatusCode, resp.String())
	}

	return &tokenResp, nil
}

func (s *openaiOAuthService) shouldFallbackToDirect() bool {
	if s == nil || s.cfg == nil {
		return true
	}
	return s.cfg.OpenAIEgressSnapshot().FallbackToDirect
}

func (s *openaiOAuthService) rejectDirectProxyBypass(proxyURL string) error {
	if s == nil || s.cfg == nil {
		return nil
	}
	settingsSnapshot := s.cfg.OpenAIEgressSnapshot()
	settings := &settingsSnapshot
	if !settings.Enabled || strings.TrimSpace(proxyURL) == "" || settings.AllowProxy || settings.FallbackToDirect {
		return nil
	}
	return infraerrors.New(http.StatusBadGateway, "OPENAI_OAUTH_PROXY_EGRESS_DISABLED", "OpenAI egress proxy forwarding is disabled; refusing a direct OAuth request")
}

func (s *openaiOAuthService) sidecarClient(proxyURL string) (*opencodeegress.Client, bool) {
	if s == nil || s.cfg == nil {
		return nil, false
	}
	settingsSnapshot := s.cfg.OpenAIEgressSnapshot()
	settings := &settingsSnapshot
	if !settings.Enabled || !settings.OAuthEnabled || (strings.TrimSpace(proxyURL) != "" && !settings.AllowProxy) {
		return nil, false
	}
	return opencodeegress.NewFromConfig(settings), true
}

func (s *openaiOAuthService) exchangeThroughSidecar(ctx context.Context, code, codeVerifier, redirectURI, proxyURL, clientID string) (*openai.TokenResponse, bool, error) {
	client, ok := s.sidecarClient(proxyURL)
	if !ok {
		return nil, false, nil
	}
	if redirectURI == "" {
		redirectURI = openai.DefaultRedirectURI
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		clientID = openai.ClientID
	}
	payload := map[string]string{
		"grant_type": "authorization_code", "client_id": clientID, "code": code,
		"redirect_uri": redirectURI, "code_verifier": codeVerifier,
	}
	if strings.TrimSpace(proxyURL) != "" {
		payload["proxy_url"] = proxyURL
	}
	status, body, err := client.CallJSON(ctx, "oauth/exchange", payload)
	if err != nil {
		return nil, true, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_REQUEST_FAILED", "sidecar request failed: %v", err)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, true, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_EXCHANGE_FAILED", "token exchange failed: status %d, body: %s", status, boundedOAuthBody(body))
	}
	var tokenResp openai.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, true, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_EXCHANGE_FAILED", "invalid token response from sidecar: %v", err)
	}
	return &tokenResp, true, nil
}

func (s *openaiOAuthService) refreshThroughSidecar(ctx context.Context, refreshToken, proxyURL, clientID string) (*openai.TokenResponse, bool, error) {
	client, ok := s.sidecarClient(proxyURL)
	if !ok {
		return nil, false, nil
	}
	payload := map[string]string{
		"grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": clientID,
	}
	if strings.TrimSpace(proxyURL) != "" {
		payload["proxy_url"] = proxyURL
	}
	status, body, err := client.CallJSON(ctx, "oauth/refresh", payload)
	if err != nil {
		return nil, true, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_REQUEST_FAILED", "sidecar request failed: %v", err)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, true, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_REFRESH_FAILED", "token refresh failed: status %d, body: %s", status, boundedOAuthBody(body))
	}
	var tokenResp openai.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, true, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_REFRESH_FAILED", "invalid token response from sidecar: %v", err)
	}
	return &tokenResp, true, nil
}

func boundedOAuthBody(body []byte) string {
	const maxLen = 4096
	if len(body) > maxLen {
		body = body[:maxLen]
	}
	return strings.TrimSpace(string(body))
}

func createOpenAIReqClient(proxyURL string) (*req.Client, error) {
	return getSharedReqClient(reqClientOptions{
		ProxyURL: proxyURL,
		Timeout:  120 * time.Second,
	})
}

func shouldReturnOpenAINoProxyHint(ctx context.Context, proxyURL string, err error) bool {
	if strings.TrimSpace(proxyURL) != "" || err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	return !errors.Is(err, context.Canceled)
}

func newOpenAINoProxyHintError(cause error) error {
	return infraerrors.New(
		http.StatusBadGateway,
		"OPENAI_OAUTH_PROXY_REQUIRED",
		"OpenAI OAuth request failed: no proxy is configured and this server could not reach OpenAI directly. Select a proxy that can access OpenAI, then retry; if the authorization code has expired, regenerate the authorization URL.",
	).WithCause(cause)
}
