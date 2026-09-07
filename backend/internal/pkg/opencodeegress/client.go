// Package opencodeegress implements the authenticated local protocol between
// Sub2API and the Bun/OpenCode egress sidecar.
package opencodeegress

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

const (
	ProtocolVersion       = "3"
	ProtocolHeader        = "X-Sub2API-Egress-Protocol"
	SecretHeader          = "X-Sub2API-Egress-Secret"
	TargetURLHeader       = "X-Sub2API-Target-URL"
	TargetMethodHeader    = "X-Sub2API-Target-Method"
	TargetHeadersHeader   = "X-Sub2API-Target-Headers"
	TargetProxyHeader     = "X-Sub2API-Target-Proxy"
	TargetIdentityHeader  = "X-Sub2API-Target-Identity"
	DefaultControlTimeout = 120 * time.Second
)

type Settings struct {
	BaseURL      string
	SharedSecret string
	Timeout      time.Duration
}

type Client struct {
	baseURL      string
	sharedSecret string
	timeout      time.Duration
	httpClient   *http.Client
}

type Health struct {
	OK                    bool   `json:"ok"`
	Service               string `json:"service"`
	OpenCode              string `json:"opencode_version"`
	OpenAIProviderVersion string `json:"openai_provider_version"`
	ProviderUtilsVersion  string `json:"provider_utils_version"`
	Runtime               string `json:"runtime"`
	Protocol              string `json:"protocol"`
	WSMaxPayloadBytes     int64  `json:"ws_max_payload_bytes"`
	WSIdleTimeoutSeconds  int    `json:"ws_idle_timeout_seconds"`
	WSSendPings           bool   `json:"ws_send_pings"`
}

func New(settings Settings) *Client {
	timeout := settings.Timeout
	if timeout <= 0 {
		timeout = DefaultControlTimeout
	}
	return &Client{
		baseURL:      strings.TrimRight(strings.TrimSpace(settings.BaseURL), "/"),
		sharedSecret: settings.SharedSecret,
		timeout:      timeout,
		// Model responses may be long-lived SSE streams. The caller context owns
		// cancellation; a client-wide timeout would recreate Bun's 300s failure.
		httpClient: &http.Client{Transport: &http.Transport{
			Proxy:                 nil,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 0,
			ForceAttemptHTTP2:     true,
		}},
	}
}

func NewFromConfig(settings *config.OpenAIEgressConfig) *Client {
	if settings == nil {
		return New(Settings{})
	}
	return New(Settings{
		BaseURL:      settings.BaseURL,
		SharedSecret: settings.SharedSecret,
		Timeout:      time.Duration(settings.ControlTimeoutSeconds) * time.Second,
	})
}

func (c *Client) Enabled() bool {
	return c != nil && c.baseURL != ""
}

func (c *Client) endpoint(path string) (string, error) {
	if !c.Enabled() {
		return "", errors.New("OpenCode egress sidecar is not configured")
	}
	base, err := url.Parse(c.baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", errors.New("invalid OpenCode egress sidecar URL")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(path, "/")
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(SecretHeader, c.sharedSecret)
	req.Header.Set(ProtocolHeader, ProtocolVersion)
	return req, nil
}

func (c *Client) boundedControlContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok || c == nil || c.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}

// CallJSON is used only by bounded OAuth/device control calls.
func (c *Client) CallJSON(ctx context.Context, path string, payload any) (int, []byte, error) {
	ctx, cancel := c.boundedControlContext(ctx)
	defer cancel()
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := c.newRequest(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, responseBody, nil
}

func (c *Client) Health(ctx context.Context) (*Health, error) {
	ctx, cancel := c.boundedControlContext(ctx)
	defer cancel()
	req, err := c.newRequest(ctx, http.MethodGet, "health", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sidecar health returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var health Health
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, err
	}
	return &health, nil
}

func (c *Client) ValidateHealth(ctx context.Context, expectedMessageBytes int64) (*Health, error) {
	health, err := c.Health(ctx)
	if err != nil {
		return nil, err
	}
	if !health.OK || health.Protocol != ProtocolVersion {
		return nil, fmt.Errorf("incompatible sidecar protocol %q", health.Protocol)
	}
	if expectedMessageBytes > 0 && health.WSMaxPayloadBytes != expectedMessageBytes {
		return nil, fmt.Errorf("sidecar ws max payload mismatch: got %d want %d", health.WSMaxPayloadBytes, expectedMessageBytes)
	}
	if health.WSIdleTimeoutSeconds != 0 || health.WSSendPings {
		return nil, fmt.Errorf("sidecar owns websocket lifecycle: idle_timeout=%d send_pings=%t", health.WSIdleTimeoutSeconds, health.WSSendPings)
	}
	return health, nil
}

// ProxyHTTP streams the raw target request body through the local sidecar.
// Metadata stays in authenticated local headers; the body is never base64 or
// JSON wrapped, so a 256 MiB request does not expand to roughly 341 MiB.
func (c *Client) ProxyHTTP(
	ctx context.Context,
	targetURL string,
	method string,
	headers http.Header,
	body io.Reader,
	contentLength int64,
	proxyURL string,
	identity string,
) (*http.Response, error) {
	req, err := c.newRequest(ctx, http.MethodPost, "proxy/http", body)
	if err != nil {
		return nil, err
	}
	if contentLength >= 0 {
		req.ContentLength = contentLength
		req.Header.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	}
	serialized, err := json.Marshal(cloneHeaderValues(headers))
	if err != nil {
		return nil, err
	}
	req.Header.Set(TargetURLHeader, targetURL)
	req.Header.Set(TargetMethodHeader, method)
	req.Header.Set(TargetHeadersHeader, base64.RawURLEncoding.EncodeToString(serialized))
	req.Header.Set(TargetIdentityHeader, identity)
	if strings.TrimSpace(proxyURL) != "" {
		req.Header.Set(TargetProxyHeader, proxyURL)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Header.Get(ProtocolHeader) != ProtocolVersion {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("sidecar proxy rejected request (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	resp.Header.Del(ProtocolHeader)
	return resp, nil
}

func (c *Client) WebSocketEndpoint() (string, error) {
	endpoint, err := c.endpoint("proxy/ws")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported sidecar URL scheme %q", parsed.Scheme)
	}
	return parsed.String(), nil
}

func (c *Client) WebSocketHeaders(targetURL string, headers http.Header, proxyURL string) (http.Header, error) {
	if !c.Enabled() {
		return nil, errors.New("OpenCode egress sidecar is not configured")
	}
	serialized, err := json.Marshal(cloneHeaderValues(headers))
	if err != nil {
		return nil, err
	}
	result := make(http.Header)
	result.Set(SecretHeader, c.sharedSecret)
	result.Set(ProtocolHeader, ProtocolVersion)
	result.Set(TargetURLHeader, targetURL)
	result.Set(TargetHeadersHeader, base64.RawURLEncoding.EncodeToString(serialized))
	if strings.TrimSpace(proxyURL) != "" {
		result.Set(TargetProxyHeader, proxyURL)
	}
	return result, nil
}

func cloneHeaderValues(headers http.Header) map[string][]string {
	result := make(map[string][]string, len(headers))
	for key, values := range headers {
		result[key] = append([]string(nil), values...)
	}
	return result
}
