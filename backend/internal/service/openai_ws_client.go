package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/opencodeegress"
	openaiwsv2 "github.com/Wei-Shaw/sub2api/internal/service/openai_ws_v2"
	coderws "github.com/coder/websocket"
)

const (
	openAIWSMessageReadLimitBytes int64 = 256 * 1024 * 1024
	openAIWSEgressFragmentBytes         = 1 * 1024 * 1024
	// HTTP2WS sends a complete response.create JSON document. The configured
	// limit is the business payload budget; reserve a small wire headroom for
	// protocol fields added while rebuilding the document.
	openAIWSEgressEnvelopeHeadroomBytes int64 = 64 * 1024
)

var globalOpenAIWSLargeMessageLimiter = make(chan struct{}, 1)
var errOpenAIWSLargeMessageThreshold = errors.New("openai websocket large message threshold exceeded")

type openAIWSEgressMessageTooLargeError struct {
	Size int64
	Max  int64
}

func (e *openAIWSEgressMessageTooLargeError) Error() string {
	return fmt.Sprintf("openai websocket message is %d bytes; limit is %d bytes", e.Size, e.Max)
}

const (
	openAIWSProxyTransportMaxIdleConns        = 128
	openAIWSProxyTransportMaxIdleConnsPerHost = 64
	openAIWSProxyTransportIdleConnTimeout     = 90 * time.Second
	openAIWSProxyClientCacheMaxEntries        = 256
	openAIWSProxyClientCacheIdleTTL           = 15 * time.Minute
)

type OpenAIWSTransportMetricsSnapshot struct {
	ProxyClientCacheHits   int64   `json:"proxy_client_cache_hits"`
	ProxyClientCacheMisses int64   `json:"proxy_client_cache_misses"`
	TransportReuseRatio    float64 `json:"transport_reuse_ratio"`
}

// openAIWSClientConn 抽象 WS 客户端连接，便于替换底层实现。
type openAIWSClientConn interface {
	WriteJSON(ctx context.Context, value any) error
	ReadMessage(ctx context.Context) ([]byte, error)
	Ping(ctx context.Context) error
	Close() error
}

// openAIWSIdlePingCapable is intentionally separate from openAIWSClientConn.
// A pool probe happens while no goroutine is reading an idle connection, which
// is not safe for every WebSocket implementation.
type openAIWSIdlePingCapable interface {
	SupportsIdlePingWithoutReader() bool
}

// openAIWSClientDialer 抽象 WS 建连器。
type openAIWSClientDialer interface {
	Dial(ctx context.Context, wsURL string, headers http.Header, proxyURL string) (openAIWSClientConn, int, http.Header, error)
}

type openAIWSTransportMetricsDialer interface {
	SnapshotTransportMetrics() OpenAIWSTransportMetricsSnapshot
}

func newDefaultOpenAIWSClientDialer() openAIWSClientDialer {
	return newConfiguredOpenAIWSClientDialer(nil)
}

func newConfiguredOpenAIWSClientDialer(cfg *config.Config) openAIWSClientDialer {
	dialer := &coderOpenAIWSClientDialer{
		cfg:          cfg,
		proxyClients: make(map[string]*openAIWSProxyClientEntry),
	}
	if cfg != nil {
		settings := cfg.OpenAIEgressSnapshot()
		dialer.egress = opencodeegress.NewFromConfig(&settings)
	}
	return dialer
}

type coderOpenAIWSClientDialer struct {
	cfg           *config.Config
	egress        *opencodeegress.Client
	healthMu      sync.Mutex
	healthOKUntil time.Time
	proxyMu       sync.Mutex
	proxyClients  map[string]*openAIWSProxyClientEntry
	proxyHits     atomic.Int64
	proxyMisses   atomic.Int64
}

// openAIWSHandshakeError keeps the upstream HTTP error body so recovery and
// HTTP-to-WS lifecycle diagnostics can classify the actual handshake failure.
type openAIWSHandshakeError struct {
	Body []byte
	Err  error
}

func (e *openAIWSHandshakeError) Error() string {
	if e == nil || e.Err == nil {
		return "openai ws handshake failed"
	}
	return e.Err.Error()
}

func (e *openAIWSHandshakeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type openAIWSProxyClientEntry struct {
	client           *http.Client
	lastUsedUnixNano int64
}

func (d *coderOpenAIWSClientDialer) Dial(
	ctx context.Context,
	wsURL string,
	headers http.Header,
	proxyURL string,
) (openAIWSClientConn, int, http.Header, error) {
	if d != nil && d.cfg != nil {
		settingsSnapshot := d.cfg.OpenAIEgressSnapshot()
		settings := &settingsSnapshot
		if settings.Enabled && settings.WSEnabled {
			if strings.TrimSpace(proxyURL) != "" && !settings.AllowProxy {
				if !settings.FallbackToDirect {
					return nil, 0, nil, errors.New("openai websocket egress proxy forwarding is disabled")
				}
				return d.dialDirect(ctx, wsURL, headers, proxyURL)
			}
			conn, status, responseHeaders, err := d.dialEgress(ctx, wsURL, headers, proxyURL)
			if err == nil || !settings.FallbackToDirect {
				return conn, status, responseHeaders, err
			}
		}
	}
	return d.dialDirect(ctx, wsURL, headers, proxyURL)
}

func (d *coderOpenAIWSClientDialer) dialDirect(
	ctx context.Context,
	wsURL string,
	headers http.Header,
	proxyURL string,
) (openAIWSClientConn, int, http.Header, error) {
	targetURL := strings.TrimSpace(wsURL)
	if targetURL == "" {
		return nil, 0, nil, errors.New("ws url is empty")
	}

	opts := &coderws.DialOptions{
		HTTPHeader:      cloneHeader(headers),
		CompressionMode: coderws.CompressionContextTakeover,
	}
	if proxy := strings.TrimSpace(proxyURL); proxy != "" {
		proxyClient, err := d.proxyHTTPClient(proxy)
		if err != nil {
			return nil, 0, nil, err
		}
		opts.HTTPClient = proxyClient
	}

	conn, resp, err := coderws.Dial(ctx, targetURL, opts)
	if err != nil {
		status := 0
		respHeaders := http.Header(nil)
		if resp != nil {
			status = resp.StatusCode
			respHeaders = cloneHeader(resp.Header)
		}
		var body []byte
		if resp != nil && resp.Body != nil {
			body, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		return nil, status, respHeaders, &openAIWSHandshakeError{Body: body, Err: err}
	}
	// coder/websocket 默认单消息读取上限为 32KB，Codex WS 事件（如 rate_limits/大 delta）
	// 可能超过该阈值，需显式提高上限，避免本地 read_fail(message too big)。
	conn.SetReadLimit(openAIWSEgressWireMessageLimit(openAIWSMessageReadLimitBytes))
	respHeaders := http.Header(nil)
	if resp != nil {
		respHeaders = cloneHeader(resp.Header)
	}
	return &coderOpenAIWSClientConn{conn: conn, messageLimit: openAIWSEgressWireMessageLimit(openAIWSMessageReadLimitBytes)}, 0, respHeaders, nil
}

type openAIEgressWSControl struct {
	Type       string              `json:"type"`
	Protocol   string              `json:"protocol"`
	Status     int                 `json:"status"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
	Message    string              `json:"message"`
}

func (d *coderOpenAIWSClientDialer) dialEgress(
	ctx context.Context,
	wsURL string,
	headers http.Header,
	proxyURL string,
) (openAIWSClientConn, int, http.Header, error) {
	if d == nil || d.cfg == nil {
		return nil, 0, nil, errors.New("openai websocket egress sidecar is not configured")
	}
	egress := d.egress
	if egress == nil || !egress.Enabled() {
		settings := d.cfg.OpenAIEgressSnapshot()
		egress = opencodeegress.NewFromConfig(&settings)
	}
	if !egress.Enabled() {
		return nil, 0, nil, errors.New("openai websocket egress sidecar is not configured")
	}
	messageLimit := d.egressWireMessageLimit()
	if err := d.validateEgressHealth(ctx, messageLimit, egress); err != nil {
		return nil, 0, nil, fmt.Errorf("openai websocket egress health check failed: %w", err)
	}
	endpoint, err := egress.WebSocketEndpoint()
	if err != nil {
		return nil, 0, nil, err
	}
	localHeaders, err := egress.WebSocketHeaders(strings.TrimSpace(wsURL), headers, proxyURL)
	if err != nil {
		return nil, 0, nil, err
	}
	conn, resp, err := coderws.Dial(ctx, endpoint, &coderws.DialOptions{
		HTTPHeader:      localHeaders,
		CompressionMode: coderws.CompressionDisabled,
	})
	if err != nil {
		status := 0
		responseHeaders := http.Header(nil)
		var body []byte
		if resp != nil {
			status = resp.StatusCode
			responseHeaders = cloneHeader(resp.Header)
			if resp.Body != nil {
				body, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}
		}
		return nil, status, responseHeaders, &openAIWSHandshakeError{Body: body, Err: err}
	}
	conn.SetReadLimit(messageLimit)
	controlCtx, cancel := d.egressControlContext(ctx)
	defer cancel()
	_, payload, err := conn.Read(controlCtx)
	if err != nil {
		_ = conn.CloseNow()
		return nil, 0, nil, &openAIWSHandshakeError{Err: fmt.Errorf("read sidecar websocket control: %w", err)}
	}
	var control openAIEgressWSControl
	if err := json.Unmarshal(payload, &control); err != nil || control.Protocol != opencodeegress.ProtocolVersion {
		_ = conn.CloseNow()
		return nil, 0, nil, &openAIWSHandshakeError{Err: errors.New("invalid sidecar websocket control message")}
	}
	responseHeaders := canonicalOpenAIEgressHeaders(control.Headers)
	switch control.Type {
	case "sub2api.egress.ready":
		return &coderOpenAIWSClientConn{
			conn: conn, messageLimit: messageLimit, fragmentBytes: openAIWSEgressFragmentBytes,
			largeThreshold: d.largeMessageThreshold(), largeLimiter: globalOpenAIWSLargeMessageLimiter,
		}, 0, responseHeaders, nil
	case "sub2api.egress.handshake_error":
		_ = conn.CloseNow()
		body, _ := base64.StdEncoding.DecodeString(control.BodyBase64)
		errMessage := fmt.Sprintf("openai websocket upstream handshake failed with status %d", control.Status)
		if message := strings.TrimSpace(control.Message); message != "" {
			errMessage += ": " + message
		}
		return nil, control.Status, responseHeaders, &openAIWSHandshakeError{
			Body: body,
			Err:  errors.New(errMessage),
		}
	default:
		_ = conn.CloseNow()
		return nil, 0, nil, &openAIWSHandshakeError{Err: fmt.Errorf("unexpected sidecar websocket control type %q", control.Type)}
	}
}

func canonicalOpenAIEgressHeaders(values map[string][]string) http.Header {
	if len(values) == 0 {
		return nil
	}
	headers := make(http.Header, len(values))
	for key, items := range values {
		for _, value := range items {
			headers.Add(key, value)
		}
	}
	return headers
}

func (d *coderOpenAIWSClientDialer) validateEgressHealth(ctx context.Context, messageLimit int64, egress *opencodeegress.Client) error {
	now := time.Now()
	d.healthMu.Lock()
	defer d.healthMu.Unlock()
	if now.Before(d.healthOKUntil) {
		return nil
	}
	if egress == nil {
		return errors.New("openai websocket egress sidecar is not configured")
	}
	if _, err := egress.ValidateHealth(ctx, messageLimit); err != nil {
		return err
	}
	d.healthOKUntil = now.Add(30 * time.Second)
	return nil
}

func (d *coderOpenAIWSClientDialer) egressControlContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	timeout := opencodeegress.DefaultControlTimeout
	if d != nil && d.cfg != nil && d.cfg.OpenAIEgressSnapshot().ControlTimeoutSeconds > 0 {
		timeout = time.Duration(d.cfg.OpenAIEgressSnapshot().ControlTimeoutSeconds) * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}

func (d *coderOpenAIWSClientDialer) egressMessageLimit() int64 {
	if d != nil && d.cfg != nil && d.cfg.Gateway.OpenAIWS.EgressMessageLimitBytes > 0 {
		return d.cfg.Gateway.OpenAIWS.EgressMessageLimitBytes
	}
	return openAIWSMessageReadLimitBytes
}

func openAIWSEgressWireMessageLimit(logicalLimit int64) int64 {
	if logicalLimit <= 0 {
		logicalLimit = openAIWSMessageReadLimitBytes
	}
	return logicalLimit + openAIWSEgressEnvelopeHeadroomBytes
}

func (d *coderOpenAIWSClientDialer) egressWireMessageLimit() int64 {
	return openAIWSEgressWireMessageLimit(d.egressMessageLimit())
}

func (d *coderOpenAIWSClientDialer) largeMessageThreshold() int64 {
	if d != nil && d.cfg != nil && d.cfg.Gateway.OpenAIWS.LargeMessageThresholdBytes > 0 {
		return d.cfg.Gateway.OpenAIWS.LargeMessageThresholdBytes
	}
	return 32 << 20
}

func (d *coderOpenAIWSClientDialer) proxyHTTPClient(proxy string) (*http.Client, error) {
	if d == nil {
		return nil, errors.New("openai ws dialer is nil")
	}
	normalizedProxy := strings.TrimSpace(proxy)
	if normalizedProxy == "" {
		return nil, errors.New("proxy url is empty")
	}
	parsedProxyURL, err := url.Parse(normalizedProxy)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy url: %w", err)
	}
	now := time.Now().UnixNano()

	d.proxyMu.Lock()
	defer d.proxyMu.Unlock()
	if entry, ok := d.proxyClients[normalizedProxy]; ok && entry != nil && entry.client != nil {
		entry.lastUsedUnixNano = now
		d.proxyHits.Add(1)
		return entry.client, nil
	}
	d.cleanupProxyClientsLocked(now)
	transport := &http.Transport{
		Proxy:               http.ProxyURL(parsedProxyURL),
		MaxIdleConns:        openAIWSProxyTransportMaxIdleConns,
		MaxIdleConnsPerHost: openAIWSProxyTransportMaxIdleConnsPerHost,
		IdleConnTimeout:     openAIWSProxyTransportIdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{Transport: transport}
	d.proxyClients[normalizedProxy] = &openAIWSProxyClientEntry{
		client:           client,
		lastUsedUnixNano: now,
	}
	d.ensureProxyClientCapacityLocked()
	d.proxyMisses.Add(1)
	return client, nil
}

func (d *coderOpenAIWSClientDialer) cleanupProxyClientsLocked(nowUnixNano int64) {
	if d == nil || len(d.proxyClients) == 0 {
		return
	}
	idleTTL := openAIWSProxyClientCacheIdleTTL
	if idleTTL <= 0 {
		return
	}
	now := time.Unix(0, nowUnixNano)
	for key, entry := range d.proxyClients {
		if entry == nil || entry.client == nil {
			delete(d.proxyClients, key)
			continue
		}
		lastUsed := time.Unix(0, entry.lastUsedUnixNano)
		if now.Sub(lastUsed) > idleTTL {
			closeOpenAIWSProxyClient(entry.client)
			delete(d.proxyClients, key)
		}
	}
}

func (d *coderOpenAIWSClientDialer) ensureProxyClientCapacityLocked() {
	if d == nil {
		return
	}
	maxEntries := openAIWSProxyClientCacheMaxEntries
	if maxEntries <= 0 {
		return
	}
	for len(d.proxyClients) > maxEntries {
		var oldestKey string
		var oldestLastUsed int64
		hasOldest := false
		for key, entry := range d.proxyClients {
			lastUsed := int64(0)
			if entry != nil {
				lastUsed = entry.lastUsedUnixNano
			}
			if !hasOldest || lastUsed < oldestLastUsed {
				hasOldest = true
				oldestKey = key
				oldestLastUsed = lastUsed
			}
		}
		if !hasOldest {
			return
		}
		if entry := d.proxyClients[oldestKey]; entry != nil {
			closeOpenAIWSProxyClient(entry.client)
		}
		delete(d.proxyClients, oldestKey)
	}
}

func closeOpenAIWSProxyClient(client *http.Client) {
	if client == nil || client.Transport == nil {
		return
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport != nil {
		transport.CloseIdleConnections()
	}
}

func (d *coderOpenAIWSClientDialer) SnapshotTransportMetrics() OpenAIWSTransportMetricsSnapshot {
	if d == nil {
		return OpenAIWSTransportMetricsSnapshot{}
	}
	hits := d.proxyHits.Load()
	misses := d.proxyMisses.Load()
	total := hits + misses
	reuseRatio := 0.0
	if total > 0 {
		reuseRatio = float64(hits) / float64(total)
	}
	return OpenAIWSTransportMetricsSnapshot{
		ProxyClientCacheHits:   hits,
		ProxyClientCacheMisses: misses,
		TransportReuseRatio:    reuseRatio,
	}
}

type coderOpenAIWSClientConn struct {
	conn           *coderws.Conn
	messageLimit   int64
	fragmentBytes  int
	largeThreshold int64
	largeLimiter   chan struct{}
}

var _ openaiwsv2.FrameConn = (*coderOpenAIWSClientConn)(nil)

func (c *coderOpenAIWSClientConn) WriteJSON(ctx context.Context, value any) error {
	if c == nil || c.conn == nil {
		return errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.largeLimiter != nil && c.largeThreshold > 0 {
		large, err := openAIWSJSONExceedsThreshold(value, c.largeThreshold)
		if err != nil {
			return err
		}
		if large {
			release, acquireErr := acquireOpenAIWSLargeMessage(ctx, c.largeLimiter)
			if acquireErr != nil {
				return acquireErr
			}
			defer release()
		}
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.writePayloadAdmitted(ctx, coderws.MessageText, payload, true)
}

func (c *coderOpenAIWSClientConn) writePayload(ctx context.Context, messageType coderws.MessageType, payload []byte) error {
	return c.writePayloadAdmitted(ctx, messageType, payload, false)
}

func (c *coderOpenAIWSClientConn) writePayloadAdmitted(ctx context.Context, messageType coderws.MessageType, payload []byte, admissionChecked bool) error {
	if c == nil || c.conn == nil {
		return errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.messageLimit > 0 && int64(len(payload)) > c.messageLimit {
		return &openAIWSEgressMessageTooLargeError{Size: int64(len(payload)), Max: c.messageLimit}
	}
	release := func() {}
	if !admissionChecked && c.largeLimiter != nil && c.largeThreshold > 0 && int64(len(payload)) > c.largeThreshold {
		var err error
		release, err = acquireOpenAIWSLargeMessage(ctx, c.largeLimiter)
		if err != nil {
			return err
		}
	}
	defer release()
	if c.fragmentBytes <= 0 || len(payload) <= c.fragmentBytes {
		return c.conn.Write(ctx, messageType, payload)
	}
	writer, err := c.conn.Writer(ctx, messageType)
	if err != nil {
		return err
	}
	for offset := 0; offset < len(payload); offset += c.fragmentBytes {
		end := offset + c.fragmentBytes
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := writer.Write(payload[offset:end]); err != nil {
			_ = writer.Close()
			return err
		}
	}
	return writer.Close()
}

func acquireOpenAIWSLargeMessage(ctx context.Context, limiter chan struct{}) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case limiter <- struct{}{}:
		return func() { <-limiter }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

type openAIWSCountingWriter struct {
	limit int64
	count int64
}

func (w *openAIWSCountingWriter) Write(p []byte) (int, error) {
	w.count += int64(len(p))
	if w.count > w.limit {
		return len(p), errOpenAIWSLargeMessageThreshold
	}
	return len(p), nil
}

func openAIWSJSONExceedsThreshold(value any, threshold int64) (bool, error) {
	if threshold <= 0 {
		return false, nil
	}
	if raw, ok := value.(json.RawMessage); ok {
		return int64(len(raw)) > threshold, nil
	}
	w := &openAIWSCountingWriter{limit: threshold}
	err := json.NewEncoder(w).Encode(value)
	if errors.Is(err, errOpenAIWSLargeMessageThreshold) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func (c *coderOpenAIWSClientConn) ReadMessage(ctx context.Context) ([]byte, error) {
	if c == nil || c.conn == nil {
		return nil, errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	msgType, payload, err := c.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	switch msgType {
	case coderws.MessageText, coderws.MessageBinary:
		return payload, nil
	default:
		return nil, errOpenAIWSConnClosed
	}
}

func (c *coderOpenAIWSClientConn) ReadFrame(ctx context.Context) (coderws.MessageType, []byte, error) {
	if c == nil || c.conn == nil {
		return coderws.MessageText, nil, errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	msgType, payload, err := c.conn.Read(ctx)
	if err != nil {
		return coderws.MessageText, nil, err
	}
	return msgType, payload, nil
}

func (c *coderOpenAIWSClientConn) WriteFrame(ctx context.Context, msgType coderws.MessageType, payload []byte) error {
	if c == nil || c.conn == nil {
		return errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.writePayload(ctx, msgType, payload)
}

func (c *coderOpenAIWSClientConn) Ping(ctx context.Context) error {
	if c == nil || c.conn == nil {
		return errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.conn.Ping(ctx)
}

// SupportsIdlePingWithoutReader reports the actual coder/websocket contract.
// Conn.Ping waits for a pong, while control frames are only consumed by Read.
// The pool deliberately has no reader on an idle connection, so using Ping as
// a health probe would deterministically time out a healthy socket.
func (*coderOpenAIWSClientConn) SupportsIdlePingWithoutReader() bool {
	return false
}

func (c *coderOpenAIWSClientConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	// Close 为幂等，忽略重复关闭错误。
	_ = c.conn.Close(coderws.StatusNormalClosure, "")
	_ = c.conn.CloseNow()
	return nil
}
