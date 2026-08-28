package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	coderws "github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

func TestCoderOpenAIWSClientDialer_ProxyHTTPClientReuse(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	c1, err := impl.proxyHTTPClient("http://127.0.0.1:8080")
	require.NoError(t, err)
	c2, err := impl.proxyHTTPClient("http://127.0.0.1:8080")
	require.NoError(t, err)
	require.Same(t, c1, c2, "同一代理地址应复用同一个 HTTP 客户端")

	c3, err := impl.proxyHTTPClient("http://127.0.0.1:8081")
	require.NoError(t, err)
	require.NotSame(t, c1, c3, "不同代理地址应分离客户端")
}

func TestCoderOpenAIWSClientDialer_ProxyHTTPClientInvalidURL(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	_, err := impl.proxyHTTPClient("://bad")
	require.Error(t, err)
}

func TestCoderOpenAIWSClientDialer_TransportMetricsSnapshot(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	_, err := impl.proxyHTTPClient("http://127.0.0.1:18080")
	require.NoError(t, err)
	_, err = impl.proxyHTTPClient("http://127.0.0.1:18080")
	require.NoError(t, err)
	_, err = impl.proxyHTTPClient("http://127.0.0.1:18081")
	require.NoError(t, err)

	snapshot := impl.SnapshotTransportMetrics()
	require.Equal(t, int64(1), snapshot.ProxyClientCacheHits)
	require.Equal(t, int64(2), snapshot.ProxyClientCacheMisses)
	require.InDelta(t, 1.0/3.0, snapshot.TransportReuseRatio, 0.0001)
}

func TestCoderOpenAIWSClientDialer_ProxyClientCacheCapacity(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	total := openAIWSProxyClientCacheMaxEntries + 32
	for i := 0; i < total; i++ {
		_, err := impl.proxyHTTPClient(fmt.Sprintf("http://127.0.0.1:%d", 20000+i))
		require.NoError(t, err)
	}

	impl.proxyMu.Lock()
	cacheSize := len(impl.proxyClients)
	impl.proxyMu.Unlock()

	require.LessOrEqual(t, cacheSize, openAIWSProxyClientCacheMaxEntries, "代理客户端缓存应受容量上限约束")
}

func TestCoderOpenAIWSClientDialer_ProxyClientCacheIdleTTL(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	oldProxy := "http://127.0.0.1:28080"
	_, err := impl.proxyHTTPClient(oldProxy)
	require.NoError(t, err)

	impl.proxyMu.Lock()
	oldEntry := impl.proxyClients[oldProxy]
	require.NotNil(t, oldEntry)
	oldEntry.lastUsedUnixNano = time.Now().Add(-openAIWSProxyClientCacheIdleTTL - time.Minute).UnixNano()
	impl.proxyMu.Unlock()

	// 触发一次新的代理获取，驱动 TTL 清理。
	_, err = impl.proxyHTTPClient("http://127.0.0.1:28081")
	require.NoError(t, err)

	impl.proxyMu.Lock()
	_, exists := impl.proxyClients[oldProxy]
	impl.proxyMu.Unlock()

	require.False(t, exists, "超过空闲 TTL 的代理客户端应被回收")
}

func TestCoderOpenAIWSClientDialer_ProxyTransportTLSHandshakeTimeout(t *testing.T) {
	dialer := newDefaultOpenAIWSClientDialer()
	impl, ok := dialer.(*coderOpenAIWSClientDialer)
	require.True(t, ok)

	client, err := impl.proxyHTTPClient("http://127.0.0.1:38080")
	require.NoError(t, err)
	require.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport)
	require.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
}

func TestCoderOpenAIWSClientConn_DoesNotSupportIdlePingWithoutReader(t *testing.T) {
	require.False(t, (&coderOpenAIWSClientConn{}).SupportsIdlePingWithoutReader())
}

func TestOpenAIWSJSONExceedsThresholdWithoutAllocatingSerializedCopy(t *testing.T) {
	large, err := openAIWSJSONExceedsThreshold(map[string]any{"input": strings.Repeat("x", 4096)}, 1024)
	require.NoError(t, err)
	require.True(t, large)
	small, err := openAIWSJSONExceedsThreshold(map[string]any{"input": "ok"}, 1024)
	require.NoError(t, err)
	require.False(t, small)
}

func TestCoderOpenAIWSClientDialer_EgressReadyAndFragmentedMessage(t *testing.T) {
	received := make(chan []byte, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "protocol": "3", "ws_max_payload_bytes": openAIWSEgressWireMessageLimit(256 << 20),
			"ws_idle_timeout_seconds": 0, "ws_send_pings": false,
		})
	})
	mux.HandleFunc("/proxy/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := coderws.Accept(w, r, nil)
		require.NoError(t, err)
		defer ws.CloseNow()
		ws.SetReadLimit(openAIWSEgressWireMessageLimit(256 << 20))
		ready, _ := json.Marshal(map[string]any{
			"type": "sub2api.egress.ready", "protocol": "3",
			"headers": map[string][]string{"x-codex-turn-state": {"turn-state"}},
		})
		require.NoError(t, ws.Write(r.Context(), coderws.MessageText, ready))
		_, payload, err := ws.Read(r.Context())
		require.NoError(t, err)
		received <- payload
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		Enabled: true, BaseURL: server.URL, WSEnabled: true, AllowProxy: true,
	}
	cfg.Gateway.OpenAIWS.EgressMessageLimitBytes = 256 << 20
	cfg.Gateway.OpenAIWS.LargeMessageThresholdBytes = 32 << 20
	dialer := newConfiguredOpenAIWSClientDialer(cfg)
	conn, status, headers, err := dialer.Dial(
		context.Background(),
		"wss://chatgpt.com/backend-api/codex/responses",
		http.Header{"Authorization": {"Bearer token"}},
		"",
	)
	require.NoError(t, err)
	require.Zero(t, status)
	require.Equal(t, "turn-state", headers.Get("x-codex-turn-state"))
	defer conn.Close()

	value := map[string]any{"type": "response.create", "input": strings.Repeat("x", 3<<20)}
	require.NoError(t, conn.WriteJSON(context.Background(), value))
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(<-received, &decoded))
	require.Equal(t, "response.create", decoded["type"])
	require.Len(t, decoded["input"], 3<<20)
}

func TestCoderOpenAIWSClientDialer_EgressLargeCompleteMessage(t *testing.T) {
	sizeMiB := 128
	if raw := strings.TrimSpace(os.Getenv("SUB2API_LARGE_WS_TEST_MIB")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		require.NoError(t, err, "SUB2API_LARGE_WS_TEST_MIB must be an integer")
		sizeMiB = parsed
	}
	if os.Getenv("SUB2API_RUN_LARGE_WS_TEST") != "1" && strings.TrimSpace(os.Getenv("SUB2API_LARGE_WS_TEST_MIB")) == "" {
		t.Skip("set SUB2API_RUN_LARGE_WS_TEST=1 or SUB2API_LARGE_WS_TEST_MIB=128|256 for the protocol stress test")
	}
	require.GreaterOrEqual(t, sizeMiB, 1)
	require.LessOrEqual(t, sizeMiB, 256)
	inputBytes := sizeMiB << 20
	type receivedMessage struct {
		size int
		hash [sha256.Size]byte
	}
	received := make(chan receivedMessage, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "protocol": "3", "ws_max_payload_bytes": openAIWSEgressWireMessageLimit(256 << 20),
			"ws_idle_timeout_seconds": 0, "ws_send_pings": false,
		})
	})
	mux.HandleFunc("/proxy/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := coderws.Accept(w, r, nil)
		require.NoError(t, err)
		defer ws.CloseNow()
		ws.SetReadLimit(openAIWSEgressWireMessageLimit(256 << 20))
		ready, _ := json.Marshal(map[string]any{"type": "sub2api.egress.ready", "protocol": "3"})
		require.NoError(t, ws.Write(r.Context(), coderws.MessageText, ready))
		messageType, payload, err := ws.Read(r.Context())
		require.NoError(t, err)
		require.Equal(t, coderws.MessageText, messageType)
		received <- receivedMessage{size: len(payload), hash: sha256.Sum256(payload)}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		Enabled: true, BaseURL: server.URL, WSEnabled: true, AllowProxy: true,
	}
	cfg.Gateway.OpenAIWS.EgressMessageLimitBytes = 256 << 20
	cfg.Gateway.OpenAIWS.LargeMessageThresholdBytes = 32 << 20
	cfg.Gateway.OpenAIWS.LargeMessageMaxInflight = 1
	dialer := newConfiguredOpenAIWSClientDialer(cfg)
	conn, _, _, err := dialer.Dial(context.Background(), "wss://chatgpt.com/backend-api/codex/responses", nil, "")
	require.NoError(t, err)
	defer conn.Close()

	value := struct {
		Input string `json:"input"`
		Type  string `json:"type"`
	}{Input: strings.Repeat("x", inputBytes), Type: "response.create"}
	writeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	require.NoError(t, conn.WriteJSON(writeCtx, value))

	wantHash := sha256.New()
	_, _ = wantHash.Write([]byte(`{"input":"`))
	chunk := []byte(strings.Repeat("x", 1<<20))
	for written := 0; written < inputBytes; written += len(chunk) {
		_, _ = wantHash.Write(chunk)
	}
	_, _ = wantHash.Write([]byte(`","type":"response.create"}`))
	wantSize := inputBytes + len(`{"input":"","type":"response.create"}`)

	select {
	case got := <-received:
		require.Equal(t, wantSize, got.size)
		require.Equal(t, fmt.Sprintf("%x", wantHash.Sum(nil)), fmt.Sprintf("%x", got.hash[:]))
	case <-writeCtx.Done():
		t.Fatal("timed out waiting for the complete reassembled WebSocket message")
	}
}

func TestCoderOpenAIWSClientDialer_EgressHandshakeErrorRestoresStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "protocol": "3", "ws_max_payload_bytes": openAIWSEgressWireMessageLimit(256 << 20),
			"ws_idle_timeout_seconds": 0, "ws_send_pings": false,
		})
	})
	mux.HandleFunc("/proxy/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := coderws.Accept(w, r, nil)
		require.NoError(t, err)
		defer ws.CloseNow()
		payload, _ := json.Marshal(map[string]any{
			"type": "sub2api.egress.handshake_error", "protocol": "3", "status": 429,
			"headers":     map[string][]string{"retry-after": {"7"}},
			"body_base64": base64.StdEncoding.EncodeToString([]byte(`{"error":{"type":"rate_limit_error"}}`)),
		})
		require.NoError(t, ws.Write(r.Context(), coderws.MessageText, payload))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{Enabled: true, BaseURL: server.URL, WSEnabled: true}
	cfg.Gateway.OpenAIWS.EgressMessageLimitBytes = 256 << 20
	dialer := newConfiguredOpenAIWSClientDialer(cfg)
	conn, status, headers, err := dialer.Dial(context.Background(), "wss://chatgpt.com/backend-api/codex/responses", nil, "")
	require.Nil(t, conn)
	require.Equal(t, 429, status)
	require.Equal(t, "7", headers.Get("retry-after"))
	var handshakeErr *openAIWSHandshakeError
	require.ErrorAs(t, err, &handshakeErr)
	require.Contains(t, string(handshakeErr.Body), "rate_limit_error")
}
