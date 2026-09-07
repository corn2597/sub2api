package opencodeegress

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientProxyHTTPStreamsRawBodyAndMetadata(t *testing.T) {
	wantBody := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/proxy/http", r.URL.Path)
		require.Equal(t, "secret", r.Header.Get(SecretHeader))
		require.Equal(t, ProtocolVersion, r.Header.Get(ProtocolHeader))
		require.Equal(t, "https://chatgpt.com/backend-api/codex/responses", r.Header.Get(TargetURLHeader))
		require.Equal(t, http.MethodPost, r.Header.Get(TargetMethodHeader))
		require.Equal(t, "model", r.Header.Get(TargetIdentityHeader))
		require.Equal(t, "socks5://127.0.0.1:1080", r.Header.Get(TargetProxyHeader))
		encoded := r.Header.Get(TargetHeadersHeader)
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		require.NoError(t, err)
		var headers map[string][]string
		require.NoError(t, json.Unmarshal(decoded, &headers))
		require.Equal(t, []string{"Bearer token"}, headers["Authorization"])
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, wantBody, body)
		w.Header().Set(ProtocolHeader, ProtocolVersion)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := New(Settings{BaseURL: server.URL, SharedSecret: "secret"})
	resp, err := client.ProxyHTTP(
		context.Background(),
		"https://chatgpt.com/backend-api/codex/responses",
		http.MethodPost,
		http.Header{"Authorization": {"Bearer token"}},
		bytes.NewReader(wantBody),
		int64(len(wantBody)),
		"socks5://127.0.0.1:1080",
		"model",
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	require.Empty(t, resp.Header.Get(ProtocolHeader))
}

func TestClientValidateHealthRequiresExactWSOwnership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Health{
			OK: true, Protocol: ProtocolVersion, WSMaxPayloadBytes: 256 << 20,
			WSIdleTimeoutSeconds: 0, WSSendPings: false,
		})
	}))
	defer server.Close()
	client := New(Settings{BaseURL: server.URL})
	_, err := client.ValidateHealth(context.Background(), 256<<20)
	require.NoError(t, err)
	_, err = client.ValidateHealth(context.Background(), 64<<20)
	require.ErrorContains(t, err, "ws max payload mismatch")
}

func TestClientWebSocketHeadersKeepTargetMetadataLocal(t *testing.T) {
	client := New(Settings{BaseURL: "http://127.0.0.1:12783", SharedSecret: "secret"})
	headers, err := client.WebSocketHeaders(
		"wss://chatgpt.com/backend-api/codex/responses",
		http.Header{"Authorization": {"Bearer token"}, "Session-Id": {"ses_0123456789abcdef0123456789abcdef"}},
		"http://proxy:8080",
	)
	require.NoError(t, err)
	require.Equal(t, "secret", headers.Get(SecretHeader))
	require.Equal(t, ProtocolVersion, headers.Get(ProtocolHeader))
	require.Equal(t, "wss://chatgpt.com/backend-api/codex/responses", headers.Get(TargetURLHeader))
	require.Equal(t, "http://proxy:8080", headers.Get(TargetProxyHeader))
	require.Empty(t, headers.Get("Authorization"))
}
