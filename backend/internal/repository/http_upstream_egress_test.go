package repository

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/opencodeegress"
	"github.com/stretchr/testify/require"
)

func TestHTTPUpstreamRoutesOfficialOpenAIHostThroughEgressWithoutProfile(t *testing.T) {
	wantBody := []byte(`{"model":"gpt-5.5","input":"hello"}`)
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/proxy/http", r.URL.Path)
		require.Equal(t, "secret", r.Header.Get(opencodeegress.SecretHeader))
		require.Equal(t, "https://api.openai.com/v1/responses", r.Header.Get(opencodeegress.TargetURLHeader))
		require.Equal(t, "model", r.Header.Get(opencodeegress.TargetIdentityHeader))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, wantBody, body)
		w.Header().Set(opencodeegress.ProtocolHeader, opencodeegress.ProtocolVersion)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_test"}`))
	}))
	defer sidecar.Close()
	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		Enabled: true, HTTPEnabled: true, BaseURL: sidecar.URL, SharedSecret: "secret",
	}
	upstream := NewHTTPUpstream(cfg)
	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", bytes.NewReader(wantBody))
	require.NoError(t, err)
	resp, err := upstream.Do(req, "", 7, 1)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Same(t, req, resp.Request)
}

func TestHTTPUpstreamEgressFailsClosedOnInvalidProtocol(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"type":"broken_sidecar"}}`))
	}))
	defer sidecar.Close()
	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		Enabled: true, HTTPEnabled: true, BaseURL: sidecar.URL, FallbackToDirect: false,
	}
	upstream := NewHTTPUpstream(cfg)
	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	resp, err := upstream.Do(req, "", 7, 1)
	require.Nil(t, resp)
	require.ErrorContains(t, err, "sidecar")
}
