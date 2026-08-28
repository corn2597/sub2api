package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/opencodeegress"
	"github.com/stretchr/testify/require"
)

func TestOpenAIEgressSettingsPartialUpdatePersistsCompleteSnapshot(t *testing.T) {
	repo := &panelRateLimitSettingRepo{}
	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		Enabled: true, BaseURL: "http://sidecar:12783", SharedSecret: "secret",
		ControlTimeoutSeconds: 120, HTTPEnabled: true, WSEnabled: true,
		OAuthEnabled: true, AllowProxy: true,
	}
	svc := NewSettingService(repo, cfg)

	updated, err := svc.UpdateOpenAIEgressSettings(context.Background(), OpenAIEgressRuntimeSettings{
		FallbackToDirect: boolPointer(true),
	})
	require.NoError(t, err)
	require.True(t, updated.FallbackToDirect)
	require.True(t, updated.HTTPEnabled)
	require.True(t, updated.WSEnabled)
	require.True(t, updated.OAuthEnabled)

	raw := repo.values[SettingKeyOpenAIEgressRuntime]
	var persisted OpenAIEgressRuntimeSettings
	require.NoError(t, json.Unmarshal([]byte(raw), &persisted))
	require.NotNil(t, persisted.Enabled)
	require.NotNil(t, persisted.HTTPEnabled)
	require.NotNil(t, persisted.WSEnabled)
	require.NotNil(t, persisted.OAuthEnabled)
	require.NotNil(t, persisted.FallbackToDirect)
	require.NotNil(t, persisted.AllowProxy)
}

func TestLoadOpenAIEgressRuntimeSettingsAppliesPersistedSwitches(t *testing.T) {
	repo := &panelRateLimitSettingRepo{values: map[string]string{
		SettingKeyOpenAIEgressRuntime: `{"enabled":true,"http_enabled":false,"ws_enabled":true,"oauth_enabled":false,"fallback_to_direct":false,"allow_proxy":true}`,
	}}
	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		Enabled: false, BaseURL: "http://sidecar:12783", SharedSecret: "secret",
		ControlTimeoutSeconds: 120, HTTPEnabled: true, WSEnabled: false,
		OAuthEnabled: true, AllowProxy: false,
	}
	svc := NewSettingService(repo, cfg)

	require.NoError(t, svc.LoadOpenAIEgressRuntimeSettings(context.Background()))
	effective := cfg.OpenAIEgressSnapshot()
	require.True(t, effective.Enabled)
	require.False(t, effective.HTTPEnabled)
	require.True(t, effective.WSEnabled)
	require.False(t, effective.OAuthEnabled)
	require.False(t, effective.FallbackToDirect)
	require.True(t, effective.AllowProxy)
}

func TestOpenAIEgressSettingsRejectsEnabledWithoutSecret(t *testing.T) {
	repo := &panelRateLimitSettingRepo{}
	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		BaseURL: "http://sidecar:12783", HTTPEnabled: true, WSEnabled: true, OAuthEnabled: true,
	}
	svc := NewSettingService(repo, cfg)

	_, err := svc.UpdateOpenAIEgressSettings(context.Background(), OpenAIEgressRuntimeSettings{
		Enabled: boolPointer(true),
	})
	require.ErrorContains(t, err, "shared_secret")
	require.Empty(t, repo.values)
}

func TestOpenAIEgressSettingsHealthCheckUsesSecretAndDoesNotExposeIt(t *testing.T) {
	const secret = "health-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, secret, r.Header.Get(opencodeegress.SecretHeader))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"service":"sub2api-opencode-egress","opencode_version":"1.18.20","runtime":"bun","protocol":"3","ws_max_payload_bytes":268500992,"ws_idle_timeout_seconds":0,"ws_send_pings":false}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		Enabled: true, BaseURL: server.URL, SharedSecret: secret,
		ControlTimeoutSeconds: 1, HTTPEnabled: true, WSEnabled: true, OAuthEnabled: true,
	}
	cfg.Gateway.OpenAIWS.EgressMessageLimitBytes = 256 << 20
	svc := NewSettingService(&panelRateLimitSettingRepo{}, cfg)

	settings, err := svc.TestOpenAIEgress(context.Background())
	require.NoError(t, err)
	require.True(t, settings.SidecarReachable)
	require.True(t, settings.SecretConfigured)
	require.Equal(t, "1.18.20", settings.SidecarVersion)
	encoded, err := json.Marshal(settings)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), secret)
}

func TestOpenAIEgressSettingsHealthCheckRejectsIncompatibleSidecar(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"service":"sub2api-opencode-egress","opencode_version":"1.18.20","runtime":"bun","protocol":"2","ws_max_payload_bytes":67108864,"ws_idle_timeout_seconds":120,"ws_send_pings":true}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Gateway.OpenAIEgress = config.OpenAIEgressConfig{
		Enabled: true, BaseURL: server.URL, SharedSecret: "secret",
		ControlTimeoutSeconds: 1, HTTPEnabled: true, WSEnabled: true, OAuthEnabled: true,
	}
	cfg.Gateway.OpenAIWS.EgressMessageLimitBytes = 256 << 20

	settings, err := NewSettingService(&panelRateLimitSettingRepo{}, cfg).TestOpenAIEgress(context.Background())
	require.NoError(t, err)
	require.False(t, settings.SidecarReachable)
	require.Contains(t, settings.SidecarError, "incompatible sidecar protocol")
}
