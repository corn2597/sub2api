package service

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestOpenAIClientTransport_SetAndGet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	require.Equal(t, OpenAIClientTransportUnknown, GetOpenAIClientTransport(c))

	SetOpenAIClientTransport(c, OpenAIClientTransportHTTP)
	require.Equal(t, OpenAIClientTransportHTTP, GetOpenAIClientTransport(c))

	SetOpenAIClientTransport(c, OpenAIClientTransportWS)
	require.Equal(t, OpenAIClientTransportWS, GetOpenAIClientTransport(c))
}

func TestOpenAIClientTransport_GetNormalizesRawContextValue(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		rawValue any
		want     OpenAIClientTransport
	}{
		{
			name:     "type_value_ws",
			rawValue: OpenAIClientTransportWS,
			want:     OpenAIClientTransportWS,
		},
		{
			name:     "http_sse_alias",
			rawValue: "http_sse",
			want:     OpenAIClientTransportHTTP,
		},
		{
			name:     "sse_alias",
			rawValue: "sSe",
			want:     OpenAIClientTransportHTTP,
		},
		{
			name:     "websocket_alias",
			rawValue: "WebSocket",
			want:     OpenAIClientTransportWS,
		},
		{
			name:     "invalid_string",
			rawValue: "tcp",
			want:     OpenAIClientTransportUnknown,
		},
		{
			name:     "invalid_type",
			rawValue: 123,
			want:     OpenAIClientTransportUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set(openAIClientTransportContextKey, tt.rawValue)
			require.Equal(t, tt.want, GetOpenAIClientTransport(c))
		})
	}
}

func TestOpenAIClientTransport_NilAndUnknownInput(t *testing.T) {
	SetOpenAIClientTransport(nil, OpenAIClientTransportHTTP)
	require.Equal(t, OpenAIClientTransportUnknown, GetOpenAIClientTransport(nil))

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	SetOpenAIClientTransport(c, OpenAIClientTransportUnknown)
	_, exists := c.Get(openAIClientTransportContextKey)
	require.False(t, exists)

	SetOpenAIClientTransport(c, OpenAIClientTransport("   "))
	_, exists = c.Get(openAIClientTransportContextKey)
	require.False(t, exists)
}

func TestResolveOpenAIWSDecisionByClientTransport(t *testing.T) {
	base := OpenAIWSProtocolDecision{
		Transport: OpenAIUpstreamTransportResponsesWebsocketV2,
		Reason:    "ws_v2_enabled",
	}

	httpDecision := resolveOpenAIWSDecisionByClientTransport(base, OpenAIClientTransportHTTP)
	require.Equal(t, OpenAIUpstreamTransportHTTPSSE, httpDecision.Transport)
	require.Equal(t, "client_protocol_http", httpDecision.Reason)

	wsDecision := resolveOpenAIWSDecisionByClientTransport(base, OpenAIClientTransportWS)
	require.Equal(t, base, wsDecision)

	unknownDecision := resolveOpenAIWSDecisionByClientTransport(base, OpenAIClientTransportUnknown)
	require.Equal(t, base, unknownDecision)
}

func TestResolveOpenAIWSDecisionForHTTPRequest(t *testing.T) {
	base := OpenAIWSProtocolDecision{
		Transport: OpenAIUpstreamTransportResponsesWebsocketV2,
		Reason:    "ws_v2_enabled",
	}
	account := &Account{
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{"openai_oauth_http_to_ws_enabled": true},
	}
	newContext := func() *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
		SetOpenAIClientTransport(c, OpenAIClientTransportHTTP)
		return c
	}

	t.Run("double switch and replay-safe body enables upstream websocket", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Gateway.OpenAIWS.HTTPToWSEnabled = true
		svc := &OpenAIGatewayService{cfg: cfg}
		decision := svc.resolveOpenAIWSDecisionForRequest(newContext(), account, []byte(`{"store":false,"stream":true}`), base)
		require.Equal(t, OpenAIUpstreamTransportResponsesWebsocketV2, decision.Transport)
		require.Equal(t, "http_to_ws_enabled", decision.Reason)
	})

	tests := []struct {
		name   string
		body   string
		reason string
	}{
		{name: "store missing", body: `{"stream":true}`, reason: "http_to_ws_store_false_required"},
		{name: "store true", body: `{"store":true}`, reason: "http_to_ws_store_false_required"},
		{name: "previous response", body: `{"store":false,"previous_response_id":"resp_1"}`, reason: "http_to_ws_previous_response_id"},
		{name: "conversation", body: `{"store":false,"conversation":"conv_1"}`, reason: "http_to_ws_conversation"},
		{name: "background", body: `{"store":false,"background":true}`, reason: "http_to_ws_background"},
		{name: "image model", body: `{"store":false,"model":"gpt-image-2"}`, reason: "http_to_ws_image_ineligible"},
		{name: "native image tool", body: `{"store":false,"model":"gpt-5","tools":[{"type":"image_generation"}]}`, reason: "http_to_ws_image_ineligible"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Gateway.OpenAIWS.HTTPToWSEnabled = true
			svc := &OpenAIGatewayService{cfg: cfg}
			decision := svc.resolveOpenAIWSDecisionForRequest(newContext(), account, []byte(tt.body), base)
			require.Equal(t, OpenAIUpstreamTransportHTTPSSE, decision.Transport)
			require.Equal(t, tt.reason, decision.Reason)
		})
	}

	t.Run("global switch defaults off", func(t *testing.T) {
		decision := (&OpenAIGatewayService{cfg: &config.Config{}}).resolveOpenAIWSDecisionForRequest(
			newContext(), account, []byte(`{"store":false}`), base,
		)
		require.Equal(t, "http_to_ws_global_disabled", decision.Reason)
	})

	t.Run("compact endpoint remains on http", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Gateway.OpenAIWS.HTTPToWSEnabled = true
		c := newContext()
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses/compact", nil)
		SetOpenAIClientTransport(c, OpenAIClientTransportHTTP)
		decision := (&OpenAIGatewayService{cfg: cfg}).resolveOpenAIWSDecisionForRequest(
			c, account, []byte(`{"store":false}`), base,
		)
		require.Equal(t, OpenAIUpstreamTransportHTTPSSE, decision.Transport)
		require.Equal(t, "http_to_ws_endpoint_ineligible", decision.Reason)
	})

	t.Run("force http reason remains observable", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Gateway.OpenAIWS.HTTPToWSEnabled = true
		for _, reason := range []string{"global_force_http", "account_force_http"} {
			decision := (&OpenAIGatewayService{cfg: cfg}).resolveOpenAIWSDecisionForRequest(
				newContext(), account, []byte(`{"store":false}`), openAIWSHTTPDecision(reason),
			)
			require.Equal(t, OpenAIUpstreamTransportHTTPSSE, decision.Transport)
			require.Equal(t, reason, decision.Reason)
		}
	})

	t.Run("account opt-in required", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Gateway.OpenAIWS.HTTPToWSEnabled = true
		accountWithoutOptIn := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}
		decision := (&OpenAIGatewayService{cfg: cfg}).resolveOpenAIWSDecisionForRequest(
			newContext(), accountWithoutOptIn, []byte(`{"store":false}`), base,
		)
		require.Equal(t, "http_to_ws_account_disabled", decision.Reason)
	})

	t.Run("api key account remains on http", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Gateway.OpenAIWS.HTTPToWSEnabled = true
		apiKeyAccount := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeAPIKey,
			Extra:    map[string]any{"openai_oauth_http_to_ws_enabled": true},
		}
		decision := (&OpenAIGatewayService{cfg: cfg}).resolveOpenAIWSDecisionForRequest(
			newContext(), apiKeyAccount, []byte(`{"store":false}`), base,
		)
		require.Equal(t, OpenAIUpstreamTransportHTTPSSE, decision.Transport)
		require.Equal(t, "http_to_ws_oauth_required", decision.Reason)
	})
}
