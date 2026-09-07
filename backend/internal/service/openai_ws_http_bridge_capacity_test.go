package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func newOpenAIWSHTTPBridgeCapacityTest(
	t *testing.T,
	streamBody string,
) (*OpenAIGatewayService, *Account, *gin.Context, *httpUpstreamRecorder) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.URLAllowlist.Enabled = false
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	cfg.Gateway.MaxLineSize = defaultMaxLineSize
	upstream := &httpUpstreamRecorder{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "x-request-id": []string{"rid-http-bridge-capacity"}},
			Body:       io.NopCloser(strings.NewReader(streamBody)),
		},
	}
	svc := &OpenAIGatewayService{
		cfg:           cfg,
		httpUpstream:  upstream,
		toolCorrector: NewCodexToolCorrector(),
	}
	account := &Account{
		ID:          553,
		Name:        "openai-http-bridge-capacity",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{"api_key": "sk-test"},
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	return svc, account, c, upstream
}

func TestOpenAIWSHTTPBridgeCapacityBeforeSemanticOutputFailsOverWithoutClientMessages(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, account, c, _ := newOpenAIWSHTTPBridgeCapacityTest(t, strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp-http-bridge-discarded"}}`,
		"",
		`data: {"type":"response.failed","response":{"id":"resp-http-bridge-discarded","error":{"message":"Our servers are currently overloaded. Please try again later."}}}`,
		"",
	}, "\n"))

	var clientMessages [][]byte
	result, err := svc.proxyOpenAIWSHTTPBridgeTurn(
		context.Background(),
		c,
		account,
		"sk-test",
		[]byte(`{"type":"response.create","model":"gpt-5.1","stream":false,"store":false,"input":"hello"}`),
		96,
		"gpt-5.1",
		"",
		"",
		"",
		"",
		1,
		func(message []byte) error {
			clientMessages = append(clientMessages, append([]byte(nil), message...))
			return nil
		},
	)

	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RetryableOnSameAccount)
	require.True(t, failoverErr.RequestScopedTransient)
	require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
	require.Empty(t, clientMessages)
}

func TestOpenAIWSHTTPBridgeCapacityAfterSemanticOutputSanitizesWithoutFailover(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, account, c, _ := newOpenAIWSHTTPBridgeCapacityTest(t, strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp-http-bridge-committed"}}`,
		"",
		`data: {"type":"response.output_text.delta","delta":"partial"}`,
		"",
		`data: {"type":"response.failed","response":{"id":"resp-http-bridge-committed","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded."}}}`,
		"",
	}, "\n"))

	var clientMessages [][]byte
	result, err := svc.proxyOpenAIWSHTTPBridgeTurn(
		context.Background(),
		c,
		account,
		"sk-test",
		[]byte(`{"type":"response.create","model":"gpt-5.1","stream":false,"store":false,"input":"hello"}`),
		96,
		"gpt-5.1",
		"",
		"",
		"",
		"",
		1,
		func(message []byte) error {
			clientMessages = append(clientMessages, append([]byte(nil), message...))
			return nil
		},
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.RequestScopedTransient)
	require.Equal(t, "response.failed", result.UpstreamTerminalEvent)
	require.Len(t, clientMessages, 3)
	require.Contains(t, string(clientMessages[0]), "response.created")
	require.Contains(t, string(clientMessages[1]), "partial")
	require.Contains(t, string(clientMessages[2]), `"code":"server_error"`)
	require.NotContains(t, string(clientMessages[2]), "server_is_overloaded")
}

func TestOpenAIWSHTTPBridgeCapacityReturnsToClientWithoutReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	cfg.Security.URLAllowlist.Enabled = false
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	cfg.Gateway.MaxLineSize = defaultMaxLineSize
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.APIKeyEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
	cfg.Gateway.OpenAIWS.IngressModeDefault = OpenAIWSIngressModeCtxPool
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 3

	upstream := &httpUpstreamSequenceRecorder{
		responses: []*http.Response{
			{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(strings.Join([]string{
					`data: {"type":"response.created","response":{"id":"resp-http-bridge-retry-discarded"}}`,
					"",
					`data: {"type":"error","error":{"code":"server_is_overloaded","message":"Server is overloaded."}}`,
					"",
				}, "\n"))),
			},
			{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(strings.Join([]string{
					`data: {"type":"response.created","response":{"id":"resp-http-bridge-retry-ok"}}`,
					"",
					`data: {"type":"response.completed","response":{"id":"resp-http-bridge-retry-ok","model":"gpt-5.1","usage":{"input_tokens":1,"output_tokens":1}}}`,
					"",
				}, "\n"))),
			},
		},
	}
	svc := &OpenAIGatewayService{
		cfg:              cfg,
		httpUpstream:     upstream,
		cache:            &stubGatewayCache{},
		openaiWSResolver: NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:    NewCodexToolCorrector(),
	}
	account := &Account{
		ID:          554,
		Name:        "openai-http-bridge-capacity-retry",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"api_key":               "sk-test",
			"pool_mode":             true,
			"pool_mode_retry_count": 1,
		},
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_mode": OpenAIWSIngressModeHTTPBridge,
		},
	}

	clientConn, serverErrCh := startOpenAIWSIngressTestClient(t, svc, account)
	defer func() { _ = clientConn.CloseNow() }()
	writeOpenAIWSIngressTestMessage(t, clientConn, `{"type":"response.create","model":"gpt-5.1","stream":false,"store":false,"input":"hello"}`)
	failed := readOpenAIWSIngressTestMessage(t, clientConn)
	require.Equal(t, "error", gjson.GetBytes(failed, "type").String())
	require.Equal(t, "server_error", gjson.GetBytes(failed, "error.code").String())
	require.NotContains(t, string(failed), "server_is_overloaded")
	require.Equal(t, 1, upstream.callCount)

	_ = clientConn.Close(coderws.StatusNormalClosure, "done")
	select {
	case serverErr := <-serverErrCh:
		var failoverErr *UpstreamFailoverError
		require.ErrorAs(t, serverErr, &failoverErr)
		require.True(t, failoverErr.RequestScopedTransient)
		require.True(t, failoverErr.ClientResponseWritten)
		require.Equal(t, NextAccountStop, failoverErr.NextAccountAction)
	case <-time.After(4 * time.Second):
		t.Fatal("等待 http_bridge capacity 会话结束超时")
	}
}

func TestOpenAIWSHTTPBridgeCapacityExhaustionStopsWithoutCrossAccountFailover(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	cfg.Security.URLAllowlist.Enabled = false
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	cfg.Gateway.MaxLineSize = defaultMaxLineSize
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.APIKeyEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
	cfg.Gateway.OpenAIWS.IngressModeDefault = OpenAIWSIngressModeHTTPBridge
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 3

	capacityResponse := func(id string) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body: io.NopCloser(strings.NewReader(strings.Join([]string{
				`data: {"type":"response.created","response":{"id":"` + id + `"}}`,
				"",
				`data: {"type":"response.failed","response":{"id":"` + id + `","error":{"code":"server_is_overloaded","message":"Server is overloaded."}}}`,
				"",
			}, "\n"))),
		}
	}
	upstream := &httpUpstreamSequenceRecorder{responses: []*http.Response{
		capacityResponse("resp-http-bridge-capacity-1"),
		capacityResponse("resp-http-bridge-capacity-2"),
	}}
	svc := &OpenAIGatewayService{
		cfg:              cfg,
		httpUpstream:     upstream,
		cache:            &stubGatewayCache{},
		openaiWSResolver: NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:    NewCodexToolCorrector(),
	}
	account := &Account{
		ID: 555, Name: "openai-http-bridge-capacity-exhausted", Platform: PlatformOpenAI,
		Type: AccountTypeAPIKey, Status: StatusActive, Schedulable: true, Concurrency: 1,
		Credentials: map[string]any{
			"api_key": "sk-test", "pool_mode": true, "pool_mode_retry_count": 1,
		},
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_mode": OpenAIWSIngressModeHTTPBridge,
		},
	}

	clientConn, serverErrCh := startOpenAIWSIngressTestClient(t, svc, account)
	defer func() { _ = clientConn.CloseNow() }()
	writeOpenAIWSIngressTestMessage(t, clientConn, `{"type":"response.create","model":"gpt-5.1","stream":false,"store":false,"input":"hello"}`)
	failed := readOpenAIWSIngressTestMessage(t, clientConn)
	require.Equal(t, "response.failed", gjson.GetBytes(failed, "type").String())
	require.Equal(t, "server_error", gjson.GetBytes(failed, "response.error.code").String())
	require.NotContains(t, string(failed), "server_is_overloaded")

	select {
	case serverErr := <-serverErrCh:
		var failoverErr *UpstreamFailoverError
		require.ErrorAs(t, serverErr, &failoverErr)
		require.True(t, failoverErr.RequestScopedTransient)
		require.False(t, failoverErr.RetryableOnSameAccount)
		require.True(t, failoverErr.ClientResponseWritten)
		require.Equal(t, NextAccountStop, failoverErr.NextAccountAction)
		require.False(t, failoverErr.ShouldRetryNextAccount())
		require.Empty(t, failoverErr.ReplayRequestBody)
	case <-time.After(4 * time.Second):
		t.Fatal("等待 http_bridge capacity exhaustion 超时")
	}
	require.Equal(t, 1, upstream.callCount)
}
