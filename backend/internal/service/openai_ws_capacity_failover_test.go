package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func newOpenAIWSCapacityTestService(t *testing.T, events []map[string]any) (*OpenAIGatewayService, *Account, *gin.Context, *httptest.ResponseRecorder, func()) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var request map[string]any
		if err := conn.ReadJSON(&request); err != nil {
			return
		}
		for _, event := range events {
			if err := conn.WriteJSON(event); err != nil {
				return
			}
		}
	}))

	cfg := &config.Config{}
	cfg.Security.URLAllowlist.Enabled = false
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.APIKeyEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 1
	cfg.Gateway.OpenAIWS.QueueLimitPerConn = 4
	cfg.Gateway.OpenAIWS.DialTimeoutSeconds = 2
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 2
	cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 2

	svc := &OpenAIGatewayService{cfg: cfg, toolCorrector: NewCodexToolCorrector()}
	account := &Account{
		ID:          9001,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{"api_key": "sk-test", "base_url": server.URL},
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	cleanup := func() {
		if svc.openaiWSPool != nil {
			svc.openaiWSPool.Close()
		}
		server.Close()
	}
	return svc, account, c, recorder, cleanup
}

func runOpenAIWSCapacityTestForward(
	t *testing.T,
	svc *OpenAIGatewayService,
	account *Account,
	c *gin.Context,
	stream bool,
) (*OpenAIForwardResult, error) {
	t.Helper()
	return svc.forwardOpenAIWSV2(
		context.Background(),
		c,
		account,
		map[string]any{"model": "gpt-5", "stream": stream, "store": false, "input": []any{}},
		"",
		"sk-test",
		OpenAIWSProtocolDecision{Transport: OpenAIUpstreamTransportResponsesWebsocketV2, Reason: "test"},
		false,
		stream,
		"gpt-5",
		"gpt-5",
		time.Now(),
		1,
		"",
		new(bool),
	)
}

func TestForwardOpenAIWSV2CapacityBeforeSemanticOutputFailsOverWithoutClientBytes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_1"}},
		{"type": "response.output_item.added", "item": map[string]any{"type": "reasoning", "summary": []any{}}},
		{"type": "error", "error": map[string]any{"message": "Our servers are currently overloaded. Please try again later."}},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RetryableOnSameAccount)
	require.True(t, failoverErr.RequestScopedTransient)
	require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
	require.Empty(t, recorder.Body.String())
}

func TestForwardOpenAIWSV2ErrorCaptureMatchesActualUpstreamFrame(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstreamFrame := make(chan []byte, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		upstreamFrame <- bytes.Clone(payload)
		_ = conn.WriteJSON(map[string]any{
			"type": "error",
			"error": map[string]any{
				"code":    "invalid_request_error",
				"message": "capture integration test",
			},
		})
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.APIKeyEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 1
	cfg.Gateway.OpenAIWS.QueueLimitPerConn = 1
	cfg.Gateway.OpenAIWS.DialTimeoutSeconds = 2
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 2
	cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 2
	svc := &OpenAIGatewayService{cfg: cfg, toolCorrector: NewCodexToolCorrector()}
	defer func() {
		if svc.openaiWSPool != nil {
			svc.openaiWSPool.Close()
		}
	}()
	account := &Account{
		ID:          9010,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{"api_key": "sk-test", "base_url": server.URL},
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	originalHTTP := []byte(`{"model":"gpt-5","stream":true,"input":"exact ingress"}`)
	SetOpsHTTPErrorPayloadCandidate(c, originalHTTP)
	MarkOpsErrorPayloadCaptureEnabled(c)

	_, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Error(t, err)
	actualFrame := <-upstreamFrame
	capture := TakeOpsErrorPayloadCapture(c)
	require.NotNil(t, capture)
	require.Equal(t, originalHTTP, capture.HTTPPayload)
	require.Len(t, capture.WSPayloads, 1)
	require.Equal(t, actualFrame, capture.WSPayloads[opsPayloadSHA256(actualFrame)])
	require.Len(t, capture.WSAttempts, 1)
	require.Equal(t, 1, capture.WSAttempts[0].AttemptNo)
	require.Equal(t, account.ID, capture.WSAttempts[0].AccountID)
	require.True(t, capture.WSAttempts[0].WriteSucceeded)
	require.NotEmpty(t, capture.WSAttempts[0].ConnID)
}

func TestForwardOpenAIWSV2CapacityAfterSemanticOutputSanitizesStream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_2"}},
		{"type": "response.output_text.delta", "delta": "partial"},
		{"type": "error", "error": map[string]any{"code": "server_is_overloaded", "message": "Our servers are currently overloaded."}},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.True(t, errors.As(err, &failoverErr))
	require.True(t, failoverErr.RequestScopedTransient)
	require.True(t, failoverErr.ClientResponseWritten)
	require.False(t, failoverErr.ShouldRetryNextAccount())
	require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
	body := recorder.Body.String()
	require.Contains(t, body, "partial")
	require.Contains(t, body, `"code":"server_error"`)
	require.NotContains(t, body, "server_is_overloaded")
}

func TestForwardOpenAIWSV2CapacityAfterEncryptedReasoningCommitsAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_encrypted"}},
		{
			"type": "response.output_item.added",
			"item": map[string]any{
				"type":              "reasoning",
				"encrypted_content": "ciphertext-that-must-not-be-replayed",
			},
		},
		{"type": "error", "error": map[string]any{"code": "server_is_overloaded", "message": "Server is overloaded."}},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RequestScopedTransient)
	require.True(t, failoverErr.ClientResponseWritten)
	require.False(t, failoverErr.ShouldRetryNextAccount())
	require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
	body := recorder.Body.String()
	require.Contains(t, body, "ciphertext-that-must-not-be-replayed")
	require.Contains(t, body, `"code":"server_error"`)
	require.NotContains(t, body, "server_is_overloaded")
}

func TestForwardOpenAIWSV2CapacityAfterUnknownEventFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_unknown"}},
		{"type": "response.future_semantic", "payload": "opaque-output"},
		{"type": "error", "error": map[string]any{"code": "server_is_overloaded", "message": "Server is overloaded."}},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RequestScopedTransient)
	require.True(t, failoverErr.ClientResponseWritten)
	require.False(t, failoverErr.ShouldRetryNextAccount())
	require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
	body := recorder.Body.String()
	require.Contains(t, body, "response.future_semantic")
	require.Contains(t, body, "opaque-output")
	require.Contains(t, body, `"code":"server_error"`)
	require.NotContains(t, body, "server_is_overloaded")
}

func TestForwardOpenAIWSV2CapacityAfterStageOverflowCommitsAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oversizedLifecyclePayload := strings.Repeat("x", openAIFirstOutputStageMaxBytes+1024)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_stage_overflow"}},
		{
			"type":     "response.in_progress",
			"response": map[string]any{"id": "resp_capacity_stage_overflow"},
			"padding":  oversizedLifecyclePayload,
		},
		{"type": "error", "error": map[string]any{"code": "server_is_overloaded", "message": "Server is overloaded."}},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RequestScopedTransient)
	require.True(t, failoverErr.ClientResponseWritten)
	require.False(t, failoverErr.ShouldRetryNextAccount())
	require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
	require.Greater(t, recorder.Body.Len(), openAIFirstOutputStageMaxBytes)
	body := recorder.Body.String()
	require.Contains(t, body, `"code":"server_error"`)
	require.NotContains(t, body, "server_is_overloaded")
}

func TestForwardOpenAIWSV2CapacityFailedTerminalDoesNotAffectAccountHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_terminal"}},
		{"type": "response.output_text.delta", "delta": "partial"},
		{"type": "response.failed", "response": map[string]any{"id": "resp_capacity_terminal", "error": map[string]any{"code": "server_is_overloaded", "message": "Server is overloaded"}}},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RequestScopedTransient)
	require.True(t, failoverErr.ClientResponseWritten)
	require.Equal(t, NextAccountStop, failoverErr.NextAccountAction)
	require.Contains(t, recorder.Body.String(), `"code":"server_error"`)
	require.NotContains(t, recorder.Body.String(), "server_is_overloaded")
}

func TestForwardOpenAIWSV2CapacityFailedBeforeOutputRetriesSameConnection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_pre_output"}},
		{"type": "response.failed", "response": map[string]any{"id": "resp_capacity_pre_output", "error": map[string]any{"code": "server_is_overloaded", "message": "Server is overloaded"}}},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RequestScopedTransient)
	require.True(t, failoverErr.RetryableOnSameAccount)
	require.False(t, failoverErr.ClientResponseWritten)
	require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
	require.Empty(t, recorder.Body.String())
	require.NotEmpty(t, getOpenAIWSRequestRetryConn(c, account.ID))
}

func TestForwardOpenAIWSV2CapacityRetryActuallyReusesSameSocket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var handshakes atomic.Int32
	var requests atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handshakes.Add(1)
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for turn := 1; turn <= 2; turn++ {
			var request map[string]any
			if err := conn.ReadJSON(&request); err != nil {
				return
			}
			requests.Add(1)
			responseID := fmt.Sprintf("resp_same_socket_%d", turn)
			if err := conn.WriteJSON(map[string]any{"type": "response.created", "response": map[string]any{"id": responseID}}); err != nil {
				return
			}
			if err := conn.WriteJSON(map[string]any{
				"type": "response.failed",
				"response": map[string]any{
					"id":    responseID,
					"error": map[string]any{"code": "server_is_overloaded", "message": "Server is overloaded"},
				},
			}); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Security.URLAllowlist.Enabled = false
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.APIKeyEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 1
	cfg.Gateway.OpenAIWS.QueueLimitPerConn = 4
	cfg.Gateway.OpenAIWS.DialTimeoutSeconds = 2
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 2
	cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 2
	svc := &OpenAIGatewayService{cfg: cfg, toolCorrector: NewCodexToolCorrector()}
	defer func() {
		if svc.openaiWSPool != nil {
			svc.openaiWSPool.Close()
		}
	}()
	account := &Account{
		ID: 9002, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
		Status: StatusActive, Schedulable: true, Concurrency: 1,
		Credentials: map[string]any{"api_key": "sk-test", "base_url": server.URL},
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)

	for attempt := 1; attempt <= 2; attempt++ {
		result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
		require.Nil(t, result)
		var failoverErr *UpstreamFailoverError
		require.ErrorAs(t, err, &failoverErr)
		require.True(t, failoverErr.RetryableOnSameAccount)
	}
	require.Equal(t, int32(1), handshakes.Load())
	require.Equal(t, int32(2), requests.Load())
}

func TestForwardOpenAIWSV2CapacityFailedWithEmbeddedOutputDoesNotReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_failed_output"}},
		{
			"type": "response.failed",
			"response": map[string]any{
				"id": "resp_capacity_failed_output",
				"error": map[string]any{
					"code":    "server_is_overloaded",
					"message": "Server is overloaded",
				},
				"output": []any{
					map[string]any{"type": "function_call", "name": "side_effect", "arguments": `{"run":true}`},
				},
			},
		},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, true)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RequestScopedTransient)
	require.True(t, failoverErr.ClientResponseWritten)
	require.Equal(t, NextAccountStop, failoverErr.NextAccountAction)
	require.Contains(t, recorder.Body.String(), "side_effect")
	require.Contains(t, recorder.Body.String(), `"code":"server_error"`)
	require.NotContains(t, recorder.Body.String(), "server_is_overloaded")
}

func TestForwardOpenAIWSV2CapacityBeforeNonStreamCommitRemainsRetryable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	events := []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": "resp_capacity_3"}},
		{"type": "response.function_call_arguments.delta", "delta": "{\"x\":"},
		{"type": "response.failed", "response": map[string]any{"id": "resp_capacity_3", "error": map[string]any{"message": "Server is overloaded. Please try again later."}}},
	}
	svc, account, c, recorder, cleanup := newOpenAIWSCapacityTestService(t, events)
	defer cleanup()

	result, err := runOpenAIWSCapacityTestForward(t, svc, account, c, false)
	require.Nil(t, result)
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RequestScopedTransient)
	require.True(t, failoverErr.RetryableOnSameAccount)
	require.False(t, failoverErr.ClientResponseWritten)
	require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
	require.Empty(t, recorder.Body.String())
}
