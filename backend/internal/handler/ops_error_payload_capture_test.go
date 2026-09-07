package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type captureOpsRepository struct {
	service.OpsRepository
	mu       sync.Mutex
	requests []string
	captures []*service.OpsErrorPayloadCaptureSnapshot
}

func (r *captureOpsRepository) InsertErrorPayloadCapture(_ context.Context, requestID string, capture *service.OpsErrorPayloadCaptureSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, requestID)
	r.captures = append(r.captures, capture)
	return nil
}

func (r *captureOpsRepository) InsertErrorLog(context.Context, *service.OpsInsertErrorLogInput) (int64, error) {
	return 1, nil
}

func (r *captureOpsRepository) BatchInsertErrorLogs(_ context.Context, entries []*service.OpsInsertErrorLogInput) (int64, error) {
	return int64(len(entries)), nil
}

func TestOpsErrorLoggerPersistsPayloadOnlyAfterFinalHTTP2WSError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &captureOpsRepository{}
	cfg := &config.Config{}
	// The explicit payload-capture switch is independent from the ordinary ops
	// monitoring switch so emergency diagnostics cannot be silently short-circuited.
	cfg.Ops.Enabled = false
	cfg.Gateway.OpenAIWS.ErrorPayloadCaptureEnabled = true
	ops := service.NewOpsService(repo, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	router.Use(OpsErrorLoggerMiddleware(ops))
	router.POST("/:outcome", func(c *gin.Context) {
		requestID := "rid-" + c.Param("outcome")
		c.Header("X-Request-Id", requestID)
		httpPayload := []byte(`{"model":"gpt-5.6-sol","input":"original"}`)
		wsPayload := []byte(`{"type":"response.create","model":"gpt-5.6-sol","input":"normalized"}`)
		service.SetOpsHTTPErrorPayloadCandidate(c, httpPayload)
		service.MarkOpsErrorPayloadCaptureEnabled(c)
		sequence := service.BeginOpsErrorWSPayloadAttempt(c, wsPayload, 1, 23, "oa_ws_capture", true)
		service.FinishOpsErrorWSPayloadAttempt(c, sequence, nil)
		if c.Param("outcome") == "failed" {
			c.JSON(http.StatusBadGateway, gin.H{"error": gin.H{"type": "upstream_error", "message": strings.Repeat("Invalid request ", 1000)}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "completed"})
	})

	failed := httptest.NewRecorder()
	router.ServeHTTP(failed, httptest.NewRequest(http.MethodPost, "/failed", nil))
	require.Equal(t, http.StatusBadGateway, failed.Code)
	require.Len(t, repo.captures, 1)
	require.Equal(t, "rid-failed", repo.requests[0])
	require.Equal(t, []byte(`{"model":"gpt-5.6-sol","input":"original"}`), repo.captures[0].HTTPPayload)
	require.Len(t, repo.captures[0].WSPayloads, 1)
	require.Len(t, repo.captures[0].WSAttempts, 1)
	require.True(t, repo.captures[0].WSAttempts[0].WriteSucceeded)

	succeeded := httptest.NewRecorder()
	router.ServeHTTP(succeeded, httptest.NewRequest(http.MethodPost, "/succeeded", nil))
	require.Equal(t, http.StatusOK, succeeded.Code)
	require.Len(t, repo.captures, 1, "successful HTTP2WS requests must not persist payloads")
}
