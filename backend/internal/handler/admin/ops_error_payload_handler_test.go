package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type errorPayloadDownloadRepo struct {
	service.OpsRepository
	payload *service.OpsErrorPayloadContent
}

func (r *errorPayloadDownloadRepo) GetErrorPayloadContent(context.Context, int64, int64) (*service.OpsErrorPayloadContent, error) {
	return r.payload, nil
}

func TestDownloadErrorPayloadReturnsExactBytesAndNoStoreHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	payload := []byte("{\"type\":\"response.create\",\"input\":\"exact\\u0000bytes\"}")
	repo := &errorPayloadDownloadRepo{payload: &service.OpsErrorPayloadContent{
		ID:           12,
		Kind:         "ws",
		SHA256:       "b557dadfe2d9dc2a53b05c3b4a6c9ca8f118b000410b7d30a14c0f8c00f8902f",
		PayloadBytes: int64(len(payload)),
		Data:         payload,
	}}
	cfg := &config.Config{}
	cfg.Ops.Enabled = true
	ops := service.NewOpsService(repo, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil)
	handler := NewOpsHandler(ops)
	router := gin.New()
	router.GET("/admin/ops/errors/:id/payloads/:payload_id", handler.DownloadErrorPayload)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/admin/ops/errors/9/payloads/12", nil)
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, payload, recorder.Body.Bytes())
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.Equal(t, repo.payload.SHA256, recorder.Header().Get("X-Content-SHA256"))
	require.Equal(t, "application/json; charset=utf-8", recorder.Header().Get("Content-Type"))
	require.Contains(t, recorder.Header().Get("Content-Disposition"), "http2ws-error-9-ws-12.json")
}
