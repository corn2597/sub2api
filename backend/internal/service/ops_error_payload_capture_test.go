package service

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestOpsErrorPayloadCapturePreservesExactHTTPAndDeduplicatesWSAttempts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)

	httpPayload := bytes.Repeat([]byte(`{"input":"original"}`), 160000)
	wantHTTP := bytes.Clone(httpPayload)
	SetOpsHTTPErrorPayloadCandidate(c, httpPayload)
	// Prove the capture owns an immutable original rather than the caller's
	// potentially reused backing array.
	httpPayload[0] = '!'

	MarkOpsErrorPayloadCaptureEnabled(c)
	wsPayload := bytes.Repeat([]byte(`{"type":"response.create"}`), 100000)
	wantWS := bytes.Clone(wsPayload)
	first := BeginOpsErrorWSPayloadAttempt(c, wsPayload, 1, 23, " oa_ws_1 ", false)
	FinishOpsErrorWSPayloadAttempt(c, first, nil)
	second := BeginOpsErrorWSPayloadAttempt(c, wsPayload, 2, 23, "oa_ws_1", true)
	writeErr := errors.New(strings.Repeat("write failed ", 20000))
	FinishOpsErrorWSPayloadAttempt(c, second, writeErr)
	wsPayload[0] = '!'

	snapshot := TakeOpsErrorPayloadCapture(c)
	require.NotNil(t, snapshot)
	require.Equal(t, wantHTTP, snapshot.HTTPPayload)
	require.Equal(t, opsPayloadSHA256(wantHTTP), snapshot.HTTPSHA256)
	require.Len(t, snapshot.WSPayloads, 1, "identical WS request bytes must be stored once")
	require.Equal(t, wantWS, snapshot.WSPayloads[opsPayloadSHA256(wantWS)])
	require.Len(t, snapshot.WSAttempts, 2, "deduplication must not discard retry attempts")
	require.True(t, snapshot.WSAttempts[0].WriteSucceeded)
	require.False(t, snapshot.WSAttempts[1].WriteSucceeded)
	require.Equal(t, writeErr.Error(), snapshot.WSAttempts[1].WriteError, "write errors must not be truncated")
	require.True(t, snapshot.WSAttempts[1].ConnectionReused)
	require.Equal(t, "oa_ws_1", snapshot.WSAttempts[0].ConnID)
	require.Nil(t, TakeOpsErrorPayloadCapture(c), "payload capture must be persisted at most once")
}

func TestOpsErrorPayloadCaptureRequiresHTTP2WSSelection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	SetOpsHTTPErrorPayloadCandidate(c, []byte(`{"model":"gpt-5.6"}`))
	require.Zero(t, BeginOpsErrorWSPayloadAttempt(c, []byte(`{"type":"response.create"}`), 1, 1, "conn", false))
	require.Nil(t, TakeOpsErrorPayloadCapture(c))
}
