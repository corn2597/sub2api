package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const opsErrorPayloadCaptureKey = "ops_error_payload_capture"

// OpsErrorPayloadCapture holds exact request bytes in memory for the duration
// of one HTTP2WS request. It is persisted only if the request ultimately fails.
type OpsErrorPayloadCapture struct {
	mu sync.Mutex

	enabled     bool
	httpPayload []byte
	httpSHA256  string
	createdAt   time.Time
	wsPayloads  map[string][]byte
	wsAttempts  []*OpsErrorWSPayloadAttempt
	taken       bool
}

type OpsErrorWSPayloadAttempt struct {
	SequenceNo       int       `json:"sequence_no"`
	PayloadSHA256    string    `json:"payload_sha256"`
	AttemptNo        int       `json:"attempt_no"`
	AccountID        int64     `json:"account_id"`
	ConnID           string    `json:"conn_id"`
	ConnectionReused bool      `json:"connection_reused"`
	WriteSucceeded   bool      `json:"write_succeeded"`
	WriteError       string    `json:"write_error,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type OpsErrorPayloadCaptureSnapshot struct {
	HTTPPayload []byte
	HTTPSHA256  string
	CreatedAt   time.Time
	WSPayloads  map[string][]byte
	WSAttempts  []*OpsErrorWSPayloadAttempt
}

func opsPayloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// SetOpsHTTPErrorPayloadCandidate copies the ingress bytes before any request
// normalization. The copy is deliberate: downstream normalizers may reuse a
// backing array, while diagnostics must reproduce the exact client payload.
func SetOpsHTTPErrorPayloadCandidate(c *gin.Context, payload []byte) {
	if c == nil || len(payload) == 0 {
		return
	}
	original := bytes.Clone(payload)
	c.Set(opsErrorPayloadCaptureKey, &OpsErrorPayloadCapture{
		httpPayload: original,
		httpSHA256:  opsPayloadSHA256(original),
		createdAt:   time.Now().UTC(),
		wsPayloads:  make(map[string][]byte),
	})
}

// MarkOpsErrorPayloadCaptureEnabled marks that this request actually selected
// HTTP2WS. HTTP requests that remain on HTTP/SSE are never persisted.
func MarkOpsErrorPayloadCaptureEnabled(c *gin.Context) {
	capture := getOpsErrorPayloadCapture(c)
	if capture == nil {
		return
	}
	capture.mu.Lock()
	capture.enabled = true
	capture.mu.Unlock()
}

func BeginOpsErrorWSPayloadAttempt(
	c *gin.Context,
	payload []byte,
	attemptNo int,
	accountID int64,
	connID string,
	connectionReused bool,
) int {
	capture := getOpsErrorPayloadCapture(c)
	if capture == nil || len(payload) == 0 {
		return 0
	}
	sha := opsPayloadSHA256(payload)
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if !capture.enabled || capture.taken {
		return 0
	}
	if _, exists := capture.wsPayloads[sha]; !exists {
		capture.wsPayloads[sha] = bytes.Clone(payload)
	}
	sequence := len(capture.wsAttempts) + 1
	capture.wsAttempts = append(capture.wsAttempts, &OpsErrorWSPayloadAttempt{
		SequenceNo:       sequence,
		PayloadSHA256:    sha,
		AttemptNo:        attemptNo,
		AccountID:        accountID,
		ConnID:           strings.TrimSpace(connID),
		ConnectionReused: connectionReused,
		CreatedAt:        time.Now().UTC(),
	})
	return sequence
}

func FinishOpsErrorWSPayloadAttempt(c *gin.Context, sequence int, writeErr error) {
	if sequence <= 0 {
		return
	}
	capture := getOpsErrorPayloadCapture(c)
	if capture == nil {
		return
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if sequence > len(capture.wsAttempts) || capture.wsAttempts[sequence-1] == nil {
		return
	}
	attempt := capture.wsAttempts[sequence-1]
	attempt.WriteSucceeded = writeErr == nil
	if writeErr != nil {
		attempt.WriteError = writeErr.Error()
	}
}

// TakeOpsErrorPayloadCapture returns the exact bytes once. The returned slices
// are immutable and may be passed directly to the persistence layer.
func TakeOpsErrorPayloadCapture(c *gin.Context) *OpsErrorPayloadCaptureSnapshot {
	capture := getOpsErrorPayloadCapture(c)
	if capture == nil {
		return nil
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if !capture.enabled || capture.taken || len(capture.httpPayload) == 0 {
		return nil
	}
	capture.taken = true
	wsPayloads := make(map[string][]byte, len(capture.wsPayloads))
	for sha, payload := range capture.wsPayloads {
		wsPayloads[sha] = payload
	}
	wsAttempts := make([]*OpsErrorWSPayloadAttempt, 0, len(capture.wsAttempts))
	for _, attempt := range capture.wsAttempts {
		if attempt == nil {
			continue
		}
		copyAttempt := *attempt
		wsAttempts = append(wsAttempts, &copyAttempt)
	}
	return &OpsErrorPayloadCaptureSnapshot{
		HTTPPayload: capture.httpPayload,
		HTTPSHA256:  capture.httpSHA256,
		CreatedAt:   capture.createdAt,
		WSPayloads:  wsPayloads,
		WSAttempts:  wsAttempts,
	}
}

func getOpsErrorPayloadCapture(c *gin.Context) *OpsErrorPayloadCapture {
	if c == nil {
		return nil
	}
	value, ok := c.Get(opsErrorPayloadCaptureKey)
	if !ok {
		return nil
	}
	capture, _ := value.(*OpsErrorPayloadCapture)
	return capture
}
