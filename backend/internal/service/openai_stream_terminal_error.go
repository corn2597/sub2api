package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type openAIResponsesFailedError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type openAIResponsesFailedBody struct {
	ID     string                     `json:"id"`
	Object string                     `json:"object"`
	Model  string                     `json:"model,omitempty"`
	Status string                     `json:"status"`
	Output []any                      `json:"output"`
	Error  openAIResponsesFailedError `json:"error"`
}

type openAIResponsesFailedEvent struct {
	Type     string                    `json:"type"`
	Response openAIResponsesFailedBody `json:"response"`
}

// writeOpenAIResponsesFailedTerminalSSE emits a protocol-compliant Responses
// terminal error event after the stream has already started. This avoids
// leaving strict clients with a non-terminal generic SSE frame.
func writeOpenAIResponsesFailedTerminalSSE(c *gin.Context, flusher http.Flusher, model, code, message string) error {
	if c == nil || c.Writer == nil || flusher == nil {
		return fmt.Errorf("responses terminal SSE writer unavailable")
	}

	code = strings.TrimSpace(code)
	if code == "" {
		code = "server_error"
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = "Upstream request failed"
	}

	payload, err := json.Marshal(openAIResponsesFailedEvent{
		Type: "response.failed",
		Response: openAIResponsesFailedBody{
			ID:     synthesizeOpenAIResponsesErrorID(c),
			Object: "response",
			Model:  strings.TrimSpace(model),
			Status: "failed",
			Output: []any{},
			Error: openAIResponsesFailedError{
				Code:    code,
				Message: message,
			},
		},
	})
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(c.Writer, "event: response.failed\ndata: %s\n\n", payload); err != nil {
		return err
	}
	flusher.Flush()
	MarkResponseCommitted(c)
	return nil
}

func synthesizeOpenAIResponsesErrorID(c *gin.Context) string {
	if c != nil && c.Request != nil {
		if rid, ok := c.Request.Context().Value(ctxkey.RequestID).(string); ok {
			if rid = strings.TrimSpace(rid); rid != "" {
				return "resp_" + strings.ReplaceAll(rid, "-", "")
			}
		}
	}
	return "resp_" + strings.ReplaceAll(uuid.NewString(), "-", "")
}
