package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestGatewayHandlerMessages_SessionAuditBlocksBeforeScheduling(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var auditCalls atomic.Int32
	auditServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditCalls.Add(1)
		require.Equal(t, "/v1/responses", r.URL.Path)
		require.Equal(t, "Bearer sk-audit", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "resp_block",
			"output_text": `{"violates":true,"confidence":0.95,"categories":["aup_fraud"],"reason":"violation","evidence_excerpt":"bad","recommended_action":"block"}`,
		})
	}))
	defer auditServer.Close()

	cfg := service.ContentModerationConfig{
		Enabled:   true,
		Mode:      service.ContentModerationModePreBlock,
		AllGroups: true,
	}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)

	settingRepo := &contentModerationHandlerSettingRepo{values: map[string]string{
		service.SettingKeyRiskControlEnabled:            "true",
		service.SettingKeyContentModerationConfig:       string(rawCfg),
		service.SettingKeyRiskControlProvider:           service.RiskControlProviderOpenAIResponsesSessionAudit,
		service.SettingKeyAuditBaseURL:                  auditServer.URL + "/v1/",
		service.SettingKeyAuditPath:                     "/v1/responses",
		service.SettingKeyAuditModel:                    "gpt-5-mini",
		service.SettingKeyAuditAPIKeys:                  `["sk-audit"]`,
		service.SettingKeyAuditBlockConfidenceThreshold: "0.7",
	}}
	moderationSvc := service.NewContentModerationService(
		settingRepo,
		&contentModerationHandlerTestRepo{},
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	h := &GatewayHandler{
		gatewayService:           &service.GatewayService{},
		contentModerationService: moderationSvc,
	}

	body := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"bad request"}]}`)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
	c.Request.Header.Set("session_id", "sess-handler-block")
	c.Set(string(middleware.ContextKeyAPIKey), &service.APIKey{
		ID:      44,
		GroupID: int64PtrForGatewaySessionAuditTest(55),
		Group:   &service.Group{ID: 55, Platform: service.PlatformAnthropic, Status: service.StatusActive},
	})
	c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 33, Concurrency: 1})

	h.Messages(c)

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, int32(1), auditCalls.Load())
	require.Equal(t, "content_policy_violation", jsonPathString(t, w.Body.Bytes(), "error.type"))
	require.Equal(t, "Request blocked by risk control policy.", jsonPathString(t, w.Body.Bytes(), "error.message"))
}

func int64PtrForGatewaySessionAuditTest(v int64) *int64 {
	return &v
}

func jsonPathString(t *testing.T, body []byte, path string) string {
	t.Helper()
	require.True(t, gjson.ValidBytes(body), "response body must be valid json: %s", string(body))
	return gjson.GetBytes(body, path).String()
}
