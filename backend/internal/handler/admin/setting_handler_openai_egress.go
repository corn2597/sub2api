package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// GetOpenAIEgressSettings returns effective sidecar settings without secrets.
func (h *SettingHandler) GetOpenAIEgressSettings(c *gin.Context) {
	settings, err := h.settingService.GetOpenAIEgressSettings(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, settings)
}

// UpdateOpenAIEgressSettings updates only persisted runtime switches.
func (h *SettingHandler) UpdateOpenAIEgressSettings(c *gin.Context) {
	var req service.OpenAIEgressRuntimeSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	settings, err := h.settingService.UpdateOpenAIEgressSettings(c.Request.Context(), req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, settings)
}

// TestOpenAIEgress performs a bounded sidecar health check.
func (h *SettingHandler) TestOpenAIEgress(c *gin.Context) {
	settings, err := h.settingService.TestOpenAIEgress(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, settings)
}
