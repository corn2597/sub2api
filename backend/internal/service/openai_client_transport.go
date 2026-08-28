package service

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// OpenAIClientTransport 表示客户端入站协议类型。
type OpenAIClientTransport string

const (
	OpenAIClientTransportUnknown OpenAIClientTransport = ""
	OpenAIClientTransportHTTP    OpenAIClientTransport = "http"
	OpenAIClientTransportWS      OpenAIClientTransport = "ws"
)

const openAIClientTransportContextKey = "openai_client_transport"

// SetOpenAIClientTransport 标记当前请求的客户端入站协议。
func SetOpenAIClientTransport(c *gin.Context, transport OpenAIClientTransport) {
	if c == nil {
		return
	}
	normalized := normalizeOpenAIClientTransport(transport)
	if normalized == OpenAIClientTransportUnknown {
		return
	}
	c.Set(openAIClientTransportContextKey, string(normalized))
}

// GetOpenAIClientTransport 读取当前请求的客户端入站协议。
func GetOpenAIClientTransport(c *gin.Context) OpenAIClientTransport {
	if c == nil {
		return OpenAIClientTransportUnknown
	}
	raw, ok := c.Get(openAIClientTransportContextKey)
	if !ok || raw == nil {
		return OpenAIClientTransportUnknown
	}

	switch v := raw.(type) {
	case OpenAIClientTransport:
		return normalizeOpenAIClientTransport(v)
	case string:
		return normalizeOpenAIClientTransport(OpenAIClientTransport(v))
	default:
		return OpenAIClientTransportUnknown
	}
}

func normalizeOpenAIClientTransport(transport OpenAIClientTransport) OpenAIClientTransport {
	switch strings.ToLower(strings.TrimSpace(string(transport))) {
	case string(OpenAIClientTransportHTTP), "http_sse", "sse":
		return OpenAIClientTransportHTTP
	case string(OpenAIClientTransportWS), "websocket":
		return OpenAIClientTransportWS
	default:
		return OpenAIClientTransportUnknown
	}
}

func resolveOpenAIWSDecisionByClientTransport(
	decision OpenAIWSProtocolDecision,
	clientTransport OpenAIClientTransport,
) OpenAIWSProtocolDecision {
	if clientTransport == OpenAIClientTransportHTTP {
		return openAIWSHTTPDecision("client_protocol_http")
	}
	return decision
}

func (s *OpenAIGatewayService) resolveOpenAIWSDecisionForRequest(
	c *gin.Context,
	account *Account,
	body []byte,
	decision OpenAIWSProtocolDecision,
) OpenAIWSProtocolDecision {
	if GetOpenAIClientTransport(c) != OpenAIClientTransportHTTP {
		return decision
	}
	deny := func(reason string) OpenAIWSProtocolDecision {
		return openAIWSHTTPDecision(reason)
	}
	if decision.Transport != OpenAIUpstreamTransportResponsesWebsocketV2 {
		if decision.Transport == OpenAIUpstreamTransportHTTPSSE {
			return decision
		}
		return deny("http_to_ws_ws_v2_required")
	}
	if s == nil || s.cfg == nil || !s.cfg.Gateway.OpenAIWS.HTTPToWSEnabled {
		return deny("http_to_ws_global_disabled")
	}
	if account == nil || !account.IsOpenAIOAuth() {
		return deny("http_to_ws_oauth_required")
	}
	if !account.IsOpenAIOAuthHTTPToWSEnabled() {
		return deny("http_to_ws_account_disabled")
	}
	if c == nil || c.Request == nil || c.Request.Method != http.MethodPost || isOpenAIResponsesCompactPath(c) {
		return deny("http_to_ws_endpoint_ineligible")
	}
	store := gjson.GetBytes(body, "store")
	if !store.Exists() || store.Type != gjson.False {
		return deny("http_to_ws_store_false_required")
	}
	if gjson.GetBytes(body, "previous_response_id").Exists() {
		return deny("http_to_ws_previous_response_id")
	}
	if gjson.GetBytes(body, "conversation").Exists() {
		return deny("http_to_ws_conversation")
	}
	background := gjson.GetBytes(body, "background")
	if background.Exists() && (background.Type != gjson.False || background.Bool()) {
		return deny("http_to_ws_background")
	}
	requestedModel := strings.TrimSpace(gjson.GetBytes(body, "model").String())
	if IsExplicitImageGenerationIntent(openAIResponsesEndpoint, requestedModel, body) {
		return deny("http_to_ws_image_ineligible")
	}
	decision.Reason = "http_to_ws_enabled"
	return decision
}
