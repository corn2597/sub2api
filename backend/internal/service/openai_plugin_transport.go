package service

import (
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

// openCodeSidecarOwnsOpenAIHTTP reports whether the configured OpenCode
// sidecar is the authoritative final egress for OpenAI HTTP requests. The
// generic OAuth transport plugin must not short-circuit this path: doing so
// would make the same account use two different outbound identities.
func openCodeSidecarOwnsOpenAIHTTP(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	settings := cfg.OpenAIEgressSnapshot()
	return settings.Enabled && settings.HTTPEnabled
}

func openCodeSidecarOwnsOpenAIWS(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	settings := cfg.OpenAIEgressSnapshot()
	return settings.Enabled && settings.WSEnabled
}

func (s *OpenAIGatewayService) SetPluginManager(manager *PluginManager) {
	s.pluginManager = manager
}

// doOpenAIUpstream 只在 OpenAI OAuth 能力绑定已启用时把真实请求交给插件。
// 插件返回标准 http.Response，响应解析、错误映射、SSE 和计费仍由现有核心链处理。
func (s *OpenAIGatewayService) doOpenAIUpstream(request *http.Request, proxyURL string, account *Account) (*http.Response, error) {
	if s.pluginManager != nil && !openCodeSidecarOwnsOpenAIHTTP(s.cfg) {
		response, handled, err := s.pluginManager.RoundTripOpenAIOAuth(request.Context(), request, proxyURL, account)
		if handled {
			return response, err
		}
	}
	return s.httpUpstream.Do(request, proxyURL, account.ID, account.Concurrency)
}

// doOpenAIAccountTestUpstream 让 OpenAI OAuth 账号测试与真实转发使用同一插件路径。
// API Key 和未命中插件的账号保持各自原有的 HTTPUpstream 行为。
func (s *AccountTestService) doOpenAIAccountTestUpstream(
	request *http.Request,
	proxyURL string,
	account *Account,
	useTLSFallback bool,
) (*http.Response, error) {
	if s.pluginManager != nil && !openCodeSidecarOwnsOpenAIHTTP(s.cfg) {
		response, handled, err := s.pluginManager.RoundTripOpenAIOAuth(request.Context(), request, proxyURL, account)
		if handled {
			return response, err
		}
	}
	if useTLSFallback {
		return s.httpUpstream.DoWithTLS(
			request,
			proxyURL,
			account.ID,
			account.Concurrency,
			s.tlsFPProfileService.ResolveTLSProfile(account),
		)
	}
	return s.httpUpstream.Do(request, proxyURL, account.ID, account.Concurrency)
}
