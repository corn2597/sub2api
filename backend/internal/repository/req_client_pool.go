package repository

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/opencodeegress"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyurl"
	"github.com/Wei-Shaw/sub2api/internal/pkg/servertiming"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/imroc/req/v3"
)

// reqClientOptions 定义 req 客户端的构建参数
type reqClientOptions struct {
	ProxyURL     string        // 代理 URL（支持 http/https/socks5）
	Timeout      time.Duration // 请求超时时间
	Impersonate  bool          // 是否模拟 Chrome 浏览器指纹
	ForceHTTP2   bool          // 是否强制使用 HTTP/2
	OpenAIEgress *config.OpenAIEgressConfig
}

// sharedReqClients 存储按配置参数缓存的 req 客户端实例
//
// 性能优化说明：
// 原实现在每次 OAuth 刷新时都创建新的 req.Client：
// 1. claude_oauth_service.go: 每次刷新创建新客户端
// 2. openai_oauth_service.go: 每次刷新创建新客户端
// 3. gemini_oauth_client.go: 每次刷新创建新客户端
//
// 新实现使用 sync.Map 缓存客户端：
// 1. 相同配置（代理+超时+模拟设置）复用同一客户端
// 2. 复用底层连接池，减少 TLS 握手开销
// 3. LoadOrStore 保证并发安全，避免重复创建
var sharedReqClients sync.Map

// getSharedReqClient 获取共享的 req 客户端实例
// 性能优化：相同配置复用同一客户端，避免重复创建
func getSharedReqClient(opts reqClientOptions) (*req.Client, error) {
	key := buildReqClientKey(opts)
	if cached, ok := sharedReqClients.Load(key); ok {
		if c, ok := cached.(*req.Client); ok {
			return c, nil
		}
	}

	client := req.C().SetTimeout(opts.Timeout)
	if opts.ForceHTTP2 {
		client = client.EnableForceHTTP2()
	}
	if opts.Impersonate {
		client = client.ImpersonateChrome()
	}
	trimmed, _, err := proxyurl.Parse(opts.ProxyURL)
	if err != nil {
		return nil, err
	}
	if trimmed != "" {
		client.SetProxyURL(trimmed)
	}
	if opts.OpenAIEgress != nil && opts.OpenAIEgress.Enabled && opts.OpenAIEgress.HTTPEnabled {
		egress := opencodeegress.NewFromConfig(opts.OpenAIEgress)
		client.GetTransport().WrapRoundTripFunc(func(rt http.RoundTripper) req.HttpRoundTripFunc {
			return openAIEgressRoundTrip(rt, egress, opts.OpenAIEgress, trimmed)
		})
	}
	client = instrumentReqClient(client)

	actual, _ := sharedReqClients.LoadOrStore(key, client)
	if c, ok := actual.(*req.Client); ok {
		return c, nil
	}
	return client, nil
}

func instrumentReqClient(client *req.Client) *req.Client {
	if client == nil {
		return nil
	}
	client.GetTransport().WrapRoundTripFunc(func(rt http.RoundTripper) req.HttpRoundTripFunc {
		timed := servertiming.WrapRoundTripper(rt)
		return timed.RoundTrip
	})
	return client
}

func buildReqClientKey(opts reqClientOptions) string {
	egressKey := ""
	if opts.OpenAIEgress != nil {
		egressKey = fmt.Sprintf("|egress=%t:%s:%t:%t:%t",
			opts.OpenAIEgress.Enabled,
			strings.TrimSpace(opts.OpenAIEgress.BaseURL),
			opts.OpenAIEgress.HTTPEnabled,
			opts.OpenAIEgress.FallbackToDirect,
			opts.OpenAIEgress.AllowProxy,
		)
	}
	return fmt.Sprintf("%s|%s|%t|%t%s",
		strings.TrimSpace(opts.ProxyURL),
		opts.Timeout.String(),
		opts.Impersonate,
		opts.ForceHTTP2,
		egressKey,
	)
}

// CreatePrivacyReqClient creates an HTTP client for OpenAI privacy settings API
// This is exported for use by OpenAIPrivacyService
// Uses Chrome TLS fingerprint impersonation to bypass Cloudflare checks
func CreatePrivacyReqClient(proxyURL string) (*req.Client, error) {
	return getSharedReqClient(reqClientOptions{
		ProxyURL:    proxyURL,
		Timeout:     30 * time.Second,
		Impersonate: true, // Enable Chrome TLS fingerprint impersonation
	})
}

func CreatePrivacyReqClientWithEgress(proxyURL string, settings *config.OpenAIEgressConfig) (*req.Client, error) {
	return getSharedReqClient(reqClientOptions{
		ProxyURL: proxyURL, Timeout: 30 * time.Second, Impersonate: true, OpenAIEgress: settings,
	})
}

func ProvidePrivacyClientFactory(cfg *config.Config) service.PrivacyClientFactory {
	return func(proxyURL string) (*req.Client, error) {
		if cfg == nil {
			return CreatePrivacyReqClient(proxyURL)
		}
		settings := cfg.OpenAIEgressSnapshot()
		return CreatePrivacyReqClientWithEgress(proxyURL, &settings)
	}
}

func openAIEgressRoundTrip(rt http.RoundTripper, egress *opencodeegress.Client, settings *config.OpenAIEgressConfig, proxyURL string) req.HttpRoundTripFunc {
	return func(request *http.Request) (*http.Response, error) {
		if request == nil || request.URL == nil || !isOpenAIHost(request.URL.Hostname()) {
			return rt.RoundTrip(request)
		}
		if strings.TrimSpace(proxyURL) != "" && settings != nil && !settings.AllowProxy {
			if settings.FallbackToDirect {
				return rt.RoundTrip(request)
			}
			return nil, fmt.Errorf("openai egress proxy forwarding is disabled; refusing direct bypass")
		}
		response, err := egress.ProxyHTTP(
			request.Context(), request.URL.String(), request.Method, request.Header,
			request.Body, request.ContentLength, proxyURL, "management",
		)
		if err == nil {
			response.Request = request
			return response, nil
		}
		if settings == nil || !settings.FallbackToDirect {
			return nil, fmt.Errorf("openai management egress sidecar request failed: %w", err)
		}
		if request.GetBody == nil {
			return nil, fmt.Errorf("openai management egress failed and request is not replayable: %w", err)
		}
		replayed, replayErr := request.GetBody()
		if replayErr != nil {
			return nil, fmt.Errorf("openai management egress replay failed: %w", replayErr)
		}
		clone := request.Clone(request.Context())
		clone.Body = replayed
		clone.GetBody = request.GetBody
		return rt.RoundTrip(clone)
	}
}

func isOpenAIHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "api.openai.com" || host == "chatgpt.com" ||
		strings.HasSuffix(host, ".openai.com") || strings.HasSuffix(host, ".chatgpt.com")
}
