package service

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func newOpenAIAuditSessionHashContext(t *testing.T) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/openai/v1/responses", nil)
	return c
}

func TestGenerateOpenAIAuditSessionHash_UsesPromptCacheKey(t *testing.T) {
	c := newOpenAIAuditSessionHashContext(t)

	got := GenerateOpenAIAuditSessionHash(c, []byte(`{"model":"gpt-5.5","prompt_cache_key":"compact-seed-1","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`), nil)

	require.Equal(t, DeriveSessionHashFromSeed("compact-seed-1"), got)
}

func TestResolveOpenAIAuditSession_ReportsExplicitSignal(t *testing.T) {
	c := newOpenAIAuditSessionHashContext(t)

	got := ResolveOpenAIAuditSession(c, []byte(`{"model":"gpt-5.5","prompt_cache_key":"compact-seed-1"}`), "", nil)

	require.True(t, got.Explicit)
	require.Equal(t, DeriveSessionHashFromSeed("compact-seed-1"), got.Hash)
}

func TestResolveOpenAIAuditSession_ContentFallbackIsNotExplicit(t *testing.T) {
	c := newOpenAIAuditSessionHashContext(t)

	got := ResolveOpenAIAuditSession(c, []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}]}`), "", &SessionContext{
		ClientIP:  "1.2.3.4",
		UserAgent: "Codex/1.0",
		APIKeyID:  101,
		UserID:    1001,
	})

	require.False(t, got.Explicit)
	require.NotEmpty(t, got.Hash)
}

func TestResolveOpenAIAuditSession_DoesNotOverwriteLegacyStickyContext(t *testing.T) {
	c := newOpenAIAuditSessionHashContext(t)
	svc := &OpenAIGatewayService{}

	routingHash := svc.GenerateSessionHashWithFallback(c, []byte(`{}`), "routing-fallback-seed")
	require.NotEmpty(t, routingHash)

	legacyBefore := openAILegacySessionHashFromContext(c.Request.Context())
	require.NotEmpty(t, legacyBefore)

	got := ResolveOpenAIAuditSession(c, []byte(`{"prompt_cache_key":"audit-session-seed"}`), routingHash, nil)

	require.True(t, got.Explicit)
	require.Equal(t, DeriveSessionHashFromSeed("audit-session-seed"), got.Hash)
	require.Equal(t, legacyBefore, openAILegacySessionHashFromContext(c.Request.Context()))
}

func TestGenerateOpenAIAuditSessionHash_SameUserDifferentAPIKeysSameHash(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"same opening prompt"}]}`)
	ctx1 := &SessionContext{ClientIP: "1.2.3.4", UserAgent: "Codex/1.2.3", APIKeyID: 101, UserID: 9001}
	ctx2 := &SessionContext{ClientIP: "1.2.3.4", UserAgent: "Codex/1.2.3", APIKeyID: 202, UserID: 9001}

	require.Equal(t, openAIAuditSessionContextDiscriminator(ctx1), openAIAuditSessionContextDiscriminator(ctx2))

	c1 := newOpenAIAuditSessionHashContext(t)
	c2 := newOpenAIAuditSessionHashContext(t)

	hash1 := GenerateOpenAIAuditSessionHash(c1, body, ctx1)
	hash2 := GenerateOpenAIAuditSessionHash(c2, body, ctx2)

	require.NotEmpty(t, hash1)
	require.Equal(t, hash1, hash2)
}

func TestGenerateOpenAIAuditSessionHash_DifferentUsersDifferentHash(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"same opening prompt"}]}`)
	ctx1 := &SessionContext{ClientIP: "1.2.3.4", UserAgent: "Codex/1.2.3", APIKeyID: 101, UserID: 9001}
	ctx2 := &SessionContext{ClientIP: "1.2.3.4", UserAgent: "Codex/1.2.3", APIKeyID: 101, UserID: 9002}

	require.NotEqual(t, openAIAuditSessionContextDiscriminator(ctx1), openAIAuditSessionContextDiscriminator(ctx2))

	c1 := newOpenAIAuditSessionHashContext(t)
	c2 := newOpenAIAuditSessionHashContext(t)

	hash1 := GenerateOpenAIAuditSessionHash(c1, body, ctx1)
	hash2 := GenerateOpenAIAuditSessionHash(c2, body, ctx2)

	require.NotEmpty(t, hash1)
	require.NotEmpty(t, hash2)
	require.NotEqual(t, hash1, hash2)
}
