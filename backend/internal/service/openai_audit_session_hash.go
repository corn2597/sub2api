package service

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type OpenAIAuditSession struct {
	Hash     string
	Explicit bool
}

// GenerateOpenAIAuditSessionHash builds a stable session hash for OpenAI-format
// moderation scopes.
//
// Priority:
//  1. Explicit client session signals: session_id / conversation_id / prompt_cache_key
//  2. Stable content seed: model + tools/functions + system/developer + first user input
//
// For content-derived fallback we mix in SessionContext so two different clients
// with identical prompts do not share the same moderation session.
func GenerateOpenAIAuditSessionHash(c *gin.Context, body []byte, sessionCtx *SessionContext) string {
	return ResolveOpenAIAuditSession(c, body, "", sessionCtx).Hash
}

func ResolveOpenAIAuditSession(c *gin.Context, body []byte, routingSessionHash string, sessionCtx *SessionContext) OpenAIAuditSession {
	sessionID := explicitOpenAISessionID(c, body)
	if sessionID != "" {
		currentHash, _ := deriveOpenAISessionHashes(sessionID)
		return OpenAIAuditSession{Hash: currentHash, Explicit: true}
	}
	seed := strings.TrimSpace(deriveOpenAIContentSessionSeed(body))
	if seed != "" {
		if discriminator := strings.TrimSpace(openAIAuditSessionContextDiscriminator(sessionCtx)); discriminator != "" {
			sessionID = discriminator + "|" + seed
		} else {
			sessionID = seed
		}
		currentHash, _ := deriveOpenAISessionHashes(sessionID)
		return OpenAIAuditSession{Hash: currentHash}
	}
	return OpenAIAuditSession{Hash: strings.TrimSpace(routingSessionHash)}
}

func openAIAuditSessionContextDiscriminator(sessionCtx *SessionContext) string {
	if sessionCtx == nil {
		return ""
	}
	ownerID := sessionCtx.APIKeyID
	if sessionCtx.UserID > 0 {
		ownerID = sessionCtx.UserID
	}
	return sessionCtx.ClientIP + ":" + NormalizeSessionUserAgent(sessionCtx.UserAgent) + ":" + strconv.FormatInt(ownerID, 10)
}
