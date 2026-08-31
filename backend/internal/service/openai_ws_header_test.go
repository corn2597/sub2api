package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeOpenAIWSTurnMetadataHeaderOmitsUnicodeRejectedByUpstream(t *testing.T) {
	raw := `{"workspace_kind":"project","workspaces":{"/Users/demo/语音记账":"changed"},"label":"😀"}`
	got := normalizeOpenAIWSTurnMetadataHeader(raw)

	require.Empty(t, got)
}

func TestNormalizeOpenAIWSTurnMetadataHeaderPreservesSafeOpaqueValue(t *testing.T) {
	require.Equal(t, "turn_meta_1", normalizeOpenAIWSTurnMetadataHeader("turn_meta_1"))
}

func TestNormalizeOpenAIWSTurnMetadataHeaderOmitsUnsafeInvalidValue(t *testing.T) {
	require.Empty(t, normalizeOpenAIWSTurnMetadataHeader("turn-元数据"))
	require.Empty(t, normalizeOpenAIWSTurnMetadataHeader("{\"turn_id\":\"turn\r\nmeta\"}"))
}

func TestSetOpenAIWSTurnMetadataOmitsUnicodeRejectedByUpstream(t *testing.T) {
	payload := map[string]any{"client_metadata": map[string]any{}}
	raw := `{"workspace_kind":"project","workspaces":{"/tmp/验收😀":{"has_changes":true}}}`
	setOpenAIWSTurnMetadata(payload, raw)

	metadata, ok := payload["client_metadata"].(map[string]any)
	require.True(t, ok)
	_, ok = metadata[openAIWSTurnMetadataHeader]
	require.False(t, ok)
}
