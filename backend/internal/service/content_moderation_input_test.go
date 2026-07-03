package service

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Anthropic/Gemini 仍保持“最后一个用户回合”语义；
// OpenAI Chat / Responses 改成聚合当前 payload 中全部 user 文本。

func TestExtractContentModerationInput_AnthropicAgentToolLoopSkipsAudit(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role":"user","content":"调用一下天气工具"},
			{"role":"assistant","content":[{"type":"tool_use","id":"tool_1","name":"weather","input":{}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_1","content":"晴 25 度"}]}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolAnthropicMessages, body)

	require.Empty(t, input.Text)
	require.Empty(t, input.Images)
}

func TestExtractContentModerationInput_AnthropicFirstTurnExtractsUser(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role":"user","content":"Q1"}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolAnthropicMessages, body)

	require.Equal(t, "Q1", input.Text)
}

func TestExtractContentModerationInput_AnthropicMultiTurnExtractsLatestUser(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role":"user","content":"Q1"},
			{"role":"assistant","content":"A1"},
			{"role":"user","content":"Q2"}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolAnthropicMessages, body)

	require.Equal(t, "Q2", input.Text)
}

func TestExtractContentModerationInput_AnthropicStreamResendExtractsResend(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role":"user","content":"原问题"},
			{"role":"assistant","content":"部分回答……"},
			{"role":"user","content":"重发"}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolAnthropicMessages, body)

	require.Equal(t, "重发", input.Text)
}

func TestExtractContentModerationInput_OpenAIChatAgentToolLoopKeepsAllUserMessages(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role":"system","content":"sys"},
			{"role":"user","content":"列出我的订单"},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"orders","arguments":"{}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"[]"}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIChat, body)

	require.Equal(t, "列出我的订单", input.Text)
	require.Empty(t, input.Images)
}

func TestExtractContentModerationInput_OpenAIChatMultiTurnExtractsAllUserMessages(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role":"user","content":"Q1"},
			{"role":"assistant","content":"A1"},
			{"role":"user","content":"Q2"}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIChat, body)

	require.Equal(t, "Q1 Q2", input.Text)
}

func TestExtractContentModerationInput_GeminiAgentToolLoopSkipsAudit(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role":"user","parts":[{"text":"查询天气"}]},
			{"role":"model","parts":[{"functionCall":{"name":"weather","args":{}}}]},
			{"role":"user","parts":[{"functionResponse":{"name":"weather","response":{"temp":25}}}]}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolGemini, body)

	require.Empty(t, input.Text)
	require.Empty(t, input.Images)
}

func TestExtractContentModerationInput_GeminiFirstTurnExtractsUser(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role":"user","parts":[{"text":"你好"}]}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolGemini, body)

	require.Equal(t, "你好", input.Text)
}

func TestExtractContentModerationInput_GeminiMultiTurnExtractsLatestUser(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role":"user","parts":[{"text":"Q1"}]},
			{"role":"model","parts":[{"text":"A1"}]},
			{"role":"user","parts":[{"text":"Q2"}]}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolGemini, body)

	require.Equal(t, "Q2", input.Text)
}

func TestExtractContentModerationInput_ResponsesAgentToolLoopKeepsAllUserMessages(t *testing.T) {
	body := []byte(`{
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"运行测试"}]},
			{"type":"function_call","call_id":"call_1","name":"run_tests","arguments":"{}"},
			{"type":"function_call_output","call_id":"call_1","output":"all passed"}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIResponses, body)

	require.Equal(t, "运行测试", input.Text)
	require.Empty(t, input.Images)
}

func TestExtractContentModerationInput_ResponsesExtractsAllUserMessages(t *testing.T) {
	body := []byte(`{
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"latest"}]}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIResponses, body)

	require.Equal(t, "first latest", input.Text)
}

func TestExtractContentModerationInput_ResponsesKeepsEarlierUserWhenLastIsAssistant(t *testing.T) {
	body := []byte(`{
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"q1"}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"a1"}]}
		]
	}`)

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIResponses, body)

	require.Equal(t, "q1", input.Text)
	require.Empty(t, input.Images)
}

func TestExtractContentModerationInput_OpenAIChatLongConversationStaysBounded(t *testing.T) {
	first := strings.Repeat("a", 7000)
	second := strings.Repeat("b", 7000)
	body := []byte(fmt.Sprintf(`{
		"messages": [
			{"role":"user","content":%q},
			{"role":"assistant","content":"ignored"},
			{"role":"user","content":%q}
		]
	}`, first, second))

	input := ExtractContentModerationInput(ContentModerationProtocolOpenAIChat, body)

	require.Len(t, []rune(input.Text), maxModerationInputRunes)
	require.Contains(t, input.Text, strings.Repeat("a", 128))
	require.Contains(t, input.Text, strings.Repeat("b", 128))
	require.NotContains(t, input.Text, "ignored")
}

func BenchmarkExtractContentModerationInput_OpenAIChatLargeMultiTurn(b *testing.B) {
	var payload strings.Builder
	payload.Grow(256 * 1024)
	payload.WriteString(`{"messages":[`)
	for i := range 40 {
		if i > 0 {
			payload.WriteByte(',')
		}
		payload.WriteString(fmt.Sprintf(`{"role":"user","content":%q}`, strings.Repeat(string(rune('a'+(i%3))), 4096)))
		if i != 39 {
			payload.WriteByte(',')
			payload.WriteString(`{"role":"assistant","content":"ok"}`)
		}
	}
	payload.WriteString(`]}`)
	body := []byte(payload.String())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := ExtractContentModerationInput(ContentModerationProtocolOpenAIChat, body)
		if len([]rune(input.Text)) != maxModerationInputRunes {
			b.Fatalf("unexpected moderation text length: %d", len([]rune(input.Text)))
		}
	}
}
