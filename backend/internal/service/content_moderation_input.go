package service

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"github.com/tidwall/gjson"
)

func ExtractContentModerationText(protocol string, body []byte) string {
	return ExtractContentModerationInput(protocol, body).Text
}

func ExtractContentModerationInput(protocol string, body []byte) ContentModerationInput {
	return extractContentModerationInputWithMode(protocol, body, false)
}

func extractLegacyContentModerationInput(protocol string, body []byte) ContentModerationInput {
	return extractContentModerationInputWithMode(protocol, body, true)
}

func extractLegacyContentModerationHash(protocol string, body []byte, current ContentModerationInput) string {
	if !isOpenAISessionModerationProtocol(protocol) {
		return ""
	}
	legacy := extractLegacyContentModerationInput(protocol, body)
	if legacy.IsEmpty() {
		return ""
	}
	legacy.Normalize()
	legacyHash := legacy.Hash()
	if legacyHash == current.Hash() {
		return ""
	}
	return legacyHash
}

func extractContentModerationInputWithMode(protocol string, body []byte, legacy bool) ContentModerationInput {
	if len(body) == 0 || !gjson.ValidBytes(body) {
		return ContentModerationInput{}
	}
	collector := newModerationInputCollector()
	switch protocol {
	case ContentModerationProtocolAnthropicMessages:
		collectLastAnthropicUserMessage(gjson.GetBytes(body, "messages"), collector)
	case ContentModerationProtocolOpenAIChat:
		if legacy {
			collectLastRoleMessage(gjson.GetBytes(body, "messages"), "user", collector)
		} else {
			collectAllRoleMessages(gjson.GetBytes(body, "messages"), "user", collector)
		}
	case ContentModerationProtocolOpenAIResponses:
		if legacy {
			collectLastResponsesInput(gjson.GetBytes(body, "input"), collector)
		} else {
			collectAllResponsesInput(gjson.GetBytes(body, "input"), collector)
		}
	case ContentModerationProtocolGemini:
		collectLastGeminiContent(gjson.GetBytes(body, "contents"), collector)
	case ContentModerationProtocolOpenAIImages:
		collector.addText(gjson.GetBytes(body, "prompt").String())
		collectContentValue(gjson.GetBytes(body, "images"), collector)
	default:
		if legacy {
			collectLastResponsesInput(gjson.GetBytes(body, "input"), collector)
			collectLastRoleMessage(gjson.GetBytes(body, "messages"), "user", collector)
		} else {
			collectAllResponsesInput(gjson.GetBytes(body, "input"), collector)
			collectAllRoleMessages(gjson.GetBytes(body, "messages"), "user", collector)
		}
		collectLastGeminiContent(gjson.GetBytes(body, "contents"), collector)
	}
	out := collector.build()
	out.Normalize()
	return out
}

type moderationInputCollector struct {
	text         strings.Builder
	textRunes    int
	pendingSpace bool
	images       []string
}

func newModerationInputCollector() *moderationInputCollector {
	return &moderationInputCollector{}
}

func (c *moderationInputCollector) build() ContentModerationInput {
	if c == nil {
		return ContentModerationInput{}
	}
	return ContentModerationInput{
		Text:   c.text.String(),
		Images: normalizeModerationImages(c.images),
	}
}

func (c *moderationInputCollector) IsEmpty() bool {
	return c == nil || (c.textRunes == 0 && len(c.images) == 0)
}

func (c *moderationInputCollector) Merge(other *moderationInputCollector) {
	if c == nil || other == nil || other.IsEmpty() {
		return
	}
	c.addText(other.text.String())
	c.images = append(c.images, other.images...)
}

func (c *moderationInputCollector) addText(text string) {
	if c == nil {
		return
	}
	text = strings.TrimSpace(text)
	if text == "" || strings.Contains(text, "<system-reminder>") {
		return
	}
	if c.textRunes > 0 {
		c.pendingSpace = true
	}
	for _, r := range text {
		if unicode.IsSpace(r) {
			if c.textRunes > 0 {
				c.pendingSpace = true
			}
			continue
		}
		if c.textRunes >= maxModerationInputRunes {
			c.pendingSpace = false
			return
		}
		if c.pendingSpace && c.textRunes > 0 {
			c.text.WriteByte(' ')
			c.pendingSpace = false
		}
		c.text.WriteRune(r)
		c.textRunes++
	}
}

func (c *moderationInputCollector) addImage(image string) {
	if c == nil {
		return
	}
	image = strings.TrimSpace(image)
	if image == "" {
		return
	}
	if strings.HasPrefix(image, "data:") || strings.HasPrefix(image, "http://") || strings.HasPrefix(image, "https://") {
		c.images = append(c.images, image)
	}
}

func collectAllRoleMessages(messages gjson.Result, role string, collector *moderationInputCollector) {
	if !messages.IsArray() {
		return
	}
	messages.ForEach(func(_, msg gjson.Result) bool {
		if strings.ToLower(strings.TrimSpace(msg.Get("role").String())) != role {
			return true
		}
		candidate := newModerationInputCollector()
		collectContentValue(msg.Get("content"), candidate)
		if candidate.IsEmpty() {
			return true
		}
		collector.Merge(candidate)
		return true
	})
}

func collectLastRoleMessage(messages gjson.Result, role string, collector *moderationInputCollector) {
	if !messages.IsArray() {
		return
	}
	array := messages.Array()
	if len(array) == 0 {
		return
	}
	last := array[len(array)-1]
	if strings.ToLower(strings.TrimSpace(last.Get("role").String())) != role {
		return
	}
	candidate := newModerationInputCollector()
	collectContentValue(last.Get("content"), candidate)
	if candidate.IsEmpty() {
		return
	}
	collector.Merge(candidate)
}

func collectLastAnthropicUserMessage(messages gjson.Result, collector *moderationInputCollector) {
	if !messages.IsArray() {
		return
	}
	array := messages.Array()
	if len(array) == 0 {
		return
	}
	last := array[len(array)-1]
	if strings.ToLower(strings.TrimSpace(last.Get("role").String())) != "user" {
		return
	}
	candidate := newModerationInputCollector()
	collectAnthropicUserContentValue(last.Get("content"), candidate)
	if candidate.IsEmpty() {
		return
	}
	collector.Merge(candidate)
}

func collectAnthropicUserContentValue(value gjson.Result, collector *moderationInputCollector) {
	switch {
	case !value.Exists():
		return
	case value.Type == gjson.String:
		if !isAnthropicSystemReminderText(value.String()) {
			collector.addText(value.String())
		}
	case value.IsArray():
		value.ForEach(func(_, item gjson.Result) bool {
			collectAnthropicUserContentValue(item, collector)
			return true
		})
	case value.IsObject():
		typ := strings.ToLower(strings.TrimSpace(value.Get("type").String()))
		switch typ {
		case "", "text", "input_text", "message":
			if value.Get("text").Exists() && !isAnthropicSystemReminderText(value.Get("text").String()) {
				collector.addText(value.Get("text").String())
			}
			if value.Get("content").Exists() {
				collectAnthropicUserContentValue(value.Get("content"), collector)
			}
		case "image_url", "input_image", "image":
			collectContentValue(value, collector)
		}
	}
}

func isAnthropicSystemReminderText(text string) bool {
	return strings.HasPrefix(strings.TrimSpace(text), "<system-reminder>")
}

func collectLastResponsesInput(input gjson.Result, collector *moderationInputCollector) {
	switch {
	case !input.Exists():
		return
	case input.Type == gjson.String:
		collector.addText(input.String())
	case input.IsArray():
		array := input.Array()
		if len(array) == 0 {
			return
		}
		last := array[len(array)-1]
		if !isResponsesUserTextItem(last) {
			return
		}
		collectContentValue(last.Get("content"), collector)
		if last.Get("type").String() == "input_text" || last.Get("text").Exists() {
			collectContentValue(last, collector)
		}
	case input.IsObject():
		if isResponsesUserTextItem(input) {
			collectContentValue(input.Get("content"), collector)
			if input.Get("type").String() == "input_text" || input.Get("text").Exists() {
				collectContentValue(input, collector)
			}
		}
	}
}

func collectAllResponsesInput(input gjson.Result, collector *moderationInputCollector) {
	switch {
	case !input.Exists():
		return
	case input.Type == gjson.String:
		collector.addText(input.String())
	case input.IsArray():
		input.ForEach(func(_, item gjson.Result) bool {
			if !isResponsesUserTextItem(item) {
				return true
			}
			collectContentValue(item.Get("content"), collector)
			if item.Get("type").String() == "input_text" || item.Get("text").Exists() {
				collectContentValue(item, collector)
			}
			return true
		})
	case input.IsObject():
		if isResponsesUserTextItem(input) {
			collectContentValue(input.Get("content"), collector)
			if input.Get("type").String() == "input_text" || input.Get("text").Exists() {
				collectContentValue(input, collector)
			}
		}
	}
}

func isResponsesUserTextItem(item gjson.Result) bool {
	role := strings.ToLower(strings.TrimSpace(item.Get("role").String()))
	if role == "user" {
		return responseItemHasModerationText(item)
	}
	if role != "" {
		return false
	}
	return responseItemHasModerationText(item)
}

func responseItemHasModerationText(item gjson.Result) bool {
	collector := newModerationInputCollector()
	collectContentValue(item.Get("content"), collector)
	if item.Get("type").String() == "input_text" || item.Get("text").Exists() {
		collectContentValue(item, collector)
	}
	return !collector.IsEmpty()
}

func collectLastGeminiContent(contents gjson.Result, collector *moderationInputCollector) {
	if !contents.IsArray() {
		return
	}
	array := contents.Array()
	if len(array) == 0 {
		return
	}
	last := array[len(array)-1]
	role := strings.ToLower(strings.TrimSpace(last.Get("role").String()))
	if role != "" && role != "user" {
		return
	}
	candidate := newModerationInputCollector()
	if arr := last.Get("parts"); arr.IsArray() {
		arr.ForEach(func(_, part gjson.Result) bool {
			candidate.addText(part.Get("text").String())
			addGeminiModerationImage(candidate, part)
			return true
		})
	}
	if candidate.IsEmpty() {
		return
	}
	collector.Merge(candidate)
}

func collectContentValue(value gjson.Result, collector *moderationInputCollector) {
	switch {
	case !value.Exists():
		return
	case value.Type == gjson.String:
		collector.addText(value.String())
	case value.IsArray():
		value.ForEach(func(_, item gjson.Result) bool {
			collectContentValue(item, collector)
			return true
		})
	case value.IsObject():
		typ := strings.ToLower(strings.TrimSpace(value.Get("type").String()))
		collector.addImage(value.Get("image_url.url").String())
		collector.addImage(value.Get("image_url").String())
		collector.addImage(value.Get("url").String())
		addModerationImageData(collector, value.Get("source.media_type").String(), value.Get("source.data").String())
		addModerationImageData(collector, value.Get("source.mediaType").String(), value.Get("source.data").String())
		addModerationImageData(collector, value.Get("media_type").String(), value.Get("data").String())
		addModerationImageData(collector, value.Get("mime_type").String(), value.Get("data").String())
		addModerationImageData(collector, value.Get("mimeType").String(), value.Get("data").String())
		collector.addImage(value.Get("source.data").String())
		collector.addImage(value.Get("data").String())
		collector.addImage(value.Get("base64").String())
		switch typ {
		case "", "text", "input_text", "message":
			if value.Get("text").Exists() {
				collector.addText(value.Get("text").String())
			}
			if value.Get("content").Exists() {
				collectContentValue(value.Get("content"), collector)
			}
		case "image_url", "input_image", "image":
		}
	}
}

func addGeminiModerationImage(collector *moderationInputCollector, part gjson.Result) {
	if inlineData := part.Get("inline_data"); inlineData.IsObject() {
		mimeType := strings.TrimSpace(inlineData.Get("mime_type").String())
		data := strings.TrimSpace(inlineData.Get("data").String())
		if mimeType != "" && data != "" {
			collector.addImage(fmt.Sprintf("data:%s;base64,%s", mimeType, data))
		}
	}
	if inlineData := part.Get("inlineData"); inlineData.IsObject() {
		mimeType := strings.TrimSpace(inlineData.Get("mimeType").String())
		data := strings.TrimSpace(inlineData.Get("data").String())
		if mimeType != "" && data != "" {
			collector.addImage(fmt.Sprintf("data:%s;base64,%s", mimeType, data))
		}
	}
	collector.addImage(part.Get("file_data.file_uri").String())
	collector.addImage(part.Get("fileData.fileUri").String())
}

func addModerationImageData(collector *moderationInputCollector, mimeType string, data string) {
	mimeType = strings.TrimSpace(mimeType)
	data = strings.TrimSpace(data)
	if mimeType == "" || data == "" {
		return
	}
	collector.addImage(fmt.Sprintf("data:%s;base64,%s", mimeType, data))
}

func normalizeModerationImages(images []string) []string {
	out := make([]string, 0, len(images))
	seen := make(map[string]struct{}, len(images))
	for _, image := range images {
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}
		if _, ok := seen[image]; ok {
			continue
		}
		seen[image] = struct{}{}
		out = append(out, image)
	}
	return out
}

func limitContentModerationImages(images []string) []string {
	if len(images) <= maxContentModerationInputImages {
		return images
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(images))))
	if err != nil {
		return images[:maxContentModerationInputImages]
	}
	return []string{images[int(idx.Int64())]}
}

func normalizeContentModerationText(text string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
}
