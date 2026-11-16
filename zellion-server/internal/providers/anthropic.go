package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"zellion-server/internal/store"
)

func normalizeAnthropicBase(base string) string {
	b := strings.TrimRight(strings.TrimSpace(base), "/")
	if b == "" {
		return "https://api.anthropic.com"
	}
	b = strings.TrimSuffix(b, "/v1/messages")
	b = strings.TrimSuffix(b, "/v1")
	return b
}

func callAnthropicMessages(
	ctx context.Context,
	prov store.UpstreamProvider,
	upstreamModel string,
	req ChatRequest,
	cb StreamCallbacks,
) (int, int, error) {
	endpoint := normalizeAnthropicBase(prov.BaseURL) + "/v1/messages"

	// Anthropic requires alternating user / assistant messages; consecutive tool results go into a single user message with tool_result blocks.
	var anthMessages []map[string]any
	appendUserBlocks := func(blocks []map[string]any) {
		if len(blocks) == 0 {
			return
		}
		if n := len(anthMessages); n > 0 && anthMessages[n-1]["role"] == "user" {
			existing, _ := anthMessages[n-1]["content"].([]map[string]any)
			anthMessages[n-1]["content"] = append(existing, blocks...)
			return
		}
		anthMessages = append(anthMessages, map[string]any{
			"role":    "user",
			"content": blocks,
		})
	}

	for _, m := range req.Messages {
		switch m.Role {
		case "user":
			var blocks []map[string]any
			for _, att := range m.Attachments {
				mt := strings.ToLower(att.MimeType)
				if strings.HasPrefix(mt, "image/") {
					blocks = append(blocks, map[string]any{
						"type": "image",
						"source": map[string]any{
							"type":       "base64",
							"media_type": att.MimeType,
							"data":       att.DataBase64,
						},
					})
				} else if mt == "application/pdf" {
					blocks = append(blocks, map[string]any{
						"type": "document",
						"source": map[string]any{
							"type":       "base64",
							"media_type": "application/pdf",
							"data":       att.DataBase64,
						},
					})
				}
			}
			if m.Content != "" || len(blocks) == 0 {
				txt := m.Content
				if txt == "" {
					txt = "..."
				}
				blocks = append(blocks, map[string]any{
					"type": "text",
					"text": txt,
				})
			}
			appendUserBlocks(blocks)

		case "assistant":
			var blocks []map[string]any
			if m.Content != "" {
				blocks = append(blocks, map[string]any{
					"type": "text",
					"text": m.Content,
				})
			}
			for _, tc := range m.ToolCalls {
				var inputObj any = map[string]any{}
				if strings.TrimSpace(tc.Arguments) != "" {
					_ = json.Unmarshal([]byte(tc.Arguments), &inputObj)
				}
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": inputObj,
				})
			}
			if len(blocks) > 0 {
				anthMessages = append(anthMessages, map[string]any{
					"role":    "assistant",
					"content": blocks,
				})
			}

		case "tool":
			appendUserBlocks([]map[string]any{
				{
					"type":        "tool_result",
					"tool_use_id": m.ToolCallID,
					"content":     m.Content,
				},
			})
		}
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 8192
	}

	budget := thinkingBudgetTokens(req.ThinkingLevel)
	// Our normalized history does not carry Anthropic's signed thinking blocks.
	// Re-enabling thinking over tool_use history would require those exact blocks;
	// degrade to normal generation rather than fabricate a signature or replay
	// display-only reasoning text as authenticated thinking.
	for _, m := range req.Messages {
		if m.Role == "assistant" && len(m.ToolCalls) > 0 {
			budget = 0
			break
		}
	}
	payload := map[string]any{
		"model":      upstreamModel,
		"messages":   anthMessages,
		"max_tokens": maxTokens,
		"stream":     true,
	}

	if strings.TrimSpace(req.SystemPrompt) != "" {
		payload["system"] = req.SystemPrompt
	}

	if budget > 0 {
		if maxTokens <= budget {
			maxTokens = budget + 4096
			payload["max_tokens"] = maxTokens
		}
		payload["thinking"] = map[string]any{
			"type":          "enabled",
			"budget_tokens": budget,
		}
	} else if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}

	if len(req.Tools) > 0 {
		var tools []map[string]any
		for _, t := range req.Tools {
			var schema any = map[string]any{"type": "object", "properties": map[string]any{}}
			if len(t.InputSchema) > 0 {
				_ = json.Unmarshal(t.InputSchema, &schema)
			}
			tools = append(tools, map[string]any{
				"name":         t.Name,
				"description":  t.Description,
				"input_schema": schema,
			})
		}
		payload["tools"] = tools
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, 0, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	if key := pickAPIKey(prov.APIKey); key != "" {
		httpReq.Header.Set("x-api-key", key)
		// Native Anthropic uses x-api-key. Gateways requiring Bearer auth can
		// opt in through CustomHeaders; do not send two credentials by default.
	}
	for k, v := range prov.CustomHeaders {
		if strings.TrimSpace(k) != "" {
			httpReq.Header.Set(k, v)
		}
	}

	client := buildHTTPClient(prov.ProxyURL, 5*time.Minute)
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return 0, 0, &UpstreamHTTPError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(errBytes))}
	}

	return parseAnthropicSSE(resp.Body, cb)
}

func parseAnthropicSSE(r io.Reader, cb StreamCallbacks) (int, int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	type anthTool struct {
		id   string
		name string
		json strings.Builder
	}
	blocks := make(map[int]*anthTool)
	var blockIndices []int
	inTokens := 0
	outTokens := 0
	finished := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		dataStr := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataStr == "" || dataStr == "[DONE]" {
			continue
		}

		var ev struct {
			Type    string `json:"type"`
			Index   int    `json:"index"`
			Message struct {
				Usage struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Thinking    string `json:"thinking"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}

		if err := json.Unmarshal([]byte(dataStr), &ev); err != nil {
			continue
		}

		switch ev.Type {
		case "message_stop":
			finished = true
		case "error":
			return inTokens, outTokens, fmt.Errorf("Anthropic stream error: %s", dataStr)
		case "message_start":
			inTokens = ev.Message.Usage.InputTokens
			if ev.Message.Usage.OutputTokens > 0 {
				outTokens = ev.Message.Usage.OutputTokens
			}
		case "content_block_start":
			if ev.ContentBlock.Type == "tool_use" {
				blocks[ev.Index] = &anthTool{
					id:   ev.ContentBlock.ID,
					name: ev.ContentBlock.Name,
				}
				blockIndices = append(blockIndices, ev.Index)
			}
		case "content_block_delta":
			switch ev.Delta.Type {
			case "thinking_delta":
				if ev.Delta.Thinking != "" && cb.OnThinkingDelta != nil {
					cb.OnThinkingDelta(ev.Delta.Thinking)
				}
			case "text_delta":
				if ev.Delta.Text != "" && cb.OnTextDelta != nil {
					cb.OnTextDelta(ev.Delta.Text)
				}
			case "input_json_delta":
				if tb, ok := blocks[ev.Index]; ok {
					tb.json.WriteString(ev.Delta.PartialJSON)
				}
			}
		case "message_delta":
			if ev.Usage.OutputTokens > 0 {
				outTokens = ev.Usage.OutputTokens
			}
		}
	}

	sort.Ints(blockIndices)
	for _, idx := range blockIndices {
		tb := blocks[idx]
		args := strings.TrimSpace(tb.json.String())
		if args == "" {
			args = "{}"
		}
		if cb.OnToolCall != nil {
			cb.OnToolCall(ToolCallSpec{
				ID:        tb.id,
				Name:      tb.name,
				Arguments: args,
			})
		}
	}

	if (inTokens > 0 || outTokens > 0) && cb.OnUsage != nil {
		cb.OnUsage(inTokens, outTokens)
	}

	if err := scanner.Err(); err != nil {
		return inTokens, outTokens, err
	}
	if !finished {
		return inTokens, outTokens, fmt.Errorf("Anthropic stream ended before message_stop: %w", io.ErrUnexpectedEOF)
	}
	return inTokens, outTokens, nil
}

func discoverAnthropicModels(ctx context.Context, prov store.UpstreamProvider) ([]string, error) {
	endpoint := normalizeAnthropicBase(prov.BaseURL) + "/v1/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("anthropic-version", "2023-06-01")
	if key := pickAPIKey(prov.APIKey); key != "" {
		req.Header.Set("x-api-key", key)
	}
	for k, v := range prov.CustomHeaders {
		if strings.TrimSpace(k) != "" {
			req.Header.Set(k, v)
		}
	}
	client := buildHTTPClient(prov.ProxyURL, 20*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var models []string
	for _, d := range parsed.Data {
		if d.ID != "" {
			models = append(models, d.ID)
		}
	}
	sort.Strings(models)
	return models, nil
}
