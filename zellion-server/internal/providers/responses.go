package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"zellion-server/internal/store"
)

func callOpenAIResponses(
	ctx context.Context,
	prov store.UpstreamProvider,
	upstreamModel string,
	req ChatRequest,
	cb StreamCallbacks,
) (int, int, error) {
	endpoint := normalizeOpenAIBase(prov.BaseURL) + "/responses"

	var inputItems []map[string]any
	for _, m := range req.Messages {
		switch m.Role {
		case "user":
			var contentParts []map[string]any
			if m.Content != "" {
				contentParts = append(contentParts, map[string]any{
					"type": "input_text",
					"text": m.Content,
				})
			}
			for _, att := range m.Attachments {
				mt := strings.ToLower(att.MimeType)
				if strings.HasPrefix(mt, "image/") {
					contentParts = append(contentParts, map[string]any{
						"type":      "input_image",
						"image_url": fmt.Sprintf("data:%s;base64,%s", att.MimeType, att.DataBase64),
					})
				} else {
					contentParts = append(contentParts, map[string]any{
											"type":      "input_file",
						"filename":  "",
						"file_data": fmt.Sprintf("data:%s;base64,%s", att.MimeType, att.DataBase64),
					})
				}
			}
			inputItems = append(inputItems, map[string]any{
				"role":    "user",
				"content": contentParts,
			})

		case "assistant":
			if m.Content != "" {
				inputItems = append(inputItems, map[string]any{
					"role": "assistant",
					"content": []map[string]any{
						{"type": "output_text", "text": m.Content},
					},
				})
			}
			for _, tc := range m.ToolCalls {
				inputItems = append(inputItems, map[string]any{
					"type":      "function_call",
					"call_id":   tc.ID,
					"name":      tc.Name,
					"arguments": tc.Arguments,
				})
			}

		case "tool":
			inputItems = append(inputItems, map[string]any{
				"type":    "function_call_output",
				"call_id": m.ToolCallID,
				"output":  m.Content,
			})
		}
	}

	payload := map[string]any{
		"model":  upstreamModel,
		"input":  inputItems,
		"stream": true,
	}
	if strings.TrimSpace(req.SystemPrompt) != "" {
		payload["instructions"] = req.SystemPrompt
	}
	if req.MaxTokens > 0 {
		payload["max_output_tokens"] = req.MaxTokens
	}
	if effort := openaiReasoningEffort(req.ThinkingLevel); effort != "" {
		payload["reasoning"] = map[string]any{
			"effort":  effort,
			"summary": "auto",
		}
	}
	if len(req.Tools) > 0 {
		var tools []map[string]any
		for _, t := range req.Tools {
			var params any = map[string]any{"type": "object", "properties": map[string]any{}}
			if len(t.InputSchema) > 0 {
				_ = json.Unmarshal(t.InputSchema, &params)
			}
			tools = append(tools, map[string]any{
				"type":        "function",
				"name":        t.Name,
				"description": t.Description,
				"parameters":  params,
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
	if key := pickAPIKey(prov.APIKey); key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+key)
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
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return 0, 0, &UpstreamHTTPError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	pTokens, cTokens := 0, 0
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
			Type  string `json:"type"`
			Delta string `json:"delta"`
			Item  struct {
				Type      string `json:"type"`
				CallID    string `json:"call_id"`
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"item"`
			Response struct {
				Usage struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"response"`
		}
		if err := json.Unmarshal([]byte(dataStr), &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "error", "response.failed", "response.incomplete":
			return pTokens, cTokens, fmt.Errorf("Responses stream %s: %s", ev.Type, dataStr)
		case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
			if ev.Delta != "" && cb.OnThinkingDelta != nil {
				cb.OnThinkingDelta(ev.Delta)
			}
		case "response.output_text.delta":
			if ev.Delta != "" && cb.OnTextDelta != nil {
				cb.OnTextDelta(ev.Delta)
			}
		case "response.output_item.done":
			if ev.Item.Type == "function_call" && ev.Item.Name != "" && cb.OnToolCall != nil {
				callID := ev.Item.CallID
				if callID == "" {
					callID = fmt.Sprintf("call_%d", time.Now().UnixMilli())
				}
				args := strings.TrimSpace(ev.Item.Arguments)
				if args == "" {
					args = "{}"
				}
				cb.OnToolCall(ToolCallSpec{
					ID:        callID,
					Name:      ev.Item.Name,
					Arguments: args,
				})
			}
		case "response.completed":
			finished = true
			pTokens = ev.Response.Usage.InputTokens
			cTokens = ev.Response.Usage.OutputTokens
			if (pTokens > 0 || cTokens > 0) && cb.OnUsage != nil {
				cb.OnUsage(pTokens, cTokens)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return pTokens, cTokens, err
	}
	if !finished {
		return pTokens, cTokens, fmt.Errorf("Responses stream ended before response.completed: %w", io.ErrUnexpectedEOF)
	}
	return pTokens, cTokens, nil
}
