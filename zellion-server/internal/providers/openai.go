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

func normalizeOpenAIBase(base string) string {
	b := strings.TrimRight(strings.TrimSpace(base), "/")
	if b == "" {
		return "https://api.openai.com/v1"
	}
	// If user passed root without /v1 and it doesn't end with a version segment like /v1, /v3, /v4
	if !strings.HasSuffix(b, "/v1") && !strings.HasSuffix(b, "/v1beta") && !strings.HasSuffix(b, "/v2") && !strings.HasSuffix(b, "/v3") && !strings.HasSuffix(b, "/v4") && !strings.Contains(b, "/openai") {
		b = b + "/v1"
	}
	return b
}

func callOpenAIChat(
	ctx context.Context,
	prov store.UpstreamProvider,
	upstreamModel string,
	req ChatRequest,
	cb StreamCallbacks,
) (int, int, error) {
	endpoint := normalizeOpenAIBase(prov.BaseURL) + "/chat/completions"

	var oaiMessages []map[string]any
	if strings.TrimSpace(req.SystemPrompt) != "" {
		oaiMessages = append(oaiMessages, map[string]any{
			"role":    "system",
			"content": req.SystemPrompt,
		})
	}

	isDeepSeekReasoner := strings.Contains(strings.ToLower(upstreamModel), "deepseek-reasoner") ||
		strings.Contains(strings.ToLower(upstreamModel), "deepseek-r1")

	for _, m := range req.Messages {
		switch m.Role {
		case "user":
			if len(m.Attachments) == 0 {
				oaiMessages = append(oaiMessages, map[string]any{
					"role":    "user",
					"content": m.Content,
				})
			} else {
				var parts []map[string]any
				if m.Content != "" {
					parts = append(parts, map[string]any{
						"type": "text",
						"text": m.Content,
					})
				}
				for _, att := range m.Attachments {
					mt := strings.ToLower(att.MimeType)
					if strings.HasPrefix(mt, "image/") {
						parts = append(parts, map[string]any{
							"type": "image_url",
							"image_url": map[string]any{
								"url": fmt.Sprintf("data:%s;base64,%s", att.MimeType, att.DataBase64),
							},
						})
					} else if strings.HasPrefix(mt, "audio/") {
						format := "wav"
						if strings.Contains(mt, "mp3") || strings.Contains(mt, "mpeg") {
							format = "mp3"
						}
						parts = append(parts, map[string]any{
							"type": "input_audio",
							"input_audio": map[string]any{
								"data":   att.DataBase64,
								"format": format,
							},
						})
					} else {
						parts = append(parts, map[string]any{
							"type": "file",
													"file": map[string]any{
								"filename":  "",
								"file_data": fmt.Sprintf("data:%s;base64,%s", att.MimeType, att.DataBase64),
							},
						})
					}
				}
				oaiMessages = append(oaiMessages, map[string]any{
					"role":    "user",
					"content": parts,
				})
			}

		case "assistant":
			msgObj := map[string]any{
				"role":    "assistant",
				"content": m.Content,
			}
			if isDeepSeekReasoner {
				msgObj["reasoning_content"] = m.Thinking
			}
			if len(m.ToolCalls) > 0 {
				var tcs []map[string]any
				for _, tc := range m.ToolCalls {
					args := tc.Arguments
					if strings.TrimSpace(args) == "" {
						args = "{}"
					}
					tcs = append(tcs, map[string]any{
						"id":   tc.ID,
						"type": "function",
						"function": map[string]any{
							"name":      tc.Name,
							"arguments": args,
						},
					})
				}
				msgObj["tool_calls"] = tcs
			}
			oaiMessages = append(oaiMessages, msgObj)

		case "tool":
			oaiMessages = append(oaiMessages, map[string]any{
				"role":         "tool",
				"tool_call_id": m.ToolCallID,
				"content":      m.Content,
			})
		}
	}

	payload := map[string]any{
		"model":    upstreamModel,
		"messages": oaiMessages,
		"stream":   true,
		"stream_options": map[string]any{
			"include_usage": true,
		},
	}

	if req.MaxTokens > 0 {
		payload["max_tokens"] = req.MaxTokens
	}
	if req.Temperature != nil && !isDeepSeekReasoner {
		payload["temperature"] = *req.Temperature
	}

	// Reasoning effort for OpenAI o-series / GPT-5 / compatible endpoints
	effort := openaiReasoningEffort(req.ThinkingLevel)
	if effort != "" && (strings.HasPrefix(strings.ToLower(upstreamModel), "o1") ||
		strings.HasPrefix(strings.ToLower(upstreamModel), "o3") ||
		strings.HasPrefix(strings.ToLower(upstreamModel), "o4") ||
		strings.HasPrefix(strings.ToLower(upstreamModel), "gpt-5") ||
		strings.HasPrefix(strings.ToLower(upstreamModel), "gpt-6")) {
		payload["reasoning_effort"] = effort
		delete(payload, "max_tokens")
		if req.MaxTokens > 0 {
			payload["max_completion_tokens"] = req.MaxTokens
		}
		delete(payload, "temperature")
	}

	if len(req.Tools) > 0 {
		var tools []map[string]any
		for _, t := range req.Tools {
			var params any = map[string]any{"type": "object", "properties": map[string]any{}}
			if len(t.InputSchema) > 0 {
				_ = json.Unmarshal(t.InputSchema, &params)
			}
			tools = append(tools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  params,
				},
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
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		// Retry without stream_options if upstream rejected unknown field
		if resp.StatusCode == 400 && bytes.Contains(errBody, []byte("stream_options")) {
			delete(payload, "stream_options")
			return retryOpenAINoStreamOpts(ctx, client, endpoint, prov, payload, cb)
		}
		return 0, 0, &UpstreamHTTPError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(errBody))}
	}

	return parseOpenAISSE(resp.Body, cb)
}

func retryOpenAINoStreamOpts(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	prov store.UpstreamProvider,
	payload map[string]any,
	cb StreamCallbacks,
) (int, int, error) {
	bodyBytes, _ := json.Marshal(payload)
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
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return 0, 0, &UpstreamHTTPError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(errBody))}
	}
	return parseOpenAISSE(resp.Body, cb)
}

type partialToolCall struct {
	id   string
	name string
	args strings.Builder
}

func parseOpenAISSE(r io.Reader, cb StreamCallbacks) (int, int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	toolAcc := make(map[int]*partialToolCall)
	var toolIndices []int
	promptTokens := 0
	completionTokens := 0
	finished := false
	inThinkTag := false
	var thinkTagBuf strings.Builder

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		dataStr := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataStr == "[DONE]" {
			finished = true
			continue
		}
		if dataStr == "" {
			continue
		}

		var chunk struct {
			Error   json.RawMessage `json:"error"`
			Choices []struct {
				FinishReason string `json:"finish_reason"`
				Delta        struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					Reasoning        string `json:"reasoning"`
					ToolCalls        []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}

		if err := json.Unmarshal([]byte(dataStr), &chunk); err != nil {
			continue
		}

		if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
			return promptTokens, completionTokens, fmt.Errorf("OpenAI stream error: %s", chunk.Error)
		}
		if chunk.Usage != nil {
			promptTokens = chunk.Usage.PromptTokens
			completionTokens = chunk.Usage.CompletionTokens
		}

		for _, ch := range chunk.Choices {
			if ch.FinishReason != "" {
				finished = true
			}
			rc := ch.Delta.ReasoningContent
			if rc == "" {
				rc = ch.Delta.Reasoning
			}
			if rc != "" && cb.OnThinkingDelta != nil {
				cb.OnThinkingDelta(rc)
			}

			// Also handle inline <think>...</think> emitted by some Ollama / vLLM / OpenRouter R1 models
			if ch.Delta.Content != "" {
				text := ch.Delta.Content
				if !inThinkTag && strings.HasPrefix(thinkTagBuf.String()+text, "<think>") && thinkTagBuf.Len() < 8 {
					combined := thinkTagBuf.String() + text
					thinkTagBuf.Reset()
					inThinkTag = true
					rest := strings.TrimPrefix(combined, "<think>")
					if endIdx := strings.Index(rest, "</think>"); endIdx >= 0 {
						inThinkTag = false
						if cb.OnThinkingDelta != nil && rest[:endIdx] != "" {
							cb.OnThinkingDelta(rest[:endIdx])
						}
						after := strings.TrimLeft(rest[endIdx+len("</think>"):], "\r\n")
						if after != "" && cb.OnTextDelta != nil {
							cb.OnTextDelta(after)
						}
					} else if rest != "" && cb.OnThinkingDelta != nil {
						cb.OnThinkingDelta(rest)
					}
				} else if inThinkTag {
					if endIdx := strings.Index(text, "</think>"); endIdx >= 0 {
						inThinkTag = false
						if endIdx > 0 && cb.OnThinkingDelta != nil {
							cb.OnThinkingDelta(text[:endIdx])
						}
						after := strings.TrimLeft(text[endIdx+len("</think>"):], "\r\n")
						if after != "" && cb.OnTextDelta != nil {
							cb.OnTextDelta(after)
						}
					} else if cb.OnThinkingDelta != nil {
						cb.OnThinkingDelta(text)
					}
				} else {
					if cb.OnTextDelta != nil {
						cb.OnTextDelta(text)
					}
				}
			}

			for _, tc := range ch.Delta.ToolCalls {
				acc, exists := toolAcc[tc.Index]
				if !exists {
					acc = &partialToolCall{}
					toolAcc[tc.Index] = acc
					toolIndices = append(toolIndices, tc.Index)
				}
				if tc.ID != "" {
					acc.id = tc.ID
				}
				if tc.Function.Name != "" {
					acc.name += tc.Function.Name
				}
				if tc.Function.Arguments != "" {
					acc.args.WriteString(tc.Function.Arguments)
				}
			}
		}
	}

	sort.Ints(toolIndices)
	for _, idx := range toolIndices {
		acc := toolAcc[idx]
		if acc.name == "" {
			continue
		}
		id := acc.id
		if id == "" {
			id = fmt.Sprintf("call_%d_%d", time.Now().UnixMilli(), idx)
		}
		args := strings.TrimSpace(acc.args.String())
		if args == "" {
			args = "{}"
		}
		if cb.OnToolCall != nil {
			cb.OnToolCall(ToolCallSpec{
				ID:        id,
				Name:      acc.name,
				Arguments: args,
			})
		}
	}

	if (promptTokens > 0 || completionTokens > 0) && cb.OnUsage != nil {
		cb.OnUsage(promptTokens, completionTokens)
	}

	if err := scanner.Err(); err != nil {
		return promptTokens, completionTokens, err
	}
	if !finished {
		return promptTokens, completionTokens, fmt.Errorf("OpenAI stream ended before finish_reason or [DONE]: %w", io.ErrUnexpectedEOF)
	}
	return promptTokens, completionTokens, nil
}

func discoverOpenAIModels(ctx context.Context, prov store.UpstreamProvider) ([]string, error) {
	endpoint := normalizeOpenAIBase(prov.BaseURL) + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if key := pickAPIKey(prov.APIKey); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
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
