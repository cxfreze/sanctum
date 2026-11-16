package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"zellion-server/internal/store"
)

func normalizeGeminiBase(base string) string {
	b := strings.TrimRight(strings.TrimSpace(base), "/")
	if b == "" {
		return "https://generativelanguage.googleapis.com"
	}
	b = strings.TrimSuffix(b, "/v1beta")
	return b
}

func callGeminiGenerate(
	ctx context.Context,
	prov store.UpstreamProvider,
	upstreamModel string,
	req ChatRequest,
	cb StreamCallbacks,
) (int, int, error) {
	modelSlug := strings.TrimPrefix(strings.TrimSpace(upstreamModel), "models/")
	base := normalizeGeminiBase(prov.BaseURL)
	key := pickAPIKey(prov.APIKey)

	endpoint := fmt.Sprintf("%s/v1beta/models/%s:streamGenerateContent?alt=sse", base, url.PathEscape(modelSlug))
	if key != "" {
		endpoint += "&key=" + url.QueryEscape(key)
	}

	var contents []map[string]any
	
		// Helper to build parts from ChatMessage
	buildParts := func(m ChatMessage) []map[string]any {
		var parts []map[string]any
		for _, att := range m.Attachments {
			if att.FileURI != "" {
				parts = append(parts, map[string]any{
					"fileData": map[string]any{
						"mimeType": att.MimeType,
						"fileUri":  att.FileURI,
					},
				})
			} else if att.DataBase64 != "" {
				data := att.DataBase64
				// 移除可能的 Data URL 前缀
				if idx := strings.Index(data, ","); idx != -1 {
					data = data[idx+1:]
				}
				parts = append(parts, map[string]any{
					"inlineData": map[string]any{
						"mimeType": att.MimeType,
						"data":     data,
					},
				})
			}
		}
		if m.Content != "" {
			parts = append(parts, map[string]any{"text": m.Content})
		}
		return parts
	}

	appendContent := func(role string, parts []map[string]any) {
		if len(parts) == 0 {
			return
		}
		if n := len(contents); n > 0 && contents[n-1]["role"] == role {
			existing, _ := contents[n-1]["parts"].([]map[string]any)
			contents[n-1]["parts"] = append(existing, parts...)
			return
		}
		contents = append(contents, map[string]any{
			"role":  role,
			"parts": parts,
		})
	}

	for _, m := range req.Messages {
		switch m.Role {
		case "user":
			appendContent("user", buildParts(m))
		case "assistant":
			var parts []map[string]any
			if m.Content != "" {
				parts = append(parts, map[string]any{"text": m.Content})
			}
			for _, tc := range m.ToolCalls {
				var argsObj any = map[string]any{}
				if strings.TrimSpace(tc.Arguments) != "" {
					_ = json.Unmarshal([]byte(tc.Arguments), &argsObj)
				}
				part := map[string]any{
					"functionCall": map[string]any{
						"name": tc.Name,
						"args": argsObj,
					},
				}
				if tc.NativeID != "" {
					part["functionCall"].(map[string]any)["id"] = tc.NativeID
				}
				if tc.ThoughtSignature != "" {
					part["thoughtSignature"] = tc.ThoughtSignature
				}
				parts = append(parts, part)
			}
			appendContent("model", parts)
		case "tool":
			name := m.ToolName
			if name == "" {
				name = "tool_result"
			}
			response := map[string]any{
				"name":     name,
				"response": map[string]any{"output": m.Content},
			}
			if m.ToolCallNativeID != "" {
				response["id"] = m.ToolCallNativeID
			}
			appendContent("user", []map[string]any{{"functionResponse": response}})
		}
	}

	genCfg := map[string]any{}
	if req.MaxTokens > 0 {
		genCfg["maxOutputTokens"] = req.MaxTokens
	}
	if req.Temperature != nil {
		genCfg["temperature"] = *req.Temperature
	}

	budget := thinkingBudgetTokens(req.ThinkingLevel)
	if budget > 0 {
		genCfg["thinkingConfig"] = map[string]any{
			"includeThoughts": true,
			"thinkingBudget":  budget,
		}
	}

	payload := map[string]any{
		"contents":         contents,
		"generationConfig": genCfg,
	}

	if strings.TrimSpace(req.SystemPrompt) != "" {
		payload["systemInstruction"] = map[string]any{
			"parts": []map[string]any{
				{"text": req.SystemPrompt},
			},
		}
	}

	if len(req.Tools) > 0 {
		var decls []map[string]any
		for _, t := range req.Tools {
			var schema map[string]any
			if len(t.InputSchema) > 0 {
				_ = json.Unmarshal(t.InputSchema, &schema)
			}
			schema = sanitizeGeminiSchema(schema)
			decls = append(decls, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  schema,
			})
		}
		payload["tools"] = []map[string]any{
			{"functionDeclarations": decls},
		}
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
	if key != "" {
		httpReq.Header.Set("x-goog-api-key", key)
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

	return parseGeminiSSE(resp.Body, cb)
}

// sanitizeGeminiSchema walks schema positions, never property-name maps or
// arbitrary values (e.g. enum/default). In particular a property named "type"
// must remain a property, not be interpreted as a schema keyword.
func sanitizeGeminiSchema(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch k {
		case "$schema", "additionalProperties":
			continue
		case "properties", "$defs", "definitions", "patternProperties":
			if props, ok := v.(map[string]any); ok {
				clean := make(map[string]any, len(props))
				for name, value := range props {
					if schema, ok := value.(map[string]any); ok {
						clean[name] = sanitizeGeminiSchema(schema)
					} else {
						clean[name] = value
					}
				}
				out[k] = clean
				continue
			}
		case "items", "not", "contains", "if", "then", "else":
			if schema, ok := v.(map[string]any); ok {
				out[k] = sanitizeGeminiSchema(schema)
				continue
			}
			fallthrough
		case "anyOf", "oneOf", "allOf", "prefixItems":
			if schemas, ok := v.([]any); ok {
				clean := make([]any, len(schemas))
				for i, value := range schemas {
					if schema, ok := value.(map[string]any); ok {
						clean[i] = sanitizeGeminiSchema(schema)
					} else {
						clean[i] = value
					}
				}
				out[k] = clean
				continue
			}
		}
		out[k] = v
	}
	// Only infer an object when there is actual object structure. A union or
	// untyped scalar schema must not gain an incompatible object constraint.
	if _, typed := out["type"]; !typed {
		if _, hasProperties := out["properties"]; hasProperties {
			out["type"] = "object"
		}
	}
	return out
}

func parseGeminiSSE(r io.Reader, cb StreamCallbacks) (int, int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	pTokens := 0
	cTokens := 0
	callSeq := 0
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

		var chunk struct {
			Error      json.RawMessage `json:"error"`
			Candidates []struct {
				FinishReason string `json:"finishReason"`
				Content      struct {
					Parts []struct {
						Text             string `json:"text"`
						Thought          bool   `json:"thought"`
						ThoughtSignature string `json:"thoughtSignature"`
						FunctionCall     *struct {
							ID   string          `json:"id"`
							Name string          `json:"name"`
							Args json.RawMessage `json:"args"`
						} `json:"functionCall"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
			UsageMetadata *struct {
				PromptTokenCount     int `json:"promptTokenCount"`
				CandidatesTokenCount int `json:"candidatesTokenCount"`
			} `json:"usageMetadata"`
		}

		if err := json.Unmarshal([]byte(dataStr), &chunk); err != nil {
			continue
		}

		if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
			return pTokens, cTokens, fmt.Errorf("Gemini stream error: %s", chunk.Error)
		}
		if chunk.UsageMetadata != nil {
			pTokens = chunk.UsageMetadata.PromptTokenCount
			cTokens = chunk.UsageMetadata.CandidatesTokenCount
		}

		for _, cand := range chunk.Candidates {
			if cand.FinishReason != "" && cand.FinishReason != "FINISH_REASON_UNSPECIFIED" {
				finished = true
			}
			for _, part := range cand.Content.Parts {
				if part.Thought && part.Text != "" {
					if cb.OnThinkingDelta != nil {
						cb.OnThinkingDelta(part.Text)
					}
					continue
				}
				if part.Text != "" && cb.OnTextDelta != nil {
					cb.OnTextDelta(part.Text)
				}
				if part.FunctionCall != nil && part.FunctionCall.Name != "" && cb.OnToolCall != nil {
					callSeq++
					args := strings.TrimSpace(string(part.FunctionCall.Args))
					if args == "" {
						args = "{}"
					}
					id := part.FunctionCall.ID
					if id == "" {
						id = fmt.Sprintf("gem_call_%d_%d", time.Now().UnixNano(), callSeq)
					}
					cb.OnToolCall(ToolCallSpec{
						ID:               id,
						NativeID:         part.FunctionCall.ID,
						Name:             part.FunctionCall.Name,
						Arguments:        args,
						ThoughtSignature: part.ThoughtSignature,
					})
				}
			}
		}
	}

	if (pTokens > 0 || cTokens > 0) && cb.OnUsage != nil {
		cb.OnUsage(pTokens, cTokens)
	}
	if err := scanner.Err(); err != nil {
		return pTokens, cTokens, err
	}
	if !finished {
		return pTokens, cTokens, fmt.Errorf("Gemini stream ended before finishReason: %w", io.ErrUnexpectedEOF)
	}
	return pTokens, cTokens, nil
}

func discoverGeminiModels(ctx context.Context, prov store.UpstreamProvider) ([]string, error) {
	base := normalizeGeminiBase(prov.BaseURL)
	key := pickAPIKey(prov.APIKey)
	endpoint := base + "/v1beta/models"
	if key != "" {
		endpoint += "?key=" + url.QueryEscape(key)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if key != "" {
		req.Header.Set("x-goog-api-key", key)
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
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var models []string
	for _, m := range parsed.Models {
		slug := strings.TrimPrefix(m.Name, "models/")
		if slug != "" {
			models = append(models, slug)
		}
	}
	sort.Strings(models)
	return models, nil
}
