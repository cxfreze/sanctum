package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"zellion-server/internal/store"
)

func TestGeminiSchemaWalksSchemaPositions(t *testing.T) {
	var schema map[string]any
	raw := `{"type":"object","additionalProperties":false,"properties":{"type":{"type":"string"},"list":{"type":"array","items":{"anyOf":[{"type":"object","additionalProperties":false,"properties":{"name":{"type":"string"}}},{"type":"string"}]}},"union":{"anyOf":[{"type":"string"},{"type":"number"}]},"literal":{"default":{"additionalProperties":"literal","type":"literal"}}}}`
	if err := json.Unmarshal([]byte(raw), &schema); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(schema)
	got := sanitizeGeminiSchema(schema)
	props := got["properties"].(map[string]any)
	if len(props) != 4 {
		t.Fatalf("property map was treated as schema: %#v", props)
	}
	if _, ok := props["union"].(map[string]any)["type"]; ok {
		t.Fatal("union gained object constraint")
	}
	items := props["list"].(map[string]any)["items"].(map[string]any)
	branch := items["anyOf"].([]any)[0].(map[string]any)
	if _, ok := branch["additionalProperties"]; ok {
		t.Fatal("nested schema was not sanitized")
	}
	if branch["properties"].(map[string]any)["name"].(map[string]any)["type"] != "string" {
		t.Fatal("nested property lost")
	}
	literal := props["literal"].(map[string]any)["default"].(map[string]any)
	if literal["additionalProperties"] != "literal" {
		t.Fatal("literal data modified")
	}
	after, _ := json.Marshal(schema)
	if string(before) != string(after) {
		t.Fatal("input mutated")
	}
	if !reflect.DeepEqual(sanitizeGeminiSchema(nil), map[string]any{"type": "object", "properties": map[string]any{}}) {
		t.Fatal("nil schema default")
	}
}

func TestGeminiNativeIDAndSignatureRoundTrip(t *testing.T) {
	var calls []ToolCallSpec
	stream := `data: {"candidates":[{"finishReason":"STOP","content":{"parts":[{"functionCall":{"id":"native-123","name":"search","args":{"q":"x"}},"thoughtSignature":"opaque-signature"},{"functionCall":{"name":"legacy","args":{}}}]}}]}` + "\n\n"
	_, _, err := parseGeminiSSE(strings.NewReader(stream), StreamCallbacks{OnToolCall: func(tc ToolCallSpec) { calls = append(calls, tc) }})
	if err != nil || len(calls) != 2 {
		t.Fatalf("parse: %v %#v", err, calls)
	}
	if calls[0].ID != "native-123" || calls[0].NativeID != "native-123" || calls[0].ThoughtSignature != "opaque-signature" {
		t.Fatalf("metadata lost: %#v", calls[0])
	}
	if calls[1].ID == "" || calls[1].NativeID != "" {
		t.Fatalf("synthetic/native conflated: %#v", calls[1])
	}
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"candidates\":[{\"finishReason\":\"STOP\"}]}\n\n"))
	}))
	defer srv.Close()
	req := ChatRequest{Messages: []ChatMessage{{Role: "assistant", ToolCalls: calls}, {Role: "tool", ToolName: "search", ToolCallID: calls[0].ID, ToolCallNativeID: calls[0].NativeID, Content: "ok"}, {Role: "tool", ToolName: "legacy", ToolCallID: calls[1].ID, Content: "legacy"}}}
	if _, _, err = callGeminiGenerate(context.Background(), store.UpstreamProvider{BaseURL: srv.URL}, "test", req, StreamCallbacks{}); err != nil {
		t.Fatal(err)
	}
	contents := payload["contents"].([]any)
	parts := contents[0].(map[string]any)["parts"].([]any)
	first := parts[0].(map[string]any)
	if first["functionCall"].(map[string]any)["id"] != "native-123" || first["thoughtSignature"] != "opaque-signature" {
		t.Fatalf("replay lost metadata: %#v", first)
	}
	if _, ok := parts[1].(map[string]any)["functionCall"].(map[string]any)["id"]; ok {
		t.Fatal("invented Gemini functionCall id")
	}
	responses := contents[1].(map[string]any)["parts"].([]any)
	if responses[0].(map[string]any)["functionResponse"].(map[string]any)["id"] != "native-123" {
		t.Fatal("response id lost")
	}
	if _, ok := responses[1].(map[string]any)["functionResponse"].(map[string]any)["id"]; ok {
		t.Fatal("invented Gemini functionResponse id")
	}
}

func TestAnthropicUnsignedToolHistoryDisablesThinkingAndUsesNativeAuth(t *testing.T) {
	for _, withHistory := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "unsigned-tool-history"}[withHistory], func(t *testing.T) {
			var payload map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("x-api-key") != "test-key" || r.Header.Get("Authorization") != "" {
					t.Errorf("unexpected auth headers")
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				_, _ = w.Write([]byte("data: {\"type\":\"message_stop\"}\n\n"))
			}))
			defer srv.Close()
			msgs := []ChatMessage{{Role: "user", Content: "test"}}
			if withHistory {
				msgs = append(msgs, ChatMessage{Role: "assistant", Thinking: "display only", ToolCalls: []ToolCallSpec{{ID: "t", Name: "tool", Arguments: "{}"}}}, ChatMessage{Role: "tool", ToolCallID: "t", Content: "ok"})
			}
			_, _, err := callAnthropicMessages(context.Background(), store.UpstreamProvider{BaseURL: srv.URL, APIKey: "test-key"}, "test", ChatRequest{Messages: msgs, ThinkingLevel: "high"}, StreamCallbacks{})
			if err != nil {
				t.Fatal(err)
			}
			_, thinking := payload["thinking"]
			if thinking == withHistory {
				t.Fatalf("unsafe or unnecessarily disabled thinking: %#v", payload)
			}
			encoded, _ := json.Marshal(payload)
			if strings.Contains(string(encoded), "signature") || strings.Contains(string(encoded), "display only") {
				t.Fatal("fabricated signed thinking")
			}
		})
	}
}

func TestAnthropicCustomBearerAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer custom" {
			t.Error("custom Authorization not respected")
		}
		_, _ = w.Write([]byte("data: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer srv.Close()
	_, _, err := callAnthropicMessages(context.Background(), store.UpstreamProvider{BaseURL: srv.URL, CustomHeaders: map[string]string{"authorization": "Bearer custom"}}, "test", ChatRequest{}, StreamCallbacks{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenAIToolMessageWireShapes(t *testing.T) {
	for _, protocol := range []string{"openai", "openai-responses"} {
		t.Run(protocol, func(t *testing.T) {
			var payload map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if protocol == "openai-responses" {
					_, _ = w.Write([]byte("data: {\"type\":\"response.completed\"}\n\n"))
				} else {
					_, _ = w.Write([]byte("data: [DONE]\n\n"))
				}
			}))
			defer srv.Close()
			req := ChatRequest{Messages: []ChatMessage{{Role: "assistant", Content: "", ToolCalls: []ToolCallSpec{{ID: "call", Name: "tool", Arguments: "{}"}}}, {Role: "tool", ToolCallID: "call", Content: ""}, {Role: "assistant", Content: "done"}}}
			_, _, err := dispatchSingleProvider(context.Background(), store.UpstreamProvider{Protocol: protocol, BaseURL: srv.URL}, "test", req, StreamCallbacks{})
			if err != nil {
				t.Fatal(err)
			}
			if protocol == "openai" {
				msgs := payload["messages"].([]any)
				tool := msgs[1].(map[string]any)
				if tool["role"] != "tool" || tool["tool_call_id"] != "call" || tool["content"] != "" {
					t.Fatalf("tool content must be a string: %#v", tool)
				}
			} else {
				items := payload["input"].([]any)
				tool := items[1].(map[string]any)
				if tool["type"] != "function_call_output" || tool["call_id"] != "call" || tool["output"] != "" {
					t.Fatalf("wrong tool output: %#v", tool)
				}
				text := items[2].(map[string]any)["content"].([]any)[0].(map[string]any)
				if text["type"] != "output_text" {
					t.Fatal("assistant content must be output_text")
				}
			}
		})
	}
}

// An HTTP 200 stream may still fail. Never report an explicit provider error
// as a successful empty/partial assistant turn.
func TestProviderStreamErrorsAreFailures(t *testing.T) {
	tests := []struct{ protocol, event string }{
		{"openai", `{"error":{"message":"offline failure"}}`},
		{"gemini", `{"error":{"code":503,"message":"offline failure"}}`},
		{"anthropic", `{"type":"error","error":{"type":"overloaded_error","message":"offline failure"}}`},
		{"openai-responses", `{"type":"error","message":"offline failure"}`},
		{"openai-responses", `{"type":"response.failed","response":{"error":{"message":"offline failure"}}}`},
		{"openai-responses", `{"type":"response.incomplete","response":{"incomplete_details":{"reason":"max_output_tokens"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.protocol+tt.event, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("data: " + tt.event + "\n\n")) }))
			defer srv.Close()
			_, _, err := dispatchSingleProvider(context.Background(), store.UpstreamProvider{Protocol: tt.protocol, BaseURL: srv.URL}, "test", ChatRequest{}, StreamCallbacks{})
			if err == nil {
				t.Fatal("explicit stream error reported as success")
			}
		})
	}
}

func TestThinkingValidationErrorsAreNotRetriedOrSilentlyDowngraded(t *testing.T) {
	for _, protocol := range []string{"anthropic", "gemini"} {
		t.Run(protocol, func(t *testing.T) {
			count := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count++
				http.Error(w, `{"error":{"message":"invalid thinking / thinkingConfig signature or budget"}}`, http.StatusBadRequest)
			}))
			defer srv.Close()
			_, _, err := dispatchSingleProvider(context.Background(), store.UpstreamProvider{Protocol: protocol, BaseURL: srv.URL}, "test", ChatRequest{ThinkingLevel: "high"}, StreamCallbacks{})
			if err == nil || count != 1 {
				t.Fatalf("validation error silently retried: requests=%d err=%v", count, err)
			}
		})
	}
}

func TestProviderStreamsRequireTerminalEvent(t *testing.T) {
	tests := []struct{ protocol, delta, terminal string }{
		{"openai", `{"choices":[{"delta":{"content":"partial"}}]}`, `[DONE]`},
		{"openai", `{"choices":[{"delta":{"content":"partial"}}]}`, `{"choices":[{"delta":{},"finish_reason":"stop"}]}`},
		{"gemini", `{"candidates":[{"content":{"parts":[{"text":"partial"}]}}]}`, `{"candidates":[{"finishReason":"STOP"}]}`},
		{"anthropic", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}`, `{"type":"message_stop"}`},
		{"openai-responses", `{"type":"response.output_text.delta","delta":"partial"}`, `{"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":2}}}`},
	}
	for _, tt := range tests {
		for _, complete := range []bool{false, true} {
			t.Run(tt.protocol+tt.terminal+map[bool]string{false: "/truncated", true: "/complete"}[complete], func(t *testing.T) {
				calls, failovers := 0, 0
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					_, _ = w.Write([]byte("data: " + tt.delta + "\n\n"))
					if complete {
						_, _ = w.Write([]byte("data: " + tt.terminal + "\n\n"))
					}
				}))
				defer srv.Close()
				fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					failovers++
					http.Error(w, "must not fail over after output", 503)
				}))
				defer fallback.Close()
				st, cm := retryTestRoutes(t, srv.URL, fallback.URL)
				prov, _ := st.GetProvider("retry-provider-0")
				prov.Protocol = tt.protocol
				if _, err := st.UpsertProvider(prov); err != nil {
					t.Fatal(err)
				}
				var text strings.Builder
				result, err := ExecuteRoutedChat(context.Background(), st, cm, ChatRequest{}, StreamCallbacks{OnTextDelta: func(s string) { text.WriteString(s) }})
				if complete && err != nil {
					t.Fatalf("valid terminal rejected: %v", err)
				}
				if !complete && err == nil {
					t.Fatal("truncated upstream turned into success")
				}
				if calls != 1 || failovers != 0 || text.String() != "partial" || result.ProviderID != "retry-provider-0" {
					t.Fatalf("output retried/corrupted: calls=%d failovers=%d text=%q result=%+v err=%v", calls, failovers, text.String(), result, err)
				}
			})
		}
	}
}
