package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"zellion-server/internal/store"
)

type MediaPart struct {
	MimeType   string `json:"mimeType"`
	DataBase64 string `json:"dataBase64,omitempty"`
	FileURI    string `json:"fileUri,omitempty"`
}

type ToolCallSpec struct {
	ID               string `json:"id"`
	NativeID         string `json:"nativeId,omitempty"`
	Name             string `json:"name"`
	Arguments        string `json:"arguments"`
	ThoughtSignature string `json:"thoughtSignature,omitempty"`
}

type ChatMessage struct {
	Role             string         `json:"role"` // "user" | "assistant" | "tool"
	Content          string         `json:"content"`
	Thinking         string         `json:"thinking,omitempty"`
	Attachments      []MediaPart    `json:"attachments,omitempty"`
	ToolCalls        []ToolCallSpec `json:"toolCalls,omitempty"`
	ToolCallID       string         `json:"toolCallId,omitempty"`
	ToolCallNativeID string         `json:"toolCallNativeId,omitempty"`
	ToolName         string         `json:"toolName,omitempty"`
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type ChatRequest struct {
	Model         string           `json:"model"`
	SystemPrompt  string           `json:"systemPrompt,omitempty"`
	Messages      []ChatMessage    `json:"messages"`
	Tools         []ToolDefinition `json:"tools,omitempty"`
	ThinkingLevel string           `json:"thinkingLevel,omitempty"` // off | low | medium | high | extra | max
	MaxTokens     int              `json:"maxTokens,omitempty"`
	Temperature   *float64         `json:"temperature,omitempty"`
	Stream        bool             `json:"stream"`
}

type StreamCallbacks struct {
	OnThinkingDelta func(delta string)
	OnTextDelta     func(delta string)
	OnToolCall      func(tc ToolCallSpec)
	OnUsage         func(promptTokens, completionTokens int)
}

type ExecutionResult struct {
	ProviderID       string
	ProviderName     string
	Protocol         string
	UpstreamModel    string
	PromptTokens     int
	CompletionTokens int
}

// UpstreamHTTPError identifies an explicit non-success HTTP response. Network,
// parsing and streaming errors must never be classified by their message text.
type UpstreamHTTPError struct {
	StatusCode int
	Body       string
}

func (e *UpstreamHTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, strings.TrimSpace(e.Body))
}

func isRetryableUpstreamError(err error) bool {
	var httpErr *UpstreamHTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	switch httpErr.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

var keySeq uint64

func pickAPIKey(raw string) string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';'
	})
	var clean []string
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			clean = append(clean, t)
		}
	}
	if len(clean) == 0 {
		return ""
	}
	idx := atomic.AddUint64(&keySeq, 1) % uint64(len(clean))
	return clean[idx]
}

// transportMiddleware adds common headers to all outgoing requests.
type transportMiddleware struct {
	base http.RoundTripper
}

func (t *transportMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "CherryStudio/1.0.0") // Emulate a browser-like client
	return t.base.RoundTrip(req)
}

func buildHTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 120 * time.Second, // Increase to 120s
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second, // Add explicit TLS handshake timeout
	}
	if strings.TrimSpace(proxyURL) != "" {
		if parsed, err := url.Parse(strings.TrimSpace(proxyURL)); err == nil {
			tr.Proxy = http.ProxyURL(parsed)
		}
	}
	return &http.Client{
		Transport: &transportMiddleware{base: tr},
		Timeout:   timeout,
	}
}

func thinkingBudgetTokens(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "off":
		return 0
	case "low":
		return 1024
	case "medium":
		return 4096
	case "high":
		return 8192
	case "extra":
		return 16384
	case "max":
		return 32000
	default:
		return 4096
	}
}

func openaiReasoningEffort(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "off":
		return ""
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high", "extra", "max":
		return "high"
	default:
		return "medium"
	}
}

// sanitizeCapabilities filters request attachments/tools/thinking according to the ClientModel's configured Modalities & limits.
func EnforceModelCapabilities(cm store.ClientModel, req ChatRequest) ChatRequest {
	out := req
	if cm.SystemPromptPrefix != "" {
		if out.SystemPrompt != "" {
			out.SystemPrompt = cm.SystemPromptPrefix + "\n\n" + out.SystemPrompt
		} else {
			out.SystemPrompt = cm.SystemPromptPrefix
		}
	}
	if out.MaxTokens <= 0 || out.MaxTokens > cm.MaxOutputTokens {
		out.MaxTokens = cm.MaxOutputTokens
	}
	if cm.Temperature != nil {
		out.Temperature = cm.Temperature
	}
	if !cm.Modalities.Tools {
		out.Tools = nil
	}
	if !cm.Modalities.Reasoning {
		out.ThinkingLevel = "off"
	} else if len(cm.SupportedThinkingLevels) > 0 {
		supported := false
		for _, l := range cm.SupportedThinkingLevels {
			if l == out.ThinkingLevel {
				supported = true
				break
			}
		}
		if !supported {
			out.ThinkingLevel = cm.DefaultThinkingLevel
		}
	}

	// Filter disallowed modalities in attachments
	msgs := make([]ChatMessage, len(out.Messages))
	for i, m := range out.Messages {
		cp := m
		if len(m.Attachments) > 0 {
			var allowed []MediaPart
			for _, att := range m.Attachments {
				mt := strings.ToLower(att.MimeType)
				switch {
				case strings.HasPrefix(mt, "image/"):
					if cm.Modalities.Vision {
						allowed = append(allowed, att)
					}
				case strings.HasPrefix(mt, "audio/"):
					if cm.Modalities.Audio {
						allowed = append(allowed, att)
					}
				case mt == "application/pdf":
					if cm.Modalities.PDF {
						allowed = append(allowed, att)
					}
				default:
					allowed = append(allowed, att)
				}
			}
			cp.Attachments = allowed
		}
		msgs[i] = cp
	}
	out.Messages = msgs
	return out
}

// ExecuteRoutedChat dispatches a ChatRequest across the configured Magpie routes with priority grouping, weighted round-robin, and automatic failover.
func ExecuteRoutedChat(
	ctx context.Context,
	st *store.Store,
	cm store.ClientModel,
	rawReq ChatRequest,
	cb StreamCallbacks,
) (ExecutionResult, error) {
	req := EnforceModelCapabilities(cm, rawReq)

	if len(cm.Routes) == 0 {
		return ExecutionResult{}, errors.New("该模型尚未绑定任何上游渠道路由")
	}

	// Group active routes by Priority
	type activeRoute struct {
		route store.ModelRoute
		prov  store.UpstreamProvider
	}
	var candidates []activeRoute
	for _, r := range cm.Routes {
		prov, ok := st.GetProvider(r.ProviderID)
		if !ok || !prov.Enabled {
			continue
		}
		if prov.Protocol != "sanctum-local" && strings.TrimSpace(prov.APIKey) == "" && !isKeylessLocalEndpoint(prov.BaseURL) {
			continue
		}
		if r.Weight <= 0 {
			r.Weight = 100
		}
		candidates = append(candidates, activeRoute{route: r, prov: prov})
	}

	if len(candidates) == 0 {
		return ExecutionResult{}, errors.New("该模型绑定的上游渠道均未启用或未填写 API Key，请在管理后台配置渠道")
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].route.Priority < candidates[j].route.Priority
	})

	// Order within each priority tier using weighted round-robin rotation
	var ordered []activeRoute
	for i := 0; i < len(candidates); {
		j := i + 1
		for j < len(candidates) && candidates[j].route.Priority == candidates[i].route.Priority {
			j++
		}
		tier := append([]activeRoute(nil), candidates[i:j]...)
		if len(tier) > 1 {
			totalWeight := 0
			for _, t := range tier {
				totalWeight += t.route.Weight
			}
			pick := int(st.NextRoundRobin() % uint64(maxInt(totalWeight, 1)))
			acc := 0
			startIdx := 0
			for idx, t := range tier {
				acc += t.route.Weight
				if pick < acc {
					startIdx = idx
					break
				}
			}
			for k := 0; k < len(tier); k++ {
				ordered = append(ordered, tier[(startIdx+k)%len(tier)])
			}
		} else {
			ordered = append(ordered, tier[0])
		}
		i = j
	}

	var errs []string
	var lastResult ExecutionResult
	for _, cand := range ordered {
		if err := ctx.Err(); err != nil {
			return lastResult, err
		}
		emitted := false
		wrappedCB := StreamCallbacks{
			OnThinkingDelta: func(d string) {
				emitted = true
				if cb.OnThinkingDelta != nil {
					cb.OnThinkingDelta(d)
				}
			},
			OnTextDelta: func(d string) {
				emitted = true
				if cb.OnTextDelta != nil {
					cb.OnTextDelta(d)
				}
			},
			OnToolCall: func(tc ToolCallSpec) {
				emitted = true
				if cb.OnToolCall != nil {
					cb.OnToolCall(tc)
				}
			},
			OnUsage: func(p, c int) {
				emitted = true
				if cb.OnUsage != nil {
					cb.OnUsage(p, c)
				}
			},
		}

		var err error
		for attempt := 0; attempt < 3; attempt++ {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return lastResult, ctxErr
			}
			pTokens, cTokens, attemptErr := dispatchSingleProvider(ctx, cand.prov, cand.route.UpstreamModel, req, wrappedCB)
			err = attemptErr
			lastResult = ExecutionResult{
				ProviderID:       cand.prov.ID,
				ProviderName:     cand.prov.Name,
				Protocol:         cand.prov.Protocol,
				UpstreamModel:    cand.route.UpstreamModel,
				PromptTokens:     pTokens,
				CompletionTokens: cTokens,
			}
			if err == nil {
				return lastResult, nil
			}
			// Any callback (even usage-only or an empty delta) commits this route.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return lastResult, ctxErr
			}
			if emitted {
				return lastResult, err
			}
			if !isRetryableUpstreamError(err) || attempt == 2 {
				break
			}
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return lastResult, ctx.Err()
			case <-timer.C:
			}
		}
		errs = append(errs, fmt.Sprintf("[%s/%s]: %v", cand.prov.Name, cand.route.UpstreamModel, err))
	}

	return lastResult, fmt.Errorf("所有上游路由尝试失败: %s", strings.Join(errs, " | "))
}

func isKeylessLocalEndpoint(baseURL string) bool {
	u := strings.ToLower(strings.TrimSpace(baseURL))
	return strings.Contains(u, "localhost") || strings.Contains(u, "127.0.0.1")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func dispatchSingleProvider(
	ctx context.Context,
	prov store.UpstreamProvider,
	upstreamModel string,
	req ChatRequest,
	cb StreamCallbacks,
) (int, int, error) {
	switch strings.ToLower(strings.TrimSpace(prov.Protocol)) {
	case "openai", "":
		return callOpenAIChat(ctx, prov, upstreamModel, req, cb)
	case "openai-responses":
		return callOpenAIResponses(ctx, prov, upstreamModel, req, cb)
	case "anthropic":
		return callAnthropicMessages(ctx, prov, upstreamModel, req, cb)
	case "gemini":
		return callGeminiGenerate(ctx, prov, upstreamModel, req, cb)
	case "sanctum-local":
		return callSanctumLocal(ctx, prov, upstreamModel, req, cb)
	default:
		return 0, 0, fmt.Errorf("未知上游协议类型: %s", prov.Protocol)
	}
}

func DiscoverProviderModels(ctx context.Context, prov store.UpstreamProvider) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(prov.Protocol)) {
	case "openai", "openai-responses", "":
		return discoverOpenAIModels(ctx, prov)
	case "anthropic":
		return discoverAnthropicModels(ctx, prov)
	case "gemini":
		return discoverGeminiModels(ctx, prov)
	case "sanctum-local":
		return []string{"sanctum-agentic-v1"}, nil
	default:
		return nil, fmt.Errorf("不支持协议 %s 的模型自动探测", prov.Protocol)
	}
}
