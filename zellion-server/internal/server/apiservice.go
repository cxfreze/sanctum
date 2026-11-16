package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"zellion-server/internal/providers"
	"zellion-server/internal/store"
	"zellion-server/internal/tlsutil"
)

type APIServiceStatus struct {
	Enabled       bool   `json:"enabled"`
	Running       bool   `json:"running"`
	HTTPSPort     int    `json:"httpsPort"`
	HTTPSAddr     string `json:"httpsAddr"`
	HTTPGuardPort int    `json:"httpGuardPort"`
	HTTPGuardOn   bool   `json:"httpGuardOn"`
	SharedPort    bool   `json:"sharedPort"`
	LastError     string `json:"lastError,omitempty"`
}

type apiListenerManager struct {
	mu            sync.Mutex
	httpsSrv      *http.Server
	httpsLn       net.Listener
	httpGuardSrv  *http.Server
	httpGuardLn   net.Listener
	running       bool
	sharedPort    bool
	httpsAddr     string
	httpGuardOn   bool
	lastError     string
}

func (s *GatewayServer) CloseAPIService() {
	s.apiMgr.mu.Lock()
	defer s.apiMgr.mu.Unlock()
	s.stopAPIListenersLocked()
}

func (s *GatewayServer) stopAPIListenersLocked() {
	if s.apiMgr.httpsSrv != nil {
		_ = s.apiMgr.httpsSrv.Close()
		s.apiMgr.httpsSrv = nil
	}
	if s.apiMgr.httpsLn != nil {
		_ = s.apiMgr.httpsLn.Close()
		s.apiMgr.httpsLn = nil
	}
	if s.apiMgr.httpGuardSrv != nil {
		_ = s.apiMgr.httpGuardSrv.Close()
		s.apiMgr.httpGuardSrv = nil
	}
	if s.apiMgr.httpGuardLn != nil {
		_ = s.apiMgr.httpGuardLn.Close()
		s.apiMgr.httpGuardLn = nil
	}
	s.apiMgr.running = false
	s.apiMgr.sharedPort = false
	s.apiMgr.httpsAddr = ""
	s.apiMgr.httpGuardOn = false
}

func (s *GatewayServer) SyncAPIServiceListeners() APIServiceStatus {
	s.apiMgr.mu.Lock()
	defer s.apiMgr.mu.Unlock()

	s.stopAPIListenersLocked()
	s.apiMgr.lastError = ""

	apiCfg := s.store.GetAPIConfig()
	zsCfg := s.zsMgr.Get()

	if !apiCfg.Enabled {
		return s.buildAPIStatusLocked(apiCfg)
	}

	certPath := s.zsMgr.ResolvePath(zsCfg.TLSCertFile)
	keyPath := s.zsMgr.ResolvePath(zsCfg.TLSKeyFile)
	info := tlsutil.InspectCertFiles(certPath, keyPath)
	if !info.Valid {
		displayHost := zsCfg.Host
		if displayHost == "" || displayHost == "0.0.0.0" || displayHost == "::" {
			displayHost = "127.0.0.1"
		}
		if genErr := tlsutil.GenerateSelfSignedCert(certPath, keyPath, []string{"localhost", "127.0.0.1", displayHost}); genErr != nil {
			s.apiMgr.lastError = "初始化 TLS 证书失败: " + genErr.Error()
			return s.buildAPIStatusLocked(apiCfg)
		}
		s.certLoader.UpdatePaths(certPath, keyPath)
	}

	if zsCfg.TLSEnabled && zsCfg.Port == apiCfg.HTTPSPort {
		s.apiMgr.running = true
		s.apiMgr.sharedPort = true
		s.apiMgr.httpsAddr = fmt.Sprintf("%s:%d", zsCfg.Host, apiCfg.HTTPSPort)
	} else {
		bindAddr := fmt.Sprintf("%s:%d", zsCfg.Host, apiCfg.HTTPSPort)
		rawLn, err := net.Listen("tcp", bindAddr)
		if err != nil {
			s.apiMgr.lastError = fmt.Sprintf("HTTPS 端口 %s 监听失败: %v", bindAddr, err)
			return s.buildAPIStatusLocked(apiCfg)
		}
		tlsCfg := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: s.certLoader.GetCertificate,
		}
		tlsLn := tls.NewListener(rawLn, tlsCfg)
		srv := &http.Server{
			Handler:           http.HandlerFunc(s.ServePublicAPIHTTP),
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		s.apiMgr.httpsLn = tlsLn
		s.apiMgr.httpsSrv = srv
		s.apiMgr.running = true
		s.apiMgr.httpsAddr = rawLn.Addr().String()
		go func() {
			_ = srv.Serve(tlsLn)
		}()
	}

	if apiCfg.RedirectHTTP80 && apiCfg.HTTPPort > 0 && apiCfg.HTTPPort != apiCfg.HTTPSPort && apiCfg.HTTPPort != zsCfg.Port {
		guardAddr := fmt.Sprintf("%s:%d", zsCfg.Host, apiCfg.HTTPPort)
		if gLn, gErr := net.Listen("tcp", guardAddr); gErr == nil {
			gSrv := &http.Server{
				Handler:           http.HandlerFunc(s.ServeHTTPGuard),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       30 * time.Second,
			}
			s.apiMgr.httpGuardLn = gLn
			s.apiMgr.httpGuardSrv = gSrv
			s.apiMgr.httpGuardOn = true
			go func() {
				_ = gSrv.Serve(gLn)
			}()
		}
	} else if apiCfg.RedirectHTTP80 && !zsCfg.TLSEnabled && zsCfg.Port == apiCfg.HTTPPort {
		s.apiMgr.httpGuardOn = true
	}

	return s.buildAPIStatusLocked(apiCfg)
}

func (s *GatewayServer) GetAPIServiceStatus() APIServiceStatus {
	apiCfg := s.store.GetAPIConfig()
	s.apiMgr.mu.Lock()
	defer s.apiMgr.mu.Unlock()
	return s.buildAPIStatusLocked(apiCfg)
}

func (s *GatewayServer) buildAPIStatusLocked(apiCfg store.APIServiceConfig) APIServiceStatus {
	return APIServiceStatus{
		Enabled:       apiCfg.Enabled,
		Running:       s.apiMgr.running,
		HTTPSPort:     apiCfg.HTTPSPort,
		HTTPSAddr:     s.apiMgr.httpsAddr,
		HTTPGuardPort: apiCfg.HTTPPort,
		HTTPGuardOn:   s.apiMgr.httpGuardOn,
		SharedPort:    s.apiMgr.sharedPort,
		LastError:     s.apiMgr.lastError,
	}
}

func extractExternalAPIKey(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		if tok := strings.TrimSpace(auth[7:]); tok != "" {
			return tok
		}
	}
	if k := strings.TrimSpace(r.Header.Get("x-api-key")); k != "" {
		return k
	}
	if k := strings.TrimSpace(r.Header.Get("x-goog-api-key")); k != "" {
		return k
	}
	if k := strings.TrimSpace(r.URL.Query().Get("key")); k != "" {
		return k
	}
	return ""
}

func isPublicAPIPath(path string) bool {
	switch path {
	case "/v1/models", "/models",
		"/v1/chat/completions", "/chat/completions",
		"/v1/responses", "/responses",
		"/v1/messages", "/messages":
		return true
	}
	return strings.HasPrefix(path, "/v1beta/models/")
}

func writeAPIError(w http.ResponseWriter, status int, errType, msg string) {
	writeJSON(w, status, map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    errType,
			"message": msg,
		},
	})
}

func (s *GatewayServer) ServeHTTPGuard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions && isPublicAPIPath(r.URL.Path) {
		setPublicAPICORS(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if extractExternalAPIKey(r) != "" && isPublicAPIPath(r.URL.Path) {
		setPublicAPICORS(w)
		writeAPIError(w, http.StatusForbidden, "https_required", "对外 API 服务仅支持 HTTPS 访问")
		return
	}
	writeBlankStealth(w)
}

func setPublicAPICORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, x-api-key, anthropic-version, anthropic-beta, x-goog-api-key")
}

func (s *GatewayServer) ServePublicAPIHTTP(w http.ResponseWriter, r *http.Request) {
	setPublicAPICORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	rawKey := extractExternalAPIKey(r)
	if rawKey == "" {
		writeBlankStealth(w)
		return
	}

	if r.TLS == nil {
		writeAPIError(w, http.StatusForbidden, "https_required", "对外 API 服务仅支持 HTTPS 加密访问")
		return
	}

	apiCfg := s.store.GetAPIConfig()
	if !apiCfg.Enabled {
		writeAPIError(w, http.StatusServiceUnavailable, "service_disabled", "对外 API 服务当前未启用")
		return
	}

	keyEntry, authed := s.store.AuthenticateAPIKey(rawKey)
	if !authed {
		writeAPIError(w, http.StatusUnauthorized, "authentication_error", "无效或已禁用的 API Key")
		return
	}

	path := r.URL.Path
	switch {
	case (path == "/v1/models" || path == "/models") && r.Method == http.MethodGet:
		s.handlePublicAPIModels(w, keyEntry)

	case (path == "/v1/chat/completions" || path == "/chat/completions") && r.Method == http.MethodPost:
		s.handlePublicOpenAIChat(w, r, keyEntry)

	case (path == "/v1/responses" || path == "/responses") && r.Method == http.MethodPost:
		s.handlePublicOpenAIResponses(w, r, keyEntry)

	case (path == "/v1/messages" || path == "/messages") && r.Method == http.MethodPost:
		s.handlePublicAnthropicMessages(w, r, keyEntry)

	case strings.HasPrefix(path, "/v1beta/models/") && r.Method == http.MethodPost:
		s.handlePublicGemini(w, r, keyEntry)

	default:
		writeAPIError(w, http.StatusNotFound, "not_found_error", "未知的 API 路径")
	}
}

func (s *GatewayServer) handlePublicAPIModels(w http.ResponseWriter, keyEntry store.APIKeyEntry) {
	models := s.store.ListAllowedAPIModels(keyEntry)
	data := make([]map[string]any, 0, len(models))
	nowUnix := time.Now().Unix()
	for _, m := range models {
		owner := m.ProviderLabel
		if owner == "" {
			owner = "zellion"
		}
		data = append(data, map[string]any{
			"id":                m.ID,
			"object":            "model",
			"created":           nowUnix,
			"owned_by":          owner,
			"display_name":      m.DisplayName,
			"context_window":    m.ContextWindow,
			"max_output_tokens": m.MaxOutputTokens,
			"modalities":        m.Modalities,
			"group_id":          m.GroupID,
			"group_name":        m.GroupName,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
	})
}

func parseDataURLAttachment(name, dataURL, fallbackMime string) (providers.MediaPart, bool) {
	s := strings.TrimSpace(dataURL)
	if !strings.HasPrefix(strings.ToLower(s), "data:") {
		return providers.MediaPart{}, false
	}
	comma := strings.Index(s, ",")
	if comma <= 5 {
		return providers.MediaPart{}, false
	}
	meta := s[5:comma]
	b64 := strings.TrimSpace(s[comma+1:])
	mime := fallbackMime
	if semi := strings.Index(meta, ";"); semi > 0 {
		mime = meta[:semi]
	} else if meta != "" {
		mime = meta
	}
	if mime == "" {
		mime = "application/octet-stream"
	}
	return providers.MediaPart{
		MimeType:   mime,
		DataBase64: b64,
	}, b64 != ""
}

func (s *GatewayServer) handlePublicOpenAIChat(w http.ResponseWriter, r *http.Request, keyEntry store.APIKeyEntry) {
	var body struct {
		Model               string            `json:"model"`
		Messages            []json.RawMessage `json:"messages"`
		Tools               []json.RawMessage `json:"tools"`
		Stream              bool              `json:"stream"`
		MaxTokens           int               `json:"max_tokens"`
		MaxCompletionTokens int               `json:"max_completion_tokens"`
		Temperature         *float64          `json:"temperature"`
		ReasoningEffort     string            `json:"reasoning_effort"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 50*1024*1024)).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "无效的 JSON 请求体")
		return
	}

	cm, ok := s.store.GetAllowedAPIModel(keyEntry, strings.TrimSpace(body.Model))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "model_not_found", "当前 API Key 无权访问该模型")
		return
	}

	var sysParts []string
	var chatMsgs []providers.ChatMessage

	for _, rawMsg := range body.Messages {
		var m struct {
			Role             string          `json:"role"`
			Content          json.RawMessage `json:"content"`
			ReasoningContent string          `json:"reasoning_content"`
			ToolCallID       string          `json:"tool_call_id"`
			Name             string          `json:"name"`
			ToolCalls        []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		}
		if err := json.Unmarshal(rawMsg, &m); err != nil {
			continue
		}

		textContent, attachments := extractOpenAIContentParts(m.Content)
		role := strings.ToLower(strings.TrimSpace(m.Role))
		switch role {
		case "system", "developer":
			if strings.TrimSpace(textContent) != "" {
				sysParts = append(sysParts, textContent)
			}
		case "user":
			chatMsgs = append(chatMsgs, providers.ChatMessage{
				Role:        "user",
				Content:     textContent,
				Attachments: attachments,
			})
		case "assistant":
			var tcs []providers.ToolCallSpec
			for _, tc := range m.ToolCalls {
				tcs = append(tcs, providers.ToolCallSpec{
					ID:        tc.ID,
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				})
			}
			chatMsgs = append(chatMsgs, providers.ChatMessage{
				Role:      "assistant",
				Content:   textContent,
				Thinking:  m.ReasoningContent,
				ToolCalls: tcs,
			})
		case "tool":
			chatMsgs = append(chatMsgs, providers.ChatMessage{
				Role:       "tool",
				Content:    textContent,
				ToolCallID: m.ToolCallID,
				ToolName:   m.Name,
			})
		}
	}

	var toolDefs []providers.ToolDefinition
	for _, rawT := range body.Tools {
		var td struct {
			Type     string `json:"type"`
			Function struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		}
		if err := json.Unmarshal(rawT, &td); err == nil && td.Function.Name != "" {
			toolDefs = append(toolDefs, providers.ToolDefinition{
				Name:        td.Function.Name,
				Description: td.Function.Description,
				InputSchema: td.Function.Parameters,
			})
		}
	}

	maxTok := body.MaxCompletionTokens
	if maxTok <= 0 {
		maxTok = body.MaxTokens
	}
	thinkLvl := strings.ToLower(strings.TrimSpace(body.ReasoningEffort))
	if thinkLvl == "" {
		thinkLvl = cm.DefaultThinkingLevel
	}

	chatReq := providers.ChatRequest{
		Model:         cm.ID,
		SystemPrompt:  strings.Join(sysParts, "\n\n"),
		Messages:      chatMsgs,
		Tools:         toolDefs,
		ThinkingLevel: thinkLvl,
		MaxTokens:     maxTok,
		Temperature:   body.Temperature,
		Stream:        body.Stream,
	}

	s.store.TouchAPIKeyUsage(keyEntry.ID)
	start := time.Now()
	completionID := fmt.Sprintf("chatcmpl-zs-%d", time.Now().UnixNano())
	createdUnix := time.Now().Unix()

	if !body.Stream {
		var textBuf, thinkBuf strings.Builder
		var toolCalls []providers.ToolCallSpec
		execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, chatReq, providers.StreamCallbacks{
			OnThinkingDelta: func(d string) { thinkBuf.WriteString(d) },
			OnTextDelta:     func(d string) { textBuf.WriteString(d) },
			OnToolCall:      func(tc providers.ToolCallSpec) { toolCalls = append(toolCalls, tc) },
		})
		s.recordAPILog(keyEntry, cm, chatReq.ThinkingLevel, execRes, time.Since(start).Milliseconds(), err)
		if err != nil {
			writeAPIError(w, http.StatusBadGateway, "upstream_error", err.Error())
			return
		}

		msgMap := map[string]any{
			"role":    "assistant",
			"content": textBuf.String(),
		}
		if thinkBuf.Len() > 0 {
			msgMap["reasoning_content"] = thinkBuf.String()
		}
		finishReason := "stop"
		if len(toolCalls) > 0 {
			finishReason = "tool_calls"
			outTC := make([]map[string]any, 0, len(toolCalls))
			for _, tc := range toolCalls {
				outTC = append(outTC, map[string]any{
					"id":   tc.ID,
					"type": "function",
					"function": map[string]any{
						"name":      tc.Name,
						"arguments": tc.Arguments,
					},
				})
			}
			msgMap["tool_calls"] = outTC
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":      completionID,
			"object":  "chat.completion",
			"created": createdUnix,
			"model":   cm.ID,
			"choices": []map[string]any{
				{
					"index":         0,
					"message":       msgMap,
					"finish_reason": finishReason,
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     execRes.PromptTokens,
				"completion_tokens": execRes.CompletionTokens,
				"total_tokens":      execRes.PromptTokens + execRes.CompletionTokens,
			},
		})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "server_error", "Streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	writeChunk := func(delta map[string]any, finish any, usage map[string]any) {
		chunk := map[string]any{
			"id":      completionID,
			"object":  "chat.completion.chunk",
			"created": createdUnix,
			"model":   cm.ID,
			"choices": []map[string]any{
				{
					"index":         0,
					"delta":         delta,
					"finish_reason": finish,
				},
			},
		}
		if usage != nil {
			chunk["usage"] = usage
		}
		b, _ := json.Marshal(chunk)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	writeChunk(map[string]any{"role": "assistant"}, nil, nil)

	toolIdx := 0
	hasToolCalls := false
	execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, chatReq, providers.StreamCallbacks{
		OnThinkingDelta: func(d string) {
			if d != "" {
				writeChunk(map[string]any{"reasoning_content": d}, nil, nil)
			}
		},
		OnTextDelta: func(d string) {
			if d != "" {
				writeChunk(map[string]any{"content": d}, nil, nil)
			}
		},
		OnToolCall: func(tc providers.ToolCallSpec) {
			hasToolCalls = true
			writeChunk(map[string]any{
				"tool_calls": []map[string]any{
					{
						"index": toolIdx,
						"id":    tc.ID,
						"type":  "function",
						"function": map[string]any{
							"name":      tc.Name,
							"arguments": tc.Arguments,
						},
					},
				},
			}, nil, nil)
			toolIdx++
		},
	})
	s.recordAPILog(keyEntry, cm, chatReq.ThinkingLevel, execRes, time.Since(start).Milliseconds(), err)

	if err != nil {
		errPayload, _ := json.Marshal(map[string]any{
			"error": map[string]any{"type": "upstream_error", "message": err.Error()},
		})
		_, _ = fmt.Fprintf(w, "data: %s\n\n", errPayload)
		flusher.Flush()
		return
	}

	finishReason := "stop"
	if hasToolCalls {
		finishReason = "tool_calls"
	}
	writeChunk(map[string]any{}, finishReason, map[string]any{
		"prompt_tokens":     execRes.PromptTokens,
		"completion_tokens": execRes.CompletionTokens,
		"total_tokens":      execRes.PromptTokens + execRes.CompletionTokens,
	})
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func extractOpenAIContentParts(raw json.RawMessage) (string, []providers.MediaPart) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return "", nil
	}
	var texts []string
	var atts []providers.MediaPart
	for _, part := range arr {
		t, _ := part["type"].(string)
		switch t {
		case "text", "input_text", "output_text":
			if txt, ok := part["text"].(string); ok && txt != "" {
				texts = append(texts, txt)
			}
		case "image_url", "input_image":
			var u string
			if sUrl, ok := part["image_url"].(string); ok {
				u = sUrl
			} else if mUrl, ok := part["image_url"].(map[string]any); ok {
				u, _ = mUrl["url"].(string)
			}
			if att, ok := parseDataURLAttachment("image", u, "image/png"); ok {
				atts = append(atts, att)
			}
		case "input_audio":
			if aud, ok := part["input_audio"].(map[string]any); ok {
				b64, _ := aud["data"].(string)
				format, _ := aud["format"].(string)
				mime := "audio/wav"
				if format == "mp3" {
					mime = "audio/mpeg"
				}
				if b64 != "" {
					atts = append(atts, providers.MediaPart{
						MimeType:   mime,
						DataBase64: b64,
					})
				}
			}
		case "file", "input_file":
			fObj := part
			if sub, ok := part["file"].(map[string]any); ok {
				fObj = sub
			}
			fdata, _ := fObj["file_data"].(string)
			if att, ok := parseDataURLAttachment("file", fdata, "application/pdf"); ok {
				atts = append(atts, att)
			}
		}
	}
	return strings.Join(texts, "\n"), atts
}

func (s *GatewayServer) handlePublicOpenAIResponses(w http.ResponseWriter, r *http.Request, keyEntry store.APIKeyEntry) {
	var body struct {
		Model           string            `json:"model"`
		Instructions    string            `json:"instructions"`
		Input           json.RawMessage   `json:"input"`
		Tools           []json.RawMessage `json:"tools"`
		Stream          bool              `json:"stream"`
		MaxOutputTokens int               `json:"max_output_tokens"`
		Temperature     *float64          `json:"temperature"`
		Reasoning       struct {
			Effort string `json:"effort"`
		} `json:"reasoning"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 50*1024*1024)).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "无效的 JSON 请求体")
		return
	}

	cm, ok := s.store.GetAllowedAPIModel(keyEntry, strings.TrimSpace(body.Model))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "model_not_found", "当前 API Key 无权访问该模型")
		return
	}

	var msgs []providers.ChatMessage
	var singleInput string
	if err := json.Unmarshal(body.Input, &singleInput); err == nil {
		msgs = append(msgs, providers.ChatMessage{Role: "user", Content: singleInput})
	} else {
		var items []map[string]any
		if err := json.Unmarshal(body.Input, &items); err == nil {
			for _, item := range items {
				itemType, _ := item["type"].(string)
				role, _ := item["role"].(string)
				if itemType == "function_call" {
					callID, _ := item["call_id"].(string)
					name, _ := item["name"].(string)
					args, _ := item["arguments"].(string)
					msgs = append(msgs, providers.ChatMessage{
						Role:      "assistant",
						ToolCalls: []providers.ToolCallSpec{{ID: callID, Name: name, Arguments: args}},
					})
				} else if itemType == "function_call_output" {
					callID, _ := item["call_id"].(string)
					outStr, _ := item["output"].(string)
					msgs = append(msgs, providers.ChatMessage{
						Role:       "tool",
						ToolCallID: callID,
						Content:    outStr,
					})
				} else if role != "" {
					rawContent, _ := json.Marshal(item["content"])
					txt, atts := extractOpenAIContentParts(rawContent)
					msgs = append(msgs, providers.ChatMessage{
						Role:        role,
						Content:     txt,
						Attachments: atts,
					})
				}
			}
		}
	}

	var toolDefs []providers.ToolDefinition
	for _, rawT := range body.Tools {
		var td struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
			Function    struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		}
		if err := json.Unmarshal(rawT, &td); err == nil {
			name := td.Name
			desc := td.Description
			params := td.Parameters
			if name == "" {
				name = td.Function.Name
				desc = td.Description
				params = td.Function.Parameters
			}
			if name != "" {
				toolDefs = append(toolDefs, providers.ToolDefinition{
					Name:        name,
					Description: desc,
					InputSchema: params,
				})
			}
		}
	}

	thinkLvl := strings.ToLower(strings.TrimSpace(body.Reasoning.Effort))
	if thinkLvl == "" {
		thinkLvl = cm.DefaultThinkingLevel
	}

	chatReq := providers.ChatRequest{
		Model:         cm.ID,
		SystemPrompt:  body.Instructions,
		Messages:      msgs,
		Tools:         toolDefs,
		ThinkingLevel: thinkLvl,
		MaxTokens:     body.MaxOutputTokens,
		Temperature:   body.Temperature,
		Stream:        body.Stream,
	}

	s.store.TouchAPIKeyUsage(keyEntry.ID)
	start := time.Now()
	respID := fmt.Sprintf("resp_zs_%d", time.Now().UnixNano())

	if !body.Stream {
		var textBuf, thinkBuf strings.Builder
		var toolCalls []providers.ToolCallSpec
		execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, chatReq, providers.StreamCallbacks{
			OnThinkingDelta: func(d string) { thinkBuf.WriteString(d) },
			OnTextDelta:     func(d string) { textBuf.WriteString(d) },
			OnToolCall:      func(tc providers.ToolCallSpec) { toolCalls = append(toolCalls, tc) },
		})
		s.recordAPILog(keyEntry, cm, chatReq.ThinkingLevel, execRes, time.Since(start).Milliseconds(), err)
		if err != nil {
			writeAPIError(w, http.StatusBadGateway, "upstream_error", err.Error())
			return
		}

		var outputItems []map[string]any
		if thinkBuf.Len() > 0 {
			outputItems = append(outputItems, map[string]any{
				"type": "reasoning",
				"summary": []map[string]any{
					{"type": "summary_text", "text": thinkBuf.String()},
				},
			})
		}
		if textBuf.Len() > 0 || len(toolCalls) == 0 {
			outputItems = append(outputItems, map[string]any{
				"type": "message",
				"role": "assistant",
				"content": []map[string]any{
					{"type": "output_text", "text": textBuf.String()},
				},
			})
		}
		for _, tc := range toolCalls {
			outputItems = append(outputItems, map[string]any{
				"type":      "function_call",
				"call_id":   tc.ID,
				"name":      tc.Name,
				"arguments": tc.Arguments,
			})
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":          respID,
			"object":      "response",
			"created_at":  time.Now().Unix(),
			"status":      "completed",
			"model":       cm.ID,
			"output":      outputItems,
			"output_text": textBuf.String(),
			"usage": map[string]any{
				"input_tokens":  execRes.PromptTokens,
				"output_tokens": execRes.CompletionTokens,
				"total_tokens":  execRes.PromptTokens + execRes.CompletionTokens,
			},
		})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "server_error", "Streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	sendRespEvent := func(evType string, data map[string]any) {
		data["type"] = evType
		b, _ := json.Marshal(data)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evType, b)
		flusher.Flush()
	}

	sendRespEvent("response.created", map[string]any{
		"response": map[string]any{"id": respID, "model": cm.ID, "status": "in_progress"},
	})

	var fullText strings.Builder
	execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, chatReq, providers.StreamCallbacks{
		OnThinkingDelta: func(d string) {
			if d != "" {
				sendRespEvent("response.reasoning_summary_text.delta", map[string]any{"delta": d})
			}
		},
		OnTextDelta: func(d string) {
			if d != "" {
				fullText.WriteString(d)
				sendRespEvent("response.output_text.delta", map[string]any{"delta": d})
			}
		},
		OnToolCall: func(tc providers.ToolCallSpec) {
			sendRespEvent("response.output_item.done", map[string]any{
				"item": map[string]any{
					"type":      "function_call",
					"call_id":   tc.ID,
					"name":      tc.Name,
					"arguments": tc.Arguments,
				},
			})
		},
	})
	s.recordAPILog(keyEntry, cm, chatReq.ThinkingLevel, execRes, time.Since(start).Milliseconds(), err)

	if err != nil {
		sendRespEvent("error", map[string]any{
			"error": map[string]any{"type": "upstream_error", "message": err.Error()},
		})
		return
	}

	sendRespEvent("response.completed", map[string]any{
		"response": map[string]any{
			"id":          respID,
			"model":       cm.ID,
			"status":      "completed",
			"output_text": fullText.String(),
			"usage": map[string]any{
				"input_tokens":  execRes.PromptTokens,
				"output_tokens": execRes.CompletionTokens,
				"total_tokens":  execRes.PromptTokens + execRes.CompletionTokens,
			},
		},
	})
}

func (s *GatewayServer) handlePublicAnthropicMessages(w http.ResponseWriter, r *http.Request, keyEntry store.APIKeyEntry) {
	var body struct {
		Model       string          `json:"model"`
		System      json.RawMessage `json:"system"`
		Messages    []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"input_schema"`
		} `json:"tools"`
		Thinking *struct {
			Type         string `json:"type"`
			BudgetTokens int    `json:"budget_tokens"`
		} `json:"thinking"`
		MaxTokens   int      `json:"max_tokens"`
		Temperature *float64 `json:"temperature"`
		Stream      bool     `json:"stream"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 50*1024*1024)).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "无效的 JSON 请求体")
		return
	}

	cm, ok := s.store.GetAllowedAPIModel(keyEntry, strings.TrimSpace(body.Model))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "not_found_error", "当前 API Key 无权访问该模型")
		return
	}

	var sysPrompt string
	if len(body.System) > 0 {
		if err := json.Unmarshal(body.System, &sysPrompt); err != nil {
			var sysBlocks []struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(body.System, &sysBlocks) == nil {
				var parts []string
				for _, b := range sysBlocks {
					if b.Text != "" {
						parts = append(parts, b.Text)
					}
				}
				sysPrompt = strings.Join(parts, "\n\n")
			}
		}
	}

	var chatMsgs []providers.ChatMessage
	for _, m := range body.Messages {
		var strContent string
		if json.Unmarshal(m.Content, &strContent) == nil {
			chatMsgs = append(chatMsgs, providers.ChatMessage{
				Role:    m.Role,
				Content: strContent,
			})
			continue
		}
		var blocks []map[string]any
		if json.Unmarshal(m.Content, &blocks) != nil {
			continue
		}
		var texts []string
		var thinkings []string
		var atts []providers.MediaPart
		var toolCalls []providers.ToolCallSpec
		var toolResults []providers.ChatMessage

		for _, blk := range blocks {
			bType, _ := blk["type"].(string)
			switch bType {
			case "text":
				if txt, _ := blk["text"].(string); txt != "" {
					texts = append(texts, txt)
				}
			case "thinking":
				if th, _ := blk["thinking"].(string); th != "" {
					thinkings = append(thinkings, th)
				}
			case "image", "document":
				if src, ok := blk["source"].(map[string]any); ok {
					mt, _ := src["media_type"].(string)
					data, _ := src["data"].(string)
					if data != "" {
						atts = append(atts, providers.MediaPart{
							MimeType:   mt,
							DataBase64: data,
						})
					}
				}
			case "tool_use":
				id, _ := blk["id"].(string)
				name, _ := blk["name"].(string)
				inputBytes, _ := json.Marshal(blk["input"])
				toolCalls = append(toolCalls, providers.ToolCallSpec{
					ID:        id,
					Name:      name,
					Arguments: string(inputBytes),
				})
			case "tool_result":
				tcID, _ := blk["tool_use_id"].(string)
				var resText string
				if sRes, ok := blk["content"].(string); ok {
					resText = sRes
				} else {
					bRes, _ := json.Marshal(blk["content"])
					resText = string(bRes)
				}
				toolResults = append(toolResults, providers.ChatMessage{
					Role:       "tool",
					ToolCallID: tcID,
					Content:    resText,
				})
			}
		}

		if len(texts) > 0 || len(atts) > 0 || len(toolCalls) > 0 {
			chatMsgs = append(chatMsgs, providers.ChatMessage{
				Role:        m.Role,
				Content:     strings.Join(texts, "\n"),
				Thinking:    strings.Join(thinkings, "\n"),
				Attachments: atts,
				ToolCalls:   toolCalls,
			})
		}
		chatMsgs = append(chatMsgs, toolResults...)
	}

	var toolDefs []providers.ToolDefinition
	for _, t := range body.Tools {
		if t.Name != "" {
			toolDefs = append(toolDefs, providers.ToolDefinition{
				Name:        t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
			})
		}
	}

	thinkLvl := cm.DefaultThinkingLevel
	if body.Thinking != nil {
		if strings.ToLower(body.Thinking.Type) == "disabled" {
			thinkLvl = "off"
		} else if body.Thinking.BudgetTokens >= 16000 {
			thinkLvl = "extra"
		} else if body.Thinking.BudgetTokens >= 8000 {
			thinkLvl = "high"
		} else if body.Thinking.BudgetTokens >= 2000 {
			thinkLvl = "medium"
		} else if body.Thinking.BudgetTokens > 0 {
			thinkLvl = "low"
		}
	}

	chatReq := providers.ChatRequest{
		Model:         cm.ID,
		SystemPrompt:  sysPrompt,
		Messages:      chatMsgs,
		Tools:         toolDefs,
		ThinkingLevel: thinkLvl,
		MaxTokens:     body.MaxTokens,
		Temperature:   body.Temperature,
		Stream:        body.Stream,
	}

	s.store.TouchAPIKeyUsage(keyEntry.ID)
	start := time.Now()
	msgID := fmt.Sprintf("msg_zs_%d", time.Now().UnixNano())

	if !body.Stream {
		var textBuf, thinkBuf strings.Builder
		var toolCalls []providers.ToolCallSpec
		execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, chatReq, providers.StreamCallbacks{
			OnThinkingDelta: func(d string) { thinkBuf.WriteString(d) },
			OnTextDelta:     func(d string) { textBuf.WriteString(d) },
			OnToolCall:      func(tc providers.ToolCallSpec) { toolCalls = append(toolCalls, tc) },
		})
		s.recordAPILog(keyEntry, cm, chatReq.ThinkingLevel, execRes, time.Since(start).Milliseconds(), err)
		if err != nil {
			writeAPIError(w, http.StatusBadGateway, "api_error", err.Error())
			return
		}

		var contentBlocks []map[string]any
		if thinkBuf.Len() > 0 {
			contentBlocks = append(contentBlocks, map[string]any{
				"type":     "thinking",
				"thinking": thinkBuf.String(),
			})
		}
		if textBuf.Len() > 0 || len(toolCalls) == 0 {
			contentBlocks = append(contentBlocks, map[string]any{
				"type": "text",
				"text": textBuf.String(),
			})
		}
		stopReason := "end_turn"
		for _, tc := range toolCalls {
			stopReason = "tool_use"
			var inputObj any = map[string]any{}
			if strings.TrimSpace(tc.Arguments) != "" {
				_ = json.Unmarshal([]byte(tc.Arguments), &inputObj)
			}
			contentBlocks = append(contentBlocks, map[string]any{
				"type":  "tool_use",
				"id":    tc.ID,
				"name":  tc.Name,
				"input": inputObj,
			})
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":            msgID,
			"type":          "message",
			"role":          "assistant",
			"model":         cm.ID,
			"content":       contentBlocks,
			"stop_reason":   stopReason,
			"stop_sequence": nil,
			"usage": map[string]any{
				"input_tokens":  execRes.PromptTokens,
				"output_tokens": execRes.CompletionTokens,
			},
		})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "api_error", "Streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	sendAnthEvent := func(ev string, payload map[string]any) {
		payload["type"] = ev
		b, _ := json.Marshal(payload)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev, b)
		flusher.Flush()
	}

	sendAnthEvent("message_start", map[string]any{
		"message": map[string]any{
			"id":      msgID,
			"type":    "message",
			"role":    "assistant",
			"model":   cm.ID,
			"content": []any{},
			"usage":   map[string]any{"input_tokens": 0, "output_tokens": 0},
		},
	})

	blockIndex := -1
	activeKind := "" // "thinking" | "text"
	closeActiveBlock := func() {
		if activeKind != "" && blockIndex >= 0 {
			sendAnthEvent("content_block_stop", map[string]any{"index": blockIndex})
			activeKind = ""
		}
	}

	hasToolUse := false
	execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, chatReq, providers.StreamCallbacks{
		OnThinkingDelta: func(d string) {
			if d == "" {
				return
			}
			if activeKind != "thinking" {
				closeActiveBlock()
				blockIndex++
				activeKind = "thinking"
				sendAnthEvent("content_block_start", map[string]any{
					"index":         blockIndex,
					"content_block": map[string]any{"type": "thinking", "thinking": ""},
				})
			}
			sendAnthEvent("content_block_delta", map[string]any{
				"index": blockIndex,
				"delta": map[string]any{"type": "thinking_delta", "thinking": d},
			})
		},
		OnTextDelta: func(d string) {
			if d == "" {
				return
			}
			if activeKind != "text" {
				closeActiveBlock()
				blockIndex++
				activeKind = "text"
				sendAnthEvent("content_block_start", map[string]any{
					"index":         blockIndex,
					"content_block": map[string]any{"type": "text", "text": ""},
				})
			}
			sendAnthEvent("content_block_delta", map[string]any{
				"index": blockIndex,
				"delta": map[string]any{"type": "text_delta", "text": d},
			})
		},
		OnToolCall: func(tc providers.ToolCallSpec) {
			hasToolUse = true
			closeActiveBlock()
			blockIndex++
			sendAnthEvent("content_block_start", map[string]any{
				"index": blockIndex,
				"content_block": map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": map[string]any{},
				},
			})
			args := tc.Arguments
			if strings.TrimSpace(args) == "" {
				args = "{}"
			}
			sendAnthEvent("content_block_delta", map[string]any{
				"index": blockIndex,
				"delta": map[string]any{"type": "input_json_delta", "partial_json": args},
			})
			sendAnthEvent("content_block_stop", map[string]any{"index": blockIndex})
		},
	})
	closeActiveBlock()
	s.recordAPILog(keyEntry, cm, chatReq.ThinkingLevel, execRes, time.Since(start).Milliseconds(), err)

	if err != nil {
		sendAnthEvent("error", map[string]any{
			"error": map[string]any{"type": "api_error", "message": err.Error()},
		})
		return
	}

	stopReason := "end_turn"
	if hasToolUse {
		stopReason = "tool_use"
	}
	sendAnthEvent("message_delta", map[string]any{
		"delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
		"usage": map[string]any{
			"input_tokens":  execRes.PromptTokens,
			"output_tokens": execRes.CompletionTokens,
		},
	})
	sendAnthEvent("message_stop", map[string]any{})
}

func (s *GatewayServer) handlePublicGemini(w http.ResponseWriter, r *http.Request, keyEntry store.APIKeyEntry) {
	tail := strings.TrimPrefix(r.URL.Path, "/v1beta/models/")
	colon := strings.Index(tail, ":")
	if colon <= 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "无效的 Gemini 请求路径")
		return
	}
	modelID := tail[:colon]
	action := tail[colon+1:]
	isStream := action == "streamGenerateContent"

	cm, ok := s.store.GetAllowedAPIModel(keyEntry, modelID)
	if !ok {
		writeAPIError(w, http.StatusNotFound, "model_not_found", fmt.Sprintf("当前 API Key 无权访问模型 %q", modelID))
		return
	}

	var body struct {
		SystemInstruction *struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"systemInstruction"`
		Contents []struct {
			Role  string `json:"role"`
			Parts []struct {
				Text       string `json:"text"`
				InlineData *struct {
					MimeType string `json:"mimeType"`
					Data     string `json:"data"`
				} `json:"inlineData"`
			} `json:"parts"`
		} `json:"contents"`
		GenerationConfig struct {
			MaxOutputTokens int      `json:"maxOutputTokens"`
			Temperature     *float64 `json:"temperature"`
		} `json:"generationConfig"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 50*1024*1024)).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "无效的 JSON 请求体")
		return
	}

	var sysPrompt string
	if body.SystemInstruction != nil {
		var sp []string
		for _, p := range body.SystemInstruction.Parts {
			if p.Text != "" {
				sp = append(sp, p.Text)
			}
		}
		sysPrompt = strings.Join(sp, "\n")
	}

	var msgs []providers.ChatMessage
	for _, c := range body.Contents {
		role := "user"
		if c.Role == "model" {
			role = "assistant"
		}
		var texts []string
		var atts []providers.MediaPart
		for _, p := range c.Parts {
			if p.Text != "" {
				texts = append(texts, p.Text)
			}
			if p.InlineData != nil && p.InlineData.Data != "" {
				atts = append(atts, providers.MediaPart{
					MimeType:   p.InlineData.MimeType,
					DataBase64: p.InlineData.Data,
				})
			}
		}
		msgs = append(msgs, providers.ChatMessage{
			Role:        role,
			Content:     strings.Join(texts, "\n"),
			Attachments: atts,
		})
	}

	chatReq := providers.ChatRequest{
		Model:         cm.ID,
		SystemPrompt:  sysPrompt,
		Messages:      msgs,
		ThinkingLevel: cm.DefaultThinkingLevel,
		MaxTokens:     body.GenerationConfig.MaxOutputTokens,
		Temperature:   body.GenerationConfig.Temperature,
		Stream:        isStream,
	}

	s.store.TouchAPIKeyUsage(keyEntry.ID)
	start := time.Now()

	var textBuf strings.Builder
	execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, chatReq, providers.StreamCallbacks{
		OnTextDelta: func(d string) { textBuf.WriteString(d) },
	})
	s.recordAPILog(keyEntry, cm, chatReq.ThinkingLevel, execRes, time.Since(start).Milliseconds(), err)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}

	respObj := map[string]any{
		"candidates": []map[string]any{
			{
				"content": map[string]any{
					"role":  "model",
					"parts": []map[string]any{{"text": textBuf.String()}},
				},
				"finishReason": "STOP",
			},
		},
		"usageMetadata": map[string]any{
			"promptTokenCount":     execRes.PromptTokens,
			"candidatesTokenCount": execRes.CompletionTokens,
			"totalTokenCount":      execRes.PromptTokens + execRes.CompletionTokens,
		},
	}

	if isStream && strings.ToLower(r.URL.Query().Get("alt")) == "sse" {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		b, _ := json.Marshal(respObj)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		return
	}
	writeJSON(w, http.StatusOK, respObj)
}

func (s *GatewayServer) recordAPILog(
	keyEntry store.APIKeyEntry,
	cm store.ClientModel,
	thinkingLevel string,
	execRes providers.ExecutionResult,
	latMs int64,
	err error,
) {
	status := "ok"
	errStr := ""
	if err != nil {
		status = "error"
		errStr = err.Error()
	}
	s.store.AppendAPILog(store.RequestLog{
		APIKeyID:         keyEntry.ID,
		APIKeyName:       keyEntry.Name,
		ClientModelID:    cm.ID,
		ClientModelName:  cm.DisplayName,
		ProviderID:       execRes.ProviderID,
		ProviderName:     execRes.ProviderName,
		UpstreamModel:    execRes.UpstreamModel,
		Protocol:         execRes.Protocol,
		ThinkingLevel:    thinkingLevel,
		LatencyMs:        latMs,
		PromptTokens:     execRes.PromptTokens,
		CompletionTokens: execRes.CompletionTokens,
		Status:           status,
		ErrorDetail:      errStr,
	})
}
