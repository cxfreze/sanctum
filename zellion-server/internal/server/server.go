package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"zellion-server/internal/adminui"
	"zellion-server/internal/providers"
	"zellion-server/internal/store"
	"zellion-server/internal/tlsutil"
	"zellion-server/internal/zsconfig"
)

type GatewayServer struct {
	zsMgr      *zsconfig.Manager
	store      *store.Store
	certLoader *tlsutil.DynamicCertLoader
	hmacSecret []byte
	apiMgr     apiListenerManager
}

func NewGatewayServer(zsMgr *zsconfig.Manager, st *store.Store, certLoader *tlsutil.DynamicCertLoader) *GatewayServer {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return &GatewayServer{
		zsMgr:      zsMgr,
		store:      st,
		certLoader: certLoader,
		hmacSecret: secret,
	}
}

// writeBlankStealth returns an completely empty 204 No Content response with zero identifying headers.
func writeBlankStealth(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *GatewayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := s.zsMgr.Get()
	path := r.URL.Path

	// 1. ZEllion Sanctum Client Gateway API (/v1/zs/*)
	if strings.HasPrefix(path, "/v1/zs/") {
		s.handleClientGateway(w, r, cfg)
		return
	}

	// 2. Secret Admin Console Path (configured in server's ZS file)
	adminPath := cfg.AdminPath
	if path == adminPath || path == adminPath+"/" || strings.HasPrefix(path, adminPath+"/api/") {
		s.handleAdmin(w, r, cfg)
		return
	}

	// 3. Independent Public API Guard / Shared-Port TLS Dispatch
	if isPublicAPIPath(path) {
		if r.TLS == nil {
			s.ServeHTTPGuard(w, r)
			return
		}
		apiCfg := s.store.GetAPIConfig()
		if apiCfg.Enabled && cfg.TLSEnabled && cfg.Port == apiCfg.HTTPSPort {
			s.ServePublicAPIHTTP(w, r)
			return
		}
	}

	// 4. Everything else (including "/", "/admin", "/login", IP root in browser) -> Completely Blank!
	writeBlankStealth(w)
}

// ======================= CLIENT GATEWAY (/v1/zs/*) =======================

func (s *GatewayServer) handleClientGateway(w http.ResponseWriter, r *http.Request, cfg zsconfig.Config) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-ZS-Client, X-ZS-Token")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Require X-ZS-Client header or Authorization so casual browser address-bar visits still show blank
	if r.Header.Get("X-ZS-Client") == "" && r.Header.Get("Authorization") == "" && r.Header.Get("X-ZS-Token") == "" {
		writeBlankStealth(w)
		return
	}

	subPath := strings.TrimPrefix(r.URL.Path, "/v1/zs")
	clientAuthed := s.verifyClientToken(r, cfg)

	if subPath == "/ping" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"server":        "ZEllion-Server",
			"version":       "2.6.0",
			"authRequired":  strings.TrimSpace(cfg.ClientToken) != "",
			"authenticated": clientAuthed,
			"tlsEnabled":    cfg.TLSEnabled,
			"modelCount":    len(s.store.ListEnabledClientModels()),
		})
		return
	}

	if !clientAuthed {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "客户端访问密钥 (CLIENT_TOKEN) 校验未通过，请检查客户端安装目录下 ZS 文件第二行密钥配置。",
		})
		return
	}

	switch {
	case subPath == "/models" && r.Method == http.MethodGet:
		models := s.store.ListEnabledClientModels()
		if models == nil {
			models = []store.ClientModel{}
		}
		groups := s.store.ListModelGroups()
		if groups == nil {
			groups = []store.ModelGroup{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"models": models,
			"groups": groups,
		})

	case subPath == "/chat" && r.Method == http.MethodPost:
		s.handleClientChat(w, r)

	default:
		writeBlankStealth(w)
	}
}

func (s *GatewayServer) verifyClientToken(r *http.Request, cfg zsconfig.Config) bool {
	expected := strings.TrimSpace(cfg.ClientToken)
	if expected == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("X-ZS-Token"))
	if got == "" {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			got = strings.TrimSpace(auth[7:])
		}
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func (s *GatewayServer) handleClientChat(w http.ResponseWriter, r *http.Request) {
	var req providers.ChatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 50*1024*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "无效请求体: " + err.Error()})
		return
	}

	cm, ok := s.store.GetClientModel(req.Model)
	if !ok || !cm.Enabled {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "请求的模型不存在或未上架，请同步模型列表后重试"})
		return
	}

	start := time.Now()

	// Non-streaming JSON mode (e.g. for /compact context summarization)
	if !req.Stream {
		var textBuf, thinkBuf strings.Builder
		var toolCalls []providers.ToolCallSpec
		execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, req, providers.StreamCallbacks{
			OnThinkingDelta: func(d string) { thinkBuf.WriteString(d) },
			OnTextDelta:     func(d string) { textBuf.WriteString(d) },
			OnToolCall:      func(tc providers.ToolCallSpec) { toolCalls = append(toolCalls, tc) },
		})
		lat := time.Since(start).Milliseconds()
		status := "ok"
		errStr := ""
		if err != nil {
			status = "error"
			errStr = err.Error()
		}
		s.store.AppendLog(store.RequestLog{
			ClientModelID:    cm.ID,
			ClientModelName:  cm.DisplayName,
			ProviderID:       execRes.ProviderID,
			ProviderName:     execRes.ProviderName,
			UpstreamModel:    execRes.UpstreamModel,
			Protocol:         execRes.Protocol,
			ThinkingLevel:    req.ThinkingLevel,
			LatencyMs:        lat,
			PromptTokens:     execRes.PromptTokens,
			CompletionTokens: execRes.CompletionTokens,
			Status:           status,
			ErrorDetail:      errStr,
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"model":            cm.ID,
			"thinking":         thinkBuf.String(),
			"content":          textBuf.String(),
			"toolCalls":        toolCalls,
			"promptTokens":     execRes.PromptTokens,
			"completionTokens": execRes.CompletionTokens,
		})
		return
	}

	// Streaming SSE mode
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Streaming unsupported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	sendEvent := func(payload map[string]any) {
		b, _ := json.Marshal(payload)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	execRes, err := providers.ExecuteRoutedChat(r.Context(), s.store, cm, req, providers.StreamCallbacks{
		OnThinkingDelta: func(delta string) {
			sendEvent(map[string]any{
				"type":  "thinking_delta",
				"delta": delta,
			})
		},
		OnTextDelta: func(delta string) {
			sendEvent(map[string]any{
				"type":  "text_delta",
				"delta": delta,
			})
		},
		OnToolCall: func(tc providers.ToolCallSpec) {
			sendEvent(map[string]any{
				"type":     "tool_call",
				"toolCall": tc,
			})
		},
		OnUsage: func(pTok, cTok int) {
			sendEvent(map[string]any{
				"type":             "usage",
				"promptTokens":     pTok,
				"completionTokens": cTok,
			})
		},
	})

	lat := time.Since(start).Milliseconds()
	if err != nil {
		s.store.AppendLog(store.RequestLog{
			ClientModelID:   cm.ID,
			ClientModelName: cm.DisplayName,
			ProviderID:      execRes.ProviderID,
			ProviderName:    execRes.ProviderName,
			UpstreamModel:   execRes.UpstreamModel,
			Protocol:        execRes.Protocol,
			ThinkingLevel:   req.ThinkingLevel,
			LatencyMs:       lat,
			Status:          "error",
			ErrorDetail:     err.Error(),
		})
		sendEvent(map[string]any{
			"type":  "error",
			"error": err.Error(),
		})
		return
	}

	s.store.AppendLog(store.RequestLog{
		ClientModelID:    cm.ID,
		ClientModelName:  cm.DisplayName,
		ProviderID:       execRes.ProviderID,
		ProviderName:     execRes.ProviderName,
		UpstreamModel:    execRes.UpstreamModel,
		Protocol:         execRes.Protocol,
		ThinkingLevel:    req.ThinkingLevel,
		LatencyMs:        lat,
		PromptTokens:     execRes.PromptTokens,
		CompletionTokens: execRes.CompletionTokens,
		Status:           "ok",
	})

	sendEvent(map[string]any{
		"type":             "done",
		"provider":         execRes.ProviderName,
		"upstreamModel":    execRes.UpstreamModel,
		"latencyMs":        lat,
		"promptTokens":     execRes.PromptTokens,
		"completionTokens": execRes.CompletionTokens,
	})
}

// ======================= ADMIN CONSOLE (${ADMIN_PATH}) =======================

func (s *GatewayServer) issueAdminToken(user string) string {
	exp := time.Now().Add(24 * time.Hour).Unix()
	payload := fmt.Sprintf("%s|%d", user, exp)
	mac := hmac.New(sha256.New, s.hmacSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig))
}

func (s *GatewayServer) verifyAdminToken(r *http.Request, cfg zsconfig.Config) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return false
	}
	rawTok := strings.TrimSpace(auth[7:])
	decoded, err := base64.RawURLEncoding.DecodeString(rawTok)
	if err != nil {
		return false
	}
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 3 {
		return false
	}
	user, expStr, gotSig := parts[0], parts[1], parts[2]
	if subtle.ConstantTimeCompare([]byte(user), []byte(cfg.AdminUser)) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	payload := fmt.Sprintf("%s|%d", user, exp)
	mac := hmac.New(sha256.New, s.hmacSecret)
	mac.Write([]byte(payload))
	wantSig := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(gotSig), []byte(wantSig)) == 1
}

func (s *GatewayServer) handleAdmin(w http.ResponseWriter, r *http.Request, cfg zsconfig.Config) {
	path := r.URL.Path
	if path == cfg.AdminPath || path == cfg.AdminPath+"/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(adminui.IndexHTML)
		return
	}

	apiSub := strings.TrimPrefix(path, cfg.AdminPath+"/api")

	if apiSub == "/login" && r.Method == http.MethodPost {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
			return
		}
		uMatch := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.Username)), []byte(cfg.AdminUser)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(body.Password), []byte(cfg.AdminPass)) == 1
		if !uMatch || !pMatch {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "管理员账号或密码错误"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"token": s.issueAdminToken(cfg.AdminUser),
		})
		return
	}

	if !s.verifyAdminToken(r, cfg) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未授权访问"})
		return
	}

	switch {
	case apiSub == "/overview" && r.Method == http.MethodGet:
		st := s.store.GetState()
		// Mask API keys for safe display in UI
		for i := range st.Providers {
			if st.Providers[i].APIKey != "" && st.Providers[i].Protocol != "sanctum-local" {
				st.Providers[i].APIKey = "********"
			}
		}
		safeCfg := cfg
		safeCfg.AdminPass = ""
		certInfo := tlsutil.InspectCertFiles(
			s.zsMgr.ResolvePath(cfg.TLSCertFile),
			s.zsMgr.ResolvePath(cfg.TLSKeyFile),
		)
		writeJSON(w, http.StatusOK, map[string]any{
			"providers":   st.Providers,
			"modelGroups": st.ModelGroups,
			"models":      st.Models,
			"logs":        st.Logs,
			"apiConfig":   st.APIConfig,
			"apiStatus":   s.GetAPIServiceStatus(),
			"apiGroups":   st.APIGroups,
			"apiModels":   st.APIModels,
			"apiKeys":     st.APIKeys,
			"apiLogs":     st.APILogs,
			"zsConfig":    safeCfg,
			"certInfo":    certInfo,
		})

	case apiSub == "/providers" && r.Method == http.MethodPost:
		var p store.UpstreamProvider
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		saved, err := s.store.UpsertProvider(p)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, saved)

	case apiSub == "/providers" && r.Method == http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeleteProvider(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/providers/discover" && r.Method == http.MethodPost:
		id := r.URL.Query().Get("id")
		prov, ok := s.store.GetProvider(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "未找到该渠道"})
			return
		}
		models, err := providers.DiscoverProviderModels(r.Context(), prov)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		prov.DiscoveredModels = models
		_, _ = s.store.UpsertProvider(prov)
		writeJSON(w, http.StatusOK, map[string]any{"models": models})

	case apiSub == "/models" && r.Method == http.MethodPost:
		var m store.ClientModel
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10*1024*1024)).Decode(&m); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		saved, err := s.store.UpsertModel(m)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, saved)

	case apiSub == "/models" && r.Method == http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeleteModel(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/model-groups" && r.Method == http.MethodPost:
		var g store.ModelGroup
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10*1024*1024)).Decode(&g); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		saved, err := s.store.UpsertModelGroup(g)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, saved)

	case apiSub == "/model-groups" && r.Method == http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeleteModelGroup(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/models/reorder" && r.Method == http.MethodPost:
		var body struct {
			GroupIDs    []string            `json:"groupIds"`
			GroupModels map[string][]string `json:"groupModels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.store.ReorderClientCatalog(body.GroupIDs, body.GroupModels); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	// ======================= INDEPENDENT HTTPS API ADMIN ROUTES =======================

	case apiSub == "/ext-api/config" && r.Method == http.MethodPut:
		var incoming store.APIServiceConfig
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		saved, err := s.store.UpdateAPIConfig(incoming)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		status := s.SyncAPIServiceListeners()
		writeJSON(w, http.StatusOK, map[string]any{
			"apiConfig": saved,
			"apiStatus": status,
		})

	case apiSub == "/ext-api/models" && r.Method == http.MethodPost:
		var m store.ClientModel
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10*1024*1024)).Decode(&m); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		saved, err := s.store.UpsertAPIModel(m)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, saved)

	case apiSub == "/ext-api/models" && r.Method == http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeleteAPIModel(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/ext-api/groups" && r.Method == http.MethodPost:
		var g store.APIGroup
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10*1024*1024)).Decode(&g); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		saved, err := s.store.UpsertAPIGroup(g)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, saved)

	case apiSub == "/ext-api/groups" && r.Method == http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeleteAPIGroup(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/ext-api/reorder" && r.Method == http.MethodPost:
		var body struct {
			GroupIDs    []string            `json:"groupIds"`
			GroupModels map[string][]string `json:"groupModels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.store.ReorderAPICatalog(body.GroupIDs, body.GroupModels); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/ext-api/keys/generate" && r.Method == http.MethodPost:
		writeJSON(w, http.StatusOK, map[string]any{
			"key": store.GenerateServerAPIKey(),
		})

	case apiSub == "/ext-api/keys" && r.Method == http.MethodPost:
		var k store.APIKeyEntry
		if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		saved, err := s.store.UpsertAPIKey(k)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, saved)

	case apiSub == "/ext-api/keys/regenerate" && r.Method == http.MethodPost:
		id := r.URL.Query().Get("id")
		saved, err := s.store.RegenerateAPIKey(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, saved)

	case apiSub == "/ext-api/keys" && r.Method == http.MethodDelete:
		id := r.URL.Query().Get("id")
		if err := s.store.DeleteAPIKey(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/ext-api/logs" && r.Method == http.MethodDelete:
		_ = s.store.ClearAPILogs()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/zs-config" && r.Method == http.MethodPut:
		var incoming zsconfig.Config
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		next := cfg
		next.Host = incoming.Host
		next.Port = incoming.Port
		next.AdminPath = incoming.AdminPath
		next.AdminUser = incoming.AdminUser
		if strings.TrimSpace(incoming.AdminPass) != "" {
			next.AdminPass = incoming.AdminPass
		}
		next.ClientToken = incoming.ClientToken
		next.TLSEnabled = incoming.TLSEnabled
		next.TLSCertFile = incoming.TLSCertFile
		next.TLSKeyFile = incoming.TLSKeyFile

		if err := s.zsMgr.Save(next); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		updated := s.zsMgr.Get()
		s.certLoader.UpdatePaths(
			s.zsMgr.ResolvePath(updated.TLSCertFile),
			s.zsMgr.ResolvePath(updated.TLSKeyFile),
		)
		_ = s.SyncAPIServiceListeners()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "adminPath": updated.AdminPath})

	case apiSub == "/tls/upload" && r.Method == http.MethodPost:
		var body struct {
			CertPEM string `json:"certPem"`
			KeyPEM  string `json:"keyPem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		certPath := s.zsMgr.ResolvePath(cfg.TLSCertFile)
		keyPath := s.zsMgr.ResolvePath(cfg.TLSKeyFile)
		if err := tlsutil.SavePEMPair(certPath, keyPath, body.CertPEM, body.KeyPEM); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		s.certLoader.UpdatePaths(certPath, keyPath)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/tls/self-signed" && r.Method == http.MethodPost:
		var body struct {
			Hosts []string `json:"hosts"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		certPath := s.zsMgr.ResolvePath(cfg.TLSCertFile)
		keyPath := s.zsMgr.ResolvePath(cfg.TLSKeyFile)
		if err := tlsutil.GenerateSelfSignedCert(certPath, keyPath, body.Hosts); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		s.certLoader.UpdatePaths(certPath, keyPath)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case apiSub == "/logs" && r.Method == http.MethodDelete:
		_ = s.store.ClearLogs()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		writeBlankStealth(w)
	}
}
