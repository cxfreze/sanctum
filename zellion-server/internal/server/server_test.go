package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"zellion-server/internal/store"
	"zellion-server/internal/tlsutil"
	"zellion-server/internal/zsconfig"
)

func setupTestGateway(t *testing.T) (*GatewayServer, string) {
	t.Helper()
	tmpDir := t.TempDir()
	zsPath := filepath.Join(tmpDir, "ZS")
	zsMgr, err := zsconfig.LoadOrInit(zsPath)
	if err != nil {
		t.Fatalf("LoadOrInit failed: %v", err)
	}
	cfg := zsMgr.Get()
	st, err := store.NewStore(zsMgr.ResolvePath(cfg.DataFile))
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	certLoader := tlsutil.NewDynamicCertLoader(
		zsMgr.ResolvePath(cfg.TLSCertFile),
		zsMgr.ResolvePath(cfg.TLSKeyFile),
	)
	return NewGatewayServer(zsMgr, st, certLoader), tmpDir
}

func TestStealthBlankAndAdminLogin(t *testing.T) {
	gw, _ := setupTestGateway(t)
	ts := httptest.NewServer(gw)
	defer ts.Close()

	// 1. Direct browser visit to /, /admin, /v1/zs/models without X-ZS-Client must return 204 with 0 bytes
	for _, p := range []string{"/", "/admin", "/login", "/robots.txt", "/v1/zs/models"} {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("GET %s error: %v", p, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent || len(body) != 0 {
			t.Fatalf("expected 204 empty body on %s, got status=%d len=%d", p, resp.StatusCode, len(body))
		}
	}

	// 2. Secret admin path /zs-admin serves console HTML
	resp, err := http.Get(ts.URL + "/zs-admin")
	if err != nil {
		t.Fatalf("GET /zs-admin error: %v", err)
	}
	htmlBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(htmlBytes, []byte("Magpie")) {
		t.Fatalf("expected 200 admin console HTML, got status=%d", resp.StatusCode)
	}

	// 3. Admin login with default ZS credentials
	loginReq, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "zellion2026",
	})
	loginResp, err := http.Post(ts.URL+"/zs-admin/api/login", "application/json", bytes.NewReader(loginReq))
	if err != nil {
		t.Fatalf("login post error: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on login, got %d", loginResp.StatusCode)
	}
	var tokData struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(loginResp.Body).Decode(&tokData)
	if tokData.Token == "" {
		t.Fatalf("expected non-empty token")
	}

	// 4. Generate self-signed TLS cert via Admin API
	certReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/zs-admin/api/tls/self-signed", strings.NewReader(`{"hosts":["localhost","127.0.0.1"]}`))
	certReq.Header.Set("Authorization", "Bearer "+tokData.Token)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, err := http.DefaultClient.Do(certReq)
	if err != nil || certResp.StatusCode != http.StatusOK {
		t.Fatalf("self-signed cert generation failed: err=%v status=%v", err, certResp)
	}
	certResp.Body.Close()
}

func TestUpstreamOpenAIAndAnthropicTranslationAndFailover(t *testing.T) {
	// Mock Anthropic upstream server
	anthUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		fmt.Fprint(w, "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":120,\"output_tokens\":0}}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Analyzing architecture...\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello from custom Anthropic route!\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"list_dir\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\\\".\\\"}\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":45}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"message_stop\"}\n\n")
		fl.Flush()
	}))
	defer anthUpstream.Close()

	gw, _ := setupTestGateway(t)
	// Register mock Anthropic provider + custom client model
	_, _ = gw.store.UpsertProvider(store.UpstreamProvider{
		ID:       "prov-test-anth",
		Name:     "Test Anthropic",
		Protocol: "anthropic",
		BaseURL:  anthUpstream.URL,
		APIKey:   "sk-ant-test",
		Enabled:  true,
	})
	_, _ = gw.store.UpsertModel(store.ClientModel{
		ID:                      "custom-sovereign",
		DisplayName:             "My Custom Sovereign Model",
		ProviderLabel:           "CustomVendor",
		Enabled:                 true,
		ContextWindow:           256000,
		MaxOutputTokens:         16384,
		Modalities:              store.ModelModalities{Text: true, Vision: true, Tools: true, Reasoning: true},
		SupportedThinkingLevels: []string{"low", "medium", "high"},
		DefaultThinkingLevel:    "high",
		Routes: []store.ModelRoute{
			{ProviderID: "prov-test-anth", UpstreamModel: "claude-sonnet-4-20250514", Priority: 0, Weight: 100},
		},
	})

	ts := httptest.NewServer(gw)
	defer ts.Close()

	// Verify /v1/zs/models returns custom model
	mReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/zs/models", nil)
	mReq.Header.Set("X-ZS-Client", "ZEllion-Sanctum")
	mResp, err := http.DefaultClient.Do(mReq)
	if err != nil || mResp.StatusCode != 200 {
		t.Fatalf("/v1/zs/models failed: %v", err)
	}
	mBody, _ := io.ReadAll(mResp.Body)
	mResp.Body.Close()
	if !bytes.Contains(mBody, []byte("My Custom Sovereign Model")) {
		t.Fatalf("expected custom displayName in /v1/zs/models, got: %s", string(mBody))
	}

	// Verify /v1/zs/chat SSE streaming translation
	chatPayload := `{
		"model": "custom-sovereign",
		"thinkingLevel": "high",
		"stream": true,
		"messages": [{"role":"user","content":"Inspect workspace"}],
		"tools": [{"name":"list_dir","description":"List dir","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]
	}`
	cReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/zs/chat", strings.NewReader(chatPayload))
	cReq.Header.Set("X-ZS-Client", "ZEllion-Sanctum")
	cReq.Header.Set("Content-Type", "application/json")
	cResp, err := http.DefaultClient.Do(cReq)
	if err != nil || cResp.StatusCode != 200 {
		t.Fatalf("/v1/zs/chat failed: %v", err)
	}
	sseData, _ := io.ReadAll(cResp.Body)
	cResp.Body.Close()

	sseStr := string(sseData)
	if !strings.Contains(sseStr, "Analyzing architecture...") ||
		!strings.Contains(sseStr, "Hello from custom Anthropic route!") ||
		!strings.Contains(sseStr, "list_dir") {
		t.Fatalf("unexpected SSE output:\n%s", sseStr)
	}
}

func TestNoImplicitModelsAndRejectUnknownModel(t *testing.T) {
	gw, _ := setupTestGateway(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/zs/models", nil)
	req.Header.Set("X-ZS-Client", "ZEllion-Sanctum")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"models":[]`) {
		t.Fatalf("fresh server must publish empty array, got %d %s", rec.Code, rec.Body.String())
	}
	// Even with another published model, an unknown ID must NOT silently switch models.
	_, err := gw.store.UpsertModel(store.ClientModel{ID: "published", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/zs/chat", strings.NewReader(`{"model":"unknown","messages":[],"stream":false}`))
	req.Header.Set("X-ZS-Client", "ZEllion-Sanctum")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown model must return 404, got %d %s", rec.Code, rec.Body.String())
	}
	if err := gw.store.DeleteModel("published"); err != nil {
		t.Fatal(err)
	}
	if len(gw.store.ListEnabledClientModels()) != 0 {
		t.Fatal("deleted models must not return")
	}
}

func TestModelGroupsIconsAndManualSorting(t *testing.T) {
	gw, _ := setupTestGateway(t)

	grpA, err := gw.store.UpsertModelGroup(store.ModelGroup{
		ID:   "grp-a",
		Name: "Alpha Group",
		Icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4"/></svg>`,
	})
	if err != nil {
		t.Fatalf("UpsertModelGroup A failed: %v", err)
	}
	if !strings.HasPrefix(grpA.Icon, "data:image/svg+xml;base64,") {
		t.Fatalf("expected raw SVG to be normalized into base64 data URI, got: %s", grpA.Icon)
	}

	grpB, err := gw.store.UpsertModelGroup(store.ModelGroup{
		ID:   "grp-b",
		Name: "Beta Group",
		Icon: "data:image/png;base64,iVBORw0KGgo=",
	})
	if err != nil {
		t.Fatalf("UpsertModelGroup B failed: %v", err)
	}

	_, _ = gw.store.UpsertModel(store.ClientModel{ID: "m1", DisplayName: "M1", GroupID: grpA.ID, Enabled: true})
	_, _ = gw.store.UpsertModel(store.ClientModel{ID: "m2", DisplayName: "M2", GroupID: grpA.ID, Enabled: true})
	_, _ = gw.store.UpsertModel(store.ClientModel{ID: "m3", DisplayName: "M3", GroupID: grpB.ID, Enabled: true})
	_, _ = gw.store.UpsertModel(store.ClientModel{ID: "m4", DisplayName: "M4", GroupID: "", Enabled: true})

	// Manually reorder: Beta Group before Alpha Group; M2 before M1 inside Alpha Group
	if err := gw.store.ReorderClientCatalog(
		[]string{grpB.ID, grpA.ID},
		map[string][]string{
			grpB.ID:         {"m3"},
			grpA.ID:         {"m2", "m1"},
			"__ungrouped__": {"m4"},
		},
	); err != nil {
		t.Fatalf("ReorderClientCatalog failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/models", nil)
	req.Header.Set("X-ZS-Client", "ZEllion-Sanctum")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp struct {
		Models []store.ClientModel `json:"models"`
		Groups []store.ModelGroup  `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	gotIDs := make([]string, 0, len(resp.Models))
	for _, m := range resp.Models {
		gotIDs = append(gotIDs, m.ID)
	}
	wantIDs := []string{"m3", "m2", "m1", "m4"}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("expected sorted model IDs %v, got %v", wantIDs, gotIDs)
	}
	if resp.Models[0].GroupName != "Beta Group" || resp.Models[0].GroupIcon != "data:image/png;base64,iVBORw0KGgo=" {
		t.Fatalf("expected Beta Group metadata on m3, got %+v", resp.Models[0])
	}
	if resp.Models[1].GroupName != "Alpha Group" || !strings.HasPrefix(resp.Models[1].GroupIcon, "data:image/svg+xml;base64,") {
		t.Fatalf("expected Alpha Group SVG icon on m2, got %+v", resp.Models[1])
	}
}

func TestIndependentHTTPSPublicAPIGroupsKeysAndProtocols(t *testing.T) {
	// Mock OpenAI-compatible upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"Step 1. \"}}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"API response ok!\"}}],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":6}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
		fl.Flush()
	}))
	defer upstream.Close()

	gw, _ := setupTestGateway(t)
	defer gw.CloseAPIService()

	_, _ = gw.store.UpsertProvider(store.UpstreamProvider{
		ID:       "prov-oai",
		Name:     "Mock OpenAI",
		Protocol: "openai",
		BaseURL:  upstream.URL + "/v1",
		APIKey:   "sk-up-test",
		Enabled:  true,
	})

	// 1. Add a client-only model and verify isolation from API models
	_, _ = gw.store.UpsertModel(store.ClientModel{
		ID:          "client-only-v1",
		DisplayName: "Client Only Model",
		Enabled:     true,
		Routes:      []store.ModelRoute{{ProviderID: "prov-oai", UpstreamModel: "gpt-4o", Priority: 0, Weight: 100}},
	})

	// 2. Add independent API models + preset group + server-generated key
	routes := []store.ModelRoute{{ProviderID: "prov-oai", UpstreamModel: "gpt-4o", Priority: 0, Weight: 100}}
	mods := store.ModelModalities{Text: true, Vision: true, Tools: true, Reasoning: true}
	_, _ = gw.store.UpsertAPIModel(store.ClientModel{ID: "api-pro", DisplayName: "API Pro", Enabled: true, Modalities: mods, Routes: routes})
	_, _ = gw.store.UpsertAPIModel(store.ClientModel{ID: "api-lite", DisplayName: "API Lite", Enabled: true, Modalities: mods, Routes: routes})
	_, _ = gw.store.UpsertAPIModel(store.ClientModel{ID: "api-restricted", DisplayName: "API Restricted", Enabled: true, Modalities: mods, Routes: routes})

	presetGrp, err := gw.store.UpsertAPIGroup(store.APIGroup{
		ID:       "preset-pro",
		Name:     "Pro Preset",
		Icon:     `<svg xmlns="http://www.w3.org/2000/svg"><rect width="8" height="8"/></svg>`,
		ModelIDs: []string{"api-pro"},
	})
	if err != nil {
		t.Fatal(err)
	}

	keyEntry, err := gw.store.UpsertAPIKey(store.APIKeyEntry{
		Name:          "Team Key",
		Enabled:       true,
		GroupIDs:      []string{presetGrp.ID},
		AllowedModels: []string{"api-lite"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(keyEntry.Key, "sk-zs-") {
		t.Fatalf("expected server-generated sk-zs- key, got %s", keyEntry.Key)
	}

	// Pick free port for independent HTTPS API listener
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeHTTPSPort := probeLn.Addr().(*net.TCPAddr).Port
	probeLn.Close()

	_, _ = gw.store.UpdateAPIConfig(store.APIServiceConfig{
		Enabled:        true,
		HTTPSPort:      freeHTTPSPort,
		HTTPPort:       0,
		RedirectHTTP80: false,
	})
	// Bind on 127.0.0.1 in ZS config for local test listener
	zsCfg := gw.zsMgr.Get()
	zsCfg.Host = "127.0.0.1"
	_ = gw.zsMgr.Save(zsCfg)

	st := gw.SyncAPIServiceListeners()
	if !st.Running {
		t.Fatalf("expected independent HTTPS API listener running, got error: %s", st.LastError)
	}

	// 3. Verify plain HTTP request on main server is strictly rejected (HTTPS only)
	plainMain := httptest.NewServer(gw)
	defer plainMain.Close()
	httpReq, _ := http.NewRequest(http.MethodGet, plainMain.URL+"/v1/models", nil)
	httpReq.Header.Set("Authorization", "Bearer "+keyEntry.Key)
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected plain HTTP API call to be rejected with 403, got %d", httpResp.StatusCode)
	}

	// 4. Verify HTTPS listener stealth (204 without key) & authenticated /v1/models scoping
	httpsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	apiBase := fmt.Sprintf("https://127.0.0.1:%d", freeHTTPSPort)

	stealthResp, err := httpsClient.Get(apiBase + "/")
	if err != nil {
		t.Fatalf("HTTPS root request failed: %v", err)
	}
	stealthResp.Body.Close()
	if stealthResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 stealth on unauthenticated HTTPS root, got %d", stealthResp.StatusCode)
	}

	modelsReq, _ := http.NewRequest(http.MethodGet, apiBase+"/v1/models", nil)
	modelsReq.Header.Set("Authorization", "Bearer "+keyEntry.Key)
	modelsResp, err := httpsClient.Do(modelsReq)
	if err != nil || modelsResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS /v1/models failed: err=%v status=%v", err, modelsResp)
	}
	modelsBytes, _ := io.ReadAll(modelsResp.Body)
	modelsResp.Body.Close()
	modelsStr := string(modelsBytes)
	if !strings.Contains(modelsStr, `"api-pro"`) || !strings.Contains(modelsStr, `"api-lite"`) {
		t.Fatalf("expected authorized preset + individual models in /v1/models, got: %s", modelsStr)
	}
	if strings.Contains(modelsStr, `"api-restricted"`) || strings.Contains(modelsStr, `"client-only-v1"`) {
		t.Fatalf("unauthorized or client-only model leaked into /v1/models: %s", modelsStr)
	}

	// 5. Verify OpenAI /v1/chat/completions non-streaming & unauthorized model rejection
	oaiBody := `{"model":"api-pro","stream":false,"messages":[{"role":"user","content":"Hi"}]}`
	oaiReq, _ := http.NewRequest(http.MethodPost, apiBase+"/v1/chat/completions", strings.NewReader(oaiBody))
	oaiReq.Header.Set("Authorization", "Bearer "+keyEntry.Key)
	oaiReq.Header.Set("Content-Type", "application/json")
	oaiResp, err := httpsClient.Do(oaiReq)
	if err != nil || oaiResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS /v1/chat/completions failed: err=%v status=%v", err, oaiResp)
	}
	oaiOut, _ := io.ReadAll(oaiResp.Body)
	oaiResp.Body.Close()
	if !strings.Contains(string(oaiOut), "API response ok!") {
		t.Fatalf("unexpected OpenAI chat response: %s", string(oaiOut))
	}

	unauthModelReq, _ := http.NewRequest(http.MethodPost, apiBase+"/v1/chat/completions", strings.NewReader(`{"model":"api-restricted","messages":[{"role":"user","content":"Hi"}]}`))
	unauthModelReq.Header.Set("Authorization", "Bearer "+keyEntry.Key)
	unauthModelReq.Header.Set("Content-Type", "application/json")
	unauthModelResp, err := httpsClient.Do(unauthModelReq)
	if err != nil {
		t.Fatal(err)
	}
	unauthModelResp.Body.Close()
	if unauthModelResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for model outside key scope, got %d", unauthModelResp.StatusCode)
	}

	// 6. Verify Anthropic /v1/messages via x-api-key header
	anthReq, _ := http.NewRequest(http.MethodPost, apiBase+"/v1/messages", strings.NewReader(`{"model":"api-lite","max_tokens":1024,"stream":false,"messages":[{"role":"user","content":"Hello"}]}`))
	anthReq.Header.Set("x-api-key", keyEntry.Key)
	anthReq.Header.Set("Content-Type", "application/json")
	anthResp, err := httpsClient.Do(anthReq)
	if err != nil || anthResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS /v1/messages failed: err=%v status=%v", err, anthResp)
	}
	anthOut, _ := io.ReadAll(anthResp.Body)
	anthResp.Body.Close()
	if !strings.Contains(string(anthOut), "API response ok!") {
		t.Fatalf("unexpected Anthropic messages response: %s", string(anthOut))
	}
}
