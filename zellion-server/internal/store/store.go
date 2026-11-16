package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProviderProtocol defines how ZEllion Server communicates with an upstream API.
// - "openai": OpenAI Chat Completions (/v1/chat/completions) & all OpenAI-compatible APIs
// - "openai-responses": OpenAI Responses API (/v1/responses)
// - "anthropic": Anthropic Messages API (/v1/messages) & Anthropic-compatible endpoints
// - "gemini": Google Gemini API (/v1beta/models/{model}:generateContent & :streamGenerateContent)
// - "sanctum-local": Built-in zero-key diagnostic harness simulator for local testing
type UpstreamProvider struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Protocol         string            `json:"protocol"`
	BaseURL          string            `json:"baseUrl"`
	APIKey           string            `json:"apiKey"`
	CustomHeaders    map[string]string `json:"customHeaders,omitempty"`
	ProxyURL         string            `json:"proxyUrl,omitempty"`
	Enabled          bool              `json:"enabled"`
	DiscoveredModels []string          `json:"discoveredModels,omitempty"`
	Notes            string            `json:"notes,omitempty"`
	UpdatedAt        string            `json:"updatedAt"`
}

type ModelRoute struct {
	ProviderID    string `json:"providerId"`
	UpstreamModel string `json:"upstreamModel"`
	Priority      int    `json:"priority"`
	Weight        int    `json:"weight"`
}

type ModelModalities struct {
	Text      bool `json:"text"`
	Vision    bool `json:"vision"`
	Audio     bool `json:"audio"`
	PDF       bool `json:"pdf"`
	Tools     bool `json:"tools"`
	Reasoning bool `json:"reasoning"`
}

type ModelGroup struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Icon      string `json:"icon,omitempty"`
	SortOrder int    `json:"sortOrder"`
	UpdatedAt string `json:"updatedAt"`
}

type ClientModel struct {
	ID                      string          `json:"id"`
	DisplayName             string          `json:"displayName"`
	ProviderLabel           string          `json:"providerLabel"`
	GroupID                 string          `json:"groupId,omitempty"`
	GroupName               string          `json:"groupName,omitempty"`
	GroupIcon               string          `json:"groupIcon,omitempty"`
	SortOrder               int             `json:"sortOrder"`
	Enabled                 bool            `json:"enabled"`
	ContextWindow           int             `json:"contextWindow"`
	MaxOutputTokens         int             `json:"maxOutputTokens"`
	Modalities              ModelModalities `json:"modalities"`
	SupportedThinkingLevels []string        `json:"supportedThinkingLevels"`
	DefaultThinkingLevel    string          `json:"defaultThinkingLevel"`
	SystemPromptPrefix      string          `json:"systemPromptPrefix,omitempty"`
	Temperature             *float64        `json:"temperature,omitempty"`
	Description             string          `json:"description,omitempty"`
	Routes                  []ModelRoute    `json:"routes"`
	UpdatedAt               string          `json:"updatedAt"`
}

type APIServiceConfig struct {
	Enabled        bool `json:"enabled"`
	HTTPSPort      int  `json:"httpsPort"`
	HTTPPort       int  `json:"httpPort"`
	RedirectHTTP80 bool `json:"redirectHttp80"`
}

type APIGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Icon        string   `json:"icon,omitempty"`
	Description string   `json:"description,omitempty"`
	ModelIDs    []string `json:"modelIds"`
	SortOrder   int      `json:"sortOrder"`
	UpdatedAt   string   `json:"updatedAt"`
}

type APIKeyEntry struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Key            string   `json:"key"`
	KeyPrefix      string   `json:"keyPrefix"`
	Enabled        bool     `json:"enabled"`
	GroupIDs       []string `json:"groupIds"`
	AllowedModels  []string `json:"allowedModels"`
	AllowAllModels bool     `json:"allowAllModels,omitempty"`
	CreatedAt      string   `json:"createdAt"`
	UpdatedAt      string   `json:"updatedAt"`
	LastUsedAt     string   `json:"lastUsedAt,omitempty"`
	RequestCount   int64    `json:"requestCount"`
}

type RequestLog struct {
	ID               string `json:"id"`
	Timestamp        string `json:"timestamp"`
	APIKeyID         string `json:"apiKeyId,omitempty"`
	APIKeyName       string `json:"apiKeyName,omitempty"`
	ClientModelID    string `json:"clientModelId"`
	ClientModelName  string `json:"clientModelName"`
	ProviderID       string `json:"providerId"`
	ProviderName     string `json:"providerName"`
	UpstreamModel    string `json:"upstreamModel"`
	Protocol         string `json:"protocol"`
	ThinkingLevel    string `json:"thinkingLevel,omitempty"`
	LatencyMs        int64  `json:"latencyMs"`
	PromptTokens     int    `json:"promptTokens"`
	CompletionTokens int    `json:"completionTokens"`
	Status           string `json:"status"`
	ErrorDetail      string `json:"errorDetail,omitempty"`
}

type GatewayState struct {
	Providers   []UpstreamProvider `json:"providers"`
	ModelGroups []ModelGroup       `json:"modelGroups"`
	Models      []ClientModel      `json:"models"`
	Logs        []RequestLog       `json:"logs"`
	APIConfig   APIServiceConfig   `json:"apiConfig"`
	APIGroups   []APIGroup         `json:"apiGroups"`
	APIModels   []ClientModel      `json:"apiModels"`
	APIKeys     []APIKeyEntry      `json:"apiKeys"`
	APILogs     []RequestLog       `json:"apiLogs"`
}

type Store struct {
	mu       sync.RWMutex
	filePath string
	state    GatewayState
	rrSeq    uint64
}

func NewStore(filePath string) (*Store, error) {
	s := &Store{
		filePath: filePath,
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		s.state = defaultGatewayState()
		if saveErr := s.saveLocked(); saveErr != nil {
			return nil, saveErr
		}
		return s, nil
	}

	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		s.state = defaultGatewayState()
		_ = s.saveLocked()
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.state); err != nil {
		return nil, fmt.Errorf("parse gateway state %s: %w", filePath, err)
	}
	s.normalizeStateLocked()
	return s, nil
}

func nowISO() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func defaultGatewayState() GatewayState {
	return GatewayState{
		Providers:   []UpstreamProvider{},
		ModelGroups: []ModelGroup{},
		Models:      []ClientModel{},
		Logs:        []RequestLog{},
		APIConfig: APIServiceConfig{
			Enabled:        false,
			HTTPSPort:      443,
			HTTPPort:       80,
			RedirectHTTP80: true,
		},
		APIGroups: []APIGroup{},
		APIModels: []ClientModel{},
		APIKeys:   []APIKeyEntry{},
		APILogs:   []RequestLog{},
	}
}

func (s *Store) normalizeStateLocked() {
	if s.state.Providers == nil {
		s.state.Providers = []UpstreamProvider{}
	}
	if s.state.ModelGroups == nil {
		s.state.ModelGroups = []ModelGroup{}
	}
	if s.state.Models == nil {
		s.state.Models = []ClientModel{}
	}
	if s.state.Logs == nil {
		s.state.Logs = []RequestLog{}
	}
	if s.state.APIConfig.HTTPSPort <= 0 || s.state.APIConfig.HTTPSPort > 65535 {
		s.state.APIConfig.HTTPSPort = 443
	}
	if s.state.APIConfig.HTTPPort < 0 || s.state.APIConfig.HTTPPort > 65535 {
		s.state.APIConfig.HTTPPort = 80
	}
	if s.state.APIGroups == nil {
		s.state.APIGroups = []APIGroup{}
	}
	if s.state.APIModels == nil {
		s.state.APIModels = []ClientModel{}
	}
	if s.state.APIKeys == nil {
		s.state.APIKeys = []APIKeyEntry{}
	}
	if s.state.APILogs == nil {
		s.state.APILogs = []RequestLog{}
	}
}

func NormalizeIconData(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "<svg") || strings.HasPrefix(lower, "<?xml") {
		return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(v))
	}
	if strings.HasPrefix(lower, "data:image/") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		return v
	}
	return ""
}

func GenerateServerAPIKey() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	var sb strings.Builder
	sb.WriteString("sk-zs-")
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < 44; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			sb.WriteByte(alphabet[i%len(alphabet)])
			continue
		}
		sb.WriteByte(alphabet[n.Int64()])
	}
	return sb.String()
}

func maskKeyPrefix(key string) string {
	if len(key) <= 14 {
		return key
	}
	return key[:10] + "..." + key[len(key)-4:]
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, raw, 0600)
}

func (s *Store) NextRoundRobin() uint64 {
	return atomic.AddUint64(&s.rrSeq, 1)
}

func sortModelGroupsSlice(groups []ModelGroup) []ModelGroup {
	cp := append([]ModelGroup(nil), groups...)
	sort.SliceStable(cp, func(i, j int) bool {
		return cp[i].SortOrder < cp[j].SortOrder
	})
	return cp
}

func sortModelsWithGroups(models []ClientModel, groups []ModelGroup) []ClientModel {
	sortedGroups := sortModelGroupsSlice(groups)
	groupMap := make(map[string]ModelGroup, len(sortedGroups))
	for _, g := range sortedGroups {
		groupMap[g.ID] = g
	}

	byGroup := make(map[string][]ClientModel)
	var ungrouped []ClientModel

	for _, m := range models {
		cp := m
		if g, ok := groupMap[cp.GroupID]; ok && cp.GroupID != "" {
			cp.GroupName = g.Name
			cp.GroupIcon = g.Icon
			byGroup[g.ID] = append(byGroup[g.ID], cp)
		} else {
			cp.GroupID = ""
			cp.GroupName = ""
			cp.GroupIcon = ""
			ungrouped = append(ungrouped, cp)
		}
	}

	out := make([]ClientModel, 0, len(models))
	for _, g := range sortedGroups {
		bucket := byGroup[g.ID]
		sort.SliceStable(bucket, func(i, j int) bool {
			return bucket[i].SortOrder < bucket[j].SortOrder
		})
		out = append(out, bucket...)
	}

	sort.SliceStable(ungrouped, func(i, j int) bool {
		return ungrouped[i].SortOrder < ungrouped[j].SortOrder
	})
	out = append(out, ungrouped...)
	return out
}

func sortAPIGroupsSlice(groups []APIGroup) []APIGroup {
	cp := append([]APIGroup(nil), groups...)
	sort.SliceStable(cp, func(i, j int) bool {
		return cp[i].SortOrder < cp[j].SortOrder
	})
	return cp
}

func sortAPIModelsWithGroups(models []ClientModel, groups []APIGroup) []ClientModel {
	sortedGroups := sortAPIGroupsSlice(groups)
	groupMap := make(map[string]APIGroup, len(sortedGroups))
	for _, g := range sortedGroups {
		groupMap[g.ID] = g
	}

	byGroup := make(map[string][]ClientModel)
	var ungrouped []ClientModel
	for _, m := range models {
		cp := m
		if g, ok := groupMap[cp.GroupID]; ok && cp.GroupID != "" {
			cp.GroupName = g.Name
			cp.GroupIcon = g.Icon
			byGroup[g.ID] = append(byGroup[g.ID], cp)
		} else {
			cp.GroupID = ""
			cp.GroupName = ""
			cp.GroupIcon = ""
			ungrouped = append(ungrouped, cp)
		}
	}

	out := make([]ClientModel, 0, len(models))
	for _, g := range sortedGroups {
		bucket := byGroup[g.ID]
		sort.SliceStable(bucket, func(i, j int) bool {
			return bucket[i].SortOrder < bucket[j].SortOrder
		})
		out = append(out, bucket...)
	}
	sort.SliceStable(ungrouped, func(i, j int) bool {
		return ungrouped[i].SortOrder < ungrouped[j].SortOrder
	})
	out = append(out, ungrouped...)
	return out
}

func (s *Store) GetState() GatewayState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.state)
	var out GatewayState
	_ = json.Unmarshal(b, &out)
	out.ModelGroups = sortModelGroupsSlice(out.ModelGroups)
	out.Models = sortModelsWithGroups(out.Models, out.ModelGroups)
	out.APIGroups = sortAPIGroupsSlice(out.APIGroups)
	out.APIModels = sortAPIModelsWithGroups(out.APIModels, out.APIGroups)
	return out
}

func (s *Store) ListModelGroups() []ModelGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortModelGroupsSlice(s.state.ModelGroups)
}

func (s *Store) ListEnabledClientModels() []ClientModel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sorted := sortModelsWithGroups(s.state.Models, s.state.ModelGroups)
	res := make([]ClientModel, 0, len(sorted))
	for _, m := range sorted {
		if m.Enabled {
			cp := m
			cp.Routes = nil
			cp.SystemPromptPrefix = ""
			res = append(res, cp)
		}
	}
	return res
}

func (s *Store) GetClientModel(id string) (ClientModel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.state.Models {
		if m.ID == id {
			return m, true
		}
	}
	return ClientModel{}, false
}

func (s *Store) GetProvider(id string) (UpstreamProvider, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.state.Providers {
		if p.ID == id {
			return p, true
		}
	}
	return UpstreamProvider{}, false
}

func (s *Store) UpsertProvider(p UpstreamProvider) (UpstreamProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		p.ID = fmt.Sprintf("prov-%d", time.Now().UnixMilli())
	}
	p.UpdatedAt = nowISO()
	found := false
	for i := range s.state.Providers {
		if s.state.Providers[i].ID == p.ID {
			if p.APIKey == "********" {
				p.APIKey = s.state.Providers[i].APIKey
			}
			s.state.Providers[i] = p
			found = true
			break
		}
	}
	if !found {
		s.state.Providers = append(s.state.Providers, p)
	}
	return p, s.saveLocked()
}

func (s *Store) DeleteProvider(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]UpstreamProvider, 0, len(s.state.Providers))
	for _, p := range s.state.Providers {
		if p.ID != id {
			next = append(next, p)
		}
	}
	s.state.Providers = next
	return s.saveLocked()
}

// ======================= CLIENT MODEL GROUPS & SORTING =======================

func (s *Store) UpsertModelGroup(g ModelGroup) (ModelGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return ModelGroup{}, fmt.Errorf("分组名称不能为空")
	}
	g.Icon = NormalizeIconData(g.Icon)
	g.UpdatedAt = nowISO()

	if g.ID == "" {
		g.ID = fmt.Sprintf("grp-%d", time.Now().UnixMilli())
		g.SortOrder = len(s.state.ModelGroups)
		s.state.ModelGroups = append(s.state.ModelGroups, g)
		return g, s.saveLocked()
	}

	found := false
	for i := range s.state.ModelGroups {
		if s.state.ModelGroups[i].ID == g.ID {
			if g.SortOrder == 0 && i > 0 && s.state.ModelGroups[i].SortOrder != 0 {
				g.SortOrder = s.state.ModelGroups[i].SortOrder
			}
			s.state.ModelGroups[i] = g
			found = true
			break
		}
	}
	if !found {
		g.SortOrder = len(s.state.ModelGroups)
		s.state.ModelGroups = append(s.state.ModelGroups, g)
	}
	return g, s.saveLocked()
}

func (s *Store) DeleteModelGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]ModelGroup, 0, len(s.state.ModelGroups))
	for _, g := range s.state.ModelGroups {
		if g.ID != id {
			next = append(next, g)
		}
	}
	s.state.ModelGroups = next
	for i := range s.state.Models {
		if s.state.Models[i].GroupID == id {
			s.state.Models[i].GroupID = ""
		}
	}
	return s.saveLocked()
}

func (s *Store) ReorderClientCatalog(groupIDs []string, groupModels map[string][]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(groupIDs) > 0 {
		orderMap := make(map[string]int, len(groupIDs))
		for idx, id := range groupIDs {
			orderMap[id] = idx
		}
		nextOrder := len(groupIDs)
		for i := range s.state.ModelGroups {
			if ord, ok := orderMap[s.state.ModelGroups[i].ID]; ok {
				s.state.ModelGroups[i].SortOrder = ord
			} else {
				s.state.ModelGroups[i].SortOrder = nextOrder
				nextOrder++
			}
		}
		s.state.ModelGroups = sortModelGroupsSlice(s.state.ModelGroups)
	}

	if len(groupModels) > 0 {
		validGroups := make(map[string]bool, len(s.state.ModelGroups))
		for _, g := range s.state.ModelGroups {
			validGroups[g.ID] = true
		}
		modelAssignment := make(map[string]struct {
			groupID string
			order   int
		})
		for gid, mids := range groupModels {
			cleanGID := gid
			if cleanGID == "__ungrouped__" || !validGroups[cleanGID] {
				cleanGID = ""
			}
			for idx, mid := range mids {
				modelAssignment[mid] = struct {
					groupID string
					order   int
				}{groupID: cleanGID, order: idx}
			}
		}
		for i := range s.state.Models {
			if assign, ok := modelAssignment[s.state.Models[i].ID]; ok {
				s.state.Models[i].GroupID = assign.groupID
				s.state.Models[i].SortOrder = assign.order
			}
		}
	}

	return s.saveLocked()
}

func normalizeModelDefaults(m *ClientModel) {
	if m.ID == "" {
		m.ID = fmt.Sprintf("model-%d", time.Now().UnixMilli())
	}
	if strings.TrimSpace(m.DisplayName) == "" {
		m.DisplayName = m.ID
	}
	if m.ContextWindow <= 0 {
		m.ContextWindow = 128000
	}
	if m.MaxOutputTokens <= 0 {
		m.MaxOutputTokens = 8192
	}
	if len(m.SupportedThinkingLevels) == 0 {
		m.SupportedThinkingLevels = []string{"off", "low", "medium", "high"}
	}
	if m.DefaultThinkingLevel == "" {
		m.DefaultThinkingLevel = m.SupportedThinkingLevels[0]
	}
	m.GroupName = ""
	m.GroupIcon = ""
	m.UpdatedAt = nowISO()
}

func (s *Store) UpsertModel(m ClientModel) (ClientModel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizeModelDefaults(&m)

	found := false
	for i := range s.state.Models {
		if s.state.Models[i].ID == m.ID {
			if m.SortOrder == 0 && s.state.Models[i].GroupID == m.GroupID {
				m.SortOrder = s.state.Models[i].SortOrder
			} else if s.state.Models[i].GroupID != m.GroupID {
				m.SortOrder = s.nextModelOrderLocked(s.state.Models, m.GroupID)
			}
			s.state.Models[i] = m
			found = true
			break
		}
	}
	if !found {
		m.SortOrder = s.nextModelOrderLocked(s.state.Models, m.GroupID)
		s.state.Models = append(s.state.Models, m)
	}
	return m, s.saveLocked()
}

func (s *Store) nextModelOrderLocked(list []ClientModel, groupID string) int {
	maxOrd := -1
	for _, item := range list {
		if item.GroupID == groupID && item.SortOrder > maxOrd {
			maxOrd = item.SortOrder
		}
	}
	return maxOrd + 1
}

func (s *Store) DeleteModel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]ClientModel, 0, len(s.state.Models))
	for _, m := range s.state.Models {
		if m.ID != id {
			next = append(next, m)
		}
	}
	s.state.Models = next
	return s.saveLocked()
}

// ======================= INDEPENDENT HTTPS API SERVICE =======================

func (s *Store) GetAPIConfig() APIServiceConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.state.APIConfig
	if cfg.HTTPSPort <= 0 || cfg.HTTPSPort > 65535 {
		cfg.HTTPSPort = 443
	}
	if cfg.HTTPPort < 0 || cfg.HTTPPort > 65535 {
		cfg.HTTPPort = 80
	}
	return cfg
}

func (s *Store) UpdateAPIConfig(cfg APIServiceConfig) (APIServiceConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.HTTPSPort <= 0 || cfg.HTTPSPort > 65535 {
		cfg.HTTPSPort = 443
	}
	if cfg.HTTPPort < 0 || cfg.HTTPPort > 65535 {
		cfg.HTTPPort = 80
	}
	s.state.APIConfig = cfg
	return cfg, s.saveLocked()
}

func (s *Store) UpsertAPIModel(m ClientModel) (ClientModel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizeModelDefaults(&m)

	found := false
	for i := range s.state.APIModels {
		if s.state.APIModels[i].ID == m.ID {
			if m.SortOrder == 0 && s.state.APIModels[i].GroupID == m.GroupID {
				m.SortOrder = s.state.APIModels[i].SortOrder
			} else if s.state.APIModels[i].GroupID != m.GroupID {
				m.SortOrder = s.nextModelOrderLocked(s.state.APIModels, m.GroupID)
			}
			s.state.APIModels[i] = m
			found = true
			break
		}
	}
	if !found {
		m.SortOrder = s.nextModelOrderLocked(s.state.APIModels, m.GroupID)
		s.state.APIModels = append(s.state.APIModels, m)
	}

	// Keep APIGroup.ModelIDs synced if a primary GroupID is set on the model
	if m.GroupID != "" {
		for gi := range s.state.APIGroups {
			if s.state.APIGroups[gi].ID == m.GroupID {
				has := false
				for _, mid := range s.state.APIGroups[gi].ModelIDs {
					if mid == m.ID {
						has = true
						break
					}
				}
				if !has {
					s.state.APIGroups[gi].ModelIDs = append(s.state.APIGroups[gi].ModelIDs, m.ID)
				}
			}
		}
	}

	return m, s.saveLocked()
}

func (s *Store) DeleteAPIModel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]ClientModel, 0, len(s.state.APIModels))
	for _, m := range s.state.APIModels {
		if m.ID != id {
			next = append(next, m)
		}
	}
	s.state.APIModels = next

	for i := range s.state.APIGroups {
		filtered := make([]string, 0, len(s.state.APIGroups[i].ModelIDs))
		for _, mid := range s.state.APIGroups[i].ModelIDs {
			if mid != id {
				filtered = append(filtered, mid)
			}
		}
		s.state.APIGroups[i].ModelIDs = filtered
	}

	for i := range s.state.APIKeys {
		filtered := make([]string, 0, len(s.state.APIKeys[i].AllowedModels))
		for _, mid := range s.state.APIKeys[i].AllowedModels {
			if mid != id {
				filtered = append(filtered, mid)
			}
		}
		s.state.APIKeys[i].AllowedModels = filtered
	}

	return s.saveLocked()
}

func (s *Store) GetAPIModel(id string) (ClientModel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.state.APIModels {
		if m.ID == id {
			return m, true
		}
	}
	return ClientModel{}, false
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		t := strings.TrimSpace(item)
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func (s *Store) UpsertAPIGroup(g APIGroup) (APIGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return APIGroup{}, fmt.Errorf("预设组名称不能为空")
	}
	g.Icon = NormalizeIconData(g.Icon)
	g.ModelIDs = dedupeStrings(g.ModelIDs)
	g.UpdatedAt = nowISO()

	if g.ID == "" {
		g.ID = fmt.Sprintf("apigrp-%d", time.Now().UnixMilli())
		g.SortOrder = len(s.state.APIGroups)
		s.state.APIGroups = append(s.state.APIGroups, g)
		return g, s.saveLocked()
	}

	found := false
	for i := range s.state.APIGroups {
		if s.state.APIGroups[i].ID == g.ID {
			if g.SortOrder == 0 && i > 0 && s.state.APIGroups[i].SortOrder != 0 {
				g.SortOrder = s.state.APIGroups[i].SortOrder
			}
			s.state.APIGroups[i] = g
			found = true
			break
		}
	}
	if !found {
		g.SortOrder = len(s.state.APIGroups)
		s.state.APIGroups = append(s.state.APIGroups, g)
	}
	return g, s.saveLocked()
}

func (s *Store) DeleteAPIGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]APIGroup, 0, len(s.state.APIGroups))
	for _, g := range s.state.APIGroups {
		if g.ID != id {
			next = append(next, g)
		}
	}
	s.state.APIGroups = next

	for i := range s.state.APIModels {
		if s.state.APIModels[i].GroupID == id {
			s.state.APIModels[i].GroupID = ""
		}
	}
	for i := range s.state.APIKeys {
		filtered := make([]string, 0, len(s.state.APIKeys[i].GroupIDs))
		for _, gid := range s.state.APIKeys[i].GroupIDs {
			if gid != id {
				filtered = append(filtered, gid)
			}
		}
		s.state.APIKeys[i].GroupIDs = filtered
	}
	return s.saveLocked()
}

func (s *Store) ReorderAPICatalog(groupIDs []string, groupModels map[string][]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(groupIDs) > 0 {
		orderMap := make(map[string]int, len(groupIDs))
		for idx, id := range groupIDs {
			orderMap[id] = idx
		}
		nextOrder := len(groupIDs)
		for i := range s.state.APIGroups {
			if ord, ok := orderMap[s.state.APIGroups[i].ID]; ok {
				s.state.APIGroups[i].SortOrder = ord
			} else {
				s.state.APIGroups[i].SortOrder = nextOrder
				nextOrder++
			}
		}
		s.state.APIGroups = sortAPIGroupsSlice(s.state.APIGroups)
	}

	if len(groupModels) > 0 {
		validGroups := make(map[string]int, len(s.state.APIGroups))
		for i, g := range s.state.APIGroups {
			validGroups[g.ID] = i
		}
		modelAssignment := make(map[string]struct {
			groupID string
			order   int
		})
		for gid, mids := range groupModels {
			cleanMids := dedupeStrings(mids)
			if gIdx, ok := validGroups[gid]; ok {
				s.state.APIGroups[gIdx].ModelIDs = cleanMids
				for idx, mid := range cleanMids {
					modelAssignment[mid] = struct {
						groupID string
						order   int
					}{groupID: gid, order: idx}
				}
			} else if gid == "" || gid == "__ungrouped__" {
				for idx, mid := range cleanMids {
					modelAssignment[mid] = struct {
						groupID string
						order   int
					}{groupID: "", order: idx}
				}
			}
		}
		for i := range s.state.APIModels {
			if assign, ok := modelAssignment[s.state.APIModels[i].ID]; ok {
				s.state.APIModels[i].GroupID = assign.groupID
				s.state.APIModels[i].SortOrder = assign.order
			}
		}
	}

	return s.saveLocked()
}

func (s *Store) UpsertAPIKey(k APIKeyEntry) (APIKeyEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k.Name = strings.TrimSpace(k.Name)
	if k.Name == "" {
		k.Name = "API Key"
	}
	k.GroupIDs = dedupeStrings(k.GroupIDs)
	k.AllowedModels = dedupeStrings(k.AllowedModels)
	now := nowISO()
	k.UpdatedAt = now

	if k.ID != "" {
		for i := range s.state.APIKeys {
			if s.state.APIKeys[i].ID == k.ID {
				existing := s.state.APIKeys[i]
				if strings.TrimSpace(k.Key) == "" || k.Key == "********" || !strings.HasPrefix(k.Key, "sk-zs-") {
					k.Key = existing.Key
				}
				k.KeyPrefix = maskKeyPrefix(k.Key)
				k.CreatedAt = existing.CreatedAt
				k.LastUsedAt = existing.LastUsedAt
				k.RequestCount = existing.RequestCount
				s.state.APIKeys[i] = k
				return k, s.saveLocked()
			}
		}
	}

	k.ID = fmt.Sprintf("apikey-%d", time.Now().UnixMilli())
	if !strings.HasPrefix(strings.TrimSpace(k.Key), "sk-zs-") || len(strings.TrimSpace(k.Key)) < 24 {
		k.Key = GenerateServerAPIKey()
	} else {
		k.Key = strings.TrimSpace(k.Key)
	}
	k.KeyPrefix = maskKeyPrefix(k.Key)
	k.CreatedAt = now
	s.state.APIKeys = append(s.state.APIKeys, k)
	return k, s.saveLocked()
}

func (s *Store) RegenerateAPIKey(id string) (APIKeyEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.APIKeys {
		if s.state.APIKeys[i].ID == id {
			s.state.APIKeys[i].Key = GenerateServerAPIKey()
			s.state.APIKeys[i].KeyPrefix = maskKeyPrefix(s.state.APIKeys[i].Key)
			s.state.APIKeys[i].UpdatedAt = nowISO()
			cp := s.state.APIKeys[i]
			return cp, s.saveLocked()
		}
	}
	return APIKeyEntry{}, fmt.Errorf("未找到该 API Key")
}

func (s *Store) DeleteAPIKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]APIKeyEntry, 0, len(s.state.APIKeys))
	for _, k := range s.state.APIKeys {
		if k.ID != id {
			next = append(next, k)
		}
	}
	s.state.APIKeys = next
	return s.saveLocked()
}

func (s *Store) AuthenticateAPIKey(secret string) (APIKeyEntry, bool) {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return APIKeyEntry{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.state.APIKeys {
		if !k.Enabled || k.Key == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(trimmed), []byte(k.Key)) == 1 {
			return k, true
		}
	}
	return APIKeyEntry{}, false
}

func (s *Store) TouchAPIKeyUsage(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.APIKeys {
		if s.state.APIKeys[i].ID == id {
			s.state.APIKeys[i].RequestCount++
			s.state.APIKeys[i].LastUsedAt = nowISO()
			_ = s.saveLocked()
			return
		}
	}
}

func (s *Store) ListAllowedAPIModels(k APIKeyEntry) []ClientModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sorted := sortAPIModelsWithGroups(s.state.APIModels, s.state.APIGroups)
	if k.AllowAllModels {
		out := make([]ClientModel, 0, len(sorted))
		for _, m := range sorted {
			if m.Enabled {
				out = append(out, m)
			}
		}
		return out
	}

	allowedSet := make(map[string]bool)
	for _, mid := range k.AllowedModels {
		allowedSet[mid] = true
	}

	groupSet := make(map[string]bool, len(k.GroupIDs))
	for _, gid := range k.GroupIDs {
		groupSet[gid] = true
	}
	for _, g := range s.state.APIGroups {
		if groupSet[g.ID] {
			for _, mid := range g.ModelIDs {
				allowedSet[mid] = true
			}
		}
	}

	out := make([]ClientModel, 0, len(allowedSet))
	for _, m := range sorted {
		if !m.Enabled {
			continue
		}
		if allowedSet[m.ID] || (m.GroupID != "" && groupSet[m.GroupID]) {
			out = append(out, m)
		}
	}
	return out
}

func (s *Store) GetAllowedAPIModel(k APIKeyEntry, modelID string) (ClientModel, bool) {
	allowed := s.ListAllowedAPIModels(k)
	for _, m := range allowed {
		if m.ID == modelID {
			return m, true
		}
	}
	return ClientModel{}, false
}

// ======================= AUDIT LOGS =======================

func (s *Store) AppendLog(entry RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	if entry.Timestamp == "" {
		entry.Timestamp = nowISO()
	}
	s.state.Logs = append([]RequestLog{entry}, s.state.Logs...)
	if len(s.state.Logs) > 200 {
		s.state.Logs = s.state.Logs[:200]
	}
	_ = s.saveLocked()
}

func (s *Store) ClearLogs() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Logs = []RequestLog{}
	return s.saveLocked()
}

func (s *Store) AppendAPILog(entry RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("apireq-%d", time.Now().UnixNano())
	}
	if entry.Timestamp == "" {
		entry.Timestamp = nowISO()
	}
	s.state.APILogs = append([]RequestLog{entry}, s.state.APILogs...)
	if len(s.state.APILogs) > 200 {
		s.state.APILogs = s.state.APILogs[:200]
	}
	_ = s.saveLocked()
}

func (s *Store) ClearAPILogs() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.APILogs = []RequestLog{}
	return s.saveLocked()
}
