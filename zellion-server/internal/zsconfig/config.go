package zsconfig

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Config holds the bootstrap configuration loaded from the extensionless "ZS" file.
type Config struct {
	FilePath    string `json:"filePath"`
	BaseDir     string `json:"baseDir"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	AdminPath   string `json:"adminPath"`
	AdminUser   string `json:"adminUser"`
	AdminPass   string `json:"adminPass"`
	ClientToken string `json:"clientToken"`
	TLSEnabled  bool   `json:"tlsEnabled"`
	TLSCertFile string `json:"tlsCertFile"`
	TLSKeyFile  string `json:"tlsKeyFile"`
	DataFile    string `json:"dataFile"`
}

type Manager struct {
	mu  sync.RWMutex
	cfg Config
}

// ResolveZSPath finds the extensionless "ZS" file in current working directory or executable directory.
func ResolveZSPath() string {
	if envPath := strings.TrimSpace(os.Getenv("ZS_CONFIG_PATH")); envPath != "" {
		if abs, err := filepath.Abs(envPath); err == nil {
			return abs
		}
		return envPath
	}

	cwd, err := os.Getwd()
	if err == nil {
		cand := filepath.Join(cwd, "ZS")
		if info, statErr := os.Stat(cand); statErr == nil && !info.IsDir() {
			return cand
		}
	}

	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		cand := filepath.Join(exeDir, "ZS")
		if info, statErr := os.Stat(cand); statErr == nil && !info.IsDir() {
			return cand
		}
		return cand
	}

	if cwd != "" {
		return filepath.Join(cwd, "ZS")
	}
	return "ZS"
}

func LoadOrInit(path string) (*Manager, error) {
	if path == "" {
		path = ResolveZSPath()
	}
	absPath, err := filepath.Abs(path)
	if err == nil {
		path = absPath
	}
	baseDir := filepath.Dir(path)

	cfg := Config{
		FilePath:    path,
		BaseDir:     baseDir,
		Host:        "0.0.0.0",
		Port:        18080,
		AdminPath:   "/zs-admin",
		AdminUser:   "admin",
		AdminPass:   "zellion2026",
		ClientToken: "",
		TLSEnabled:  false,
		TLSCertFile: "./certs/fullchain.pem",
		TLSKeyFile:  "./certs/privkey.pem",
		DataFile:    "./data/gateway-state.json",
	}

	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		m := &Manager{cfg: cfg}
		if writeErr := m.Save(cfg); writeErr != nil {
			return nil, fmt.Errorf("create default ZS file: %w", writeErr)
		}
		return m, nil
	}

	parsed, err := parseFile(path, cfg)
	if err != nil {
		return nil, err
	}
	return &Manager{cfg: parsed}, nil
}

func parseFile(path string, defaults Config) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return defaults, err
	}
	defer f.Close()

	cfg := defaults
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimPrefix(line, "\ufeff")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"'`)

		switch key {
		case "HOST", "IP", "BIND", "LISTEN_IP":
			if val != "" {
				cfg.Host = val
			}
		case "PORT", "ADMIN_PORT", "LISTEN_PORT":
			if p, pErr := strconv.Atoi(val); pErr == nil && p > 0 && p <= 65535 {
				cfg.Port = p
			}
		case "ADMIN_PATH", "MANAGE_PATH":
			cfg.AdminPath = normalizeAdminPath(val)
		case "ADMIN_USER", "USERNAME", "USER":
			if val != "" {
				cfg.AdminUser = val
			}
		case "ADMIN_PASS", "PASSWORD", "PASS":
			if val != "" {
				cfg.AdminPass = val
			}
		case "CLIENT_TOKEN", "API_TOKEN", "TOKEN":
			cfg.ClientToken = val
		case "TLS_ENABLED", "HTTPS", "SSL":
			cfg.TLSEnabled = parseBool(val)
		case "TLS_CERT_FILE", "CERT_FILE", "SSL_CERT":
			if val != "" {
				cfg.TLSCertFile = val
			}
		case "TLS_KEY_FILE", "KEY_FILE", "SSL_KEY":
			if val != "" {
				cfg.TLSKeyFile = val
			}
		case "DATA_FILE":
			if val != "" {
				cfg.DataFile = val
			}
		}
	}
	cfg.AdminPath = normalizeAdminPath(cfg.AdminPath)
	return cfg, scanner.Err()
}

func normalizeAdminPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/zs-admin"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" || strings.HasPrefix(p, "/v1/zs") {
		return "/zs-admin"
	}
	return p
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func (m *Manager) Get() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *Manager) ResolvePath(relOrAbs string) string {
	m.mu.RLock()
	base := m.cfg.BaseDir
	m.mu.RUnlock()
	if filepath.IsAbs(relOrAbs) {
		return relOrAbs
	}
	return filepath.Join(base, relOrAbs)
}

func (m *Manager) Save(next Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	next.FilePath = m.cfg.FilePath
	next.BaseDir = m.cfg.BaseDir
	if strings.TrimSpace(next.Host) == "" {
		next.Host = "0.0.0.0"
	}
	if next.Port <= 0 || next.Port > 65535 {
		next.Port = 18080
	}
	next.AdminPath = normalizeAdminPath(next.AdminPath)
	if strings.TrimSpace(next.AdminUser) == "" {
		next.AdminUser = "admin"
	}
	if strings.TrimSpace(next.AdminPass) == "" {
		next.AdminPass = m.cfg.AdminPass
	}
	if strings.TrimSpace(next.TLSCertFile) == "" {
		next.TLSCertFile = "./certs/fullchain.pem"
	}
	if strings.TrimSpace(next.TLSKeyFile) == "" {
		next.TLSKeyFile = "./certs/privkey.pem"
	}
	if strings.TrimSpace(next.DataFile) == "" {
		next.DataFile = "./data/gateway-state.json"
	}

	content := fmt.Sprintf(`# ============================================================================
# ZEllion Server 核心启动配置 (无后缀文件 ZS)
# 说明:
# 1. 直接在浏览器访问 http(s)://IP:PORT/ 或任何未知路径将返回完全空白 (HTTP 204 无内容)
# 2. 仅访问下方 ADMIN_PATH 指定的隐蔽管理入口才能打开 Magpie 聚合管理后台
# 3. 客户端 ZEllion Sanctum 通过安装目录下的 ZS 文件连接本服务端的 IP:PORT
# ============================================================================

HOST=%s
PORT=%d
ADMIN_PATH=%s
ADMIN_USER=%s
ADMIN_PASS=%s
CLIENT_TOKEN=%s
TLS_ENABLED=%v
TLS_CERT_FILE=%s
TLS_KEY_FILE=%s
DATA_FILE=%s
`,
		next.Host,
		next.Port,
		next.AdminPath,
		next.AdminUser,
		next.AdminPass,
		next.ClientToken,
		next.TLSEnabled,
		next.TLSCertFile,
		next.TLSKeyFile,
		next.DataFile,
	)

	if err := os.MkdirAll(filepath.Dir(next.FilePath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(next.FilePath, []byte(content), 0600); err != nil {
		return err
	}
	m.cfg = next
	return nil
}
