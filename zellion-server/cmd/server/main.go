package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"zellion-server/internal/server"
	"zellion-server/internal/store"
	"zellion-server/internal/tlsutil"
	"zellion-server/internal/zsconfig"
)

func main() {
	zsPath := zsconfig.ResolveZSPath()
	zsMgr, err := zsconfig.LoadOrInit(zsPath)
	if err != nil {
		log.Fatalf("[ZEllion-Server] 无法加载 ZS 配置文件 (%s): %v", zsPath, err)
	}
	cfg := zsMgr.Get()

	dataPath := zsMgr.ResolvePath(cfg.DataFile)
	st, err := store.NewStore(dataPath)
	if err != nil {
		log.Fatalf("[ZEllion-Server] 初始化网关存储失败 (%s): %v", dataPath, err)
	}

	certPath := zsMgr.ResolvePath(cfg.TLSCertFile)
	keyPath := zsMgr.ResolvePath(cfg.TLSKeyFile)
	certLoader := tlsutil.NewDynamicCertLoader(certPath, keyPath)

	gw := server.NewGatewayServer(zsMgr, st, certLoader)
	apiStatus := gw.SyncAPIServiceListeners()

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	displayHost := cfg.Host
	if displayHost == "0.0.0.0" || displayHost == "::" {
		displayHost = "127.0.0.1"
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           gw,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	scheme := "http"
	if cfg.TLSEnabled {
		scheme = "https"
		// Auto-generate self-signed cert if TLS_ENABLED=true but cert files don't exist yet so startup never crashes
		info := tlsutil.InspectCertFiles(certPath, keyPath)
		if !info.Valid {
			log.Printf("[ZEllion-Server] 检测到 TLS_ENABLED=true 但未发现有效证书，正在生成初始自签名证书 (%s)...", certPath)
			if genErr := tlsutil.GenerateSelfSignedCert(certPath, keyPath, []string{"localhost", "127.0.0.1", displayHost}); genErr != nil {
				log.Fatalf("[ZEllion-Server] 无法初始化 TLS 证书: %v", genErr)
			}
		}
	}

	fmt.Println("========================================================================")
	fmt.Println("  ✦ ZEllion Server · Magpie LLM Aggregator & Sanctum Gateway v2.6")
	fmt.Println("========================================================================")
	fmt.Printf("  配置文件 (ZS) : %s\n", cfg.FilePath)
	fmt.Printf("  监听地址      : %s://%s\n", scheme, addr)
	fmt.Printf("  隐蔽模式      : 已开启 (浏览器直接访问 %s://%s:%d/ 返回完全空白)\n", scheme, displayHost, cfg.Port)
	fmt.Printf("  管理后台入口  : %s://%s:%d%s\n", scheme, displayHost, cfg.Port, cfg.AdminPath)
	fmt.Printf("  客户端鉴权    : %s\n", map[bool]string{true: "已启用 CLIENT_TOKEN 校验", false: "免密钥直连 (可在后台开启)"}[cfg.ClientToken != ""])
	if apiStatus.Enabled {
		if apiStatus.Running {
			fmt.Printf("  独立 API 服务 : 已启用 (仅 HTTPS · 端口 %d)\n", apiStatus.HTTPSPort)
		} else {
			fmt.Printf("  独立 API 服务 : 启动异常 (%s)\n", apiStatus.LastError)
		}
	} else {
		fmt.Printf("  独立 API 服务 : 未启用 (可在管理后台「对外 API 服务」一键开启 HTTPS 免端口访问)\n")
	}
	fmt.Println("========================================================================")

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ZEllion-Server] 端口监听失败 (%s): %v\n", addr, err)
		os.Exit(1)
	}

	if cfg.TLSEnabled {
		tlsCfg := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certLoader.GetCertificate,
		}
		tlsLn := tls.NewListener(ln, tlsCfg)
		if err := httpSrv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ZEllion-Server] HTTPS 服务异常退出: %v", err)
		}
	} else {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ZEllion-Server] HTTP 服务异常退出: %v", err)
		}
	}
}
