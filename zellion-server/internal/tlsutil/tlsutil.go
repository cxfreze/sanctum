package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type CertInfo struct {
	CertExists bool      `json:"certExists"`
	KeyExists  bool      `json:"keyExists"`
	Valid      bool      `json:"valid"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	DNSNames   []string  `json:"dnsNames"`
	IPs        []string  `json:"ips"`
	NotBefore  string    `json:"notBefore"`
	NotAfter   string    `json:"notAfter"`
	Error      string    `json:"error,omitempty"`
}

type DynamicCertLoader struct {
	mu          sync.RWMutex
	certPath    string
	keyPath     string
	cachedCert  *tls.Certificate
	certModTime time.Time
	keyModTime  time.Time
}

func NewDynamicCertLoader(certPath, keyPath string) *DynamicCertLoader {
	return &DynamicCertLoader{
		certPath: certPath,
		keyPath:  keyPath,
	}
}

func (l *DynamicCertLoader) UpdatePaths(certPath, keyPath string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.certPath != certPath || l.keyPath != keyPath {
		l.certPath = certPath
		l.keyPath = keyPath
		l.cachedCert = nil
	}
}

func (l *DynamicCertLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.RLock()
	certPath := l.certPath
	keyPath := l.keyPath
	cached := l.cachedCert
	cMod := l.certModTime
	kMod := l.keyModTime
	l.mu.RUnlock()

	cStat, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("stat cert %s: %w", certPath, err)
	}
	kStat, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat key %s: %w", keyPath, err)
	}

	if cached != nil && cStat.ModTime().Equal(cMod) && kStat.ModTime().Equal(kMod) {
		return cached, nil
	}

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	l.mu.Lock()
	l.cachedCert = &pair
	l.certModTime = cStat.ModTime()
	l.keyModTime = kStat.ModTime()
	l.mu.Unlock()

	return &pair, nil
}

func InspectCertFiles(certPath, keyPath string) CertInfo {
	info := CertInfo{}
	if st, err := os.Stat(certPath); err == nil && !st.IsDir() {
		info.CertExists = true
	}
	if st, err := os.Stat(keyPath); err == nil && !st.IsDir() {
		info.KeyExists = true
	}
	if !info.CertExists || !info.KeyExists {
		return info
	}

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	if len(pair.Certificate) == 0 {
		info.Error = "empty certificate chain"
		return info
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		info.Error = err.Error()
		return info
	}

	info.Valid = true
	info.Subject = leaf.Subject.CommonName
	if info.Subject == "" {
		info.Subject = leaf.Subject.String()
	}
	info.Issuer = leaf.Issuer.CommonName
	if info.Issuer == "" {
		info.Issuer = leaf.Issuer.String()
	}
	info.DNSNames = leaf.DNSNames
	for _, ip := range leaf.IPAddresses {
		info.IPs = append(info.IPs, ip.String())
	}
	info.NotBefore = leaf.NotBefore.Format(time.RFC3339)
	info.NotAfter = leaf.NotAfter.Format(time.RFC3339)
	return info
}

func SavePEMPair(certPath, keyPath, certPEM, keyPEM string) error {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return fmt.Errorf("invalid PEM certificate/key pair: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, []byte(certPEM+"\n"), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM+"\n"), 0600); err != nil {
		return err
	}
	return nil
}

func GenerateSelfSignedCert(certPath, keyPath string, hosts []string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}

	commonName := "zellion-sanctum.local"
	var dnsNames []string
	var ips []net.IP
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, h)
			if commonName == "zellion-sanctum.local" {
				commonName = h
			}
		}
	}
	if len(ips) == 0 {
		ips = append(ips, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	}
	if len(dnsNames) == 0 {
		dnsNames = append(dnsNames, "localhost")
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ZEllion Sanctum Gateway"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return SavePEMPair(certPath, keyPath, string(certOut), string(keyOut))
}
