package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestHTTP01CertificateUsesDedicatedReportEndpoint(t *testing.T) {
	certificatePEM, privateKeyPEM := agentTestCertificateMaterial(t, []string{"entry.example.com"})
	fixtureDir := t.TempDir()
	certSource := filepath.Join(fixtureDir, "cert.pem")
	keySource := filepath.Join(fixtureDir, "key.pem")
	if err := os.WriteFile(certSource, []byte(certificatePEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keySource, []byte(privateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(fixtureDir, "fake-acme.sh")
	scriptBody := `#!/bin/sh
set -eu
mode=""
cert_file=""
fullchain_file=""
key_file=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --issue) mode=issue ;;
    --install-cert) mode=install ;;
    --cert-file) shift; cert_file=$1 ;;
    --fullchain-file) shift; fullchain_file=$1 ;;
    --key-file) shift; key_file=$1 ;;
  esac
  shift
done
if [ "$mode" = install ]; then
  cp "$FAKE_ACME_CERT" "$cert_file"
  cp "$FAKE_ACME_CERT" "$fullchain_file"
  cp "$FAKE_ACME_KEY" "$key_file"
fi
`
	if err := os.WriteFile(script, []byte(scriptBody), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OBOARD_ACME_SH", script)
	t.Setenv("FAKE_ACME_CERT", certSource)
	t.Setenv("FAKE_ACME_KEY", keySource)
	var report model.CertificateIssueReport
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/certificate-issues" || r.Header.Get("X-Agent-ID") != "agent-1" || r.Header.Get("Authorization") != "Bearer token-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer controller.Close()
	runner := newTestRunner(t, Config{ControllerURL: controller.URL, AgentID: "agent-1", AgentToken: "token-1", StateDir: t.TempDir(), AllowInsecureController: true})
	result, err := runner.issueCertificateHTTP(42, model.IssueCertificateHTTPTaskPayload{CertificateID: 9, Domains: []string{"entry.example.com"}, ACMECA: "letsencrypt"})
	if err != nil {
		t.Fatal(err)
	}
	if result["certificate_id"] != int64(9) || report.TaskID != 42 || report.CertificateID != 9 || report.PrivateKeyPEM != privateKeyPEM || report.FullchainPEM != certificatePEM {
		t.Fatalf("unexpected HTTP-01 result=%#v report=%#v", result, report)
	}
}

func agentTestCertificateMaterial(t *testing.T, domains []string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains, NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}
