package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestManagedAssetsDownloadOnlyWhenChangedAndResolvePaths(t *testing.T) {
	var requests atomic.Int64
	fullchain := []byte("certificate")
	privateKey := []byte("private-key")
	reference := model.ManagedAssetReference{Kind: "certificate", ID: 7, Revision: managedCertificateRevision(fullchain, privateKey)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/api/v1/agent/assets" || r.Header.Get("X-Agent-ID") != "agent-1" || r.Header.Get("Authorization") != "Bearer token-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request model.ManagedAssetRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Assets) != 1 || request.Assets[0].Kind != reference.Kind || request.Assets[0].ID != reference.ID {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		requested := request.Assets[0]
		_ = json.NewEncoder(w).Encode(model.ManagedAssetResponse{Assets: []model.ManagedAsset{{ManagedAssetReference: requested, Files: []model.ManagedAssetFile{
			{Name: "fullchain.pem", ContentB64: base64.StdEncoding.EncodeToString(fullchain), Mode: 0o600},
			{Name: "privkey.pem", ContentB64: base64.StdEncoding.EncodeToString(privateKey), Mode: 0o600},
		}}}})
	}))
	defer server.Close()
	stateDir := t.TempDir()
	runner := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: "token-1", StateDir: stateDir, AllowInsecureController: true})
	config := `{"inbounds":[{"tls":{"certificate_path":"oboard-asset://certificate/7/fullchain.pem","key_path":"oboard-asset://certificate/7/privkey.pem"}}]}`
	resolved, changed, err := runner.syncManagedAssets(context.Background(), []model.ManagedAssetReference{reference}, config)
	if err != nil || !changed {
		t.Fatalf("first asset sync changed=%v err=%v", changed, err)
	}
	assetDir := runner.managedAssetDir(reference)
	if strings.Contains(resolved, "oboard-asset://") || !strings.Contains(resolved, filepath.Join(assetDir, "privkey.pem")) {
		t.Fatalf("managed paths were not resolved: %s", resolved)
	}
	for _, path := range []string{assetDir, filepath.Join(assetDir, "fullchain.pem"), filepath.Join(assetDir, "privkey.pem")} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if info.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("mode for %s = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
	_, changed, err = runner.syncManagedAssets(context.Background(), []model.ManagedAssetReference{reference}, config)
	if err != nil || !changed || requests.Load() != 1 {
		t.Fatalf("uncommitted sync changed=%v requests=%d err=%v", changed, requests.Load(), err)
	}
	if err := runner.cleanupManagedAssets([]model.ManagedAssetReference{reference}); err != nil {
		t.Fatal(err)
	}
	_, changed, err = runner.syncManagedAssets(context.Background(), []model.ManagedAssetReference{reference}, config)
	if err != nil || changed || requests.Load() != 1 {
		t.Fatalf("committed sync changed=%v requests=%d err=%v", changed, requests.Load(), err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "privkey.pem"), []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, changed, err = runner.syncManagedAssets(context.Background(), []model.ManagedAssetReference{reference}, config)
	if err != nil || !changed || requests.Load() != 2 {
		t.Fatalf("corrupted cache was not refreshed: changed=%v requests=%d err=%v", changed, requests.Load(), err)
	}
	if err := runner.cleanupManagedAssets([]model.ManagedAssetReference{reference}); err != nil {
		t.Fatal(err)
	}
	nextReference := reference
	privateKey = []byte("private-key-2")
	nextReference.Revision = managedCertificateRevision(fullchain, privateKey)
	oldAssetDir := assetDir
	_, changed, err = runner.syncManagedAssets(context.Background(), []model.ManagedAssetReference{nextReference}, config)
	if err != nil || !changed || requests.Load() != 3 {
		t.Fatalf("rotated sync changed=%v requests=%d err=%v", changed, requests.Load(), err)
	}
	if _, err := os.Stat(oldAssetDir); err != nil {
		t.Fatalf("old certificate revision was removed before apply commit: %v", err)
	}
	if err := runner.cleanupManagedAssets([]model.ManagedAssetReference{nextReference}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldAssetDir); !os.IsNotExist(err) {
		t.Fatalf("old certificate revision still exists after apply commit: %v", err)
	}
	assetDir = runner.managedAssetDir(nextReference)
	if err := runner.cleanupManagedAssets(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(assetDir); !os.IsNotExist(err) {
		t.Fatalf("unreferenced certificate directory still exists: %v", err)
	}
}

func TestApplyCoreConfigTaskSynchronizesAssetsAfterVersionGate(t *testing.T) {
	var requests atomic.Int64
	fullchain := []byte("certificate")
	privateKey := []byte("private-key")
	reference := model.ManagedAssetReference{Kind: "certificate", ID: 7, Revision: managedCertificateRevision(fullchain, privateKey)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(model.ManagedAssetResponse{Assets: []model.ManagedAsset{{ManagedAssetReference: reference, Files: []model.ManagedAssetFile{
			{Name: "fullchain.pem", ContentB64: base64.StdEncoding.EncodeToString(fullchain), Mode: 0o600},
			{Name: "privkey.pem", ContentB64: base64.StdEncoding.EncodeToString(privateKey), Mode: 0o600},
		}}}})
	}))
	defer server.Close()
	stateDir := t.TempDir()
	runner := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: "token-1", StateDir: stateDir, CoreBinary: filepath.Join(stateDir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large", AllowInsecureController: true})
	payload := model.ApplyCoreConfigTaskPayload{
		Config: `{"inbounds":[{"tls":{"certificate_path":"oboard-asset://certificate/7/fullchain.pem","key_path":"oboard-asset://certificate/7/privkey.pem"}}]}`,
		Assets: []model.ManagedAssetReference{reference},
	}
	result, err := runner.applyCoreConfigTask(42, payload)
	if err != nil {
		t.Fatal(err)
	}
	if result["managed_assets_changed"] != true || requests.Load() != 1 {
		t.Fatalf("unexpected apply result=%#v requests=%d", result, requests.Load())
	}
	current, err := os.ReadFile(filepath.Join(stateDir, "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(current), "oboard-asset://") || !strings.Contains(string(current), filepath.Join(runner.managedAssetDir(reference), "privkey.pem")) {
		t.Fatalf("applied config did not contain resolved asset paths: %s", current)
	}
	stale := payload
	stale.Assets = []model.ManagedAssetReference{{Kind: "certificate", ID: 7, Revision: managedCertificateRevision(fullchain, []byte("private-key-2"))}}
	staleResult, err := runner.applyCoreConfigTask(41, stale)
	requireSuperseded(t, staleResult, err, 42)
	// The decisive property: a skipped task touches nothing. Syncing or pruning
	// against its stale asset list would delete files the current config needs.
	if requests.Load() != 1 {
		t.Fatalf("stale task requested assets: requests=%d", requests.Load())
	}
}

func TestManagedAssetDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(root, "managed-assets")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateAssetDirectory(link); err == nil {
		t.Fatal("symbolic-link managed asset directory was accepted")
	}
}

func TestManagedRoutingRuleSetAssetInstallResolveAndCleanupByKind(t *testing.T) {
	content := []byte(`{"version":1,"rules":[{"domain":["example.com"]}]}`)
	sum := sha256.Sum256(content)
	reference := model.ManagedAssetReference{Kind: "routing_rule_set", ID: 7, Revision: hex.EncodeToString(sum[:])}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(model.ManagedAssetResponse{Assets: []model.ManagedAsset{{ManagedAssetReference: reference, Files: []model.ManagedAssetFile{{Name: "rules.json", ContentB64: base64.StdEncoding.EncodeToString(content), Mode: 0o600}}}}})
	}))
	defer server.Close()
	runner := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: "token-1", StateDir: t.TempDir(), AllowInsecureController: true})
	config := `{"route":{"rule_set":[{"type":"local","tag":"routing-rule-set-7","format":"source","path":"oboard-asset://routing-rule-set/7/rules.json"}]}}`
	resolved, changed, err := runner.syncManagedAssets(context.Background(), []model.ManagedAssetReference{reference}, config)
	if err != nil || !changed || strings.Contains(resolved, "oboard-asset://") {
		t.Fatalf("rule-set sync changed=%v err=%v config=%s", changed, err, resolved)
	}
	certificateReference := model.ManagedAssetReference{Kind: "certificate", ID: 7, Revision: managedCertificateRevision([]byte("cert"), []byte("key"))}
	if err := runner.cleanupManagedAssets([]model.ManagedAssetReference{reference}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(runner.managedAssetDir(reference)); err != nil {
		t.Fatalf("rule-set asset removed by same numeric certificate id: %v", err)
	}
	if _, err := os.Stat(runner.managedAssetDir(certificateReference)); err == nil {
		t.Fatal("unexpected certificate asset exists")
	}
	if err := os.WriteFile(filepath.Join(runner.managedAssetDir(reference), "rules.json"), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runner.managedAssetFilesReady(reference) {
		t.Fatal("corrupt rule-set cache was accepted")
	}
}
