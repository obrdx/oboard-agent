package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
)

func TestDownloadAndInstallSignedRelease(t *testing.T) {
	oldKey := version.ReleasePublicKey
	defer func() { version.ReleasePublicKey = oldKey }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	realmName := "oboard-realm-" + runtime.GOOS + "-" + runtime.GOARCH
	agentData := []byte("signed-agent-binary")
	coreData := []byte("signed-core-binary")
	realmData := []byte("signed-realm-binary")
	manifest := security.ReleaseManifest{
		Version: "1.2.3", Build: "build-123", Commit: "abc123", Date: "2026-07-17T00:00:00Z", Repo: "example/oboard-agent",
		Files: []security.ReleaseManifestFile{
			{Name: agentName, Component: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex(agentData), Size: int64(len(agentData))},
			{Name: coreName, Component: "sb", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex(coreData), Size: int64(len(coreData))},
			{Name: realmName, Component: "realm", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex(realmData), Size: int64(len(realmData))},
		},
	}
	privateKey := base64.RawStdEncoding.EncodeToString(priv)
	signature, err := security.SignReleaseManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := security.CanonicalReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string][]byte{
		"/release-manifest.json":     manifestJSON,
		"/release-manifest.json.sig": []byte(signature),
		"/" + agentName:              agentData,
		"/" + coreName:               coreData,
		"/" + realmName:              realmData,
	}
	var mu sync.Mutex
	requested := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()
		body, ok := assets[strings.TrimPrefix(r.URL.Path, "/hidden/downloads/github")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	dir := t.TempDir()
	targets := signedReleaseTargets{Agent: filepath.Join(dir, "oboard-agent"), Core: filepath.Join(dir, "oboard-sb"), Realm: filepath.Join(dir, "oboard-realm")}
	if err := os.WriteFile(targets.Agent, []byte("old-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targets.Core, []byte("old-core"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := New(Config{StateDir: dir, UpdateRepo: manifest.Repo}).downloadAndInstallSignedRelease(context.Background(), server.Client(), server.URL+"/hidden/downloads/github", manifest.Repo, manifest.Build, targets, ".oboard-update")
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Build != manifest.Build {
		t.Fatalf("installed build = %q", got.Manifest.Build)
	}
	assertFileContent(t, targets.Agent, agentData)
	assertFileContent(t, targets.Core, coreData)
	// realm is bundled like the kernel, so a first install that had no realm on
	// disk must still end up with the signed binary in place.
	assertFileContent(t, targets.Realm, realmData)
	mu.Lock()
	sort.Strings(requested)
	gotPaths := append([]string(nil), requested...)
	mu.Unlock()
	wantPaths := []string{"/" + agentName, "/" + coreName, "/" + realmName, "/release-manifest.json", "/release-manifest.json.sig"}
	sort.Strings(wantPaths)
	if len(gotPaths) != len(wantPaths) {
		t.Fatalf("requested paths = %#v", gotPaths)
	}
	for i := range wantPaths {
		if gotPaths[i] != "/hidden/downloads/github"+wantPaths[i] {
			t.Fatalf("requested paths = %#v", gotPaths)
		}
	}
}

func TestDownloadReleaseAssetResumesTruncatedResponse(t *testing.T) {
	data := []byte("complete-signed-binary")
	expected := security.ReleaseManifestFile{SHA256: sha256Hex(data), Size: int64(len(data))}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		if request == 2 {
			wantRange := fmt.Sprintf("bytes=%d-", len(data)/2)
			if got := r.Header.Get("Range"); got != wantRange {
				t.Errorf("resume range = %q, want %q", got, wantRange)
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", len(data)/2, len(data)-1, len(data)))
			w.Header().Set("Content-Length", strconv.Itoa(len(data)-len(data)/2))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(data[len(data)/2:])
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data[:len(data)/2])
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "oboard-agent-linux-amd64")
	policy := releaseDownloadPolicy{attempts: 3}
	if err := downloadReleaseAssetWithPolicy(context.Background(), server.Client(), server.URL, path, maxReleaseBinaryBytes, &expected, policy); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
	assertFileContent(t, path, data)
}

func TestDownloadReleaseAssetReportsExhaustedRetries(t *testing.T) {
	data := []byte("complete-signed-binary")
	expected := security.ReleaseManifestFile{SHA256: sha256Hex(data), Size: int64(len(data))}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		start := int64(0)
		if rawRange := r.Header.Get("Range"); rawRange != "" {
			if _, err := fmt.Sscanf(rawRange, "bytes=%d-", &start); err != nil {
				t.Errorf("invalid range %q: %v", rawRange, err)
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(data)-1, len(data)))
			w.Header().Set("Content-Length", strconv.Itoa(len(data)-int(start)))
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		}
		remaining := data[start:]
		cut := len(remaining) / 2
		if cut < 1 {
			cut = 1
		}
		_, _ = w.Write(remaining[:cut])
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "oboard-sb-linux-amd64")
	policy := releaseDownloadPolicy{attempts: 3}
	err := downloadReleaseAssetWithPolicy(context.Background(), server.Client(), server.URL, path, maxReleaseBinaryBytes, &expected, policy)
	if err == nil || !strings.Contains(err.Error(), "download oboard-sb-linux-amd64 failed after 3 attempts") || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("unexpected retry error: %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3", got)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial download remains at %s: %v", path, statErr)
	}
}

func TestManualReleaseDownloadStopsAfterOneRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "release-manifest.json")
	err := downloadReleaseAssetUsingPolicy(context.Background(), server.Client(), server.URL, path, maxReleaseManifestBytes, nil, releaseDownloadPolicy{attempts: 1})
	if err == nil || requests.Load() != 1 {
		t.Fatalf("manual download error = %v, requests = %d", err, requests.Load())
	}
}

func TestDownloadReleaseAssetLimitsChunkedResponseToSignedSize(t *testing.T) {
	expectedData := []byte("signed")
	expected := security.ReleaseManifestFile{SHA256: sha256Hex(expectedData), Size: int64(len(expectedData))}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("signed-with-untrusted-suffix"))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "oboard-agent-linux-amd64")
	policy := releaseDownloadPolicy{attempts: 2}
	err := downloadReleaseAssetWithPolicy(context.Background(), server.Client(), server.URL, path, maxReleaseBinaryBytes, &expected, policy)
	if err == nil || !strings.Contains(err.Error(), "failed after 2 attempts: response exceeds signed size") {
		t.Fatalf("unexpected signed size error: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("oversized partial download remains at %s: %v", path, statErr)
	}
}

func TestDownloadReleaseAssetDoesNotRetryPermanentStatus(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "release-manifest.json")
	policy := releaseDownloadPolicy{attempts: 3}
	err := downloadReleaseAssetWithPolicy(context.Background(), server.Client(), server.URL, path, maxReleaseManifestBytes, nil, policy)
	if err == nil || !strings.Contains(err.Error(), "download release-manifest.json: returned 404 Not Found") {
		t.Fatalf("unexpected permanent error: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestDownloadReleaseAssetStopsDuringBackoff(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	path := filepath.Join(t.TempDir(), "release-manifest.json")
	policy := releaseDownloadPolicy{attempts: 3, retryDelays: []time.Duration{time.Hour}}
	err := downloadReleaseAssetWithPolicy(ctx, server.Client(), server.URL, path, maxReleaseManifestBytes, nil, policy)
	if err == nil || !strings.Contains(err.Error(), "stopped after 1 attempts: context deadline exceeded") {
		t.Fatalf("unexpected cancellation error: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestReleaseUpdateTimeoutFitsControllerWindow(t *testing.T) {
	if releaseUpdateTimeout >= 5*time.Minute {
		t.Fatalf("release update timeout = %s, must remain below Controller task timeout", releaseUpdateTimeout)
	}
}

func TestSignedReleaseRejectsTamperedBinaryBeforeInstall(t *testing.T) {
	oldKey := version.ReleasePublicKey
	defer func() { version.ReleasePublicKey = oldKey }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	realmName := "oboard-realm-" + runtime.GOOS + "-" + runtime.GOARCH
	manifest := security.ReleaseManifest{Version: "1", Build: "2", Repo: "example/oboard-agent", Files: []security.ReleaseManifestFile{
		{Name: agentName, Component: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("good-agent")), Size: int64(len("good-agent"))},
		{Name: coreName, Component: "sb", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("good-core")), Size: int64(len("good-core"))},
		{Name: realmName, Component: "realm", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("good-realm")), Size: int64(len("good-realm"))},
	}}
	signature, err := security.SignReleaseManifest(manifest, base64.RawStdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, _ := security.CanonicalReleaseManifest(manifest)
	var agentRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release-manifest.json":
			_, _ = w.Write(manifestJSON)
		case "/release-manifest.json.sig":
			_, _ = w.Write([]byte(signature))
		case "/" + agentName:
			agentRequests.Add(1)
			_, _ = w.Write([]byte("tampered-agent"))
		case "/" + coreName:
			_, _ = w.Write([]byte("good-core"))
		case "/" + realmName:
			_, _ = w.Write([]byte("good-realm"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	targets := signedReleaseTargets{Agent: filepath.Join(dir, "oboard-agent"), Core: filepath.Join(dir, "oboard-sb"), Realm: filepath.Join(dir, "oboard-realm")}
	_ = os.WriteFile(targets.Agent, []byte("old-agent"), 0o755)
	_ = os.WriteFile(targets.Core, []byte("old-core"), 0o755)
	_ = os.WriteFile(targets.Realm, []byte("old-realm"), 0o755)
	_, err = New(Config{StateDir: dir, UpdateRepo: manifest.Repo}).downloadAndInstallSignedRelease(context.Background(), server.Client(), server.URL, manifest.Repo, manifest.Build, targets, ".oboard-update")
	if err == nil || !strings.Contains(err.Error(), "failed after 3 attempts") {
		t.Fatalf("unexpected tampered release error: %v", err)
	}
	if got := agentRequests.Load(); got != 3 {
		t.Fatalf("agent binary requests = %d, want 3", got)
	}
	assertFileContent(t, targets.Agent, []byte("old-agent"))
	assertFileContent(t, targets.Core, []byte("old-core"))
	assertFileContent(t, targets.Realm, []byte("old-realm"))
}

// A release whose realm asset is missing must leave every installed binary
// untouched: a half-updated node would run a new Agent that cannot forward.
func TestSignedReleaseRejectsMissingRealmAsset(t *testing.T) {
	oldKey := version.ReleasePublicKey
	defer func() { version.ReleasePublicKey = oldKey }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	manifest := security.ReleaseManifest{Version: "1", Build: "2", Repo: "example/oboard-agent", Files: []security.ReleaseManifestFile{
		{Name: agentName, Component: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("good-agent")), Size: int64(len("good-agent"))},
		{Name: coreName, Component: "sb", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("good-core")), Size: int64(len("good-core"))},
	}}
	signature, err := security.SignReleaseManifest(manifest, base64.RawStdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, _ := security.CanonicalReleaseManifest(manifest)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release-manifest.json":
			_, _ = w.Write(manifestJSON)
		case "/release-manifest.json.sig":
			_, _ = w.Write([]byte(signature))
		case "/" + agentName:
			_, _ = w.Write([]byte("good-agent"))
		case "/" + coreName:
			_, _ = w.Write([]byte("good-core"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	targets := signedReleaseTargets{Agent: filepath.Join(dir, "oboard-agent"), Core: filepath.Join(dir, "oboard-sb"), Realm: filepath.Join(dir, "oboard-realm")}
	_ = os.WriteFile(targets.Agent, []byte("old-agent"), 0o755)
	_ = os.WriteFile(targets.Core, []byte("old-core"), 0o755)
	_, err = New(Config{StateDir: dir, UpdateRepo: manifest.Repo}).downloadAndInstallSignedRelease(context.Background(), server.Client(), server.URL, manifest.Repo, manifest.Build, targets, ".oboard-update")
	if err == nil || !strings.Contains(err.Error(), "oboard-realm-") {
		t.Fatalf("unexpected missing realm error: %v", err)
	}
	assertFileContent(t, targets.Agent, []byte("old-agent"))
	assertFileContent(t, targets.Core, []byte("old-core"))
	if _, statErr := os.Stat(targets.Realm); !os.IsNotExist(statErr) {
		t.Fatalf("realm target should not exist after a rejected release: %v", statErr)
	}
}

func TestVerifyReleaseFilesRejectsTraversalName(t *testing.T) {
	oldKey := version.ReleasePublicKey
	defer func() { version.ReleasePublicKey = oldKey }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	manifest := security.ReleaseManifest{
		Version: "1", Build: "2", Repo: "example/oboard-agent",
		Files: []security.ReleaseManifestFile{{Name: "../escape", Component: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex([]byte("x")), Size: 1}},
	}
	signature, err := security.SignReleaseManifest(manifest, base64.RawStdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manifestJSON, err := security.CanonicalReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "release-manifest.json")
	signaturePath := filepath.Join(dir, "release-manifest.json.sig")
	if err := os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, []byte(signature), 0o600); err != nil {
		t.Fatal(err)
	}
	err = VerifyReleaseFiles(manifestPath, signaturePath, dir, runtime.GOOS, runtime.GOARCH, []string{"../escape"})
	if err == nil || !strings.Contains(err.Error(), "base name") {
		t.Fatalf("traversal release name was not rejected: %v", err)
	}
}

func TestPreserveExistingReleaseFileDoesNotClone(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "oboard-agent")
	data := []byte("old-agent")
	if err := os.WriteFile(target, data, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	item := stagedReleaseFile{target: target}
	if err := preserveExistingReleaseFile(&item, ".oboard-update"); err != nil {
		t.Fatal(err)
	}
	if !item.hadOld || item.backup == "" {
		t.Fatalf("backup was not reserved: %+v", item)
	}
	backup, err := os.Stat(item.backup)
	if item.linked {
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, backup) {
			t.Fatal("backup cloned the live binary instead of linking it")
		}
		assertFileContent(t, target, data)
		return
	}
	if err == nil {
		t.Fatal("rename-style backup should not create a second copy before commit")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	assertFileContent(t, target, data)
}

func TestInstallVerifiedReleaseFilesRemovesStaleSidecars(t *testing.T) {
	dir := t.TempDir()
	agent := filepath.Join(dir, "oboard-agent")
	core := filepath.Join(dir, "oboard-sb")
	if err := os.WriteFile(agent, []byte("old-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(core, []byte("old-core"), 0o755); err != nil {
		t.Fatal(err)
	}
	staleNew := filepath.Join(dir, ".oboard-update-new.stale")
	staleBackup := filepath.Join(dir, ".oboard-update-backup.stale")
	if err := os.WriteFile(staleNew, []byte("stale-new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staleBackup, []byte("stale-backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	realm := filepath.Join(dir, "oboard-realm")
	if err := os.WriteFile(realm, []byte("old-realm"), 0o755); err != nil {
		t.Fatal(err)
	}
	srcDir := t.TempDir()
	agentSrc := filepath.Join(srcDir, "agent")
	coreSrc := filepath.Join(srcDir, "core")
	realmSrc := filepath.Join(srcDir, "realm")
	if err := os.WriteFile(agentSrc, []byte("new-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coreSrc, []byte("new-core"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realmSrc, []byte("new-realm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (&Runner{}).installVerifiedReleaseFiles(".oboard-update", []stagedReleaseFile{
		{source: agentSrc, target: agent},
		{source: coreSrc, target: core},
		{source: realmSrc, target: realm},
	}); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, agent, []byte("new-agent"))
	assertFileContent(t, core, []byte("new-core"))
	assertFileContent(t, realm, []byte("new-realm"))
	matches, err := filepath.Glob(filepath.Join(dir, ".oboard-update-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("leftover update files: %v", matches)
	}
}

func TestCommitStagedReleaseFilesRestoresFirstBinaryIfSecondFails(t *testing.T) {
	dir := t.TempDir()
	agent := filepath.Join(dir, "oboard-agent")
	core := filepath.Join(dir, "oboard-sb")
	if err := os.WriteFile(agent, []byte("old-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(core, []byte("old-core"), 0o755); err != nil {
		t.Fatal(err)
	}
	agentItem := stagedReleaseFile{target: agent}
	coreItem := stagedReleaseFile{target: core}
	if err := preserveExistingReleaseFile(&agentItem, ".oboard-update"); err != nil {
		t.Fatal(err)
	}
	if err := preserveExistingReleaseFile(&coreItem, ".oboard-update"); err != nil {
		t.Fatal(err)
	}
	agentStage := filepath.Join(dir, ".oboard-update-new.agent")
	if err := os.WriteFile(agentStage, []byte("new-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	agentItem.stage = agentStage
	coreItem.stage = filepath.Join(dir, "missing-stage")
	err := commitStagedReleaseFiles([]stagedReleaseFile{agentItem, coreItem})
	if err == nil {
		t.Fatal("expected second commit to fail")
	}
	assertFileContent(t, agent, []byte("old-agent"))
	assertFileContent(t, core, []byte("old-core"))
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func assertFileContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func writeStagedCoreStub(t *testing.T, dir, name string, exitCode int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// A downloaded kernel that rejects the live configuration must abort the update
// while every file on disk is still the working one. Installing first leaves a
// node whose running process is the old kernel and whose executable is a build
// that fails at the next restart.
func TestPreflightStagedCoreRejectsIncompatibleKernel(t *testing.T) {
	dir := t.TempDir()
	staged := writeStagedCoreStub(t, dir, "oboard-sb-staged", 1)
	config := filepath.Join(dir, "sing-box.json")
	if err := os.WriteFile(config, []byte(`{"log":{"level":"warn"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state, _, err := (&Runner{}).preflightStagedCore(staged, config, 10*time.Second)
	if err == nil {
		t.Fatal("an incompatible kernel must abort the update")
	}
	if !strings.Contains(err.Error(), "rejected the active configuration") {
		t.Fatalf("unexpected preflight error: %v", err)
	}
	if state != corePreflightSkipped {
		t.Fatalf("preflight state = %q", state)
	}
}

func TestPreflightStagedCoreAcceptsCompatibleKernel(t *testing.T) {
	dir := t.TempDir()
	staged := writeStagedCoreStub(t, dir, "oboard-sb-staged", 0)
	config := filepath.Join(dir, "sing-box.json")
	if err := os.WriteFile(config, []byte(`{"log":{"level":"warn"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state, _, err := (&Runner{}).preflightStagedCore(staged, config, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if state != corePreflightValidated {
		t.Fatalf("preflight state = %q, want validated", state)
	}
}

// Nothing is deployed yet on a fresh node, so there is no configuration to
// validate against and the update proceeds.
func TestPreflightStagedCoreSkipsWithoutDeployedConfig(t *testing.T) {
	dir := t.TempDir()
	staged := writeStagedCoreStub(t, dir, "oboard-sb-staged", 1)
	state, _, err := (&Runner{}).preflightStagedCore(staged, filepath.Join(dir, "sing-box.json"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if state != corePreflightNotDeployed {
		t.Fatalf("preflight state = %q, want not_deployed", state)
	}
	state, _, err = (&Runner{}).preflightStagedCore(staged, "", 10*time.Second)
	if err != nil || state != corePreflightNotDeployed {
		t.Fatalf("empty config path: state=%q err=%v", state, err)
	}
}

// A staged binary that cannot be executed at all yields no verdict. Blocking
// every update on that would be worse than proceeding, so it is recorded as
// skipped instead of failing the task.
func TestPreflightStagedCoreSkipsWhenBinaryCannotRun(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sing-box.json")
	if err := os.WriteFile(config, []byte(`{"log":{"level":"warn"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state, note, err := (&Runner{}).preflightStagedCore(filepath.Join(dir, "does-not-exist"), config, 10*time.Second)
	if err != nil {
		t.Fatalf("a missing staged binary must not fail the update: %v", err)
	}
	if state != corePreflightSkipped || note == "" {
		t.Fatalf("preflight state = %q note = %q", state, note)
	}
}

func TestDownloadReleaseAssetFallsBackToControllerWithSignedChecksum(t *testing.T) {
	data := []byte("pinned-controller-binary")
	expected := security.ReleaseManifestFile{SHA256: sha256Hex(data), Size: int64(len(data))}
	for _, validFallback := range []bool{true, false} {
		t.Run(fmt.Sprint(validFallback), func(t *testing.T) {
			var fallbackRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/hidden/downloads/github/oboard-agent-linux-amd64" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				if r.URL.Query().Get("source") != "controller" {
					http.Error(w, "GitHub resource unavailable", http.StatusNotFound)
					return
				}
				fallbackRequests.Add(1)
				if validFallback {
					_, _ = w.Write(data)
				} else {
					_, _ = w.Write([]byte("wrong-version"))
				}
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "agent")
			err := downloadReleaseAsset(context.Background(), server.Client(), server.URL+"/hidden/downloads/github/oboard-agent-linux-amd64", path, 1024, &expected)
			if (err == nil) != validFallback {
				t.Fatalf("fallback error = %v", err)
			}
			if fallbackRequests.Load() == 0 {
				t.Fatal("did not retry Controller directly")
			}
			if validFallback {
				assertFileContent(t, path, data)
			}
		})
	}
}

func TestGitHubUpdateUsesControllerPinnedManifest(t *testing.T) {
	oldExecutable, oldKey := osExecutable, version.ReleasePublicKey
	t.Cleanup(func() { osExecutable, version.ReleasePublicKey = oldExecutable, oldKey })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)
	manifest := security.ReleaseManifest{Version: "dev-012345abcdef", Build: "20260909010101", Repo: defaultUpdateRepo}
	signature, err := security.SignReleaseManifest(manifest, base64.RawStdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	body, err := security.CanonicalReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var paths atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		paths.Add(1)
		switch req.URL.Path {
		case "/hidden/downloads/github/release-manifest.json":
			_, _ = w.Write(body)
		case "/hidden/downloads/github/release-manifest.json.sig":
			_, _ = w.Write([]byte(signature))
		default:
			t.Errorf("unexpected release request: %s", req.URL)
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	agentPath, corePath := filepath.Join(dir, "oboard-agent"), filepath.Join(dir, "oboard-sb")
	if err := os.WriteFile(agentPath, []byte("old-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corePath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	osExecutable = func() (string, error) { return agentPath, nil }
	r := newTestRunner(t, Config{ControllerURL: server.URL + "/hidden", StateDir: filepath.Join(dir, "state"), CoreBinary: corePath, UpdateSource: "github"})
	r.client = server.Client()
	result, err := r.updateAgentBinary(`{"source":"github","expected_build":"20260909020202"}`)
	if err == nil || !strings.Contains(err.Error(), "does not match expected build") || result["installed"] == true {
		t.Fatalf("accepted mismatched Controller build: %#v, %v", result, err)
	}
	if paths.Load() != 4 {
		t.Fatalf("manifest chunk/EOF requests = %v", paths.Load())
	}
	assertFileContent(t, agentPath, []byte("old-agent"))
}

// The staged-kernel preflight starts a second kernel beside the live one. On a
// memory-capped node that pair can cross the cgroup limit, and the OOM killer
// then picks a victim by RSS - routinely the Agent, which dies silently and,
// under a service manager with no supervisor, never returns. The preflight is
// one verdict; the Agent is the whole node, so a node without headroom skips
// the check instead of risking itself.
func TestCorePreflightMemoryVerdict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int64
		usage uint64
		want  bool
	}{
		{"no cgroup limit runs the preflight", 0, 0, true},
		{"unlimited cgroup runs the preflight", 0, 64 << 20, true},
		{"ample headroom runs the preflight", 2 << 30, 512 << 20, true},
		{"headroom exactly at the floor runs the preflight", 256 << 20, 160 << 20, true},
		// The node this guard exists for: a 128 MiB container already holding a
		// live kernel at 78 MiB, which is where the Agent was OOM-killed.
		{"starved container skips the preflight", 128 << 20, 78 << 20, false},
		{"headroom just under the floor skips the preflight", 256 << 20, (160 << 20) + 1, false},
		{"usage above the limit skips the preflight", 128 << 20, 256 << 20, false},
		{"unreadable usage skips the preflight", 128 << 20, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			note, ok := corePreflightMemoryVerdict(tc.limit, tc.usage)
			if ok != tc.want {
				t.Fatalf("verdict = %v, want %v (limit=%d usage=%d)", ok, tc.want, tc.limit, tc.usage)
			}
			if ok && note != "" {
				t.Fatalf("a preflight that runs must not carry a skip note: %q", note)
			}
			if !ok && note == "" {
				t.Fatal("a skipped preflight must explain itself in the task result")
			}
		})
	}
}
