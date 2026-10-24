package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
)

func TestSelfExecutablePathResolvesReplacedBinary(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "oboard-agent")
	if err := os.WriteFile(installed, []byte("new-agent"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Linux reports the path of an unlinked executable with this suffix. An
	// Agent that installed an update but has not restarted yet sees itself this
	// way, and it still has to resolve the installed file.
	original := osExecutable
	defer func() { osExecutable = original }()
	osExecutable = func() (string, error) { return installed + deletedExecutableSuffix, nil }
	got, err := selfExecutablePath()
	if err != nil {
		t.Fatal(err)
	}
	wantInstalled, err := canonicalFilePath(installed)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantInstalled {
		t.Fatalf("resolved path = %q, want %q", got, wantInstalled)
	}

	// A file that really is named this way must not be rewritten.
	literal := filepath.Join(dir, "oboard-agent"+deletedExecutableSuffix)
	if err := os.WriteFile(literal, []byte("literal"), 0o755); err != nil {
		t.Fatal(err)
	}
	osExecutable = func() (string, error) { return literal, nil }
	got, err = selfExecutablePath()
	if err != nil {
		t.Fatal(err)
	}
	wantLiteral, err := canonicalFilePath(literal)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantLiteral {
		t.Fatalf("resolved path = %q, want %q", got, wantLiteral)
	}
}

func TestSignedReleaseTargetsAcceptsReplacedAgentBinary(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "oboard-agent")
	if err := os.WriteFile(installed, []byte("new-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := osExecutable
	defer func() { osExecutable = original }()
	osExecutable = func() (string, error) { return installed + deletedExecutableSuffix, nil }

	r := New(Config{StateDir: t.TempDir()})
	targets, err := r.signedReleaseTargets()
	if err != nil {
		t.Fatalf("a stale Agent must still resolve its own update targets: %v", err)
	}
	wantAgent, err := canonicalFilePath(installed)
	if err != nil {
		t.Fatal(err)
	}
	if targets.Agent != wantAgent {
		t.Fatalf("agent target = %q, want %q", targets.Agent, wantAgent)
	}
	if wantCore := filepath.Join(filepath.Dir(wantAgent), "oboard-sb"); targets.Core != wantCore {
		t.Fatalf("core target = %q, want %q", targets.Core, wantCore)
	}
}

func TestParseAgentBuildIdentity(t *testing.T) {
	build, commit, err := parseAgentBuildIdentity("OBoard Agent 0.0.1 (build 20260829170815, commit 95f4facbd6fd, built 2026-08-29T17:08:15Z)")
	if err != nil {
		t.Fatal(err)
	}
	if build != "20260829170815" || commit != "95f4facbd6fd" {
		t.Fatalf("build = %q commit = %q", build, commit)
	}
	if _, _, err := parseAgentBuildIdentity("OBoard Agent"); err == nil {
		t.Fatal("output without a build identity must be an error")
	}
}

func TestSameAgentBuild(t *testing.T) {
	if !sameAgentBuild("dev", "abc", "dev", "abc") {
		t.Fatal("identical identities must match")
	}
	if sameAgentBuild("dev", "abc", "dev", "def") {
		t.Fatal("development builds share a build tag and must be separated by commit")
	}
	if sameAgentBuild("2026", "", "2027", "") {
		t.Fatal("different builds must not match")
	}
	if !sameAgentBuild("", "", "2027", "abc") {
		t.Fatal("a missing identity is not evidence of drift")
	}
}

// writeFakeAgentBinary installs an executable that answers -version the way the
// real Agent does.
func writeFakeAgentBinary(t *testing.T, path, build, commit string) {
	t.Helper()
	script := "#!/bin/sh\necho \"OBoard Agent 0.0.1 (build " + build + ", commit " + commit + ", built 2026-09-04T00:00:00Z)\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileInstalledAgentBuildRestartsStaleProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Agent runs on Linux hosts")
	}
	dir := t.TempDir()
	installed := filepath.Join(dir, "oboard-agent")
	original := osExecutable
	defer func() { osExecutable = original }()
	osExecutable = func() (string, error) { return installed + deletedExecutableSuffix, nil }

	oldBuild, oldCommit := version.Build, version.Commit
	defer func() { version.Build, version.Commit = oldBuild, oldCommit }()
	version.Build, version.Commit = "20260829170815", "95f4facbd6fd"

	var scheduled atomic.Int32
	newRunner := func() *Runner {
		r := New(Config{StateDir: t.TempDir()})
		r.agentRestartCommand = func() error { scheduled.Add(1); return nil }
		return r
	}

	// The process is running a build the installed executable no longer carries,
	// which is exactly the state an interrupted update leaves behind.
	writeFakeAgentBinary(t, installed, "20260903120000", "c22fd5f00000")
	newRunner().reconcileInstalledAgentBuild()
	if scheduled.Load() != 1 {
		t.Fatalf("stale agent scheduled %d restarts, want 1", scheduled.Load())
	}

	// Once restarted onto the installed build there is nothing left to do, so a
	// restart loop is impossible.
	scheduled.Store(0)
	writeFakeAgentBinary(t, installed, version.Build, version.Commit)
	newRunner().reconcileInstalledAgentBuild()
	if scheduled.Load() != 0 {
		t.Fatalf("current agent scheduled %d restarts, want 0", scheduled.Load())
	}

	// An executable that cannot report itself is not evidence of drift.
	scheduled.Store(0)
	if err := os.WriteFile(installed, []byte("not an executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	newRunner().reconcileInstalledAgentBuild()
	if scheduled.Load() != 0 {
		t.Fatalf("unreadable agent scheduled %d restarts, want 0", scheduled.Load())
	}
}

// TestUpdateArmsRestartWhenResultReportFails starts from the state that stranded
// the fleet: the update replaced the executable, and the control link failed
// before the Controller could acknowledge the result. The restart has to be
// armed anyway, or the process keeps serving from the unlinked inode forever.
func TestUpdateArmsRestartWhenResultReportFails(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	oldKey := version.ReleasePublicKey
	defer func() { version.ReleasePublicKey = oldKey }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version.ReleasePublicKey = base64.RawStdEncoding.EncodeToString(pub)

	dir := t.TempDir()
	installedAgent := filepath.Join(dir, "oboard-agent")
	installedCore := filepath.Join(dir, "oboard-sb")
	if err := os.WriteFile(installedAgent, []byte("old-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installedCore, []byte("old-core"), 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	writeCoreConfig(t, stateDir, coreConfigA)
	original := osExecutable
	defer func() { osExecutable = original }()
	osExecutable = func() (string, error) { return installedAgent, nil }

	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	realmName := "oboard-realm-" + runtime.GOOS + "-" + runtime.GOARCH
	agentData := []byte("signed-agent-binary")
	coreData := []byte("signed-core-binary")
	realmData := []byte("signed-realm-binary")
	manifest := security.ReleaseManifest{
		Version: "1.2.3", Build: "build-123", Commit: "abc123", Date: "2026-09-04T00:00:00Z", Repo: "obrdx/oboard-agent",
		Files: []security.ReleaseManifestFile{
			{Name: agentName, Component: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex(agentData), Size: int64(len(agentData))},
			{Name: coreName, Component: "sb", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex(coreData), Size: int64(len(coreData))},
			{Name: realmName, Component: "realm", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: sha256Hex(realmData), Size: int64(len(realmData))},
		},
	}
	signature, err := security.SignReleaseManifest(manifest, base64.RawStdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := security.CanonicalReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string][]byte{
		"/downloads/release-manifest.json":     manifestJSON,
		"/downloads/release-manifest.json.sig": []byte(signature),
		"/downloads/" + agentName:              agentData,
		"/downloads/" + coreName:               coreData,
		"/downloads/" + realmName:              realmData,
	}

	token := "agent-token"
	payload := `{"source":"panel","expected_build":"` + manifest.Build + `","github_repo":"` + manifest.Repo + `"}`
	task := model.AgentTask{ID: 77, ServerID: 1, Type: "update_agent", PayloadJSON: payload, ConfigVersion: 1, Nonce: "task-nonce"}
	taskSignature := security.SignTaskEnvelope(security.HashSecret(token), security.TaskEnvelope{ID: task.ID, ServerID: task.ServerID, Type: task.Type, ConfigVersion: task.ConfigVersion, Nonce: task.Nonce, PayloadJSON: task.PayloadJSON})

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if body, ok := assets[req.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		switch req.URL.Path {
		case "/api/v1/agent/connect":
			conn, err := upgrader.Upgrade(w, req, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			var initial map[string]any
			if conn.ReadJSON(&initial) != nil {
				return
			}
			if conn.WriteJSON(map[string]any{"type": "hello", "server_id": task.ServerID}) != nil {
				return
			}
			if conn.WriteJSON(map[string]any{"type": "task_request", "task": task, "signature_version": 2, "signature": taskSignature}) != nil {
				return
			}
			// Nothing else arrives: the Agent gives up once the result report
			// fails. Close the socket so connect() returns.
			var next map[string]any
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_ = conn.ReadJSON(&next)
		case "/api/v1/agent/task-results":
			// The link the Agent needs to confirm the update is exactly what an
			// update tends to break.
			http.Error(w, "temporary failure", http.StatusInternalServerError)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	var scheduled atomic.Int32
	r := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: token, StateDir: stateDir, CoreBinary: installedCore, AllowPanelUpdate: true, AllowInsecureController: true})
	r.agentRestartCommand = func() error { scheduled.Add(1); return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.connectTestControl(ctx); err == nil {
		t.Fatal("expected the task result report to fail")
	}

	assertFileContent(t, installedAgent, agentData)
	deadline := time.Now().Add(5 * time.Second)
	for scheduled.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if scheduled.Load() != 1 {
		t.Fatalf("restart scheduled %d times after a successful install with a failed report, want 1", scheduled.Load())
	}
}
