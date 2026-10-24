//go:build !windows

package agent

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/terminal"
)

func TestStartInteractivePTYDoesNotSetPgid(t *testing.T) {
	session, spec, err := startInteractivePTY(80, 24, terminal.ModeMinimal)
	if err != nil {
		t.Fatalf("start interactive pty: %v", err)
	}
	defer session.Close()
	ptmx := session.(interface{ File() *os.File }).File()
	cmd := session.(interface{ Command() *exec.Cmd }).Command()
	if spec.Mode != terminal.ModeMinimal {
		t.Fatalf("mode = %q", spec.Mode)
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid {
		t.Fatal("Setpgid must stay false; pty.StartWithSize already sets Setsid and Setctty")
	}
	if cmd.Process == nil || cmd.Process.Pid <= 0 {
		t.Fatal("pty process was not started")
	}
	if _, err := ptmx.Write([]byte("printf ready\\n\n")); err != nil {
		t.Fatalf("write pty: %v", err)
	}
	_ = ptmx.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := ptmx.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read pty: %v", err)
	}
}

func TestStartInteractivePTYConflictsWithSetpgidOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Setpgid combined with pty session setup is a Linux agent hazard")
	}
	cmd := exec.Command("/bin/sh")
	cmd.Dir = "/"
	cmd.Env = append(remoteExecEnv(), "TERM=xterm-256color")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 80, Rows: 24})
	if ptmx != nil {
		_ = ptmx.Close()
		killProcessGroup(cmd)
	}
	if err == nil {
		// Go applies setsid before setpgid(0,0). That is a no-op on a session
		// leader, so this combination can succeed on current kernels. Production
		// still omits Setpgid; TestStartInteractivePTYDoesNotSetPgid holds that.
		return
	}
	if !errors.Is(err, syscall.EPERM) && !os.IsPermission(err) {
		t.Fatalf("conflict error = %v, want EPERM or success", err)
	}
}

func TestInteractivePrepareReportsControlFailure(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8, AgentToken: "agent-token"})
	var mu sync.Mutex
	var messages []map[string]any
	runner.setControlSend(func(payload any, _ bool) error {
		mu.Lock()
		defer mu.Unlock()
		messages = append(messages, payload.(map[string]any))
		return nil
	})
	err := runner.handleInteractivePrepare(model.InteractivePrepareEnvelope{
		Type: "interactive_prepare", SignatureVersion: 1, SessionID: "sess-denied", Kind: "terminal",
	})
	if err == nil {
		t.Fatal("expected prepare rejection")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(messages) != 1 {
		t.Fatalf("control messages = %#v", messages)
	}
	if messages[0]["type"] != "interactive_failed" || messages[0]["session_id"] != "sess-denied" || messages[0]["reason"] != interactiveReasonPrepareInvalid {
		t.Fatalf("failed payload = %#v", messages[0])
	}
}

func TestInteractivePrepareUsesFreshControllerTime(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{
		StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off",
		LogMaxMB: 8, CoreLogMaxMB: 8, AgentToken: "agent-token", ControllerURL: "not-a-controller",
	})
	controllerNow := time.Now().UTC().Add(2 * time.Minute)
	runner.setControllerReference(controllerNow)
	got := make(chan map[string]any, 1)
	runner.setControlSend(func(payload any, _ bool) error {
		select {
		case got <- payload.(map[string]any):
		default:
		}
		return nil
	})
	env := model.InteractivePrepareEnvelope{
		Type: "interactive_prepare", SignatureVersion: security.InteractiveSignatureV1,
		SessionID: "sess-controller-time", Nonce: "nonce-controller-time",
		IssuedAt:  controllerNow.Format(time.RFC3339Nano),
		ExpiresAt: controllerNow.Add(security.InteractivePrepareTTL).Format(time.RFC3339Nano),
		Kind:      "terminal", Cols: 80, Rows: 24,
	}
	env.Signature = security.SignInteractiveEnvelope(security.HashSecret("agent-token"), security.InteractiveEnvelope{
		Type: env.Type, ServerID: env.ServerID, SessionID: env.SessionID, Nonce: env.Nonce,
		IssuedAt: env.IssuedAt, ExpiresAt: env.ExpiresAt, Kind: env.Kind, Cols: env.Cols, Rows: env.Rows,
	})
	if err := runner.handleInteractivePrepare(env); err != nil {
		t.Fatalf("prepare aligned with Controller time was rejected: %v", err)
	}
	select {
	case payload := <-got:
		if payload["reason"] != interactiveReasonAgentLinkConfigInvalid {
			t.Fatalf("prepare did not pass validation: %#v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the post-validation URL failure")
	}
}

func TestValidateInteractiveTimesPreservesReplayWindow(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name    string
		issued  time.Time
		expires time.Time
		wantErr string
	}{
		{name: "valid", issued: now, expires: now.Add(security.InteractivePrepareTTL)},
		{name: "expired", issued: now.Add(-2 * time.Minute), expires: now.Add(-time.Minute), wantErr: "expired"},
		{name: "future", issued: now.Add(security.MaxClockSkew + time.Second), expires: now.Add(security.MaxClockSkew + time.Second + security.InteractivePrepareTTL), wantErr: "future"},
		{name: "reversed", issued: now, expires: now, wantErr: "timestamp window"},
		{name: "oversized ttl", issued: now, expires: now.Add(security.InteractivePrepareTTL + time.Nanosecond), wantErr: "timestamp window"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateInteractiveTimes(test.issued, test.expires, now)
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestInteractiveValidationNowFallsBackToLogicalClock(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "small"})
	logicalNow := time.Now().UTC().Add(90 * time.Second)
	if err := runner.clock.Apply(true, logicalNow, "test", logicalNow); err != nil {
		t.Fatal(err)
	}
	if delta := runner.interactiveValidationNow().Sub(logicalNow); delta < -time.Second || delta > time.Second {
		t.Fatalf("interactive validation time did not use logical clock: delta=%s", delta)
	}
}

func TestInteractiveNonceReplayIgnoresCorrectedClockJumps(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "small"})
	runner.setControllerReference(time.Now().UTC())
	if !runner.rememberInteractiveNonce("nonce-replay") {
		t.Fatal("first nonce use was rejected")
	}
	// A corrected security clock may move forward and back as Controller/NTP
	// references change. Nonce retention uses process-monotonic time so that a
	// forward correction cannot evict a nonce that is still replayable.
	runner.setControllerReference(time.Now().UTC().Add(10 * time.Minute))
	if runner.rememberInteractiveNonce("nonce-replay") {
		t.Fatal("clock correction allowed an in-process nonce replay")
	}
}

func TestInteractiveSessionReportsAgentLinkConfigFailure(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{
		StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off",
		LogMaxMB: 8, CoreLogMaxMB: 8, AgentToken: "agent-token", ControllerURL: "not-a-controller",
	})
	var mu sync.Mutex
	got := make(chan map[string]any, 1)
	runner.setControlSend(func(payload any, _ bool) error {
		mu.Lock()
		defer mu.Unlock()
		select {
		case got <- payload.(map[string]any):
		default:
		}
		return nil
	})
	now := time.Now().UTC()
	env := model.InteractivePrepareEnvelope{
		Type: "interactive_prepare", SignatureVersion: 1, ServerID: 0, SessionID: "sess-url",
		Nonce: "nonce-url", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Kind: "terminal", Cols: 80, Rows: 24,
	}
	env.Signature = security.SignInteractiveEnvelope(security.HashSecret("agent-token"), security.InteractiveEnvelope{
		Type: env.Type, ServerID: env.ServerID, SessionID: env.SessionID, Nonce: env.Nonce,
		IssuedAt: env.IssuedAt, ExpiresAt: env.ExpiresAt, Kind: env.Kind, Cols: env.Cols, Rows: env.Rows,
	})
	if err := runner.handleInteractivePrepare(env); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-got:
		if payload["type"] != "interactive_failed" || payload["reason"] != interactiveReasonAgentLinkConfigInvalid {
			t.Fatalf("url failure payload = %#v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for interactive_failed")
	}
}

func TestInteractiveSessionLimitReportsFailure(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8})
	runner.terminalSessions = map[string]*terminalSession{
		"one": {id: "one"},
		"two": {id: "two"},
	}
	got := make(chan map[string]any, 1)
	runner.setControlSend(func(payload any, _ bool) error {
		select {
		case got <- payload.(map[string]any):
		default:
		}
		return nil
	})
	now := time.Now().UTC()
	runner.runTerminalSession(model.InteractivePrepareEnvelope{
		SessionID: "sess-limit", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}, 80, 24, terminal.ModeLogin, "secret")
	select {
	case payload := <-got:
		if payload["type"] != "interactive_failed" || payload["reason"] != interactiveReasonSessionLimit {
			t.Fatalf("limit payload = %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for session_limit failure")
	}
}
