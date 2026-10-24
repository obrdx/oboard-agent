package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A deleted or re-enrolled node keeps its old token and its own report timers.
// Without a shared backoff the HTTP callbacks kept posting on those timers
// forever, so the Controller spent a credential lookup per attempt on an
// identity that no longer exists.
func TestControllerRejectionPausesAuthenticatedCallbacks(t *testing.T) {
	for name, status := range map[string]int{
		"unauthorized":        http.StatusUnauthorized,
		"forbidden":           http.StatusForbidden,
		"too many requests":   http.StatusTooManyRequests,
		"service unavailable": http.StatusServiceUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests.Add(1)
				http.Error(w, "rejected", status)
			}))
			defer server.Close()
			runner := newTestRunner(t, Config{ConfigPath: filepath.Join(t.TempDir(), "agent.json"), ControllerURL: server.URL, AgentID: "agent-1", AgentToken: "stale", StateDir: t.TempDir()})
			ctx := context.Background()
			if err := runner.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{}, nil, true); err == nil {
				t.Fatal("a rejected identity must surface as an error")
			}
			for i := 0; i < 5; i++ {
				if err := runner.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{}, nil, true); err == nil {
					t.Fatal("callbacks resumed while the identity is still rejected")
				}
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("controller received %d requests, want only the one that established the rejection", got)
			}
		})
	}
}

// Unauthenticated calls (enrollment) are never gated, and a successful
// authenticated call releases the pause.
func TestControllerAuthBackoffScopeAndRelease(t *testing.T) {
	var requests atomic.Int64
	reject := atomic.Bool{}
	reject.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if reject.Load() && req.Header.Get("X-Agent-ID") != "" {
			http.Error(w, "rejected", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"server_id":7,"agent_id":"new-agent","agent_token":"new-token"}`))
	}))
	defer server.Close()
	runner := newTestRunner(t, Config{ConfigPath: filepath.Join(t.TempDir(), "agent.json"), ControllerURL: server.URL, AgentID: "agent-1", AgentToken: "stale", StateDir: t.TempDir()})
	ctx := context.Background()
	_ = runner.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{}, nil, true)
	before := requests.Load()
	if err := runner.Enroll(ctx, "fresh-enrollment"); err != nil {
		t.Fatalf("enrollment must not be gated by an agent-identity rejection: %v", err)
	}
	if requests.Load() != before+1 {
		t.Fatal("the unauthenticated call did not reach the controller")
	}
	// Re-enrollment restores the identity; the realtime loop clears the pause
	// once a session lives, and a successful callback clears it too.
	runner.controllerAuth.clear()
	reject.Store(false)
	if err := runner.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", map[string]any{}, nil, true); err != nil {
		t.Fatal(err)
	}
	if wait := runner.controllerAuth.remaining(time.Now()); wait != 0 {
		t.Fatalf("a successful callback left the pause armed for %s", wait)
	}
}

func TestControllerThrottleHonorsRetryAfter(t *testing.T) {
	var backoff controllerAuthBackoff
	header := make(http.Header)
	header.Set("Retry-After", "12")
	now := time.Now()
	backoff.armWithResponse(now, http.StatusTooManyRequests, header)
	wait := backoff.remaining(now)
	if wait < 12*time.Second || wait > 12*time.Second+controllerThrottleJitterMax+time.Second {
		t.Fatalf("throttle wait = %s, want about 12s plus jitter", wait)
	}
	if backoff.class != "throttle" {
		t.Fatalf("class = %q, want throttle", backoff.class)
	}
}

func TestControllerAuthBackoffGrowsExponentially(t *testing.T) {
	var backoff controllerAuthBackoff
	now := time.Now()
	backoff.armWithResponse(now, http.StatusUnauthorized, nil)
	first := backoff.remaining(now)
	// Re-arm without clearing so authStep advances inside one pause window.
	backoff.armWithResponse(now.Add(time.Millisecond), http.StatusUnauthorized, nil)
	second := backoff.remaining(now)
	if first < 20*time.Second {
		t.Fatalf("first auth backoff = %s", first)
	}
	if second <= first {
		t.Fatalf("auth backoff did not grow: first=%s second=%s", first, second)
	}
}

func TestUpdateAgentConfigClearsControllerBackoff(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	runner := newTestRunner(t, Config{ControllerURL: "http://127.0.0.1:9", AgentID: "agent-1", AgentToken: "tok", StateDir: dir, ConfigPath: cfgPath})
	if err := SaveConfig(cfgPath, runner.Config()); err != nil {
		t.Fatal(err)
	}
	runner.controllerAuth.armWithResponse(time.Now(), http.StatusUnauthorized, nil)
	if runner.controllerAuth.remaining(time.Now()) == 0 {
		t.Fatal("expected auth pause")
	}
	fields := map[string]json.RawMessage{"controller_url": json.RawMessage(`"http://127.0.0.1:9"`)}
	if _, err := runner.updateAgentConfig(runner.Config(), fields); err != nil {
		t.Fatal(err)
	}
	if wait := runner.controllerAuth.remaining(time.Now()); wait != 0 {
		t.Fatalf("config update left auth pause armed for %s", wait)
	}
}
