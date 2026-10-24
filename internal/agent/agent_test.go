package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
)

func TestNormalizeConfigResourceDefaults(t *testing.T) {
	cfg := normalizeConfig(Config{})
	if cfg.StateDir == "" {
		t.Fatal("expected default state dir")
	}
	if cfg.ResourceProfile != "auto" {
		t.Fatalf("resource profile = %q, want auto", cfg.ResourceProfile)
	}
	if cfg.CommandTimeoutSeconds != 20 {
		t.Fatalf("command timeout = %d, want 20", cfg.CommandTimeoutSeconds)
	}
	if cfg.RestartCommand != "auto" {
		t.Fatalf("restart command = %q, want auto", cfg.RestartCommand)
	}
	if cfg.ReloadCommand != "auto" {
		t.Fatalf("reload command = %q, want auto", cfg.ReloadCommand)
	}
	if cfg.TimeSyncCommand != "auto" || cfg.TimeCorrectionMode != model.TimeCorrectionOff {
		t.Fatalf("time correction defaults = %q/%q, want auto/off", cfg.TimeSyncCommand, cfg.TimeCorrectionMode)
	}
}

func TestImplicitCoreIdentityUsesOBoardNames(t *testing.T) {
	runner := New(Config{})
	if got := runner.coreBinary(); got != "oboard-sb" {
		t.Fatalf("implicit core binary = %q, want oboard-sb", got)
	}
	if got := runner.coreService(); got != "oboard-sb" {
		t.Fatalf("implicit core service = %q, want oboard-sb", got)
	}
	if got := detectCoreBinary(); got != "oboard-sb" {
		t.Fatalf("detected core binary = %q, want oboard-sb", got)
	}
}

func TestEnrollTimeoutPreservesBootstrapCoreConfig(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"server_id":7,"agent_id":"agent-7","agent_token":"token-7"}`))
	}))
	defer server.Close()

	configPath := filepath.Join(t.TempDir(), "agent.json")
	runner := newTestRunner(t, Config{
		ConfigPath:              configPath,
		ControllerURL:           server.URL,
		StateDir:                "/var/lib/oboard-agent",
		CoreBinary:              "/opt/oboard/oboard-sb",
		CoreService:             "oboard-sb",
		AllowInsecureController: true,
	})
	runner.client.Timeout = 25 * time.Millisecond
	if err := runner.Enroll(context.Background(), "enrollment-token"); err == nil {
		t.Fatal("expected enrollment timeout")
	}
	stored, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CoreBinary != "/opt/oboard/oboard-sb" || stored.CoreService != "oboard-sb" {
		t.Fatalf("bootstrap core config was lost after timeout: %#v", stored)
	}
	if stored.AgentID != "" || stored.AgentToken != "" {
		t.Fatalf("unconfirmed enrollment credentials were persisted: %#v", stored)
	}
}

func TestEnrollSuccessPersistsCredentialsAndCoreConfig(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"server_id":7,"agent_id":"agent-7","agent_token":"token-7","connection_audit_enabled":true}`))
	}))
	defer server.Close()

	configPath := filepath.Join(t.TempDir(), "agent.json")
	runner := newTestRunner(t, Config{
		ConfigPath:              configPath,
		ControllerURL:           server.URL,
		StateDir:                "/var/lib/oboard-agent",
		CoreBinary:              "/opt/oboard/oboard-sb",
		CoreService:             "oboard-sb",
		AllowInsecureController: true,
	})
	if err := runner.Enroll(context.Background(), "enrollment-token"); err != nil {
		t.Fatal(err)
	}
	stored, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ServerID != 7 || stored.AgentID != "agent-7" || stored.AgentToken != "token-7" || !stored.ConnectionAuditEnabled {
		t.Fatalf("enrollment credentials were not persisted: %#v", stored)
	}
	if stored.CoreBinary != "/opt/oboard/oboard-sb" || stored.CoreService != "oboard-sb" {
		t.Fatalf("enrollment changed the core identity: %#v", stored)
	}
}

func TestExecuteDeploymentTaskReturnsOneReadableResult(t *testing.T) {
	dir := t.TempDir()
	config := `{"log":{"level":"warn"}}`
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(Config{StateDir: dir, TimeSyncCommand: "none"})
	payload := model.DeploymentTaskPayload{
		Version:       42,
		Config:        model.ApplyCoreConfigTaskPayload{Config: config},
		ConfigChanged: false,
		PortForwards:  model.PortForwardPlan{Version: 42},
		Tunnels:       model.TunnelPlan{Version: 42},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	status, resultJSON := r.ExecuteAgentTask(model.AgentTask{Type: model.AgentTaskTypeApplyDeployment, PayloadJSON: string(raw), ConfigVersion: 42})
	if status != "succeeded" {
		t.Fatalf("deployment status = %q, result=%s", status, resultJSON)
	}
	var result struct {
		Message string `json:"message"`
		Summary struct {
			Total   int `json:"total"`
			Skipped int `json:"skipped"`
		} `json:"summary"`
		Steps []struct {
			Key    string `json:"key"`
			Status string `json:"status"`
		} `json:"steps"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatal(err)
	}
	if result.Message != "部署已完成" || result.Summary.Total != 6 || result.Summary.Skipped != 2 || len(result.Steps) != 6 {
		t.Fatalf("unexpected aggregated deployment result: %#v", result)
	}
	if result.Steps[0].Key != "managed_assets" || result.Steps[0].Status != "skipped" || result.Steps[1].Key != "config" || result.Steps[1].Status != "skipped" {
		t.Fatalf("unchanged config step was not readable: %#v", result.Steps)
	}
}

func TestDeploymentRepairsMissingCoreConfigDespiteUnchangedHint(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, TimeSyncCommand: "none", ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	payload := model.DeploymentTaskPayload{
		Version:       43,
		Config:        model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"warn"}}`},
		ConfigChanged: false,
		PortForwards:  model.PortForwardPlan{Version: 43},
		Tunnels:       model.TunnelPlan{Version: 43},
	}
	status, result := r.executeDeploymentTask(payload)
	if status != "succeeded" {
		t.Fatalf("deployment did not repair missing config: %s", result)
	}
	if _, err := os.Stat(filepath.Join(dir, "sing-box.json")); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentCriticalForwardFailureStopsLaterMutations(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, TimeSyncCommand: "none"})
	payload := model.DeploymentTaskPayload{
		Version:       44,
		ConfigChanged: false,
		PortForwards: model.PortForwardPlan{Version: 44, Rules: []model.PortForward{{
			ID: 1, Name: "invalid-backend", Backend: model.ForwardBackend("unsupported"), Enabled: true,
		}}},
		Tunnels:     model.TunnelPlan{Version: 44},
		SSHInbounds: model.SSHInboundPlan{Version: 44},
	}
	status, resultJSON := r.executeDeploymentTask(payload)
	if status != "failed" {
		t.Fatalf("deployment status = %q, result=%s", status, resultJSON)
	}
	var result struct {
		Steps []deploymentStepResult `json:"steps"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatal(err)
	}
	seenForwardFailure := false
	for _, step := range result.Steps {
		switch step.Key {
		case "port_forwards":
			seenForwardFailure = step.Status == "failed"
		case "tunnels", "ssh_inbounds":
			t.Fatalf("later mutating step %q ran after critical forward failure: %#v", step.Key, result.Steps)
		}
	}
	if !seenForwardFailure {
		t.Fatalf("forward failure missing from deployment steps: %#v", result.Steps)
	}
	for _, path := range []string{filepath.Join(dir, tunnelsCurrent), filepath.Join(dir, sshInboundsCurrent)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later component state %s was mutated: %v", path, err)
		}
	}
}

func TestRemovedStandaloneTaskTypesAreRejected(t *testing.T) {
	r := New(Config{})
	for _, taskType := range []string{
		"sync_time",
		"restart_sing_box",
		"apply_port_forwards",
		"apply_tunnels",
		"request_warp_config",
		"prune_subscription_nodes",
	} {
		status, result := r.ExecuteAgentTask(model.AgentTask{Type: taskType, PayloadJSON: `{}`})
		if status != "failed" || !strings.Contains(result, "unknown task type") {
			t.Fatalf("removed task %q was accepted: status=%q result=%s", taskType, status, result)
		}
	}
}

func TestStandaloneDNSBenchmarkTaskAcceptsPlan(t *testing.T) {
	r := New(Config{})
	status, result := r.ExecuteAgentTask(model.AgentTask{Type: model.AgentTaskTypeBenchmarkDNS, PayloadJSON: `{}`})
	if status != "succeeded" || !strings.Contains(result, "empty dns benchmark plan") {
		t.Fatalf("dns benchmark task was not accepted safely: status=%q result=%s", status, result)
	}
}

func TestBestDNSBenchmarksReturnsTwoUsableCandidates(t *testing.T) {
	items := []dnsBenchmarkItem{{Tag: "failed", Error: "timeout", LatencyMS: 2000}, {Tag: "one", LatencyMS: 11}, {Tag: "two", LatencyMS: 18}, {Tag: "three", LatencyMS: 25}}
	best := bestDNSBenchmarks(items, 2)
	if len(best) != 2 || best[0].Tag != "one" || best[1].Tag != "two" {
		t.Fatalf("best = %#v", best)
	}
}

func TestDNSProbeRequiresAValidResponse(t *testing.T) {
	query, err := buildDNSProbeQuery(42)
	if err != nil {
		t.Fatal(err)
	}
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	if err := validateDNSProbeResponse(response, 42); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	if err := validateDNSProbeResponse(response, 43); err == nil {
		t.Fatal("mismatched DNS response id was accepted")
	}
	if err := validateDNSProbeResponse(query, 42); err == nil {
		t.Fatal("query packet was accepted as a response")
	}
}

func TestConfigRejectsUnsafeRuntimeSettings(t *testing.T) {
	base := normalizeConfig(Config{})
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.CommandTimeoutSeconds = 4 },
		func(cfg *Config) { cfg.CommandTimeoutSeconds = 121 },
		func(cfg *Config) { cfg.TimeCorrectionMode = "invalid" },
		func(cfg *Config) { cfg.RestartCommand = "sh -c reboot" },
	} {
		cfg := base
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe config was accepted: %#v", cfg)
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

func TestRunnerConfigSnapshotsAreAtomic(t *testing.T) {
	r := New(Config{AgentID: "a", AgentToken: "a", ResourceProfile: "large"})
	const iterations = 5000
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := range iterations {
			value := "a"
			if i%2 == 1 {
				value = "b"
			}
			cfg := r.Config()
			cfg.AgentID = value
			cfg.AgentToken = value
			r.storeConfig(cfg)
		}
	}()
	for range 2 {
		go func() {
			defer wg.Done()
			for range iterations {
				cfg := r.Config()
				if cfg.AgentID != cfg.AgentToken {
					t.Errorf("torn config snapshot: %#v", cfg)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSaveConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "agent.json")
	want := Config{ControllerURL: "https://controller.example", ServerID: 17, AgentID: "agent-1", StateDir: "/var/lib/oboard-agent"}
	if err := SaveConfig(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ControllerURL != want.ControllerURL || got.ServerID != want.ServerID || got.AgentID != want.AgentID || got.StateDir != want.StateDir {
		t.Fatalf("saved config = %#v, want %#v", got, want)
	}
}

func TestUpdateAgentControllerURLReportsResultThroughNewBasePath(t *testing.T) {
	reported := make(chan string, 1)
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reported <- req.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer controller.Close()
	configPath := filepath.Join(t.TempDir(), "agent.json")
	runner := newTestRunner(t, Config{
		ControllerURL:           controller.URL + "/old",
		AgentID:                 "agent-1",
		AgentToken:              "token-1",
		StateDir:                t.TempDir(),
		ConfigPath:              configPath,
		AllowInsecureController: true,
	})
	payload, _ := json.Marshal(map[string]any{"controller_url": controller.URL + "/new"})
	status, result := runner.ExecuteAgentTask(model.AgentTask{ID: 91, Type: model.AgentTaskTypeUpdateAgentConfig, PayloadJSON: string(payload), ConfigVersion: 10})
	if status != "succeeded" {
		t.Fatalf("update status = %s; result=%s", status, result)
	}
	stored, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ControllerURL != controller.URL+"/new" || runner.Config().ControllerURL != controller.URL+"/new" {
		t.Fatalf("Controller URL was not switched: stored=%q runtime=%q", stored.ControllerURL, runner.Config().ControllerURL)
	}
	if err := runner.ReportTaskResult(context.Background(), 91, status, result, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case path := <-reported:
		if path != "/new/api/v1/agent/task-results" {
			t.Fatalf("task result path = %q; want new base path", path)
		}
	case <-time.After(time.Second):
		t.Fatal("new Controller path did not receive task result")
	}
}

func TestConnectReportsAppliedConfigurationOnConnectAndHeartbeat(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	stateDir := t.TempDir()
	r := newTestRunner(t, Config{ControllerURL: "", AgentID: "agent-applied", AgentToken: "agent-token", ServerID: 1, StateDir: stateDir, CommandTimeoutSeconds: 1})
	payload := []byte(`{"version":51}`)
	if err := r.persistAppliedVersion(model.AgentTaskTypeApplyDeployment, 51, payload); err != nil {
		t.Fatal(err)
	}
	wantDigest := appliedPayloadID(model.AgentTaskTypeApplyDeployment, payload)
	reports := make(chan []model.HealthReport, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/agent/connect" {
			http.NotFound(w, req)
			return
		}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		seen := make([]model.HealthReport, 0, 2)
		readHealth := func() bool {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			for {
				var message struct {
					Type   string             `json:"type"`
					Health model.HealthReport `json:"health_report"`
				}
				if conn.ReadJSON(&message) != nil {
					return false
				}
				if message.Type == "health_report" {
					seen = append(seen, message.Health)
					return true
				}
			}
		}
		if !readHealth() {
			return
		}
		if conn.WriteJSON(map[string]any{"type": "hello", "server_id": 1, "desired_config_revision": 9}) != nil ||
			conn.WriteJSON(map[string]any{"type": "heartbeat", "desired_config_revision": 9, "configuration_sync_state": "queued", "configuration_sync_version": 51}) != nil || !readHealth() {
			return
		}
		reports <- seen
	}))
	defer server.Close()
	cfg := r.Config()
	cfg.ControllerURL = server.URL
	r.storeConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.connectTestControl(ctx) }()
	select {
	case seen := <-reports:
		if len(seen) != 2 {
			t.Fatalf("health report count = %d", len(seen))
		}
		for index, health := range seen {
			if health.AppliedConfigVersion != 51 || health.AppliedConfigDigest != wantDigest {
				t.Fatalf("health report %d applied state = version:%d digest:%q", index, health.AppliedConfigVersion, health.AppliedConfigDigest)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Agent did not report applied configuration on connect and heartbeat")
	}
	cancel()
	<-done
}

func TestConnectClosesSocketWhenTaskResultReportFails(t *testing.T) {
	token := "agent-token"
	task := model.AgentTask{ID: 42, ServerID: 1, Type: "unknown", PayloadJSON: "{}", ConfigVersion: 1, Nonce: "task-nonce"}
	signature := security.SignTaskEnvelope(security.HashSecret(token), security.TaskEnvelope{ID: task.ID, ServerID: task.ServerID, Type: task.Type, ConfigVersion: task.ConfigVersion, Nonce: task.Nonce, PayloadJSON: task.PayloadJSON})
	afterTask := make(chan string, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/connect":
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var initial map[string]any
			if err := conn.ReadJSON(&initial); err != nil {
				afterTask <- ""
				return
			}
			if err := conn.WriteJSON(map[string]any{"type": "hello", "server_id": task.ServerID}); err != nil {
				afterTask <- ""
				return
			}
			if err := conn.WriteJSON(map[string]any{"type": "task_request", "task": task, "signature_version": 2, "signature": signature}); err != nil {
				afterTask <- ""
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var next struct {
				Type string `json:"type"`
			}
			if err := conn.ReadJSON(&next); err != nil {
				afterTask <- ""
				return
			}
			afterTask <- next.Type
		case "/api/v1/agent/task-results":
			http.Error(w, "temporary failure", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	r := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: token, StateDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := r.connectTestControl(ctx); err == nil {
		t.Fatal("expected task result report error")
	}
	select {
	case message := <-afterTask:
		if message != "" {
			t.Fatalf("unexpected websocket message after report failure: %q", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("websocket handler did not observe the client disconnect")
	}
}

func TestConnectAcknowledgesReportedTaskOnWebSocket(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	token := "agent-token"
	task := model.AgentTask{ID: 43, ServerID: 1, Type: "unknown", PayloadJSON: "{}", ConfigVersion: 1, Nonce: "task-nonce"}
	signature := security.SignTaskEnvelope(security.HashSecret(token), security.TaskEnvelope{ID: task.ID, ServerID: task.ServerID, Type: task.Type, ConfigVersion: task.ConfigVersion, Nonce: task.Nonce, PayloadJSON: task.PayloadJSON})
	ack := make(chan map[string]any, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/agent/connect":
			conn, err := upgrader.Upgrade(w, req, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			var initial map[string]any
			if conn.ReadJSON(&initial) != nil {
				return
			}
			if conn.WriteJSON(map[string]any{"type": "hello", "server_id": task.ServerID}) != nil {
				return
			}
			if conn.WriteJSON(map[string]any{"type": "task_request", "task": task, "signature_version": 2, "signature": signature}) != nil {
				return
			}
			var message map[string]any
			if conn.ReadJSON(&message) == nil {
				ack <- message
			}
		case "/api/v1/agent/task-results":
			var body model.AgentTaskResultReport
			if json.NewDecoder(req.Body).Decode(&body) != nil || body.TaskID != task.ID || body.HealthReport == nil {
				http.Error(w, "invalid result", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	r := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: token, StateDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connectErr := r.connectTestControl(ctx)
	select {
	case message := <-ack:
		if message["type"] != "task_ack" || message["task_id"] != float64(task.ID) {
			t.Fatalf("unexpected task acknowledgement: %#v", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("task acknowledgement was not sent; connect error: %v", connectErr)
	}
}

// standardAuditCollection is the detail-collection policy a Controller in
// standard mode publishes, and the only mode under which presence exists.
var standardAuditCollection = auditCollectionPolicy{Mode: "standard"}

func TestConnectSendsPresenceWhileTaskAcknowledgementIsInFlight(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	token := "agent-token"
	task := model.AgentTask{ID: 45, ServerID: 1, Type: "unknown", PayloadJSON: "{}", ConfigVersion: 1, Nonce: "presence-task"}
	signature := security.SignTaskEnvelope(security.HashSecret(token), security.TaskEnvelope{ID: task.ID, ServerID: task.ServerID, Type: task.Type, ConfigVersion: task.ConfigVersion, Nonce: task.Nonce, PayloadJSON: task.PayloadJSON})
	result := make(chan map[string]bool, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/agent/connect":
			conn, err := upgrader.Upgrade(w, req, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			var initial map[string]any
			if conn.ReadJSON(&initial) != nil {
				return
			}
			if conn.WriteJSON(map[string]any{"type": "hello", "server_id": task.ServerID, "connection_audit_enabled": true, "audit_collection": standardAuditCollection}) != nil || conn.WriteJSON(map[string]any{"type": "task_request", "task": task, "signature_version": 2, "signature": signature}) != nil {
				return
			}
			seen := map[string]bool{}
			_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
			for !seen["task_ack"] || !seen["presence_delta"] {
				var message map[string]any
				if conn.ReadJSON(&message) != nil {
					return
				}
				if kind, _ := message["type"].(string); kind != "" {
					seen[kind] = true
				}
			}
			result <- seen
		case "/api/v1/agent/task-results":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	r := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: token, StateDir: t.TempDir(), ServerID: task.ServerID, ConnectionAuditEnabled: true})
	// Presence events exist only while detail collection is allowed; the light
	// default keeps a session accounting-only and emits nothing to deliver. The
	// policy matches the one the hello carries, so the session started here
	// survives the handshake instead of being discarded as a policy switch.
	r.connectionAudit.setCollectionPolicy(standardAuditCollection)
	session := r.connectionAudit.startSession(connectionAuditSnapshotItem{UserID: 7, InboundID: 11, SourceIP: "198.51.100.10", Network: "tcp"})
	defer session.finish()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connectDone := make(chan error, 1)
	go func() { connectDone <- r.connectTestControl(ctx) }()
	select {
	case seen := <-result:
		if !seen["task_ack"] || !seen["presence_delta"] {
			t.Fatalf("websocket messages = %#v", seen)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("task acknowledgement and presence delta did not coexist")
	}
	cancel()
	<-connectDone
}

func TestConnectRejectsLegacyTaskSignatureVersion(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	token := "agent-token"
	task := model.AgentTask{ID: 44, ServerID: 9, Type: "unknown", PayloadJSON: "{}", ConfigVersion: 1, Nonce: "legacy-signature"}
	ack := make(chan map[string]any, 1)
	reported := make(chan model.AgentTaskResultReport, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/agent/connect":
			conn, err := upgrader.Upgrade(w, req, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			var initial map[string]any
			if conn.ReadJSON(&initial) != nil {
				return
			}
			_ = conn.WriteJSON(map[string]any{"type": "hello", "server_id": task.ServerID})
			_ = conn.WriteJSON(map[string]any{"type": "task_request", "task": task, "signature_version": 1, "signature": "legacy"})
			_ = conn.WriteJSON(map[string]any{"type": "heartbeat"})
			for {
				var message map[string]any
				if conn.ReadJSON(&message) != nil {
					return
				}
				if message["type"] == "task_ack" {
					ack <- message
				}
			}
		case "/api/v1/agent/task-results":
			var report model.AgentTaskResultReport
			if err := json.NewDecoder(req.Body).Decode(&report); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			reported <- report
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	r := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: token, StateDir: t.TempDir(), ServerID: task.ServerID})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.connectTestControl(ctx) }()
	select {
	case report := <-reported:
		if report.TaskID != task.ID || report.Status != "failed" || !strings.Contains(report.ResultJSON, "signature version 1") {
			t.Fatalf("rejected task report = %#v", report)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("legacy signature was not reported as a failed task")
	}
	select {
	case message := <-ack:
		if message["task_id"] != float64(task.ID) {
			t.Fatalf("task_ack = %#v", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("legacy signature closed the control channel before task_ack")
	}
	cancel()
	<-done
}

func TestConnectKeepsControlChannelWhenLatencyPlanIsRejected(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	current := model.LatencyProbeTargetsPlan{
		Version: 20, ResourceVersion: "resource-v1", Mode: model.LatencyProbeModeTCP,
		Enabled: true, IntervalSeconds: 60, SampleCount: 1, IntervalMS: 150, TimeoutMS: 1000,
		Targets: []model.LatencyProbeTarget{{ProbeID: "public-cloudflare", Kind: "public", Host: "cp.cloudflare.com", Port: 443}},
	}
	stale := current
	stale.Version = 9
	health := make(chan string, 2)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/agent/connect" {
			http.NotFound(w, req)
			return
		}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var initial map[string]any
		if conn.ReadJSON(&initial) != nil {
			return
		}
		_ = conn.WriteJSON(map[string]any{"type": "hello", "server_id": int64(3), "latency_probe_plan": stale})
		_ = conn.WriteJSON(map[string]any{"type": "heartbeat"})
		for {
			var message map[string]any
			if conn.ReadJSON(&message) != nil {
				return
			}
			if message["type"] == "health_report" {
				health <- "health"
			}
		}
	}))
	defer server.Close()
	r := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: "agent-token", StateDir: t.TempDir(), ServerID: 3})
	if err := r.setLatencyProbePlan(current); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.connectTestControl(ctx) }()
	select {
	case <-health:
	case err := <-done:
		t.Fatalf("stale latency plan closed the control channel: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("expected a heartbeat health report after a rejected latency plan")
	}
	cancel()
	<-done
}

func TestWGCFProfileToSingBoxEmitsCurrentWireGuardEndpointSchema(t *testing.T) {
	profile := `[Interface]
PrivateKey = private-key
Address = 172.16.0.2/32, 2606:4700:110:abcd::2/128
MTU = 1280
Reserved = 1, 2, 3

[Peer]
PublicKey = public-key
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
`
	endpoint, err := wgcfProfileToSingBox(profile, model.WARPRequestPlan{ProfileID: 42, IPStack: model.IPStackDualStack, DNSStrategy: "prefer_ipv6"})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint["type"] != "wireguard" || endpoint["tag"] != "warp-42" {
		t.Fatalf("unexpected endpoint identity: %#v", endpoint)
	}
	for _, key := range []string{"local_address", "server", "server_port", "peer_public_key", "network"} {
		if _, ok := endpoint[key]; ok {
			t.Fatalf("endpoint should not emit deprecated wireguard outbound field %s: %#v", key, endpoint)
		}
	}
	peers, ok := endpoint["peers"].([]map[string]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("unexpected peers: %#v", endpoint["peers"])
	}
	if peers[0]["address"] != "engage.cloudflareclient.com" || peers[0]["port"] != 2408 || peers[0]["public_key"] != "public-key" {
		t.Fatalf("peer was not normalized to endpoint schema: %#v", peers[0])
	}
	reserved, ok := peers[0]["reserved"].([]int)
	if !ok || len(reserved) != 3 || reserved[0] != 1 || reserved[1] != 2 || reserved[2] != 3 {
		t.Fatalf("WARP reserved bytes must be attached to the peer: %#v", peers[0])
	}
	resolver, ok := endpoint["domain_resolver"].(map[string]any)
	if !ok || resolver["server"] != warpBootstrapResolverTag || resolver["strategy"] != "prefer_ipv6" {
		t.Fatalf("domain_resolver was not normalized: %#v", endpoint["domain_resolver"])
	}
	encoded, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "local_address") || strings.Contains(string(encoded), "peer_public_key") {
		t.Fatalf("encoded endpoint contains deprecated fields: %s", encoded)
	}
}

func TestRegisterWARPWireGuardWithoutWGCF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("CF-Client-Version") != "a-6.10-2158" {
			t.Fatalf("unexpected WARP registration request: method=%s headers=%v", r.Method, r.Header)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["key"] == "" || payload["install_id"] == "" || payload["tos"] == "" {
			t.Fatalf("registration payload is incomplete: %#v", payload)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"id":"device-id","config":{"client_id":"AQID","interface":{"addresses":{"v4":"172.16.0.2/32","v6":"2606:4700:110:abcd::2/128"}}}}`))
	}))
	defer server.Close()

	endpoint, err := registerWARPWireGuard(context.Background(), server.Client(), server.URL, model.WARPRequestPlan{ProfileID: 7, DNSStrategy: "prefer_ipv6"})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint["type"] != "wireguard" || endpoint["tag"] != "warp-7" || endpoint["mtu"] != 1280 {
		t.Fatalf("unexpected WARP endpoint: %#v", endpoint)
	}
	if key, _ := endpoint["private_key"].(string); len(key) != 44 {
		t.Fatalf("invalid generated private key: %q", key)
	}
	peers := endpoint["peers"].([]map[string]any)
	reserved := peers[0]["reserved"].([]int)
	if len(reserved) != 3 || reserved[0] != 1 || reserved[1] != 2 || reserved[2] != 3 {
		t.Fatalf("native WARP reserved bytes = %#v, want [1 2 3]", reserved)
	}
	if peers[0]["public_key"] != warpPeerPublicKey {
		t.Fatalf("native WARP peer public key = %#v", peers[0]["public_key"])
	}
	resolver, ok := endpoint["domain_resolver"].(map[string]any)
	if !ok || resolver["server"] != warpBootstrapResolverTag || resolver["strategy"] != "prefer_ipv6" {
		t.Fatalf("native WARP domain_resolver = %#v", endpoint["domain_resolver"])
	}
}

func TestWARPReservedBytesFallback(t *testing.T) {
	for _, clientID := range []string{"", "not-base64"} {
		reserved, err := warpReservedBytes(clientID)
		if err != nil || len(reserved) != 3 || reserved[0] != 0 || reserved[1] != 0 || reserved[2] != 0 {
			t.Fatalf("client_id %q fallback = %#v, %v; want [0 0 0]", clientID, reserved, err)
		}
	}
}

func TestRunnerProbeUsesCachedFullProbe(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	dir := t.TempDir()
	counter := filepath.Join(dir, "counter")
	binary := filepath.Join(dir, "fake-sb")
	script := "#!/bin/sh\necho hit >> \"" + counter + "\"\necho fake-sing-box-1.0\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	r := New(Config{
		AgentID:               "agent-test",
		CoreBinary:            binary,
		ResourceProfile:       "large",
		CommandTimeoutSeconds: 2,
		RestartCommand:        "none",
	})
	first := r.Probe(true)
	second := r.Probe(false)

	if first.SingBoxVersion != "fake-sing-box-1.0" || second.SingBoxVersion != "fake-sing-box-1.0" {
		t.Fatalf("unexpected versions: %q / %q", first.SingBoxVersion, second.SingBoxVersion)
	}
	b, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "hit"); got != 1 {
		t.Fatalf("probe command executions = %d, want 1", got)
	}
}

func TestRunnerMonitoringPolicyModes(t *testing.T) {
	r := New(Config{ResourceProfile: "large", CommandTimeoutSeconds: 20})
	r.setMonitoringPolicy("standard")
	r.mu.Lock()
	mode := r.monitoringMode
	r.mu.Unlock()
	if mode != "standard" {
		t.Fatalf("standard policy mode=%q", mode)
	}
	r.setMonitoringPolicy("unknown")
	r.mu.Lock()
	mode = r.monitoringMode
	r.mu.Unlock()
	if mode != "lightweight" {
		t.Fatalf("fallback policy mode=%q", mode)
	}
}

func TestCommandOutputIsBounded(t *testing.T) {
	out, err := commandOutput(2*time.Second, "sh", "-c", "i=0; while [ $i -lt 20000 ]; do printf 0123456789; i=$((i+1)); done")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != commandOutputLimit {
		t.Fatalf("bounded output length = %d, want %d", len(out), commandOutputLimit)
	}
}

func TestRunnerExecuteCollectLogs(t *testing.T) {
	r := New(Config{CoreBinary: "missing-oboard-sb-for-test"})
	status, resultJSON := r.ExecuteAgentTask(model.AgentTask{Type: model.AgentTaskTypeCollectLogs, PayloadJSON: `{"lines":20,"services":"agent"}`})
	if status != "succeeded" {
		t.Fatalf("status = %s result=%s", status, resultJSON)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatal(err)
	}
	if result["message"] != "logs collected" || result["agent_build"] == "" {
		t.Fatalf("unexpected collect logs result: %#v", result)
	}
	if _, ok := result["logs"].(map[string]any)["agent"]; !ok {
		t.Fatalf("agent log section missing: %#v", result)
	}
}

func TestReadDiagnosticTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\nfour\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readDiagnosticTail(path, 2)
	if ok, _ := got["ok"].(bool); !ok {
		t.Fatalf("tail read failed: %#v", got)
	}
	if content := got["content"]; content != "three\nfour" {
		t.Fatalf("content = %#v, want tail lines", content)
	}
}

func TestReadDiagnosticTailMatching(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	body := "kernel: ready\noboard-agent: connected\ncron: tick\noboard-sb: started\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readDiagnosticTailMatching(path, []string{"oboard-agent", "oboard-sb"}, 10)
	if ok, _ := got["ok"].(bool); !ok {
		t.Fatalf("tail match failed: %#v", got)
	}
	if content := got["content"]; content != "oboard-agent: connected\noboard-sb: started" {
		t.Fatalf("content = %#v, want matching lines", content)
	}
}

func TestReadMemoryLimit(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		body string
		want int64
	}{
		{name: "cgroup-v2-max", body: "max", want: 0},
		{name: "empty", body: "", want: 0},
		{name: "invalid", body: "not-a-number", want: 0},
		{name: "huge-sentinel", body: "9223372036854771712", want: 0},
		{name: "valid", body: "67108864", want: 67108864},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := readMemoryLimit(path); got != tc.want {
				t.Fatalf("readMemoryLimit() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRestartCommandNoneSkipsProcessManager(t *testing.T) {
	r := New(Config{RestartCommand: "none", ResourceProfile: "large", StateDir: t.TempDir()})
	if err := r.restartCore(); err != nil {
		t.Fatal(err)
	}
}

func TestReloadCommandNoneSkipsProcessManager(t *testing.T) {
	r := New(Config{ReloadCommand: "none", ResourceProfile: "large", StateDir: t.TempDir()})
	if err := r.reloadCore(); err != nil {
		t.Fatal(err)
	}
}

func TestOBoardCoreDoesNotClaimHotReloadSupport(t *testing.T) {
	r := New(Config{CoreBinary: "/usr/local/bin/oboard-sb", CoreService: "oboard-sb", ResourceProfile: "large"})
	if r.coreHotReloadSupported() {
		t.Fatal("oboard-sb must use a verified managed restart")
	}
}

// An oboard-sb core never takes the reload branch, even when the service
// manager is unmanaged. Reporting "hot_reload" there was a label for something
// that never happened: nothing had asked the kernel to re-read anything.
func TestApplyCoreConfigNeverReportsHotReloadForOBoardCore(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	result, err := r.applyCoreConfigTask(42, model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"info"}}`})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "restart_fallback" || result["connection_draining"] != false {
		t.Fatalf("unexpected apply result: %#v", result)
	}
	if _, err := os.Stat(filepath.Join(dir, "sing-box.json")); err != nil {
		t.Fatal(err)
	}
}

// A third-party core that Agent was pointed at keeps the reload path.
func TestApplyCoreConfigKeepsHotReloadForThirdPartyCore(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "custom-core"), CoreService: "custom-core", ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	result, err := r.applyCoreConfigTask(42, model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"info"}}`})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "hot_reload" || result["connection_draining"] != true {
		t.Fatalf("unexpected apply result: %#v", result)
	}
}

// A failed apply restores the last-good configuration and must bring the
// running kernel back onto it with a restart. Signalling a reload at oboard-sb
// is either a no-op that leaves the failed configuration serving, or - on
// OpenRC, where nothing restarts the kernel automatically - a plain kill.
func TestApplyCoreConfigRollbackRestartsAndNeverSignalsReload(t *testing.T) {
	dir := t.TempDir()
	previous := `{"log":{"level":"warn"}}`
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(Config{
		StateDir:        dir,
		CoreBinary:      filepath.Join(dir, "missing-sb"),
		CoreService:     "oboard-sb",
		ReloadCommand:   "bogus-reload",
		RestartCommand:  "bogus-restart",
		ResourceProfile: "large",
	})
	result, err := r.applyCoreConfigTask(43, model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"debug"}}`})
	if err == nil {
		t.Fatal("apply must fail when the core cannot be restarted")
	}
	if result["reload_strategy"] != "rollback" {
		t.Fatalf("reload_strategy = %v, want rollback", result["reload_strategy"])
	}
	if _, signalled := result["rollback_reload_error"]; signalled {
		t.Fatalf("oboard-sb rollback signalled a reload: %#v", result)
	}
	if result["rollback_strategy"] != "restart_failed" {
		t.Fatalf("rollback_strategy = %v, want restart_failed", result["rollback_strategy"])
	}
	current, err := os.ReadFile(filepath.Join(dir, "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(current)) != previous {
		t.Fatalf("last-good configuration was not restored: %s", current)
	}
}

func TestCoreRuntimeMetadataComparisonIgnoresOnlyOBoardBlock(t *testing.T) {
	previous := []byte(`{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"used_baseline_bytes":4}}}}}`)
	next := []byte(`{"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"used_baseline_bytes":10}}}},"log":{"level":"warn"}}`)
	onlyRuntime, err := coreRuntimeMetadataOnlyChange(previous, next)
	if err != nil {
		t.Fatal(err)
	}
	if !onlyRuntime {
		t.Fatal("runtime metadata-only change was not recognized")
	}
	operational := []byte(`{"log":{"level":"error"},"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"used_baseline_bytes":10}}}}}`)
	onlyRuntime, err = coreRuntimeMetadataOnlyChange(previous, operational)
	if err != nil {
		t.Fatal(err)
	}
	if onlyRuntime {
		t.Fatal("operational config change was mistaken for runtime metadata")
	}
	trusted := []byte(`{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"used_baseline_bytes":10}}},"trusted_forward":{"receivers":[{"id":"one"}]}}}`)
	onlyRuntime, err = coreRuntimeMetadataOnlyChange(next, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if onlyRuntime {
		t.Fatal("trusted forward change was mistaken for runtime-only metadata")
	}
}

func TestApplyCoreConfigUpdatesRuntimeMetadataWithoutReload(t *testing.T) {
	dir := t.TempDir()
	previous := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{}}}`
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	next := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{}}}}`
	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	result, err := r.applyCoreConfigTask(44, model.ApplyCoreConfigTaskPayload{Config: next})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "runtime_policy_only" || result["connection_draining"] != false {
		t.Fatalf("runtime metadata update reloaded core: %#v", result)
	}
	current, err := os.ReadFile(filepath.Join(dir, "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	var currentValue, nextValue any
	if err := json.Unmarshal(current, &currentValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(next), &nextValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(currentValue, nextValue) {
		t.Fatalf("runtime metadata was not persisted: %s", current)
	}
}

func TestApplyCoreRuntimeMetadataPartitionsLeaseWithSSH(t *testing.T) {
	dir := t.TempDir()
	previous := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"billable":true,"lease_enforced":true,"lease_bytes":100,"reset_lease_bytes":80}}}}}`
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}

	socketFile, err := os.CreateTemp("/tmp", "oboard-core-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	socket := socketFile.Name()
	_ = socketFile.Close()
	_ = os.Remove(socket)
	t.Cleanup(func() { _ = os.Remove(socket) })
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var received model.TrafficRuntimePolicy
	coreServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body struct {
			Policies map[string]model.TrafficRuntimePolicy `json:"policies"`
		}
		if request.URL.Path == "/traffic/snapshot" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
			return
		}
		if request.URL.Path != "/traffic/policy" || json.NewDecoder(request.Body).Decode(&body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		received = body.Policies["user:7"]
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})}
	go func() { _ = coreServer.Serve(listener) }()
	t.Cleanup(func() { _ = coreServer.Close() })

	counter := &sshInboundCounter{}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, InboundID: 17, Billable: true, LeaseEnforced: true, LeaseBytes: 50, ResetLeaseBytes: 40})
	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	r.coreClient = unixHTTPClient(socket)
	r.sshInboundManager = &sshInboundManager{listeners: map[int64]*managedSSHInbound{17: {plan: model.SSHInbound{InboundID: 17}, counters: map[int64]*sshInboundCounter{7: counter}}}}
	next := `{"log":{"level":"warn"},"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"billable":true,"lease_enforced":true,"lease_bytes":80,"reset_lease_bytes":60}}}}}`
	result, err := r.applyCoreConfigTask(45, model.ApplyCoreConfigTaskPayload{Config: next})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "runtime_policy_only" {
		t.Fatalf("unexpected apply result: %#v", result)
	}
	sshPolicy := counter.currentPolicy()
	if received.LeaseBytes != 40 || received.ResetLeaseBytes != 30 || sshPolicy.LeaseBytes != 40 || sshPolicy.ResetLeaseBytes != 30 {
		t.Fatalf("runtime lease was not partitioned: core=%#v ssh=%#v", received, sshPolicy)
	}
}

func TestEmbeddedCoreTrafficPoliciesUseUserIdentity(t *testing.T) {
	policies, err := embeddedCoreTrafficPolicies([]byte(`{"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"billable":true,"lease_enforced":true}},"inbounds":{"path":{"user_id":9,"inbound_id":3,"billable":true}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 || policies["user:7"] == nil || policies["user:9"] == nil {
		t.Fatalf("unexpected embedded policies: %#v", policies)
	}
}

func TestApplyCoreConfigSkipsRollbackAndPersistsVersion(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"}
	r := newTestRunner(t, cfg)
	newConfig := `{"log":{"level":"warn"}}`
	if _, err := r.applyCoreConfigTask(20, model.ApplyCoreConfigTaskPayload{Config: newConfig}); err != nil {
		t.Fatal(err)
	}
	stale, err := r.applyCoreConfigTask(19, model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"debug"}}`})
	requireSuperseded(t, stale, err, 20)
	current, err := os.ReadFile(filepath.Join(dir, "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != newConfig {
		t.Fatalf("older config changed current file: %s", current)
	}

	restarted := newTestRunner(t, cfg)
	// The watermark survives a restart, so the rollback is still skipped rather
	// than applied — the guard lives on disk, not in process memory.
	afterRestart, err := restarted.applyCoreConfigTask(19, model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"error"}}`})
	requireSuperseded(t, afterRestart, err, 20)
	result, err := restarted.applyCoreConfigTask(20, model.ApplyCoreConfigTaskPayload{Config: newConfig})
	if err != nil || result["idempotent_replay"] != true {
		t.Fatalf("same-version replay was not idempotent: result=%#v err=%v", result, err)
	}
	if _, err := restarted.applyCoreConfigTask(20, model.ApplyCoreConfigTaskPayload{Config: `{"log":{"level":"info"}}`}); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("same-version content replacement was not rejected: %v", err)
	}
}

func TestFamilySelectorCoreConfigUsesPersistentVersionGate(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"}
	familyConfig := `{"outbounds":[{"type":"direct","tag":"family-v4"},{"type":"direct","tag":"family-v6"},{"type":"family-selector","tag":"family","ipv4_outbound":"family-v4","ipv6_outbound":"family-v6","strategy":"prefer_ipv4","fallback":true}]}`
	runner := newTestRunner(t, cfg)
	if _, err := runner.applyCoreConfigTask(30, model.ApplyCoreConfigTaskPayload{Config: familyConfig}); err != nil {
		t.Fatal(err)
	}
	restarted := newTestRunner(t, cfg)
	result, err := restarted.applyCoreConfigTask(30, model.ApplyCoreConfigTaskPayload{Config: familyConfig})
	if err != nil || result["idempotent_replay"] != true {
		t.Fatalf("family-selector same-version replay was not idempotent: result=%#v err=%v", result, err)
	}
	if _, err := restarted.applyCoreConfigTask(30, model.ApplyCoreConfigTaskPayload{Config: strings.Replace(familyConfig, "prefer_ipv4", "prefer_ipv6", 1)}); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("family-selector same-version replacement was accepted: %v", err)
	}
	rollback, err := restarted.applyCoreConfigTask(29, model.ApplyCoreConfigTaskPayload{Config: familyConfig})
	requireSuperseded(t, rollback, err, 30)
}

func TestDeploymentVersionGateCoversUnchangedConfigPlans(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	payload := func(version int64) model.DeploymentTaskPayload {
		return model.DeploymentTaskPayload{Version: version, ConfigChanged: false, PortForwards: model.PortForwardPlan{Version: version}, Tunnels: model.TunnelPlan{Version: version}}
	}
	if status, result := r.executeDeploymentTask(payload(30)); status != "succeeded" {
		t.Fatalf("new deployment failed: %s", result)
	}
	status, result := r.executeDeploymentTask(payload(29))
	requireSupersededTaskResult(t, status, result, 30)
	restarted := New(Config{StateDir: dir, ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	status, result = restarted.executeDeploymentTask(payload(29))
	requireSupersededTaskResult(t, status, result, 30)
}

func TestTaskServerIdentityMustMatchEnrollment(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")
	r := New(Config{ConfigPath: configPath, AgentID: "agent-a", AgentToken: "token-a", StateDir: dir})
	if err := r.bindServerIdentity(7); err != nil {
		t.Fatal(err)
	}
	if err := r.validateTaskServerID(model.AgentTask{ID: 1, ServerID: 7}); err != nil {
		t.Fatalf("matching task rejected: %v", err)
	}
	if err := r.validateTaskServerID(model.AgentTask{ID: 2, ServerID: 8}); err == nil {
		t.Fatal("task for another server was accepted")
	}
	if err := r.bindServerIdentity(8); err == nil {
		t.Fatal("conflicting hello server identity was accepted")
	}
	reloaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ServerID != 7 {
		t.Fatalf("bound server ID was not persisted: %#v", reloaded)
	}
}

func TestApplyCoreConfigRestartsWhenInboundListenRemoved(t *testing.T) {
	dir := t.TempDir()
	current := `{"inbounds":[{"type":"vless","tag":"in-1","listen":"0.0.0.0","listen_port":21001},{"type":"vless","tag":"in-2","listen":"0.0.0.0","listen_port":21002}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	next := `{"inbounds":[{"type":"vless","tag":"in-1","listen":"0.0.0.0","listen_port":21001}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	r := New(Config{StateDir: dir, CoreBinary: filepath.Join(dir, "missing-sb"), ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	result, err := r.applyCoreConfigTask(43, model.ApplyCoreConfigTaskPayload{Config: next})
	if err != nil {
		t.Fatal(err)
	}
	if result["reload_strategy"] != "restart_fallback" || result["connection_draining"] != false {
		t.Fatalf("unexpected apply result: %#v", result)
	}
	removed, ok := result["removed_listen_resources"].([]string)
	if !ok || len(removed) != 1 || !strings.Contains(removed[0], "21002") {
		t.Fatalf("removed resources = %#v", result["removed_listen_resources"])
	}
}

func TestTimeSyncCommandNoneDisablesSystemCorrection(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, TimeSyncCommand: "none", ResourceProfile: "large"})
	command, args, err := r.timeSyncCommand(defaultTimeServers())
	if err != nil {
		t.Fatal(err)
	}
	if command != "none" || len(args) != 0 {
		t.Fatalf("time sync command = %q %#v, want none", command, args)
	}
}

func TestDNSBenchmarkFirstApplySkipsWhenAlreadyRun(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, RestartCommand: "none", ResourceProfile: "large"})
	plan := testDNSBenchmarkPlan()
	state := dnsBenchmarkLocalState{LastRun: map[string]time.Time{dnsBenchmarkPlanKey(plan): time.Now().UTC()}}
	if err := r.saveDNSBenchmarkState(state); err != nil {
		t.Fatal(err)
	}
	result, err := r.runDNSBenchmarkTask(context.Background(), plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if result["skipped"] != true {
		t.Fatalf("expected first_apply benchmark to skip, got %#v", result)
	}
}

func TestDNSBenchmarkFailsWhenStateCannotBeRead(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(stateDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(Config{StateDir: stateDir, ResourceProfile: "large"})
	_, err := r.runDNSBenchmarkTask(context.Background(), testDNSBenchmarkPlan(), false)
	if err == nil {
		t.Fatal("expected state read failure")
	}
}

// Controller matches this exact string to fall a server back to local DNS, so a
// reworded Agent message would silently disable that fallback. Keep the literal
// pinned on both sides of the wire.
func TestDNSBenchmarkNoUsableCandidatesSentinelIsPinned(t *testing.T) {
	const controllerConstant = "both encrypted and bootstrap dns groups require at least one usable candidate"
	if model.DNSBenchmarkNoUsableCandidatesError != controllerConstant {
		t.Fatalf("sentinel = %q, want the Controller model constant %q", model.DNSBenchmarkNoUsableCandidatesError, controllerConstant)
	}
}

func TestDNSBenchmarkAcceptsPlanWithoutEncryptedGroup(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, RestartCommand: "none", ResourceProfile: "large"})
	plan := testDNSBenchmarkPlan()
	plan.EncryptedListID = 0
	plan.EncryptedListRevision = 0
	plan.EncryptedCandidates = nil
	state := dnsBenchmarkLocalState{LastRun: map[string]time.Time{dnsBenchmarkPlanKey(plan): time.Now().UTC()}}
	if err := r.saveDNSBenchmarkState(state); err != nil {
		t.Fatal(err)
	}
	result, err := r.runDNSBenchmarkTask(context.Background(), plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if result["skipped"] != true || result["reason"] != "first_apply already completed" {
		t.Fatalf("plain-only plan = %#v, want a runnable plan that stops at the first_apply gate", result)
	}
}

func TestDNSBenchmarkRejectsInconsistentEncryptedGroup(t *testing.T) {
	dir := t.TempDir()
	r := New(Config{StateDir: dir, RestartCommand: "none", ResourceProfile: "large"})
	plan := testDNSBenchmarkPlan()
	plan.EncryptedListID = 0
	plan.EncryptedListRevision = 0
	result, err := r.runDNSBenchmarkTask(context.Background(), plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if result["skipped"] != true || result["reason"] != "inconsistent dns benchmark encrypted group" {
		t.Fatalf("inconsistent plan = %#v, want it rejected before probing", result)
	}
}

func testDNSBenchmarkPlan() model.DNSBenchmarkPlan {
	return model.DNSBenchmarkPlan{
		ServerID: 7, PolicyRevision: 3, EncryptedListID: 11, EncryptedListRevision: 4, BootstrapListID: 12, BootstrapListRevision: 5,
		Mode: model.DNSAutoTestFirstApply,
		EncryptedCandidates: []model.DNSCandidate{
			{Tag: "encrypted-one", Transport: model.DNSTransportDoH, Server: "dns.google", Port: 443, Path: "/dns-query", TLSName: "dns.google"},
			{Tag: "encrypted-two", Transport: model.DNSTransportDoT, Server: "dns.quad9.net", Port: 853, TLSName: "dns.quad9.net"},
		},
		BootstrapCandidates: []model.DNSCandidate{
			{Tag: "bootstrap-one", Transport: model.DNSTransportUDP, Server: "1.1.1.1", Port: 53},
			{Tag: "bootstrap-two", Transport: model.DNSTransportTCP, Server: "8.8.8.8", Port: 53},
		},
	}
}

func TestGenerateRealmConfig(t *testing.T) {
	rules := []forwardRule{{PortForward: model.PortForward{ID: 1, Name: "a-to-b", ListenIP: "127.0.0.1", ListenPort: 443, TargetAddress: "203.0.113.2", TargetPort: 8443, Protocol: model.ForwardProtocolTCP, Priority: 10}, ResolvedBackend: model.ForwardBackendRealm}}
	config, err := generateRealmConfig(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`listen = "127.0.0.1:443"`, `remote = "203.0.113.2:8443"`, `[[endpoints]]`} {
		if !strings.Contains(config, want) {
			t.Fatalf("realm config missing %q:\n%s", want, config)
		}
	}
}

func TestResolveForwardBackends(t *testing.T) {
	rules := []model.PortForward{{ID: 1, Name: "unset", Backend: ""}, {ID: 2, Name: "realm", Backend: model.ForwardBackendRealm}}
	resolved, err := resolveForwardBackends(rules, map[string]bool{"realm": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range resolved {
		if rule.ResolvedBackend != model.ForwardBackendRealm {
			t.Fatalf("rule %d backend = %s, want realm", rule.ID, rule.ResolvedBackend)
		}
	}
	if _, err := resolveForwardBackends(rules, map[string]bool{}); err == nil {
		t.Fatal("expected a rule to fail when realm is unavailable")
	}
	if _, err := resolveForwardBackends([]model.PortForward{{ID: 3, Name: "nft", Backend: model.ForwardBackend("nft")}}, map[string]bool{"realm": true}); err == nil {
		t.Fatal("expected a retired backend to be rejected")
	}
}

func TestApplyPortForwardsKeepsExistingRulesWhenCurrentPlanIsUnreadable(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(stateDir, portForwardsCurrent), 0o700); err != nil {
		t.Fatal(err)
	}
	r := New(Config{StateDir: stateDir})
	if _, err := r.applyPortForwards(model.PortForwardPlan{}); err == nil {
		t.Fatal("expected unreadable current plan error")
	}
	if r.forwardDesiredState != "" {
		t.Fatal("desired state was recorded after the current plan could not be read")
	}
}

func TestPortForwardDesiredStateSkipsVersionOnlyUpdate(t *testing.T) {
	r := New(Config{StateDir: t.TempDir()})
	plan := model.PortForwardPlan{Version: 1}
	if _, err := r.applyPortForwards(plan); err != nil {
		t.Fatal(err)
	}
	plan.Version = 2
	result, err := r.applyPortForwards(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Unchanged {
		t.Fatalf("version-only desired state update was applied: %#v", result)
	}
}

func TestResetRuntimeDesiredStateCachesForcesRebuild(t *testing.T) {
	r := New(Config{StateDir: t.TempDir()})
	plan := model.PortForwardPlan{Version: 1}
	if _, err := r.applyPortForwards(plan); err != nil {
		t.Fatal(err)
	}
	plan.Version = 2
	replay, err := r.applyPortForwards(plan)
	if err != nil || !replay.Unchanged {
		t.Fatalf("expected version-only replay, got %#v err=%v", replay, err)
	}
	r.resetRuntimeDesiredStateCaches()
	rebuilt, err := r.applyPortForwards(plan)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Unchanged {
		t.Fatal("force refresh left the listener desired-state shortcut in place")
	}
}

func TestDesiredStateIDsIgnorePlanVersion(t *testing.T) {
	forwardOne, err := portForwardDesiredStateID(model.PortForwardPlan{Version: 1, Rules: []model.PortForward{{ID: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	forwardTwo, _ := portForwardDesiredStateID(model.PortForwardPlan{Version: 2, Rules: []model.PortForward{{ID: 1}}})
	tunnelOne, _ := tunnelDesiredStateID(model.TunnelPlan{Version: 1, Tunnels: []model.Tunnel{{ID: 1}}})
	tunnelTwo, _ := tunnelDesiredStateID(model.TunnelPlan{Version: 2, Tunnels: []model.Tunnel{{ID: 1}}})
	sshOne, _ := sshInboundDesiredStateID(model.SSHInboundPlan{Version: 1, Inbounds: []model.SSHInbound{{InboundID: 1}}})
	sshTwo, _ := sshInboundDesiredStateID(model.SSHInboundPlan{Version: 2, Inbounds: []model.SSHInbound{{InboundID: 1}}})
	if forwardOne != forwardTwo || tunnelOne != tunnelTwo || sshOne != sshTwo {
		t.Fatal("plan desired-state IDs must ignore version fields")
	}
}

func TestInboundListenEndpointsMatchForwardTransports(t *testing.T) {
	cases := []struct {
		name     string
		config   string
		protocol model.ForwardProtocol
		want     bool
	}{
		{name: "vless tcp", config: `{"inbounds":[{"type":"vless","listen_port":443}]}`, protocol: model.ForwardProtocolTCP, want: true},
		{name: "vless does not conflict udp", config: `{"inbounds":[{"type":"vless","listen_port":443}]}`, protocol: model.ForwardProtocolUDP, want: false},
		{name: "hy2 udp", config: `{"inbounds":[{"type":"hysteria2","listen_port":443}]}`, protocol: model.ForwardProtocolUDP, want: true},
		{name: "ss both", config: `{"inbounds":[{"type":"shadowsocks","listen_port":443}]}`, protocol: model.ForwardProtocolTCPUDP, want: true},
		{name: "ss tcp only does not conflict udp", config: `{"inbounds":[{"type":"shadowsocks","network":"tcp","listen_port":443}]}`, protocol: model.ForwardProtocolUDP, want: false},
		{name: "different specific address", config: `{"inbounds":[{"type":"vless","listen":"192.0.2.10","listen_port":443}]}`, protocol: model.ForwardProtocolTCP, want: false},
		{name: "wildcard overlaps specific address", config: `{"inbounds":[{"type":"vless","listen":"0.0.0.0","listen_port":443}]}`, protocol: model.ForwardProtocolTCP, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := model.PortForward{ListenIP: "192.0.2.11", ListenPort: 443, Protocol: tc.protocol}
			if tc.name != "different specific address" && tc.name != "wildcard overlaps specific address" {
				rule.ListenIP = ""
			}
			got := forwardConflictsWithInbounds(rule, inboundListenEndpoints([]byte(tc.config)))
			if got != tc.want {
				t.Fatalf("conflict = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestValidateTunnelSetRejectsInvalidConfigBeforeApplying(t *testing.T) {
	err := validateTunnelSet([]model.Tunnel{{Name: "invalid", Type: model.TunnelTypeSSH, ConfigJSON: `{}`}}, map[string]bool{"ssh": true})
	if err == nil {
		t.Fatal("expected invalid tunnel config to be rejected")
	}
}

func TestValidateTunnelSetRequiresAvailableBackend(t *testing.T) {
	err := validateTunnelSet([]model.Tunnel{{Name: "ssh", Type: model.TunnelTypeSSH, ConfigJSON: `{"user":"root"}`}}, map[string]bool{})
	if err == nil {
		t.Fatal("expected unavailable ssh backend to be rejected")
	}
}

func TestValidateTunnelSetRejectsMissingSSHEndpoint(t *testing.T) {
	err := validateTunnelSet([]model.Tunnel{{Name: "ssh", Type: model.TunnelTypeSSH, ConfigJSON: `{"user":"root"}`}}, map[string]bool{"ssh": true})
	if err == nil {
		t.Fatal("expected missing ssh endpoint to be rejected")
	}
}

func TestNormalizeMTUPlanDefaults(t *testing.T) {
	plan := normalizeMTUPlan(model.MTUDetectionPlan{Mode: model.MTUModeDisabled, OverheadBytes: -1, SampleCount: 99, TimeoutMS: 9000})
	if plan.Mode != model.MTUModeDetect {
		t.Fatalf("mode = %s, want detect", plan.Mode)
	}
	if plan.TargetHost != "1.1.1.1" || plan.TargetPort != 443 {
		t.Fatalf("target = %s:%d", plan.TargetHost, plan.TargetPort)
	}
	if plan.SampleCount != 3 || plan.TimeoutMS != 1200 || plan.MinMTU != 1280 || plan.MaxMTU != 9000 {
		t.Fatalf("unexpected probe defaults: %#v", plan)
	}
	if plan.OverheadBytes != 0 {
		t.Fatalf("overhead = %d, want 0", plan.OverheadBytes)
	}
}

func TestRecommendMTUUsesLowestVerifiedSignalAndOverhead(t *testing.T) {
	if got := recommendMTU(1500, 1480, 80, 1280, 9000); got != 1400 {
		t.Fatalf("recommendMTU() = %d, want 1400", got)
	}
	if got := recommendMTU(1500, 0, 250, 1280, 9000); got != 1280 {
		t.Fatalf("recommendMTU clamp = %d, want 1280", got)
	}
	if got := recommendMTU(0, 0, 0, 1280, 9000); got != 0 {
		t.Fatalf("recommendMTU empty = %d, want 0", got)
	}
}

func TestFormatCoreVersionJSON(t *testing.T) {
	raw := `{"name":"oboard-sb","version":"0.1.0-dev","build":"20260705225905","sing_box_version":"1.13.14","capabilities":["family_selector_v1","connection_presence_v1","family_selector_v1",""]}`
	got := formatCoreVersion(raw)
	want := "oboard-sb 0.1.0-dev / build 20260705225905 / sing-box 1.13.14"
	if got != want {
		t.Fatalf("formatCoreVersion() = %q, want %q", got, want)
	}
	capabilities := parseKernelCapabilities(raw)
	if len(capabilities) != 2 || capabilities[0] != "connection_presence_v1" || capabilities[1] != "family_selector_v1" {
		t.Fatalf("parseKernelCapabilities() = %v", capabilities)
	}
}

// TestCoreBinaryMustLiveInSystemDirectory pins that the root-executed kernel
// binary cannot be redirected into a user-writable directory. A matching base
// name alone is not enough: a local user who can create /tmp/oboard-sb would
// otherwise get root the next time the Agent starts the core.
func TestCoreBinaryMustLiveInSystemDirectory(t *testing.T) {
	for _, path := range []string{"/usr/local/bin/oboard-sb", "/usr/bin/sing-box", "/opt/oboard/oboard-sb"} {
		if err := validateManagedPath("core_binary", path); err != nil {
			t.Fatalf("legitimate core binary %q rejected: %v", path, err)
		}
	}
	for _, path := range []string{"/tmp/oboard-sb", "/home/user/oboard-sb", "/var/tmp/sing-box", "/dev/shm/oboard-sb"} {
		if err := validateManagedPath("core_binary", path); err == nil {
			t.Fatalf("writable-directory core binary %q was accepted", path)
		}
	}
	// The base-name constraint must still hold inside allowed directories.
	if err := validateManagedPath("core_binary", "/usr/local/bin/curl"); err == nil {
		t.Fatal("arbitrary system binary was accepted as the core binary")
	}
	if err := validateWarpCommand("/tmp/wgcf"); err == nil {
		t.Fatal("writable-directory warp command was accepted")
	}
	if err := validateWarpCommand("/usr/local/bin/wgcf"); err != nil {
		t.Fatalf("legitimate warp command rejected: %v", err)
	}
}

// TestControllerCannotGrantPanelUpdateConsent pins that allow_panel_update is
// owned by the host operator. A Controller may withdraw it but must not grant
// itself permission to install binaries it serves.
func TestControllerCannotGrantPanelUpdateConsent(t *testing.T) {
	dir := t.TempDir()
	runner := newTestRunner(t, Config{
		ConfigPath:       filepath.Join(dir, "agent.json"),
		StateDir:         filepath.Join(dir, "state"),
		AgentID:          "agent-1",
		AgentToken:       "token-1",
		ControllerURL:    "https://panel.example",
		UpdateSource:     "github",
		AllowPanelUpdate: false,
	})

	// A Controller asking to enable panel updates must be ignored.
	patch := Config{UpdateSource: "panel", AllowPanelUpdate: true}
	fields := map[string]json.RawMessage{"update_source": json.RawMessage(`"panel"`), "allow_panel_update": json.RawMessage(`true`)}
	if _, err := runner.updateAgentConfig(patch, fields); err != nil {
		t.Fatalf("config patch rejected: %v", err)
	}
	if runner.Config().AllowPanelUpdate {
		t.Fatal("Controller granted itself panel update consent")
	}

	// Withdrawing consent remains possible.
	granted := newTestRunner(t, Config{
		ConfigPath:       filepath.Join(dir, "agent2.json"),
		StateDir:         filepath.Join(dir, "state2"),
		AgentID:          "agent-2",
		AgentToken:       "token-2",
		ControllerURL:    "https://panel.example",
		UpdateSource:     "panel",
		AllowPanelUpdate: true,
	})
	revoke := Config{UpdateSource: "panel", AllowPanelUpdate: false}
	revokeFields := map[string]json.RawMessage{"update_source": json.RawMessage(`"panel"`), "allow_panel_update": json.RawMessage(`false`)}
	if _, err := granted.updateAgentConfig(revoke, revokeFields); err != nil {
		t.Fatalf("consent withdrawal rejected: %v", err)
	}
	if granted.Config().AllowPanelUpdate {
		t.Fatal("consent withdrawal was ignored")
	}
}

func TestCoreServiceChangeStopsPreviousManagedInstance(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	serviceLog := filepath.Join(dir, "services.log")
	rcService := filepath.Join(binDir, "rc-service")
	if err := os.WriteFile(rcService, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SERVICE_LOG\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("SERVICE_LOG", serviceLog)

	configPath := filepath.Join(dir, "agent.json")
	runner := New(Config{
		ConfigPath:      configPath,
		StateDir:        filepath.Join(dir, "state"),
		CoreBinary:      "/usr/bin/sing-box",
		CoreService:     "sing-box",
		RestartCommand:  "auto",
		ResourceProfile: "large",
	})
	patch := Config{CoreBinary: "/opt/oboard/oboard-sb", CoreService: "oboard-sb"}
	fields := map[string]json.RawMessage{
		"core_binary":  json.RawMessage(`"/opt/oboard/oboard-sb"`),
		"core_service": json.RawMessage(`"oboard-sb"`),
	}
	result, err := runner.updateAgentConfig(patch, fields)
	if err != nil {
		t.Fatal(err)
	}
	if stopped, _ := result["previous_service_stopped"].(bool); !stopped {
		t.Fatalf("previous service was not stopped: %#v", result)
	}
	commands, err := os.ReadFile(serviceLog)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(commands); got != "sing-box status\nsing-box stop\n" {
		t.Fatalf("managed service transition commands = %q", got)
	}
	stored, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CoreBinary != "/opt/oboard/oboard-sb" || stored.CoreService != "oboard-sb" {
		t.Fatalf("new core identity was not persisted: %#v", stored)
	}
}

func TestAgentProcessHelper(t *testing.T) {
	if os.Getenv("OBOARD_AGENT_PROCESS_HELPER") != "1" {
		return
	}
	serverID := int64(1)
	r := newTestRunner(t, Config{
		ControllerURL: os.Getenv("OBOARD_AGENT_PROCESS_CONTROLLER"), AgentID: "agent-process", AgentToken: os.Getenv("OBOARD_AGENT_PROCESS_TOKEN"),
		ServerID: serverID, StateDir: os.Getenv("OBOARD_AGENT_PROCESS_STATE"), TimeSyncCommand: "none", ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := r.connectTestControl(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestAgentSubprocessExecutesDeploymentAndReportsAppliedMetadata(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	token := "agent-process-token"
	stateDir := t.TempDir()
	config := `{"log":{"level":"warn"}}`
	if err := os.WriteFile(filepath.Join(stateDir, "sing-box.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := model.DeploymentTaskPayload{Version: 52, Config: model.ApplyCoreConfigTaskPayload{Config: config}, ConfigChanged: false, PortForwards: model.PortForwardPlan{Version: 52}, Tunnels: model.TunnelPlan{Version: 52}}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	task := model.AgentTask{ID: 101, ServerID: 1, Type: model.AgentTaskTypeApplyDeployment, PayloadJSON: string(payloadJSON), ConfigVersion: 52, Nonce: "process-deployment"}
	signature := security.SignTaskEnvelope(security.HashSecret(token), security.TaskEnvelope{ID: task.ID, ServerID: task.ServerID, Type: task.Type, ConfigVersion: task.ConfigVersion, Nonce: task.Nonce, PayloadJSON: task.PayloadJSON})
	resultCh := make(chan model.AgentTaskResultReport, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/agent/connect":
			conn, err := upgrader.Upgrade(w, req, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			var initial map[string]any
			if conn.ReadJSON(&initial) != nil {
				return
			}
			if conn.WriteJSON(map[string]any{"type": "hello", "server_id": task.ServerID}) != nil || conn.WriteJSON(map[string]any{"type": "task_request", "task": task, "signature_version": 2, "signature": signature}) != nil {
				return
			}
			var ack map[string]any
			_ = conn.ReadJSON(&ack)
		case "/api/v1/agent/task-results":
			var result model.AgentTaskResultReport
			if json.NewDecoder(req.Body).Decode(&result) == nil {
				resultCh <- result
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	command := exec.Command(os.Args[0], "-test.run=^TestAgentProcessHelper$", "-test.v")
	command.Env = append(os.Environ(), "OBOARD_AGENT_PROCESS_HELPER=1", "OBOARD_AGENT_PROCESS_CONTROLLER="+server.URL, "OBOARD_AGENT_PROCESS_TOKEN="+token, "OBOARD_AGENT_PROCESS_STATE="+stateDir, "OBOARD_DISABLE_PUBLIC_IP_DETECT=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}()
	select {
	case result := <-resultCh:
		if result.Status != "succeeded" || result.HealthReport == nil || result.HealthReport.AppliedConfigVersion != task.ConfigVersion || result.HealthReport.AppliedConfigDigest != appliedPayloadID(task.Type, payloadJSON) {
			t.Fatalf("subprocess convergence result = %#v", result)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Agent subprocess did not execute and report deployment")
	}
}

func TestConnectExecutesDeploymentAndReportsAppliedMetadata(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	token := "agent-token"
	stateDir := t.TempDir()
	config := `{"log":{"level":"warn"}}`
	if err := os.WriteFile(filepath.Join(stateDir, "sing-box.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := model.DeploymentTaskPayload{
		Version: 42, Config: model.ApplyCoreConfigTaskPayload{Config: config}, ConfigChanged: false,
		PortForwards: model.PortForwardPlan{Version: 42}, Tunnels: model.TunnelPlan{Version: 42},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	task := model.AgentTask{ID: 91, ServerID: 1, Type: model.AgentTaskTypeApplyDeployment, PayloadJSON: string(payloadJSON), ConfigVersion: 42, Nonce: "deployment-reconnect"}
	signature := security.SignTaskEnvelope(security.HashSecret(token), security.TaskEnvelope{ID: task.ID, ServerID: task.ServerID, Type: task.Type, ConfigVersion: task.ConfigVersion, Nonce: task.Nonce, PayloadJSON: task.PayloadJSON})
	resultCh := make(chan model.AgentTaskResultReport, 1)
	ackCh := make(chan bool, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/agent/connect":
			conn, err := upgrader.Upgrade(w, req, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			var initial map[string]any
			if conn.ReadJSON(&initial) != nil {
				return
			}
			if conn.WriteJSON(map[string]any{"type": "hello", "server_id": task.ServerID}) != nil || conn.WriteJSON(map[string]any{"type": "task_request", "task": task, "signature_version": 2, "signature": signature}) != nil {
				return
			}
			var ack map[string]any
			if conn.ReadJSON(&ack) == nil {
				ackCh <- ack["type"] == "task_ack" && ack["task_id"] == float64(task.ID)
			}
		case "/api/v1/agent/task-results":
			var result model.AgentTaskResultReport
			if err := json.NewDecoder(req.Body).Decode(&result); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			resultCh <- result
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	r := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "agent-1", AgentToken: token, ServerID: 1, StateDir: stateDir, TimeSyncCommand: "none", ReloadCommand: "none", RestartCommand: "none", ResourceProfile: "large"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connectDone := make(chan error, 1)
	go func() { connectDone <- r.connectTestControl(ctx) }()
	select {
	case result := <-resultCh:
		if result.TaskID != task.ID || result.Status != "succeeded" || result.HealthReport == nil {
			t.Fatalf("deployment result = %#v", result)
		}
		if result.HealthReport.AppliedConfigVersion != task.ConfigVersion || result.HealthReport.AppliedConfigDigest != appliedPayloadID(task.Type, payloadJSON) {
			t.Fatalf("applied metadata = version:%d digest:%q", result.HealthReport.AppliedConfigVersion, result.HealthReport.AppliedConfigDigest)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Agent did not execute and report deployment")
	}
	select {
	case ok := <-ackCh:
		if !ok {
			t.Fatal("Agent did not acknowledge the executed deployment")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not send task acknowledgement")
	}
	cancel()
	<-connectDone
}

func TestUpdateRepoAllowedAfterAccountRename(t *testing.T) {
	if !updateRepoAllowed("obrdx/oboard-agent") {
		t.Fatal("current repository rejected")
	}
	if !updateRepoAllowed("  OboardProject/oboard-agent  ") {
		t.Fatal("repository name from before the rename rejected")
	}
	if updateRepoAllowed("obrdx/other") || updateRepoAllowed("") {
		t.Fatal("unexpected repository allowed")
	}
}
