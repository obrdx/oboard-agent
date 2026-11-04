package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func diagnosticRunner(t *testing.T, pluginsAllowed bool) *Runner {
	t.Helper()
	dir := t.TempDir()
	policy := `{"version":1,"mode":"standard","deny":{"plugins_enabled":true}}`
	if pluginsAllowed {
		policy = `{"version":1,"mode":"standard"}`
	}
	if err := os.WriteFile(filepath.Join(dir, "local-security.json"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(Config{ConfigPath: filepath.Join(dir, "config.json"), StateDir: dir, CommandTimeoutSeconds: 20, ResourceProfile: "small", TimeCorrectionMode: "off", LogMaxMB: 8, CoreLogMaxMB: 8})
}

func dnsTask(t *testing.T, mutate func(*model.NetworkDNSLookupTaskPayload)) model.AgentTask {
	t.Helper()
	payload := model.NetworkDNSLookupTaskPayload{
		NetworkDiagnosticEnvelope: model.NetworkDiagnosticEnvelope{ProtocolVersion: 1, OperationID: "op-1", Origin: model.NetworkDiagnosticOriginPlugin, RunID: "run-1", PluginID: "acme.demo", InstanceID: 1, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC()},
		Name:                      "router.lan",
		RecordTypes:               []string{"A"},
		TimeoutMS:                 1000,
	}
	if mutate != nil {
		mutate(&payload)
	}
	raw, _ := json.Marshal(payload)
	return model.AgentTask{Type: model.AgentTaskTypeNetworkDNS, PayloadJSON: string(raw)}
}

func diagnosticCode(t *testing.T, status, raw string) string {
	t.Helper()
	if status != "failed" {
		t.Fatalf("expected a failed diagnostic, got %s %s", status, raw)
	}
	var result struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatal(err)
	}
	return result.Code
}

func TestNetworkDiagnosticEnvelopeIsCheckedBeforeAnyProbe(t *testing.T) {
	allowed := diagnosticRunner(t, true)
	cases := []struct {
		name   string
		runner *Runner
		task   model.AgentTask
		code   string
	}{
		{"local gate", diagnosticRunner(t, false), dnsTask(t, nil), model.NetworkDiagnosticCodeLocalGateDenied},
		{"protocol", allowed, dnsTask(t, func(p *model.NetworkDNSLookupTaskPayload) { p.ProtocolVersion = 2 }), model.NetworkDiagnosticCodeUnsupported},
		{"origin", allowed, dnsTask(t, func(p *model.NetworkDNSLookupTaskPayload) { p.Origin = "mcp" }), model.NetworkDiagnosticCodeInvalidInput},
		{"expired", allowed, dnsTask(t, func(p *model.NetworkDNSLookupTaskPayload) { p.ExpiresAt = time.Now().Add(-time.Second) }), model.NetworkDiagnosticCodeExpired},
		{"operation id", allowed, dnsTask(t, func(p *model.NetworkDNSLookupTaskPayload) { p.OperationID = "" }), model.NetworkDiagnosticCodeInvalidInput},
		{"unknown field", allowed, model.AgentTask{Type: model.AgentTaskTypeNetworkDNS, PayloadJSON: `{"protocol_version":1,"command":"ping 10.0.0.1"}`}, model.NetworkDiagnosticCodeInvalidInput},
		{"trailing data", allowed, model.AgentTask{Type: model.AgentTaskTypeNetworkDNS, PayloadJSON: dnsTask(t, nil).PayloadJSON + `{}`}, model.NetworkDiagnosticCodeInvalidInput},
		{"internal name", allowed, dnsTask(t, nil), model.NetworkDiagnosticCodeInvalidInput},
	}
	for _, tc := range cases {
		status, raw := tc.runner.executeNetworkDiagnosticTask(tc.task)
		if code := diagnosticCode(t, status, raw); code != tc.code {
			t.Fatalf("%s: code %s, want %s (%s)", tc.name, code, tc.code, raw)
		}
	}
}

func TestNetworkDiagnosticTasksAreRecognised(t *testing.T) {
	for _, taskType := range []string{model.AgentTaskTypeNetworkPing, model.AgentTaskTypeNetworkTrace, model.AgentTaskTypeNetworkTCP, model.AgentTaskTypeNetworkDNS, model.AgentTaskTypeNetworkHTTP} {
		if !isNetworkDiagnosticTask(taskType) {
			t.Fatalf("%s must be a diagnostic task", taskType)
		}
	}
	for _, taskType := range []string{"remote_exec", "remote_operation", "host_power_action", "probe_inbounds"} {
		if isNetworkDiagnosticTask(taskType) {
			t.Fatalf("%s must not be a diagnostic task", taskType)
		}
	}
}

func TestNetworkDiagnosticCapabilitiesMatchThePlatform(t *testing.T) {
	advertised := map[string]bool{}
	for _, capability := range networkDiagnosticCapabilities() {
		advertised[capability] = true
	}
	for _, required := range []string{model.AgentCapabilityNetworkDiagnostics, model.AgentCapabilityNetworkTCPProbe, model.AgentCapabilityNetworkDNSLookup, model.AgentCapabilityNetworkHTTPProbe} {
		if !advertised[required] {
			t.Fatalf("%s must be advertised on every platform", required)
		}
	}
	rawSocket := []string{model.AgentCapabilityNetworkPing, model.AgentCapabilityNetworkTraceICMP, model.AgentCapabilityNetworkTraceUDP, model.AgentCapabilityNetworkTraceTCP}
	for _, capability := range rawSocket {
		if advertised[capability] != (runtime.GOOS == "linux") {
			t.Fatalf("%s advertised=%v on %s", capability, advertised[capability], runtime.GOOS)
		}
	}
}

func TestLANRequestRequiresPluginOriginAndLocalLANGate(t *testing.T) {
	task := func(origin string) model.AgentTask {
		payload := model.LANRequestTaskPayload{
			NetworkDiagnosticEnvelope: model.NetworkDiagnosticEnvelope{ProtocolVersion: 1, OperationID: "op-1", Origin: origin, RunID: "run-1", PluginID: "acme.demo", InstanceID: 1, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC()},
			TargetID:                  "router", Scheme: "http", Address: "10.10.18.1", Port: 5000, PathPrefix: "/", Method: "GET", Path: "/", TimeoutMS: 1000,
		}
		if origin == model.NetworkDiagnosticOriginMonitor {
			payload.RunID, payload.PluginID, payload.InstanceID = "", "", 0
		}
		raw, _ := json.Marshal(payload)
		return model.AgentTask{Type: model.AgentTaskTypeLANRequest, PayloadJSON: string(raw)}
	}
	run := func(r *Runner, origin string) string {
		status, raw := r.executeNetworkDiagnosticTask(task(origin))
		return diagnosticCode(t, status, raw)
	}
	allowed := diagnosticRunner(t, true)
	if code := run(allowed, model.NetworkDiagnosticOriginPlugin); code != model.NetworkDiagnosticCodeLANDisabled {
		t.Fatalf("standard mode without allow lan must refuse, got %s", code)
	}
	if code := run(allowed, model.NetworkDiagnosticOriginMonitor); code != model.NetworkDiagnosticCodeInvalidInput {
		t.Fatalf("monitor origin must be refused, got %s", code)
	}
	if code := run(diagnosticRunner(t, false), model.NetworkDiagnosticOriginPlugin); code != model.NetworkDiagnosticCodeLocalGateDenied {
		t.Fatalf("plugins gate must be checked first, got %s", code)
	}
}
