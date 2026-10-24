package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestControllerAndAgentProcessesConvergeOfflineSavedConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-repository process integration")
	}
	agentRepo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	controllerRepo := filepath.Clean(filepath.Join(agentRepo, "..", "oboard"))
	if _, err := os.Stat(filepath.Join(controllerRepo, "go.mod")); err != nil {
		t.Skip("sibling Controller repository is not available")
	}
	scope := t.TempDir()
	controllerBinary := filepath.Join(scope, "oboard-controller")
	agentBinary := filepath.Join(scope, "oboard-agent")
	buildEnv := append(os.Environ(), "GOCACHE="+filepath.Join(scope, "go-cache"), "GOTMPDIR="+filepath.Join(scope, "go-tmp"))
	if err := os.MkdirAll(filepath.Join(scope, "go-tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	buildProcessBinary(t, controllerRepo, controllerBinary, "./cmd/controller", buildEnv)
	buildProcessBinary(t, agentRepo, agentBinary, "./cmd/agent", buildEnv)

	port := processTestPort(t)
	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	staticDir := filepath.Join(scope, "static")
	if err := os.MkdirAll(staticDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("<div id=root></div>"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := exec.Command(controllerBinary,
		"-addr", "127.0.0.1:"+strconv.Itoa(port),
		"-db", filepath.Join(scope, "controller.sqlite"),
		"-static", staticDir,
		"-session-secret", "controller-agent-process-test-secret-32-chars",
		"-admin-password", "very-secure-password",
	)
	controller.Env = append(os.Environ(), "OBOARD_LOG_OUTPUT=stdout", "OBOARD_DISABLE_PUBLIC_IP_DETECT=1")
	if err := controller.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopProcess(controller) })
	waitProcessCondition(t, 20*time.Second, func() bool {
		response, err := http.Get(baseURL + "/healthz") // #nosec G107 -- loopback integration endpoint.
		if err != nil {
			return false
		}
		_ = response.Body.Close()
		return response.StatusCode == http.StatusOK
	})

	login := processJSONRequest(t, baseURL, http.MethodPost, "/api/v1/ui/auth/login", "", map[string]any{"username": "admin", "password": "very-secure-password"}, http.StatusOK)
	token, _ := login["token"].(string)
	if token == "" {
		t.Fatal("Controller login did not return a token")
	}
	// Enrollment command generation requires the public controller address.
	processJSONRequest(t, baseURL, http.MethodPost, "/api/v1/ui/settings", token, map[string]any{"controller_url": baseURL}, http.StatusOK)
	linkAddress := "127.0.0.1:" + strconv.Itoa(processTestPort(t))
	processJSONRequest(t, baseURL, http.MethodPost, "/api/v1/ui/settings", token, map[string]any{"stealth_transport": map[string]any{"enabled": true, "listen_address": linkAddress, "public_address": linkAddress}}, http.StatusOK)
	created := processJSONRequest(t, baseURL, http.MethodPost, "/api/v1/ui/servers", token, map[string]any{
		"name": "process-node", "renewal_cycle": "monthly", "listen_ip": "0.0.0.0", "entry_ip_mode": "custom", "entry_address": "198.51.100.20", "public_ipv4": "198.51.100.20", "port_range_start": 10000, "port_range_end": 11000,
	}, http.StatusCreated)
	serverID := int64(created["server"].(map[string]any)["id"].(float64))
	enroll := processJSONRequest(t, baseURL, http.MethodPost, "/api/v1/ui/servers/"+strconv.FormatInt(serverID, 10)+"/enroll-token", token, map[string]any{}, http.StatusOK)
	enrollmentToken, _ := enroll["enrollment_token"].(string)
	if enrollmentToken == "" {
		t.Fatal("Controller did not return an enrollment token")
	}

	fakeCore := filepath.Join(scope, "oboard-sb")
	fakeCoreScript := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'oboard-sb test'; fi\nexit 0\n"
	if runtime.GOOS == "windows" {
		t.Skip("process integration fake core requires POSIX shell")
	}
	if err := os.WriteFile(fakeCore, []byte(fakeCoreScript), 0o700); err != nil {
		t.Fatal(err)
	}
	agentState := filepath.Join(scope, "agent-state")
	agentConfig := filepath.Join(scope, "agent.json")
	// Recreate the installed old Agent state, then start the new binary without transport fields.
	legacy := processJSONRequest(t, baseURL, http.MethodPost, "/api/v1/agent/enroll", "", map[string]any{"enrollment_token": enrollmentToken, "health": map[string]any{"os": "linux", "arch": runtime.GOARCH}}, http.StatusOK)
	oldConfig := map[string]any{"controller_url": baseURL, "server_id": serverID, "agent_id": legacy["agent_id"], "agent_token": legacy["agent_token"], "state_dir": agentState, "allow_insecure_controller": true}
	previousBytes, _ := json.Marshal(oldConfig)
	if err := os.WriteFile(agentConfig, previousBytes, 0600); err != nil {
		t.Fatal(err)
	}
	agentProcess := exec.Command(agentBinary,
		"-controller", baseURL, "-config", agentConfig, "-state-dir", agentState,
		"-reload-command", "none", "-restart-command", "none",
		"-time-sync-command", "none", "-resource-profile", "large",
	)
	agentProcess.Env = append(os.Environ(), "OBOARD_DISABLE_PUBLIC_IP_DETECT=1", "PATH="+scope+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := agentProcess.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopProcess(agentProcess) })
	waitProcessCondition(t, 20*time.Second, func() bool {
		migrated, err := LoadConfig(agentConfig)
		if err != nil || migrated.ControllerAddr != linkAddress || len(migrated.ControllerCertSHA256) != 64 {
			return false
		}
		servers := processJSONRequestOptional(baseURL, http.MethodGet, "/api/v1/ui/servers", token, nil)
		for _, raw := range processArray(servers["servers"]) {
			server, _ := raw.(map[string]any)
			if int64(processNumber(server["id"])) == serverID && server["status"] == "online" {
				return true
			}
		}
		return false
	})

	migrated, err := LoadConfig(agentConfig)
	if err != nil || migrated.ControllerAddr != linkAddress || len(migrated.ControllerCertSHA256) != 64 {
		t.Fatalf("real Agent did not persist automatic transition: %v", err)
	}

	// Save while the Agent is offline, then restart the enrolled Agent. The
	// durable desired revision must survive the disconnect and converge after
	// the real Agent process reconnects.
	stopProcess(agentProcess)
	processJSONRequest(t, baseURL, http.MethodPost, "/api/v1/ui/inbounds", token, map[string]any{
		"server_id": serverID, "name": "process-entry", "protocol": "vless", "listen_ip": "0.0.0.0", "port": 10443, "config_json": "{}", "enabled": true,
	}, http.StatusCreated)
	agentProcess = exec.Command(agentBinary,
		"-config", agentConfig, "-state-dir", agentState,
		"-reload-command", "none", "-restart-command", "none", "-time-sync-command", "none", "-resource-profile", "large",
	)
	agentProcess.Env = append(os.Environ(), "OBOARD_DISABLE_PUBLIC_IP_DETECT=1", "PATH="+scope+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := agentProcess.Start(); err != nil {
		t.Fatal(err)
	}

	waitProcessCondition(t, 30*time.Second, func() bool {
		response := processJSONRequestOptional(baseURL, http.MethodGet, "/api/v1/ui/configuration-sync", token, nil)
		for _, raw := range processArray(response["configuration_sync"]) {
			state, _ := raw.(map[string]any)
			if int64(processNumber(state["server_id"])) == serverID && state["state"] == "synced" && processNumber(state["config_version"]) > 0 {
				return true
			}
		}
		return false
	})
	if _, err := os.Stat(filepath.Join(agentState, appliedVersionStateFile)); err != nil {
		t.Fatalf("Agent did not persist applied convergence state: %v", err)
	}
}

func buildProcessBinary(t *testing.T, repo, output, pkg string, env []string) {
	t.Helper()
	command := exec.Command("go", "build", "-o", output, pkg)
	command.Dir, command.Env = repo, env
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, result)
	}
}

func processTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func processJSONRequest(t *testing.T, baseURL, method, path, token string, body any, want int) map[string]any {
	t.Helper()
	response, status, err := processJSON(baseURL, method, path, token, body)
	if err != nil {
		t.Fatal(err)
	}
	if status != want {
		t.Fatalf("%s %s status=%d want=%d body=%#v", method, path, status, want, response)
	}
	return response
}

func processJSONRequestOptional(baseURL, method, path, token string, body any) map[string]any {
	response, _, _ := processJSON(baseURL, method, path, token, body)
	return response
}

func processJSON(baseURL, method, path, token string, body any) (map[string]any, int, error) {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	result := map[string]any{}
	_ = json.NewDecoder(response.Body).Decode(&result)
	return result, response.StatusCode, nil
}

func waitProcessCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func stopProcess(command *exec.Cmd) {
	if command == nil || command.Process == nil || command.ProcessState != nil {
		return
	}
	_ = command.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		<-done
	}
}

func processArray(value any) []any {
	items, _ := value.([]any)
	return items
}

func processNumber(value any) float64 {
	number, _ := value.(float64)
	return number
}
