package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

// Only the Controller is a controlled peer: Agent connect/apply and the kernel
// run in separate real processes. This is not a three-binary Controller E2E test.
func TestDeliveryFaultHelper(t *testing.T) {
	if os.Getenv("OBOARD_DELIVERY_HELPER") != "1" {
		return
	}
	state := os.Getenv("OBOARD_DELIVERY_STATE")
	r := newTestRunner(t, Config{ControllerURL: os.Getenv("OBOARD_DELIVERY_CONTROLLER"), AgentID: "delivery-agent", AgentToken: "synthetic-delivery-token", ServerID: 1, StateDir: state, CoreBinary: os.Getenv("OBOARD_PROCESS_KERNEL"), CoreSocket: filepath.Join(state, "k.sock"), ResourceProfile: "large", RestartCommand: "none", ReloadCommand: "none", TimeSyncCommand: "none"})
	r.coreRestartCommand = func() error {
		c := &http.Client{Timeout: 10 * time.Second}
		resp, err := c.Post(os.Getenv("OBOARD_DELIVERY_SUPERVISOR"), "application/json", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("supervisor rejected restart")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		_ = r.connectTestControl(ctx)
	}
}

type deliveryRig struct {
	state, binary, config string
	port                  int
	supervisor            *httptest.Server
}

func newDeliveryRig(t *testing.T, authorized bool) *deliveryRig {
	t.Helper()
	binary := os.Getenv("OBOARD_PROCESS_KERNEL")
	if binary == "" {
		t.Skip("opt-in: real kernel required")
	}
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("existing kernel_sha256=%x; no rebuild or source-provenance assertion", sha256.Sum256(binaryBytes))
	state, err := os.MkdirTemp("", "df-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	if len(filepath.Join(state, "k.sock")) >= 104 {
		t.Fatal("set TMPDIR to a short task-owned directory")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"socks","tag":"in-test","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}]}`, port)
	if authorized {
		lease := deliveryLease(1, false)
		raw, _ := json.Marshal(lease)
		cfg = fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"socks","tag":"in-test","listen":"127.0.0.1","listen_port":%d,"users":[{"username":"test-user","password":"synthetic-password"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"_oboard":{"authorization":%s,"rate_limits":{"users":{"test-user":{"user_id":1,"authorization_key":"test-key"}}}}}`, port, raw)
	}
	if err := os.WriteFile(filepath.Join(state, "sing-box.json"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	k := &faultKernel{binary: binary, state: state}
	t.Cleanup(func() { k.mu.Lock(); defer k.mu.Unlock(); k.stop() })
	supervisor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if k.restart() != nil {
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(supervisor.Close)
	if err := k.restart(); err != nil {
		t.Fatal(err)
	}
	return &deliveryRig{state: state, binary: binary, config: cfg, port: port, supervisor: supervisor}
}
func (r *deliveryRig) start(t *testing.T, url string) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeliveryFaultHelper$")
	cmd.Env = append(os.Environ(), "OBOARD_DELIVERY_HELPER=1", "OBOARD_DELIVERY_CONTROLLER="+url, "OBOARD_DELIVERY_STATE="+r.state, "OBOARD_DELIVERY_SUPERVISOR="+r.supervisor.URL, "OBOARD_DISABLE_PUBLIC_IP_DETECT=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(stop)
	return stop
}
func (r *deliveryRig) runtime(t *testing.T) int {
	t.Helper()
	runner := New(Config{StateDir: r.state, CoreBinary: r.binary, CoreSocket: filepath.Join(r.state, "k.sock"), ResourceProfile: "large"})
	check := runner.checkCoreRuntimeConfig(context.Background(), []byte(r.config))
	if !check.verified() || check.drift() || check.PID <= 0 {
		t.Fatal("real runtime failed convergence verification")
	}
	return check.PID
}
func deliveryReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(15 * time.Second):
		t.Fatal("delivery barrier timeout")
		var zero T
		return zero
	}
}
func deliveryHello(w http.ResponseWriter, req *http.Request) *websocket.Conn {
	conn, err := (&websocket.Upgrader{}).Upgrade(w, req, nil)
	if err != nil {
		return nil
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var hello map[string]any
	if conn.ReadJSON(&hello) != nil || conn.WriteJSON(map[string]any{"type": "hello", "server_id": 1}) != nil {
		conn.Close()
		return nil
	}
	return conn
}
func (r *deliveryRig) proveHTTP(t *testing.T) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "delivery-proof") }))
	defer target.Close()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", r.port), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Dial: dialer.Dial}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "delivery-proof" {
		t.Fatal("data plane proof failed")
	}
}

func TestRealAgentHTTPResultLoss(t *testing.T) {
	rig := newDeliveryRig(t, false)
	beforePID := rig.runtime(t)
	rig.config = strings.Replace(rig.config, `"tag":"direct"`, `"tag":"direct-next"`, 1)
	payload, _ := json.Marshal(model.ApplyCoreConfigTaskPayload{Config: rig.config})
	task := model.AgentTask{ID: 701, ServerID: 1, Type: model.AgentTaskTypeApplyCoreConfig, ConfigVersion: 71, Nonce: "delivery-result-loss", PayloadJSON: string(payload)}
	signature := security.SignTaskEnvelope(security.HashSecret("synthetic-delivery-token"), security.TaskEnvelope{ID: task.ID, ServerID: 1, Type: task.Type, ConfigVersion: 71, Nonce: task.Nonce, PayloadJSON: task.PayloadJSON})
	var originalPID int
	for attempt := 0; attempt < 2; attempt++ {
		reports := make(chan model.AgentTaskResultReport, 8)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case "/api/v1/agent/connect":
				conn := deliveryHello(w, req)
				if conn == nil {
					return
				}
				defer conn.Close()
				if conn.WriteJSON(map[string]any{"type": "task_request", "task": task, "signature_version": 2, "signature": signature}) != nil {
					return
				}
				for {
					var message map[string]any
					if conn.ReadJSON(&message) != nil {
						return
					}
				}
			case "/api/v1/agent/task-results":
				var report model.AgentTaskResultReport
				if json.NewDecoder(req.Body).Decode(&report) != nil {
					w.WriteHeader(400)
					return
				}
				if attempt == 0 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}
					conn.Close() // full body received, no HTTP ACK
				} else {
					json.NewEncoder(w).Encode(map[string]any{"ok": true})
				}
				select {
				case reports <- report:
				default:
				}
			default:
				http.NotFound(w, req)
			}
		}))
		t.Cleanup(server.Close)
		stop := rig.start(t, server.URL)
		report := deliveryReceive(t, reports)
		if report.Status != "succeeded" {
			stop()
			server.Close()
			t.Fatal("configuration delivery not successful")
		}
		pid := rig.runtime(t)
		rig.proveHTTP(t)
		stop()
		server.Close()
		if attempt == 0 {
			if pid == beforePID {
				t.Fatal("changed operational configuration did not restart the real kernel")
			}
			originalPID = pid
		} else if pid != originalPID {
			t.Fatal("replayed configuration restarted the real kernel")
		}
	}
}

func deliveryLease(revision int64, deny bool) model.AuthorizationLease {
	now := time.Now().UTC()
	end := now.Add(3 * time.Minute).Format(time.RFC3339Nano)
	lease := model.AuthorizationLease{Revision: revision, Sequence: 1, Digest: fmt.Sprintf("delivery-%d", revision), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: end, Grants: map[string]string{"test-key": end}}
	if deny {
		lease.Grants = map[string]string{}
		lease.Denied = []string{"test-key"}
	}
	return lease
}

func TestRealAgentAuthorizationReconnect(t *testing.T) {
	rig := newDeliveryRig(t, true)
	originalPID := rig.runtime(t)
	peers := make(chan *websocket.Conn, 4)
	acks := make(chan model.AuthorizationAck, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/agent/connect" {
			http.NotFound(w, req)
			return
		}
		conn := deliveryHello(w, req)
		if conn == nil {
			return
		}
		defer conn.Close()
		peers <- conn
		for {
			var message json.RawMessage
			if conn.ReadJSON(&message) != nil {
				return
			}
			var ack model.AuthorizationAck
			if json.Unmarshal(message, &ack) == nil && ack.MessageID != "" {
				acks <- ack
			}
		}
	}))
	defer server.Close()
	stop := rig.start(t, server.URL)
	defer stop()
	peer := deliveryReceive(t, peers)
	grant := deliveryLease(2, false)
	if err := peer.WriteJSON(signedTestEnvelope(t, "synthetic-delivery-token", 1, "grant", grant)); err != nil {
		t.Fatal(err)
	}
	if ack := deliveryReceive(t, acks); !ack.Confirmed || ack.Revision != 2 {
		t.Fatal("initial grant not confirmed")
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	echoed := make(chan struct{})
	go func() {
		defer close(echoed)
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.Copy(c, c)
	}()
	defer func() { target.Close(); <-echoed }()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", rig.port), &proxy.Auth{User: "test-user", Password: "synthetic-password"}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", target.Addr().String())
	}
	echo := func(c net.Conn) error {
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("proof")); err != nil {
			return err
		}
		b := make([]byte, 5)
		_, err := io.ReadFull(c, b)
		if err == nil && string(b) != "proof" {
			return fmt.Errorf("wrong echo")
		}
		return err
	}
	live, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := echo(live); err != nil {
		t.Fatal(err)
	}
	// Disconnect only after the signed grant ACK and an actual payload roundtrip.
	peer.Close()
	peer = deliveryReceive(t, peers)
	if err := peer.WriteJSON(signedTestEnvelope(t, "synthetic-delivery-token", 1, "revoke", deliveryLease(3, true))); err != nil {
		t.Fatal(err)
	}
	if ack := deliveryReceive(t, acks); !ack.Confirmed || ack.Revision != 3 {
		t.Fatal("reconnected revoke not confirmed")
	}
	if echo(live) == nil {
		t.Fatal("revoke preserved established data plane")
	}
	denied := func() {
		t.Helper()
		c, err := dial()
		if err == nil {
			c.Close()
			t.Fatal("revoked SOCKS connection accepted")
		}
	}
	denied()
	peer.Close()
	peer = deliveryReceive(t, peers)
	if err := peer.WriteJSON(signedTestEnvelope(t, "synthetic-delivery-token", 1, "stale", grant)); err != nil {
		t.Fatal(err)
	}
	if ack := deliveryReceive(t, acks); !ack.Confirmed || ack.Revision != 3 {
		t.Fatal("stale grant replaced revoke after reconnect")
	}
	denied()
	if rig.runtime(t) != originalPID {
		t.Fatal("authorization reconnect restarted the real kernel")
	}
}
