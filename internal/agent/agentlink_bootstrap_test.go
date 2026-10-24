package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/agentlink"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

func TestAgentLinkUpgradesPreviousStandardConfig(t *testing.T) {
	for _, broken := range []string{"", "signature", "nonce", "identity", "save", "unreachable"} {
		t.Run(broken, func(t *testing.T) {
			addr, pin := agentLinkFixture(t, func(conn net.Conn) {
				_, _, err := readAgentLinkFixture(conn)
				if err == nil {
					_ = writeAgentLinkFixture(conn, 3, nil)
				}
			})
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if req.URL.Path != "/prefix/api/v1/agent/transport" || req.Header.Get("Authorization") != "Bearer old-token" || req.Header.Get("X-Agent-ID") != "old-agent" {
					t.Errorf("invalid upgrade request")
				}
				b := agentlink.Bootstrap{ServerID: 7, AgentID: "old-agent", Address: addr, CertSHA256: pin, Nonce: req.Header.Get("X-Oboard-Transport-Nonce")}
				if broken == "unreachable" {
					b.Address = "127.0.0.1:1"
				}
				if broken == "identity" {
					b.ServerID++
				}
				if broken == "nonce" {
					b.Nonce = strings.Repeat("0", 64)
				}
				b.Signature = b.Sign(security.HashSecret("old-token"))
				if broken == "signature" {
					b.Signature = strings.Repeat("0", 64)
				}
				_ = json.NewEncoder(w).Encode(b)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "agent.json")
			// This is the real pre-transition shape: there is no transport address or pin.
			previous := map[string]any{"controller_url": server.URL + "/prefix", "server_id": 7, "agent_id": "old-agent", "agent_token": "old-token", "state_dir": t.TempDir()}
			raw, _ := json.Marshal(previous)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg.ConfigPath = path
			runner := New(cfg)
			runner.client = server.Client()
			if broken == "save" {
				runnerCfg := runner.Config()
				runnerCfg.ConfigPath = filepath.Join(path, "invalid")
				runner.storeConfig(runnerCfg)
			}
			err = runner.ensureAgentLink(context.Background())
			if broken != "" {
				if err == nil || runner.Config().ControllerAddr != "" {
					t.Fatalf("invalid bootstrap committed: %v", err)
				}
				stored, _ := os.ReadFile(path)
				if string(stored) != string(raw) {
					t.Fatal("failed bootstrap changed previous config")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			stored, err := LoadConfig(path)
			if err != nil || stored.ControllerAddr != addr || stored.AgentToken != "old-token" || stored.ControllerCertSHA256 != pin {
				t.Fatalf("bad persisted upgrade: %v", err)
			}
			if err := runner.ensureAgentLink(context.Background()); err != nil || calls.Load() != 1 {
				t.Fatalf("upgrade is not idempotent: %v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestAgentLinkPreservesPreviousEncryptedTransport(t *testing.T) {
	cfg := normalizeConfig(Config{Stealth: &stealth.Settings{ControllerAddr: "old.example.com:24443", ControllerCertSHA256: strings.Repeat("b", 64)}})
	if cfg.ControllerAddr != "old.example.com:24443" || cfg.ControllerCertSHA256 != strings.Repeat("b", 64) {
		t.Fatal("old pin lost")
	}
	cfg.ControllerAddr = "new.example.com:24443"
	cfg.ControllerCertSHA256 = strings.Repeat("c", 64)
	cfg = normalizeConfig(cfg)
	if cfg.ControllerAddr != "new.example.com:24443" || cfg.ControllerCertSHA256 != strings.Repeat("c", 64) {
		t.Fatal("old transport replaced explicit config")
	}
}

func agentLinkFixture(t *testing.T, handle func(net.Conn)) (string, string) {
	t.Helper()
	source := httptest.NewTLSServer(http.NotFoundHandler())
	cert := source.TLS.Certificates[0]
	sum := sha256.Sum256(source.Certificate().Raw)
	source.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String(), hex.EncodeToString(sum[:])
}

func readAgentLinkFixture(conn net.Conn) (byte, []byte, error) {
	var header [6]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(header[2:])
	if n > 16<<20 {
		return 0, nil, io.ErrShortBuffer
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(conn, data); err != nil {
		return 0, nil, err
	}
	if header[1]&2 != 0 {
		if len(data) < 2 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		pad := int(binary.BigEndian.Uint16(data[:2]))
		if 2+pad > len(data) {
			return 0, nil, io.ErrUnexpectedEOF
		}
		data = data[2+pad:]
	}
	return header[0], data, nil
}
func writeAgentLinkFixture(conn net.Conn, kind byte, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var header [6]byte
	header[0], header[1] = kind, 1
	binary.BigEndian.PutUint32(header[2:], uint32(len(data)))
	_, err = conn.Write(append(header[:], data...))
	return err
}

func TestAgentLinkStandardCallbackAndControl(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	requests := make(chan agentlink.RequestFrame, 1)
	controls := make(chan agentlink.AuthRequest, 1)
	addr, pin := agentLinkFixture(t, func(conn net.Conn) {
		_, data, err := readAgentLinkFixture(conn)
		if err != nil {
			return
		}
		var auth agentlink.AuthRequest
		_ = json.Unmarshal(data, &auth)
		if auth.AgentID != "agent-7" || auth.Token != "token-7" {
			t.Error("identity missing")
			return
		}
		if err := writeAgentLinkFixture(conn, 3, nil); err != nil {
			return
		}
		if auth.Purpose == "rpc" {
			_, data, err = readAgentLinkFixture(conn)
			if err != nil {
				return
			}
			var req agentlink.RequestFrame
			_ = json.Unmarshal(data, &req)
			requests <- req
			_ = writeAgentLinkFixture(conn, 6, agentlink.ResponseFrame{ID: req.ID, Status: 200, Body: json.RawMessage("{}")})
			return
		}
		controls <- auth
		_ = writeAgentLinkFixture(conn, 1, map[string]any{"type": "hello", "server_id": 7})
		_, _, _ = readAgentLinkFixture(conn)
	})
	runner := New(Config{ServerID: 7, AgentID: "agent-7", AgentToken: "token-7", ControllerAddr: addr, ControllerCertSHA256: pin, StateDir: t.TempDir()})
	headers := http.Header{"X-Oboard-Users-Revision": []string{"17"}}
	if err := runner.controllerJSON(context.Background(), http.MethodGet, "/api/v1/agent/users-snapshot", headers, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	req := <-requests
	if req.Path != "/api/v1/agent/users-snapshot" || req.Headers["X-Oboard-Users-Revision"][0] != "17" {
		t.Fatal("callback confirmation header lost")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = runner.connect(ctx)
	select {
	case <-controls:
	case <-time.After(time.Second):
		t.Fatal("standard mode did not use AgentLink")
	}
}

func TestAgentLinkRejectsMissingConfigWithoutHTTPFallback(t *testing.T) {
	var calls atomic.Int32
	httpServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer httpServer.Close()
	runner := New(Config{ControllerURL: httpServer.URL, StateDir: t.TempDir(), AgentID: "a", AgentToken: "t"})
	if err := runner.connect(context.Background()); err == nil {
		t.Fatal("accepted missing pin")
	}
	if err := runner.postControllerJSON(context.Background(), "/api/v1/agent/task-results", nil, nil, true); err == nil {
		t.Fatal("callback used HTTP")
	}
	if calls.Load() != 0 {
		t.Fatal("fell back to HTTP")
	}
}

func TestAgentLinkLoadsPreviousEncryptedConfig(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	path := filepath.Join(t.TempDir(), "encrypted-config")
	previous := map[string]any{"server_id": 7, "agent_id": "old-agent", "agent_token": "old-token", "stealth": map[string]any{"controller_addr": "old.example.com:24443", "controller_cert_sha256": strings.Repeat("b", 64)}}
	raw, _ := json.Marshal(previous)
	encrypted, err := stealth.Encrypt(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigWithKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConfigPath = path
	runner := New(cfg)
	if err := runner.ensureAgentLink(context.Background()); err != nil {
		t.Fatal(err)
	}

	saved, err := os.ReadFile(path)
	if err != nil || !stealth.IsEncrypted(saved) {
		t.Fatal("upgrade downgraded encrypted configuration")
	}
	reloaded, err := LoadConfigWithKey(path, key)
	if err != nil || reloaded.ControllerAddr != "old.example.com:24443" || reloaded.ControllerCertSHA256 != strings.Repeat("b", 64) || reloaded.AgentToken != "old-token" {
		t.Fatalf("previous encrypted identity or pin changed: %v", err)
	}
}

func TestAgentLinkCallbackErrorsOmitResponseBody(t *testing.T) {
	addr, pin := agentLinkFixture(t, func(conn net.Conn) {
		_, _, err := readAgentLinkFixture(conn)
		if err != nil {
			return
		}
		_ = writeAgentLinkFixture(conn, 3, nil)
		_, data, err := readAgentLinkFixture(conn)
		if err != nil {
			return
		}
		var req agentlink.RequestFrame
		_ = json.Unmarshal(data, &req)
		raw, _ := json.Marshal(map[string]any{"error": "private-response-token"})
		_ = writeAgentLinkFixture(conn, 6, agentlink.ResponseFrame{ID: req.ID, Status: 500, Body: raw, Error: "private-response-token"})
	})
	runner := New(Config{ControllerAddr: addr, ControllerCertSHA256: pin, AgentID: "a", AgentToken: "t", StateDir: t.TempDir()})
	err := runner.postControllerJSON(context.Background(), "/api/v1/agent/task-results", nil, nil, true)
	if err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "private-response-token") {
		t.Fatalf("unsafe callback error: %v", err)
	}
}

func TestAgentLinkAuthenticationRejectionPausesCallbacks(t *testing.T) {
	var calls atomic.Int32
	addr, pin := agentLinkFixture(t, func(conn net.Conn) {
		_, _, err := readAgentLinkFixture(conn)
		if err != nil {
			return
		}
		calls.Add(1)
		_ = writeAgentLinkFixture(conn, 4, "invalid agent credentials")
	})
	runner := New(Config{ControllerAddr: addr, ControllerCertSHA256: pin, AgentID: "a", AgentToken: "t", StateDir: t.TempDir()})
	if err := runner.postControllerJSON(context.Background(), "/api/v1/agent/task-results", nil, nil, true); err == nil {
		t.Fatal("rejected identity accepted")
	}
	if runner.controllerAuth.remaining(time.Now()) <= 0 {
		t.Fatal("AgentLink rejection did not pause callbacks")
	}
	_ = runner.postControllerJSON(context.Background(), "/api/v1/agent/task-results", nil, nil, true)
	if calls.Load() != 1 {
		t.Fatal("rejected identity redialed while paused")
	}
}
