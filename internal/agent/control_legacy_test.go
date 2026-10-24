package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/OboardProject/oboard-agent/internal/agentlink"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The session regression suite can exercise the transport-neutral loop using WebSocket fixtures.
// wsControlConn adapts the gorilla connection.
type wsControlConn struct {
	conn *websocket.Conn
}

func (c wsControlConn) Close() error       { return c.conn.Close() }
func (c wsControlConn) RemoteAddr() string { return c.conn.RemoteAddr().String() }
func (c wsControlConn) WriteJSON(payload any) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(controllerSocketWriteTimeout)); err != nil {
		return err
	}
	return c.conn.WriteJSON(payload)
}
func (c wsControlConn) ReadMessage() ([]byte, error) {
	_, data, err := c.conn.ReadMessage()
	return data, err
}
func (c wsControlConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// dialControl establishes the standard WebSocket channel.
func (r *Runner) dialControl(ctx context.Context) (*websocket.Conn, error) {
	cfg := r.Config()
	url, err := security.ControllerWebSocketURL(cfg.ControllerURL, version.IsDev(), cfg.AllowInsecureController)
	if err != nil {
		return nil, err
	}
	header := http.Header{"Authorization": []string{"Bearer " + cfg.AgentToken}, "X-Agent-ID": []string{cfg.AgentID}}
	dialer := websocket.Dialer{ReadBufferSize: 1024, WriteBufferSize: 1024, EnableCompression: false, HandshakeTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, Time: time.Now}}
	conn, handshakeResponse, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		return nil, newControllerHandshakeError(err, handshakeResponse)
	}
	return conn, nil
}

func (r *Runner) connectTestControl(ctx context.Context) error {
	conn, err := r.dialControl(ctx)
	if err != nil {
		return err
	}
	conn.SetReadLimit(controllerSocketReadLimit)
	configureControllerSocket(conn, controllerSocketReadTimeout)
	return r.runControlSession(ctx, wsControlConn{conn: conn})
}

// newTestRunner adapts the existing callback fixtures to an actual TLS AgentLink
// listener, keeping report/accounting assertions independent of the old wire.
func newTestRunner(t *testing.T, cfg Config) *Runner {
	t.Helper()
	if cfg.ControllerURL == "" || cfg.ControllerAddr != "" || cfg.Stealth != nil {
		return New(cfg)
	}
	var runner *Runner
	addr, pin := agentLinkFixture(t, func(conn net.Conn) {
		_, data, err := readAgentLinkFixture(conn)
		if err != nil {
			return
		}
		var auth agentlink.AuthRequest
		if json.Unmarshal(data, &auth) != nil {
			return
		}
		if auth.EnrollmentToken != "" {
			raw, _ := json.Marshal(map[string]any{"enrollment_token": auth.EnrollmentToken, "health": auth.Health})
			req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.ControllerURL, "/")+"/api/v1/agent/enroll", bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			resp, err := runner.client.Do(req)
			if err != nil {
				_ = writeAgentLinkFixture(conn, 4, "enrollment failed")
				return
			}
			defer resp.Body.Close()
			var body any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			if resp.StatusCode >= 300 {
				_ = writeAgentLinkFixture(conn, 4, "enrollment rejected")
				return
			}
			_ = writeAgentLinkFixture(conn, 3, body)
			return
		}
		if err := writeAgentLinkFixture(conn, 3, nil); err != nil {
			return
		}
		for {
			kind, data, err := readAgentLinkFixture(conn)
			if err != nil {
				return
			}
			if kind == 8 {
				_ = writeAgentLinkFixture(conn, 10, nil)
				continue
			}
			if kind != 5 {
				return
			}
			var rpc agentlink.RequestFrame
			if json.Unmarshal(data, &rpc) != nil {
				return
			}
			if rpc.Path == "/download" {
				var chunk struct {
					Stream string
					Offset int64
					Length int64
				}
				if json.Unmarshal(rpc.Body, &chunk) != nil || chunk.Offset < 0 || chunk.Length < 1 {
					return
				}
				prefix := "/downloads/"
				if cfg.UpdateSource == "github" {
					prefix = "/downloads/github/"
				}
				resp, err := runner.client.Get(strings.TrimRight(cfg.ControllerURL, "/") + prefix + chunk.Stream)
				if err != nil {
					return
				}
				data, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == 200 {
					if chunk.Offset >= int64(len(data)) {
						data = nil
					} else {
						data = data[chunk.Offset:]
						if int64(len(data)) > chunk.Length {
							data = data[:chunk.Length]
						}
					}
				}
				body, _ := json.Marshal(data)
				_ = writeAgentLinkFixture(conn, 6, agentlink.ResponseFrame{ID: rpc.ID, Status: resp.StatusCode, Body: body})
				continue
			}
			method := http.MethodPost
			if rpc.Path == "/api/v1/agent/authorization" || rpc.Path == "/api/v1/agent/users-snapshot" {
				method = http.MethodGet
			}
			current := runner.Config()
			req, err := http.NewRequest(method, strings.TrimRight(current.ControllerURL, "/")+rpc.Path, bytes.NewReader(rpc.Body))
			if err != nil {
				return
			}
			req.Header = http.Header(rpc.Headers)
			if req.Header == nil {
				req.Header = http.Header{}
			}
			req.Header.Set("Authorization", "Bearer "+auth.Token)
			req.Header.Set("X-Agent-ID", auth.AgentID)
			req.Header.Set("Content-Type", "application/json")
			resp, err := runner.client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if !json.Valid(body) {
				body, _ = json.Marshal(string(body))
			}
			_ = writeAgentLinkFixture(conn, 6, agentlink.ResponseFrame{ID: rpc.ID, Status: resp.StatusCode, Body: body, Headers: resp.Header})
		}
	})
	cfg.ControllerAddr, cfg.ControllerCertSHA256 = addr, pin
	runner = New(cfg)
	return runner
}
