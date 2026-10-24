package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/agentlink"
	"github.com/OboardProject/oboard-agent/internal/security"
)

// agentlinkControlConn adapts a binary-transport session to controlConn.
// The session's Run loop is started by connectAgentLink; ReadMessage pulls the
// envelopes Run delivers.
type agentlinkControlConn struct {
	session  *agentlink.Session
	messages chan []byte
	runErr   chan error
	started  bool
}

func newAgentlinkControlConn(session *agentlink.Session) *agentlinkControlConn {
	return &agentlinkControlConn{
		session:  session,
		messages: make(chan []byte, 32),
		runErr:   make(chan error, 1),
	}
}

// start launches the session read loop. It must be called exactly once
// before ReadMessage.
func (c *agentlinkControlConn) start() {
	if c.started {
		return
	}
	c.started = true
	go func() {
		c.runErr <- c.session.Run(func(envelope map[string]json.RawMessage) {
			encoded, err := json.Marshal(envelope)
			if err != nil {
				return
			}
			select {
			case c.messages <- encoded:
			case <-c.session.Closed():
			}
		})
	}()
}

func (c *agentlinkControlConn) Close() error {
	return c.session.Close()
}

func (c *agentlinkControlConn) RemoteAddr() string { return "agentlink" }

func (c *agentlinkControlConn) WriteJSON(payload any) error {
	return c.session.WriteMessage(payload)
}

func (c *agentlinkControlConn) ReadMessage() ([]byte, error) {
	c.start()
	select {
	case data := <-c.messages:
		return data, nil
	case err := <-c.runErr:
		if err != nil {
			return nil, err
		}
		return nil, errors.New("agentlink session ended")
	}
}

func (c *agentlinkControlConn) SetReadDeadline(t time.Time) error {
	// Deadlines are enforced inside the session read loop (90s read
	// deadline); the adapter has nothing to arm.
	_ = t
	return nil
}

// connectAgentLink establishes the binary transport session and runs the
// shared control session over it.
func (r *Runner) connectAgentLink(ctx context.Context) error {
	cfg := r.Config()
	if err := cfg.validateAgentLink(); err != nil {
		return err
	}
	session, err := agentlink.Dial(ctx, agentlink.ClientConfig{
		Address:    cfg.ControllerAddr,
		CertSHA256: cfg.ControllerCertSHA256,
		AgentID:    cfg.AgentID,
		Token:      cfg.AgentToken,
	})
	if err != nil {
		return err
	}
	r.setLiveAgentLinkSession(session)
	defer r.setLiveAgentLinkSession(nil)
	conn := newAgentlinkControlConn(session)
	return r.runControlSession(ctx, conn)
}

// setLiveAgentLinkSession records the session callbacks can reuse.
func (r *Runner) setLiveAgentLinkSession(session *agentlink.Session) {
	r.controlSessionMu.Lock()
	r.controlSessionLink = session
	r.controlSessionMu.Unlock()
}

// enrollAgentLink performs enrollment over the binary transport and persists
// the returned identity plus the certificate pin.
func (r *Runner) enrollAgentLink(ctx context.Context, addr, pin, enrollmentToken string) error {
	session, err := agentlink.Dial(ctx, agentlink.ClientConfig{
		Address:         addr,
		EnrollmentToken: enrollmentToken,
		Health:          mustEnrollmentHealth(r.Probe(true)),
		// Bootstrap: the panel passes the pin out of band, so the handshake
		// is validated against it directly.
		CertSHA256: pin,
	})
	if err != nil {
		return err
	}
	defer session.Close()
	var response agentlink.AuthEnrollResponse
	if len(session.AcceptPayload()) > 0 {
		if err := json.Unmarshal(session.AcceptPayload(), &response); err != nil {
			return err
		}
	}
	if response.AgentID == "" || response.AgentToken == "" {
		return fmt.Errorf("stealth enrollment returned no identity")
	}
	cfg := r.Config()
	cfg.ServerID = response.ServerID
	cfg.AgentID = response.AgentID
	cfg.AgentToken = response.AgentToken
	cfg.ConnectionAuditEnabled = response.ConnectionAuditEnabled
	cfg.ControllerAddr = addr
	cfg.ControllerCertSHA256 = session.CertPin()
	if err := r.saveAgentConfig(cfg); err != nil {
		return err
	}
	r.storeConfig(cfg)
	r.connectionAudit.setEnabled(cfg.ConnectionAuditEnabled)
	return nil
}

// controllerJSONOverTransport performs one callback as a transport RPC. The
// server bridges the request into the existing HTTP handler, so the response
// shapes are identical to the HTTP surface.
func (r *Runner) controllerJSONOverTransport(ctx context.Context, method, path string, headers http.Header, body any, out any, auth bool) error {
	if auth {
		if wait := r.controllerAuth.remaining(time.Now()); wait > 0 {
			return fmt.Errorf("controller rejected this agent identity; callbacks paused for %s", wait.Truncate(time.Second))
		}
	}
	var raw json.RawMessage
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		raw = encoded
	}
	resp, err := r.transportRequest(ctx, path, raw, headers)
	if err != nil {
		return err
	}
	if auth {
		if isControllerAuthRejection(resp.Status) {
			r.controllerAuth.armWithResponse(time.Now(), resp.Status, http.Header(resp.Headers))
		} else if resp.Status < 300 {
			r.controllerAuth.clear()
		}
	}
	if resp.Status >= 300 {
		return fmt.Errorf("controller returned %d %s", resp.Status, http.StatusText(resp.Status))
	}
	if out != nil && len(resp.Body) > 0 {
		return json.Unmarshal(resp.Body, out)
	}
	return nil
}

// transportRequest issues one RPC on the live session, dialing a short-lived
// one when no session is up (callbacks may fire between reconnects).
func (r *Runner) transportRequest(ctx context.Context, path string, body json.RawMessage, headers http.Header) (*agentlink.ResponseFrame, error) {
	cfg := r.Config()
	if strings.TrimSpace(cfg.ControllerAddr) == "" {
		return nil, errors.New("AgentLink is not configured; reinstall with a current Controller enrollment command")
	}
	if session := r.liveAgentLinkSession(); session != nil {
		return session.RequestWithHeaders(ctx, path, body, nil, headers)
	}
	// No live session: a short-lived authenticated session serves the
	// callback. This mirrors HTTP callbacks that work while the WebSocket is
	// down.
	session, err := agentlink.Dial(ctx, agentlink.ClientConfig{
		Address:    cfg.ControllerAddr,
		CertSHA256: cfg.ControllerCertSHA256,
		AgentID:    cfg.AgentID,
		Token:      cfg.AgentToken,
		Purpose:    "rpc",
	})
	if err != nil {
		var authError *agentlink.AuthError
		if errors.As(err, &authError) {
			r.controllerAuth.armAgentLink(time.Now())
		}
		return nil, err
	}
	defer session.Close()
	go func() {
		_ = session.Run(func(map[string]json.RawMessage) {})
	}()
	return session.RequestWithHeaders(ctx, path, body, nil, headers)
}

// liveAgentLinkSession returns the current control-channel session when it is
// the binary transport, or nil.
func (r *Runner) liveAgentLinkSession() *agentlink.Session {
	r.controlSessionMu.Lock()
	defer r.controlSessionMu.Unlock()
	if r.controlSessionLink != nil {
		return r.controlSessionLink
	}
	return nil
}

// transportDownload fetches one release artifact over the binary transport
// in bounded chunks with resume, replacing the HTTP download path for all Agent layouts. Integrity stays end-to-end: the caller still verifies the signed
// manifest after assembly, exactly as with HTTP downloads.
func (r *Runner) transportDownload(ctx context.Context, session *agentlink.Session, name, destination string, expectedSize, maxBytes int64) error {
	if expectedSize > 0 {
		if info, err := os.Stat(destination); err == nil && info.Size() == expectedSize {
			return nil // already complete from a previous attempt
		}
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	offset := int64(0)
	if info, err := os.Stat(destination); err == nil && info.Size() > 0 && (expectedSize <= 0 || info.Size() < expectedSize) {
		offset = info.Size()
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return err
		}
	} else if err == nil && expectedSize > 0 && info.Size() > expectedSize {
		if err := file.Truncate(0); err != nil {
			return err
		}
	}
	const chunkSize = 512 << 10
	for {
		want := int64(chunkSize)
		if expectedSize > 0 && offset+want > expectedSize {
			want = expectedSize - offset
		}
		if want <= 0 {
			return nil
		}
		req := map[string]any{"stream": name, "offset": offset, "length": want}
		resp, err := session.Request(ctx, "/download", req, nil)
		if err != nil {
			return err
		}
		if resp.Status != 200 {
			return fmt.Errorf("transport download %s: %s", name, resp.Error)
		}
		var chunk []byte
		if len(resp.Body) > 0 {
			if err := json.Unmarshal(resp.Body, &chunk); err != nil {
				return err
			}
		}
		if len(chunk) == 0 {
			return nil // EOF
		}
		if offset+int64(len(chunk)) > maxBytes || (expectedSize > 0 && offset+int64(len(chunk)) > expectedSize) {
			return fmt.Errorf("transport download %s exceeded the signed size limit", name)
		}
		if _, err := file.Write(chunk); err != nil {
			return err
		}
		offset += int64(len(chunk))
		if expectedSize > 0 && offset >= expectedSize {
			return nil
		}
	}
}

// downloadAndInstallSignedReleaseOverTransport is the stealth-mode update
// path: the same signed release, fetched over the binary transport instead
// of HTTP. Verification, staging, preflight, and atomic install are shared
// with the HTTP path.
func (r *Runner) downloadAndInstallSignedReleaseOverTransport(ctx context.Context, repo, expectedBuild string, targets signedReleaseTargets, stagingPrefix string) (releaseInstallOutcome, error) {
	var outcome releaseInstallOutcome
	ctx, cancel := context.WithTimeout(ctx, releaseUpdateTimeout)
	defer cancel()
	cfg := r.Config()
	session, err := agentlink.Dial(ctx, agentlink.ClientConfig{
		Address:    cfg.ControllerAddr,
		CertSHA256: cfg.ControllerCertSHA256,
		AgentID:    cfg.AgentID,
		Token:      cfg.AgentToken,
		Purpose:    "rpc",
	})
	if err != nil {
		return outcome, err
	}
	go func() { _ = session.Run(func(map[string]json.RawMessage) {}) }()
	defer session.Close()
	tmpDir, err := os.MkdirTemp("", "oboard-signed-update.*")
	if err != nil {
		return outcome, err
	}
	defer os.RemoveAll(tmpDir)
	// Fetch and verify the manifest exactly as the HTTP path does.
	manifestPath := filepath.Join(tmpDir, "release-manifest.json")
	signaturePath := filepath.Join(tmpDir, "release-manifest.json.sig")
	if err := r.transportDownload(ctx, session, "release-manifest.json", manifestPath, 0, maxReleaseManifestBytes); err != nil {
		return outcome, err
	}
	if err := r.transportDownload(ctx, session, "release-manifest.json.sig", signaturePath, 0, maxReleaseSignatureBytes); err != nil {
		return outcome, err
	}
	manifest, err := verifyDownloadedManifest(manifestPath, signaturePath, strings.TrimSpace(repo), strings.TrimSpace(expectedBuild))
	if err != nil {
		return outcome, err
	}
	agentName := "oboard-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	coreName := "oboard-sb-" + runtime.GOOS + "-" + runtime.GOARCH
	realmName := "oboard-realm-" + runtime.GOOS + "-" + runtime.GOARCH
	agentFile, err := validateManifestBinary(manifest, agentName, "agent")
	if err != nil {
		return outcome, err
	}
	coreFile, err := validateManifestBinary(manifest, coreName, "sb")
	if err != nil {
		return outcome, err
	}
	realmFile, err := validateManifestBinary(manifest, realmName, "realm")
	if err != nil {
		return outcome, err
	}
	for _, file := range []security.ReleaseManifestFile{agentFile, coreFile, realmFile} {
		if err := r.transportDownload(ctx, session, file.Name, filepath.Join(tmpDir, file.Name), file.Size, maxReleaseBinaryBytes); err != nil {
			return outcome, err
		}
	}
	if err := ctx.Err(); err != nil {
		return outcome, fmt.Errorf("release update stopped before verification: %w", err)
	}
	if err := VerifyReleaseFiles(manifestPath, signaturePath, tmpDir, runtime.GOOS, runtime.GOARCH, []string{agentName, coreName, realmName}); err != nil {
		return outcome, err
	}
	if err := ctx.Err(); err != nil {
		return outcome, fmt.Errorf("release update stopped before installation: %w", err)
	}
	if err := checkUpdateDiskBudget(targets, agentFile.Size, coreFile.Size, realmFile.Size); err != nil {
		return outcome, err
	}
	if err := r.preflightRuntimeSecurityUpdate(filepath.Join(tmpDir, coreName)); err != nil {
		return outcome, err
	}
	state, note, err := r.preflightStagedCore(filepath.Join(tmpDir, coreName), targets.ActiveConfig, coreCheckTimeout)
	outcome.CorePreflight = state
	outcome.CorePreflightNote = note
	if err != nil {
		return outcome, err
	}
	if err := r.installVerifiedReleaseWithProof(stagingPrefix, manifestPath, signaturePath, []stagedReleaseFile{
		{source: filepath.Join(tmpDir, agentName), target: targets.Agent},
		{source: filepath.Join(tmpDir, coreName), target: targets.Core},
		{source: filepath.Join(tmpDir, realmName), target: targets.Realm},
	}); err != nil {
		return outcome, err
	}
	outcome.Manifest = manifest
	return outcome, nil
}

func mustEnrollmentHealth(health any) json.RawMessage {
	data, _ := json.Marshal(health)
	return data
}

func (cfg Config) validateAgentLink() error {
	host, port, err := net.SplitHostPort(cfg.ControllerAddr)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || portNumber < 1 || portNumber > 65535 || host == "" || strings.ContainsAny(host, " /?#@\t\r\n") {
		return errors.New("AgentLink requires controller_addr (host:port); reinstall with a current Controller enrollment command")
	}
	pin, err := hex.DecodeString(cfg.ControllerCertSHA256)
	if err != nil || len(pin) != 32 || strings.ToLower(cfg.ControllerCertSHA256) != cfg.ControllerCertSHA256 {
		return errors.New("AgentLink requires a lowercase SHA-256 controller certificate pin")
	}
	return nil
}
