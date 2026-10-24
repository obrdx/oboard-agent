package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/agentlink"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/version"
)

// ensureAgentLink upgrades an enrolled pre-AgentLink configuration once. A
// configured address or pin is never replaced by HTTP discovery.
func (r *Runner) ensureAgentLink(ctx context.Context) error {
	cfg := r.Config()
	if cfg.ControllerAddr != "" || cfg.ControllerCertSHA256 != "" {
		if err := cfg.validateAgentLink(); err != nil {
			return err
		}
		if cfg.agentLinkMigrationPending {
			if err := r.saveAgentConfig(cfg); err != nil {
				return fmt.Errorf("persist previous AgentLink configuration: %w", err)
			}
			cfg.agentLinkMigrationPending = false
			r.storeConfig(cfg)
		}
		return nil
	}
	if cfg.AgentID == "" || cfg.AgentToken == "" {
		return errors.New("AgentLink bootstrap requires an enrolled identity")
	}
	if _, err := security.ValidateControllerURL(cfg.ControllerURL, version.IsDev(), cfg.AllowInsecureController); err != nil {
		return err
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ControllerURL, "/")+"/api/v1/agent/transport", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("X-Agent-ID", cfg.AgentID)
	req.Header.Set("X-Oboard-Transport-Nonce", nonce)
	// Bootstrap must not send the enrolled identity through a redirect.
	client := *r.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("AgentLink upgrade discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AgentLink upgrade discovery returned %d; configure the Controller dedicated address before updating Agents", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil {
		return err
	}
	if len(data) > 8192 {
		return errors.New("AgentLink bootstrap response too large")
	}
	var bootstrap agentlink.Bootstrap
	if err := json.Unmarshal(data, &bootstrap); err != nil {
		return errors.New("invalid AgentLink bootstrap response")
	}
	if bootstrap.Nonce != nonce || bootstrap.ServerID != cfg.ServerID || bootstrap.AgentID != cfg.AgentID || !bootstrap.Verify(security.HashSecret(cfg.AgentToken)) {
		return errors.New("AgentLink bootstrap identity or signature mismatch")
	}
	next := cfg
	next.ControllerAddr, next.ControllerCertSHA256 = bootstrap.Address, bootstrap.CertSHA256
	if err := next.validateAgentLink(); err != nil {
		return err
	}
	link, err := agentlink.Dial(ctx, agentlink.ClientConfig{Address: next.ControllerAddr, CertSHA256: next.ControllerCertSHA256, AgentID: next.AgentID, Token: next.AgentToken, Purpose: "rpc"})
	if err != nil {
		return fmt.Errorf("verify AgentLink upgrade connection: %w", err)
	}
	_ = link.Close()
	if err := r.saveAgentConfig(next); err != nil {
		return fmt.Errorf("persist AgentLink upgrade: %w", err)
	}
	r.storeConfig(next)
	return nil
}
