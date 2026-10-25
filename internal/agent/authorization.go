package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/authorization"
	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
)

// kernelCapabilityAuthorizationControl is advertised by kernels that accept the
// wrapped {lease, deny} authorization body and expose GET /authorization/status.
const kernelCapabilityAuthorizationControl = "authorization_control_v1"

// authorizationSyncInterval is the steady-state pull cadence of the independent
// authorization lane. It is well under the lease's five-minute lifetime so a
// missed control message never lets the lease expire on a healthy link.
const authorizationSyncInterval = 30 * time.Second

func (r *Runner) authorizationState() *authorization.Store {
	r.authorizationMu.Lock()
	defer r.authorizationMu.Unlock()
	if r.authorizationStore == nil {
		r.authorizationStore = authorization.NewStore(r.statePath("authorization.json"), r.Config().StealthKey)
		if r.clock != nil {
			r.authorizationStore.SetClock(r.clock.Now)
		}
	}
	return r.authorizationStore
}

func (r *Runner) authorizationAllows(key string) bool {
	now := time.Now()
	if r.clock != nil {
		now = r.clock.Now()
	}
	return r.authorizationState().Allows(key, now)
}

func (r *Runner) authorizationOfflineAllows(key string) bool {
	now := time.Now()
	if r.clock != nil {
		now = r.clock.Now()
	}
	return r.authorizationState().OfflineAllows(key, now)
}

func (r *Runner) setControllerDisconnected(disconnected bool) {
	r.authorizationApplyMu.Lock()
	defer r.authorizationApplyMu.Unlock()
	r.authorizationState().SetDisconnected(disconnected)
	body, _ := json.Marshal(map[string]bool{"disconnected": disconnected})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/authorization/connectivity", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := r.coreAPIClient().Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
}

// appliedAuthorization is the opaque confirmation identity reported to the
// Controller in health reports, pull requests, and task results.
func (r *Runner) appliedAuthorization() *model.AuthorizationAppliedSnapshot {
	status := r.authorizationState().Status()
	if status.Revision <= 0 {
		return nil
	}
	return &model.AuthorizationAppliedSnapshot{Revision: status.Revision, Sequence: status.Sequence, Digest: status.Digest, BootID: status.BootID}
}

func configAuthorization(raw []byte) (*model.AuthorizationLease, error) {
	var config struct {
		Metadata struct {
			Authorization *model.AuthorizationLease `json:"authorization"`
			Limits        map[string]map[string]struct {
				Key string `json:"authorization_key"`
			} `json:"rate_limits"`
		} `json:"_oboard"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	if config.Metadata.Authorization == nil {
		for _, entries := range config.Metadata.Limits {
			for _, entry := range entries {
				if entry.Key != "" {
					return nil, fmt.Errorf("authorization snapshot is required for installed credentials")
				}
			}
		}
	}
	return config.Metadata.Authorization, config.Metadata.Authorization.Validate()
}

func configHasAuthorizationUsers(raw []byte) (bool, error) {
	type identity struct {
		UserID int64  `json:"user_id"`
		Key    string `json:"authorization_key"`
	}
	var config struct {
		Metadata struct {
			RuntimeUsers struct {
				Inbounds []string `json:"inbounds"`
			} `json:"runtime_users"`
			Limits struct {
				Users    map[string]identity `json:"users"`
				Inbounds map[string]identity `json:"inbounds"`
			} `json:"rate_limits"`
		} `json:"_oboard"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return false, err
	}
	for _, tag := range config.Metadata.RuntimeUsers.Inbounds {
		if strings.TrimSpace(tag) != "" {
			return true, nil
		}
	}
	for _, entries := range []map[string]identity{config.Metadata.Limits.Users, config.Metadata.Limits.Inbounds} {
		for _, entry := range entries {
			if entry.UserID > 0 || entry.Key != "" {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r *Runner) stageConfigAuthorization(raw []byte) (resultErr error) {
	stage := "validate"
	revision, count := int64(0), 0
	defer func() {
		if revision > 0 || resultErr != nil {
			r.noteSyncOutcome("credential_install", stage, revision, count, resultErr)
		}
	}()
	lease, err := configAuthorization(raw)
	if err != nil {
		return err
	}
	hasUsers, err := configHasAuthorizationUsers(raw)
	if err != nil {
		return err
	}
	if lease != nil {
		revision, count = lease.Revision, len(lease.Grants)
	}
	stage = "kernel_capability"
	if lease != nil && hasUsers {
		output, err := commandOutput(r.commandTimeout(), r.coreBinary(), "-version")
		if err != nil {
			return fmt.Errorf("authorization requires a lease-capable kernel: %w", err)
		}
		supported := false
		for _, capability := range parseKernelCapabilities(output) {
			supported = supported || capability == "authorization_lease_v1"
		}
		if !supported {
			return fmt.Errorf("update oboard-sb before applying proxy authorization: authorization_lease_v1 required")
		}
	}
	stage = "persist"
	r.authorizationApplyMu.Lock()
	defer r.authorizationApplyMu.Unlock()
	return r.authorizationState().Update(lease)
}

func (r *Runner) applyConfigAuthorization(ctx context.Context, raw []byte) error {
	lease, err := configAuthorization(raw)
	if err != nil {
		return err
	}
	_, err = r.applyAuthorization(ctx, lease)
	return err
}

// authorizationApplyOutcome is what one apply pass established about the
// runtimes that enforce authorization.
type authorizationApplyOutcome struct {
	Status          authorization.Status
	RuntimeVerified bool
	Runtimes        map[string]string
	Revoked         int
}

// applyAuthorization installs a lease on every runtime that enforces it, in a
// fixed order: persist the snapshot and deny watermark first (so a crash
// between steps can only lose grants, never a denial), push it into the kernel,
// reap SSH sessions, then read the kernel's installed identity back. It holds
// only authorizationApplyMu: a long deployment, the traffic reporter, and the
// kernel lifecycle lock never block a revoke.
func (r *Runner) applyAuthorization(ctx context.Context, lease *model.AuthorizationLease) (outcome authorizationApplyOutcome, resultErr error) {
	if lease != nil && lease.ContinueWhenDisconnected {
		_, capabilities := r.coreIdentity()
		supported := false
		for _, capability := range capabilities {
			supported = supported || capability == "offline_service_v1"
		}
		if !supported {
			return outcome, errors.New("offline service requires an updated kernel with offline_service_v1")
		}
	}
	stage := "persist"
	revision, count := int64(0), 0
	if lease != nil {
		revision, count = lease.Revision, len(lease.Grants)
	}
	defer func() {
		if lease != nil || resultErr != nil {
			r.noteSyncOutcome("authorization", stage, revision, count, resultErr)
		}
	}()
	r.authorizationApplyMu.Lock()
	defer r.authorizationApplyMu.Unlock()
	store := r.authorizationState()
	update, err := store.UpdateWithResult(lease)
	if err != nil {
		return outcome, err
	}
	outcome.Revoked = len(update.Revoked)
	outcome.Runtimes = map[string]string{}
	stage = "ssh_runtime"
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	manager.reapAuthorization()
	outcome.Runtimes["ssh"] = "applied"
	latest, err := store.Snapshot()
	if err != nil {
		return outcome, err
	}
	outcome.Status = store.Status()
	if latest == nil {
		outcome.RuntimeVerified = true
		return outcome, nil
	}
	revision, count = latest.Revision, len(latest.Grants)
	stage = "read_kernel_config"
	raw, err := r.stateRead(singBoxConfigFile)
	if os.IsNotExist(err) {
		outcome.Runtimes["kernel"] = "no_config"
		outcome.RuntimeVerified = true
		return outcome, nil
	}
	if err != nil {
		return outcome, err
	}
	hasUsers, err := configHasAuthorizationUsers(raw)
	if err != nil {
		return outcome, err
	}
	if !hasUsers {
		outcome.Runtimes["kernel"] = "no_users"
		outcome.RuntimeVerified = true
		return outcome, nil
	}
	stage = "kernel_apply"
	controlCapable := r.kernelSupportsAuthorizationControl()
	var body []byte
	if controlCapable {
		body, err = json.Marshal(map[string]any{"lease": latest, "deny": store.DeniedKeys()})
	} else {
		body, err = json.Marshal(latest)
	}
	if err != nil {
		return outcome, err
	}
	client := r.coreAPIClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/authorization/config", bytes.NewReader(body))
	if err != nil {
		return outcome, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		outcome.Runtimes["kernel"] = "unreachable"
		return outcome, fmt.Errorf("apply kernel authorization: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		outcome.Runtimes["kernel"] = "rejected"
		return outcome, fmt.Errorf("kernel authorization status %d", res.StatusCode)
	}
	outcome.Runtimes["kernel"] = "applied"
	if !controlCapable {
		// Older kernels have no read-back endpoint; the accepted POST is the
		// strongest evidence available and is labelled as such.
		outcome.Runtimes["kernel"] = "applied_unverified"
		return outcome, nil
	}
	stage = "kernel_verify"
	status, err := r.readKernelAuthorizationStatus(ctx)
	if err != nil {
		outcome.Runtimes["kernel"] = "readback_failed"
		return outcome, err
	}
	if status.Revision != latest.Revision || status.Sequence != latest.Sequence || (status.Digest != "" && latest.Digest != "" && status.Digest != latest.Digest) {
		outcome.Runtimes["kernel"] = "mismatch"
		return outcome, fmt.Errorf("kernel reports authorization revision=%d sequence=%d, expected revision=%d sequence=%d", status.Revision, status.Sequence, latest.Revision, latest.Sequence)
	}
	outcome.Runtimes["kernel"] = "verified"
	outcome.RuntimeVerified = true
	return outcome, nil
}

func (r *Runner) kernelSupportsAuthorizationControl() bool {
	r.mu.Lock()
	capabilities := append([]string(nil), r.lastKernelCapabilities...)
	r.mu.Unlock()
	if len(capabilities) == 0 {
		_, capabilities = r.coreIdentity()
	}
	for _, capability := range capabilities {
		if capability == kernelCapabilityAuthorizationControl {
			return true
		}
	}
	return false
}

func (r *Runner) readKernelAuthorizationStatus(ctx context.Context) (authorization.Status, error) {
	var status authorization.Status
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/authorization/status", nil)
	if err != nil {
		return status, err
	}
	res, err := r.coreAPIClient().Do(req)
	if err != nil {
		return status, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return status, fmt.Errorf("kernel authorization status %d", res.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&status); err != nil {
		return status, err
	}
	return status, nil
}

var errAuthorizationEnvelopeRejected = errors.New("authorization envelope rejected")

// verifyAuthorizationEnvelope checks the envelope's signature and server binding
// and decodes the lease it carries. Every transport (control message, HTTP
// pull, traffic response) goes through this single verification.
func (r *Runner) verifyAuthorizationEnvelope(envelope model.AuthorizationEnvelope) (*model.AuthorizationLease, error) {
	cfg := r.Config()
	if cfg.ServerID > 0 && envelope.ServerID != cfg.ServerID {
		return nil, fmt.Errorf("%w: server_id %d does not match enrolled server %d", errAuthorizationEnvelopeRejected, envelope.ServerID, cfg.ServerID)
	}
	if strings.TrimSpace(envelope.LeaseJSON) == "" || strings.TrimSpace(envelope.Signature) == "" {
		return nil, fmt.Errorf("%w: missing lease or signature", errAuthorizationEnvelopeRejected)
	}
	var lease model.AuthorizationLease
	if err := json.Unmarshal([]byte(envelope.LeaseJSON), &lease); err != nil {
		return nil, fmt.Errorf("%w: %v", errAuthorizationEnvelopeRejected, err)
	}
	fields := security.AuthorizationEnvelopeFields{ServerID: envelope.ServerID, MessageID: envelope.MessageID, Revision: lease.Revision, Sequence: lease.Sequence, IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt, LeaseJSON: envelope.LeaseJSON}
	if !security.VerifyAuthorizationEnvelope(security.HashSecret(cfg.AgentToken), fields, envelope.Signature) {
		return nil, fmt.Errorf("%w: signature verification failed", errAuthorizationEnvelopeRejected)
	}
	if err := lease.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errAuthorizationEnvelopeRejected, err)
	}
	return &lease, nil
}

// applyAuthorizationEnvelope verifies and applies one envelope and builds the
// acknowledgement the Controller uses to advance its ledger. A rejected
// signature is never acknowledged as confirmed; the ack reports the identity
// the data plane actually holds.
func (r *Runner) applyAuthorizationEnvelope(ctx context.Context, envelope model.AuthorizationEnvelope) model.AuthorizationAck {
	ack := model.AuthorizationAck{Type: model.AgentControlAuthorizationAck, MessageID: envelope.MessageID}
	lease, err := r.verifyAuthorizationEnvelope(envelope)
	if err != nil {
		logging.Warnf("authorization envelope rejected message=%s: %v", envelope.MessageID, err)
		ack.Error = err.Error()
		ack.Applied = r.appliedAuthorization()
		return ack
	}
	ack.Revision, ack.Sequence, ack.Digest = lease.Revision, lease.Sequence, lease.Digest
	outcome, err := r.applyAuthorization(ctx, lease)
	ack.Runtimes = outcome.Runtimes
	ack.BootID = outcome.Status.BootID
	ack.Applied = r.appliedAuthorization()
	if err != nil {
		ack.Error = err.Error()
		return ack
	}
	// Confirmation names the installed identity, which may be newer than the
	// envelope when a later message was applied first; the Controller treats
	// a newer confirmation as covering this one.
	ack.Revision, ack.Sequence, ack.Digest = outcome.Status.Revision, outcome.Status.Sequence, outcome.Status.Digest
	// Confirmed means every runtime accepted the snapshot. Whether the kernel's
	// installed identity was read back is reported separately so a kernel
	// without the status endpoint is labelled, not treated as a failure.
	r.setControllerDisconnected(false)
	ack.Confirmed = true
	if ack.Runtimes == nil {
		ack.Runtimes = map[string]string{}
	}
	ack.Runtimes["runtime_verified"] = strconv.FormatBool(outcome.RuntimeVerified)
	if outcome.Revoked > 0 {
		logging.Infof("authorization revision=%d sequence=%d applied: revoked=%d grants=%d denied=%d", outcome.Status.Revision, outcome.Status.Sequence, outcome.Revoked, outcome.Status.GrantCount, outcome.Status.DeniedCount)
	}
	return ack
}

// wakeAuthorizationSync asks the independent lane to pull the current snapshot
// now: on connect, after a reconnect, or when a revision gap is observed.
func (r *Runner) wakeAuthorizationSync() {
	if r.authorizationSyncWake == nil {
		return
	}
	select {
	case r.authorizationSyncWake <- struct{}{}:
	default:
	}
}

// startAuthorizationSyncLoop runs the independent authorization lane. It pulls
// GET /api/v1/agent/authorization on start and on every wake, and otherwise
// about every 30 seconds with jitter. It shares no lock with the traffic
// reporter and does not depend on a report having succeeded.
func (r *Runner) startAuthorizationSyncLoop(ctx context.Context) {
	if r.authorizationSyncWake == nil {
		r.authorizationSyncWake = make(chan struct{}, 1)
	}
	go func() {
		timer := time.NewTimer(jitteredAuthorizationInterval())
		defer timer.Stop()
		r.pullAuthorization(ctx, "startup")
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.authorizationSyncWake:
				r.pullAuthorization(ctx, "wake")
				timer.Reset(jitteredAuthorizationInterval())
			case <-timer.C:
				r.pullAuthorization(ctx, "periodic")
				timer.Reset(jitteredAuthorizationInterval())
			}
		}
	}()
}

func jitteredAuthorizationInterval() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(authorizationSyncInterval/3)))
	if err != nil {
		return authorizationSyncInterval
	}
	return authorizationSyncInterval + time.Duration(n.Int64())
}

// pullAuthorization fetches and applies the signed envelope over HTTP. The
// request headers carry the applied identity so the pull doubles as a
// confirmation for the Controller ledger.
func (r *Runner) pullAuthorization(ctx context.Context, reason string) {
	if ctx.Err() != nil {
		return
	}
	pullCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	headers := http.Header{}
	if applied := r.appliedAuthorization(); applied != nil {
		headers.Set("X-Oboard-Authorization-Revision", strconv.FormatInt(applied.Revision, 10))
		headers.Set("X-Oboard-Authorization-Sequence", strconv.FormatInt(applied.Sequence, 10))
		headers.Set("X-Oboard-Authorization-Digest", applied.Digest)
		headers.Set("X-Oboard-Authorization-Boot-Id", applied.BootID)
	}
	var envelope model.AuthorizationEnvelope
	if err := r.controllerJSON(pullCtx, http.MethodGet, "/api/v1/agent/authorization", headers, nil, &envelope, true); err != nil {
		r.setControllerDisconnected(true)
		r.noteSyncOutcome("authorization_pull", reason, 0, 0, err)
		return
	}
	ack := r.applyAuthorizationEnvelope(pullCtx, envelope)
	if ack.Error != "" {
		r.noteSyncOutcome("authorization_pull", reason, ack.Revision, 0, errors.New(ack.Error))
		return
	}
	r.noteSyncOutcome("authorization_pull", reason, ack.Revision, 0, nil)
}

// applyAuthorizationResponse applies the authorization carried in a traffic
// response, preferring the signed envelope and falling back to the bare lease
// only when a Controller did not include one.
func (r *Runner) applyAuthorizationResponse(ctx context.Context, envelope *model.AuthorizationEnvelope, lease *model.AuthorizationLease) error {
	if envelope != nil {
		ack := r.applyAuthorizationEnvelope(ctx, *envelope)
		if ack.Error != "" {
			return errors.New(ack.Error)
		}
		return nil
	}
	_, err := r.applyAuthorization(ctx, lease)
	return err
}
