package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	sshInboundsCurrent  = "ssh-inbounds.json"
	sshInboundsLastGood = "ssh-inbounds.last-good.json"
	sshInboundHostKey   = "ssh-inbounds-host-key"
	sshInboundIOChunk   = 32 << 10

	sshInboundPolicyRetryInterval = 15 * time.Second
)

var (
	sshDeviceIDHashPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	sshRouteInboundPattern  = regexp.MustCompile(`^in-[1-9][0-9]*$`)
	sshRouteAuthUserPattern = regexp.MustCompile(`^u[0-9a-f]{32}$`)
)

type sshInboundApplyResult struct {
	model.SSHAuthenticationVerification
	Unchanged            bool     `json:"unchanged,omitempty"`
	RuntimeOnly          bool     `json:"runtime_only,omitempty"`
	RuntimeReconciled    bool     `json:"runtime_reconciled,omitempty"`
	ReconciledComponents []string `json:"reconciled_components,omitempty"`
	Applied              int      `json:"applied"`
	Listeners            int      `json:"listeners"`
	Users                int      `json:"users"`
	HostPublicKey        string   `json:"host_public_key"`
	HostKeyFingerprint   string   `json:"host_key_fingerprint"`
	Warnings             []string `json:"warnings,omitempty"`
}

// sshInboundManager owns only the Agent-native SSH proxy listeners. Keeping
// this separate from the SSH tunnel machinery prevents an inbound deployment
// from changing the host's sshd configuration or user accounts.
type sshInboundManager struct {
	mu        sync.RWMutex
	listeners map[int64]*managedSSHInbound
	signer    ssh.Signer
	usage     map[int64]*sshInboundUserUsage
}

type managedSSHInbound struct {
	authorizationAllows func(string) bool
	offlineAllows       func(string) bool
	plan                model.SSHInbound
	listener            net.Listener
	auth                map[string]sshInboundCredential
	authMu              sync.RWMutex
	counters            map[int64]*sshInboundCounter
	audit               *connectionAuditAccumulator
	routeDial           routeRelayDialFunc

	mu       sync.Mutex
	conns    map[net.Conn]int64
	sessions map[*ssh.ServerConn]string
	probes   map[string]chan sshAuthenticationObservation
}

type sshInboundCredential struct {
	authorizationKey string
	userID           int64
	password         string
	deviceIDHash     string
	credentialEpoch  int64
	credentialStatus string
	pathID           int64
	routeKind        string
	routeInboundTag  string
	routeAuthUser    string
}

type sshInboundCounter struct {
	mu                   sync.RWMutex
	epoch                string
	policy               model.TrafficRuntimePolicy
	upload               atomic.Int64
	download             atomic.Int64
	acknowledgedUpload   atomic.Int64
	acknowledgedDownload atomic.Int64
	usage                *sshInboundUserUsage
	offlineAllows        func() bool
}

type sshInboundUserUsage struct {
	mu      sync.Mutex
	periods map[string]*sshInboundUsagePeriod
}

type sshInboundUsagePeriod struct {
	upload               atomic.Int64
	download             atomic.Int64
	acknowledgedUpload   atomic.Int64
	acknowledgedDownload atomic.Int64
}

type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func passwordDigest(password string) string {
	// Drift-detection fingerprint of a cryptographically random credential,
	// not password storage or authentication: SHA-256 is the right tool here
	// and preimage resistance is what matters.
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func sshInboundUserFingerprint(user model.SSHInboundUser) string {
	// Fingerprint includes all identity-relevant fields but not plaintext password
	return user.AuthorizationKey + "|" + fmt.Sprintf("%d|%s|%s|%s|%d|%s|%d|%s|%s|%s", user.UserID, user.Username, passwordDigest(user.Password), strings.TrimSpace(user.DeviceIDHash), user.CredentialEpoch, strings.TrimSpace(user.CredentialStatus), user.PathID, user.RouteKind, user.RouteInboundTag, user.RouteAuthUser)
}

func sshInboundFingerprint(inbound model.SSHInbound) string {
	// Stable fingerprint for one inbound including listen and users
	var users []string
	for _, u := range inbound.Users {
		if !u.Enabled {
			continue
		}
		users = append(users, sshInboundUserFingerprint(u))
	}
	sort.Strings(users)
	// Policy identity: sorted keys
	var policyKeys []string
	for k := range inbound.Policies {
		policyKeys = append(policyKeys, k)
	}
	sort.Strings(policyKeys)
	policyPart := strings.Join(policyKeys, ",")
	raw := fmt.Sprintf("%d|%s|%d|%v|%s|%s|%d", inbound.InboundID, strings.TrimSpace(inbound.ListenIP), inbound.Port, inbound.Enabled, strings.Join(users, ";"), policyPart, len(users))
	// The password digest inside raw is a fingerprint input, not a stored
	// password hash; see passwordDigest.
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func desiredSSHInboundFingerprints(plan model.SSHInboundPlan) map[int64]string {
	out := map[int64]string{}
	for _, inbound := range plan.Inbounds {
		if !inbound.Enabled {
			continue
		}
		out[inbound.InboundID] = sshInboundFingerprint(inbound)
	}
	return out
}

func liveSSHInboundFingerprints(manager *sshInboundManager) map[int64]string {
	if manager == nil {
		return map[int64]string{}
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	out := map[int64]string{}
	for id, inbound := range manager.listeners {
		// Build live inbound representation from actual auth map and listener
		inbound.mu.Lock()
		// Use the stored plan but replace Users with live auth snapshot
		liveInbound := inbound.plan
		// Reconstruct Users from live auth map
		inbound.authMu.RLock()
		liveUsers := []model.SSHInboundUser{}
		for username, cred := range inbound.auth {
			liveUsers = append(liveUsers, model.SSHInboundUser{
				UserID:           cred.userID,
				Username:         username,
				Password:         cred.password,
				DeviceIDHash:     cred.deviceIDHash,
				AuthorizationKey: cred.authorizationKey,
				CredentialEpoch:  cred.credentialEpoch,
				CredentialStatus: cred.credentialStatus,
				PathID:           cred.pathID,
				RouteKind:        cred.routeKind,
				RouteInboundTag:  cred.routeInboundTag,
				RouteAuthUser:    cred.routeAuthUser,
				Enabled:          true,
			})
		}
		inbound.authMu.RUnlock()
		liveInbound.Users = liveUsers
		// Listener address check: use actual listener if available
		if inbound.listener != nil {
			if addr, ok := inbound.listener.Addr().(*net.TCPAddr); ok {
				liveInbound.ListenIP = addr.IP.String()
				liveInbound.Port = addr.Port
			}
		}
		inbound.mu.Unlock()
		out[id] = sshInboundFingerprint(liveInbound)
	}
	return out
}

type sshDriftCheck struct {
	NoDrift         bool
	ListenerDrift   bool
	CredentialDrift bool
	PolicyDrift     bool
	Missing         []int64
	Extra           []int64
}

func (m *sshInboundManager) checkDrift(plan model.SSHInboundPlan) sshDriftCheck {
	desired := desiredSSHInboundFingerprints(plan)
	live := liveSSHInboundFingerprints(m)
	if len(desired) == 0 && len(live) == 0 {
		return sshDriftCheck{NoDrift: true}
	}
	// Quick compare
	if len(desired) != len(live) {
		// Determine missing/extra
		missing := []int64{}
		for id := range desired {
			if _, ok := live[id]; !ok {
				missing = append(missing, id)
			}
		}
		extra := []int64{}
		for id := range live {
			if _, ok := desired[id]; !ok {
				extra = append(extra, id)
			}
		}
		return sshDriftCheck{ListenerDrift: true, Missing: missing, Extra: extra}
	}
	for id, desiredFP := range desired {
		if liveFP, ok := live[id]; !ok {
			return sshDriftCheck{ListenerDrift: true, Missing: []int64{id}}
		} else if desiredFP != liveFP {
			// Need to determine if it's credential/policy vs listener
			// For simplicity, treat any fingerprint mismatch as credential drift
			// unless listen address/port changed. We can refine by comparing
			// inbound's listen/port separately.
			desiredInbound := findInboundByID(plan.Inbounds, id)
			m.mu.RLock()
			liveInbound := m.listeners[id]
			m.mu.RUnlock()
			if liveInbound != nil {
				liveInbound.mu.Lock()
				liveListen := ""
				livePort := 0
				if liveInbound.listener != nil {
					if addr, ok := liveInbound.listener.Addr().(*net.TCPAddr); ok {
						liveListen = addr.IP.String()
						livePort = addr.Port
					}
				} else {
					liveListen = liveInbound.plan.ListenIP
					livePort = liveInbound.plan.Port
				}
				liveInbound.mu.Unlock()
				if strings.TrimSpace(desiredInbound.ListenIP) != strings.TrimSpace(liveListen) || desiredInbound.Port != livePort {
					return sshDriftCheck{ListenerDrift: true}
				}
			}
			return sshDriftCheck{CredentialDrift: true}
		}
	}
	return sshDriftCheck{NoDrift: true}
}

func findInboundByID(inbounds []model.SSHInbound, id int64) model.SSHInbound {
	for _, in := range inbounds {
		if in.InboundID == id {
			return in
		}
	}
	return model.SSHInbound{}
}

func (m *sshInboundManager) reconcileInPlace(plan model.SSHInboundPlan) {
	if m == nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, desired := range plan.Inbounds {
		if !desired.Enabled {
			continue
		}
		live, ok := m.listeners[desired.InboundID]
		if !ok {
			continue
		}
		// Update auth map without restarting listener
		live.authMu.Lock()
		live.auth = sshInboundCredentials(desired.Users)
		live.plan = desired
		live.authMu.Unlock()
		// Update counters for new users, remove old
		// Note: counters are kept per userID; new users will be added on next need
		// For removed users, keep counters but they will not be used
	}
}

type sshDiagnostics struct {
	Inbounds []sshInboundDiagnostics `json:"ssh_inbounds"`
}

type sshInboundDiagnostics struct {
	InboundID       int64  `json:"inbound_id"`
	Listener        string `json:"listener"`
	DesiredUsers    int    `json:"desired_users"`
	RuntimeUsers    int    `json:"runtime_users"`
	CredentialDrift bool   `json:"credential_drift"`
	PolicyDrift     bool   `json:"policy_drift"`
	CounterDrift    bool   `json:"counter_drift"`
}

func (r *Runner) sshDiagnostics(plan model.SSHInboundPlan) sshDiagnostics {
	diag := sshDiagnostics{Inbounds: []sshInboundDiagnostics{}}
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	desiredMap := map[int64]model.SSHInbound{}
	for _, in := range plan.Inbounds {
		if in.Enabled {
			desiredMap[in.InboundID] = in
		}
	}
	if manager != nil {
		manager.mu.RLock()
		for id, live := range manager.listeners {
			desired, hasDesired := desiredMap[id]
			desiredUsers := 0
			if hasDesired {
				for _, u := range desired.Users {
					if u.Enabled {
						desiredUsers++
					}
				}
			}
			live.authMu.RLock()
			runtimeUsers := len(live.auth)
			live.authMu.RUnlock()
			listenerStatus := "healthy"
			if live.listener == nil {
				listenerStatus = "missing"
			}
			// Check drift per inbound
			drift := false
			if hasDesired {
				desiredFP := sshInboundFingerprint(desired)
				// Compute live FP for this single inbound
				live.authMu.RLock()
				liveUsers := []model.SSHInboundUser{}
				for username, cred := range live.auth {
					liveUsers = append(liveUsers, model.SSHInboundUser{AuthorizationKey: cred.authorizationKey, UserID: cred.userID, Username: username, Password: cred.password, DeviceIDHash: cred.deviceIDHash, CredentialEpoch: cred.credentialEpoch, CredentialStatus: cred.credentialStatus, PathID: cred.pathID, RouteKind: cred.routeKind, RouteInboundTag: cred.routeInboundTag, RouteAuthUser: cred.routeAuthUser, Enabled: true})
				}
				live.authMu.RUnlock()
				tmp := live.plan
				tmp.Users = liveUsers
				if live.listener != nil {
					if addr, ok := live.listener.Addr().(*net.TCPAddr); ok {
						tmp.ListenIP = addr.IP.String()
						tmp.Port = addr.Port
					}
				}
				liveFP := sshInboundFingerprint(tmp)
				drift = desiredFP != liveFP
			}
			diag.Inbounds = append(diag.Inbounds, sshInboundDiagnostics{
				InboundID:       id,
				Listener:        listenerStatus,
				DesiredUsers:    desiredUsers,
				RuntimeUsers:    runtimeUsers,
				CredentialDrift: drift,
				PolicyDrift:     false,
				CounterDrift:    false,
			})
		}
		manager.mu.RUnlock()
	}
	// Add desired inbounds that have no live listener
	for id, desired := range desiredMap {
		found := false
		for _, d := range diag.Inbounds {
			if d.InboundID == id {
				found = true
				break
			}
		}
		if !found {
			desiredUsers := 0
			for _, u := range desired.Users {
				if u.Enabled {
					desiredUsers++
				}
			}
			diag.Inbounds = append(diag.Inbounds, sshInboundDiagnostics{
				InboundID:       id,
				Listener:        "missing",
				DesiredUsers:    desiredUsers,
				RuntimeUsers:    0,
				CredentialDrift: true,
			})
		}
	}
	return diag
}

func (r *Runner) currentSSHDiagnostics() sshDiagnostics {
	b, err := r.stateRead(sshInboundsCurrent)
	if err != nil {
		return sshDiagnostics{Inbounds: []sshInboundDiagnostics{}}
	}
	var plan model.SSHInboundPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return sshDiagnostics{Inbounds: []sshInboundDiagnostics{}}
	}
	return r.sshDiagnostics(plan)
}

func (r *Runner) applySSHInbounds(plan model.SSHInboundPlan) (result sshInboundApplyResult, applyErr error) {
	r.sshInboundLifecycleMu.Lock()
	defer r.sshInboundLifecycleMu.Unlock()

	result = sshInboundApplyResult{SSHAuthenticationVerification: model.SSHAuthenticationVerification{Version: plan.Version}}
	previous, readErr := r.stateRead(sshInboundsCurrent)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return result, readErr
	}
	defer func() {
		if applyErr != nil {
			return
		}
		result.AuthenticatedUsers, result.RejectedUsers, applyErr = r.verifySSHAuthentication(plan)
		if applyErr == nil {
			result.AuthenticationVerified = true
			result.AuthenticationPlanDigest = model.SSHAuthenticationPlanDigest(plan)
			return
		}
		result.Unchanged = false
		fileErr := r.restoreSSHInboundPlanFile(r.statePath(sshInboundsCurrent), previous)
		runtimeErr := r.restoreSSHInboundPlanLocked(previous)
		var previousPlan model.SSHInboundPlan
		var policyErr error
		if len(previous) > 0 {
			policyErr = json.Unmarshal(previous, &previousPlan)
		}
		if runtimeErr == nil && policyErr == nil {
			policyErr = r.reconcileSSHAndCoreTrafficPolicies(context.Background(), previousPlan)
		}
		applyErr = errors.Join(applyErr, fileErr, runtimeErr, policyErr)
	}()
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return result, err
	}
	hostSigner, err := r.loadSSHInboundHostSigner()
	if err != nil {
		return result, err
	}
	result.HostPublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))
	result.HostKeyFingerprint = ssh.FingerprintSHA256(hostSigner.PublicKey())
	desiredState, err := sshInboundDesiredStateID(plan)
	if err != nil {
		return result, err
	}
	if desiredState != "" && desiredState == r.sshInboundDesiredState {
		r.mu.Lock()
		managerCheck := r.sshInboundManager
		r.mu.Unlock()
		if managerCheck != nil {
			drift := managerCheck.checkDrift(plan)
			if drift.NoDrift {
				if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
					return result, fmt.Errorf("reconcile shared core/SSH quota lease: %w", err)
				}
				result.Unchanged = true
				return result, nil
			}
			if !drift.ListenerDrift {
				// In-place reconcile without restarting listeners
				managerCheck.reconcileInPlace(plan)
				if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
					return result, fmt.Errorf("reconcile shared core/SSH quota lease: %w", err)
				}
				// Ensure persisted file matches desired
				currentPath := r.statePath(sshInboundsCurrent)
				if b, err := r.stateReadPath(currentPath); err != nil || string(b) == "" {
					if encoded, merr := json.MarshalIndent(plan, "", "  "); merr == nil {
						_ = r.stateWritePath(currentPath, encoded, 0o600)
					}
				}
				result.RuntimeReconciled = true
				components := []string{}
				if drift.CredentialDrift {
					components = append(components, "credentials")
				}
				if drift.PolicyDrift {
					components = append(components, "traffic_policy")
				}
				if len(components) == 0 {
					components = []string{"credentials", "traffic_policy"}
				}
				result.ReconciledComponents = components
				for _, inbound := range plan.Inbounds {
					if !inbound.Enabled {
						continue
					}
					result.Applied++
					result.Listeners++
					for _, user := range inbound.Users {
						if user.Enabled {
							result.Users++
						}
					}
				}
				return result, nil
			}
		} else if len(plan.Inbounds) == 0 {
			if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
				return result, fmt.Errorf("reconcile shared core/SSH quota lease: %w", err)
			}
			result.Unchanged = true
			return result, nil
		}
	}
	if err := validateSSHInboundPlan(plan); err != nil {
		return result, err
	}
	if err := r.validateSSHInboundServerIDs(plan); err != nil {
		return result, err
	}
	current := r.statePath(sshInboundsCurrent)
	backup := r.statePath(sshInboundsLastGood)
	var previousPlan []byte
	if b, err := r.stateReadPath(current); err == nil {
		previousPlan = b
		if err := r.stateWritePath(backup, b, 0o600); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	} else if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	if len(previousPlan) > 0 {
		var previous model.SSHInboundPlan
		r.mu.Lock()
		manager := r.sshInboundManager
		r.mu.Unlock()
		if json.Unmarshal(previousPlan, &previous) == nil && manager != nil && manager.credentialStateOnlyCompatible(plan) {
			encoded, marshalErr := json.MarshalIndent(plan, "", "  ")
			if marshalErr != nil {
				return result, marshalErr
			}
			if err := r.stateWritePath(current, encoded, 0o600); err != nil {
				return result, err
			}
			manager.applyCredentialStates(plan)
			if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
				_ = r.stateWritePath(current, previousPlan, 0o600)
				manager.applyCredentialStates(previous)
				_ = r.reconcileSSHAndCoreTrafficPolicies(context.Background(), previous)
				return result, fmt.Errorf("update SSH credential runtime state: %w", err)
			}
			r.sshInboundDesiredState = desiredState
			result.RuntimeOnly = true
			for _, inbound := range plan.Inbounds {
				if !inbound.Enabled {
					continue
				}
				result.Applied++
				result.Listeners++
				for _, user := range inbound.Users {
					if user.Enabled {
						result.Users++
					}
				}
			}
			return result, nil
		}
	}

	manager, err := r.newSSHInboundManager(plan)
	if err != nil {
		return result, err
	}
	old := r.swapSSHInboundManager(manager)
	if old != nil {
		old.close()
	}
	if err := manager.start(); err != nil {
		manager.close()
		// The current manager is intentionally empty at this point. Restore the
		// last known plan so a failed update never leaves an old inbound exposed.
		if rollbackErr := r.restoreLastGoodSSHInboundsLocked(); rollbackErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("restore last-good SSH inbounds: %v", rollbackErr))
		}
		return result, err
	}

	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		manager.close()
		_ = r.restoreLastGoodSSHInboundsLocked()
		return result, err
	}
	if err := r.stateWritePath(current, b, 0o600); err != nil {
		manager.close()
		if rollbackErr := r.restoreLastGoodSSHInboundsLocked(); rollbackErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("restore last-good SSH inbounds: %v", rollbackErr))
		}
		return result, err
	}
	r.sshInboundDesiredState = desiredState
	if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
		rollbackErr := r.restoreSSHInboundPlanFile(current, previousPlan)
		if managerErr := r.restoreSSHInboundPlanLocked(previousPlan); managerErr != nil {
			if rollbackErr == nil {
				rollbackErr = managerErr
			} else {
				rollbackErr = fmt.Errorf("restore plan file: %v; restore runtime: %w", rollbackErr, managerErr)
			}
		}
		if rollbackErr != nil {
			return result, fmt.Errorf("reconcile shared core/SSH quota lease: %w; rollback SSH inbounds: %v", err, rollbackErr)
		}
		return result, fmt.Errorf("reconcile shared core/SSH quota lease: %w", err)
	}
	for _, inbound := range plan.Inbounds {
		if !inbound.Enabled {
			continue
		}
		result.Applied++
		result.Listeners++
		for _, user := range inbound.Users {
			if user.Enabled {
				result.Users++
			}
		}
	}
	return result, nil
}

func (r *Runner) restoreManagedSSHInboundsOnStartup() error {
	r.sshInboundLifecycleMu.Lock()
	defer r.sshInboundLifecycleMu.Unlock()
	b, err := r.stateRead(sshInboundsCurrent)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var plan model.SSHInboundPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	if err := validateSSHInboundPlan(plan); err != nil {
		return fmt.Errorf("validate persisted SSH inbounds: %w", err)
	}
	if err := r.validateSSHInboundServerIDs(plan); err != nil {
		return err
	}
	manager, err := r.newSSHInboundManager(plan)
	if err != nil {
		return err
	}
	old := r.swapSSHInboundManager(manager)
	if old != nil {
		old.close()
	}
	if err := manager.start(); err != nil {
		manager.close()
		return err
	}
	desiredState, err := sshInboundDesiredStateID(plan)
	if err != nil {
		manager.close()
		return err
	}
	r.sshInboundDesiredState = desiredState
	if err := r.reconcileSSHAndCoreTrafficPolicies(context.Background(), plan); err != nil {
		// The listeners are already serving authorized users; only the shared
		// kernel quota lease is behind, and on startup the core has usually not
		// finished starting yet. Closing the manager here would take every
		// restricted SSH user offline until the next deployment, so keep it
		// running and converge the lease once the core API answers.
		pending := plan
		r.sshInboundPendingPolicyPlan = &pending
		logging.Warnf("SSH inbounds restored, shared core/SSH quota lease reconcile deferred: %v", err)
	}
	return nil
}

// retrySSHInboundPolicyReconcile converges a startup quota lease reconcile that
// was deferred because the core API was unreachable. It reports whether work is
// still pending.
func (r *Runner) retrySSHInboundPolicyReconcile(ctx context.Context) (bool, error) {
	r.sshInboundLifecycleMu.Lock()
	defer r.sshInboundLifecycleMu.Unlock()
	plan := r.sshInboundPendingPolicyPlan
	if plan == nil {
		return false, nil
	}
	desiredState, err := sshInboundDesiredStateID(*plan)
	if err != nil || desiredState != r.sshInboundDesiredState {
		// A deployment already replaced this plan and ran its own reconcile.
		r.sshInboundPendingPolicyPlan = nil
		return false, nil
	}
	if err := r.reconcileSSHAndCoreTrafficPolicies(ctx, *plan); err != nil {
		return true, err
	}
	r.sshInboundPendingPolicyPlan = nil
	logging.Infof("SSH inbounds: deferred shared core/SSH quota lease reconcile succeeded")
	return false, nil
}

func (r *Runner) sshInboundPolicyReconcilePending() bool {
	r.sshInboundLifecycleMu.Lock()
	defer r.sshInboundLifecycleMu.Unlock()
	return r.sshInboundPendingPolicyPlan != nil
}

func (r *Runner) startSSHInboundPolicyReconciler(ctx context.Context) {
	ticker := time.NewTicker(sshInboundPolicyRetryInterval)
	defer ticker.Stop()
	attempts := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pending, err := r.retrySSHInboundPolicyReconcile(ctx)
			if !pending {
				return
			}
			attempts++
			if attempts%20 == 0 {
				logging.Warnf("SSH inbounds: shared core/SSH quota lease reconcile still failing after %d attempts: %v", attempts, err)
			}
		}
	}
}

func (r *Runner) validateSSHInboundServerIDs(plan model.SSHInboundPlan) error {
	serverID := r.Config().ServerID
	if serverID == 0 {
		return nil
	}
	for _, inbound := range plan.Inbounds {
		if inbound.ServerID != serverID {
			return fmt.Errorf("SSH inbound %d belongs to server %d, enrolled server is %d", inbound.InboundID, inbound.ServerID, serverID)
		}
	}
	return nil
}

func (r *Runner) restoreLastGoodSSHInboundsLocked() error {
	path := r.statePath(sshInboundsLastGood)
	b, err := r.stateReadPath(path)
	if errors.Is(err, os.ErrNotExist) {
		return r.restoreSSHInboundPlanLocked(nil)
	}
	if err != nil {
		return err
	}
	return r.restoreSSHInboundPlanLocked(b)
}

func (r *Runner) restoreSSHInboundPlanLocked(b []byte) error {
	if len(b) == 0 {
		old := r.swapSSHInboundManager(nil)
		if old != nil {
			old.close()
		}
		r.sshInboundDesiredState = ""
		return nil
	}
	var plan model.SSHInboundPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		return err
	}
	if err := validateSSHInboundPlan(plan); err != nil {
		return err
	}
	if err := r.validateSSHInboundServerIDs(plan); err != nil {
		return err
	}
	manager, err := r.newSSHInboundManager(plan)
	if err != nil {
		return err
	}
	old := r.swapSSHInboundManager(manager)
	if old != nil {
		old.close()
	}
	if err := manager.start(); err != nil {
		manager.close()
		return err
	}
	desiredState, err := sshInboundDesiredStateID(plan)
	if err != nil {
		manager.close()
		return err
	}
	r.sshInboundDesiredState = desiredState
	return nil
}

func (r *Runner) restoreSSHInboundPlanFile(path string, plan []byte) error {
	if len(plan) > 0 {
		return r.stateWritePath(path, plan, 0o600)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (r *Runner) swapSSHInboundManager(next *sshInboundManager) *sshInboundManager {
	r.mu.Lock()
	current := r.sshInboundManager
	r.mu.Unlock()
	if current != nil {
		_ = r.persistTrafficCheckpointBeforeRuntimeTransition(context.Background())
	}
	r.mu.Lock()
	old := r.sshInboundManager
	r.sshInboundManager = next
	r.mu.Unlock()
	return old
}

func (r *Runner) reconcileSSHAndCoreTrafficPolicies(ctx context.Context, plan model.SSHInboundPlan) error {
	policies := collectSSHInboundTrafficPolicies(plan)
	explicitUsers := runtimePolicyUsers(policies)
	corePolicies, err := r.currentCoreTrafficPolicies()
	if err != nil {
		return err
	}
	for key, policy := range corePolicies {
		if explicitUsers[policy.UserID] {
			continue
		}
		policies["core:"+key] = policy
	}
	if len(policies) == 0 {
		return nil
	}
	return r.pushTrafficPolicies(ctx, policies, r.trafficAcknowledgements())
}

func collectSSHInboundTrafficPolicies(plan model.SSHInboundPlan) map[string]interface{} {
	policies := map[string]interface{}{}
	for _, inbound := range plan.Inbounds {
		for key, policy := range inbound.Policies {
			policies[fmt.Sprintf("ssh-inbound:%d:%s", inbound.InboundID, key)] = policy
		}
	}
	return policies
}

func runtimePolicyUsers(policies map[string]interface{}) map[int64]bool {
	users := map[int64]bool{}
	for _, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		var policy model.TrafficRuntimePolicy
		if json.Unmarshal(encoded, &policy) == nil && policy.UserID > 0 {
			users[policy.UserID] = true
		}
	}
	return users
}

func (r *Runner) newSSHInboundManager(plan model.SSHInboundPlan) (*sshInboundManager, error) {
	plan, err := r.partitionSSHInboundPlanPolicies(plan)
	if err != nil {
		return nil, err
	}
	signer, err := r.loadSSHInboundHostSigner()
	if err != nil {
		return nil, err
	}
	needsRelay := false
	for _, inbound := range plan.Inbounds {
		for _, user := range inbound.Users {
			needsRelay = needsRelay || user.Enabled
		}
	}
	if needsRelay {
		if err := r.validateRouteRelayCapability(context.Background()); err != nil {
			return nil, err
		}
	}
	manager := &sshInboundManager{listeners: make(map[int64]*managedSSHInbound), signer: signer, usage: map[int64]*sshInboundUserUsage{}}
	for _, planInbound := range plan.Inbounds {
		if !planInbound.Enabled {
			continue
		}
		inbound, err := newManagedSSHInbound(planInbound, manager.usage, r.connectionAudit, r.dialSSHRouteRelay)
		if err != nil {
			return nil, err
		}
		inbound.authorizationAllows = r.authorizationAllows
		inbound.offlineAllows = r.authorizationOfflineAllows
		for userID, counter := range inbound.counters {
			counter.offlineAllows = func() bool { return inbound.offlineForUser(userID) }
		}
		manager.listeners[planInbound.InboundID] = inbound
	}
	return manager, nil
}

func (m *sshInboundManager) credentialStateOnlyCompatible(plan model.SSHInboundPlan) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	enabled := 0
	for _, planned := range plan.Inbounds {
		if !planned.Enabled {
			continue
		}
		enabled++
		current := m.listeners[planned.InboundID]
		if current == nil || current.plan.InboundID != planned.InboundID || current.plan.ServerID != planned.ServerID || current.plan.Name != planned.Name || current.plan.ListenIP != planned.ListenIP || current.plan.Address != planned.Address || current.plan.Port != planned.Port || current.plan.Enabled != planned.Enabled {
			return false
		}
	}
	return enabled == len(m.listeners)
}

func (m *sshInboundManager) applyCredentialStates(plan model.SSHInboundPlan) {
	if m == nil {
		return
	}
	m.mu.RLock()
	defer func() { m.mu.RUnlock(); m.reapAuthorization() }()
	for _, planned := range plan.Inbounds {
		current := m.listeners[planned.InboundID]
		if current == nil || !planned.Enabled {
			continue
		}
		wanted := sshInboundCredentials(planned.Users)
		current.authMu.Lock()
		current.auth = wanted
		current.plan = planned
		current.authMu.Unlock()
		m.ensureSSHInboundCounters(current, planned)
	}
}

func (m *sshInboundManager) ensureSSHInboundCounters(inbound *managedSSHInbound, planned model.SSHInbound) {
	if inbound == nil {
		return
	}
	if inbound.counters == nil {
		inbound.counters = map[int64]*sshInboundCounter{}
	}
	if m.usage == nil {
		m.usage = map[int64]*sshInboundUserUsage{}
	}
	for _, user := range planned.Users {
		if !user.Enabled || inbound.counters[user.UserID] != nil {
			continue
		}
		usage := m.usage[user.UserID]
		if usage == nil {
			usage = &sshInboundUserUsage{periods: map[string]*sshInboundUsagePeriod{}}
			m.usage[user.UserID] = usage
		}
		inbound.counters[user.UserID] = &sshInboundCounter{epoch: newTrafficCounterEpoch(), usage: usage, offlineAllows: func() bool { return inbound.offlineForUser(user.UserID) }}
	}
}

func sshInboundCredentials(users []model.SSHInboundUser) map[string]sshInboundCredential {
	out := map[string]sshInboundCredential{}
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		status := strings.TrimSpace(user.CredentialStatus)
		if status == "" {
			status = "active"
		}
		out[user.Username] = sshInboundCredential{authorizationKey: user.AuthorizationKey, userID: user.UserID, password: user.Password, deviceIDHash: strings.TrimSpace(user.DeviceIDHash), credentialEpoch: user.CredentialEpoch, credentialStatus: status, pathID: user.PathID, routeKind: user.RouteKind, routeInboundTag: user.RouteInboundTag, routeAuthUser: user.RouteAuthUser}
	}
	return out
}

func (r *Runner) partitionSSHInboundPlanPolicies(plan model.SSHInboundPlan) (model.SSHInboundPlan, error) {
	coreUsers, err := r.currentCoreTrafficPolicyUsers()
	if err != nil {
		return model.SSHInboundPlan{}, err
	}
	plan.Inbounds = append([]model.SSHInbound(nil), plan.Inbounds...)
	for index := range plan.Inbounds {
		policies := make(map[string]model.TrafficRuntimePolicy, len(plan.Inbounds[index].Policies))
		for key, policy := range plan.Inbounds[index].Policies {
			if coreUsers[policy.UserID] && policy.LeaseEnforced {
				policy.LeaseBytes /= 2
				policy.ResetLeaseBytes /= 2
			}
			policies[key] = policy
		}
		plan.Inbounds[index].Policies = policies
	}
	return plan, nil
}

func (r *Runner) loadSSHInboundHostSigner() (ssh.Signer, error) {
	path := r.statePath(sshInboundHostKey)
	if b, err := r.stateReadPath(path); err == nil {
		return ssh.ParsePrivateKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if err := r.stateWritePath(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(pemBytes)
}

func validateSSHInboundPlan(plan model.SSHInboundPlan) error {
	seenIDs := map[int64]struct{}{}
	seenEndpoints := map[string]struct{}{}
	for _, inbound := range plan.Inbounds {
		if inbound.InboundID <= 0 {
			return errors.New("SSH inbound requires a valid inbound_id")
		}
		if _, exists := seenIDs[inbound.InboundID]; exists {
			return fmt.Errorf("SSH inbound_id %d is duplicated", inbound.InboundID)
		}
		seenIDs[inbound.InboundID] = struct{}{}
		if inbound.ServerID <= 0 {
			return fmt.Errorf("SSH inbound %d requires a valid server_id", inbound.InboundID)
		}
		if !inbound.Enabled {
			continue
		}
		if inbound.Port < 1 || inbound.Port > 65535 {
			return fmt.Errorf("SSH inbound %d has invalid port", inbound.InboundID)
		}
		listenIP := strings.TrimSpace(inbound.ListenIP)
		if listenIP == "" {
			listenIP = "0.0.0.0"
		}
		if net.ParseIP(listenIP) == nil {
			return fmt.Errorf("SSH inbound %d has invalid listen_ip", inbound.InboundID)
		}
		endpoint := net.JoinHostPort(listenIP, strconv.Itoa(inbound.Port))
		if _, exists := seenEndpoints[endpoint]; exists {
			return fmt.Errorf("SSH inbound listener %s is duplicated", endpoint)
		}
		seenEndpoints[endpoint] = struct{}{}
		seenUsers := map[string]struct{}{}
		for _, user := range inbound.Users {
			if !user.Enabled {
				continue
			}
			if user.UserID <= 0 || !validSSHInboundUsername(user.Username) {
				return fmt.Errorf("SSH inbound %d has an invalid user", inbound.InboundID)
			}
			if _, exists := seenUsers[user.Username]; exists {
				return fmt.Errorf("SSH inbound %d repeats username %q", inbound.InboundID, user.Username)
			}
			seenUsers[user.Username] = struct{}{}
			if strings.TrimSpace(user.Password) == "" {
				return fmt.Errorf("SSH inbound user %q has no password", user.Username)
			}
			deviceIDHash := strings.TrimSpace(user.DeviceIDHash)
			credentialStatus := strings.TrimSpace(user.CredentialStatus)
			if credentialStatus == "" {
				credentialStatus = "active"
			}
			if deviceIDHash == "" {
				if user.CredentialEpoch != 0 {
					return fmt.Errorf("SSH inbound legacy user %q has invalid device credential metadata", user.Username)
				}
			} else if !sshDeviceIDHashPattern.MatchString(deviceIDHash) || user.CredentialEpoch <= 0 {
				return fmt.Errorf("SSH inbound user %q has invalid device credential metadata", user.Username)
			}
			// Credential status is authorization state, not device identity: an
			// access change stages every candidate credential as reject_new,
			// including an account that owns no device-bound credential.
			switch credentialStatus {
			case "active", "reject_new", "disconnect_and_reject", "revoked", "disabled":
			default:
				return fmt.Errorf("SSH inbound user %q has invalid credential_status", user.Username)
			}
			if user.PathID <= 0 {
				return fmt.Errorf("SSH inbound user %q has no path_id", user.Username)
			}
			if user.RouteKind != "kernel" || strings.TrimSpace(user.OutboundTag) != "" {
				return fmt.Errorf("SSH inbound user %q has an invalid route_kind", user.Username)
			}
			if !sshRouteInboundPattern.MatchString(strings.TrimSpace(user.RouteInboundTag)) {
				return fmt.Errorf("SSH inbound user %q has an invalid route inbound tag", user.Username)
			}
			if !sshRouteAuthUserPattern.MatchString(user.RouteAuthUser) || user.RouteAuthUser != user.Username || len(user.AuthorizationKey) != 32 {
				return fmt.Errorf("SSH inbound user %q has an invalid route auth user", user.Username)
			}
		}
	}
	return nil
}

func validSSHInboundUsername(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func newManagedSSHInbound(plan model.SSHInbound, usageByUser map[int64]*sshInboundUserUsage, audit *connectionAuditAccumulator, routeDial routeRelayDialFunc) (*managedSSHInbound, error) {
	inbound := &managedSSHInbound{plan: plan, auth: sshInboundCredentials(plan.Users), counters: map[int64]*sshInboundCounter{}, audit: audit, routeDial: routeDial, conns: map[net.Conn]int64{}}
	for _, user := range plan.Users {
		if !user.Enabled {
			continue
		}
		usage := usageByUser[user.UserID]
		if usage == nil {
			usage = &sshInboundUserUsage{periods: map[string]*sshInboundUsagePeriod{}}
			usageByUser[user.UserID] = usage
		}
		counter := &sshInboundCounter{epoch: newTrafficCounterEpoch(), usage: usage, offlineAllows: func() bool { return inbound.offlineForUser(user.UserID) }}
		if policy, ok := sshInboundPolicyForUser(plan.Policies, user.UserID); ok {
			counter.setPolicy(policy)
		}
		inbound.counters[user.UserID] = counter
	}
	return inbound, nil
}

func sshInboundPolicyForUser(policies map[string]model.TrafficRuntimePolicy, userID int64) (model.TrafficRuntimePolicy, bool) {
	for key, policy := range policies {
		if policy.UserID == userID || key == fmt.Sprintf("user:%d", userID) || key == strconv.FormatInt(userID, 10) {
			policy.UserID = userID
			return policy, true
		}
	}
	return model.TrafficRuntimePolicy{}, false
}

func (m *sshInboundManager) start() error {
	for _, inbound := range m.listeners {
		listenIP := strings.TrimSpace(inbound.plan.ListenIP)
		if listenIP == "" {
			listenIP = "0.0.0.0"
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(listenIP, strconv.Itoa(inbound.plan.Port)))
		if err != nil {
			m.close()
			return fmt.Errorf("listen SSH inbound %q: %w", inbound.plan.Name, err)
		}
		inbound.listener = listener
		go inbound.serve(listener, m.signer)
	}
	return nil
}

func (m *sshInboundManager) close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	inbounds := make([]*managedSSHInbound, 0, len(m.listeners))
	for _, inbound := range m.listeners {
		inbounds = append(inbounds, inbound)
	}
	m.mu.Unlock()
	for _, inbound := range inbounds {
		inbound.close()
	}
}

func (m *managedSSHInbound) close() {
	m.mu.Lock()
	listener := m.listener
	m.listener = nil
	connections := make([]net.Conn, 0, len(m.conns))
	for conn := range m.conns {
		connections = append(connections, conn)
	}
	m.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (m *managedSSHInbound) serve(listener net.Listener, signer ssh.Signer) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		m.conns[conn] = 0
		m.mu.Unlock()
		go func(raw net.Conn) {
			defer func() {
				m.mu.Lock()
				delete(m.conns, raw)
				m.mu.Unlock()
				_ = raw.Close()
			}()
			m.handle(raw, signer)
		}(conn)
	}
}

func logSSHAuthFailure(inboundID, userID int64, username, reason string) {
	// Structured internal reason, never log password/token
	// Use fmt for diagnostics; real deployment may hook into audit log
	_ = fmt.Sprintf("ssh auth failure inbound=%d user=%d username=%s reason=%s time=%s", inboundID, userID, username, reason, time.Now().UTC().Format(time.RFC3339Nano))
}

func (m *managedSSHInbound) handle(raw net.Conn, signer ssh.Signer) {
	serverConfig := &ssh.ServerConfig{ServerVersion: "SSH-2.0-OBoard-RestrictedSSH"}
	serverConfig.PasswordCallback = func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		m.mu.Lock()
		probe := m.probes[metadata.RemoteAddr().String()]
		m.mu.Unlock()
		observation := sshAuthenticationObservation{Reason: "credential_mismatch"}
		if probe != nil {
			defer func() {
				select {
				case probe <- observation:
				default:
				}
			}()
		}
		m.authMu.RLock()
		credential, ok := m.auth[metadata.User()]
		m.authMu.RUnlock()
		if !ok {
			logSSHAuthFailure(m.plan.InboundID, 0, metadata.User(), "unknown_user")
			return nil, errors.New("password is not authorized")
		}
		if subtle.ConstantTimeCompare([]byte(credential.password), password) != 1 {
			logSSHAuthFailure(m.plan.InboundID, credential.userID, metadata.User(), "password_mismatch")
			return nil, errors.New("password is not authorized")
		}
		observation.CredentialMatched = true
		observation.Reason = "authorization_denied"
		if credential.credentialStatus != "active" {
			observation.Reason = "credential_inactive"
		}
		if !m.credentialAuthorized(credential, false) {
			if probe == nil {
				m.audit.recordCredentialRejected(connectionAuditSnapshotItem{UserID: credential.userID, InboundID: m.plan.InboundID, PathID: credential.pathID, DeviceIDHash: credential.deviceIDHash, CredentialEpoch: credential.credentialEpoch, SourceIP: sourceIPFromNetAddr(metadata.RemoteAddr()), Network: "tcp"})
			}
			logSSHAuthFailure(m.plan.InboundID, credential.userID, metadata.User(), "credential_inactive")
			return nil, errors.New("password is not authorized")
		}
		counter := m.counterFor(credential.userID)
		observation.Reason = "policy_missing"
		if counter == nil {
			logSSHAuthFailure(m.plan.InboundID, credential.userID, metadata.User(), "policy_missing")
			return nil, errors.New("user traffic quota is exhausted")
		}
		observation.Reason = "quota_exhausted"
		if !counter.allowNewConnection() {
			logSSHAuthFailure(m.plan.InboundID, credential.userID, metadata.User(), "quota_exhausted")
			return nil, errors.New("user traffic quota is exhausted")
		}
		observation.Reason = ""
		return &ssh.Permissions{Extensions: map[string]string{
			"oboard_user_id":       strconv.FormatInt(credential.userID, 10),
			"oboard_inbound_id":    strconv.FormatInt(m.plan.InboundID, 10),
			"oboard_path_id":       strconv.FormatInt(credential.pathID, 10),
			"oboard_device_id":     credential.deviceIDHash,
			"oboard_device_epoch":  strconv.FormatInt(credential.credentialEpoch, 10),
			"oboard_route_kind":    credential.routeKind,
			"oboard_route_inbound": credential.routeInboundTag,
			"oboard_route_user":    credential.routeAuthUser,
		}}, nil
	}
	serverConfig.AddHostKey(signer)
	connection, channels, requests, err := ssh.NewServerConn(raw, serverConfig)
	if err != nil {
		return
	}
	defer connection.Close()
	m.mu.Lock()
	if m.sessions == nil {
		m.sessions = map[*ssh.ServerConn]string{}
	}
	m.sessions[connection] = connection.User()
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.sessions, connection); m.mu.Unlock() }()
	done := make(chan struct{})
	defer close(done)
	go m.watchAuthorization(connection, done)
	if !m.sessionAuthorized(connection.User()) {
		return
	}
	if connection.Permissions != nil {
		if userID, parseErr := strconv.ParseInt(connection.Permissions.Extensions["oboard_user_id"], 10, 64); parseErr == nil && userID > 0 {
			m.mu.Lock()
			if _, ok := m.conns[raw]; ok {
				m.conns[raw] = userID
			}
			m.mu.Unlock()
		}
	}
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only direct-tcpip forwarding is permitted")
			continue
		}
		m.handleDirectTCPIP(connection, newChannel)
	}
}

func (m *managedSSHInbound) handleDirectTCPIP(connection *ssh.ServerConn, newChannel ssh.NewChannel) {
	if !m.sessionAuthorized(connection.User()) {
		_ = newChannel.Reject(ssh.Prohibited, "authorization expired")
		_ = connection.Close()
		return
	}
	if connection.Permissions == nil {
		_ = newChannel.Reject(ssh.Prohibited, "missing authenticated OBoard user")
		return
	}
	userID, err := strconv.ParseInt(connection.Permissions.Extensions["oboard_user_id"], 10, 64)
	if err != nil || userID <= 0 {
		_ = newChannel.Reject(ssh.Prohibited, "invalid authenticated OBoard user")
		return
	}
	pathID, err := strconv.ParseInt(connection.Permissions.Extensions["oboard_path_id"], 10, 64)
	if err != nil || pathID <= 0 {
		_ = newChannel.Reject(ssh.Prohibited, "invalid authenticated OBoard path")
		return
	}
	deviceIDHash := strings.TrimSpace(connection.Permissions.Extensions["oboard_device_id"])
	credentialEpoch, err := strconv.ParseInt(connection.Permissions.Extensions["oboard_device_epoch"], 10, 64)
	if err != nil || credentialEpoch < 0 || deviceIDHash == "" && credentialEpoch != 0 || deviceIDHash != "" && credentialEpoch <= 0 {
		_ = newChannel.Reject(ssh.Prohibited, "invalid authenticated OBoard device")
		return
	}
	routeKind := connection.Permissions.Extensions["oboard_route_kind"]
	routeInboundTag := connection.Permissions.Extensions["oboard_route_inbound"]
	routeAuthUser := connection.Permissions.Extensions["oboard_route_user"]
	counter := m.counterFor(userID)
	if counter == nil || !counter.allowNewConnection() {
		_ = newChannel.Reject(ssh.Prohibited, "user traffic quota is exhausted")
		return
	}
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "invalid direct-tcpip request")
		return
	}
	if isBadVPNUDPGatewayDestination(payload.DestAddr, payload.DestPort) {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go ssh.DiscardRequests(requests)
		dial := func(ctx context.Context, destination netip.AddrPort) (badVPNPacketConn, error) {
			return m.routeDial(ctx, "udp", routeInboundTag, routeAuthUser, destination.String(), []netip.Addr{destination.Addr()})
		}
		go serveBadVPNUDPGateway(channel, counter, m.audit, userID, m.plan.InboundID, pathID, deviceIDHash, credentialEpoch, "kernel-route", sourceIPFromNetAddr(connection.RemoteAddr()), dial)
		return
	}
	addresses, err := resolvePermittedSSHDestination(context.Background(), payload.DestAddr, payload.DestPort)
	if err != nil {
		_ = newChannel.Reject(ssh.Prohibited, err.Error())
		return
	}
	var target net.Conn
	if routeKind == "kernel" && m.routeDial != nil {
		destination := net.JoinHostPort(strings.TrimSpace(payload.DestAddr), strconv.FormatUint(uint64(payload.DestPort), 10))
		target, err = m.routeDial(context.Background(), "tcp", routeInboundTag, routeAuthUser, destination, addresses)
	} else {
		err = errors.New("authenticated SSH route is unavailable")
	}
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "destination connection failed")
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	auditSession := m.audit.startSession(connectionAuditSnapshotItem{
		UserID:          userID,
		InboundID:       m.plan.InboundID,
		PathID:          pathID,
		DeviceIDHash:    deviceIDHash,
		CredentialEpoch: credentialEpoch,
		SourceIP:        sourceIPFromNetAddr(connection.RemoteAddr()),
		Network:         "tcp",
	})
	go func() {
		defer auditSession.finish()
		proxySSHDirectTCPIP(channel, target, counter, auditSession)
	}()
}

func dialSSHRelayAddresses(ctx context.Context, dial outboundRelayDialFunc, outboundTag string, addresses []netip.Addr, port uint32) (net.Conn, error) {
	var lastErr error
	for _, address := range addresses {
		conn, err := dial(ctx, "tcp", outboundTag, net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no permitted destination addresses")
	}
	return nil, lastErr
}

func (m *managedSSHInbound) counterFor(userID int64) *sshInboundCounter {
	return m.counters[userID]
}

func resolvePermittedSSHDestination(ctx context.Context, host string, port uint32) ([]netip.Addr, error) {
	host = strings.TrimSpace(host)
	if host == "" || port == 0 || port > 65535 {
		return nil, errors.New("invalid destination")
	}
	if parsed, err := netip.ParseAddr(host); err == nil {
		parsed = parsed.Unmap()
		if !isPermittedSSHDestination(parsed) {
			return nil, errors.New("destination is not allowed")
		}
		return []netip.Addr{parsed}, nil
	}
	if !validSSHInboundHostname(host) {
		return nil, errors.New("invalid destination hostname")
	}
	resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(resolved) == 0 {
		return nil, errors.New("destination hostname could not be resolved")
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, address := range resolved {
		address = address.Unmap()
		if !isPermittedSSHDestination(address) {
			return nil, errors.New("destination is not allowed")
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func validSSHInboundHostname(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

var blockedSSHDestinationPrefixes = func() []netip.Prefix {
	prefixes := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"2001:2::/48", "2001:10::/28", "2001:db8::/32",
	}
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, raw := range prefixes {
		prefix := netip.MustParsePrefix(raw)
		prefix = prefix.Masked()
		out = append(out, prefix)
	}
	return out
}()

func isPermittedSSHDestination(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return false
	}
	for _, prefix := range blockedSSHDestinationPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func dialPermittedSSHAddresses(ctx context.Context, addresses []netip.Addr, port uint32) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, address := range addresses {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no permitted destination addresses")
	}
	return nil, lastErr
}

func proxySSHDirectTCPIP(channel ssh.Channel, target net.Conn, counter *sshInboundCounter, auditSession *connectionAuditSession) {
	defer channel.Close()
	defer target.Close()
	done := make(chan struct{}, 2)
	go func() {
		copySSHInboundTraffic(target, channel, counter, auditSession, true)
		_ = target.Close()
		done <- struct{}{}
	}()
	go func() {
		copySSHInboundTraffic(channel, target, counter, auditSession, false)
		_ = channel.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func copySSHInboundTraffic(dst io.Writer, src io.Reader, counter *sshInboundCounter, auditSession *connectionAuditSession, upload bool) {
	buffer := make([]byte, sshInboundIOChunk)
	for {
		if !counter.allowTransfer() {
			return
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			counter.addTraffic(upload, int64(written))
			auditSession.addTraffic(upload, int64(written))
			if writeErr != nil || written != n {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

func (c *sshInboundCounter) setPolicy(policy model.TrafficRuntimePolicy) {
	c.mu.Lock()
	previous := c.policy
	periodChanged := previous.PeriodKey != "" && policy.PeriodKey != "" && previous.PeriodKey != policy.PeriodKey
	if periodChanged && (policy.PreviousPeriodKey == "" || policy.PreviousPeriodKey != previous.PeriodKey) {
		c.resetCountersLocked()
	}
	c.policy = policy
	c.mu.Unlock()
}

func (c *sshInboundCounter) resetCountersLocked() {
	c.epoch = newTrafficCounterEpoch()
	c.upload.Store(0)
	c.download.Store(0)
	c.acknowledgedUpload.Store(0)
	c.acknowledgedDownload.Store(0)
}

func (c *sshInboundCounter) currentPolicy() model.TrafficRuntimePolicy {
	c.mu.RLock()
	policy := c.policy
	c.mu.RUnlock()
	if !trafficPolicyExpired(policy, time.Now()) {
		return policy
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	policy = c.policy
	if !trafficPolicyExpired(policy, time.Now()) {
		return policy
	}
	loc := time.FixedZone("Asia/Shanghai", 8*60*60)
	if policy.Timezone != "" {
		if loaded, err := time.LoadLocation(policy.Timezone); err == nil {
			loc = loaded
		}
	}
	previousPeriod := policy.PeriodKey
	anchor := time.Time{}
	if policy.ResetAnchor != "" {
		anchor, _ = time.Parse(time.RFC3339Nano, policy.ResetAnchor)
	}
	periodKey, start, end := agentTrafficWindow(time.Now(), policy.ResetMode, policy.ResetDay, anchor, loc)
	resetCounters := policy.PeriodKey != periodKey && (policy.PreviousPeriodKey == "" || policy.PreviousPeriodKey != previousPeriod)
	if resetCounters {
		c.resetCountersLocked()
	}
	policy.PeriodKey = periodKey
	policy.PeriodStart = start.UTC().Format(time.RFC3339Nano)
	policy.PeriodEnd = end.UTC().Format(time.RFC3339Nano)
	policy.UsedBaselineBytes = 0
	if policy.LeaseEnforced {
		policy.LeaseBytes = policy.ResetLeaseBytes
	}
	policy.QuotaState = "active"
	c.policy = policy
	return policy
}

func trafficPolicyExpired(policy model.TrafficRuntimePolicy, now time.Time) bool {
	if policy.PeriodEnd == "" {
		return false
	}
	end, err := time.Parse(time.RFC3339Nano, policy.PeriodEnd)
	return err == nil && !now.Before(end)
}

func agentTrafficWindow(now time.Time, mode string, day int, anchor time.Time, loc *time.Location) (string, time.Time, time.Time) {
	if loc == nil {
		loc = time.FixedZone("Asia/Shanghai", 8*60*60)
	}
	now = now.In(loc)
	if day < 1 {
		day = 1
	}
	if day > 31 {
		day = 31
	}
	if mode == "never" {
		if anchor.IsZero() {
			anchor = now
		}
		return anchor.UTC().Format(time.RFC3339Nano), anchor.In(loc), time.Date(9999, time.December, 31, 23, 59, 59, 0, loc)
	}
	if mode == "anniversary_month" {
		if anchor.IsZero() {
			anchor = now
		}
		start, end := agentAnniversaryWindow(now, anchor.In(loc), loc)
		return start.UTC().Format(time.RFC3339Nano), start, end
	}
	if mode != "month_day" {
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
		return start.Format("2006-01-02"), start, start.AddDate(0, 1, 0)
	}
	start := time.Date(now.Year(), now.Month(), agentClampedMonthDay(now.Year(), now.Month(), day), 0, 0, 0, 0, loc)
	if now.Before(start) {
		previous := start.AddDate(0, -1, 0)
		start = time.Date(previous.Year(), previous.Month(), agentClampedMonthDay(previous.Year(), previous.Month(), day), 0, 0, 0, 0, loc)
	}
	next := start.AddDate(0, 1, 0)
	end := time.Date(next.Year(), next.Month(), agentClampedMonthDay(next.Year(), next.Month(), day), 0, 0, 0, 0, loc)
	return start.Format("2006-01-02"), start, end
}

func agentAnniversaryWindow(now, anchor time.Time, loc *time.Location) (time.Time, time.Time) {
	if now.Before(anchor) {
		return anchor, agentAnniversaryBoundary(anchor, 1, loc)
	}
	months := (now.Year()-anchor.Year())*12 + int(now.Month()-anchor.Month())
	start := agentAnniversaryBoundary(anchor, months, loc)
	if now.Before(start) {
		months--
		start = agentAnniversaryBoundary(anchor, months, loc)
	}
	return start, agentAnniversaryBoundary(anchor, months+1, loc)
}

func agentAnniversaryBoundary(anchor time.Time, months int, loc *time.Location) time.Time {
	monthStart := time.Date(anchor.Year(), anchor.Month()+time.Month(months), 1, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), loc)
	day := agentClampedMonthDay(monthStart.Year(), monthStart.Month(), anchor.Day())
	return time.Date(monthStart.Year(), monthStart.Month(), day, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), loc)
}

func agentClampedMonthDay(year int, month time.Month, day int) int {
	last := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > last {
		return last
	}
	if day < 1 {
		return 1
	}
	return day
}

func (m *managedSSHInbound) offlineForUser(userID int64) bool {
	if m.offlineAllows == nil {
		return false
	}
	m.authMu.RLock()
	defer m.authMu.RUnlock()
	for _, credential := range m.auth {
		if credential.userID == userID && credential.credentialStatus == "active" && m.offlineAllows(credential.authorizationKey) {
			return true
		}
	}
	return false
}

func (c *sshInboundCounter) allowNewConnection() bool { return !c.quotaExceeded() }
func (c *sshInboundCounter) allowTransfer() bool {
	return !c.quotaExceeded()
}

func (c *sshInboundCounter) quotaExceeded() bool {
	policy := c.currentPolicy()
	if policy.QuotaState == "quota_exceeded" {
		return true
	}
	if policy.TrafficLimitBytes <= 0 {
		return false
	}
	capBytes := policy.TrafficLimitBytes
	if policy.LeaseEnforced && (c.offlineAllows == nil || !c.offlineAllows()) {
		leaseBytes := policy.LeaseBytes
		if leaseBytes < 0 {
			leaseBytes = 0
		}
		leaseCap := policy.UsedBaselineBytes + leaseBytes
		if leaseCap < capBytes {
			capBytes = leaseCap
		}
	}
	return policy.UsedBaselineBytes+c.unacknowledged(policy.PeriodKey) >= capBytes
}

func (c *sshInboundCounter) addTraffic(upload bool, bytes int64) {
	if bytes <= 0 {
		return
	}
	policy := c.currentPolicy()
	if upload {
		c.upload.Add(bytes)
	} else {
		c.download.Add(bytes)
	}
	if c.usage != nil {
		period := c.usage.period(policy.PeriodKey)
		if upload {
			period.upload.Add(bytes)
		} else {
			period.download.Add(bytes)
		}
	}
}

func (c *sshInboundCounter) acknowledge(checkpoint trafficCounterCheckpoint) {
	if c == nil || checkpoint.PeriodKey == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.policy.PeriodKey != checkpoint.PeriodKey {
		return
	}
	if checkpoint.CounterEpoch != "" && checkpoint.CounterEpoch != c.epoch {
		return
	}
	upload := minInt64(checkpoint.Upload, c.upload.Load())
	download := minInt64(checkpoint.Download, c.download.Load())
	if upload < 0 {
		upload = 0
	}
	if download < 0 {
		download = 0
	}
	previousUpload := c.acknowledgedUpload.Load()
	previousDownload := c.acknowledgedDownload.Load()
	if upload < previousUpload {
		upload = previousUpload
	}
	if download < previousDownload {
		download = previousDownload
	}
	c.acknowledgedUpload.Store(upload)
	c.acknowledgedDownload.Store(download)
	if c.usage != nil {
		period := c.usage.period(checkpoint.PeriodKey)
		period.acknowledgedUpload.Add(upload - previousUpload)
		period.acknowledgedDownload.Add(download - previousDownload)
	}
}

func (c *sshInboundCounter) unacknowledged(periodKey string) int64 {
	if c.usage != nil {
		return c.usage.period(periodKey).unacknowledged()
	}
	return positiveDifference(c.upload.Load(), c.acknowledgedUpload.Load()) + positiveDifference(c.download.Load(), c.acknowledgedDownload.Load())
}

func (u *sshInboundUserUsage) period(periodKey string) *sshInboundUsagePeriod {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.periods == nil {
		u.periods = map[string]*sshInboundUsagePeriod{}
	}
	period := u.periods[periodKey]
	if period == nil {
		period = &sshInboundUsagePeriod{}
		u.periods[periodKey] = period
	}
	return period
}

func (p *sshInboundUsagePeriod) unacknowledged() int64 {
	return positiveDifference(p.upload.Load(), p.acknowledgedUpload.Load()) + positiveDifference(p.download.Load(), p.acknowledgedDownload.Load())
}

func positiveDifference(total, acknowledged int64) int64 {
	if total <= acknowledged {
		return 0
	}
	return total - acknowledged
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func (m *sshInboundManager) snapshot() []trafficSnapshotItem {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	inbounds := make([]*managedSSHInbound, 0, len(m.listeners))
	for _, inbound := range m.listeners {
		inbounds = append(inbounds, inbound)
	}
	m.mu.RUnlock()
	items := make([]trafficSnapshotItem, 0)
	for _, inbound := range inbounds {
		for userID, counter := range inbound.counters {
			policy := counter.currentPolicy()
			upload, download := counter.upload.Load(), counter.download.Load()
			if upload == 0 && download == 0 {
				continue
			}
			periodKey := policy.PeriodKey
			items = append(items, trafficSnapshotItem{Key: fmt.Sprintf("ssh-inbound:%d:user:%d", inbound.plan.InboundID, userID), Source: trafficSourceSSH, CounterEpoch: counter.epoch, UserID: userID, InboundID: inbound.plan.InboundID, PeriodKey: periodKey, Upload: upload, Download: download})
		}
	}
	return items
}

func (m *sshInboundManager) updatePolicies(policies map[string]interface{}, acknowledged map[string]trafficCounterCheckpoint) {
	if m == nil || (len(policies) == 0 && len(acknowledged) == 0) {
		return
	}
	parsed := make([]model.TrafficRuntimePolicy, 0, len(policies))
	for _, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		var policy model.TrafficRuntimePolicy
		if json.Unmarshal(encoded, &policy) == nil && policy.UserID > 0 {
			parsed = append(parsed, policy)
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, inbound := range m.listeners {
		for userID, counter := range inbound.counters {
			key := fmt.Sprintf("ssh-inbound:%d:user:%d", inbound.plan.InboundID, userID)
			if checkpoint, ok := acknowledged[key]; ok {
				counter.acknowledge(checkpoint)
			}
		}
		for _, policy := range parsed {
			if policy.InboundID != 0 && policy.InboundID != inbound.plan.InboundID {
				continue
			}
			if counter := inbound.counterFor(policy.UserID); counter != nil {
				counter.setPolicy(policy)
				if counter.quotaExceeded() {
					inbound.closeUserConnections(policy.UserID)
				}
			}
		}
	}
}

func (m *sshInboundManager) trafficPolicyUsers() map[int64]bool {
	out := map[int64]bool{}
	if m == nil {
		return out
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, inbound := range m.listeners {
		for userID := range inbound.counters {
			out[userID] = true
		}
	}
	return out
}

func (m *managedSSHInbound) closeUserConnections(userID int64) {
	m.mu.Lock()
	connections := make([]net.Conn, 0)
	for connection, connectedUserID := range m.conns {
		if connectedUserID == userID {
			connections = append(connections, connection)
		}
	}
	m.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}
