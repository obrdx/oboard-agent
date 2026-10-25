package minibox

import (
	"context"
	"fmt"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
)

func (s *runtimeState) authorizationDenied() bool {
	return s.authorizationRevokedFor(s.identity())
}

// authorizationReaperMaxWait bounds how long the reaper sleeps when no grant
// expiry is scheduled sooner. A logical-clock step or an authorization change
// wakes it earlier through the store's change hook.
const authorizationReaperMaxWait = 5 * time.Second

// InitializeAuthorization runs before listeners start. Its state is independent
// of configuration files, so a rollback cannot restore a superseded grant.
func (t *RateLimitTracker) InitializeAuthorization(path string, key []byte, lease *authorization.Lease) error {
	if lease == nil {
		for _, state := range t.states {
			if state.loadedPolicy().AuthorizationKey != "" {
				return fmt.Errorf("authorization snapshot is required for installed credentials")
			}
		}
	}
	store := authorization.NewStore(path, key)
	if t.now != nil {
		store.SetClock(t.timeNow)
	}
	if err := store.Update(lease); err != nil {
		return err
	}
	t.installAuthorizationStore(store)
	return nil
}

func (t *RateLimitTracker) installAuthorizationStore(store *authorization.Store) {
	t.authorization = store
	for _, state := range t.states {
		state.authorization = store
	}
	if t.authorizationWake == nil {
		t.authorizationWake = make(chan struct{}, 1)
	}
	wake := t.authorizationWake
	store.SetChangeHook(func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	})
}

func (t *RateLimitTracker) SetControllerDisconnected(disconnected bool) {
	if t.authorization != nil {
		t.authorization.SetDisconnected(disconnected)
	}
	t.ReapAuthorization()
}

// AuthorizationUpdate is the body of POST /authorization/config: the lease to
// install plus the Agent's full deny watermark, which the kernel merges into
// its own so the two stay identical after every apply.
type AuthorizationUpdate struct {
	Lease *authorization.Lease `json:"lease"`
	Deny  []string             `json:"deny,omitempty"`
}

// UpdateAuthorization installs a snapshot and closes every connection whose
// credential is no longer granted. Denials are recorded before the lease so a
// crash between the two steps can only lose grants, never a denial.
func (t *RateLimitTracker) UpdateAuthorization(lease *authorization.Lease) error {
	return t.ApplyAuthorization(AuthorizationUpdate{Lease: lease})
}

// ApplyAuthorization installs the lease and deny watermark carried by one
// Agent update, then reaps revoked sessions.
func (t *RateLimitTracker) ApplyAuthorization(update AuthorizationUpdate) error {
	if t.authorization == nil {
		t.installAuthorizationStore(authorization.NewStore("", nil))
	}
	if len(update.Deny) > 0 {
		revision := int64(0)
		if update.Lease != nil {
			revision = update.Lease.Revision
		}
		if err := t.authorization.Deny(update.Deny, revision); err != nil {
			return err
		}
	}
	if update.Lease != nil {
		if err := t.authorization.Update(update.Lease); err != nil {
			return err
		}
	}
	t.ReapAuthorization()
	return nil
}

// DenyAuthorization is the emergency path: it records keys on the deny
// watermark and closes their sessions without waiting for a full snapshot.
func (t *RateLimitTracker) DenyAuthorization(keys []string, revision int64) (int, error) {
	if t.authorization == nil {
		t.installAuthorizationStore(authorization.NewStore("", nil))
	}
	if err := t.authorization.Deny(keys, revision); err != nil {
		return 0, err
	}
	closed := 0
	for _, key := range keys {
		closed += t.closeByCredential(key)
	}
	return closed, nil
}

// AuthorizationStatus is the read-back identity for GET /authorization/status.
func (t *RateLimitTracker) AuthorizationStatus() authorization.Status {
	if t.authorization == nil {
		return authorization.Status{}
	}
	return t.authorization.Status()
}

// ReapAuthorization closes every connection whose authorization identity is
// revoked. Quota reject_new never closes an admitted connection here; only
// the authorization verdict does.
func (t *RateLimitTracker) ReapAuthorization() int {
	defer t.reapSnellParents(false)
	conns, packets := t.revokedConnections()
	for _, conn := range conns {
		_ = conn.Close()
	}
	for _, conn := range packets {
		_ = conn.Close()
	}
	// Credential-status revokes (not reject_new) still close through the
	// per-key path so a rotated credential's sessions end promptly.
	t.mu.RLock()
	keys := make([]string, 0, len(t.states))
	for key, state := range t.states {
		if normalizeCredentialStatus(state.currentPolicy().CredentialStatus) != "active" && normalizeCredentialStatus(state.currentPolicy().CredentialStatus) != "reject_new" {
			keys = append(keys, key)
		}
	}
	t.mu.RUnlock()
	for _, key := range keys {
		t.closeActive(key)
	}
	return len(conns) + len(packets)
}

// RunAuthorizationReaper closes sessions as their grants expire. It sleeps
// until the earliest scheduled expiry (bounded by authorizationReaperMaxWait)
// and is woken immediately by any authorization change, replacing the former
// fixed 100 ms full scan.
func (t *RateLimitTracker) RunAuthorizationReaper(ctx context.Context) {
	if t.authorization == nil {
		t.installAuthorizationStore(authorization.NewStore("", nil))
	}
	wake := t.authorizationWake
	timer := time.NewTimer(t.nextAuthorizationWait())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			t.ReapAuthorization()
		case <-timer.C:
			t.ReapAuthorization()
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(t.nextAuthorizationWait())
	}
}

func (t *RateLimitTracker) nextAuthorizationWait() time.Duration {
	wait := authorizationReaperMaxWait
	if t.authorization == nil {
		return wait
	}
	lease, err := t.authorization.Snapshot()
	if err != nil || lease == nil {
		return wait
	}
	now := t.timeNow()
	next := lease.NextExpiry(now)
	if next.IsZero() {
		return wait
	}
	// Fire just past the boundary so the expired grant is already invalid.
	if until := next.Sub(now) + 10*time.Millisecond; until < wait {
		if until < 10*time.Millisecond {
			until = 10 * time.Millisecond
		}
		wait = until
	}
	return wait
}
