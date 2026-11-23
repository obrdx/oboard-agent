package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

const runtimeClockStateFile = "runtime-clock.json"

type runtimeClockState struct {
	Enabled       bool      `json:"enabled"`
	ReferenceTime time.Time `json:"reference_time"`
	LocalTime     time.Time `json:"local_time"`
	Source        string    `json:"source"`
	CheckedAt     time.Time `json:"checked_at"`
	// BootID and BootElapsedNS anchor the reference to the boot-scoped clock
	// so a restart inside the same boot does not inherit a host clock step.
	BootID        string `json:"boot_id,omitempty"`
	BootElapsedNS int64  `json:"boot_elapsed_ns,omitempty"`
}

// readBootClock is a seam so tests can simulate restarts and reboots.
var readBootClock = platformBootClock

type runtimeClock struct {
	mu        sync.RWMutex
	enabled   bool
	reference time.Time
	anchor    time.Time
	source    string
	checkedAt time.Time
	// unverified marks a reference carried across a reboot (or a platform
	// without a boot clock) by the host wall clock, which may have been
	// stepped meanwhile. Only a Controller time comparison clears it.
	unverified bool
	stateDir   string
	key        []byte
}

func newRuntimeClock(stateDir string, key []byte) *runtimeClock {
	clock := &runtimeClock{stateDir: stateDir, key: key}
	clock.restore()
	return clock
}

func (c *runtimeClock) statePath() string {
	if len(c.key) == stealth.KeyLen {
		return filepath.Join(c.stateDir, stealth.PhysicalName(c.key, runtimeClockStateFile))
	}
	return filepath.Join(c.stateDir, runtimeClockStateFile)
}

func (c *runtimeClock) Now() time.Time {
	if c == nil {
		return time.Now()
	}
	c.mu.RLock()
	enabled, reference, anchor := c.enabled, c.reference, c.anchor
	c.mu.RUnlock()
	if !enabled || reference.IsZero() || anchor.IsZero() {
		return time.Now()
	}
	return reference.Add(time.Since(anchor))
}

func (c *runtimeClock) Apply(enabled bool, reference time.Time, source string, checkedAt time.Time) error {
	anchor := time.Now()
	if !enabled || reference.IsZero() {
		enabled = false
		reference = time.Time{}
	}
	if checkedAt.IsZero() {
		checkedAt = reference
	}
	c.mu.Lock()
	c.enabled = enabled
	c.reference = reference.UTC()
	c.anchor = anchor
	c.source = source
	c.checkedAt = checkedAt.UTC()
	c.unverified = false
	c.mu.Unlock()
	return c.persist()
}

func (c *runtimeClock) Snapshot() runtimeClockState {
	if c == nil {
		return runtimeClockState{}
	}
	c.mu.RLock()
	enabled, source, checkedAt := c.enabled, c.source, c.checkedAt
	c.mu.RUnlock()
	state := runtimeClockState{Enabled: enabled, Source: source, CheckedAt: checkedAt, LocalTime: time.Now().UTC()}
	if enabled {
		state.ReferenceTime = c.Now().UTC()
		if bootID, elapsed, ok := readBootClock(); ok {
			state.BootID, state.BootElapsedNS = bootID, elapsed.Nanoseconds()
		}
	}
	return state
}

func (c *runtimeClock) persist() error {
	if c == nil {
		return nil
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	if len(c.key) == stealth.KeyLen {
		if data, err = stealth.Encrypt(c.key, data); err != nil {
			return err
		}
	}
	return atomicWriteFile(c.statePath(), data, 0o600)
}

func (c *runtimeClock) restore() {
	if c == nil {
		return
	}
	// #nosec G304 -- statePath is derived from the agent state directory.
	data, err := os.ReadFile(c.statePath())
	if err != nil {
		return
	}
	if len(c.key) == stealth.KeyLen && stealth.IsEncrypted(data) {
		if data, err = stealth.Decrypt(c.key, data); err != nil {
			return
		}
	}
	var state runtimeClockState
	if json.Unmarshal(data, &state) != nil || !state.Enabled || state.ReferenceTime.IsZero() || state.LocalTime.IsZero() {
		return
	}
	anchor := time.Now()
	// Within one boot the boot clock measures the downtime exactly. Across a
	// reboot only the host wall clock is left, and an installer or chrony may
	// have stepped it since the state was saved; that step would be added to
	// the logical clock, so the result stays unverified until checked.
	elapsed := anchor.Sub(state.LocalTime)
	unverified := true
	if bootID, now, ok := readBootClock(); ok && state.BootID != "" && state.BootID == bootID && now.Nanoseconds() >= state.BootElapsedNS {
		elapsed = now - time.Duration(state.BootElapsedNS)
		unverified = false
	}
	c.enabled = true
	c.reference = state.ReferenceTime.Add(elapsed).UTC()
	c.anchor = anchor
	c.source = state.Source
	c.checkedAt = state.CheckedAt.UTC()
	c.unverified = unverified
}

// Active reports whether a logical reference currently replaces host time.
func (c *runtimeClock) Active() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled && !c.reference.IsZero() && !c.anchor.IsZero()
}

// Unverified reports whether the active logical clock was restored across a
// reboot and has not yet been compared with the Controller.
func (c *runtimeClock) Unverified() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled && c.unverified
}

// markVerified records that the active reference agrees with the Controller.
func (c *runtimeClock) markVerified() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.unverified = false
	c.mu.Unlock()
}

func (r *Runner) setControllerReference(reference time.Time) {
	if r == nil || reference.IsZero() {
		return
	}
	r.controllerClockMu.Lock()
	r.controllerReference = reference.UTC()
	r.controllerReferenceAnchor = time.Now()
	r.controllerClockMu.Unlock()
	r.reconcileLogicalClockWithController()
}

const (
	// logicalClockControllerDriftLimit matches the default time-check
	// threshold and stays far inside the five-minute authorization lease, so
	// a drifted logical clock is repaired long before it rejects valid leases.
	logicalClockControllerDriftLimit = 30 * time.Second
	logicalClockReconcileInterval    = time.Minute
)

// reconcileLogicalClockWithController keeps an active logical clock inside the
// Controller's time domain. Authorization leases, task signatures and traffic
// windows are issued in Controller time; a logical clock that drifted away
// from it (for example one restored across a host clock step) would reject
// every fresh lease. When the host clock already agrees with the Controller
// the logical clock is no longer needed and is dropped; otherwise it is
// re-anchored to the Controller time, the same reference check_time falls back
// to when NTP is unavailable.
func (r *Runner) reconcileLogicalClockWithController() {
	if r == nil || r.clock == nil || !r.clock.Active() {
		return
	}
	now := time.Now()
	if last := r.logicalClockCheckedAt.Load(); last != 0 && now.Sub(time.Unix(0, last)) < logicalClockReconcileInterval && !r.clock.Unverified() {
		return
	}
	controller, ok := r.controllerReferenceNow()
	if !ok {
		return
	}
	r.logicalClockCheckedAt.Store(now.UnixNano())
	drift := r.clock.Now().Sub(controller)
	if absDuration(drift) <= logicalClockControllerDriftLimit {
		r.clock.markVerified()
		return
	}
	if !r.logicalClockReconciling.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer r.logicalClockReconciling.Store(false)
		hostDrift := time.Now().Sub(controller)
		keep := absDuration(hostDrift) >= logicalClockControllerDriftLimit && normalizeTimeCorrectionMode(r.Config().TimeCorrectionMode) != model.TimeCorrectionOff
		var err error
		if keep {
			err = r.clock.Apply(true, controller, "controller", controller)
		} else {
			err = r.clock.Apply(false, time.Time{}, "controller", controller)
		}
		if err != nil {
			logging.Warnf("logical clock drifted from controller time: drift=%s host_drift=%s persist_error=%q", drift.Round(time.Millisecond), hostDrift.Round(time.Millisecond), err.Error())
			return
		}
		logging.Warnf("logical clock drifted from controller time: drift=%s host_drift=%s action=%s", drift.Round(time.Millisecond), hostDrift.Round(time.Millisecond), map[bool]string{true: "reanchored", false: "disabled"}[keep])
		if err := r.configureCoreClock(context.Background()); err != nil {
			logging.Warnf("push corrected logical clock to core failed: %s", err.Error())
		}
	}()
}

func (r *Runner) controllerReferenceNow() (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	r.controllerClockMu.RLock()
	reference, anchor := r.controllerReference, r.controllerReferenceAnchor
	r.controllerClockMu.RUnlock()
	if reference.IsZero() || anchor.IsZero() {
		return time.Time{}, false
	}
	age := time.Since(anchor)
	if age < 0 || age > controllerTimeMaxAge {
		return time.Time{}, false
	}
	return reference.Add(age), true
}
