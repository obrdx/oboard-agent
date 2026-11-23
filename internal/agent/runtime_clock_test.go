package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func withBootClockStub(t *testing.T, bootID string, elapsed func() time.Duration) {
	t.Helper()
	previous := readBootClock
	readBootClock = func() (string, time.Duration, bool) { return bootID, elapsed(), true }
	t.Cleanup(func() { readBootClock = previous })
}

func writeRuntimeClockState(t *testing.T, dir string, state runtimeClockState) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, runtimeClockStateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A host clock step between save and restart (an installer running chrony
// makestep, for example) must not be added to the logical clock.
func TestRuntimeClockRestoreIgnoresHostClockStepWithinOneBoot(t *testing.T) {
	bootNow := 10 * time.Hour
	withBootClockStub(t, "boot-a", func() time.Duration { return bootNow })
	dir := t.TempDir()
	reference := time.Now().UTC().Add(-time.Hour)
	writeRuntimeClockState(t, dir, runtimeClockState{
		Enabled:       true,
		ReferenceTime: reference,
		// The host clock was stepped ten minutes forward after the save.
		LocalTime:     time.Now().UTC().Add(-10*time.Minute - 3*time.Second),
		Source:        "ntp:test",
		BootID:        "boot-a",
		BootElapsedNS: (bootNow - 3*time.Second).Nanoseconds(),
	})
	restored := newRuntimeClock(dir, nil)
	if restored.Unverified() {
		t.Fatal("same-boot restore must be verified by the boot clock")
	}
	want := reference.Add(3 * time.Second)
	if got := restored.Now(); absDuration(got.Sub(want)) > time.Second {
		t.Fatalf("restored logical time = %s, want %s (host step leaked in)", got, want)
	}
}

func TestRuntimeClockRestoreAcrossRebootIsUnverified(t *testing.T) {
	withBootClockStub(t, "boot-b", func() time.Duration { return time.Minute })
	for name, state := range map[string]runtimeClockState{
		"other boot":       {BootID: "boot-a", BootElapsedNS: (10 * time.Hour).Nanoseconds()},
		"no boot identity": {},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			state.Enabled, state.Source = true, "ntp:test"
			state.ReferenceTime = time.Now().UTC().Add(time.Hour)
			state.LocalTime = time.Now().UTC().Add(-time.Minute)
			writeRuntimeClockState(t, dir, state)
			restored := newRuntimeClock(dir, nil)
			if !restored.Active() || !restored.Unverified() {
				t.Fatalf("restore across a reboot must stay active but unverified: active=%t unverified=%t", restored.Active(), restored.Unverified())
			}
		})
	}
}

func waitLogicalClock(t *testing.T, runner *Runner, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !runner.logicalClockReconciling.Load() && done() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("logical clock not reconciled: active=%t now=%s", runner.clock.Active(), runner.clock.Now())
}

func TestControllerTimeDisablesDriftedLogicalClockWhenHostAgrees(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), TimeCorrectionMode: model.TimeCorrectionNTP, ResourceProfile: "large"})
	if err := runner.clock.Apply(true, time.Now().Add(10*time.Minute), "ntp:test", time.Now()); err != nil {
		t.Fatal(err)
	}
	runner.setControllerReference(time.Now())
	waitLogicalClock(t, runner, func() bool { return !runner.clock.Active() })
	if absDuration(runner.clock.Now().Sub(time.Now())) > time.Second {
		t.Fatalf("clock = %s, want host time", runner.clock.Now())
	}
}

func TestControllerTimeReanchorsDriftedLogicalClockWhenHostIsSkewed(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), TimeCorrectionMode: model.TimeCorrectionNTP, ResourceProfile: "large"})
	if err := runner.clock.Apply(true, time.Now().Add(12*time.Minute), "ntp:test", time.Now()); err != nil {
		t.Fatal(err)
	}
	controller := time.Now().Add(2 * time.Minute)
	runner.setControllerReference(controller)
	waitLogicalClock(t, runner, func() bool { return absDuration(runner.clock.Now().Sub(controller)) < 5*time.Second })
	if !runner.clock.Active() || runner.clock.Snapshot().Source != "controller" {
		t.Fatalf("logical clock should be re-anchored to controller time: %#v", runner.clock.Snapshot())
	}
	if _, err := os.Stat(filepath.Join(runner.stateDir(), runtimeClockStateFile)); err != nil {
		t.Fatalf("re-anchored clock must be persisted: %v", err)
	}
}

func TestControllerTimeKeepsAgreeingLogicalClockAndVerifiesIt(t *testing.T) {
	withBootClockStub(t, "boot-b", func() time.Duration { return time.Minute })
	dir := t.TempDir()
	reference := time.Now().UTC().Add(2 * time.Minute)
	writeRuntimeClockState(t, dir, runtimeClockState{Enabled: true, Source: "ntp:test", ReferenceTime: reference, LocalTime: time.Now().UTC(), BootID: "boot-a"})
	runner := New(Config{StateDir: dir, TimeCorrectionMode: model.TimeCorrectionNTP, ResourceProfile: "large"})
	if !runner.clock.Unverified() {
		t.Fatal("precondition: restored clock should be unverified")
	}
	runner.setControllerReference(reference.Add(time.Second))
	if runner.clock.Unverified() || runner.clock.Snapshot().Source != "ntp:test" {
		t.Fatalf("agreeing controller time should only verify the clock: %#v", runner.clock.Snapshot())
	}
}
