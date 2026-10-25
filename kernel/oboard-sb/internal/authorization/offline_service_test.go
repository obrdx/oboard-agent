package authorization

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineServiceRequiresOptInAndPreservesBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	lease := &Lease{Revision: 1, Sequence: 1, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(MaxLifetime).Format(time.RFC3339Nano), Grants: map[string]string{"open": now.Add(MaxLifetime).Format(time.RFC3339Nano), "dated": now.Add(MaxLifetime).Format(time.RFC3339Nano)}}
	later := now.Add(time.Hour)
	if lease.Allows("open", later) {
		t.Fatal("default must deny expired authorization")
	}
	lease.ContinueWhenDisconnected = true
	lease.OfflineGrants = map[string]string{"open": "", "dated": later.Format(time.RFC3339Nano)}
	if err := lease.Validate(); err != nil {
		t.Fatal(err)
	}
	if !lease.Allows("open", later) || lease.Allows("dated", later) || lease.Allows("missing", later) || lease.Allows("open", now.Add(-time.Second)) {
		t.Fatal("offline boundaries violated")
	}
	path := filepath.Join(t.TempDir(), "authorization.json")
	store := NewStore(path, nil)
	if err := store.Update(lease); err != nil {
		t.Fatal(err)
	}
	if store.OfflineAllows("open", now) {
		t.Fatal("connected lease bypassed local allocation")
	}
	store.SetDisconnected(true)
	if !store.OfflineAllows("open", now) {
		t.Fatal("disconnected node did not use fallback")
	}
	store.SetDisconnected(false)
	if store.OfflineAllows("open", now) {
		t.Fatal("reconnection did not restore allocation")
	}
	restored := NewStore(path, nil)
	if !restored.Allows("open", later) || !restored.OfflineAllows("open", later) {
		t.Fatal("offline policy did not survive restart")
	}
	if err := restored.Deny([]string{"open"}, 2); err != nil {
		t.Fatal(err)
	}
	if restored.Allows("open", later) || restored.OfflineAllows("open", later) {
		t.Fatal("offline policy bypassed denial")
	}
	disabled := clone(lease)
	disabled.Revision = 3
	disabled.ContinueWhenDisconnected = false
	disabled.OfflineGrants = nil
	if err := restored.Update(disabled); err != nil {
		t.Fatal(err)
	}
	if restored.Allows("dated", now.Add(6*time.Minute)) {
		t.Fatal("disabling did not restore expiry")
	}
	if err := restored.Update(lease); err != nil {
		t.Fatal(err)
	}
	if restored.Allows("dated", now.Add(6*time.Minute)) {
		t.Fatal("old configuration restored offline policy")
	}
}

func TestOfflineServiceRejectsMalformedAndConflictingGrants(t *testing.T) {
	now := time.Now().UTC()
	lease := &Lease{Revision: 1, Sequence: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"key": now.Add(MaxLifetime).Format(time.RFC3339Nano)}, ContinueWhenDisconnected: true, OfflineGrants: map[string]string{"key": ""}}
	store := NewStore("", nil)
	if err := store.Update(lease); err != nil {
		t.Fatal(err)
	}
	changed := clone(lease)
	changed.OfflineGrants["key"] = now.Add(time.Hour).Format(time.RFC3339Nano)
	if err := store.Update(changed); err != ErrConflict {
		t.Fatalf("same identity changed offline deadline: %v", err)
	}
	for _, grants := range []map[string]string{{"unknown": ""}, {"key": "invalid"}, {"key": now.Format(time.RFC3339Nano)}} {
		changed.OfflineGrants = grants
		if err := changed.Validate(); err == nil {
			t.Fatal("malformed offline grant accepted")
		}
	}
	changed.ContinueWhenDisconnected = false
	changed.OfflineGrants = map[string]string{"key": ""}
	if err := changed.Validate(); err == nil {
		t.Fatal("offline grant accepted without opt-in")
	}
}
