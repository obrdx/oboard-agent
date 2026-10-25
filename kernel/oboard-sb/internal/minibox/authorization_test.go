package minibox

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	"github.com/sagernet/sing-box/adapter"
)

func authorizedQuotaFixture(metadata RuntimeMetadata) *RateLimitTracker {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{}}
	for _, entries := range []map[string]RuntimeUserLimit{metadata.RateLimits.Users, metadata.RateLimits.Inbounds} {
		for name, policy := range entries {
			if policy.UserID <= 0 {
				continue
			}
			policy.AuthorizationKey = "quota-fixture-" + name
			entries[name] = policy
			lease.Grants[policy.AuthorizationKey] = now.Add(5 * time.Minute).Format(time.RFC3339Nano)
		}
	}
	metadata.Authorization = lease
	return NewRateLimitTracker(metadata)
}

func TestAuthorizationExpiryClosesConnectionsAndPolicyCannotRegrant(t *testing.T) {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"installed": now.Add(time.Second).Format(time.RFC3339Nano)}}
	tracker := newRateLimitTracker(RuntimeMetadata{Authorization: lease, RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"opaque": {UserID: 7, AuthorizationKey: "installed"}}}}, func() time.Time { return now })
	client, server := net.Pipe()
	defer client.Close()
	wrapped := tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "opaque"}, nil, nil)
	defer wrapped.Close()
	packet := &testPacketConn{}
	udp := tracker.RoutedPacketConnection(context.Background(), packet, adapter.InboundContext{User: "opaque"}, nil, nil)
	defer udp.Close()
	state := tracker.stateForKey("user:opaque")
	if state.deniedForConnection(false) {
		t.Fatal("valid authorization rejected")
	}
	now = now.Add(time.Second)
	tracker.ReapAuthorization()
	if !packet.closed.Load() {
		t.Fatal("expired UDP association remained open")
	}
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("expired TCP connection remained open")
	}
	tracker.UpdatePolicies(map[string]RuntimeUserLimit{"user:7": {UserID: 7, AuthorizationKey: "replacement", CredentialStatus: "active"}})
	if state.loadedPolicy().AuthorizationKey != "installed" || !state.deniedForConnection(true) {
		t.Fatal("quota renewal changed installed authorization")
	}
	if err := tracker.UpdateAuthorization(&authorization.Lease{Revision: 2, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"replacement": now.Add(time.Minute).Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	if !state.deniedForConnection(false) {
		t.Fatal("lease installed a new credential")
	}
}

func TestAuthorizationRevocationClosesConnectionWithinQuota(t *testing.T) {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"installed": now.Add(time.Minute).Format(time.RFC3339Nano)}}
	tracker := newRateLimitTracker(RuntimeMetadata{Authorization: lease, RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"opaque": {UserID: 7, AuthorizationKey: "installed", Billable: true, TrafficLimitBytes: 100},
	}}}, func() time.Time { return now })
	client, server := net.Pipe()
	defer client.Close()
	admitted := baseTrackedConn(tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "opaque"}, nil, nil))
	if admitted.closed.Load() {
		t.Fatal("unexhausted quota closed a still-authorized connection")
	}
	if err := tracker.UpdateAuthorization(&authorization.Lease{Revision: 2, IssuedAt: now.Add(time.Second).Format(time.RFC3339Nano), Grants: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if !admitted.closed.Load() {
		t.Fatal("revoked authorization left an admitted connection open within quota")
	}
}

// Connections carry the credential identity they authenticated with. A deny
// pushed for that key closes exactly its sessions, the status read-back names
// the installed identity, and a later grant for the same key cannot re-admit
// while the deny watermark holds it.
func TestAuthorizationDenyClosesByCredentialAndStatusReadsBack(t *testing.T) {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 3, Sequence: 1, Digest: "d3", IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{
		"cred-a": now.Add(time.Minute).Format(time.RFC3339Nano),
		"cred-b": now.Add(time.Minute).Format(time.RFC3339Nano),
	}}
	tracker := newRateLimitTracker(RuntimeMetadata{Authorization: lease, RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{
		"alice": {UserID: 7, AuthorizationKey: "cred-a", CredentialEpoch: 1, Billable: true},
		"bob":   {UserID: 8, AuthorizationKey: "cred-b", CredentialEpoch: 1, Billable: true},
	}}}, func() time.Time { return now })
	aliceClient, aliceServer := net.Pipe()
	defer aliceClient.Close()
	bobClient, bobServer := net.Pipe()
	defer bobClient.Close()
	alice := baseTrackedConn(tracker.RoutedConnection(context.Background(), aliceServer, adapter.InboundContext{User: "alice"}, nil, nil))
	bob := baseTrackedConn(tracker.RoutedConnection(context.Background(), bobServer, adapter.InboundContext{User: "bob"}, nil, nil))
	if alice.identity.authorizationKey != "cred-a" || alice.identity.credentialEpoch != 1 || alice.identity.userID != 7 {
		t.Fatalf("admission did not capture credential identity: %+v", alice.identity)
	}
	status := tracker.AuthorizationStatus()
	if status.Revision != 3 || status.Sequence != 1 || status.Digest != "d3" || status.GrantCount != 2 || status.BootID == "" {
		t.Fatalf("status read-back: %+v", status)
	}

	// Emergency deny without a snapshot closes only cred-a.
	closed, err := tracker.DenyAuthorization([]string{"cred-a"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if closed != 1 || !alice.closed.Load() || bob.closed.Load() {
		t.Fatalf("deny closed=%d alice=%v bob=%v", closed, alice.closed.Load(), bob.closed.Load())
	}
	if tracker.AuthorizationStatus().DeniedCount != 1 {
		t.Fatalf("deny watermark not recorded: %+v", tracker.AuthorizationStatus())
	}
	// A wrapped update whose lease still grants cred-a cannot re-admit it: the
	// watermark is authoritative until a newer confirmed revision prunes it.
	now = now.Add(time.Second)
	if err := tracker.ApplyAuthorization(AuthorizationUpdate{Lease: &authorization.Lease{Revision: 3, Sequence: 2, Digest: "d3", IssuedAt: now.Format(time.RFC3339Nano), Grants: lease.Grants}}); err != nil {
		t.Fatal(err)
	}
	if !tracker.stateForKey("user:alice").deniedForConnection(false) {
		t.Fatal("denied credential re-admitted by a renewal that still lists it")
	}
	if tracker.stateForKey("user:bob").deniedForConnection(true) {
		t.Fatal("unrelated credential denied")
	}

	// Credential rotation: the policy now names a new key/epoch for alice; a
	// session that authenticated with the old identity is revoked even though
	// the new key is granted, and a fresh session under the new key is admitted.
	now = now.Add(time.Second)
	if err := tracker.ApplyAuthorization(AuthorizationUpdate{Lease: &authorization.Lease{Revision: 5, Sequence: 1, Digest: "d5", IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{
		"cred-a2": now.Add(time.Minute).Format(time.RFC3339Nano),
		"cred-b":  now.Add(time.Minute).Format(time.RFC3339Nano),
	}}}); err != nil {
		t.Fatal(err)
	}
	tracker.UpdatePolicies(map[string]RuntimeUserLimit{"user:7": {UserID: 7, AuthorizationKey: "cred-a2", CredentialEpoch: 2, CredentialStatus: "active", Billable: true}})
	// UpdatePolicies keeps installed authorization identity; a structural
	// reinstall carries the new key.
	tracker.stateForKey("user:alice").storePolicyLocked(RuntimeUserLimit{UserID: 7, AuthorizationKey: "cred-a2", CredentialEpoch: 2, Billable: true}, false)
	stale := &trackedConn{state: tracker.stateForKey("user:alice"), identity: connectionIdentity{authorizationKey: "cred-a", credentialEpoch: 1, userID: 7}, admitted: true}
	if !stale.deny() {
		t.Fatal("session authenticated with a rotated-out credential stayed authorized")
	}
	fresh := &trackedConn{state: tracker.stateForKey("user:alice"), identity: connectionIdentity{authorizationKey: "cred-a2", credentialEpoch: 2, userID: 7}, admitted: true}
	if fresh.deny() {
		t.Fatal("session under the rotated-in credential denied")
	}
}

func TestMissingAuthorizationFailsClosed(t *testing.T) {
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"old": {UserID: 7}}}})
	if !tracker.stateForKey("user:old").deniedForConnection(false) {
		t.Fatal("legacy credential admitted without authorization")
	}
}

// A rollback to sing-box.last-good.json restarts the kernel with the older
// configuration-embedded lease. The persisted store outranks it: the confirmed
// revocation stays denied and the configuration lease is superseded, while the
// other credential from the newer snapshot keeps its grant.
func TestRollbackConfigLeaseCannotResurrectConfirmedRevocation(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "kernel-authorization.json")
	old := &authorization.Lease{Revision: 2, Sequence: 1, Digest: "d2", IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{
		"cred-a": now.Add(4 * time.Minute).Format(time.RFC3339Nano),
		"cred-b": now.Add(4 * time.Minute).Format(time.RFC3339Nano),
	}}
	users := map[string]RuntimeUserLimit{
		"alice": {UserID: 7, AuthorizationKey: "cred-a", CredentialEpoch: 1, Billable: true},
		"bob":   {UserID: 8, AuthorizationKey: "cred-b", CredentialEpoch: 1, Billable: true},
	}
	first := newRateLimitTracker(RuntimeMetadata{Authorization: old, RateLimits: RuntimeRateLimits{Users: users}}, func() time.Time { return now })
	if err := first.InitializeAuthorization(path, nil, old); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	revoke := &authorization.Lease{Revision: 3, Sequence: 1, Digest: "d3", IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{
		"cred-b": now.Add(4 * time.Minute).Format(time.RFC3339Nano),
	}, Denied: []string{"cred-a"}}
	if err := first.ApplyAuthorization(AuthorizationUpdate{Lease: revoke, Deny: []string{"cred-a"}}); err != nil {
		t.Fatal(err)
	}
	if !first.stateForKey("user:alice").deniedForConnection(false) {
		t.Fatal("revocation not applied before rollback")
	}

	// The kernel restarts from the rolled-back configuration, which still
	// embeds revision 2 with cred-a granted.
	now = now.Add(time.Second)
	rolledBack := newRateLimitTracker(RuntimeMetadata{Authorization: old, RateLimits: RuntimeRateLimits{Users: users}}, func() time.Time { return now })
	if err := rolledBack.InitializeAuthorization(path, nil, old); err != nil {
		t.Fatal(err)
	}
	status := rolledBack.AuthorizationStatus()
	if status.Revision != 3 || status.DeniedCount != 1 {
		t.Fatalf("rollback replaced the persisted authorization: %+v", status)
	}
	if !rolledBack.stateForKey("user:alice").deniedForConnection(false) {
		t.Fatal("rollback resurrected a confirmed revocation")
	}
	if rolledBack.stateForKey("user:bob").deniedForConnection(false) {
		t.Fatal("rollback lost an unrelated live grant")
	}
	// The stale configuration lease arriving again over the API is
	// superseded rather than installed.
	if err := rolledBack.UpdateAuthorization(old); err != nil {
		t.Fatal(err)
	}
	if rolledBack.AuthorizationStatus().Revision != 3 || !rolledBack.stateForKey("user:alice").deniedForConnection(false) {
		t.Fatal("stale lease replay re-admitted a revoked credential")
	}
}

func TestPersistedLeaseDoesNotPermitConfigToOmitAuthorization(t *testing.T) {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"installed": now.Add(time.Minute).Format(time.RFC3339Nano)}}
	path := filepath.Join(t.TempDir(), "kernel-authorization.json")
	if err := authorization.NewStore(path, nil).Update(lease); err != nil {
		t.Fatal(err)
	}
	tracker := NewRateLimitTracker(RuntimeMetadata{RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"opaque": {UserID: 7, AuthorizationKey: "installed"}}}})
	if err := tracker.InitializeAuthorization(path, nil, nil); err == nil {
		t.Fatal("config without authorization reused persisted grants")
	}
}

func TestOfflineServiceKeepsTCPUDPAndEnforcesLocalTotal(t *testing.T) {
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"key": now.Add(5 * time.Minute).Format(time.RFC3339Nano)}, ContinueWhenDisconnected: true, OfflineGrants: map[string]string{"key": ""}}
	tracker := newRateLimitTracker(RuntimeMetadata{Authorization: lease, RateLimits: RuntimeRateLimits{Users: map[string]RuntimeUserLimit{"alice": {UserID: 7, AuthorizationKey: "key", Billable: true, TrafficLimitBytes: 100, LeaseEnforced: true, LeaseBytes: 10}}}}, func() time.Time { return now })
	state := tracker.stateForKey("user:alice")
	client, server := net.Pipe()
	defer client.Close()
	wrapped := tracker.RoutedConnection(context.Background(), server, adapter.InboundContext{User: "alice"}, nil, nil)
	defer wrapped.Close()
	packet := &testPacketConn{}
	udp := tracker.RoutedPacketConnection(context.Background(), packet, adapter.InboundContext{User: "alice"}, nil, nil)
	defer udp.Close()
	tracker.SetControllerDisconnected(true)
	now = now.Add(time.Hour)
	tracker.ReapAuthorization()
	if packet.closed.Load() || state.deniedForConnection(true) {
		t.Fatal("offline opt-in terminated authorized traffic")
	}
	state.addTraffic(10, 0)
	if state.quotaDeniedFor(true) {
		t.Fatal("offline allocation was not relaxed")
	}
	state.addTraffic(90, 0)
	if !state.quotaDeniedFor(true) {
		t.Fatal("offline mode bypassed local total quota")
	}
	if err := tracker.authorization.Deny([]string{"key"}, 2); err != nil {
		t.Fatal(err)
	}
	tracker.ReapAuthorization()
	if !packet.closed.Load() {
		t.Fatal("offline mode bypassed revocation")
	}
}
