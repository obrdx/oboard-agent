package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/security"
)

func signedTestEnvelope(t *testing.T, token string, serverID int64, messageID string, lease model.AuthorizationLease) model.AuthorizationEnvelope {
	t.Helper()
	leaseJSON, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	envelope := model.AuthorizationEnvelope{Type: model.AgentControlAuthorizationUpdate, MessageID: messageID, ServerID: serverID, LeaseJSON: string(leaseJSON)}
	envelope.Signature = security.SignAuthorizationEnvelope(security.HashSecret(token), security.AuthorizationEnvelopeFields{ServerID: serverID, MessageID: messageID, Revision: lease.Revision, Sequence: lease.Sequence, IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt, LeaseJSON: envelope.LeaseJSON})
	return envelope
}

// The authorization lane verifies every envelope with the Agent token, applies
// it to the kernel through the control-capable body, reads the installed
// identity back, and acknowledges only what the data plane really enforces.
func TestAuthorizationEnvelopeLaneAppliesVerifiesAndRejectsForgeries(t *testing.T) {
	dir := t.TempDir()
	core := writeFakeCoreBinaryWithCapabilities(t, dir, "build-auth", []string{"authorization_lease_v1", kernelCapabilityAuthorizationControl, coreRuntimeDigestCapability})
	issued := time.Now().UTC()
	granted := issued.Add(4 * time.Minute).Format(time.RFC3339Nano)
	config := fmt.Sprintf(`{"log":{"level":"warn"},"inbounds":[{"tag":"in-b","type":"socks","listen":"127.0.0.1","listen_port":22222}],"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"authorization_key":"k-alice","lease_bytes":100}}},"authorization":{"revision":1,"sequence":1,"digest":"d1","issued_at":%q,"expires_at":%q,"grants":{"k-alice":%q}}}}`, issued.Format(time.RFC3339Nano), granted, granted)
	writeCoreConfig(t, dir, config)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.authorizationControl = true
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, core)
	cfg := r.Config()
	cfg.AgentToken = "lane-token"
	cfg.AgentID = "lane-agent"
	cfg.ServerID = 5
	r.storeConfig(cfg)

	grant := model.AuthorizationLease{Revision: 1, Sequence: 1, Digest: "d1", IssuedAt: issued.Format(time.RFC3339Nano), ExpiresAt: granted, Grants: map[string]string{"k-alice": granted}}
	ack := r.applyAuthorizationEnvelope(context.Background(), signedTestEnvelope(t, "lane-token", 5, "m1", grant))
	if !ack.Confirmed || ack.Error != "" || ack.Revision != 1 || ack.Sequence != 1 || ack.MessageID != "m1" {
		t.Fatalf("valid envelope not confirmed: %+v", ack)
	}
	if ack.Runtimes["kernel"] != "verified" || ack.BootID == "" {
		t.Fatalf("kernel read-back not verified: %+v", ack)
	}
	if !r.authorizationAllows("k-alice") {
		t.Fatal("granted key not allowed after apply")
	}

	offline := grant
	offline.Revision = 2
	offline.ContinueWhenDisconnected = true
	offline.OfflineGrants = map[string]string{"k-alice": ""}
	unsupported := r.applyAuthorizationEnvelope(context.Background(), signedTestEnvelope(t, "lane-token", 5, "offline-unsupported", offline))
	if unsupported.Confirmed || unsupported.Error == "" {
		t.Fatal("old kernel confirmed offline policy")
	}
	installed, err := r.authorizationState().Snapshot()
	if err != nil || installed.ContinueWhenDisconnected {
		t.Fatal("unsupported offline policy was persisted")
	}
	tampered := signedTestEnvelope(t, "lane-token", 5, "offline-forged", grant)
	modified, _ := json.Marshal(offline)
	tampered.LeaseJSON = string(modified)
	if ack := r.applyAuthorizationEnvelope(context.Background(), tampered); ack.Confirmed || ack.Error == "" {
		t.Fatal("unsigned offline opt-in accepted")
	}

	// A forged envelope (wrong key) is rejected and never confirmed; the ack
	// still reports the identity the data plane holds.
	forged := signedTestEnvelope(t, "other-token", 5, "m2", model.AuthorizationLease{Revision: 2, Sequence: 1, Digest: "d2", IssuedAt: issued.Add(time.Second).Format(time.RFC3339Nano), ExpiresAt: granted, Grants: map[string]string{}})
	ack = r.applyAuthorizationEnvelope(context.Background(), forged)
	if ack.Confirmed || ack.Error == "" || ack.Applied == nil || ack.Applied.Revision != 1 {
		t.Fatalf("forged envelope accepted: %+v", ack)
	}
	if !r.authorizationAllows("k-alice") {
		t.Fatal("forged revoke took effect")
	}
	// An envelope bound to a different server is rejected.
	foreign := signedTestEnvelope(t, "lane-token", 6, "m3", grant)
	if ack := r.applyAuthorizationEnvelope(context.Background(), foreign); ack.Confirmed || ack.Error == "" {
		t.Fatalf("foreign server envelope accepted: %+v", ack)
	}

	// A genuine revoke closes the grant, carries the deny watermark to the
	// kernel, and is confirmed.
	revoke := model.AuthorizationLease{Revision: 2, Sequence: 1, Digest: "d2", IssuedAt: issued.Add(time.Second).Format(time.RFC3339Nano), ExpiresAt: granted, Grants: map[string]string{}, Denied: []string{"k-alice"}}
	ack = r.applyAuthorizationEnvelope(context.Background(), signedTestEnvelope(t, "lane-token", 5, "m4", revoke))
	if !ack.Confirmed || ack.Revision != 2 {
		t.Fatalf("revoke not confirmed: %+v", ack)
	}
	if r.authorizationAllows("k-alice") {
		t.Fatal("revoked key still allowed")
	}
	if denied := kernel.deniedKeys(); len(denied) != 1 || denied[0] != "k-alice" {
		t.Fatalf("deny watermark not pushed to kernel: %v", denied)
	}
	// A late replay of the older grant is superseded, not re-admitted, and the
	// ack names the installed (newer) identity.
	ack = r.applyAuthorizationEnvelope(context.Background(), signedTestEnvelope(t, "lane-token", 5, "m5", grant))
	if !ack.Confirmed || ack.Revision != 2 {
		t.Fatalf("stale replay changed installed identity: %+v", ack)
	}
	if r.authorizationAllows("k-alice") {
		t.Fatal("stale grant replay re-admitted a revoked key")
	}
	health := r.taskResultHealth()
	if applied := r.appliedAuthorization(); applied == nil || applied.Revision != 2 || applied.BootID == "" {
		t.Fatalf("applied authorization not reported: %+v health=%v", applied, health)
	}
}

// A revoke must land while the single task slot is busy with a long task
// (certificate issuance, a deployment holding the kernel lifecycle lock, a
// traffic report in flight). The lane holds only its own lock, so the envelope
// is confirmed within the two-second budget. Afterwards a rollback that
// re-applies the previous configuration's embedded lease is superseded: the
// deny watermark stays on the kernel and the installed revision is unchanged.
func TestAuthorizationRevokeBypassesBusyTaskLocksAndRollbackCannotResurrect(t *testing.T) {
	dir := t.TempDir()
	core := writeFakeCoreBinaryWithCapabilities(t, dir, "build-auth", []string{"authorization_lease_v1", kernelCapabilityAuthorizationControl, coreRuntimeDigestCapability})
	issued := time.Now().UTC()
	granted := issued.Add(4 * time.Minute).Format(time.RFC3339Nano)
	config := fmt.Sprintf(`{"log":{"level":"warn"},"inbounds":[{"tag":"in-b","type":"socks","listen":"127.0.0.1","listen_port":22222}],"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"authorization_key":"k-alice","lease_bytes":100}}},"authorization":{"revision":1,"sequence":1,"digest":"d1","issued_at":%q,"expires_at":%q,"grants":{"k-alice":%q}}}}`, issued.Format(time.RFC3339Nano), granted, granted)
	writeCoreConfig(t, dir, config)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.authorizationControl = true
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, core)
	cfg := r.Config()
	cfg.AgentToken = "lane-token"
	cfg.ServerID = 5
	r.storeConfig(cfg)
	if err := r.applyConfigAuthorization(context.Background(), []byte(config)); err != nil {
		t.Fatal(err)
	}
	if !r.authorizationAllows("k-alice") {
		t.Fatal("initial grant not installed")
	}

	// Simulate a long task occupying every lock a deployment, certificate
	// issuance, or traffic report can hold.
	r.deploymentMu.Lock()
	r.coreLifecycleMu.Lock()
	r.trafficMu.Lock()
	r.sshInboundLifecycleMu.Lock()
	defer func() {
		r.sshInboundLifecycleMu.Unlock()
		r.trafficMu.Unlock()
		r.coreLifecycleMu.Unlock()
		r.deploymentMu.Unlock()
	}()

	revoke := model.AuthorizationLease{Revision: 2, Sequence: 1, Digest: "d2", IssuedAt: issued.Add(time.Second).Format(time.RFC3339Nano), ExpiresAt: granted, Grants: map[string]string{}, Denied: []string{"k-alice"}}
	done := make(chan model.AuthorizationAck, 1)
	go func() {
		done <- r.applyAuthorizationEnvelope(context.Background(), signedTestEnvelope(t, "lane-token", 5, "busy-1", revoke))
	}()
	select {
	case ack := <-done:
		if !ack.Confirmed || ack.Revision != 2 || ack.Runtimes["kernel"] != "verified" {
			t.Fatalf("revoke not confirmed while task locks were held: %+v", ack)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoke blocked behind task locks for more than two seconds")
	}
	if r.authorizationAllows("k-alice") {
		t.Fatal("revoked key still allowed")
	}

	// Rollback: the previous configuration (revision 1, k-alice granted) is
	// re-applied through the configuration path a rollback uses.
	if err := r.applyConfigAuthorization(context.Background(), []byte(config)); err != nil {
		t.Fatalf("rollback lease apply: %v", err)
	}
	if r.authorizationAllows("k-alice") {
		t.Fatal("rollback resurrected a revoked key")
	}
	if denied := kernel.deniedKeys(); len(denied) != 1 || denied[0] != "k-alice" {
		t.Fatalf("kernel deny watermark lost after rollback: %v", denied)
	}
	if applied := r.appliedAuthorization(); applied == nil || applied.Revision != 2 {
		t.Fatalf("rollback changed the confirmed revision: %+v", applied)
	}
}

func TestAuthorizationRenewalReachesRuntimeOnlyUsers(t *testing.T) {
	dir := t.TempDir()
	core := writeFakeCoreBinaryWithCapabilities(t, dir, "build-auth", []string{"authorization_lease_v1", kernelCapabilityAuthorizationControl, coreRuntimeDigestCapability})
	config := `{"inbounds":[{"tag":"in-b","type":"vless","listen":"127.0.0.1","listen_port":22222}],"_oboard":{"runtime_users":{"inbounds":["in-b"]}}}`
	writeCoreConfig(t, dir, config)
	kernel := newFakeCoreKernel(t, filepath.Join(dir, "sing-box.json"), true)
	kernel.authorizationControl = true
	r := newRuntimeTestRunnerWithCore(t, dir, kernel, core)
	issued := time.Now().UTC()
	for sequence := int64(1); sequence <= 2; sequence++ {
		at := issued.Add(time.Duration(sequence-1) * time.Second)
		expires := at.Add(4 * time.Minute).Format(time.RFC3339Nano)
		lease := model.AuthorizationLease{Revision: 11, Sequence: sequence, Digest: "runtime-users", IssuedAt: at.Format(time.RFC3339Nano), ExpiresAt: expires, Grants: map[string]string{"runtime-key": expires}}
		outcome, err := r.applyAuthorization(t.Context(), &lease)
		if err != nil || !outcome.RuntimeVerified || outcome.Runtimes["kernel"] != "verified" {
			t.Fatalf("renewal skipped kernel: %#v, %v", outcome, err)
		}
		status, err := r.readKernelAuthorizationStatus(t.Context())
		if err != nil || status.Sequence != sequence {
			t.Fatalf("kernel did not receive renewal: %#v, %v", status, err)
		}
	}
}
