package agent

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/authorization"
	"github.com/OboardProject/oboard-agent/internal/logging"
)

func captureSyncLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previous, level := log.Writer(), logging.CurrentLevel()
	log.SetOutput(&output)
	logging.SetLevel(logging.LevelInfo)
	t.Cleanup(func() { log.SetOutput(previous); logging.SetLevel(level) })
	return &output
}

func TestSyncLogsThrottleAndRecoverWithoutResponseSecrets(t *testing.T) {
	output := captureSyncLogs(t)
	r := &Runner{}
	failure := errors.New("controller returned 403 Forbidden: confidential-response")
	r.noteSyncOutcome("traffic_limits", "controller_request", 4, 2, failure)
	r.noteSyncOutcome("traffic_limits", "controller_request", 4, 2, failure)
	r.noteSyncOutcome("traffic_limits", "runtime_apply", 4, 2, errors.New("kernel unavailable"))
	r.noteSyncOutcome("traffic_limits", "policy_persist", 4, 2, nil)
	r.noteSyncOutcome("traffic_limits", "policy_persist", 4, 2, nil)
	got := output.String()
	if strings.Count(got, "sync failed:") != 2 || strings.Count(got, "sync completed:") != 1 || !strings.Contains(got, "recovered=true previous_failures=3") || strings.Contains(got, "confidential-response") {
		t.Fatalf("incorrect sync lifecycle logging: %s", got)
	}
}

func TestAuthorizationExpiryAndRecoveryLogsOmitGrantKeys(t *testing.T) {
	output := captureSyncLogs(t)
	r := New(Config{StateDir: t.TempDir()})
	now := time.Now().UTC()
	lapsedAt := now.Add(-time.Second).Format(time.RFC3339Nano)
	old := &authorization.Lease{Revision: 1, IssuedAt: now.Add(-authorization.MaxLifetime - time.Second).Format(time.RFC3339Nano), ExpiresAt: lapsedAt, Grants: map[string]string{"private-grant-key": lapsedAt}}
	if err := r.authorizationState().Update(old); err != nil {
		t.Fatal(err)
	}
	r.noteAuthorizationAvailability()
	renewed := &authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: map[string]string{"private-grant-key": now.Add(time.Minute).Format(time.RFC3339Nano)}}
	if err := r.authorizationState().Update(renewed); err != nil {
		t.Fatal(err)
	}
	r.noteAuthorizationAvailability()
	got := output.String()
	if !strings.Contains(got, "stage=expired") || !strings.Contains(got, "recovered=true") || strings.Contains(got, "private-grant-key") {
		t.Fatalf("incorrect authorization log: %s", got)
	}
}

func TestAuthorizationGrantEndingAtBusinessBoundaryIsNotReportedAsExpired(t *testing.T) {
	output := captureSyncLogs(t)
	r := New(Config{StateDir: t.TempDir()})
	now := time.Now().UTC()
	lease := &authorization.Lease{Revision: 1, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339Nano), Grants: map[string]string{
		"plan-ended": now.Add(-time.Second).Format(time.RFC3339Nano),
		"renewed":    now.Add(4 * time.Minute).Format(time.RFC3339Nano),
	}}
	if err := r.authorizationState().Update(lease); err != nil {
		t.Fatal(err)
	}
	r.noteAuthorizationAvailability()
	got := output.String()
	if strings.Contains(got, "stage=expired") || !strings.Contains(got, "stage=valid") || !strings.Contains(got, "entries=1") {
		t.Fatalf("scheduled grant end reported as a renewal lapse: %s", got)
	}
}

func TestTrafficRequestRejectionLogsRestrictionAndPersistsStage(t *testing.T) {
	output := captureSyncLogs(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "confidential-response", http.StatusTooManyRequests)
	}))
	defer server.Close()
	r := newTestRunner(t, Config{ControllerURL: server.URL, StateDir: t.TempDir(), AgentID: "test", AgentToken: "private-token"})
	state := r.trafficStateLocked()
	for range 2 {
		if err := r.reportTrafficLedger(context.Background(), state, nil); err == nil {
			t.Fatal("expected rejection")
		}
	}
	if state.Sync.Status != trafficStatusStale || !strings.HasPrefix(state.Sync.LastError, "controller_request:") {
		t.Fatalf("sync status does not explain failure: %+v", state.Sync)
	}
	got := output.String()
	if strings.Count(got, "controller access restricted:") != 1 || !strings.Contains(got, "http_status=429") || !strings.Contains(got, "operation=traffic_limits stage=controller_request") || strings.Contains(got, "confidential-response") || strings.Contains(got, "private-token") {
		t.Fatalf("unsafe or missing restriction log: %s", got)
	}
	r.controllerAuth.clear()
	if !strings.Contains(output.String(), "controller access recovered:") {
		t.Fatal("missing restriction recovery log")
	}
}
