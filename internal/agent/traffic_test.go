package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestPostControllerJSONPreservesControllerBasePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/hidden-panel/api/v1/agent/task-results" {
			http.Error(w, req.URL.Path, http.StatusNotFound)
			return
		}
		if req.Header.Get("X-Agent-ID") != "agent-1" || req.Header.Get("Authorization") != "Bearer token-1" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	runner := newTestRunner(t, Config{ControllerURL: server.URL + "/hidden-panel", AgentID: "agent-1", AgentToken: "token-1", StateDir: t.TempDir()})
	if err := runner.postControllerJSON(context.Background(), "/api/v1/agent/task-results", map[string]any{"task_id": 1}, nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestTrafficReportBatchLimitsRequestSize(t *testing.T) {
	pending := make([]trafficPendingReport, trafficReportBatchSize+1)
	for i := range pending {
		pending[i].ReportID = string(rune('a' + i%26))
	}

	batch := trafficReportBatch(pending)
	if len(batch) != trafficReportBatchSize {
		t.Fatalf("batch size = %d, want %d", len(batch), trafficReportBatchSize)
	}
	if len(pending) != trafficReportBatchSize+1 {
		t.Fatalf("pending reports were truncated: %d", len(pending))
	}
}

func TestRemoveAcceptedTrafficReportsPreservesUnacknowledged(t *testing.T) {
	pending := []trafficPendingReport{
		{ReportID: "first"},
		{ReportID: "second"},
		{ReportID: "third"},
	}
	remaining := removeAcceptedTrafficReports(pending, []string{"second", "unknown"})
	if len(remaining) != 2 {
		t.Fatalf("remaining reports = %#v", remaining)
	}
	if remaining[0].ReportID != "first" || remaining[1].ReportID != "third" {
		t.Fatalf("remaining report order = %#v", remaining)
	}
}

func TestAcceptedTrafficReportAdvancesDurableCheckpoint(t *testing.T) {
	state := &trafficLocalState{Pending: []trafficPendingReport{
		{ReportID: "accepted", PeriodKey: "2026-07", SnapshotKey: "user:alice", CumulativeUpload: 11, CumulativeDownload: 13},
		{ReportID: "pending", PeriodKey: "2026-07", SnapshotKey: "user:bob", CumulativeUpload: 17, CumulativeDownload: 19},
	}}
	acknowledgeAcceptedTrafficReports(state, []string{"accepted"})
	checkpoint, ok := state.Acknowledged["user:alice"]
	if !ok || checkpoint.PeriodKey != "2026-07" || checkpoint.Upload != 11 || checkpoint.Download != 13 {
		t.Fatalf("unexpected accepted checkpoint: %#v", state.Acknowledged)
	}
	if _, ok := state.Acknowledged["user:bob"]; ok {
		t.Fatal("unaccepted report advanced its checkpoint")
	}
}

func TestTrafficReportWireBatchOmitsLocalCheckpointFields(t *testing.T) {
	batch := trafficReportBatch([]trafficPendingReport{{ReportID: "r1", UserID: 7, SnapshotKey: "user:alice", CumulativeUpload: 99, CumulativeDownload: 100}})
	b, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "snapshot_key") || strings.Contains(string(b), "cumulative_") {
		t.Fatalf("local checkpoint fields leaked onto Controller wire: %s", b)
	}
}

func TestRuntimeLeaseIsPartitionedAcrossCoreAndSSH(t *testing.T) {
	policies := map[string]interface{}{"user:7": map[string]interface{}{
		"user_id": 7, "billable": true, "lease_enforced": true, "lease_bytes": 101, "reset_lease_bytes": 51,
	}}
	corePolicies, sshPolicies := partitionRuntimePolicyLeases(policies, map[int64]bool{7: true}, map[int64]bool{7: true})
	core := corePolicies["user:7"].(model.TrafficRuntimePolicy)
	ssh := sshPolicies["user:7"].(model.TrafficRuntimePolicy)
	if core.LeaseBytes+ssh.LeaseBytes != 101 || core.ResetLeaseBytes+ssh.ResetLeaseBytes != 51 {
		t.Fatalf("partition changed total lease: core=%#v ssh=%#v", core, ssh)
	}
	if core.LeaseBytes != 51 || ssh.LeaseBytes != 50 {
		t.Fatalf("unexpected lease partition: core=%d ssh=%d", core.LeaseBytes, ssh.LeaseBytes)
	}
}

func TestCorePolicyFailureDoesNotMutateSSHPolicy(t *testing.T) {
	dir := t.TempDir()
	config := `{"_oboard":{"rate_limits":{"users":{"alice":{"user_id":7,"billable":true,"lease_enforced":true,"lease_bytes":100}}}}}`
	if err := os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	counter := &sshInboundCounter{}
	counter.setPolicy(model.TrafficRuntimePolicy{UserID: 7, InboundID: 17, Billable: true, LeaseEnforced: true, LeaseBytes: 50})
	runner := New(Config{StateDir: dir, ResourceProfile: "large"})
	runner.sshInboundManager = &sshInboundManager{listeners: map[int64]*managedSSHInbound{17: {plan: model.SSHInbound{InboundID: 17}, counters: map[int64]*sshInboundCounter{7: counter}}}}
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	err := runner.pushTrafficPolicies(context.Background(), map[string]interface{}{"user:7": model.TrafficRuntimePolicy{UserID: 7, Billable: true, LeaseEnforced: true, LeaseBytes: 80}}, nil)
	if err == nil {
		t.Fatal("core policy failure was ignored")
	}
	if policy := counter.currentPolicy(); policy.LeaseBytes != 50 {
		t.Fatalf("SSH policy changed after core rejected the update: %#v", policy)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestTrafficDeltaCountsEntireFirstSnapshotOfNewPeriod(t *testing.T) {
	previous := trafficSnapshotItem{PeriodKey: "2026-07", Upload: 100, Download: 200}
	current := trafficSnapshotItem{PeriodKey: "2026-08", Upload: 150, Download: 250}
	upload, download := trafficDelta(current, previous)
	if upload != 150 || download != 250 {
		t.Fatalf("delta = (%d,%d), want (150,250)", upload, download)
	}
}

func TestPostControllerJSONRejectsUnencodablePayload(t *testing.T) {
	r := New(Config{ResourceProfile: "large"})
	err := r.postControllerJSON(context.Background(), "/unused", map[string]any{"bad": make(chan int)}, nil, false)
	if err == nil {
		t.Fatal("expected JSON encoding error")
	}
}

func TestCorruptTrafficStateDoesNotBecomeEmptyLedger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traffic-state.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := New(Config{StateDir: dir, AgentID: "agent-1"})
	state := runner.loadTrafficState()
	if !state.RecoveryRequired || state.Sync.Status != trafficStatusStateCorrupt {
		t.Fatalf("corrupt state = %#v", state)
	}
	if len(state.PendingReports) != 0 || len(state.Last) != 0 {
		t.Fatalf("corrupt state was treated as an empty ledger: %#v", state)
	}
}

func TestMissingTrafficStateRequiresControllerReconciliation(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), AgentID: "agent-1"})
	state := runner.loadTrafficState()
	if !state.RecoveryRequired || state.Sync.Status != trafficStatusRecovering {
		t.Fatalf("missing state = %#v", state)
	}
	changed := runner.observeTrafficSnapshotLocked(&state, []trafficSnapshotItem{{
		Key: "user:7", Source: "core", CounterEpoch: "ce_1", UserID: 7, InboundID: 1, PeriodKey: "2026-08-01", Upload: 10, Download: 10,
	}}, true)
	if !changed {
		t.Fatal("expected recovering observation to change state")
	}
	if len(state.PendingReports) != 0 {
		t.Fatalf("missing state billed kernel totals: %#v", state.PendingReports)
	}
}

func TestSameEpochCounterRegressionDoesNotBill(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), AgentID: "agent-1"})
	state := runner.trafficStateLocked()
	item := trafficSnapshotItem{Key: "user:7", Source: "core", CounterEpoch: "ce_1", UserID: 7, InboundID: 1, PeriodKey: "2026-08-01", Upload: 10, Download: 10}
	runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
	item.Upload = 1
	item.Download = 1
	runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
	stream := state.Streams[trafficStreamID("core", "user:7")]
	if stream == nil || stream.Status != trafficStatusCounterRegression {
		t.Fatalf("regression stream = %#v", stream)
	}
	if len(state.PendingReports) != 0 {
		t.Fatalf("regression billed traffic: %#v", state.PendingReports)
	}
}

func TestTrafficRangeReportIDIsDeterministic(t *testing.T) {
	report := &trafficPendingRange{StreamID: "ts_a", CounterEpoch: "ce_1", PeriodKey: "2026-08-01", FromUpload: 8, ToUpload: 10, FromDownload: 8, ToDownload: 10}
	first := trafficRangeReportID("agent-1", report)
	second := trafficRangeReportID("agent-1", report)
	if first == "" || first != second || !strings.HasPrefix(first, "tr_") {
		t.Fatalf("report ids = %q %q", first, second)
	}
}

func TestPersistBeforeReloadWritesPendingRange(t *testing.T) {
	dir := t.TempDir()
	runner := New(Config{StateDir: dir, AgentID: "agent-1"})
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/traffic/snapshot" {
			return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Header: make(http.Header)}, nil
		}
		body, _ := json.Marshal(map[string]any{"items": []trafficSnapshotItem{{
			Key: "user:7", CounterEpoch: "ce_1", Source: "core", UserID: 7, InboundID: 12, PeriodKey: "2026-08-01", Upload: 500, Download: 500,
		}}})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	state := runner.trafficStateLocked()
	state.RecoveryRequired = false
	state.SchemaVersion = trafficStateSchemaV2
	if err := runner.persistTrafficCheckpointBeforeRuntimeTransition(context.Background()); err != nil {
		t.Fatal(err)
	}
	loaded, err := runner.readTrafficStateFile(runner.trafficStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.PendingReports) != 1 {
		t.Fatalf("pending after persist-before-reload = %#v", loaded.PendingReports)
	}
	for _, report := range loaded.PendingReports {
		if report.FromUpload != 0 || report.ToUpload != 500 || report.FromDownload != 0 || report.ToDownload != 500 {
			t.Fatalf("pending range = %#v", report)
		}
	}
}

func TestLegacyPendingConvertsToCheckpointRange(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), AgentID: "agent-1"})
	state := runner.trafficStateLocked()
	inboundID := int64(17)
	state.Pending = []trafficPendingReport{{
		ReportID: "legacy-pending", UserID: 7, PeriodKey: "2026-08-01", Upload: 20, Download: 30,
		SnapshotKey: "user:7", CumulativeUpload: 120, CumulativeDownload: 130, InboundID: &inboundID,
	}}
	state.Last = map[string]trafficSnapshotItem{"user:7": {Key: "user:7", Source: "core", CounterEpoch: "ce_1"}}
	if !runner.convertLegacyPendingToRangesLocked(state) {
		t.Fatal("expected leftover pending to convert")
	}
	if len(state.Pending) != 0 {
		t.Fatalf("leftover pending = %#v", state.Pending)
	}
	report := state.PendingReports["legacy-pending"]
	if report == nil || report.FromUpload != 100 || report.ToUpload != 120 || report.FromDownload != 100 || report.ToDownload != 130 || report.CounterEpoch != "ce_1" {
		t.Fatalf("converted range = %#v", report)
	}
}

func TestControllerCheckpointRecoveryDoesNotRebillFromZero(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), AgentID: "agent-1"})
	state := &trafficLocalState{SchemaVersion: 2, Streams: map[string]*trafficStreamState{}, PendingReports: map[string]*trafficPendingRange{}, RecoveryRequired: true}
	streamID := trafficStreamID("core", "user:7")
	state.Streams[streamID] = &trafficStreamState{Source: "core", SnapshotKey: "user:7", CounterEpoch: "ce_1", PeriodKey: "2026-08-01", UserID: 7, ObservedUpload: 10, ObservedDownload: 10, Status: trafficStatusRecovering}
	applyTrafficLedgerResponse(state, trafficReportResponse{
		StreamCheckpoints: []trafficStreamCheckpoint{{
			Source: "core", StreamID: streamID, CounterEpoch: "ce_1", PeriodKey: "2026-08-01", AcceptedUpload: 8, AcceptedDownload: 8, Status: trafficStatusHealthy,
		}},
	})
	runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{{
		Key: "user:7", Source: "core", CounterEpoch: "ce_1", UserID: 7, InboundID: 17, PeriodKey: "2026-08-01", Upload: 10, Download: 10,
	}}, false)
	if len(state.PendingReports) != 1 {
		t.Fatalf("pending = %#v", state.PendingReports)
	}
	for _, report := range state.PendingReports {
		if report.FromUpload != 8 || report.ToUpload != 10 || report.FromDownload != 8 || report.ToDownload != 10 {
			t.Fatalf("recovered range = %#v", report)
		}
	}
}

func TestSameEpochPeriodMigrationKeepsAcceptedCheckpoint(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), AgentID: "agent-1"})
	state := runner.trafficStateLocked()
	state.RecoveryRequired = false
	state.SchemaVersion = trafficStateSchemaV2
	item := trafficSnapshotItem{Key: "user:7", Source: "core", CounterEpoch: "ce_1", UserID: 7, InboundID: 1, PeriodKey: "old-cycle", Upload: 100, Download: 100}
	runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
	streamID := trafficStreamID("core", "user:7")
	stream := state.Streams[streamID]
	if stream == nil {
		t.Fatal("missing stream")
	}
	stream.AcceptedUpload = 100
	stream.AcceptedDownload = 100
	stream.Status = trafficStatusHealthy
	state.PendingReports = map[string]*trafficPendingRange{}
	item.PeriodKey = "new-cycle"
	item.Upload = 120
	item.Download = 130
	runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
	stream = state.Streams[streamID]
	if stream == nil || stream.AcceptedUpload != 100 || stream.AcceptedDownload != 100 {
		t.Fatalf("accepted reset on period migration: %#v", stream)
	}
	if len(state.PendingReports) != 1 {
		t.Fatalf("pending = %#v", state.PendingReports)
	}
	for _, report := range state.PendingReports {
		if report.FromUpload != 100 || report.ToUpload != 120 || report.PeriodKey != "new-cycle" {
			t.Fatalf("migrated range = %#v", report)
		}
	}
}

func TestCheckTrafficPolicyRevisionGate(t *testing.T) {
	applied := map[string]model.TrafficRuntimePolicy{"7": {UserID: 7, UsedBaselineBytes: 100, PolicyRevision: 10}}
	incoming := map[string]model.TrafficRuntimePolicy{"7": {UserID: 7, UsedBaselineBytes: 100, PolicyRevision: 10}}
	skipped, err := checkTrafficPolicyRevision(10, applied, 9, incoming)
	if err != nil || !skipped {
		t.Fatalf("older revision should skip, err=%v skipped=%v", err, skipped)
	}
	skipped, err = checkTrafficPolicyRevision(10, applied, 10, incoming)
	if err != nil || !skipped {
		t.Fatalf("same revision same content should be idempotent, err=%v skipped=%v", err, skipped)
	}
	different := map[string]model.TrafficRuntimePolicy{"7": {UserID: 7, UsedBaselineBytes: 200, PolicyRevision: 10}}
	if _, err := checkTrafficPolicyRevision(10, applied, 10, different); err == nil {
		t.Fatal("same revision different content should fail")
	}
	skipped, err = checkTrafficPolicyRevision(10, applied, 11, different)
	if err != nil || skipped {
		t.Fatalf("newer revision should apply, err=%v skipped=%v", err, skipped)
	}
}

// An SSH counter that produced bytes before its runtime policy arrived has no
// period key yet. Sending that observation made the Controller fail the entire
// batch, and because the stream stays in local state the same batch failed on
// every retry - so the Agent never received the policy that would have supplied
// the missing period. An unusable observation is dropped locally instead.
func TestTrafficStreamWireBatchDropsUnusableIdentities(t *testing.T) {
	state := &trafficLocalState{Streams: map[string]*trafficStreamState{
		"stream-no-period": {Source: trafficSourceSSH, SnapshotKey: "ssh-inbound:4:user:7", CounterEpoch: "ce_1", PeriodKey: "", UserID: 7, ObservedUpload: 10},
		"stream-no-user":   {Source: trafficSourceCore, SnapshotKey: "user:8", CounterEpoch: "ce_1", PeriodKey: "2026-09", UserID: 0, ObservedUpload: 10},
		"stream-ok":        {Source: trafficSourceCore, SnapshotKey: "user:9", CounterEpoch: "ce_1", PeriodKey: "2026-09", UserID: 9, ObservedUpload: 10},
	}}
	batch := trafficStreamWireBatch(state, []trafficSnapshotItem{
		{Source: trafficSourceSSH, Key: "ssh-inbound:5:user:11", CounterEpoch: "ce_2", PeriodKey: "", UserID: 11, Upload: 5},
	})
	if len(batch) != 1 {
		t.Fatalf("wire batch = %#v, want only the complete stream", batch)
	}
	if batch[0].UserID != 9 || batch[0].PeriodKey != "2026-09" {
		t.Fatalf("wire batch kept the wrong stream: %#v", batch[0])
	}
}

// Stream state was never pruned, so an entry the Controller can never accept
// stayed in the state file across restarts and was resent in every batch.
func TestPruneTrafficStreamsDropsUnusableAndStaleEntries(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Format(time.RFC3339Nano)
	state := &trafficLocalState{
		Streams: map[string]*trafficStreamState{
			"unusable":      {Source: trafficSourceSSH, SnapshotKey: "ssh-inbound:4:user:7", CounterEpoch: "ce_1", PeriodKey: "", UserID: 7, LastObservedAt: fresh},
			"checkpointed":  {Source: trafficSourceCore},
			"stale-settled": {Source: trafficSourceCore, SnapshotKey: "user:8", CounterEpoch: "ce_1", PeriodKey: "2026-08", UserID: 8, ObservedUpload: 50, AcceptedUpload: 50, LastObservedAt: now.Add(-trafficStreamRetention - time.Hour).Format(time.RFC3339Nano)},
			"stale-unsent":  {Source: trafficSourceCore, SnapshotKey: "user:9", CounterEpoch: "ce_1", PeriodKey: "2026-08", UserID: 9, ObservedUpload: 50, AcceptedUpload: 10, LastObservedAt: now.Add(-trafficStreamRetention - time.Hour).Format(time.RFC3339Nano)},
			"undated":       {Source: trafficSourceCore, SnapshotKey: "user:10", CounterEpoch: "ce_1", PeriodKey: "2026-09", UserID: 10},
			"live":          {Source: trafficSourceCore, SnapshotKey: "user:11", CounterEpoch: "ce_1", PeriodKey: "2026-09", UserID: 11, LastObservedAt: fresh},
		},
	}
	if !pruneTrafficStreamsLocked(state, now) {
		t.Fatal("prune reported no change")
	}
	for _, id := range []string{"unusable", "checkpointed", "stale-settled"} {
		if _, ok := state.Streams[id]; ok {
			t.Fatalf("stream %q survived pruning", id)
		}
	}
	// Unacknowledged bytes and live streams are never dropped, and state
	// written before the field existed is dated rather than treated as expired.
	for _, id := range []string{"stale-unsent", "undated", "live"} {
		if _, ok := state.Streams[id]; !ok {
			t.Fatalf("stream %q was pruned but must be kept", id)
		}
	}
	if state.Streams["undated"].LastObservedAt == "" {
		t.Fatal("undated stream was not stamped")
	}
}

// A stream still carrying an unreported range is kept even when it is otherwise
// unusable, so pruning can never drop pending accounting.
func TestPruneTrafficStreamsKeepsStreamsWithPendingReports(t *testing.T) {
	now := time.Now().UTC()
	state := &trafficLocalState{
		Streams: map[string]*trafficStreamState{
			"pending": {Source: trafficSourceSSH, SnapshotKey: "ssh-inbound:4:user:7", CounterEpoch: "ce_1", PeriodKey: "", UserID: 7},
		},
		PendingReports: map[string]*trafficPendingRange{
			"r1": {ReportID: "r1", StreamID: "pending", UserID: 7, ToUpload: 100},
		},
	}
	pruneTrafficStreamsLocked(state, now)
	if _, ok := state.Streams["pending"]; !ok {
		t.Fatal("a stream with a pending report was pruned")
	}
}
