package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// ledgerControllerStub keeps one accepted checkpoint per stream identity and
// answers like the Controller ledger: a range is accepted only from the
// stored checkpoint, and an anomalous observation status is echoed back in
// that stream's checkpoint.
type ledgerControllerStub struct {
	mu       sync.Mutex
	accepted map[string][2]int64
	billed   map[int64]int64
	calls    int
	// unanswered users get no answer for their ranges, which stay pending.
	unanswered map[int64]bool
	epochs     map[string]bool
}

func newLedgerControllerStub() *ledgerControllerStub {
	return &ledgerControllerStub{accepted: map[string][2]int64{}, billed: map[int64]int64{}, unanswered: map[int64]bool{}, epochs: map[string]bool{}}
}

func (c *ledgerControllerStub) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	var batch struct {
		Streams []trafficStreamWire       `json:"streams"`
		Reports []trafficLedgerReportItem `json:"reports"`
	}
	if err := json.NewDecoder(req.Body).Decode(&batch); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	key := func(source, stream, epoch, period string) string {
		return source + "|" + stream + "|" + epoch + "|" + period
	}
	checkpoints := map[string]trafficStreamCheckpoint{}
	for _, obs := range batch.Streams {
		k := key(obs.Source, obs.StreamID, obs.CounterEpoch, obs.PeriodKey)
		c.epochs[obs.CounterEpoch] = true
		acc := c.accepted[k]
		status := trafficStatusHealthy
		if trafficStreamAwaitsCheckpoint(obs.Status) {
			status = obs.Status
		}
		checkpoints[k] = trafficStreamCheckpoint{Source: obs.Source, StreamID: obs.StreamID, CounterEpoch: obs.CounterEpoch, PeriodKey: obs.PeriodKey, AcceptedUpload: acc[0], AcceptedDownload: acc[1], Status: status}
	}
	var answers []trafficAcceptedReport
	for _, report := range batch.Reports {
		if c.unanswered[report.UserID] {
			continue
		}
		k := key(report.Source, report.StreamID, report.CounterEpoch, report.PeriodKey)
		c.epochs[report.CounterEpoch] = true
		acc := c.accepted[k]
		status := validateStubCheckpoint(report, acc)
		if status == "accepted" {
			c.billed[report.UserID] += report.ToUpload - report.FromUpload + report.ToDownload - report.FromDownload
			acc = [2]int64{report.ToUpload, report.ToDownload}
			c.accepted[k] = acc
		}
		answers = append(answers, trafficAcceptedReport{ReportID: report.ReportID, Status: status, AcceptedUpload: acc[0], AcceptedDownload: acc[1]})
		cpStatus := trafficStatusHealthy
		if status != "accepted" && status != "covered" {
			cpStatus = status
		}
		checkpoints[k] = trafficStreamCheckpoint{Source: report.Source, StreamID: report.StreamID, CounterEpoch: report.CounterEpoch, PeriodKey: report.PeriodKey, AcceptedUpload: acc[0], AcceptedDownload: acc[1], Status: cpStatus}
	}
	resp := trafficReportResponse{AcceptedReports: answers}
	for _, checkpoint := range checkpoints {
		resp.StreamCheckpoints = append(resp.StreamCheckpoints, checkpoint)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func validateStubCheckpoint(report trafficLedgerReportItem, acc [2]int64) string {
	switch {
	case report.ToUpload <= acc[0] && report.ToDownload <= acc[1]:
		return "covered"
	case report.FromUpload == acc[0] && report.FromDownload == acc[1]:
		return "accepted"
	case report.FromUpload > acc[0] || report.FromDownload > acc[1]:
		return trafficStatusCheckpointGap
	default:
		return trafficStatusCheckpointOverlap
	}
}

type trafficKernelStub struct {
	mu    sync.Mutex
	items []trafficSnapshotItem
	acks  map[string]trafficCounterCheckpoint
}

func (k *trafficKernelStub) set(items ...trafficSnapshotItem) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.items = items
}

func (k *trafficKernelStub) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch req.URL.Path {
	case "/traffic/snapshot":
		_ = json.NewEncoder(w).Encode(map[string]any{"items": k.items})
	case "/traffic/policy":
		var body struct {
			Acknowledged map[string]trafficCounterCheckpoint `json:"acknowledged"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		k.acks = body.Acknowledged
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		http.NotFound(w, req)
	}
}

func newIsolationRunner(t *testing.T, controller *ledgerControllerStub, kernel *trafficKernelStub, stateDir string) *Runner {
	t.Helper()
	controllerServer := httptest.NewServer(controller)
	t.Cleanup(controllerServer.Close)
	kernelServer := httptest.NewServer(kernel)
	t.Cleanup(kernelServer.Close)
	runner := newTestRunner(t, Config{ControllerURL: controllerServer.URL, AgentID: "agent-1", AgentToken: "token", StateDir: stateDir})
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.URL.Scheme, clone.URL.Host = "http", kernelServer.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(clone)
	})}
	return runner
}

func isolationItem(key string, userID, upload, download int64) trafficSnapshotItem {
	return trafficSnapshotItem{Key: key, Source: trafficSourceCore, CounterEpoch: "ce_1", UserID: userID, InboundID: 34, PeriodKey: "2026-11", Upload: upload, Download: download}
}

// One stream regressing inside its epoch, then losing its credential, used to
// put the whole server into recovery that nothing could end: every healthy
// stream stopped reporting, so the Controller never saw consumption and never
// renewed the lease the kernel was enforcing.
func TestCounterRegressionStaysWithItsStreamAndRebases(t *testing.T) {
	controller := newLedgerControllerStub()
	kernel := &trafficKernelStub{}
	runner := newIsolationRunner(t, controller, kernel, t.TempDir())
	state := runner.trafficStateLocked()
	state.RecoveryRequired = false
	ctx := context.Background()
	collect := func() {
		t.Helper()
		if err := runner.collectAndReportTraffic(ctx); err != nil {
			t.Logf("collect: %v", err)
		}
		if state.RecoveryRequired {
			t.Fatalf("a stream anomaly put the whole server into recovery: %+v", state.Sync)
		}
	}

	kernel.set(isolationItem("user:7", 7, 100, 100), isolationItem("user:8", 8, 500, 500))
	collect()
	if controller.billed[7] != 200 || controller.billed[8] != 1000 {
		t.Fatalf("initial billing = %v", controller.billed)
	}

	// User 8's growth is observed but its range stays unsettled.
	controller.unanswered[8] = true
	kernel.set(isolationItem("user:7", 7, 100, 100), isolationItem("user:8", 8, 700, 700))
	collect()
	delete(controller.unanswered, 8)
	if len(state.PendingReports) != 1 {
		t.Fatalf("pending = %d, want the unsettled range", len(state.PendingReports))
	}

	// User 8's counter regresses inside the same epoch.
	kernel.set(isolationItem("user:7", 7, 200, 200), isolationItem("user:8", 8, 50, 50))
	collect()
	if controller.billed[7] != 400 {
		t.Fatalf("healthy stream stopped billing during a neighbour's regression: %v", controller.billed)
	}
	if controller.billed[8] != 1400 {
		t.Fatalf("bytes observed before the regression were not settled: %v", controller.billed)
	}
	streamB := state.Streams[trafficStreamID(trafficSourceCore, "user:8")]
	if streamB.Status != trafficStatusHealthy || streamB.RebaseGeneration != 1 || streamB.BaseUpload != 50 || streamB.ledgerEpoch() != "ce_1~r1" {
		t.Fatalf("regressed stream was not rebased: %+v", streamB)
	}
	if ack := kernel.acks["user:8"]; ack.CounterEpoch != "ce_1" || ack.Upload != 50 || ack.Download != 50 {
		t.Fatalf("kernel acknowledgement after rebase = %+v", ack)
	}

	// The rebased stream resumes its own accounting from the rebase point.
	kernel.set(isolationItem("user:7", 7, 250, 250), isolationItem("user:8", 8, 80, 80))
	collect()
	if controller.billed[7] != 500 || controller.billed[8] != 1460 {
		t.Fatalf("billing after rebase = %v", controller.billed)
	}
	if ack := kernel.acks["user:8"]; ack.CounterEpoch != "ce_1" || ack.Upload != 80 || ack.Download != 80 {
		t.Fatalf("kernel acknowledgement in kernel coordinates = %+v", ack)
	}

	// The credential is removed; the other stream keeps reporting.
	kernel.set(isolationItem("user:7", 7, 300, 300))
	collect()
	collect()
	if controller.billed[7] != 600 || controller.billed[8] != 1460 {
		t.Fatalf("billing after credential removal = %v", controller.billed)
	}
	if len(state.PendingReports) != 0 || state.Sync.Status != trafficStatusHealthy {
		t.Fatalf("state did not settle: pending=%d sync=%+v", len(state.PendingReports), state.Sync)
	}
}

// The state an Agent was left in by the old global recovery: recovery
// required, a regressed stream whose credential is gone, and a healthy stream
// whose bytes grew past its checkpoint without being queued. One cycle must
// release the server and settle the healthy stream's owed bytes.
func TestStuckGlobalRecoveryFromRegressionReleasesInOneCycle(t *testing.T) {
	controller := newLedgerControllerStub()
	kernel := &trafficKernelStub{}
	stateDir := t.TempDir()
	idA := trafficStreamID(trafficSourceCore, "user:7")
	idB := trafficStreamID(trafficSourceCore, "user:8")
	controller.accepted[trafficSourceCore+"|"+idA+"|ce_1|2026-11"] = [2]int64{100, 100}
	controller.accepted[trafficSourceCore+"|"+idB+"|ce_1|2026-11"] = [2]int64{500, 500}

	runner := newIsolationRunner(t, controller, kernel, stateDir)
	state := runner.trafficStateLocked()
	state.RecoveryRequired = true
	state.Sync = trafficSyncState{Status: trafficStatusCounterRegression, LastError: "counter regression in the same epoch"}
	state.Streams[idA] = &trafficStreamState{Source: trafficSourceCore, SnapshotKey: "user:7", CounterEpoch: "ce_1", PeriodKey: "2026-11", UserID: 7, InboundID: 34, ObservedUpload: 100, ObservedDownload: 100, AcceptedUpload: 100, AcceptedDownload: 100, Status: trafficStatusRecovering}
	state.Streams[idB] = &trafficStreamState{Source: trafficSourceCore, SnapshotKey: "user:8", CounterEpoch: "ce_1", PeriodKey: "2026-11", UserID: 8, InboundID: 34, ObservedUpload: 10, ObservedDownload: 10, AcceptedUpload: 500, AcceptedDownload: 500, Status: trafficStatusCounterRegression, LastError: "counter regression in the same epoch"}
	if err := runner.saveTrafficState(*state); err != nil {
		t.Fatal(err)
	}

	runner = newIsolationRunner(t, controller, kernel, stateDir)
	kernel.set(isolationItem("user:7", 7, 400, 400))
	if err := runner.collectAndReportTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	state = runner.trafficStateLocked()
	if state.RecoveryRequired {
		t.Fatalf("server stayed in recovery: %+v", state.Sync)
	}
	if controller.billed[7] != 600 {
		t.Fatalf("owed bytes of the healthy stream = %d, want 600", controller.billed[7])
	}
	if controller.billed[8] != 0 {
		t.Fatalf("regressed stream was billed during recovery: %d", controller.billed[8])
	}
	if b := state.Streams[idB]; b.Status != trafficStatusHealthy || b.RebaseGeneration != 1 || b.BaseUpload != 10 {
		t.Fatalf("regressed stream was not rebased: %+v", b)
	}
	if ack := kernel.acks["user:7"]; ack.Upload != 400 || ack.Download != 400 {
		t.Fatalf("kernel acknowledgement for the healthy stream = %+v", ack)
	}
	if state.Sync.Status != trafficStatusHealthy {
		t.Fatalf("sync status = %+v", state.Sync)
	}
}
