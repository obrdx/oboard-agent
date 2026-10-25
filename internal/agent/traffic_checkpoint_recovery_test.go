package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRejectedTrafficRangeRecoversFromPersistedCheckpoint(t *testing.T) {
	for _, status := range []string{trafficStatusCheckpointGap, trafficStatusCheckpointOverlap} {
		t.Run(status, func(t *testing.T) {
			cfg := Config{StateDir: t.TempDir(), AgentID: "agent-1"}
			runner := New(cfg)
			state := runner.trafficStateLocked()
			state.RecoveryRequired = false
			item := trafficSnapshotItem{Key: "user:7", Source: "core", CounterEpoch: "ce_1", UserID: 7, InboundID: 34, PeriodKey: "2026-10", Upload: 400, Download: 546 * 1024}
			runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
			streamID := trafficStreamID(item.Source, item.Key)
			checkpoint := trafficStreamCheckpoint{Source: item.Source, StreamID: streamID, CounterEpoch: item.CounterEpoch, PeriodKey: item.PeriodKey, AcceptedUpload: 100, AcceptedDownload: 200, Status: status}
			var rejected []trafficAcceptedReport
			for id := range state.PendingReports {
				rejected = append(rejected, trafficAcceptedReport{ReportID: id, Status: status, AcceptedUpload: 100, AcceptedDownload: 200})
			}
			applyTrafficLedgerResponse(state, trafficReportResponse{StreamCheckpoints: []trafficStreamCheckpoint{checkpoint}, AcceptedReports: rejected})
			if !state.RecoveryRequired || len(state.PendingReports) != 0 {
				t.Fatalf("rejected state = %+v", state)
			}
			if err := runner.saveTrafficState(*state); err != nil {
				t.Fatal(err)
			}
			runner = New(cfg)
			state = runner.trafficStateLocked()
			item.Upload += 20
			item.Download += 1024
			runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, true)
			applyTrafficLedgerResponse(state, trafficReportResponse{StreamCheckpoints: []trafficStreamCheckpoint{checkpoint}})
			if state.RecoveryRequired || state.Streams[streamID].Status != trafficStatusHealthy {
				t.Fatalf("checkpoint did not recover stream: %+v", state.Streams[streamID])
			}
			runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
			if len(state.PendingReports) != 1 {
				t.Fatalf("pending reports = %d, want 1", len(state.PendingReports))
			}
			var report *trafficPendingRange
			for _, pending := range state.PendingReports {
				report = pending
			}
			if report.FromUpload != 100 || report.FromDownload != 200 || report.ToUpload != item.Upload || report.ToDownload != item.Download {
				t.Fatalf("recovered range = %+v", report)
			}
			runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
			if len(state.PendingReports) != 1 {
				t.Fatal("unacknowledged range was duplicated")
			}
			applyTrafficLedgerResponse(state, trafficReportResponse{AcceptedReports: []trafficAcceptedReport{{ReportID: report.ReportID, Status: "accepted", AcceptedUpload: item.Upload, AcceptedDownload: item.Download}}})
			runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
			if len(state.PendingReports) != 0 || state.RecoveryRequired {
				t.Fatal("acknowledged snapshot was billed again")
			}
			item.Download += 50
			runner.observeTrafficSnapshotLocked(state, []trafficSnapshotItem{item}, false)
			for _, next := range state.PendingReports {
				if next.FromDownload != report.ToDownload || next.ToDownload != item.Download || next.FromUpload != next.ToUpload {
					t.Fatalf("next incremental range = %+v", next)
				}
			}
			if len(state.PendingReports) != 1 {
				t.Fatal("new bytes did not produce an incremental range")
			}
		})
	}
}

func TestTrafficCheckpointRecoveryPreservesCounterSafety(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		epoch, period, status string
		upload, download      int64
		want                  string
	}{
		{"upload below checkpoint", "ce_1", "2026-10", trafficStatusCheckpointGap, 99, 300, trafficStatusCounterRegression},
		{"download below checkpoint", "ce_1", "2026-10", trafficStatusCheckpointGap, 300, 199, trafficStatusCounterRegression},
		{"existing regression", "ce_1", "2026-10", trafficStatusCounterRegression, 300, 300, trafficStatusCounterRegression},
		{"different epoch", "ce_other", "2026-10", trafficStatusCheckpointGap, 300, 300, trafficStatusEpochConflict},
		{"different period", "ce_1", "other-period", trafficStatusCheckpointGap, 300, 300, trafficStatusCheckpointGap},
		{"missing epoch", "", "2026-10", trafficStatusCheckpointGap, 300, 300, trafficStatusCheckpointGap},
		{"missing period", "ce_1", "", trafficStatusCheckpointGap, 300, 300, trafficStatusCheckpointGap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := trafficStreamID("core", "user:7")
			stream := &trafficStreamState{Source: "core", SnapshotKey: "user:7", CounterEpoch: "ce_1", PeriodKey: "2026-10", UserID: 7, ObservedUpload: tc.upload, ObservedDownload: tc.download, Status: tc.status}
			state := &trafficLocalState{Streams: map[string]*trafficStreamState{id: stream}, PendingReports: map[string]*trafficPendingRange{}, RecoveryRequired: true}
			applyTrafficLedgerResponse(state, trafficReportResponse{StreamCheckpoints: []trafficStreamCheckpoint{{Source: "core", StreamID: id, CounterEpoch: tc.epoch, PeriodKey: tc.period, AcceptedUpload: 100, AcceptedDownload: 200, Status: trafficStatusCheckpointGap}}})
			if !state.RecoveryRequired || stream.Status != tc.want || len(state.PendingReports) != 0 {
				t.Fatalf("unsafe recovery: recovery=%v stream=%+v", state.RecoveryRequired, stream)
			}
		})
	}
}

func TestTrafficReportLoopRecoversGapWithoutRebilling(t *testing.T) {
	item := trafficSnapshotItem{Key: "user:7", Source: "core", CounterEpoch: "ce_1", UserID: 7, InboundID: 34, PeriodKey: "2026-10", Upload: 400, Download: 546 * 1024}
	streamID := trafficStreamID(item.Source, item.Key)
	var acceptedUpload, acceptedDownload, billedUpload, billedDownload int64
	var calls, rejected int
	status := trafficStatusHealthy
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/agent/traffic-reports" {
			http.NotFound(w, req)
			return
		}
		var batch struct {
			Reports []trafficLedgerReportItem `json:"reports"`
		}
		if err := json.NewDecoder(req.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		calls++
		var reports []trafficAcceptedReport
		for _, report := range batch.Reports {
			if report.FromUpload != acceptedUpload || report.FromDownload != acceptedDownload {
				status = trafficStatusCheckpointGap
				rejected++
			} else {
				billedUpload += report.ToUpload - report.FromUpload
				billedDownload += report.ToDownload - report.FromDownload
				acceptedUpload, acceptedDownload = report.ToUpload, report.ToDownload
				status = trafficStatusHealthy
			}
			reportStatus := status
			if reportStatus == trafficStatusHealthy {
				reportStatus = "accepted"
			}
			reports = append(reports, trafficAcceptedReport{ReportID: report.ReportID, Status: reportStatus, AcceptedUpload: acceptedUpload, AcceptedDownload: acceptedDownload})
		}
		_ = json.NewEncoder(w).Encode(trafficReportResponse{AcceptedReports: reports, StreamCheckpoints: []trafficStreamCheckpoint{{Source: item.Source, StreamID: streamID, CounterEpoch: item.CounterEpoch, PeriodKey: item.PeriodKey, AcceptedUpload: acceptedUpload, AcceptedDownload: acceptedDownload, Status: status}}})
	}))
	defer controller.Close()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/traffic/snapshot":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []trafficSnapshotItem{item}})
		case "/traffic/policy":
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.NotFound(w, req)
		}
	}))
	defer core.Close()
	runner := newTestRunner(t, Config{ControllerURL: controller.URL, AgentID: "agent-1", AgentToken: "token", StateDir: t.TempDir()})
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.URL.Scheme, clone.URL.Host = "http", core.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(clone)
	})}
	state := runner.trafficStateLocked()
	state.RecoveryRequired = false
	state.Streams[streamID] = &trafficStreamState{Source: item.Source, SnapshotKey: item.Key, CounterEpoch: item.CounterEpoch, PeriodKey: item.PeriodKey, UserID: item.UserID, InboundID: item.InboundID, AcceptedUpload: 100, AcceptedDownload: 200, Status: trafficStatusHealthy}
	if err := runner.collectAndReportTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rejected != 1 || !state.RecoveryRequired || billedDownload != 0 {
		t.Fatalf("gap not reproduced: rejected=%d state=%+v", rejected, state)
	}
	if err := runner.collectAndReportTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || state.RecoveryRequired || billedUpload != item.Upload || billedDownload != item.Download || len(state.PendingReports) != 0 {
		t.Fatalf("recovery failed: calls=%d billed=%d/%d state=%+v", calls, billedUpload, billedDownload, state)
	}
	if err := runner.collectAndReportTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if billedUpload != item.Upload || billedDownload != item.Download {
		t.Fatal("unchanged snapshot billed again")
	}
	item.Download += 123
	if err := runner.collectAndReportTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rejected != 1 || billedUpload != item.Upload || billedDownload != item.Download || len(state.PendingReports) != 0 {
		t.Fatalf("incremental billing failed: rejected=%d billed=%d/%d", rejected, billedUpload, billedDownload)
	}
}
