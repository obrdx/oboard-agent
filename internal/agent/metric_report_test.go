package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/gorilla/websocket"
)

func TestMetricReportQueuePersistsOrdersAndAcknowledges(t *testing.T) {
	stateDir := t.TempDir()
	runner := New(Config{AgentID: "agent-metric", StateDir: stateDir, ResourceProfile: "large", CommandTimeoutSeconds: 20})
	base := time.Now().UTC().Truncate(time.Second)
	later := model.MetricReport{ReportID: "later", SampledAt: base.Add(time.Minute), CPUUsagePercent: 20}
	earlier := model.MetricReport{ReportID: "earlier", SampledAt: base, CPUUsagePercent: 10}
	if _, err := runner.queueMetricReport(later, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.queueMetricReport(earlier, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(runner.metricReportStatePath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode=%v err=%v", info.Mode().Perm(), err)
	}
	restarted := New(Config{AgentID: "agent-metric", StateDir: stateDir, ResourceProfile: "large", CommandTimeoutSeconds: 20})
	pending, ok := restarted.nextPendingMetricReport()
	if !ok || pending.ReportID != earlier.ReportID {
		t.Fatalf("first pending=%#v ok=%v", pending, ok)
	}
	if err := restarted.ackMetricReport("unknown"); err != nil {
		t.Fatal(err)
	}
	if stillFirst, ok := restarted.nextPendingMetricReport(); !ok || stillFirst.ReportID != earlier.ReportID {
		t.Fatalf("unknown ack advanced queue: %#v ok=%v", stillFirst, ok)
	}
	if err := restarted.ackMetricReport(earlier.ReportID); err != nil {
		t.Fatal(err)
	}
	pending, ok = restarted.nextPendingMetricReport()
	if !ok || pending.ReportID != later.ReportID {
		t.Fatalf("pending after ack=%#v ok=%v", pending, ok)
	}
}

func TestMetricReportQueueBoundsAndPersistenceFailureRollback(t *testing.T) {
	runner := New(Config{AgentID: "agent-metric", StateDir: t.TempDir(), ResourceProfile: "large", CommandTimeoutSeconds: 20})
	now := time.Now().UTC()
	runner.metricReportStateLoaded = true
	runner.metricReportState.Pending = append(runner.metricReportState.Pending, model.MetricReport{ReportID: "expired", SampledAt: now.Add(-metricReportRetention - time.Minute)})
	for index := 0; index < metricReportMaxPending+3; index++ {
		runner.metricReportState.Pending = append(runner.metricReportState.Pending, model.MetricReport{ReportID: string(rune(index + 1)), SampledAt: now.Add(time.Duration(index) * time.Second)})
	}
	runner.metricReportMu.Lock()
	dropped := runner.pruneMetricReportStateLocked(now)
	pending := append([]model.MetricReport(nil), runner.metricReportState.Pending...)
	runner.metricReportMu.Unlock()
	if dropped != 4 || len(pending) != metricReportMaxPending || pending[0].ReportID == "expired" {
		t.Fatalf("dropped=%d pending=%d first=%q", dropped, len(pending), pending[0].ReportID)
	}

	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := New(Config{AgentID: "agent-metric", StateDir: blocked, ResourceProfile: "large", CommandTimeoutSeconds: 20})
	broken.metricReportStateLoaded = true
	broken.metricReportState.Pending = []model.MetricReport{{ReportID: "durable", SampledAt: now}}
	if _, err := broken.queueMetricReport(model.MetricReport{ReportID: "new", SampledAt: now.Add(time.Minute)}, now.Add(time.Minute)); err == nil {
		t.Fatal("queue succeeded with unwritable state path")
	}
	if len(broken.metricReportState.Pending) != 1 || broken.metricReportState.Pending[0].ReportID != "durable" {
		t.Fatalf("queue rollback=%#v", broken.metricReportState.Pending)
	}
}

func TestCollectMetricReportQueuesIndependentMinuteSample(t *testing.T) {
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	runner := New(Config{AgentID: "agent-metric", StateDir: t.TempDir(), ResourceProfile: "large", CommandTimeoutSeconds: 20})
	runner.clock = nil
	sampledAt := time.Date(2026, 8, 24, 12, 34, 56, 789, time.UTC)
	if err := runner.collectMetricReport(sampledAt); err != nil {
		t.Fatal(err)
	}
	report, ok := runner.nextPendingMetricReport()
	if !ok || report.ReportID == "" || len(report.ReportID) > 128 || !report.SampledAt.Equal(sampledAt) {
		t.Fatalf("collected report=%#v ok=%v", report, ok)
	}
}

func TestMetricReportQueueReplaysInOrderOverWebSocket(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	received := make(chan []string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(w, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "hello", "server_id": 1, "monitoring_mode": "lightweight"})
		ids := make([]string, 0, 2)
		for len(ids) < 2 {
			var message struct {
				Type   string             `json:"type"`
				Report model.MetricReport `json:"metric_report"`
			}
			if conn.ReadJSON(&message) != nil {
				return
			}
			if message.Type != "metric_report" {
				continue
			}
			ids = append(ids, message.Report.ReportID)
			_ = conn.WriteJSON(map[string]any{"type": "metric_report_ack", "report_id": message.Report.ReportID})
		}
		received <- ids
	}))
	defer server.Close()

	stateDir := t.TempDir()
	runner := newTestRunner(t, Config{AgentID: "agent-metric", AgentToken: "token", ControllerURL: server.URL, StateDir: stateDir, ResourceProfile: "large", CommandTimeoutSeconds: 20, AllowInsecureController: true})
	base := time.Now().UTC()
	_, _ = runner.queueMetricReport(model.MetricReport{ReportID: "second", SampledAt: base.Add(time.Minute)}, base.Add(time.Minute))
	_, _ = runner.queueMetricReport(model.MetricReport{ReportID: "first", SampledAt: base}, base.Add(time.Minute))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = runner.connectTestControl(ctx) }()
	select {
	case ids := <-received:
		if len(ids) != 2 || ids[0] != "first" || ids[1] != "second" {
			t.Fatalf("replay order=%v", ids)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for metric replay")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := runner.nextPendingMetricReport(); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("acknowledged queue was not drained")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
