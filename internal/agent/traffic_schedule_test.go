package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTrafficStablePhaseAndBounds(t *testing.T) {
	for _, period := range []time.Duration{time.Nanosecond, 2 * time.Nanosecond, 3 * time.Nanosecond, time.Millisecond, time.Second, 9 * time.Second, 30 * time.Second} {
		for i := int64(1); i <= 100; i++ {
			id := fmt.Sprintf("agent-%d", i)
			a := trafficPhase(id, i, period)
			b := trafficPhase(id, i, period)
			window := min(10*time.Second, period/3)
			if a != b || a < 0 || (window > 0 && a >= window) || (window == 0 && a != 0) {
				t.Fatalf("period=%s offset=%s/%s", period, a, b)
			}
		}
	}
	seen := map[time.Duration]bool{}
	for i := int64(1); i <= 100; i++ {
		seen[trafficPhase(fmt.Sprintf("agent-%d", i), i, 30*time.Second)] = true
	}
	if len(seen) != 100 {
		t.Fatalf("distinct offsets=%d", len(seen))
	}
	if trafficSchedulePeriod(0) != 30*time.Second || trafficSchedulePeriod(-1) != 30*time.Second || trafficSchedulePeriod(time.Second) != time.Second {
		t.Fatal("invalid period normalization")
	}
}
func TestTrafficSchedulePreservesPeriodAndSkipsMissedSlots(t *testing.T) {
	at := time.Now()
	period := 30 * time.Second
	offset := trafficPhase("agent-a", 46, period)
	delay := trafficInitialDelay(at, period, offset)
	if delay <= 0 || delay > period {
		t.Fatal(delay)
	}
	next := at.Add(delay)
	initial := next
	for i := 0; i < 1000; i++ {
		next = trafficNextDeadline(next, next.Add(3*time.Millisecond), period)
	}
	if next.Sub(initial) != 1000*period {
		t.Fatalf("drift=%s", next.Sub(initial))
	}
	slow := initial.Add(100*period + time.Second)
	next = trafficNextDeadline(initial, slow, period)
	if !next.After(slow) || next.Sub(slow) > period || next.Sub(initial)%period != 0 {
		t.Fatalf("missed slots=%v", next)
	}
	// Reconnect wake before a deadline must keep the original deadline.
	if got := trafficNextDeadline(initial, initial.Add(-time.Second), period); !got.Equal(initial) {
		t.Fatal("wake moved phase")
	}
	// Starting at a different instant aligns to the same identity phase.
	restart := at.Add(13 * time.Second)
	restarted := restart.Add(trafficInitialDelay(restart, period, offset))
	if restarted.Sub(initial)%period != 0 {
		t.Fatal("restart changed phase")
	}
}
func TestTrafficRecoveryWakeIsBoundedAndNonblocking(t *testing.T) {
	r := &Runner{trafficReportWake: make(chan struct{}, 1)}
	for i := 0; i < 100; i++ {
		r.wakeTrafficReport()
	}
	if len(r.trafficReportWake) != 1 {
		t.Fatal("wake not coalesced")
	}
	(&Runner{}).wakeTrafficReport()
}

func TestTrafficLoopStartupRecoveryAndCancellation(t *testing.T) {
	calls := make(chan struct{}, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v1/agent/traffic-reports" {
			calls <- struct{}{}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "policies": map[string]any{}, "accepted_reports": []any{}})
			return
		}
		http.NotFound(w, req)
	}))
	defer server.Close()
	r := newTestRunner(t, Config{ControllerURL: server.URL, AgentID: "schedule-agent", ServerID: 46, AgentToken: "synthetic", StateDir: t.TempDir()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.runTrafficLoop(ctx) }()
	await := func() {
		t.Helper()
		select {
		case <-calls:
		case <-time.After(3 * time.Second):
			t.Fatal("critical traffic sync waited for periodic phase")
		}
	}
	await()
	r.wakeTrafficReport()
	await()
	cancel()
	select {
	case <-done:
	case <-time.After(7 * time.Second):
		t.Fatal("traffic loop did not finish bounded flush")
	}
}
