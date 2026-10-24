package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/OboardProject/oboard-agent/internal/auditwire"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestAccountActivityDurableBeforeACKAndRestart(t *testing.T) {
	dir := t.TempDir()
	report := auditwire.Report{CollectorStartedAt: time.Unix(600, 0).UnixNano(), CollectorBootID: "0123456789abcdef0123456789abcdef", StreamType: "kernel", Sequence: 1, MinuteUnix: 600, ClockState: "aligned", Items: []auditwire.Item{}}
	var runner *Runner
	localPending := true
	localACKs := 0
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch q.URL.Path {
		case "/activity/read":
			if localPending {
				json.NewEncoder(w).Encode(report)
			} else {
				w.Write([]byte("null"))
			}
		case "/activity/ack":
			raw, e := os.ReadFile(runner.statePath("account-activity-pending.json"))
			if e != nil {
				t.Error("ACK before persistence", e)
			}
			var p []auditwire.Report
			json.Unmarshal(raw, &p)
			if len(p) != 1 || !reflect.DeepEqual(p[0], report) {
				t.Error("wrong durable report")
			}
			localACKs++
			if localACKs == 1 {
				http.Error(w, "lost local ack", 503)
				return
			}
			localPending = false
			w.Write([]byte("{}"))
		default:
			http.NotFound(w, q)
		}
	}))
	defer local.Close()
	attempts := 0
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path != "/base/api/v1/agent/account-activity" || q.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("base path or auth lost")
		}
		var got auditwire.Report
		json.NewDecoder(q.Body).Decode(&got)
		if !reflect.DeepEqual(got, report) {
			t.Errorf("retry mutated %+v", got)
		}
		attempts++
		if attempts == 1 {
			http.Error(w, "lost ack", 503)
			return
		}
		json.NewEncoder(w).Encode(auditwire.Ack{Accepted: true, Duplicate: true, Sequence: 1})
	}))
	defer controller.Close()
	makeRunner := func() *Runner {
		r := newTestRunner(t, Config{StateDir: dir, ConnectionAuditEnabled: true, ControllerURL: controller.URL + "/base", AllowInsecureController: true, AgentToken: "test-token"})
		r.connectionAudit = nil
		r.coreClient = &http.Client{Transport: roundTripFunc(func(q *http.Request) (*http.Response, error) {
			q.URL.Scheme = "http"
			q.URL.Host = local.Listener.Addr().String()
			return http.DefaultTransport.RoundTrip(q)
		})}
		return r
	}
	runner = makeRunner()
	if runner.collectAndReportAccountActivity(context.Background()) == nil {
		t.Fatal("lost ACK accepted")
	}
	runner = makeRunner()
	if e := runner.collectAndReportAccountActivity(context.Background()); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(runner.statePath("account-activity-pending.json"))
	if e != nil || string(raw) != "[]" {
		t.Fatalf("pending retained %s %v", raw, e)
	}
	if localACKs != 2 {
		t.Fatal("local ACK was not retried")
	}
	if attempts != 2 {
		t.Fatal(attempts)
	}
}
func TestAccountActivityCapacityNeverACKsUnpersistedReport(t *testing.T) {
	r := newTestRunner(t, Config{StateDir: t.TempDir(), ConnectionAuditEnabled: true, ControllerURL: "https://controller.invalid"})
	r.connectionAudit = nil
	pending := make([]auditwire.Report, auditwire.MaxPending)
	for i := range pending {
		pending[i] = auditwire.Report{CollectorStartedAt: time.Unix(600, 0).UnixNano(), CollectorBootID: "0123456789abcdef0123456789abcdef", StreamType: "kernel", Sequence: uint64(i + 1), MinuteUnix: 600, Items: []auditwire.Item{}}
	}
	raw, _ := json.Marshal(pending)
	if e := r.stateWritePathSynced(r.statePath("account-activity-pending.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	next := pending[0]
	next.Sequence = 257
	body, _ := json.Marshal(next)
	r.coreClient = &http.Client{Transport: roundTripFunc(func(q *http.Request) (*http.Response, error) {
		if q.URL.Path == "/activity/ack" {
			t.Fatal("unpersisted report ACKed")
		}
		b := []byte(`{}`)
		if q.URL.Path == "/activity/read" {
			b = body
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
	})}
	r.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Status: "503 unavailable", Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	if r.collectAndReportAccountActivity(context.Background()) == nil {
		t.Fatal("capacity not surfaced")
	}
	after, _ := r.stateReadPath(r.statePath("account-activity-pending.json"))
	if !bytes.Equal(raw, after) {
		t.Fatal("pending changed under capacity pressure")
	}
}

func TestAccountActivityDisabledDoesNotPoll(t *testing.T) {
	r := New(Config{StateDir: t.TempDir()})
	r.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("disabled poll"); return nil, nil })}
	if e := r.collectAndReportAccountActivity(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestAccountActivityRestartPreservesPreviousBootPending(t *testing.T) {
	r := newTestRunner(t, Config{StateDir: t.TempDir(), ConnectionAuditEnabled: true, ControllerURL: "https://controller.invalid"})
	r.connectionAudit = nil
	old := auditwire.Report{CollectorBootID: "0123456789abcdef0123456789abcdef", CollectorStartedAt: time.Unix(600, 0).UnixNano(), StreamType: "kernel", Sequence: 1, MinuteUnix: 600, Items: []auditwire.Item{}}
	next := old
	next.CollectorBootID = "fedcba9876543210fedcba9876543210"
	next.CollectorStartedAt = time.Unix(660, 0).UnixNano()
	next.MinuteUnix = 660
	raw, err := json.Marshal([]auditwire.Report{old})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.stateWritePathSynced(r.statePath("account-activity-pending.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	acked := false
	r.coreClient = &http.Client{Transport: roundTripFunc(func(q *http.Request) (*http.Response, error) {
		body := []byte(`{}`)
		switch q.URL.Path {
		case "/activity/read":
			body, _ = json.Marshal(next)
		case "/activity/ack":
			persisted, err := r.stateReadPath(r.statePath("account-activity-pending.json"))
			var pending []auditwire.Report
			if err != nil || json.Unmarshal(persisted, &pending) != nil || !reflect.DeepEqual(pending, []auditwire.Report{old, next}) {
				t.Fatal("new boot ACK did not preserve both durable reports")
			}
			acked = true
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	var received []auditwire.Report
	r.client = &http.Client{Transport: roundTripFunc(func(q *http.Request) (*http.Response, error) {
		var report auditwire.Report
		if err := json.NewDecoder(q.Body).Decode(&report); err != nil {
			t.Fatal(err)
		}
		received = append(received, report)
		body, _ := json.Marshal(auditwire.Ack{Sequence: report.Sequence, Accepted: true})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	if err := r.collectAndReportAccountActivity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !acked || !reflect.DeepEqual(received, []auditwire.Report{old, next}) {
		t.Fatalf("boot transition lost or reordered reports: %+v", received)
	}
	persisted, err := r.stateReadPath(r.statePath("account-activity-pending.json"))
	if err != nil || string(persisted) != "[]" {
		t.Fatalf("acknowledged reports still pending: %s, %v", persisted, err)
	}
}
