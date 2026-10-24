package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/auditwire"
)

func TestAccountActivitySharedContract(t *testing.T) {
	raw, err := os.ReadFile("../auditwire/testdata/account_activity_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != "410ff3c513ff2d04149da9ad6ce29355abbd3c343bd2ba7c562dc1826225f543" {
		t.Fatalf("shared fixture changed: %s", got)
	}
	var fixture struct {
		Report  json.RawMessage `json:"report"`
		Invalid []struct {
			Name, Field string
			Value       json.RawMessage
			AgentDecode bool `json:"agent_decode"`
		} `json:"invalid"`
		Acks []struct {
			ReportSequence *uint64 `json:"report_sequence"`
			Name           string
			Body           json.RawMessage
			Remove         bool
		} `json:"acks"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var report auditwire.Report
	if err := json.Unmarshal(fixture.Report, &report); err != nil {
		t.Fatal(err)
	}
	if report.CollectorStartedAt != 1790000000123456789 || report.Sequence != 1 || report.Items[0].UploadBytes != 9007199254740993 || report.ClockState != "unknown" || report.Complete {
		t.Fatalf("wire precision/coverage lost: %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]json.RawMessage
	if err := json.Unmarshal(fixture.Report, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("wire fields changed: %s", encoded)
	}
	for _, vector := range fixture.Invalid {
		t.Run(vector.Name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(fixture.Report, &fields); err != nil {
				t.Fatal(err)
			}
			if string(vector.Value) == "null" {
				delete(fields, vector.Field)
			} else {
				fields[vector.Field] = vector.Value
			}
			body, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var decoded auditwire.Report
			// Agent transport decoding is not the Controller's semantic validator.
			if err := json.Unmarshal(body, &decoded); (err == nil) != vector.AgentDecode {
				t.Fatalf("Agent decode: %v", err)
			}
		})
	}
	for _, vector := range fixture.Acks {
		t.Run(vector.Name, func(t *testing.T) {
			report := report
			if vector.ReportSequence != nil {
				report.Sequence = *vector.ReportSequence
			}
			var ack auditwire.Ack
			if err := json.Unmarshal(vector.Body, &ack); err != nil {
				t.Fatal(err)
			}
			calls := 0
			controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls++
				if req.Method != http.MethodPost || req.URL.Path != "/base/api/v1/agent/account-activity" || req.Header.Get("Authorization") != "Bearer contract-token" {
					t.Error("request contract lost")
				}
				var received auditwire.Report
				if err := json.NewDecoder(req.Body).Decode(&received); err != nil || !reflect.DeepEqual(received, report) {
					t.Errorf("pending report changed: %+v %v", received, err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(vector.Body)
			}))
			defer controller.Close()
			r := newTestRunner(t, Config{StateDir: t.TempDir(), ConnectionAuditEnabled: true, ControllerURL: controller.URL + "/base", AllowInsecureController: true, AgentToken: "contract-token"})
			r.connectionAudit = nil
			r.coreClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/activity/clock" {
					var clock struct {
						ControllerUnix int64 `json:"controller_unix"`
					}
					if err := json.NewDecoder(req.Body).Decode(&clock); err != nil || clock.ControllerUnix != 0 {
						t.Errorf("missing reference must remain unknown: %+v %v", clock, err)
					}
				} else if req.URL.Path != "/activity/read" {
					t.Errorf("unexpected local request: %s", req.URL.Path)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("null")), Header: make(http.Header)}, nil
			})}
			pending, err := json.Marshal([]auditwire.Report{report})
			if err != nil {
				t.Fatal(err)
			}
			path := r.statePath("account-activity-pending.json")
			if err := r.stateWritePathSynced(path, pending, 0600); err != nil {
				t.Fatal(err)
			}
			err = r.collectAndReportAccountActivity(context.Background())
			if (err == nil) != vector.Remove {
				t.Fatalf("ACK disposition: %v", err)
			}
			after, err := r.stateReadPath(path)
			if err != nil {
				t.Fatal(err)
			}
			expected := string(pending)
			if vector.Remove {
				expected = "[]"
			}
			if string(after) != expected || calls != 1 {
				t.Fatalf("pending=%s calls=%d", after, calls)
			}
		})
	}
}
