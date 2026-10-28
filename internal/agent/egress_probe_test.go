package agent

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func externalEgressAgentTarget(id int) model.ExternalEgressProbeTarget {
	return model.ExternalEgressProbeTarget{
		ProbeID: "probe-" + string(rune('a'+id)), PathID: int64(id + 1), ExternalOutboundID: int64(id + 101),
		OwnerServerID: 1, OutboundTag: "path-1-step-" + string(rune('1'+id)), TopologyFingerprint: "fingerprint",
	}
}

func TestExternalEgressProbeRejectsConfigVersionMismatchBeforeCoreRequest(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	if err := runner.persistAppliedVersion("apply_deployment", 7, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"exit_ip":"8.8.8.8"}`)), Header: make(http.Header)}, nil
	})}
	result, err := runner.runExternalEgressProbeTask(context.Background(), model.ExternalEgressProbePlan{ExpectedConfigVersion: 8, Targets: []model.ExternalEgressProbeTarget{externalEgressAgentTarget(0)}})
	if err == nil || !strings.Contains(err.Error(), "active version is 7") {
		t.Fatalf("version mismatch error = %v", err)
	}
	if calls.Load() != 0 || len(result.Items) != 1 || result.Items[0].Status != "failed" || !strings.Contains(result.Items[0].Error, "active version is 7") {
		t.Fatalf("version mismatch result = %#v, calls = %d", result, calls.Load())
	}
}

func TestExternalEgressProbeLimitsCoreRequestsToFourConcurrent(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	if err := runner.persistAppliedVersion("apply_deployment", 9, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/outbounds/egress-ip" {
			return &http.Response{StatusCode: http.StatusBadRequest, Body: http.NoBody, Header: make(http.Header)}, nil
		}
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-request.Context().Done():
		}
		active.Add(-1)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"exit_ip":"8.8.8.8"}`)), Header: make(http.Header)}, nil
	})}
	targets := make([]model.ExternalEgressProbeTarget, 8)
	for i := range targets {
		targets[i] = externalEgressAgentTarget(i)
	}
	type probeOutcome struct {
		result model.ExternalEgressProbeResult
		err    error
	}
	done := make(chan probeOutcome, 1)
	go func() {
		result, err := runner.runExternalEgressProbeTask(context.Background(), model.ExternalEgressProbePlan{ExpectedConfigVersion: 9, TimeoutMS: 1000, Targets: targets})
		done <- probeOutcome{result: result, err: err}
	}()
	for i := 0; i < externalEgressProbeConcurrency; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for the first four probes")
		}
	}
	select {
	case <-started:
		t.Fatal("a fifth probe started before a concurrency slot was released")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	var outcome probeOutcome
	select {
	case outcome = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe batch did not finish")
	}
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	if maximum.Load() != externalEgressProbeConcurrency {
		t.Fatalf("maximum concurrency = %d, want %d", maximum.Load(), externalEgressProbeConcurrency)
	}
	for _, item := range outcome.result.Items {
		if item.Status != "succeeded" || item.ExitIP != "8.8.8.8" {
			t.Fatalf("probe item = %#v", item)
		}
	}
}

func TestStandaloneExternalProbeNeedsNoDeployedConfig(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	calls := 0
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Path != "/outbounds/check" {
			t.Fatalf("wrong kernel path: %s", request.URL.Path)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"exit_ip":"8.8.8.8"}`)), Header: make(http.Header)}, nil
	})}
	plan := model.ExternalEgressProbePlan{Standalone: &model.ExternalOutboundProbe{ExternalOutboundID: 2, Fingerprint: strings.Repeat("a", 64), Outbound: []byte(`{"type":"http","tag":"external-probe","server":"1.1.1.1","server_port":8080}`)}}
	result, err := runner.runExternalEgressProbeTask(context.Background(), plan)
	if err != nil || len(result.Items) != 1 || result.Items[0].ExitIP != "8.8.8.8" || calls != 1 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	plan.Targets = []model.ExternalEgressProbeTarget{externalEgressAgentTarget(0)}
	if _, err := runner.runExternalEgressProbeTask(context.Background(), plan); err == nil || calls != 1 {
		t.Fatal("mixed standalone/path probe accepted")
	}
}

func TestStandaloneExternalProbeDoesNotExposeProxyErrors(t *testing.T) {
	runner := New(Config{StateDir: t.TempDir(), ResourceProfile: "large"})
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader("password=private-secret")), Header: make(http.Header)}, nil
	})}
	result, err := runner.runExternalEgressProbeTask(context.Background(), model.ExternalEgressProbePlan{Standalone: &model.ExternalOutboundProbe{ExternalOutboundID: 1, Fingerprint: strings.Repeat("b", 64), Outbound: []byte(`{}`)}})
	if err == nil || len(result.Items) != 1 || result.Items[0].Status != "failed" || strings.Contains(result.Items[0].Error, "private-secret") {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}
