package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func withNTPQueryStub(t *testing.T, query func(context.Context, string) (time.Duration, error)) {
	t.Helper()
	previous := queryNTPSource
	queryNTPSource = query
	t.Cleanup(func() { queryNTPSource = previous })
}

func TestQueryNTPMedianRequiresTwoSourcesAndUsesMedian(t *testing.T) {
	withNTPQueryStub(t, func(_ context.Context, server string) (time.Duration, error) {
		switch server {
		case "one.example":
			return -12 * time.Second, nil
		case "two.example":
			return 3 * time.Second, nil
		case "three.example":
			return 40 * time.Second, nil
		default:
			return 0, errors.New("unexpected source")
		}
	})
	reference, err := queryNTPMedian(context.Background(), []string{"one.example", "two.example", "three.example"})
	if err != nil {
		t.Fatal(err)
	}
	if reference.Offset != 3*time.Second || !strings.Contains(reference.Source, "one.example") || !strings.Contains(reference.Source, "three.example") {
		t.Fatalf("median reference = %#v", reference)
	}

	withNTPQueryStub(t, func(_ context.Context, server string) (time.Duration, error) {
		if server == "one.example" {
			return time.Second, nil
		}
		return 0, errors.New("unavailable")
	})
	if _, err := queryNTPMedian(context.Background(), []string{"one.example", "two.example", "three.example"}); err == nil || !strings.Contains(err.Error(), "至少需要两个") {
		t.Fatalf("single-source result error = %v", err)
	}
}

func TestNormalizeNTPServersCanonicalizesIPv6AndRejectsPorts(t *testing.T) {
	servers, err := normalizeNTPServers([]string{"[2001:db8::1]", "time.example.com", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if servers[0] != "2001:db8::1" {
		t.Fatalf("normalized IPv6 NTP server = %q", servers[0])
	}
	if _, err := normalizeNTPServers([]string{"[2001:db8::1]:123", "time.example.com", "192.0.2.1"}); err == nil {
		t.Fatal("NTP server with an explicit port was accepted")
	}
}

func TestNTPTimestampCodecBoundaries(t *testing.T) {
	tests := []time.Time{
		time.Unix(-ntpUnixEpochDelta, 0).UTC(),
		time.Unix(0, 123_456_789).UTC(),
		time.Unix(int64(math.MaxUint32)-ntpUnixEpochDelta, 999_999_999).UTC(),
	}
	for _, value := range tests {
		encoded, err := encodeNTPTimestamp(value)
		if err != nil {
			t.Fatalf("encode %s: %v", value, err)
		}
		decoded := decodeNTPTimestamp(encoded)
		if delta := value.Sub(decoded); delta < 0 || delta > time.Nanosecond {
			t.Fatalf("round trip %s = %s (delta %s)", value, decoded, delta)
		}
	}

	for _, value := range []time.Time{
		time.Unix(-ntpUnixEpochDelta-1, 0).UTC(),
		time.Unix(int64(math.MaxUint32)-ntpUnixEpochDelta+1, 0).UTC(),
	} {
		if _, err := encodeNTPTimestamp(value); err == nil {
			t.Fatalf("out-of-era time %s was encoded", value)
		}
	}
}

func TestResolveTimeReferenceRejectsControllerNTPConflict(t *testing.T) {
	withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) { return 0, nil })
	runner := New(Config{StateDir: t.TempDir(), TimeSyncCommand: "none", ResourceProfile: "large"})
	runner.setControllerReference(time.Now().Add(10 * time.Second))
	_, err := runner.resolveTimeReference(context.Background(), []string{"one.example", "two.example", "three.example"})
	if err == nil || !strings.Contains(err.Error(), "拒绝应用") {
		t.Fatalf("controller/NTP conflict error = %v", err)
	}
}

func TestTimeCorrectionModesUseExpectedClockStrategy(t *testing.T) {
	withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) { return 45 * time.Second, nil })
	tests := []struct {
		name            string
		mode            model.TimeCorrectionMode
		wantStatus      string
		wantLogical     bool
		wantSystemTry   bool
		wantSystemError bool
		wantEffectiveMS int64
	}{
		{name: "off only reports skew", mode: model.TimeCorrectionOff, wantStatus: "skewed", wantEffectiveMS: 45_000},
		{name: "auto falls back to logical clock", mode: model.TimeCorrectionAuto, wantStatus: "corrected", wantLogical: true, wantSystemTry: true, wantSystemError: true},
		{name: "ntp directly enables logical clock", mode: model.TimeCorrectionNTP, wantStatus: "corrected", wantLogical: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := New(Config{StateDir: t.TempDir(), TimeSyncCommand: "none", ResourceProfile: "large"})
			result, err := runner.runTimeCheckTask(context.Background(), model.TimeCheckPlan{CorrectionMode: test.mode, ThresholdSeconds: 30, NTPServers: []string{"one.example", "two.example", "three.example"}})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.wantStatus || result.LogicalTimeActive != test.wantLogical || result.SystemSyncAttempted != test.wantSystemTry {
				t.Fatalf("time result = %#v", result)
			}
			if result.EffectiveOffsetMS != test.wantEffectiveMS {
				t.Fatalf("effective offset = %d, want %d", result.EffectiveOffsetMS, test.wantEffectiveMS)
			}
			if (result.SystemSyncError != "") != test.wantSystemError {
				t.Fatalf("system sync error = %q", result.SystemSyncError)
			}
			if result.Error != "" {
				t.Fatalf("time check reported a core error before core configuration: %q", result.Error)
			}
			if test.wantLogical && absDuration(runner.clock.Now().Sub(time.Now().Add(45*time.Second))) > time.Second {
				t.Fatalf("logical clock did not apply expected offset: now=%s", runner.clock.Now())
			}
		})
	}
}

func TestTimeCheckKeepsEffectiveOffsetWhenCorrectionIsNotNeeded(t *testing.T) {
	withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) { return 12 * time.Second, nil })
	for _, mode := range []model.TimeCorrectionMode{model.TimeCorrectionOff, model.TimeCorrectionAuto, model.TimeCorrectionNTP} {
		runner := New(Config{StateDir: t.TempDir(), TimeSyncCommand: "none", ResourceProfile: "large"})
		result, err := runner.runTimeCheckTask(context.Background(), model.TimeCheckPlan{CorrectionMode: mode, ThresholdSeconds: 30, NTPServers: []string{"one.example", "two.example", "three.example"}})
		if err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		if result.Status != "ok" || result.RawOffsetMS != 12_000 || result.EffectiveOffsetMS != 12_000 || result.LogicalTimeActive {
			t.Fatalf("mode %s result = %#v", mode, result)
		}
	}
}

func TestTimeCheckConfigFailureAndRecovery(t *testing.T) {
	for _, failure := range []struct {
		name string
		err  error
	}{
		{"bind-mounted config", syscall.EBUSY},
		{"permission denied", os.ErrPermission},
	} {
		t.Run(failure.name, func(t *testing.T) {
			var queries atomic.Int32
			withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) {
				queries.Add(1)
				return -13 * time.Millisecond, nil
			})
			cfg := Config{StateDir: t.TempDir(), ConfigPath: filepath.Join(t.TempDir(), "config.json"), TimeCorrectionMode: model.TimeCorrectionOff, TimeSyncCommand: "none", ResourceProfile: "large"}
			if err := SaveConfig(cfg.ConfigPath, cfg); err != nil {
				t.Fatal(err)
			}
			runner := newTestRunner(t, cfg)
			previousSave := saveTimeCorrectionConfig
			t.Cleanup(func() { saveTimeCorrectionConfig = previousSave })
			saveTimeCorrectionConfig = func(_ *Runner, cfg Config) error {
				return &os.LinkError{Op: "rename", Old: cfg.ConfigPath + ".tmp", New: cfg.ConfigPath, Err: failure.err}
			}
			plan := model.TimeCheckPlan{CorrectionMode: model.TimeCorrectionNTP, NTPServers: []string{"one.example", "two.example", "three.example"}}
			payload, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			task := model.AgentTask{Type: model.AgentTaskTypeCheckTime, PayloadJSON: string(payload)}
			status, raw := runner.executeAgentTask(task)
			var result model.TimeCheckResult
			if err := json.Unmarshal([]byte(raw), &result); err != nil {
				t.Fatal(err)
			}
			if status != "failed" || result.Status != model.TimeCheckStatusConfigError || !strings.Contains(result.Error, failure.err.Error()) {
				t.Fatalf("config failure = %s %s", status, raw)
			}
			if queries.Load() != 0 || result.Source != "" || runner.Config().TimeCorrectionMode != model.TimeCorrectionOff || runner.clock.Snapshot().Enabled {
				t.Fatalf("config failure changed clock/mode or measured time: result=%#v queries=%d", result, queries.Load())
			}
			saved, err := LoadConfig(cfg.ConfigPath)
			if err != nil || saved.TimeCorrectionMode != model.TimeCorrectionOff {
				t.Fatalf("persisted mode after failure = %s, err=%v", saved.TimeCorrectionMode, err)
			}

			saveTimeCorrectionConfig = previousSave
			status, raw = runner.executeAgentTask(task)
			result = model.TimeCheckResult{}
			if err := json.Unmarshal([]byte(raw), &result); err != nil {
				t.Fatal(err)
			}
			if status != "succeeded" || result.Status != "ok" || result.RawOffsetMS != -13 || result.EffectiveOffsetMS != -13 || result.Error != "" || queries.Load() != 3 {
				t.Fatalf("writable config recovery = %s %s, queries=%d", status, raw, queries.Load())
			}
			saved, err = LoadConfig(cfg.ConfigPath)
			if err != nil || saved.TimeCorrectionMode != model.TimeCorrectionNTP || runner.Config().TimeCorrectionMode != model.TimeCorrectionNTP {
				t.Fatalf("persisted mode after recovery = %s, err=%v", saved.TimeCorrectionMode, err)
			}
			saveTimeCorrectionConfig = func(*Runner, Config) error {
				t.Fatal("unchanged mode must not rewrite config")
				return failure.err
			}
			if status, raw = runner.executeAgentTask(task); status != "succeeded" {
				t.Fatalf("unchanged mode = %s %s", status, raw)
			}
		})
	}
}

func TestConfigureCoreClockDefersUntilCoreIsConfigured(t *testing.T) {
	stateDir := t.TempDir()
	runner := New(Config{StateDir: stateDir, TimeSyncCommand: "none", ResourceProfile: "large"})
	requests := 0
	runner.coreClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("core unavailable")
	})}

	if err := runner.configureCoreClock(context.Background()); err != nil {
		t.Fatalf("clock sync before core configuration = %v", err)
	}
	if requests != 0 {
		t.Fatalf("clock sync requests before core configuration = %d, want 0", requests)
	}

	if err := os.WriteFile(filepath.Join(stateDir, "sing-box.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runner.configureCoreClock(context.Background()); err == nil || !strings.Contains(err.Error(), "core unavailable") {
		t.Fatalf("clock sync with configured unavailable core = %v", err)
	}
	if requests != 1 {
		t.Fatalf("clock sync requests with core configuration = %d, want 1", requests)
	}
}

func TestRuntimeClockPersistsAndRestoresMonotonicReference(t *testing.T) {
	dir := t.TempDir()
	clock := newRuntimeClock(dir, nil)
	reference := time.Now().UTC().Add(2 * time.Minute)
	if err := clock.Apply(true, reference, "ntp:test", reference); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, runtimeClockStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime clock state mode = %o", info.Mode().Perm())
	}
	restored := newRuntimeClock(dir, nil)
	if !restored.Snapshot().Enabled || restored.Snapshot().Source != "ntp:test" {
		t.Fatalf("restored clock state = %#v", restored.Snapshot())
	}
	if absDuration(restored.Now().Sub(clock.Now())) > time.Second {
		t.Fatalf("restored clock differs: restored=%s original=%s", restored.Now(), clock.Now())
	}
}

func TestTurningTimeCorrectionOffClearsLogicalClockWhenSourcesFail(t *testing.T) {
	withNTPQueryStub(t, func(context.Context, string) (time.Duration, error) { return 0, errors.New("offline") })
	runner := New(Config{StateDir: t.TempDir(), TimeSyncCommand: "none", TimeCorrectionMode: model.TimeCorrectionNTP, ResourceProfile: "large"})
	if err := runner.clock.Apply(true, time.Now().Add(time.Minute), "previous", time.Now()); err != nil {
		t.Fatal(err)
	}
	result, err := runner.runTimeCheckTask(context.Background(), model.TimeCheckPlan{CorrectionMode: model.TimeCorrectionOff, NTPServers: []string{"one.example", "two.example", "three.example"}})
	if err == nil || result.Status != "unavailable" {
		t.Fatalf("off mode failure result = %#v, err=%v", result, err)
	}
	if runner.clock.Snapshot().Enabled || result.LogicalTimeActive {
		t.Fatalf("logical clock remained active: state=%#v result=%#v", runner.clock.Snapshot(), result)
	}
}

func TestUnsupportedLogicalTimePathsDropsMieruKeepsReality(t *testing.T) {
	stateDir := t.TempDir()
	config := `{
  "outbounds": [
    {"type": "vless", "tag": "v-out", "tls": {"reality": {"enabled": true}}},
    {"type": "mieru", "tag": "m-out"},
    {"type": "shadowsocks", "tag": "s-out"}
  ]
}`
	if err := os.WriteFile(filepath.Join(stateDir, "sing-box.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := New(Config{StateDir: stateDir, TimeSyncCommand: "none", ResourceProfile: "large"})
	paths := runner.unsupportedLogicalTimePaths()
	if len(paths) != 1 || paths[0] != "reality_outbound" {
		t.Fatalf("unsupported logical time paths = %#v, want [reality_outbound]", paths)
	}
}
