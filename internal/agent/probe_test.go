package agent

import (
	"context"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestParseOSReleaseDebianUbuntuAlpine(t *testing.T) {
	cases := []struct {
		name    string
		content string
		id      string
		version string
		pretty  string
	}{
		{
			name: "debian",
			content: `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian`,
			id:      "debian",
			version: "12",
			pretty:  "Debian GNU/Linux 12 (bookworm)",
		},
		{
			name: "ubuntu",
			content: `PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu`,
			id:      "ubuntu",
			version: "24.04",
			pretty:  "Ubuntu 24.04.2 LTS",
		},
		{
			name: "alpine",
			content: `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.0
PRETTY_NAME="Alpine Linux v3.20"`,
			id:      "alpine",
			version: "3.20.0",
			pretty:  "Alpine Linux v3.20",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOSRelease(tc.content)
			if got.ID != tc.id || got.Version != tc.version || got.Name != tc.pretty {
				t.Fatalf("parseOSRelease() = %#v, want id=%q version=%q pretty=%q", got, tc.id, tc.version, tc.pretty)
			}
		})
	}
}

func TestParseOSReleaseMinimalAndQuoted(t *testing.T) {
	got := parseOSRelease("ID='custom-linux'\nNAME=Custom\\\"OS\n")
	if got.ID != "custom-linux" {
		t.Fatalf("id = %q, want custom-linux", got.ID)
	}
	if got.Name != `Custom"OS` {
		t.Fatalf("name = %q", got.Name)
	}
}

func TestSelectGlobalIPv6(t *testing.T) {
	cases := []struct {
		name       string
		candidates []string
		want       string
	}{
		{name: "empty", want: ""},
		{name: "single global", candidates: []string{"2001:db8::1"}, want: "2001:db8::1"},
		{name: "picks smallest deterministic", candidates: []string{"2001:db8::5", "2400:3200::1", "2001:db8::2"}, want: "2001:db8::2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var candidates []netip.Addr
			for _, raw := range tc.candidates {
				addr, err := netip.ParseAddr(raw)
				if err != nil {
					t.Fatalf("bad test address %q: %v", raw, err)
				}
				candidates = append(candidates, addr)
			}
			got, ok := selectGlobalIPv6(candidates)
			if tc.want == "" {
				if ok {
					t.Fatalf("selectGlobalIPv6(%v) = %s, want none", tc.candidates, got)
				}
				return
			}
			if !ok || got.String() != tc.want {
				t.Fatalf("selectGlobalIPv6(%v) = %s, want %s", tc.candidates, got, tc.want)
			}
		})
	}
}

func TestParsePublicIPRequiresRequestedPublicFamily(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		family string
		want   string
	}{
		{name: "ipv4", value: "8.8.8.8\n", family: "ipv4", want: "8.8.8.8"},
		{name: "ipv6", value: "2606:4700:4700::1111", family: "ipv6", want: "2606:4700:4700::1111"},
		{name: "wrong family", value: "8.8.8.8", family: "ipv6"},
		{name: "private", value: "10.0.0.1", family: "ipv4"},
		{name: "link local", value: "fe80::1", family: "ipv6"},
		{name: "invalid", value: "not-an-ip", family: "ipv4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parsePublicIP(tc.value, tc.family); got != tc.want {
				t.Fatalf("parsePublicIP(%q, %q) = %q, want %q", tc.value, tc.family, got, tc.want)
			}
		})
	}
}

func TestDetectPublicIPsRunsFamiliesConcurrently(t *testing.T) {
	var started sync.WaitGroup
	started.Add(2)
	release := make(chan struct{})
	go func() {
		started.Wait()
		close(release)
	}()
	probe := func(ctx context.Context, family string, _ []string) string {
		started.Done()
		select {
		case <-release:
			if family == "ipv4" {
				return "8.8.8.8"
			}
			return "2606:4700:4700::1111"
		case <-ctx.Done():
			return ""
		}
	}
	ipv4, ipv6 := detectPublicIPsWithProbe(time.Second, probe)
	if ipv4 != "8.8.8.8" || ipv6 != "2606:4700:4700::1111" {
		t.Fatalf("addresses = %q / %q", ipv4, ipv6)
	}
}

func TestDetectPublicIPsUsesSingleOverallTimeout(t *testing.T) {
	probe := func(ctx context.Context, _ string, _ []string) string {
		<-ctx.Done()
		return ""
	}
	started := time.Now()
	ipv4, ipv6 := detectPublicIPsWithProbe(40*time.Millisecond, probe)
	if ipv4 != "" || ipv6 != "" {
		t.Fatalf("unexpected addresses = %q / %q", ipv4, ipv6)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("overall timeout took %s", elapsed)
	}
}

func TestCPUUsageBetweenSamples(t *testing.T) {
	got, ok := cpuUsageBetween(procCPU{idle: 40, total: 100}, procCPU{idle: 50, total: 200})
	if !ok || got != 90 {
		t.Fatalf("cpu usage = %v, %t; want 90, true", got, ok)
	}
	if _, ok := cpuUsageBetween(procCPU{}, procCPU{idle: 50, total: 200}); ok {
		t.Fatal("first sample should not report CPU usage")
	}
	// Idle regression must not produce a wild percentage.
	if _, ok := cpuUsageBetween(procCPU{idle: 80, total: 100}, procCPU{idle: 10, total: 200}); ok {
		t.Fatal("idle regression should be invalid")
	}
}

func TestClampCPUPercent(t *testing.T) {
	if got := clampCPUPercent(-1); got != 0 {
		t.Fatalf("negative = %v", got)
	}
	if got := clampCPUPercent(150); got != 100 {
		t.Fatalf("over = %v", got)
	}
	if got := clampCPUPercent(12.34); got != 12.3 {
		t.Fatalf("round = %v", got)
	}
}

func TestDiskUsedBytesValidatesAndSaturates(t *testing.T) {
	if got := diskUsedBytes(100, 25, 4096); got != 75*4096 {
		t.Fatalf("used bytes = %d", got)
	}
	for _, test := range []struct {
		name      string
		blocks    uint64
		free      uint64
		blockSize int64
	}{
		{name: "no used blocks", blocks: 10, free: 10, blockSize: 4096},
		{name: "invalid free blocks", blocks: 10, free: 11, blockSize: 4096},
		{name: "zero block size", blocks: 10, free: 1, blockSize: 0},
		{name: "negative block size", blocks: 10, free: 1, blockSize: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := diskUsedBytes(test.blocks, test.free, test.blockSize); got != 0 {
				t.Fatalf("used bytes = %d, want 0", got)
			}
		})
	}
	if got := diskUsedBytes(math.MaxUint64, 0, 2); got != math.MaxUint64 {
		t.Fatalf("overflow result = %d, want saturation", got)
	}
}

func TestDiskTotalBytesValidatesAndSaturates(t *testing.T) {
	if got := diskTotalBytes(100, 4096); got != 100*4096 {
		t.Fatalf("total bytes = %d", got)
	}
	for _, test := range []struct {
		name      string
		blocks    uint64
		blockSize int64
	}{
		{name: "no blocks", blockSize: 4096},
		{name: "zero block size", blocks: 10},
		{name: "negative block size", blocks: 10, blockSize: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := diskTotalBytes(test.blocks, test.blockSize); got != 0 {
				t.Fatalf("total bytes = %d, want 0", got)
			}
		})
	}
	if got := diskTotalBytes(math.MaxUint64, 2); got != math.MaxUint64 {
		t.Fatalf("overflow result = %d, want saturation", got)
	}
}

func TestLinuxConnectionCounts(t *testing.T) {
	procNet := t.TempDir()
	files := map[string]string{
		"tcp":  "header\nconnection-1\nconnection-2\n",
		"tcp6": "header\nconnection-3\n",
		"udp":  "header\nconnection-1\n",
		"udp6": "header\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(procNet, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tcp, udp := linuxConnectionCounts(procNet)
	if tcp != 3 || udp != 1 {
		t.Fatalf("connection counts = tcp:%d udp:%d, want tcp:3 udp:1", tcp, udp)
	}
}

func TestLinuxProcessCountIgnoresNonPIDEntries(t *testing.T) {
	procRoot := t.TempDir()
	for _, name := range []string{"1", "42", "self", "net"} {
		if err := os.Mkdir(filepath.Join(procRoot, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(procRoot, "123"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := linuxProcessCount(procRoot); got != 2 {
		t.Fatalf("process count = %d, want 2", got)
	}
}

func TestProbeRefreshesLocalMetricsWhileThrottlingPublicIP(t *testing.T) {
	r := New(Config{AgentID: "agent-1", ResourceProfile: "large", CommandTimeoutSeconds: 1})
	r.resources = ResourceInfo{Profile: ResourceProfileLarge, EffectiveMemoryBytes: 2 << 30}
	// Seed a previous CPU sample so the next local sample can compute usage
	// without depending on a 250ms first-window sleep alone.
	r.lastCPUSample = procCPU{idle: 100, total: 1000}
	r.lastPublicIPv4 = "203.0.113.10"
	r.lastPublicIPv6 = "2001:db8::10"
	r.lastPublicIPAt = time.Now().UTC()
	r.lastCoreVersion = "oboard-sb test"
	r.lastCoreVersionAt = time.Now().UTC()
	// Force public-IP path to stay cached by setting interval far in the future via lastPublicIPAt=now.
	// Disable live public IP detect for safety.
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")

	first := r.Probe(false)
	if first.AgentID != "agent-1" {
		t.Fatalf("agent id = %q", first.AgentID)
	}
	if first.PublicIPv4 != "203.0.113.10" {
		t.Fatalf("public ipv4 should stay cached, got %q", first.PublicIPv4)
	}
	// Local metrics should have been sampled (memory/cpu fields populated on Linux;
	// on non-Linux agent memory is still filled from runtime).
	if first.AgentMemoryBytes == 0 {
		t.Fatal("agent memory should be sampled")
	}
	// Second probe within local min interval reuses local metrics values.
	r.lastLocalMetricsAt = time.Now().UTC()
	r.lastProbe = first
	second := r.Probe(false)
	if second.CPUUsagePercent != first.CPUUsagePercent {
		t.Fatalf("local metrics should be reused inside min interval: %v vs %v", second.CPUUsagePercent, first.CPUUsagePercent)
	}
	if second.PublicIPv4 != first.PublicIPv4 {
		t.Fatalf("public ip changed unexpectedly: %q", second.PublicIPv4)
	}
	// Expire local interval; public still fresh.
	r.lastLocalMetricsAt = time.Now().UTC().Add(-time.Minute)
	third := r.Probe(false)
	if third.PublicIPv4 != "203.0.113.10" {
		t.Fatalf("public ip should remain cached across local refresh, got %q", third.PublicIPv4)
	}
}

func TestProbeReportsPersistedAppliedConfigurationState(t *testing.T) {
	stateDir := t.TempDir()
	r := New(Config{AgentID: "agent-applied", StateDir: stateDir, CommandTimeoutSeconds: 1})
	r.resources = ResourceInfo{Profile: ResourceProfileLarge, EffectiveMemoryBytes: 2 << 30}
	r.lastPublicIPv4 = "203.0.113.10"
	r.lastPublicIPAt = time.Now().UTC()
	r.lastCoreVersion = "oboard-sb test"
	r.lastCoreVersionAt = time.Now().UTC()
	t.Setenv("OBOARD_DISABLE_PUBLIC_IP_DETECT", "1")
	payload := []byte(`{"version":41}`)
	if err := r.persistAppliedVersion("apply_deployment", 41, payload); err != nil {
		t.Fatal(err)
	}
	health := r.Probe(false)
	if health.AppliedConfigVersion != 41 {
		t.Fatalf("applied version = %d, want 41", health.AppliedConfigVersion)
	}
	if health.AppliedConfigDigest != appliedPayloadID("apply_deployment", payload) {
		t.Fatalf("applied digest = %q", health.AppliedConfigDigest)
	}
}

func TestParseLinuxNetworkTotalsExcludesVirtualInterfaces(t *testing.T) {
	raw := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 2000 1 0 0 0 0 0 0 1000 1 0 0 0 0 0 0
    lo: 9000 1 0 0 0 0 0 0 9000 1 0 0 0 0 0 0
docker0: 8000 1 0 0 0 0 0 0 7000 1 0 0 0 0 0 0
  ens3: 4000 1 0 0 0 0 0 0 3000 1 0 0 0 0 0 0`
	upload, download, ok := parseLinuxNetworkTotals(raw)
	if !ok || upload != 4000 || download != 6000 {
		t.Fatalf("totals upload=%d download=%d ok=%t", upload, download, ok)
	}
}

func TestNetworkRateUsesCounterDeltaAndRejectsReset(t *testing.T) {
	now := time.Now()
	previous := networkCounterSample{UploadBytes: 1000, DownloadBytes: 2000, SampledAt: now.Add(-10 * time.Second), Valid: true}
	upload, download := networkRatesBetween(previous, networkCounterSample{UploadBytes: 1600, DownloadBytes: 3200, SampledAt: now, Valid: true})
	if upload != 60 || download != 120 {
		t.Fatalf("rates upload=%d download=%d", upload, download)
	}
	upload, download = networkRatesBetween(previous, networkCounterSample{UploadBytes: 10, DownloadBytes: 20, SampledAt: now, Valid: true})
	if upload != 0 || download != 0 {
		t.Fatalf("counter reset rates upload=%d download=%d", upload, download)
	}
}

func TestCPUCountFromCPUInfoDoesNotParseModelName(t *testing.T) {
	qemuXeon := `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 58
model name	: Intel Xeon E3-12xx v2 (Ivy Bridge, IBRS)
processor	: 1
model name	: Intel Xeon E3-12xx v2 (Ivy Bridge, IBRS)
processor	: 2
model name	: Intel Xeon E3-12xx v2 (Ivy Bridge, IBRS)
processor	: 3
model name	: Intel Xeon E3-12xx v2 (Ivy Bridge, IBRS)
`
	if name := cpuNameFromCPUInfo(qemuXeon); name != "Intel Xeon E3-12xx v2 (Ivy Bridge, IBRS)" {
		t.Fatalf("cpu name = %q", name)
	}
	if cores := cpuCountFromCPUInfo(qemuXeon); cores != 4 {
		t.Fatalf("cpu cores = %d, want 4 logical processors not a model token", cores)
	}

	amdNamedCores := `processor	: 0
model name	: AMD EPYC 7763 64-Core Processor
processor	: 1
model name	: AMD EPYC 7763 64-Core Processor
`
	if cores := cpuCountFromCPUInfo(amdNamedCores); cores != 2 {
		t.Fatalf("named-core model parsed as cores: %d", cores)
	}

	armHardwareOnly := `Hardware	: BCM2835
Revision	: a020d3
Serial		: 00000000
`
	if name := cpuNameFromCPUInfo(armHardwareOnly); name != "BCM2835" {
		t.Fatalf("arm hardware name = %q", name)
	}
	if cores := cpuCountFromCPUInfo(armHardwareOnly); cores != 0 {
		t.Fatalf("hardware-only cpuinfo cores = %d, want 0 so NumCPU can fall back", cores)
	}
}

func TestMonitoringModeLocalIntervals(t *testing.T) {
	if got := monitoringLocalMetricsInterval("standard"); got != 9*time.Second {
		t.Fatalf("standard interval = %s", got)
	}
	if got := monitoringLocalMetricsInterval("lightweight"); got != 19*time.Second {
		t.Fatalf("lightweight interval = %s", got)
	}
}

func TestTaskResultHealthDoesNotWaitForProbe(t *testing.T) {
	r := New(Config{AgentID: "task-agent", StateDir: t.TempDir()})
	if r.taskResultHealth() != nil {
		t.Fatal("unexpected health before first sample")
	}
	r.lastProbe = model.HealthReport{AgentID: "task-agent", Timestamp: time.Now().Add(-time.Hour), AppliedConfigVersion: 1}
	payload := []byte(`{"version":42}`)
	if err := r.persistAppliedVersion("apply_deployment", 42, payload); err != nil {
		t.Fatal(err)
	}
	r.probeMu.Lock()
	defer r.probeMu.Unlock()
	done := make(chan *model.HealthReport, 1)
	go func() { done <- r.taskResultHealth() }()
	select {
	case health := <-done:
		if health.AppliedConfigVersion != 42 || health.AppliedConfigDigest != appliedPayloadID("apply_deployment", payload) {
			t.Fatalf("stale applied config in task result: %#v", health)
		}
		if !health.Timestamp.Equal(r.lastProbe.Timestamp) {
			t.Fatal("cached sample was falsely timestamped as fresh")
		}
	case <-time.After(time.Second):
		t.Fatal("task result blocked behind health probe")
	}
}

func TestParseProcUptime(t *testing.T) {
	cases := map[string]uint64{
		"350735.47 234388.90\n": 350735,
		"0.42 0.10":             0,
		"":                      0,
		"garbage 1":             0,
	}
	for input, want := range cases {
		if got := parseProcUptime(input); got != want {
			t.Fatalf("parseProcUptime(%q) = %d, want %d", input, got, want)
		}
	}
}
