package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	latencyProbeMaxTargets     = 256
	latencyProbeMaxConcurrency = 16
	latencyProbeBatchTimeout   = 90 * time.Second
	latencyProbeStateFile      = "latency-probe.json"
	latencyProbeMaxPending     = 2048
	latencyProbeRetention      = 35 * 24 * time.Hour
)

type latencyProbeSamplesFunc func(context.Context, string, int, int, time.Duration, time.Duration) ([]int64, []string)

type latencyProbeLocalState struct {
	Plan      model.LatencyProbeTargetsPlan `json:"plan"`
	LastRunAt time.Time                     `json:"last_run_at"`
	// TargetLastRunAt tracks the last autonomous run per probe target so each task keeps its own cadence.
	TargetLastRunAt map[string]time.Time             `json:"target_last_run_at,omitempty"`
	Pending         []model.LatencyProbeResultReport `json:"pending"`
}

var latencyProbeSequence atomic.Uint32

func (r *Runner) runLatencyProbeTask(ctx context.Context, plan model.LatencyProbeTargetsPlan) (model.LatencyProbeResultReport, error) {
	return r.runLatencyProbeTaskWithProbe(ctx, plan, nil)
}

func (r *Runner) runLatencyProbeTaskWithProbe(ctx context.Context, plan model.LatencyProbeTargetsPlan, probe latencyProbeSamplesFunc) (model.LatencyProbeResultReport, error) {
	now := func() time.Time {
		if r != nil && r.clock != nil {
			return r.clock.Now().UTC()
		}
		return time.Now().UTC()
	}
	if len(plan.Targets) == 0 {
		return model.LatencyProbeResultReport{ResourceVersion: plan.ResourceVersion, CheckedAt: now(), Items: []model.LatencyProbeResult{}}, errors.New("延迟测试没有可用目标")
	}
	if len(plan.Targets) > latencyProbeMaxTargets {
		return model.LatencyProbeResultReport{}, fmt.Errorf("延迟测试目标不能超过 %d 个", latencyProbeMaxTargets)
	}
	samples := plan.SampleCount
	if samples < 1 || samples > 10 {
		samples = 3
	}
	interval := time.Duration(plan.IntervalMS) * time.Millisecond
	if interval < 25*time.Millisecond || interval > 5*time.Second {
		interval = 150 * time.Millisecond
	}
	timeout := time.Duration(plan.TimeoutMS) * time.Millisecond
	if timeout < 100*time.Millisecond || timeout > 10*time.Second {
		timeout = 3 * time.Second
	}
	batchCtx, cancel := context.WithTimeout(ctx, latencyProbeBatchTimeout)
	defer cancel()
	items := make([]model.LatencyProbeResult, len(plan.Targets))
	sem := make(chan struct{}, latencyProbeMaxConcurrency)
	var wg sync.WaitGroup
	for i, target := range plan.Targets {
		i, target := i, target
		mode := latencyTargetMode(target, plan.Mode)
		port := target.Port
		if mode == model.LatencyProbeModeICMP {
			port = 0
		}
		items[i] = model.LatencyProbeResult{MeasurementRevision: target.MeasurementRevision, ProbeID: target.ProbeID, Kind: target.Kind, TaskID: target.TaskID, TaskName: target.TaskName, Mode: string(mode), Province: target.Province, Carrier: target.Carrier, Host: target.Host, IP: target.IP, Port: port, SampleCount: samples, CheckedAt: now()}
		if err := validateLatencyProbeTarget(target, latencyTargetMode(target, plan.Mode)); err != nil {
			items[i].Error = err.Error()
			continue
		}
		if target.ProbeID == "" {
			items[i].Error = "目标标识无效"
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-batchCtx.Done():
				items[i].Error = "测试等待超时"
				return
			}
			targetProbe := probe
			host := target.Host
			if targetProbe == nil {
				switch mode {
				case model.LatencyProbeModeTCP:
					targetProbe = tcpProbeSamplesContext
				case model.LatencyProbeModeICMP:
					targetProbe = icmpProbeSamplesContext
				case model.LatencyProbeModeHTTP:
					targetProbe = r.httpProbeSamplesContext
					host = target.URL
				}
			}
			latencies, failures := targetProbe(batchCtx, host, target.Port, samples, interval, timeout)
			applyLatencyStats(&items[i], latencies, samples)
			if len(failures) > 0 {
				items[i].Error = boundedLatencyProbeError(failures[0])
			}
			items[i].Available = items[i].SuccessCount > 0
			items[i].CheckedAt = now()
		}()
	}
	wg.Wait()
	failed := 0
	for i := range items {
		if !items[i].Available {
			failed++
			if items[i].Error == "" {
				items[i].Error = "目标不可达"
			}
		}
	}
	checkedAt := now()
	return model.LatencyProbeResultReport{ReportID: newLatencyProbeReportID(r.Config().AgentID, checkedAt), ResourceVersion: plan.ResourceVersion, CheckedAt: checkedAt, Items: items}, func() error {
		if failed > 0 {
			return fmt.Errorf("%d 个延迟测试目标失败", failed)
		}
		return nil
	}()
}

func validateLatencyProbeTarget(target model.LatencyProbeTarget, mode model.LatencyProbeMode) error {
	if strings.TrimSpace(target.ProbeID) == "" {
		return errors.New("目标标识无效")
	}
	host := strings.TrimSpace(target.Host)
	switch target.Kind {
	case "public":
		if host != "cp.cloudflare.com" && host != "www.12306.cn" && host != "www.gstatic.com" {
			return errors.New("公网延迟目标无效")
		}
	case "regional", "custom":
		if target.Kind == "regional" && (strings.TrimSpace(target.Province) == "" || strings.TrimSpace(target.Carrier) == "") {
			return errors.New("地区目标必须包含省份和运营商")
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			if (target.Kind == "regional" && !validLatencyProbeIPv4(addr)) || strings.TrimSpace(target.IP) != addr.String() {
				return errors.New("目标 IP 地址无效")
			}
		} else if !(validLatencyProbeHostname(host) || (target.Kind == "custom" && validCustomProbeHostname(host))) || strings.TrimSpace(target.IP) != "" {
			return errors.New("目标必须是 IP 地址或主机名")
		}
	default:
		return errors.New("延迟目标类型无效")
	}
	if mode != model.LatencyProbeModeTCP && mode != model.LatencyProbeModeICMP && mode != model.LatencyProbeModeHTTP {
		return errors.New("延迟测试方式无效")
	}
	if mode == model.LatencyProbeModeHTTP {
		u, err := url.Parse(target.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.Hostname() != host || len(target.URL) > 2048 {
			return errors.New("HTTP 探测 URL 无效")
		}
		port := 80
		if u.Scheme == "https" {
			port = 443
		}
		if u.Port() != "" {
			port, err = strconv.Atoi(u.Port())
			if err != nil {
				return errors.New("HTTP 探测端口无效")
			}
		}
		if port != target.Port {
			return errors.New("HTTP 探测端口不匹配")
		}
	}
	if (mode == model.LatencyProbeModeTCP || mode == model.LatencyProbeModeHTTP) && (target.Port < 1 || target.Port > 65535) {
		return errors.New("TCP 延迟目标端口无效")
	}
	return nil
}

func validLatencyProbeIPv4(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() && !addr.IsMulticast() && !addr.IsUnspecified()
}

func validLatencyProbeHostname(host string) bool {
	return validProbeHostname(host, false)
}

func validProbeHostname(host string, allowSingleLabel bool) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	labels := strings.Split(host, ".")
	if !allowSingleLabel && len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	if allowSingleLabel && len(labels) == 1 {
		return true
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, c := range tld {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func validCustomProbeHostname(host string) bool {
	return validProbeHostname(host, true)
}

func icmpProbeSamplesContext(ctx context.Context, host string, _ int, count int, interval, timeout time.Duration) ([]int64, []string) {
	target, err := resolveLatencyProbeIP(ctx, host)
	if err != nil {
		return nil, []string{"无法解析目标 IP 地址"}
	}
	network, bind, protocol := "ip4:icmp", "0.0.0.0", 1
	var requestType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if target.Is6() {
		network, bind, protocol = "ip6:ipv6-icmp", "::", 58
		requestType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	conn, err := icmp.ListenPacket(network, bind)
	if err != nil {
		return nil, []string{"当前环境不允许执行 ICMP 延迟测试"}
	}
	defer conn.Close()
	id := int((uint32(os.Getpid()) + latencyProbeSequence.Add(1)) & 0xffff)
	latencies := make([]int64, 0, count)
	failures := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			failures = append(failures, "测试已取消")
			break
		}
		sequence := int(latencyProbeSequence.Add(1) & 0xffff)
		message := icmp.Message{Type: requestType, Code: 0, Body: &icmp.Echo{ID: id, Seq: sequence, Data: []byte("oboard-latency")}}
		payload, marshalErr := message.Marshal(nil)
		if marshalErr != nil {
			failures = append(failures, "无法创建 ICMP 测试请求")
			continue
		}
		started := time.Now()
		deadline := started.Add(timeout)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			failures = append(failures, "无法设置 ICMP 测试超时")
			continue
		}
		if _, err := conn.WriteTo(payload, &net.IPAddr{IP: net.IP(target.AsSlice()), Zone: target.Zone()}); err != nil {
			failures = append(failures, "无法发送 ICMP 测试请求")
			continue
		}
		buffer := make([]byte, 1500)
		matched := false
		for !matched {
			n, peer, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				if ctx.Err() != nil {
					failures = append(failures, "测试已取消")
				} else {
					failures = append(failures, "目标未响应")
				}
				break
			}
			if !icmpPeerMatches(peer, net.IP(target.AsSlice())) {
				continue
			}
			reply, parseErr := icmp.ParseMessage(protocol, buffer[:n])
			if parseErr != nil || reply.Type != replyType {
				continue
			}
			echo, ok := reply.Body.(*icmp.Echo)
			if !ok || echo.ID != id || echo.Seq != sequence {
				continue
			}
			latencies = append(latencies, time.Since(started).Milliseconds())
			matched = true
		}
		if i+1 < count {
			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				failures = append(failures, "测试已取消")
				return latencies, failures
			}
		}
	}
	return latencies, failures
}

func tcpProbeSamplesContext(ctx context.Context, host string, port, count int, interval, timeout time.Duration) ([]int64, []string) {
	if port < 1 || port > 65535 {
		return nil, []string{"TCP 延迟目标端口无效"}
	}
	targetIP, err := resolveLatencyProbeIP(ctx, host)
	if err != nil {
		return nil, []string{"无法解析目标 IP 地址"}
	}
	latencies := make([]int64, 0, count)
	failures := make([]string, 0, count)
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(targetIP.String(), fmt.Sprintf("%d", port))
	for index := 0; index < count; index++ {
		started := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			if ctx.Err() != nil {
				failures = append(failures, "测试已取消")
			} else {
				failures = append(failures, "目标未响应")
			}
		} else {
			latencies = append(latencies, time.Since(started).Milliseconds())
			_ = conn.Close()
		}
		if index+1 < count {
			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return latencies, append(failures, "测试已取消")
			}
		}
	}
	return latencies, failures
}

func resolveLatencyProbeIP(ctx context.Context, host string) (netip.Addr, error) {
	host = strings.TrimSpace(host)
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addresses) > 0 {
		return addresses[0].Unmap(), nil
	}
	return netip.Addr{}, errors.New("hostname has no IP address")
}

func newLatencyProbeReportID(agentID string, checkedAt time.Time) string {
	return fmt.Sprintf("%s-latency-%d-%d", strings.TrimSpace(agentID), checkedAt.UnixNano(), latencyProbeSequence.Add(1))
}

func (r *Runner) latencyProbeStatePath() string {
	return r.statePath(latencyProbeStateFile)
}

func (r *Runner) loadLatencyProbeStateLocked() {
	if r.latencyProbeStateLoaded {
		return
	}
	r.latencyProbeStateLoaded = true
	data, err := r.stateReadPath(r.latencyProbeStatePath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logging.Errorf("读取延迟测试本地状态失败: %v", err)
		}
		return
	}
	var state latencyProbeLocalState
	if err := json.Unmarshal(data, &state); err != nil {
		logging.Errorf("延迟测试本地状态无效: %v", err)
		return
	}
	r.latencyProbeState = state
	r.pruneLatencyProbeStateLocked(time.Now().UTC())
}

func (r *Runner) persistLatencyProbeStateLocked() error {
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(r.latencyProbeState)
	if err != nil {
		return err
	}
	return r.stateWritePath(r.latencyProbeStatePath(), data, 0o600)
}

func (r *Runner) pruneLatencyProbeStateLocked(now time.Time) {
	cutoff := now.Add(-latencyProbeRetention)
	pending := r.latencyProbeState.Pending[:0]
	for _, report := range r.latencyProbeState.Pending {
		if report.CheckedAt.Before(cutoff) {
			continue
		}
		pending = append(pending, report)
	}
	if len(pending) > latencyProbeMaxPending {
		pending = pending[len(pending)-latencyProbeMaxPending:]
	}
	r.latencyProbeState.Pending = pending
}

func (r *Runner) setLatencyProbePlan(plan model.LatencyProbeTargetsPlan) error {
	if plan.Version <= 0 || strings.TrimSpace(plan.ResourceVersion) == "" {
		return errors.New("延迟测试计划版本无效")
	}
	if plan.IntervalSeconds < 30 || plan.IntervalSeconds > 86400 {
		return errors.New("延迟测试间隔无效")
	}
	if plan.Mode != model.LatencyProbeModeTCP && plan.Mode != model.LatencyProbeModeICMP {
		return errors.New("延迟测试方式无效")
	}
	if len(plan.Targets) == 0 || len(plan.Targets) > latencyProbeMaxTargets {
		return errors.New("延迟测试目标数量无效")
	}
	for _, target := range plan.Targets {
		if err := validateLatencyProbeTarget(target, latencyTargetMode(target, plan.Mode)); err != nil {
			return err
		}
		if target.IntervalSeconds != 0 && (target.IntervalSeconds < 30 || target.IntervalSeconds > 86400) {
			return errors.New("延迟测试目标间隔无效")
		}
	}
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	current, _ := json.Marshal(r.latencyProbeState.Plan)
	next, _ := json.Marshal(plan)
	if r.latencyProbeState.Plan.Version > plan.Version {
		return errors.New("延迟测试计划版本早于当前版本")
	}
	if r.latencyProbeState.Plan.Version == plan.Version && string(current) != string(next) {
		return errors.New("延迟测试计划版本对应的内容不一致")
	}
	if string(current) == string(next) {
		return nil
	}
	previous := r.latencyProbeState
	r.latencyProbeState.Plan = plan
	r.latencyProbeState.LastRunAt = time.Time{}
	r.latencyProbeState.TargetLastRunAt = pruneLatencyProbeTargetRuns(r.latencyProbeState.TargetLastRunAt, plan)
	if err := r.persistLatencyProbeStateLocked(); err != nil {
		r.latencyProbeState = previous
		return err
	}
	return nil
}

// pruneLatencyProbeTargetRuns drops per-target run marks whose probe target left the plan.
func pruneLatencyProbeTargetRuns(runs map[string]time.Time, plan model.LatencyProbeTargetsPlan) map[string]time.Time {
	if len(runs) == 0 {
		return nil
	}
	keep := make(map[string]time.Time, len(runs))
	for _, target := range plan.Targets {
		if at, ok := runs[target.ProbeID]; ok {
			keep[target.ProbeID] = at
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return keep
}

// latencyProbeTargetInterval resolves the effective cadence for one target.
func latencyProbeTargetInterval(target model.LatencyProbeTarget, plan model.LatencyProbeTargetsPlan) time.Duration {
	seconds := target.IntervalSeconds
	if seconds <= 0 {
		seconds = plan.IntervalSeconds
	}
	if seconds < 30 {
		seconds = 30
	}
	return time.Duration(seconds) * time.Second
}

func (r *Runner) startLatencyProbeLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				r.runLatencyProbeIfDue(ctx, now.UTC())
			}
		}
	}()
}

// appliedLatencyProbe reports the plan this node currently holds, so the
// Controller can see a plan it keeps re-sending being refused. setLatencyProbePlan
// can only log that refusal locally; without this the two sides disagree with no
// evidence anywhere, and the version never moves off the conflicting binding.
func (r *Runner) appliedLatencyProbe() *model.LatencyProbeAppliedSnapshot {
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	plan := r.latencyProbeState.Plan
	if plan.Version <= 0 {
		return nil
	}
	return &model.LatencyProbeAppliedSnapshot{PlanVersion: plan.Version, PlanDigest: model.LatencyProbePlanContentDigest(plan)}
}

func (r *Runner) runLatencyProbeIfDue(ctx context.Context, now time.Time) {
	r.latencyProbeMu.Lock()
	r.loadLatencyProbeStateLocked()
	plan := r.latencyProbeState.Plan
	if !plan.Enabled || len(plan.Targets) == 0 {
		r.latencyProbeMu.Unlock()
		return
	}
	// Each task owns its cadence. The controller requires exactly one public
	// target per report, so a due batch always carries the public target along.
	due := make([]model.LatencyProbeTarget, 0, len(plan.Targets))
	regionalDue := false
	for _, target := range plan.Targets {
		if target.Kind == "public" {
			continue
		}
		last, seen := r.latencyProbeState.TargetLastRunAt[target.ProbeID]
		if seen && now.Sub(last) < latencyProbeTargetInterval(target, plan) {
			continue
		}
		due = append(due, target)
		regionalDue = true
	}
	publicDue := r.latencyProbeState.LastRunAt.IsZero() || now.Sub(r.latencyProbeState.LastRunAt) >= time.Duration(plan.IntervalSeconds)*time.Second
	if !regionalDue && !publicDue {
		r.latencyProbeMu.Unlock()
		return
	}
	batch := make([]model.LatencyProbeTarget, 0, len(due)+1)
	for _, target := range plan.Targets {
		if target.Kind == "public" {
			batch = append(batch, target)
		}
	}
	batch = append(batch, due...)
	if len(batch) == 0 {
		r.latencyProbeMu.Unlock()
		return
	}
	previous := r.latencyProbeState
	previous.TargetLastRunAt = maps.Clone(r.latencyProbeState.TargetLastRunAt)
	r.latencyProbeState.LastRunAt = now
	if r.latencyProbeState.TargetLastRunAt == nil {
		r.latencyProbeState.TargetLastRunAt = map[string]time.Time{}
	}
	for _, target := range due {
		r.latencyProbeState.TargetLastRunAt[target.ProbeID] = now
	}
	if err := r.persistLatencyProbeStateLocked(); err != nil {
		r.latencyProbeState = previous
		r.latencyProbeMu.Unlock()
		logging.Errorf("保存延迟测试执行时间失败: %v", err)
		return
	}
	r.latencyProbeMu.Unlock()

	batchPlan := plan
	batchPlan.Targets = batch
	report, _ := r.runLatencyProbeTask(ctx, batchPlan)
	if len(report.Items) == 0 || report.ReportID == "" {
		return
	}
	if err := r.queueLatencyProbeReport(report, now); err != nil {
		logging.Errorf("保存延迟测试待补报结果失败: %v", err)
	}
}

func (r *Runner) queueLatencyProbeReport(report model.LatencyProbeResultReport, now time.Time) error {
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	previous := r.latencyProbeState
	previous.Pending = append([]model.LatencyProbeResultReport(nil), r.latencyProbeState.Pending...)
	r.latencyProbeState.Pending = append(r.latencyProbeState.Pending, report)
	r.pruneLatencyProbeStateLocked(now)
	if err := r.persistLatencyProbeStateLocked(); err != nil {
		r.latencyProbeState = previous
		return err
	}
	return nil
}

func (r *Runner) nextPendingLatencyProbeReport() (model.LatencyProbeResultReport, bool) {
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	if len(r.latencyProbeState.Pending) == 0 {
		return model.LatencyProbeResultReport{}, false
	}
	return r.latencyProbeState.Pending[0], true
}

func (r *Runner) ackLatencyProbeReport(reportID string) error {
	r.latencyProbeMu.Lock()
	defer r.latencyProbeMu.Unlock()
	r.loadLatencyProbeStateLocked()
	previous := append([]model.LatencyProbeResultReport(nil), r.latencyProbeState.Pending...)
	pending := r.latencyProbeState.Pending[:0]
	for _, report := range r.latencyProbeState.Pending {
		if report.ReportID != reportID {
			pending = append(pending, report)
		}
	}
	r.latencyProbeState.Pending = pending
	if err := r.persistLatencyProbeStateLocked(); err != nil {
		r.latencyProbeState.Pending = previous
		return err
	}
	return nil
}

func icmpPeerMatches(peer net.Addr, target net.IP) bool {
	switch value := peer.(type) {
	case *net.IPAddr:
		return value.IP.Equal(target)
	case *net.UDPAddr:
		return value.IP.Equal(target)
	default:
		return strings.TrimSpace(peer.String()) == target.String()
	}
}

func applyLatencyStats(result *model.LatencyProbeResult, latencies []int64, total int) {
	result.SampleCount = total
	result.SuccessCount = len(latencies)
	if len(latencies) == 0 {
		return
	}
	ordered := append([]int64(nil), latencies...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	var sum int64
	for _, value := range ordered {
		sum += value
	}
	result.LatencyMS = sum / int64(len(ordered))
	result.MinLatencyMS = ordered[0]
	p95 := int(math.Ceil(float64(len(ordered))*0.95)) - 1
	if p95 < 0 {
		p95 = 0
	}
	if p95 >= len(ordered) {
		p95 = len(ordered) - 1
	}
	result.P95LatencyMS = ordered[p95]
	if len(latencies) > 1 {
		var delta int64
		for i := 1; i < len(latencies); i++ {
			d := latencies[i] - latencies[i-1]
			if d < 0 {
				d = -d
			}
			delta += d
		}
		result.JitterMS = delta / int64(len(latencies)-1)
	}
}

func boundedLatencyProbeError(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}

func latencyTargetMode(target model.LatencyProbeTarget, fallback model.LatencyProbeMode) model.LatencyProbeMode {
	if target.Mode != "" {
		return target.Mode
	}
	return fallback
}

func networkProbeHTTPClient(timeout time.Duration, now func() time.Time) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, Time: now},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			target, err := resolveLatencyProbeIP(ctx, host)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(target.String(), port))
		},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 || (req.URL.Scheme != "http" && req.URL.Scheme != "https") || req.URL.User != nil {
			return errors.New("HTTP 重定向无效或过多")
		}
		return nil
	}}
}

func (r *Runner) httpProbeSamplesContext(ctx context.Context, address string, _ int, count int, interval, timeout time.Duration) ([]int64, []string) {
	now := time.Now
	if r != nil && r.clock != nil {
		now = r.clock.Now
	}
	client := networkProbeHTTPClient(timeout, now)
	defer client.CloseIdleConnections()
	return httpProbeSamplesWithClient(ctx, address, count, interval, client)
}

func httpProbeSamplesWithClient(ctx context.Context, address string, count int, interval time.Duration, client *http.Client) ([]int64, []string) {
	latencies, failures := []int64{}, []string{}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return latencies, append(failures, "测试已取消")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return latencies, append(failures, "HTTP URL 无效")
		}
		request.Header.Set("User-Agent", "OBoard-Network-Probe")
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			failures = append(failures, "HTTP 请求失败")
		} else {
			response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				latencies = append(latencies, time.Since(started).Milliseconds())
			} else {
				failures = append(failures, fmt.Sprintf("HTTP %d", response.StatusCode))
			}
		}
		if i+1 < count {
			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return latencies, append(failures, "测试已取消")
			}
		}
	}
	return latencies, failures
}
