package minibox

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"golang.org/x/time/rate"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/activity"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/auditwire"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/familyselector"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeuser"
)

const rateLimitIOChunk = 64 * 1024

type RateLimitTracker struct {
	activity      activity.Collector
	usersBarrier  sync.RWMutex
	usersFailed   atomic.Bool
	snellParents  map[*parentConn]struct{}
	snellUsers    map[string]snellIdentity
	snellRetired  map[string]bool
	authorization *authorization.Store
	mu            sync.RWMutex
	states        map[string]*runtimeState
	active        map[string]map[*trackedConn]struct{}
	activePacket  map[string]map[*trackedPacketConn]struct{}
	// byCredential indexes live connections by the authorization key they
	// authenticated with so a revoke can close exactly that credential's
	// sessions without scanning every inbound user.
	byCredential          map[string]map[*trackedConn]struct{}
	byCredentialPacket    map[string]map[*trackedPacketConn]struct{}
	authorizationWake     chan struct{}
	auditMu               sync.Mutex
	auditBuckets          map[string]*ConnectionAuditBucket
	auditActiveByIdentity map[string]int64
	auditGeneration       uint64
	auditDropped          int64
	auditWindowStart      time.Time
	auditEnabled          atomic.Bool
	auditDiagnostics      atomic.Bool
	auditCollection       atomic.Pointer[auditwire.CollectionPolicy]
	auditPresenceSequence atomic.Uint64
	presenceStates        map[string]*connectionPresenceState
	presenceEvents        []ConnectionPresenceEvent
	presenceDropped       int64
	activeTCP             atomic.Int64
	socketGovernor        *SocketBufferGovernor
	now                   func() time.Time
}

func (t *RateLimitTracker) timeNow() time.Time {
	if t != nil && t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *RateLimitTracker) SetSocketGovernor(governor *SocketBufferGovernor) {
	if t != nil {
		t.socketGovernor = governor
	}
}

type runtimeState struct {
	authorization *authorization.Store
	key           string
	user          string
	inbound       string
	config        atomic.Pointer[runtimeConfig]
	periodMu      sync.Mutex
	usage         *runtimeUserUsage
	now           func() time.Time
}

type runtimeConfig struct {
	policy       RuntimeUserLimit
	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
	counters     *runtimeCounters
}

type runtimeCounters struct {
	epoch                string
	upload               atomic.Int64
	download             atomic.Int64
	acknowledgedUpload   atomic.Int64
	acknowledgedDownload atomic.Int64
}

type runtimeUserUsage struct {
	mu      sync.Mutex
	periods map[string]*runtimeUsagePeriod
}

type runtimeUsagePeriod struct {
	upload               atomic.Int64
	download             atomic.Int64
	acknowledgedUpload   atomic.Int64
	acknowledgedDownload atomic.Int64
}

type TrafficCounter struct {
	Key          string `json:"key"`
	CounterEpoch string `json:"counter_epoch,omitempty"`
	User         string `json:"user"`
	Inbound      string `json:"inbound"`
	UserID       int64  `json:"user_id"`
	InboundID    int64  `json:"inbound_id,omitempty"`
	PathID       int64  `json:"path_id,omitempty"`
	PeriodKey    string `json:"period_key,omitempty"`
	Upload       int64  `json:"upload_bytes"`
	Download     int64  `json:"download_bytes"`
}

type TrafficCounterAcknowledgement struct {
	CounterEpoch string `json:"counter_epoch,omitempty"`
	PeriodKey    string `json:"period_key"`
	Upload       int64  `json:"upload_bytes"`
	Download     int64  `json:"download_bytes"`
}

func newCounterEpoch() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "ce_invalid"
	}
	return "ce_" + base64.RawURLEncoding.EncodeToString(raw[:])
}

func newRuntimeCounters() *runtimeCounters {
	return &runtimeCounters{epoch: newCounterEpoch()}
}

func NewRateLimitTracker(metadata RuntimeMetadata) *RateLimitTracker {
	return newRateLimitTracker(metadata, time.Now)
}

func newRateLimitTracker(metadata RuntimeMetadata, now func() time.Time) *RateLimitTracker {
	if now == nil {
		now = time.Now
	}
	tracker := &RateLimitTracker{states: map[string]*runtimeState{}, active: map[string]map[*trackedConn]struct{}{}, activePacket: map[string]map[*trackedPacketConn]struct{}{}, now: now}
	tracker.installAuthorizationStore(authorization.NewStore("", nil))
	tracker.authorization.SetClock(tracker.timeNow)
	_ = tracker.authorization.Update(metadata.Authorization)
	auditEnabled := metadata.ConnectionAudit != nil && metadata.ConnectionAudit.Enabled
	tracker.auditEnabled.Store(auditEnabled)
	tracker.activity.SetEnabled(auditEnabled)
	if auditEnabled {
		tracker.auditWindowStart = now().UTC()
	}
	usageByUser := map[int64]*runtimeUserUsage{}
	usageFor := func(userID int64) *runtimeUserUsage {
		if userID <= 0 {
			return nil
		}
		usage := usageByUser[userID]
		if usage == nil {
			usage = &runtimeUserUsage{periods: map[string]*runtimeUsagePeriod{}}
			usageByUser[userID] = usage
		}
		return usage
	}
	for user, limit := range metadata.RateLimits.Users {
		if user == "" {
			continue
		}
		if !limit.Billable && limit.UserID > 0 {
			limit.Billable = true
		}
		key := "user:" + user
		state := newRuntimeStateWithClock(key, user, "", limit, now)
		state.authorization = tracker.authorization
		state.usage = usageFor(limit.UserID)
		tracker.states[key] = state
	}
	for inbound, limit := range metadata.RateLimits.Inbounds {
		if inbound == "" {
			continue
		}
		key := "inbound:" + inbound
		state := newRuntimeStateWithClock(key, "", inbound, limit, now)
		state.authorization = tracker.authorization
		state.usage = usageFor(limit.UserID)
		tracker.states[key] = state
	}
	return tracker
}

func (t *RateLimitTracker) SetConnectionAuditEnabled(enabled bool) {
	if t == nil {
		return
	}
	t.activity.SetEnabled(enabled)
	wasEnabled := t.auditEnabled.Swap(enabled)
	if enabled {
		if !wasEnabled {
			t.auditMu.Lock()
			t.auditWindowStart = t.timeNow().UTC()
			t.auditDropped = 0
			t.auditMu.Unlock()
		}
		return
	}
	t.auditMu.Lock()
	t.auditBuckets = nil
	t.auditActiveByIdentity = nil
	t.presenceStates = nil
	t.presenceEvents = nil
	t.presenceDropped = 0
	t.auditGeneration++
	t.auditDropped = 0
	t.auditWindowStart = time.Time{}
	t.auditMu.Unlock()
}

func (t *RateLimitTracker) ConnectionAuditEnabled() bool {
	return t != nil && t.auditEnabled.Load()
}

func newRuntimeState(key, user, inbound string, policy RuntimeUserLimit) *runtimeState {
	return newRuntimeStateWithClock(key, user, inbound, policy, time.Now)
}

func newRuntimeStateWithClock(key, user, inbound string, policy RuntimeUserLimit, now func() time.Time) *runtimeState {
	if now == nil {
		now = time.Now
	}
	state := &runtimeState{key: key, user: user, inbound: inbound, now: now}
	state.storePolicyLocked(policy, true)
	return state
}

func (s *runtimeState) storePolicyLocked(policy RuntimeUserLimit, resetTraffic bool) *runtimeConfig {
	counters := newRuntimeCounters()
	if current := s.config.Load(); !resetTraffic && current != nil && current.counters != nil {
		counters = current.counters
	}
	readLimiter, writeLimiter := newRuntimeLimiters(policy)
	next := &runtimeConfig{policy: policy, readLimiter: readLimiter, writeLimiter: writeLimiter, counters: counters}
	s.config.Store(next)
	return next
}

func (s *runtimeState) currentConfig() *runtimeConfig {
	config := s.loadedConfig()
	if config.policy.PeriodEnd == "" {
		return config
	}
	end, err := time.Parse(time.RFC3339Nano, config.policy.PeriodEnd)
	if err != nil || s.now().Before(end) {
		return config
	}

	s.periodMu.Lock()
	defer s.periodMu.Unlock()
	config = s.loadedConfig()
	policy := config.policy
	previousPeriod := policy.PeriodKey
	end, err = time.Parse(time.RFC3339Nano, policy.PeriodEnd)
	if err != nil || s.now().Before(end) {
		return config
	}
	loc := time.FixedZone("Asia/Shanghai", 8*3600)
	if policy.Timezone != "" {
		if loaded, loadErr := time.LoadLocation(policy.Timezone); loadErr == nil {
			loc = loaded
		}
	}
	anchor := time.Time{}
	if policy.ResetAnchor != "" {
		anchor, _ = time.Parse(time.RFC3339Nano, policy.ResetAnchor)
	}
	periodKey, start, nextEnd := runtimeTrafficWindow(s.now(), policy.ResetMode, policy.ResetDay, anchor, loc)
	policy.PeriodKey = periodKey
	policy.PeriodStart = start.UTC().Format(time.RFC3339Nano)
	policy.PeriodEnd = nextEnd.UTC().Format(time.RFC3339Nano)
	policy.UsedBaselineBytes = 0
	if policy.LeaseEnforced {
		policy.LeaseBytes = policy.ResetLeaseBytes
	}
	policy.QuotaState = "active"
	return s.storePolicyLocked(policy, policy.PreviousPeriodKey == "" || policy.PreviousPeriodKey != previousPeriod)
}

func (s *runtimeState) loadedConfig() *runtimeConfig {
	if s != nil {
		if config := s.config.Load(); config != nil {
			return config
		}
	}
	return &runtimeConfig{counters: newRuntimeCounters()}
}

func (s *runtimeState) currentPolicy() RuntimeUserLimit {
	return s.currentConfig().policy
}

func (s *runtimeState) loadedPolicy() RuntimeUserLimit {
	if s == nil {
		return RuntimeUserLimit{}
	}
	return s.loadedConfig().policy
}

func (s *runtimeState) currentLimiter() *rate.Limiter {
	if s == nil {
		return nil
	}
	return s.currentConfig().readLimiter
}

func (s *runtimeState) currentReadLimiter() *rate.Limiter {
	if s == nil {
		return nil
	}
	return s.currentConfig().readLimiter
}

func (s *runtimeState) currentWriteLimiter() *rate.Limiter {
	if s == nil {
		return nil
	}
	return s.currentConfig().writeLimiter
}

func (s *runtimeState) addTraffic(upload, download int64) {
	config := s.currentConfig()
	policy := config.policy
	if !policy.Billable || policy.UserID <= 0 {
		return
	}
	if upload > 0 {
		config.counters.upload.Add(upload)
	}
	if download > 0 {
		config.counters.download.Add(download)
	}
	if s.usage != nil {
		period := s.usage.period(policy.PeriodKey)
		if upload > 0 {
			period.upload.Add(upload)
		}
		if download > 0 {
			period.download.Add(download)
		}
	}
}

func (s *runtimeState) denied() bool {
	if s.authorizationDenied() {
		return true
	}
	config := s.currentConfig()
	if s.authorization != nil && s.authorization.OfflineAllows(config.policy.AuthorizationKey, s.now()) {
		local := *config
		local.policy.LeaseEnforced = false
		return runtimeConfigDenied(&local, s.unacknowledged(config))
	}
	return runtimeConfigDenied(config, s.unacknowledged(config))
}

// connectionIdentity is the credential a connection authenticated with. It is
// captured at admission so a later credential rotation (new epoch, new key on
// the same inbound user) still identifies and closes the old session.
type connectionIdentity struct {
	authorizationKey string
	credentialEpoch  int64
	userID           int64
}

func (s *runtimeState) identity() connectionIdentity {
	p := s.loadedPolicy()
	return connectionIdentity{authorizationKey: p.AuthorizationKey, credentialEpoch: p.CredentialEpoch, userID: p.UserID}
}

// authorizationRevokedFor is the authorization verdict for one identity: the
// key it authenticated with is denied or no longer granted, or the credential
// it used has been superseded by a newer epoch. Unlike quota, a revoked
// connection is always closed regardless of how it was admitted.
func (s *runtimeState) authorizationRevokedFor(identity connectionIdentity) bool {
	if s.authorization == nil {
		return false
	}
	p := s.loadedPolicy()
	if p.UserID <= 0 && p.AuthorizationKey == "" && identity.authorizationKey == "" {
		return false
	}
	key := identity.authorizationKey
	if key == "" {
		key = p.AuthorizationKey
	}
	if !s.authorization.Allows(key, s.now()) {
		return true
	}
	return identity.authorizationKey != "" && p.AuthorizationKey != "" && (identity.authorizationKey != p.AuthorizationKey || (identity.credentialEpoch > 0 && p.CredentialEpoch > 0 && identity.credentialEpoch != p.CredentialEpoch))
}

// quotaDeniedFor preserves admitted sessions for credential-only rejection,
// but quota exhaustion always denies both admission and existing traffic.
func (s *runtimeState) quotaDeniedFor(admitted bool) bool {
	config := s.currentConfig()
	switch normalizeCredentialStatus(config.policy.CredentialStatus) {
	case "active":
	case "reject_new":
		return !admitted
	default:
		return true
	}
	if s.authorization != nil && s.authorization.OfflineAllows(config.policy.AuthorizationKey, s.now()) {
		local := *config
		local.policy.LeaseEnforced = false
		return runtimeConfigDenied(&local, s.unacknowledged(config))
	}
	return runtimeConfigDenied(config, s.unacknowledged(config))
}

func (s *runtimeState) deniedForConnection(admitted bool) bool {
	return s.authorizationRevokedFor(s.identity()) || s.quotaDeniedFor(admitted)
}

func runtimeConfigDenied(config *runtimeConfig, unacknowledged int64) bool {
	policy := config.policy
	if normalizeCredentialStatus(policy.CredentialStatus) != "active" {
		return true
	}
	if !policy.Billable || policy.UserID <= 0 {
		return false
	}
	if policy.QuotaState == "quota_exceeded" {
		return true
	}
	if policy.TrafficLimitBytes <= 0 {
		return false
	}
	used := policy.UsedBaselineBytes + unacknowledged
	return used >= runtimeEffectiveCap(policy)
}

func runtimeEffectiveCap(policy RuntimeUserLimit) int64 {
	if policy.TrafficLimitBytes <= 0 {
		return 0
	}
	capBytes := policy.TrafficLimitBytes
	if !policy.LeaseEnforced {
		return capBytes
	}
	leaseBytes := policy.LeaseBytes
	if leaseBytes < 0 {
		leaseBytes = 0
	}
	leaseCap := policy.UsedBaselineBytes + leaseBytes
	if leaseCap < capBytes {
		return leaseCap
	}
	return capBytes
}

func normalizeCredentialStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "active"
	}
	return value
}

func (s *runtimeState) unacknowledged(config *runtimeConfig) int64 {
	if config == nil || config.counters == nil {
		return 0
	}
	if s.usage != nil {
		return s.usage.period(config.policy.PeriodKey).unacknowledged()
	}
	return runtimePositiveDifference(config.counters.upload.Load(), config.counters.acknowledgedUpload.Load()) + runtimePositiveDifference(config.counters.download.Load(), config.counters.acknowledgedDownload.Load())
}

func (s *runtimeState) acknowledge(checkpoint TrafficCounterAcknowledgement) {
	if s == nil || checkpoint.PeriodKey == "" {
		return
	}
	s.periodMu.Lock()
	defer s.periodMu.Unlock()
	config := s.loadedConfig()
	if config.policy.PeriodKey != checkpoint.PeriodKey || config.counters == nil {
		return
	}
	if checkpoint.CounterEpoch != "" && checkpoint.CounterEpoch != config.counters.epoch {
		return
	}
	upload := runtimeMinInt64(checkpoint.Upload, config.counters.upload.Load())
	download := runtimeMinInt64(checkpoint.Download, config.counters.download.Load())
	if upload < 0 {
		upload = 0
	}
	if download < 0 {
		download = 0
	}
	previousUpload := config.counters.acknowledgedUpload.Load()
	previousDownload := config.counters.acknowledgedDownload.Load()
	if upload < previousUpload {
		upload = previousUpload
	}
	if download < previousDownload {
		download = previousDownload
	}
	config.counters.acknowledgedUpload.Store(upload)
	config.counters.acknowledgedDownload.Store(download)
	if s.usage != nil {
		period := s.usage.period(checkpoint.PeriodKey)
		period.acknowledgedUpload.Add(upload - previousUpload)
		period.acknowledgedDownload.Add(download - previousDownload)
	}
}

func (u *runtimeUserUsage) period(periodKey string) *runtimeUsagePeriod {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.periods == nil {
		u.periods = map[string]*runtimeUsagePeriod{}
	}
	period := u.periods[periodKey]
	if period == nil {
		period = &runtimeUsagePeriod{}
		u.periods[periodKey] = period
	}
	return period
}

func (p *runtimeUsagePeriod) unacknowledged() int64 {
	return runtimePositiveDifference(p.upload.Load(), p.acknowledgedUpload.Load()) + runtimePositiveDifference(p.download.Load(), p.acknowledgedDownload.Load())
}

func runtimePositiveDifference(total, acknowledged int64) int64 {
	if total <= acknowledged {
		return 0
	}
	return total - acknowledged
}

func runtimeMinInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func (s *runtimeState) updatePolicy(policy RuntimeUserLimit) {
	s.periodMu.Lock()
	defer s.periodMu.Unlock()
	current := s.loadedPolicy()
	periodChanged := current.PeriodKey != "" && policy.PeriodKey != "" && current.PeriodKey != policy.PeriodKey
	reset := periodChanged && (policy.PreviousPeriodKey == "" || policy.PreviousPeriodKey != current.PeriodKey)
	s.storePolicyLocked(policy, reset)
}

func (s *runtimeState) snapshot() (TrafficCounter, bool) {
	config := s.currentConfig()
	upload := config.counters.upload.Load()
	download := config.counters.download.Load()
	if upload == 0 && download == 0 {
		return TrafficCounter{}, false
	}
	policy := config.policy
	return TrafficCounter{Key: s.key, CounterEpoch: config.counters.epoch, User: s.user, Inbound: s.inbound, UserID: policy.UserID, InboundID: policy.InboundID, PathID: policy.PathID, PeriodKey: policy.PeriodKey, Upload: upload, Download: download}, true
}

func (t *RateLimitTracker) Enabled() bool {
	if t == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.states) > 0
}

func (t *RateLimitTracker) stateForKey(key string) *runtimeState {
	if t == nil || key == "" {
		return nil
	}
	t.mu.RLock()
	state := t.states[key]
	t.mu.RUnlock()
	return state
}

func (t *RateLimitTracker) LimiterForUser(user string) *rate.Limiter {
	state := t.stateForKey("user:" + user)
	if state == nil {
		return nil
	}
	return state.currentLimiter()
}

func (t *RateLimitTracker) RoutedFlow(ctx context.Context, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) tun.FlowTracker {
	// oboard-sb never hosts TUN inbounds; flow tracking is not used.
	return nil
}

func (t *RateLimitTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) net.Conn {
	state := t.runtimeFor(metadata)
	if state == nil {
		return conn
	}
	config := state.currentConfig()
	if config.readLimiter == nil && config.writeLimiter == nil && !config.policy.Billable {
		return conn
	}
	admitted := !state.denied()
	tracked := &trackedConn{ExtendedConn: bufio.NewExtendedConn(conn), ctx: ctx, tracker: t, state: state, identity: state.identity(), admitted: admitted, activityIdentity: activity.Bind(config.policy.UserID, config.policy.InboundID, config.policy.PathID, metadata.Source.Addr), auditKey: t.recordConnectionStart(state, metadata, outbound, "tcp", admitted)}
	t.registerConn(state.key, tracked)
	if tracked.deny() {
		_ = tracked.Close()
	}
	if config.readLimiter == nil && config.writeLimiter == nil {
		return &trackedCounterConn{trackedConn: tracked}
	}
	return tracked
}

func (t *RateLimitTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) N.PacketConn {
	state := t.runtimeFor(metadata)
	if state == nil {
		return conn
	}
	config := state.currentConfig()
	if config.readLimiter == nil && config.writeLimiter == nil && !config.policy.Billable {
		return conn
	}
	admitted := !state.denied()
	tracked := &trackedPacketConn{PacketConn: conn, ctx: ctx, tracker: t, state: state, identity: state.identity(), admitted: admitted, activityIdentity: activity.Bind(config.policy.UserID, config.policy.InboundID, config.policy.PathID, metadata.Source.Addr), auditKey: t.recordConnectionStart(state, metadata, outbound, "udp", admitted)}
	t.registerPacketConn(state.key, tracked)
	if tracked.deny() {
		_ = tracked.Close()
	}
	return tracked
}

func (t *RateLimitTracker) runtimeFor(metadata adapter.InboundContext) *runtimeState {
	if metadata.User != "" {
		if state := t.stateForKey("user:" + metadata.User); state != nil {
			return state
		}
	}
	if metadata.Inbound != "" {
		return t.stateForKey("inbound:" + metadata.Inbound)
	}
	return nil
}

func newRuntimeLimiters(limit RuntimeUserLimit) (*rate.Limiter, *rate.Limiter) {
	if limit.SpeedLimitMbps <= 0 {
		return nil, nil
	}
	bytesPerSecond := limit.SpeedLimitMbps * 1_000_000 / 8
	if bytesPerSecond <= 0 {
		return nil, nil
	}
	burst := bytesPerSecond / 5
	if burst < rateLimitIOChunk {
		burst = rateLimitIOChunk
	}
	return rate.NewLimiter(rate.Limit(bytesPerSecond), burst), rate.NewLimiter(rate.Limit(bytesPerSecond), burst)
}

func AttachRuntimeTrackers(ctx context.Context, metadata RuntimeMetadata) *RateLimitTracker {
	tracker := newRateLimitTracker(metadata, ntp.TimeFuncFromContext(ctx))
	service.MustRegister[familyselector.SelectionObserver](ctx, tracker)
	service.MustRegister[runtimeuser.AdmissionGate](ctx, tracker)
	if !tracker.Enabled() && (metadata.RuntimeUsers == nil || len(metadata.RuntimeUsers.Inbounds) == 0) {
		return tracker
	}
	router := service.FromContext[adapter.Router](ctx)
	if router != nil {
		router.AppendTracker(tracker)
	}
	return tracker
}

type trackedConn struct {
	activityIdentity activity.Identity
	N.ExtendedConn
	ctx      context.Context
	tracker  *RateLimitTracker
	state    *runtimeState
	identity connectionIdentity
	admitted bool
	auditKey string
	closed   atomic.Bool
}

func (c *trackedConn) Read(p []byte) (int, error) {
	if c.deny() {
		return 0, errors.New("oboard traffic quota exceeded")
	}
	readBuffer := p
	if c.state.currentReadLimiter() != nil && len(readBuffer) > rateLimitIOChunk {
		readBuffer = readBuffer[:rateLimitIOChunk]
	}
	n, err := c.ExtendedConn.Read(readBuffer)
	if n > 0 {
		if waitErr := waitBytes(c.ctx, c.state.currentReadLimiter(), n); waitErr != nil && err == nil {
			err = waitErr
		}
		c.addTraffic(int64(n), 0)
		if c.deny() {
			_ = c.Close()
		}
	}
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	if c.deny() {
		return 0, errors.New("oboard traffic quota exceeded")
	}
	limiter := c.state.currentWriteLimiter()
	if limiter == nil {
		n, err := c.ExtendedConn.Write(p)
		if n > 0 {
			c.addTraffic(0, int64(n))
			if c.deny() {
				_ = c.Close()
			}
		}
		return n, err
	}
	total := 0
	for total < len(p) {
		end := total + rateLimitIOChunk
		if end > len(p) {
			end = len(p)
		}
		chunkSize := end - total
		if err := waitBytes(c.ctx, limiter, chunkSize); err != nil {
			return total, err
		}
		n, err := c.ExtendedConn.Write(p[total:end])
		total += n
		if n > 0 {
			c.addTraffic(0, int64(n))
		}
		if err != nil {
			return total, err
		}
		if n != chunkSize {
			return total, io.ErrShortWrite
		}
	}
	if c.deny() {
		_ = c.Close()
	}
	return total, nil
}

func (c *trackedConn) ReadBuffer(buffer *buf.Buffer) error {
	if c.deny() {
		return errors.New("oboard traffic quota exceeded")
	}
	before := 0
	if buffer != nil {
		before = buffer.Len()
	}
	err := c.ExtendedConn.ReadBuffer(buffer)
	read := 0
	if buffer != nil && buffer.Len() > before {
		read = buffer.Len() - before
	}
	if read > 0 {
		if waitErr := waitBytes(c.ctx, c.state.currentReadLimiter(), read); waitErr != nil && err == nil {
			return waitErr
		}
		c.addTraffic(int64(read), 0)
		if c.deny() {
			_ = c.Close()
		}
	}
	return err
}

func (c *trackedConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.deny() {
		return errors.New("oboard traffic quota exceeded")
	}
	if buffer == nil {
		return nil
	}
	if buffer.Len() == 0 {
		return c.ExtendedConn.WriteBuffer(buffer)
	}
	limiter := c.state.currentWriteLimiter()
	if limiter == nil {
		before := buffer.Len()
		err := c.ExtendedConn.WriteBuffer(buffer)
		written := before - buffer.Len()
		if written > 0 {
			c.addTraffic(0, int64(written))
			if c.deny() {
				_ = c.Close()
			}
		}
		return err
	}
	for buffer.Len() > rateLimitIOChunk {
		if err := waitBytes(c.ctx, limiter, rateLimitIOChunk); err != nil {
			return err
		}
		n, err := c.ExtendedConn.Write(buffer.To(rateLimitIOChunk))
		if n > 0 {
			c.addTraffic(0, int64(n))
			buffer.Advance(n)
		}
		if err != nil {
			return err
		}
		if n != rateLimitIOChunk {
			return io.ErrShortWrite
		}
	}
	size := buffer.Len()
	if err := waitBytes(c.ctx, limiter, size); err != nil {
		return err
	}
	err := c.ExtendedConn.WriteBuffer(buffer)
	written := size - buffer.Len()
	if written > 0 {
		c.addTraffic(0, int64(written))
	}
	if c.deny() {
		_ = c.Close()
	}
	return err
}

func (c *trackedConn) Upstream() any { return c.ExtendedConn }

func (c *trackedConn) addTraffic(upload, download int64) {
	if c == nil || c.state == nil {
		return
	}
	if c.tracker != nil && c.tracker.auditEnabled.Load() && c.admitted && c.state.currentConfig().policy.Billable && upload >= 0 && download >= 0 {
		c.tracker.activity.Record(c.activityIdentity, c.tracker.timeNow().Unix(), uint64(upload), uint64(download))
	}
	c.state.addTraffic(upload, download)
	if c.tracker != nil {
		c.tracker.recordConnectionPayload(c.auditKey, upload, download)
	}
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) && c.tracker != nil && c.state != nil {
		c.tracker.recordConnectionEnd(c.auditKey)
		c.tracker.unregisterConn(c.state.key, c)
	}
	return c.ExtendedConn.Close()
}

func (c *trackedConn) deny() bool {
	return c.state != nil && (c.state.authorizationRevokedFor(c.identity) || c.state.quotaDeniedFor(c.admitted))
}

// trackedCounterConn lets sing's copy engine unwrap traffic accounting into
// callbacks. Unrestricted users can then keep the official direct-copy/splice
// path instead of forcing every payload through Go buffers.
type trackedCounterConn struct {
	*trackedConn
}

func (c *trackedCounterConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.ExtendedConn, []N.CountFunc{c.countUpload}
}

func (c *trackedCounterConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return c.ExtendedConn, []N.CountFunc{c.countDownload}
}

func (c *trackedCounterConn) countUpload(n int64) {
	if n <= 0 || c.state == nil {
		return
	}
	c.addTraffic(n, 0)
	if c.deny() {
		_ = c.Close()
	}
}

func (c *trackedCounterConn) countDownload(n int64) {
	if n <= 0 || c.state == nil {
		return
	}
	c.addTraffic(0, n)
	if c.deny() {
		_ = c.Close()
	}
}

type trackedPacketConn struct {
	activityIdentity activity.Identity
	N.PacketConn
	ctx      context.Context
	tracker  *RateLimitTracker
	state    *runtimeState
	identity connectionIdentity
	admitted bool
	auditKey string
	closed   atomic.Bool
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if c.deny() {
		return destination, errors.New("oboard traffic quota exceeded")
	}
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err == nil && buffer != nil && buffer.Len() > 0 {
		if limiter := c.state.currentReadLimiter(); limiter != nil && !limiter.AllowN(time.Now(), buffer.Len()) {
			buffer.Reset()
			return destination, nil
		}
		c.addTraffic(int64(buffer.Len()), 0)
		if c.deny() {
			_ = c.Close()
		}
	}
	return destination, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.deny() {
		return errors.New("oboard traffic quota exceeded")
	}
	size := 0
	if buffer != nil {
		size = buffer.Len()
	}
	if size > 0 {
		if limiter := c.state.currentWriteLimiter(); limiter != nil && !limiter.AllowN(time.Now(), size) {
			return nil
		}
	}
	if err := c.PacketConn.WritePacket(buffer, destination); err != nil {
		return err
	}
	if size > 0 {
		c.addTraffic(0, int64(size))
		if c.deny() {
			_ = c.Close()
		}
	}
	return nil
}

func (c *trackedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) && c.tracker != nil && c.state != nil {
		c.tracker.recordConnectionEnd(c.auditKey)
		c.tracker.unregisterPacketConn(c.state.key, c)
	}
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) addTraffic(upload, download int64) {
	if c == nil || c.state == nil {
		return
	}
	if c.tracker != nil && c.tracker.auditEnabled.Load() && c.admitted && c.state.currentConfig().policy.Billable && upload >= 0 && download >= 0 {
		c.tracker.activity.Record(c.activityIdentity, c.tracker.timeNow().Unix(), uint64(upload), uint64(download))
	}
	c.state.addTraffic(upload, download)
	if c.tracker != nil {
		c.tracker.recordConnectionPayload(c.auditKey, upload, download)
	}
}

func (c *trackedPacketConn) deny() bool {
	return c.state != nil && (c.state.authorizationRevokedFor(c.identity) || c.state.quotaDeniedFor(c.admitted))
}

func (c *trackedPacketConn) Upstream() any { return c.PacketConn }

var (
	_ N.ExtendedConn = (*trackedConn)(nil)
	_ N.ReadCounter  = (*trackedCounterConn)(nil)
	_ N.WriteCounter = (*trackedCounterConn)(nil)
	_ N.PacketConn   = (*trackedPacketConn)(nil)
)

func runtimeTrafficWindow(now time.Time, mode string, day int, anchor time.Time, loc *time.Location) (string, time.Time, time.Time) {
	n := now.In(loc)
	if day < 1 {
		day = 1
	}
	if day > 31 {
		day = 31
	}
	if mode == "never" {
		if anchor.IsZero() {
			anchor = n
		}
		return anchor.UTC().Format(time.RFC3339Nano), anchor.In(loc), time.Date(9999, time.December, 31, 23, 59, 59, 0, loc)
	}
	if mode == "anniversary_month" {
		if anchor.IsZero() {
			anchor = n
		}
		start, end := runtimeAnniversaryWindow(n, anchor.In(loc), loc)
		return start.UTC().Format(time.RFC3339Nano), start, end
	}
	if mode != "month_day" {
		start := time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, loc)
		return start.Format("2006-01-02"), start, start.AddDate(0, 1, 0)
	}
	start := time.Date(n.Year(), n.Month(), runtimeClampedMonthDay(n.Year(), n.Month(), day), 0, 0, 0, 0, loc)
	if n.Before(start) {
		prev := start.AddDate(0, -1, 0)
		start = time.Date(prev.Year(), prev.Month(), runtimeClampedMonthDay(prev.Year(), prev.Month(), day), 0, 0, 0, 0, loc)
	}
	next := start.AddDate(0, 1, 0)
	end := time.Date(next.Year(), next.Month(), runtimeClampedMonthDay(next.Year(), next.Month(), day), 0, 0, 0, 0, loc)
	return start.Format("2006-01-02"), start, end
}

func runtimeAnniversaryWindow(now, anchor time.Time, loc *time.Location) (time.Time, time.Time) {
	if now.Before(anchor) {
		return anchor, runtimeAnniversaryBoundary(anchor, 1, loc)
	}
	months := (now.Year()-anchor.Year())*12 + int(now.Month()-anchor.Month())
	start := runtimeAnniversaryBoundary(anchor, months, loc)
	if now.Before(start) {
		months--
		start = runtimeAnniversaryBoundary(anchor, months, loc)
	}
	return start, runtimeAnniversaryBoundary(anchor, months+1, loc)
}

func runtimeAnniversaryBoundary(anchor time.Time, months int, loc *time.Location) time.Time {
	monthStart := time.Date(anchor.Year(), anchor.Month()+time.Month(months), 1, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), loc)
	day := runtimeClampedMonthDay(monthStart.Year(), monthStart.Month(), anchor.Day())
	return time.Date(monthStart.Year(), monthStart.Month(), day, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), loc)
}

func runtimeClampedMonthDay(year int, month time.Month, day int) int {
	last := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > last {
		return last
	}
	if day < 1 {
		return 1
	}
	return day
}

func (t *RateLimitTracker) Snapshot() []TrafficCounter {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	states := make([]*runtimeState, 0, len(t.states))
	for _, state := range t.states {
		states = append(states, state)
	}
	t.mu.RUnlock()
	out := make([]TrafficCounter, 0, len(states))
	for _, state := range states {
		if counter, ok := state.snapshot(); ok {
			out = append(out, counter)
		}
	}
	return out
}

// ReplaceScopedUsers upserts tracker identities for the users just installed
// on the named inbounds. Removed users keep their counters for tail traffic;
// they can no longer authenticate, and authorization closes remaining sessions.
func (t *RateLimitTracker) ReplaceScopedUsers(scope []string, entries []UserInstallEntry) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, entry := range entries {
		user := strings.TrimSpace(entry.AuthUser)
		if user == "" {
			continue
		}
		policy := entry.Policy
		if entry.AuthorizationKey != "" {
			policy.AuthorizationKey = entry.AuthorizationKey
		}
		if entry.Identity.UserID > 0 {
			policy.UserID = entry.Identity.UserID
		}
		if entry.Identity.InboundID > 0 {
			policy.InboundID = entry.Identity.InboundID
		}
		policy.PathID = entry.Identity.PathID
		policy.DeviceIDHash = entry.Identity.DeviceIDHash
		policy.CredentialEpoch = entry.Identity.CredentialEpoch
		policy.CredentialStatus = entry.Identity.CredentialStatus
		if !policy.Billable && policy.UserID > 0 {
			policy.Billable = true
		}
		key := "user:" + user
		if state := t.states[key]; state != nil {
			state.updatePolicy(mergeRuntimeIdentity(state.loadedPolicy(), policy))
			continue
		}
		state := newRuntimeStateWithClock(key, user, "", policy, t.now)
		if policy.UserID > 0 {
			state.usage = &runtimeUserUsage{periods: map[string]*runtimeUsagePeriod{}}
			for _, existing := range t.states {
				if existing.loadedPolicy().UserID == policy.UserID && existing.usage != nil {
					state.usage = existing.usage
					break
				}
			}
		}
		state.authorization = t.authorization
		t.states[key] = state
	}
	_ = scope
}

func mergeRuntimeIdentity(current, update RuntimeUserLimit) RuntimeUserLimit {
	if update.AuthorizationKey != "" {
		current.AuthorizationKey = update.AuthorizationKey
	}
	if update.UserID > 0 {
		current.UserID = update.UserID
	}
	if update.InboundID > 0 {
		current.InboundID = update.InboundID
	}
	current.PathID = update.PathID
	current.DeviceIDHash = update.DeviceIDHash
	current.CredentialEpoch = update.CredentialEpoch
	current.CredentialStatus = update.CredentialStatus
	if update.SpeedLimitMbps != 0 {
		current.SpeedLimitMbps = update.SpeedLimitMbps
	}
	if update.TrafficLimitBytes != 0 {
		current.TrafficLimitBytes = update.TrafficLimitBytes
	}
	if update.LeaseBytes != 0 {
		current.LeaseBytes = update.LeaseBytes
	}
	current.Billable = update.Billable || current.Billable
	current.LeaseEnforced = update.LeaseEnforced || current.LeaseEnforced
	return current
}

func (t *RateLimitTracker) UpdatePolicies(policies map[string]RuntimeUserLimit) {
	if t == nil || len(policies) == 0 {
		return
	}
	t.mu.RLock()
	states := make(map[string]*runtimeState, len(t.states))
	for key, state := range t.states {
		states[key] = state
	}
	t.mu.RUnlock()
	updates := map[*runtimeState]RuntimeUserLimit{}
	for key, policy := range policies {
		if state := states[key]; state != nil {
			updates[state] = mergeRuntimePolicy(state.loadedPolicy(), policy)
		}
		if policy.UserID <= 0 {
			continue
		}
		for _, state := range states {
			current := state.loadedPolicy()
			if current.UserID == policy.UserID {
				updates[state] = mergeRuntimePolicy(current, policy)
			}
		}
	}
	for state, policy := range updates {
		state.updatePolicy(policy)
		if state.deniedForConnection(true) {
			t.closeActive(state.key)
		}
	}
}

func (t *RateLimitTracker) AcknowledgeTraffic(acknowledged map[string]TrafficCounterAcknowledgement) {
	if t != nil {
		defer t.pruneSnellCounters()
	}
	if t == nil || len(acknowledged) == 0 {
		return
	}
	t.mu.RLock()
	states := make(map[string]*runtimeState, len(t.states))
	for key, state := range t.states {
		states[key] = state
	}
	t.mu.RUnlock()
	for key, checkpoint := range acknowledged {
		if state := states[key]; state != nil {
			state.acknowledge(checkpoint)
		}
	}
}

func mergeRuntimePolicy(current, update RuntimeUserLimit) RuntimeUserLimit {
	update.InboundID = current.InboundID
	update.UserID = current.UserID
	update.AuthorizationKey = current.AuthorizationKey
	update.DeviceIDHash = current.DeviceIDHash
	update.CredentialEpoch = current.CredentialEpoch
	update.CredentialStatus = current.CredentialStatus
	update.PathID = current.PathID
	return update
}

func (t *RateLimitTracker) registerConn(key string, c *trackedConn) {
	if t == nil || key == "" || c == nil {
		return
	}
	t.mu.Lock()
	if t.active[key] == nil {
		t.active[key] = map[*trackedConn]struct{}{}
	}
	t.active[key][c] = struct{}{}
	if credential := c.identity.authorizationKey; credential != "" {
		if t.byCredential == nil {
			t.byCredential = map[string]map[*trackedConn]struct{}{}
		}
		if t.byCredential[credential] == nil {
			t.byCredential[credential] = map[*trackedConn]struct{}{}
		}
		t.byCredential[credential][c] = struct{}{}
	}
	t.mu.Unlock()
	active := t.activeTCP.Add(1)
	if t.socketGovernor != nil {
		t.socketGovernor.ObserveConnections(active)
	}
	if c.deny() {
		_ = c.Close()
	}
}

func (t *RateLimitTracker) unregisterConn(key string, c *trackedConn) {
	t.mu.Lock()
	delete(t.active[key], c)
	if len(t.active[key]) == 0 {
		delete(t.active, key)
	}
	if credential := c.identity.authorizationKey; credential != "" && t.byCredential != nil {
		delete(t.byCredential[credential], c)
		if len(t.byCredential[credential]) == 0 {
			delete(t.byCredential, credential)
		}
	}
	t.mu.Unlock()
	active := t.activeTCP.Add(-1)
	if active < 0 {
		t.activeTCP.Store(0)
		active = 0
	}
	if t.socketGovernor != nil {
		t.socketGovernor.ObserveConnections(active)
	}
}

func (t *RateLimitTracker) registerPacketConn(key string, c *trackedPacketConn) {
	if t == nil || key == "" || c == nil {
		return
	}
	t.mu.Lock()
	if t.activePacket[key] == nil {
		t.activePacket[key] = map[*trackedPacketConn]struct{}{}
	}
	t.activePacket[key][c] = struct{}{}
	if credential := c.identity.authorizationKey; credential != "" {
		if t.byCredentialPacket == nil {
			t.byCredentialPacket = map[string]map[*trackedPacketConn]struct{}{}
		}
		if t.byCredentialPacket[credential] == nil {
			t.byCredentialPacket[credential] = map[*trackedPacketConn]struct{}{}
		}
		t.byCredentialPacket[credential][c] = struct{}{}
	}
	t.mu.Unlock()
	if c.deny() {
		_ = c.Close()
	}
}

func (t *RateLimitTracker) unregisterPacketConn(key string, c *trackedPacketConn) {
	t.mu.Lock()
	delete(t.activePacket[key], c)
	if len(t.activePacket[key]) == 0 {
		delete(t.activePacket, key)
	}
	if credential := c.identity.authorizationKey; credential != "" && t.byCredentialPacket != nil {
		delete(t.byCredentialPacket[credential], c)
		if len(t.byCredentialPacket[credential]) == 0 {
			delete(t.byCredentialPacket, credential)
		}
	}
	t.mu.Unlock()
}

// closeActive closes every connection routed for one inbound user key.
func (t *RateLimitTracker) closeActive(key string) {
	defer t.reapSnellParents(false)
	t.mu.RLock()
	conns := make([]*trackedConn, 0, len(t.active[key]))
	for conn := range t.active[key] {
		conns = append(conns, conn)
	}
	packets := make([]*trackedPacketConn, 0, len(t.activePacket[key]))
	for conn := range t.activePacket[key] {
		packets = append(packets, conn)
	}
	t.mu.RUnlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	for _, conn := range packets {
		_ = conn.Close()
	}
}

// closeByCredential closes every connection that authenticated with one
// authorization key, whichever inbound user it is currently mapped to. It
// returns how many connections were closed. Only the routed TCP/UDP streams are
// closed here: a HY2 QUIC connection, AnyTLS session, or multiplex tunnel that
// carried them stays up until the client opens a new stream, which is then
// rejected at admission.
func (t *RateLimitTracker) closeByCredential(credential string) int {
	if credential == "" {
		return 0
	}
	t.mu.RLock()
	conns := make([]*trackedConn, 0, len(t.byCredential[credential]))
	for conn := range t.byCredential[credential] {
		conns = append(conns, conn)
	}
	packets := make([]*trackedPacketConn, 0, len(t.byCredentialPacket[credential]))
	for conn := range t.byCredentialPacket[credential] {
		packets = append(packets, conn)
	}
	t.mu.RUnlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	for _, conn := range packets {
		_ = conn.Close()
	}
	return len(conns) + len(packets)
}

// revokedConnections lists connections whose authorization identity is no
// longer granted, independent of the inbound user they are mapped to.
func (t *RateLimitTracker) revokedConnections() ([]*trackedConn, []*trackedPacketConn) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var conns []*trackedConn
	var packets []*trackedPacketConn
	for _, set := range t.active {
		for conn := range set {
			if conn.state != nil && conn.state.authorizationRevokedFor(conn.identity) {
				conns = append(conns, conn)
			}
		}
	}
	for _, set := range t.activePacket {
		for conn := range set {
			if conn.state != nil && conn.state.authorizationRevokedFor(conn.identity) {
				packets = append(packets, conn)
			}
		}
	}
	return conns, packets
}

func waitBytes(ctx context.Context, limiter *rate.Limiter, n int) error {
	if limiter == nil || n <= 0 {
		return nil
	}
	burst := limiter.Burst()
	if burst <= 0 {
		burst = 1
	}
	for n > 0 {
		chunk := n
		if chunk > burst {
			chunk = burst
		}
		if err := limiter.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}
