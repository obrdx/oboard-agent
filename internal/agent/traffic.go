package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/OboardProject/oboard-agent/internal/securefile"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	trafficReportBatchSize         = 200
	trafficStateSchemaV2           = 2
	trafficSourceCore              = "core"
	trafficSourceSSH               = "ssh"
	trafficStatusHealthy           = "healthy"
	trafficStatusRecovering        = "recovering"
	trafficStatusStale             = "stale"
	trafficStatusStateCorrupt      = "state_corrupt"
	trafficStatusCounterRegression = "counter_regression"
	trafficStatusCheckpointGap     = "checkpoint_gap"
	trafficStatusCheckpointOverlap = "checkpoint_overlap"
	trafficStatusEpochConflict     = "epoch_conflict"
	trafficLeaseStaleAfter         = 24 * time.Hour
)

var coreAPISocket = defaultCoreAPISocket()

type trafficSnapshotItem struct {
	Key          string `json:"key"`
	CounterEpoch string `json:"counter_epoch,omitempty"`
	Source       string `json:"source,omitempty"`
	UserID       int64  `json:"user_id"`
	InboundID    int64  `json:"inbound_id"`
	PathID       int64  `json:"path_id"`
	PeriodKey    string `json:"period_key"`
	Upload       int64  `json:"upload_bytes"`
	Download     int64  `json:"download_bytes"`
}

type trafficLocalState struct {
	SchemaVersion    int                                   `json:"schema_version"`
	AgentInstanceID  string                                `json:"agent_instance_id,omitempty"`
	Last             map[string]trafficSnapshotItem        `json:"last,omitempty"`
	Pending          []trafficPendingReport                `json:"pending,omitempty"`
	Acknowledged     map[string]trafficCounterCheckpoint   `json:"acknowledged,omitempty"`
	Streams          map[string]*trafficStreamState        `json:"streams,omitempty"`
	PendingReports   map[string]*trafficPendingRange       `json:"pending_reports,omitempty"`
	Sync             trafficSyncState                      `json:"sync"`
	RecoveryRequired bool                                  `json:"recovery_required,omitempty"`
	PolicyRevision   int64                                 `json:"policy_revision,omitempty"`
	Policies         map[string]model.TrafficRuntimePolicy `json:"policies,omitempty"`
}

type trafficStreamState struct {
	Source           string `json:"source"`
	SnapshotKey      string `json:"snapshot_key,omitempty"`
	CounterEpoch     string `json:"counter_epoch"`
	PeriodKey        string `json:"period_key"`
	UserID           int64  `json:"user_id"`
	InboundID        int64  `json:"inbound_id,omitempty"`
	PathID           int64  `json:"path_id,omitempty"`
	ObservedUpload   int64  `json:"observed_upload"`
	ObservedDownload int64  `json:"observed_download"`
	AcceptedUpload   int64  `json:"accepted_upload"`
	AcceptedDownload int64  `json:"accepted_download"`
	Status           string `json:"status"`
	LastError        string `json:"last_error,omitempty"`
	// LastObservedAt dates the last local counter snapshot that carried this
	// stream. It is what lets a stream whose inbound or user is gone leave the
	// state file; without it, every stream this Agent ever saw was resent in
	// every batch for the lifetime of the installation.
	LastObservedAt string `json:"last_observed_at,omitempty"`
}

type trafficPendingRange struct {
	ReportID     string `json:"report_id"`
	Source       string `json:"source"`
	StreamID     string `json:"stream_id"`
	CounterEpoch string `json:"counter_epoch"`
	PeriodKey    string `json:"period_key"`
	UserID       int64  `json:"user_id"`
	InboundID    *int64 `json:"inbound_id,omitempty"`
	PathID       *int64 `json:"path_id,omitempty"`
	FromUpload   int64  `json:"from_upload_bytes"`
	ToUpload     int64  `json:"to_upload_bytes"`
	FromDownload int64  `json:"from_download_bytes"`
	ToDownload   int64  `json:"to_download_bytes"`
	StartedAt    string `json:"started_at"`
	EndedAt      string `json:"ended_at"`
	SnapshotKey  string `json:"snapshot_key,omitempty"`
}

type trafficSyncState struct {
	Status      string `json:"status,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type trafficCounterCheckpoint struct {
	CounterEpoch string `json:"counter_epoch,omitempty"`
	PeriodKey    string `json:"period_key"`
	Upload       int64  `json:"upload_bytes"`
	Download     int64  `json:"download_bytes"`
}

type trafficPendingReport struct {
	ReportID           string `json:"report_id"`
	UserID             int64  `json:"user_id"`
	InboundID          *int64 `json:"inbound_id,omitempty"`
	PathID             *int64 `json:"path_id,omitempty"`
	PeriodKey          string `json:"period_key"`
	Upload             int64  `json:"upload_bytes"`
	Download           int64  `json:"download_bytes"`
	StartedAt          string `json:"started_at"`
	EndedAt            string `json:"ended_at"`
	SnapshotKey        string `json:"snapshot_key,omitempty"`
	CumulativeUpload   int64  `json:"cumulative_upload_bytes,omitempty"`
	CumulativeDownload int64  `json:"cumulative_download_bytes,omitempty"`
}

type trafficReportItem struct {
	ReportID  string `json:"report_id"`
	UserID    int64  `json:"user_id"`
	InboundID *int64 `json:"inbound_id,omitempty"`
	PathID    *int64 `json:"path_id,omitempty"`
	PeriodKey string `json:"period_key"`
	Upload    int64  `json:"upload_bytes"`
	Download  int64  `json:"download_bytes"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
}

type trafficLedgerReportItem struct {
	ReportID     string `json:"report_id"`
	Source       string `json:"source"`
	StreamID     string `json:"stream_id"`
	CounterEpoch string `json:"counter_epoch"`
	PeriodKey    string `json:"period_key"`
	UserID       int64  `json:"user_id"`
	InboundID    *int64 `json:"inbound_id,omitempty"`
	PathID       *int64 `json:"path_id,omitempty"`
	FromUpload   int64  `json:"from_upload_bytes"`
	ToUpload     int64  `json:"to_upload_bytes"`
	FromDownload int64  `json:"from_download_bytes"`
	ToDownload   int64  `json:"to_download_bytes"`
	StartedAt    string `json:"started_at"`
	EndedAt      string `json:"ended_at"`
}

type trafficStreamWire struct {
	Source          string `json:"source"`
	StreamID        string `json:"stream_id"`
	CounterEpoch    string `json:"counter_epoch"`
	PeriodKey       string `json:"period_key"`
	UserID          int64  `json:"user_id"`
	InboundID       int64  `json:"inbound_id,omitempty"`
	PathID          int64  `json:"path_id,omitempty"`
	CurrentUpload   int64  `json:"current_upload_bytes"`
	CurrentDownload int64  `json:"current_download_bytes"`
	Status          string `json:"status,omitempty"`
}

type trafficAcceptedReport struct {
	ReportID string `json:"report_id"`
	Status   string `json:"status"`
	// Reason is set for status "rejected". A terminal reason means the report
	// can never be accounted, so the pending record is dropped without opening
	// a counter recovery.
	Reason           string `json:"reason,omitempty"`
	StreamID         string `json:"stream_id,omitempty"`
	CounterEpoch     string `json:"counter_epoch,omitempty"`
	PeriodKey        string `json:"period_key,omitempty"`
	AcceptedUpload   int64  `json:"accepted_upload_bytes"`
	AcceptedDownload int64  `json:"accepted_download_bytes"`
}

type trafficStreamCheckpoint struct {
	Source           string `json:"source"`
	StreamID         string `json:"stream_id"`
	CounterEpoch     string `json:"counter_epoch"`
	PeriodKey        string `json:"period_key"`
	AcceptedUpload   int64  `json:"accepted_upload_bytes"`
	AcceptedDownload int64  `json:"accepted_download_bytes"`
	Status           string `json:"status"`
}

type trafficReportResponse struct {
	Authorization         *model.AuthorizationLease    `json:"authorization,omitempty"`
	AuthorizationEnvelope *model.AuthorizationEnvelope `json:"authorization_envelope,omitempty"`
	Accepted              []string                     `json:"accepted_report_ids"`
	AcceptedReports       []trafficAcceptedReport      `json:"accepted_reports"`
	StreamCheckpoints     []trafficStreamCheckpoint    `json:"stream_checkpoints"`
	Policies              map[string]interface{}       `json:"policies"`
	PolicyRevision        int64                        `json:"policy_revision"`
}

func (r *Runner) startTrafficLoop(ctx context.Context) {
	// #nosec G118 -- loopCtx is the caller's lifecycle context; only the final bounded flush uses a fresh timeout after cancellation.
	go r.runTrafficLoop(ctx)
}

func (r *Runner) runTrafficLoop(loopCtx context.Context) {
	period := trafficSchedulePeriod(r.resources.TrafficReportInterval())
	cfg := r.Config()
	anchor := time.Now()
	next := anchor.Add(trafficInitialDelay(anchor, period, trafficPhase(cfg.AgentID, cfg.ServerID, period)))
	timer := time.NewTimer(time.Until(next))
	defer timer.Stop()
	for {
		// A failed cycle means the Controller returned no policies, so no
		// lease was renewed. Swallowing that error is how a node goes
		// quiet: it keeps serving until every user's current lease is
		// spent, then refuses connections with nothing recorded anywhere.
		r.noteTrafficReportOutcome(r.collectAndReportTraffic(loopCtx))
		if r.Config().ConnectionAuditEnabled {
			_ = r.collectAndReportAccountActivity(loopCtx)
			r.collectDiagnosticActivity(loopCtx)
		}
		latest := r.Config()
		if latest.AgentID != cfg.AgentID || latest.ServerID != cfg.ServerID {
			cfg = latest
			anchor = time.Now()
			next = anchor.Add(trafficInitialDelay(anchor, period, trafficPhase(cfg.AgentID, cfg.ServerID, period)))
		}
		next = trafficNextDeadline(next, time.Now(), period)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(time.Until(next))
		select {
		case <-loopCtx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = r.persistTrafficCheckpointBeforeRuntimeTransition(flushCtx)
			_ = r.collectAndReportTraffic(flushCtx)
			if r.Config().ConnectionAuditEnabled {
				_ = r.collectAndReportAccountActivity(flushCtx)
				r.collectDiagnosticActivity(flushCtx)
			}
			cancel()
			return
		case <-r.trafficReportWake:
		// Recovery is serialized with periodic reports and does not move their phase.
		case <-timer.C:
		}
	}
}

// Initial wall-clock alignment gives restarts the same phase. Subsequent
// deadlines retain Go's monotonic clock and skip missed slots after a slow call.
func trafficSchedulePeriod(period time.Duration) time.Duration {
	if period <= 0 {
		return 30 * time.Second
	}
	return min(period, 30*time.Second)
}
func trafficPhase(agentID string, serverID int64, period time.Duration) time.Duration {
	window := min(10*time.Second, period/3)
	if window <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(agentID + "\x00" + strconv.FormatInt(serverID, 10)))
	return time.Duration(binary.BigEndian.Uint64(sum[:8]) % uint64(window))
}
func trafficInitialDelay(at time.Time, period, offset time.Duration) time.Duration {
	if period <= 0 {
		return 0
	}
	position := time.Duration(at.UnixNano() % int64(period))
	if position < 0 {
		position += period
	}
	delay := (offset - position) % period
	if delay <= 0 {
		delay += period
	}
	return delay
}
func trafficNextDeadline(next, at time.Time, period time.Duration) time.Time {
	if !next.After(at) {
		next = next.Add((at.Sub(next)/period + 1) * period)
	}
	return next
}
func (r *Runner) wakeTrafficReport() {
	select {
	case r.trafficReportWake <- struct{}{}:
	default:
	}
}

func (r *Runner) collectAndReportTraffic(ctx context.Context) error {
	r.trafficMu.Lock()
	defer r.trafficMu.Unlock()
	state := r.trafficStateLocked()
	r.convertLegacyPendingToRangesLocked(state)
	pruned := pruneTrafficStreamsLocked(state, time.Now())
	items, err := r.snapshotTrafficItems(ctx)
	if err != nil && len(items) == 0 {
		if pruned {
			if saveErr := r.saveTrafficState(*state); saveErr != nil {
				return saveErr
			}
		}
		if state.RecoveryRequired {
			return r.reportTrafficLedger(ctx, state, nil)
		}
		return r.syncTrafficPolicies(ctx, state)
	}
	if state.RecoveryRequired || state.Sync.Status == trafficStatusStateCorrupt {
		r.observeTrafficSnapshotLocked(state, items, true)
		r.convertLegacyPendingToRangesLocked(state)
		if err := r.saveTrafficState(*state); err != nil {
			return err
		}
		if err := r.reportTrafficLedger(ctx, state, items); err != nil {
			return err
		}
		if !state.RecoveryRequired {
			r.observeTrafficSnapshotLocked(state, items, false)
			r.convertLegacyPendingToRangesLocked(state)
			if err := r.saveTrafficState(*state); err != nil {
				return err
			}
			if len(state.PendingReports) > 0 {
				return r.reportTrafficLedger(ctx, state, items)
			}
		}
		return nil
	}
	changed := r.observeTrafficSnapshotLocked(state, items, false)
	converted := r.convertLegacyPendingToRangesLocked(state)
	if changed || converted || pruned {
		if err := r.saveTrafficState(*state); err != nil {
			return err
		}
	}
	return r.reportTrafficLedger(ctx, state, items)
}

func (r *Runner) snapshotTrafficItems(ctx context.Context) ([]trafficSnapshotItem, error) {
	items, coreErr := r.coreTrafficSnapshot(ctx)
	for i := range items {
		if items[i].Source == "" {
			items[i].Source = trafficSourceCore
		}
	}
	sshItems := r.sshInboundTrafficSnapshot()
	items = append(items, sshItems...)
	if coreErr != nil && len(sshItems) == 0 {
		return items, coreErr
	}
	return items, nil
}

func (r *Runner) persistTrafficCheckpointBeforeRuntimeTransition(ctx context.Context) error {
	if strings.TrimSpace(r.Config().StateDir) == "" {
		return nil
	}
	r.trafficMu.Lock()
	defer r.trafficMu.Unlock()
	state := r.trafficStateLocked()
	items, err := r.snapshotTrafficItems(ctx)
	if err == nil {
		r.observeTrafficSnapshotLocked(state, items, false)
	}
	return r.saveTrafficState(*state)
}

func (r *Runner) observeTrafficSnapshotLocked(state *trafficLocalState, items []trafficSnapshotItem, recovering bool) bool {
	if state.Streams == nil {
		state.Streams = map[string]*trafficStreamState{}
	}
	if state.PendingReports == nil {
		state.PendingReports = map[string]*trafficPendingRange{}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	changed := false
	for _, item := range items {
		if item.Key == "" || item.UserID <= 0 {
			continue
		}
		source := strings.TrimSpace(item.Source)
		if source == "" {
			source = trafficSourceCore
		}
		if item.CounterEpoch == "" {
			continue
		}
		streamID := trafficStreamID(source, item.Key)
		stream := state.Streams[streamID]
		if stream == nil {
			stream = &trafficStreamState{Source: source, SnapshotKey: item.Key, UserID: item.UserID, Status: trafficStatusRecovering}
			state.Streams[streamID] = stream
			changed = true
		}
		stream.Source = source
		stream.SnapshotKey = item.Key
		stream.UserID = item.UserID
		stream.InboundID = item.InboundID
		stream.PathID = item.PathID
		stream.LastObservedAt = now
		period := strings.TrimSpace(item.PeriodKey)
		epochChanged := stream.CounterEpoch != "" && stream.CounterEpoch != item.CounterEpoch
		if epochChanged {
			stream.AcceptedUpload = 0
			stream.AcceptedDownload = 0
			if stream.Status == trafficStatusCounterRegression {
				stream.Status = trafficStatusHealthy
				stream.LastError = ""
			}
		}
		if stream.CounterEpoch == item.CounterEpoch && stream.PeriodKey == period && (item.Upload < stream.ObservedUpload || item.Download < stream.ObservedDownload) {
			stream.Status = trafficStatusCounterRegression
			stream.LastError = "counter regression in the same epoch"
			stream.ObservedUpload = item.Upload
			stream.ObservedDownload = item.Download
			changed = true
			continue
		}
		stream.CounterEpoch = item.CounterEpoch
		stream.PeriodKey = period
		stream.ObservedUpload = item.Upload
		stream.ObservedDownload = item.Download
		if recovering || state.RecoveryRequired {
			if stream.Status == "" || stream.Status == trafficStatusHealthy {
				stream.Status = trafficStatusRecovering
			}
			changed = true
			continue
		}
		if stream.Status == trafficStatusCounterRegression || stream.Status == trafficStatusCheckpointGap || stream.Status == trafficStatusCheckpointOverlap || stream.Status == trafficStatusEpochConflict {
			changed = true
			continue
		}
		if item.Upload < stream.AcceptedUpload || item.Download < stream.AcceptedDownload {
			stream.Status = trafficStatusCounterRegression
			stream.LastError = "observed counters are below the accepted checkpoint"
			changed = true
			continue
		}
		if item.Upload == stream.AcceptedUpload && item.Download == stream.AcceptedDownload {
			if stream.Status != trafficStatusHealthy {
				stream.Status = trafficStatusHealthy
				changed = true
			}
			continue
		}
		pendingExists := false
		for _, pending := range state.PendingReports {
			if pending != nil && pending.StreamID == streamID {
				pendingExists = true
				break
			}
		}
		if !pendingExists {
			for _, pending := range state.Pending {
				if pending.SnapshotKey == item.Key {
					pendingExists = true
					break
				}
			}
		}
		if pendingExists {
			continue
		}
		if item.InboundID <= 0 || item.UserID <= 0 {
			// A counter without inbound identity can never be accounted: the
			// Controller rejects a report that names no inbound. Queuing it used
			// to wedge the whole batch on every retry, because a request-fatal
			// rejection never carries a per-report acknowledgement that would let
			// the pending entry drain. Keep the stream observable but never
			// queue a report for it.
			stream.Status = trafficStatusHealthy
			continue
		}
		report := &trafficPendingRange{
			Source: source, StreamID: streamID, CounterEpoch: item.CounterEpoch, PeriodKey: period,
			UserID: item.UserID, FromUpload: stream.AcceptedUpload, ToUpload: item.Upload,
			FromDownload: stream.AcceptedDownload, ToDownload: item.Download,
			StartedAt: now, EndedAt: now, SnapshotKey: item.Key,
		}
		if item.InboundID > 0 {
			inboundID := item.InboundID
			report.InboundID = &inboundID
		}
		if item.PathID > 0 {
			pathID := item.PathID
			report.PathID = &pathID
		}
		report.ReportID = trafficRangeReportID(r.Config().AgentID, report)
		state.PendingReports[report.ReportID] = report
		stream.Status = trafficStatusHealthy
		changed = true
	}
	_ = recovering
	return changed
}

// trafficStreamRetention is how long a stream stays in the local state after
// its last observation. It only applies to fully acknowledged streams, so a
// pruned entry never drops unreported bytes.
const trafficStreamRetention = 14 * 24 * time.Hour

// pruneTrafficStreamsLocked drops stream state the Agent can no longer use.
//
// Two kinds leave. A stream whose identity is incomplete can never be sent, so
// keeping it only re-sends an observation the Controller must skip. A stream
// that has not been observed for trafficStreamRetention belongs to an inbound
// or user that is gone. Neither is dropped while a pending report still
// references it, and the stale rule additionally requires every observed byte
// to be acknowledged, so pruning cannot lose accounting.
func pruneTrafficStreamsLocked(state *trafficLocalState, now time.Time) bool {
	if state == nil || len(state.Streams) == 0 {
		return false
	}
	referenced := make(map[string]bool, len(state.PendingReports))
	for _, report := range state.PendingReports {
		if report != nil {
			referenced[report.StreamID] = true
		}
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	changed := false
	for streamID, stream := range state.Streams {
		if stream == nil {
			delete(state.Streams, streamID)
			changed = true
			continue
		}
		if referenced[streamID] {
			continue
		}
		if strings.TrimSpace(stream.SnapshotKey) == "" || strings.TrimSpace(stream.CounterEpoch) == "" ||
			strings.TrimSpace(stream.PeriodKey) == "" || stream.UserID <= 0 {
			delete(state.Streams, streamID)
			changed = true
			continue
		}
		if strings.TrimSpace(stream.LastObservedAt) == "" {
			// State written before this field existed, or a stub created from
			// a Controller checkpoint. Date it now rather than treating an
			// unknown age as expired.
			stream.LastObservedAt = stamp
			changed = true
			continue
		}
		observedAt, err := time.Parse(time.RFC3339Nano, stream.LastObservedAt)
		if err != nil {
			stream.LastObservedAt = stamp
			changed = true
			continue
		}
		if now.Sub(observedAt) < trafficStreamRetention {
			continue
		}
		if stream.ObservedUpload != stream.AcceptedUpload || stream.ObservedDownload != stream.AcceptedDownload {
			continue
		}
		delete(state.Streams, streamID)
		changed = true
	}
	return changed
}

func trafficDelta(current, previous trafficSnapshotItem) (int64, int64) {
	if previous.PeriodKey != "" && current.PeriodKey != "" && previous.PeriodKey != current.PeriodKey {
		return current.Upload, current.Download
	}
	upload := current.Upload - previous.Upload
	download := current.Download - previous.Download
	if upload < 0 || download < 0 {
		return current.Upload, current.Download
	}
	return upload, download
}

func (r *Runner) convertLegacyPendingToRangesLocked(state *trafficLocalState) bool {
	if state == nil || len(state.Pending) == 0 {
		return false
	}
	if state.Streams == nil {
		state.Streams = map[string]*trafficStreamState{}
	}
	if state.PendingReports == nil {
		state.PendingReports = map[string]*trafficPendingRange{}
	}
	changed := false
	remaining := state.Pending[:0]
	for _, pending := range state.Pending {
		source := trafficSourceCore
		if last, ok := state.Last[pending.SnapshotKey]; ok && strings.TrimSpace(last.Source) != "" {
			source = last.Source
		}
		streamID := trafficStreamID(source, pending.SnapshotKey)
		stream := state.Streams[streamID]
		if stream == nil {
			stream = &trafficStreamState{Source: source, SnapshotKey: pending.SnapshotKey, UserID: pending.UserID, Status: trafficStatusHealthy}
			state.Streams[streamID] = stream
			changed = true
		}
		if pending.InboundID != nil {
			stream.InboundID = *pending.InboundID
		}
		if pending.PathID != nil {
			stream.PathID = *pending.PathID
		}
		fromUpload := pending.CumulativeUpload - pending.Upload
		fromDownload := pending.CumulativeDownload - pending.Download
		if fromUpload < 0 {
			fromUpload = 0
		}
		if fromDownload < 0 {
			fromDownload = 0
		}
		if stream.AcceptedUpload == 0 && stream.AcceptedDownload == 0 {
			stream.AcceptedUpload = fromUpload
			stream.AcceptedDownload = fromDownload
		}
		stream.ObservedUpload = pending.CumulativeUpload
		stream.ObservedDownload = pending.CumulativeDownload
		if stream.PeriodKey == "" {
			stream.PeriodKey = pending.PeriodKey
		}
		epoch := stream.CounterEpoch
		if epoch == "" {
			if last, ok := state.Last[pending.SnapshotKey]; ok {
				epoch = last.CounterEpoch
			}
		}
		if epoch == "" {
			remaining = append(remaining, pending)
			continue
		}
		if pending.InboundID == nil || *pending.InboundID <= 0 {
			// Same rule as new reports: a report without inbound identity can
			// never be accounted, so converting it would only recreate the
			// wedge the load-time cleanup drops.
			continue
		}
		stream.CounterEpoch = epoch
		report := &trafficPendingRange{
			ReportID: pending.ReportID, Source: source, StreamID: streamID, CounterEpoch: epoch, PeriodKey: pending.PeriodKey,
			UserID: pending.UserID, InboundID: pending.InboundID, PathID: pending.PathID,
			FromUpload: fromUpload, ToUpload: pending.CumulativeUpload, FromDownload: fromDownload, ToDownload: pending.CumulativeDownload,
			StartedAt: pending.StartedAt, EndedAt: pending.EndedAt, SnapshotKey: pending.SnapshotKey,
		}
		if strings.TrimSpace(report.ReportID) == "" {
			report.ReportID = trafficRangeReportID(r.Config().AgentID, report)
		}
		state.PendingReports[report.ReportID] = report
		changed = true
	}
	state.Pending = remaining
	if len(state.Pending) == 0 {
		r.finishLegacyTrafficBridgeLocked(state)
		changed = true
	}
	return changed
}

func (r *Runner) reportTrafficLedger(ctx context.Context, state *trafficLocalState, items []trafficSnapshotItem) (resultErr error) {
	stage := "controller_request"
	var resp trafficReportResponse
	defer func() {
		if state == nil {
			return
		}
		r.noteSyncOutcome("traffic_limits", stage, resp.PolicyRevision, len(resp.Policies), resultErr)
		if resultErr != nil && ctx.Err() == nil {
			state.Sync.Status, state.Sync.LastError = trafficStatusStale, stage+": "+safeSyncError(resultErr)
			if err := r.saveTrafficState(*state); err != nil {
				r.noteSyncOutcome("traffic_checkpoint", "persist_failure", state.PolicyRevision, 0, err)
			}
		}
	}()
	if state == nil {
		return nil
	}
	req := map[string]any{
		"agent_instance_id": state.AgentInstanceID,
		"streams":           trafficStreamWireBatch(state, items),
		"reports":           trafficLedgerReportBatch(state.PendingReports),
	}
	if err := r.postControllerJSON(ctx, "/api/v1/agent/traffic-reports", req, &resp, true); err != nil {
		return err
	}
	stage = "authorization_apply"
	if err := r.applyAuthorizationResponse(ctx, resp.AuthorizationEnvelope, resp.Authorization); err != nil {
		return err
	}
	stage = "checkpoint_persist"
	applyTrafficLedgerResponse(state, resp)
	if err := r.saveTrafficState(*state); err != nil {
		return err
	}
	policies := applyStaleLeasePolicies(resp.Policies, state)
	typed := trafficPoliciesFromWire(policies)
	revision := resp.PolicyRevision
	if revision == 0 {
		revision = trafficPolicyRevisionFromPolicies(typed)
	}
	stage = "revision_check"
	if revision > 0 {
		skipped, err := checkTrafficPolicyRevision(state.PolicyRevision, state.Policies, revision, typed)
		if err != nil {
			return err
		}
		if skipped {
			return nil
		}
	}
	stage = "runtime_apply"
	if err := r.pushTrafficPolicies(ctx, policies, state.Acknowledged); err != nil {
		return err
	}
	stage = "policy_persist"
	state.PolicyRevision = revision
	state.Policies = typed
	return r.saveTrafficState(*state)
}

func (r *Runner) syncTrafficPolicies(ctx context.Context, state *trafficLocalState) error {
	return r.reportTrafficLedger(ctx, state, nil)
}

func (r *Runner) sshInboundTrafficSnapshot() []trafficSnapshotItem {
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	return manager.snapshot()
}

func (r *Runner) pushTrafficPolicies(ctx context.Context, policies map[string]interface{}, acknowledged map[string]trafficCounterCheckpoint) error {
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	coreUsers, err := r.currentCoreTrafficPolicyUsers()
	if err != nil {
		if err := r.pushCoreTrafficPolicy(ctx, policies, acknowledged); err != nil {
			return err
		}
		manager.updatePolicies(policies, acknowledged)
		return nil
	}
	sshUsers := manager.trafficPolicyUsers()
	corePolicies, sshPolicies := partitionRuntimePolicyLeases(policies, coreUsers, sshUsers)
	if err := r.pushCoreTrafficPolicy(ctx, corePolicies, acknowledged); err != nil {
		return err
	}
	manager.updatePolicies(sshPolicies, acknowledged)
	return nil
}

func (r *Runner) reconcileSharedCoreAndSSHTrafficPolicies(ctx context.Context, config []byte) error {
	policies, err := embeddedCoreTrafficPolicies(config)
	if err != nil {
		return err
	}
	r.mu.Lock()
	manager := r.sshInboundManager
	r.mu.Unlock()
	sshUsers := manager.trafficPolicyUsers()
	for _, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		var policy model.TrafficRuntimePolicy
		if err := json.Unmarshal(encoded, &policy); err != nil {
			return err
		}
		if sshUsers[policy.UserID] {
			return r.pushTrafficPolicies(ctx, policies, r.trafficAcknowledgements())
		}
	}
	return nil
}

func (r *Runner) currentCoreTrafficPolicyUsers() (map[int64]bool, error) {
	policies, err := r.currentCoreTrafficPolicies()
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, policy := range policies {
		if policy.UserID > 0 {
			out[policy.UserID] = true
		}
	}
	return out, nil
}

func (r *Runner) currentCoreTrafficPolicies() (map[string]model.TrafficRuntimePolicy, error) {
	b, err := r.stateRead(singBoxConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]model.TrafficRuntimePolicy{}, nil
	}
	if err != nil {
		return nil, err
	}
	policies, err := embeddedCoreTrafficPolicies(b)
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.TrafficRuntimePolicy, len(policies))
	for key, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		var policy model.TrafficRuntimePolicy
		if err := json.Unmarshal(encoded, &policy); err != nil {
			return nil, err
		}
		if policy.UserID > 0 {
			out[key] = policy
		}
	}
	return out, nil
}

func partitionRuntimePolicyLeases(policies map[string]interface{}, coreUsers, sshUsers map[int64]bool) (map[string]interface{}, map[string]interface{}) {
	corePolicies := map[string]interface{}{}
	sshPolicies := map[string]interface{}{}
	for key, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			corePolicies[key] = raw
			sshPolicies[key] = raw
			continue
		}
		var policy model.TrafficRuntimePolicy
		if json.Unmarshal(encoded, &policy) != nil || policy.UserID <= 0 {
			corePolicies[key] = raw
			sshPolicies[key] = raw
			continue
		}
		hasCore := coreUsers[policy.UserID]
		hasSSH := sshUsers[policy.UserID]
		if !hasCore && !hasSSH {
			hasCore, hasSSH = true, true
		}
		corePolicy, sshPolicy := policy, policy
		if hasCore && hasSSH && policy.LeaseEnforced {
			corePolicy.LeaseBytes = (policy.LeaseBytes + 1) / 2
			sshPolicy.LeaseBytes = policy.LeaseBytes / 2
			corePolicy.ResetLeaseBytes = (policy.ResetLeaseBytes + 1) / 2
			sshPolicy.ResetLeaseBytes = policy.ResetLeaseBytes / 2
		}
		if hasCore {
			corePolicies[key] = corePolicy
		}
		if hasSSH {
			sshPolicies[key] = sshPolicy
		}
	}
	return corePolicies, sshPolicies
}

func (r *Runner) trafficAcknowledgements() map[string]trafficCounterCheckpoint {
	r.trafficMu.Lock()
	defer r.trafficMu.Unlock()
	state := r.trafficStateLocked()
	out := make(map[string]trafficCounterCheckpoint, len(state.Acknowledged))
	for key, checkpoint := range state.Acknowledged {
		out[key] = checkpoint
	}
	return out
}

func trafficReportBatch(pending []trafficPendingReport) []trafficReportItem {
	limit := len(pending)
	if limit > trafficReportBatchSize {
		limit = trafficReportBatchSize
	}
	out := make([]trafficReportItem, 0, limit)
	for _, report := range pending[:limit] {
		out = append(out, trafficReportItem{ReportID: report.ReportID, UserID: report.UserID, InboundID: report.InboundID, PathID: report.PathID, PeriodKey: report.PeriodKey, Upload: report.Upload, Download: report.Download, StartedAt: report.StartedAt, EndedAt: report.EndedAt})
	}
	return out
}

func trafficLedgerReportBatch(pending map[string]*trafficPendingRange) []trafficLedgerReportItem {
	out := make([]trafficLedgerReportItem, 0, len(pending))
	for _, report := range pending {
		if report == nil {
			continue
		}
		// Final defense: the Controller requires an inbound on every report.
		// Entries without one are dropped by the load-time cleanup, so this
		// only guards a state file written by a future regression.
		if report.InboundID == nil || *report.InboundID <= 0 {
			continue
		}
		out = append(out, trafficLedgerReportItem{
			ReportID: report.ReportID, Source: report.Source, StreamID: report.StreamID, CounterEpoch: report.CounterEpoch,
			PeriodKey: report.PeriodKey, UserID: report.UserID, InboundID: report.InboundID, PathID: report.PathID,
			FromUpload: report.FromUpload, ToUpload: report.ToUpload, FromDownload: report.FromDownload, ToDownload: report.ToDownload,
			StartedAt: report.StartedAt, EndedAt: report.EndedAt,
		})
		if len(out) >= trafficReportBatchSize {
			break
		}
	}
	return out
}

func trafficStreamWireBatch(state *trafficLocalState, items []trafficSnapshotItem) []trafficStreamWire {
	out := make([]trafficStreamWire, 0)
	seen := map[string]bool{}
	add := func(source, key, epoch, period string, userID, inboundID, pathID, upload, download int64, status string) {
		if source == "" {
			source = trafficSourceCore
		}
		// The Controller stores source, stream, epoch, period and user as one
		// identity, so an observation missing any part of it can never be
		// recorded. A counter that has produced bytes before its runtime
		// policy arrived has no period yet; sending it anyway made the
		// Controller fail the entire batch, including the healthy reports and
		// the policy response that would have supplied the missing period.
		if key == "" || epoch == "" || strings.TrimSpace(period) == "" || userID <= 0 {
			return
		}
		streamID := trafficStreamID(source, key)
		if seen[streamID] {
			return
		}
		seen[streamID] = true
		out = append(out, trafficStreamWire{
			Source: source, StreamID: streamID, CounterEpoch: epoch, PeriodKey: period, UserID: userID,
			InboundID: inboundID, PathID: pathID, CurrentUpload: upload, CurrentDownload: download, Status: status,
		})
	}
	for _, item := range items {
		add(item.Source, item.Key, item.CounterEpoch, item.PeriodKey, item.UserID, item.InboundID, item.PathID, item.Upload, item.Download, "")
	}
	if state != nil {
		for _, stream := range state.Streams {
			if stream == nil {
				continue
			}
			add(stream.Source, stream.SnapshotKey, stream.CounterEpoch, stream.PeriodKey, stream.UserID, stream.InboundID, stream.PathID, stream.ObservedUpload, stream.ObservedDownload, stream.Status)
		}
	}
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out
}

func acknowledgeAcceptedTrafficReports(state *trafficLocalState, acceptedIDs []string) {
	if state == nil || len(acceptedIDs) == 0 {
		return
	}
	if state.Acknowledged == nil {
		state.Acknowledged = map[string]trafficCounterCheckpoint{}
	}
	accepted := make(map[string]struct{}, len(acceptedIDs))
	for _, id := range acceptedIDs {
		accepted[id] = struct{}{}
	}
	for _, report := range state.Pending {
		if _, ok := accepted[report.ReportID]; !ok || report.SnapshotKey == "" {
			continue
		}
		state.Acknowledged[report.SnapshotKey] = trafficCounterCheckpoint{PeriodKey: report.PeriodKey, Upload: report.CumulativeUpload, Download: report.CumulativeDownload}
	}
	for id, report := range state.PendingReports {
		if _, ok := accepted[id]; !ok || report == nil || report.SnapshotKey == "" {
			continue
		}
		state.Acknowledged[report.SnapshotKey] = trafficCounterCheckpoint{CounterEpoch: report.CounterEpoch, PeriodKey: report.PeriodKey, Upload: report.ToUpload, Download: report.ToDownload}
		if stream := state.Streams[report.StreamID]; stream != nil {
			stream.AcceptedUpload = report.ToUpload
			stream.AcceptedDownload = report.ToDownload
			stream.Status = trafficStatusHealthy
		}
	}
}

func applyTrafficLedgerResponse(state *trafficLocalState, resp trafficReportResponse) {
	if state.Acknowledged == nil {
		state.Acknowledged = map[string]trafficCounterCheckpoint{}
	}
	if state.Streams == nil {
		state.Streams = map[string]*trafficStreamState{}
	}
	for _, checkpoint := range resp.StreamCheckpoints {
		stream := state.Streams[checkpoint.StreamID]
		if stream == nil {
			stream = &trafficStreamState{Source: checkpoint.Source}
			state.Streams[checkpoint.StreamID] = stream
		}
		if checkpoint.CounterEpoch != "" && stream.CounterEpoch != "" && checkpoint.CounterEpoch != stream.CounterEpoch {
			stream.Status = trafficStatusEpochConflict
			stream.LastError = "controller epoch does not match local counters"
			continue
		}
		sameIdentity := checkpoint.CounterEpoch != "" && checkpoint.CounterEpoch == stream.CounterEpoch &&
			checkpoint.PeriodKey != "" && checkpoint.PeriodKey == stream.PeriodKey && stream.SnapshotKey != ""
		counterRegressed := stream.Status == trafficStatusCounterRegression
		if checkpoint.CounterEpoch != "" {
			stream.CounterEpoch = checkpoint.CounterEpoch
		}
		if checkpoint.PeriodKey != "" {
			stream.PeriodKey = checkpoint.PeriodKey
		}
		stream.AcceptedUpload = checkpoint.AcceptedUpload
		stream.AcceptedDownload = checkpoint.AcceptedDownload
		if checkpoint.Status != "" {
			stream.Status = checkpoint.Status
			// A rejected range does not invalidate the Controller's checkpoint.
			// Rebuild from it only when the local counters cover the same identity.
			if sameIdentity && (checkpoint.Status == trafficStatusCheckpointGap || checkpoint.Status == trafficStatusCheckpointOverlap) {
				switch {
				case counterRegressed:
					stream.Status = trafficStatusCounterRegression
				case stream.ObservedUpload < checkpoint.AcceptedUpload || stream.ObservedDownload < checkpoint.AcceptedDownload:
					stream.Status = trafficStatusCounterRegression
					stream.LastError = "observed counters are below the accepted checkpoint"
				default:
					stream.Status = trafficStatusHealthy
					stream.LastError = ""
				}
			}
		} else if stream.Status == trafficStatusRecovering || stream.Status == trafficStatusStateCorrupt {
			stream.Status = trafficStatusHealthy
		}
		if stream.SnapshotKey != "" {
			state.Acknowledged[stream.SnapshotKey] = trafficCounterCheckpoint{CounterEpoch: stream.CounterEpoch, PeriodKey: stream.PeriodKey, Upload: stream.AcceptedUpload, Download: stream.AcceptedDownload}
		}
	}
	for _, accepted := range resp.AcceptedReports {
		report := state.PendingReports[accepted.ReportID]
		switch accepted.Status {
		case "", "accepted", "duplicate", "covered":
			if report != nil {
				if stream := state.Streams[report.StreamID]; stream != nil {
					stream.AcceptedUpload = accepted.AcceptedUpload
					stream.AcceptedDownload = accepted.AcceptedDownload
					if stream.AcceptedUpload == 0 && stream.AcceptedDownload == 0 {
						stream.AcceptedUpload = report.ToUpload
						stream.AcceptedDownload = report.ToDownload
					}
					stream.Status = trafficStatusHealthy
					stream.LastError = ""
					if report.SnapshotKey != "" {
						state.Acknowledged[report.SnapshotKey] = trafficCounterCheckpoint{CounterEpoch: report.CounterEpoch, PeriodKey: report.PeriodKey, Upload: stream.AcceptedUpload, Download: stream.AcceptedDownload}
					}
				}
				delete(state.PendingReports, accepted.ReportID)
			}
		case trafficStatusCheckpointGap, trafficStatusCheckpointOverlap, trafficStatusEpochConflict, "rejected":
			terminal := accepted.Status == "rejected" && terminalTrafficRejectionReason(accepted.Reason)
			if report != nil {
				if stream := state.Streams[report.StreamID]; stream != nil && !terminal {
					stream.Status = accepted.Status
					stream.LastError = accepted.Status
					if accepted.Status != "rejected" {
						stream.AcceptedUpload = accepted.AcceptedUpload
						stream.AcceptedDownload = accepted.AcceptedDownload
					}
				}
				delete(state.PendingReports, accepted.ReportID)
			}
			if terminal {
				// The user, binding, inbound, or path this report accounts
				// against is gone. Dropping it is the complete resolution;
				// local counters are still consistent, so no recovery is due.
				continue
			}
			state.RecoveryRequired = true
		}
	}
	if len(resp.StreamCheckpoints) > 0 {
		state.RecoveryRequired = false
		if state.Sync.Status == trafficStatusStateCorrupt {
			state.Sync.Status = trafficStatusRecovering
		}
	}
	if !state.RecoveryRequired && state.Sync.Status != trafficStatusCounterRegression && state.Sync.Status != trafficStatusStateCorrupt {
		state.Sync.Status = trafficStatusHealthy
	}
	state.Sync.LastSuccess = time.Now().UTC().Format(time.RFC3339Nano)
	state.Sync.LastError = ""
	for _, stream := range state.Streams {
		if stream == nil {
			continue
		}
		switch stream.Status {
		case trafficStatusCounterRegression, trafficStatusCheckpointGap, trafficStatusCheckpointOverlap, trafficStatusEpochConflict, trafficStatusStateCorrupt:
			state.Sync.Status = stream.Status
			state.Sync.LastError = stream.LastError
			state.RecoveryRequired = true
		}
	}
}

// terminalTrafficRejectionReason lists the Controller reasons that mean a
// report will never be accounted. They are business outcomes, not counter
// problems, so they must not put the local traffic state into recovery.
//
// binding_removed is the live reason for a user that is no longer bound to the
// inbound. Retrying one is what turned a single stale report into a batch that
// could never drain, stalling lease renewal for every user on the server.
func terminalTrafficRejectionReason(reason string) bool {
	switch strings.TrimSpace(reason) {
	case "user_deleted", "user_inactive", "binding_removed", "inbound_deleted", "inbound_disabled", "path_removed", "invalid_report",
		"unattributable_traffic", "legal_tail",
		// Tolerated for a Controller older than the split that made
		// binding_removed a per-report reason. That Controller answered the
		// same situation with these, and a rolling upgrade can put a newer
		// Agent in front of it. A current Controller never sends either: its
		// only remaining request-level refusal is cross-tenant ownership, which
		// is an HTTP 403 and never a per-report reason.
		"unauthorized", "forbidden":
		return true
	default:
		return false
	}
}

func removeAcceptedTrafficReports(pending []trafficPendingReport, acceptedIDs []string) []trafficPendingReport {
	if len(pending) == 0 || len(acceptedIDs) == 0 {
		return pending
	}
	accepted := make(map[string]struct{}, len(acceptedIDs))
	for _, id := range acceptedIDs {
		accepted[id] = struct{}{}
	}
	remaining := pending[:0]
	for _, report := range pending {
		if _, ok := accepted[report.ReportID]; !ok {
			remaining = append(remaining, report)
		}
	}
	return remaining
}

func (r *Runner) finishLegacyTrafficBridgeLocked(state *trafficLocalState) {
	if state == nil || len(state.Pending) > 0 {
		return
	}
	state.SchemaVersion = trafficStateSchemaV2
	if state.Streams == nil {
		state.Streams = map[string]*trafficStreamState{}
	}
	for key, last := range state.Last {
		source := last.Source
		if source == "" {
			source = trafficSourceCore
		}
		if last.CounterEpoch == "" {
			continue
		}
		streamID := trafficStreamID(source, key)
		stream := state.Streams[streamID]
		if stream == nil {
			stream = &trafficStreamState{}
			state.Streams[streamID] = stream
		}
		stream.Source = source
		stream.SnapshotKey = key
		stream.CounterEpoch = last.CounterEpoch
		stream.PeriodKey = last.PeriodKey
		stream.UserID = last.UserID
		stream.InboundID = last.InboundID
		stream.PathID = last.PathID
		stream.ObservedUpload = last.Upload
		stream.ObservedDownload = last.Download
		if ack, ok := state.Acknowledged[key]; ok {
			stream.AcceptedUpload = ack.Upload
			stream.AcceptedDownload = ack.Download
		} else {
			stream.AcceptedUpload = last.Upload
			stream.AcceptedDownload = last.Download
		}
		stream.Status = trafficStatusHealthy
	}
}

func (r *Runner) coreTrafficSnapshot(ctx context.Context) ([]trafficSnapshotItem, error) {
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(r.coreAPISocketPath())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/traffic/snapshot", nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("core traffic snapshot status %d", res.StatusCode)
	}
	var payload struct {
		Items []trafficSnapshotItem `json:"items"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Items, nil
}

func (r *Runner) coreResourceSnapshot(ctx context.Context) map[string]any {
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(r.coreAPISocketPath())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://oboard-sb/resources", nil)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	res, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return map[string]any{"ok": false, "status": res.StatusCode}
	}
	var payload map[string]any
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	payload["ok"] = true
	return payload
}

func (r *Runner) pushCoreTrafficPolicy(ctx context.Context, policies map[string]interface{}, acknowledged map[string]trafficCounterCheckpoint) error {
	converted := map[string]interface{}{}
	for _, raw := range policies {
		b, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		var p struct {
			UserID int64 `json:"user_id"`
		}
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		if p.UserID <= 0 {
			continue
		}
		converted[fmt.Sprintf("user:%d", p.UserID)] = raw
	}
	if len(converted) == 0 && len(acknowledged) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"policies": converted, "acknowledged": acknowledged})
	if err != nil {
		return err
	}
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(r.coreAPISocketPath())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/traffic/policy", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("core traffic policy status %d", res.StatusCode)
	}
	return nil
}

func unixHTTPClient(socket string) *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}}
}

func (r *Runner) trafficStateLocked() *trafficLocalState {
	if !r.trafficStateLoaded {
		r.trafficState = r.loadTrafficState()
		r.trafficStateLoaded = true
	}
	if r.trafficState.Last == nil {
		r.trafficState.Last = map[string]trafficSnapshotItem{}
	}
	if r.trafficState.Acknowledged == nil {
		r.trafficState.Acknowledged = map[string]trafficCounterCheckpoint{}
	}
	if r.trafficState.Streams == nil {
		r.trafficState.Streams = map[string]*trafficStreamState{}
	}
	if r.trafficState.PendingReports == nil {
		r.trafficState.PendingReports = map[string]*trafficPendingRange{}
	}
	if r.trafficState.AgentInstanceID == "" {
		r.trafficState.AgentInstanceID = newTrafficCounterEpoch()
	}
	return &r.trafficState
}

func (r *Runner) trafficStatePath() string {
	return r.statePath("traffic-state.json")
}

func (r *Runner) trafficStateBackupPath() string {
	return r.trafficStatePath() + ".bak"
}

func (r *Runner) loadTrafficState() trafficLocalState {
	state, err := r.readTrafficStateFile(r.trafficStatePath())
	if err == nil {
		return migrateLoadedTrafficState(state, false)
	}
	if !errors.Is(err, os.ErrNotExist) {
		if backup, backupErr := r.readTrafficStateFile(r.trafficStateBackupPath()); backupErr == nil {
			migrated := migrateLoadedTrafficState(backup, false)
			migrated.Sync.Status = trafficStatusRecovering
			migrated.Sync.LastError = "primary traffic-state.json was unreadable"
			migrated.RecoveryRequired = true
			return migrated
		}
		return corruptTrafficState("traffic-state.json is corrupt")
	}
	if backup, backupErr := r.readTrafficStateFile(r.trafficStateBackupPath()); backupErr == nil {
		migrated := migrateLoadedTrafficState(backup, false)
		migrated.RecoveryRequired = true
		migrated.Sync.Status = trafficStatusRecovering
		return migrated
	}
	empty := migrateLoadedTrafficState(trafficLocalState{}, true)
	empty.RecoveryRequired = true
	empty.Sync.Status = trafficStatusRecovering
	return empty
}

func (r *Runner) readTrafficStateFile(path string) (trafficLocalState, error) {
	b, err := r.stateReadPath(path)
	if err != nil {
		return trafficLocalState{}, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return trafficLocalState{}, errors.New("traffic state is empty")
	}
	var state trafficLocalState
	if err := json.Unmarshal(b, &state); err != nil {
		return trafficLocalState{}, err
	}
	if err := validateTrafficState(state); err != nil {
		return trafficLocalState{}, err
	}
	return state, nil
}

func migrateLoadedTrafficState(state trafficLocalState, missing bool) trafficLocalState {
	if state.Last == nil {
		state.Last = map[string]trafficSnapshotItem{}
	}
	if state.Acknowledged == nil {
		state.Acknowledged = map[string]trafficCounterCheckpoint{}
	}
	if state.Streams == nil {
		state.Streams = map[string]*trafficStreamState{}
	}
	if state.PendingReports == nil {
		state.PendingReports = map[string]*trafficPendingRange{}
	}
	if state.AgentInstanceID == "" {
		state.AgentInstanceID = newTrafficCounterEpoch()
	}
	// A pending report that names no inbound can never be accepted by any
	// Controller: the ledger requires the inbound identity on every report.
	// One such entry used to wedge the whole batch on every retry, because a
	// request-fatal rejection never carries the per-report acknowledgement
	// that would let it drain. Drop them at load so a server poisoned by an
	// older configuration self-heals instead of resending the same batch
	// forever; the local counters stay consistent, so no recovery is due.
	for id, report := range state.PendingReports {
		if report == nil || report.InboundID == nil || *report.InboundID <= 0 {
			delete(state.PendingReports, id)
		}
	}
	if state.SchemaVersion >= trafficStateSchemaV2 {
		return state
	}
	if missing && len(state.Last) == 0 && len(state.Pending) == 0 && len(state.PendingReports) == 0 {
		state.SchemaVersion = trafficStateSchemaV2
		return state
	}
	return state
}

func corruptTrafficState(reason string) trafficLocalState {
	return trafficLocalState{
		SchemaVersion:    trafficStateSchemaV2,
		AgentInstanceID:  newTrafficCounterEpoch(),
		Last:             map[string]trafficSnapshotItem{},
		Acknowledged:     map[string]trafficCounterCheckpoint{},
		Streams:          map[string]*trafficStreamState{},
		PendingReports:   map[string]*trafficPendingRange{},
		RecoveryRequired: true,
		Sync:             trafficSyncState{Status: trafficStatusStateCorrupt, LastError: reason},
	}
}

func validateTrafficState(state trafficLocalState) error {
	if state.SchemaVersion < 0 || state.SchemaVersion > trafficStateSchemaV2 {
		return fmt.Errorf("unsupported traffic state schema_version %d", state.SchemaVersion)
	}
	for id, report := range state.PendingReports {
		if report == nil || strings.TrimSpace(report.ReportID) == "" || report.ReportID != id {
			return errors.New("pending traffic report identity is invalid")
		}
		if report.ToUpload < report.FromUpload || report.ToDownload < report.FromDownload {
			return errors.New("pending traffic report range is invalid")
		}
	}
	return nil
}

func (r *Runner) saveTrafficState(state trafficLocalState) error {
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	if state.SchemaVersion == 0 && len(state.Pending) == 0 {
		state.SchemaVersion = trafficStateSchemaV2
	}
	if err := validateTrafficState(state); err != nil {
		return err
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	path := r.trafficStatePath()
	if current, err := r.stateReadPath(path); err == nil && len(current) > 0 {
		if err := r.stateWritePathSynced(r.trafficStateBackupPath(), current, 0o600); err != nil {
			return err
		}
	}
	return r.stateWritePathSynced(path, b, 0o600)
}

func atomicWriteFileWithSync(path string, data []byte, perm os.FileMode) error {
	return securefile.Write(path, data, perm, true)
}

func sanitizeTrafficKey(key string) string {
	key = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, key)
	return strings.Trim(key, "-")
}

func newTrafficCounterEpoch() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "ce_invalid"
	}
	return "ce_" + base64.RawURLEncoding.EncodeToString(raw[:])
}

func trafficStreamID(source, snapshotKey string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + snapshotKey))
	return "ts_" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func trafficRangeReportID(agentID string, report *trafficPendingRange) string {
	if report == nil {
		return ""
	}
	payload := fmt.Sprintf("range\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d", agentID, report.StreamID, report.CounterEpoch, report.PeriodKey, report.FromUpload, report.ToUpload, report.FromDownload, report.ToDownload)
	sum := sha256.Sum256([]byte(payload))
	return "tr_" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func applyStaleLeasePolicies(policies map[string]interface{}, state *trafficLocalState) map[string]interface{} {
	if state == nil || len(policies) == 0 || state.Sync.LastSuccess == "" {
		return policies
	}
	lastSuccess, err := time.Parse(time.RFC3339Nano, state.Sync.LastSuccess)
	if err != nil || time.Since(lastSuccess) < trafficLeaseStaleAfter {
		return policies
	}
	out := map[string]interface{}{}
	for key, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			out[key] = raw
			continue
		}
		var policy model.TrafficRuntimePolicy
		if json.Unmarshal(encoded, &policy) != nil || !policy.LeaseEnforced {
			out[key] = raw
			continue
		}
		policy.LeaseBytes = 0
		out[key] = policy
	}
	if state.Sync.Status == "" || state.Sync.Status == trafficStatusHealthy {
		state.Sync.Status = trafficStatusStale
	}
	return out
}

func (r *Runner) applyTrafficPolicyTask(payload model.ApplyTrafficPolicyTaskPayload) (result map[string]any, resultErr error) {
	stage := "authorization_apply"
	defer func() {
		r.noteSyncOutcome("traffic_policy_task", stage, payload.PolicyRevision, len(payload.Policies), resultErr)
	}()
	if _, err := r.applyAuthorization(context.Background(), payload.Authorization); err != nil {
		return nil, err
	}
	if payload.Authorization != nil && payload.PolicyRevision == 0 && len(payload.Policies) == 0 {
		return map[string]any{"message": "authorization applied", "authorization_revision": payload.Authorization.Revision}, nil
	}
	r.trafficMu.Lock()
	defer r.trafficMu.Unlock()
	state := r.trafficStateLocked()
	stage = "revision_check"
	skipped, err := checkTrafficPolicyRevision(state.PolicyRevision, state.Policies, payload.PolicyRevision, payload.Policies)
	if err != nil {
		return map[string]any{"message": "traffic policy rejected"}, err
	}
	result = map[string]any{"message": "traffic policy applied", "policy_revision": payload.PolicyRevision}
	if skipped {
		result["message"] = "traffic policy unchanged"
		result["skipped"] = true
		return result, nil
	}
	stage = "runtime_apply"
	if err := r.pushTrafficPolicies(context.Background(), trafficPoliciesToWire(payload.Policies), state.Acknowledged); err != nil {
		return map[string]any{"message": "traffic policy apply failed"}, err
	}
	state.PolicyRevision = payload.PolicyRevision
	state.Policies = payload.Policies
	stage = "policy_persist"
	if err := r.saveTrafficState(*state); err != nil {
		return map[string]any{"message": "traffic policy persist failed"}, err
	}
	return result, nil
}

func (r *Runner) restoreTrafficRuntimePolicies(ctx context.Context) error {
	r.trafficMu.Lock()
	state := r.trafficStateLocked()
	policies := trafficPoliciesToWire(state.Policies)
	acks := state.Acknowledged
	r.trafficMu.Unlock()
	if len(policies) == 0 {
		return nil
	}
	return r.pushTrafficPolicies(ctx, policies, acks)
}

func checkTrafficPolicyRevision(applied int64, appliedPolicies map[string]model.TrafficRuntimePolicy, incoming int64, incomingPolicies map[string]model.TrafficRuntimePolicy) (bool, error) {
	if incoming <= 0 {
		return false, errors.New("traffic_policy_revision must be positive")
	}
	if incoming < applied {
		return true, nil
	}
	if incoming == applied {
		if trafficPolicyContentID(appliedPolicies) != trafficPolicyContentID(incomingPolicies) {
			return false, fmt.Errorf("traffic_policy_revision %d was already applied with different content", incoming)
		}
		return true, nil
	}
	return false, nil
}

func trafficPolicyContentID(policies map[string]model.TrafficRuntimePolicy) string {
	encoded, err := json.Marshal(policies)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum[:])
}

func trafficPoliciesToWire(policies map[string]model.TrafficRuntimePolicy) map[string]interface{} {
	out := make(map[string]interface{}, len(policies))
	for key, policy := range policies {
		encoded, err := json.Marshal(policy)
		if err != nil {
			continue
		}
		var raw map[string]interface{}
		if json.Unmarshal(encoded, &raw) != nil {
			continue
		}
		out[key] = raw
	}
	return out
}

func trafficPoliciesFromWire(policies map[string]interface{}) map[string]model.TrafficRuntimePolicy {
	out := make(map[string]model.TrafficRuntimePolicy, len(policies))
	for key, raw := range policies {
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		var policy model.TrafficRuntimePolicy
		if json.Unmarshal(encoded, &policy) != nil {
			continue
		}
		out[key] = policy
	}
	return out
}

func trafficPolicyRevisionFromPolicies(policies map[string]model.TrafficRuntimePolicy) int64 {
	var revision int64
	for _, policy := range policies {
		if policy.PolicyRevision > revision {
			revision = policy.PolicyRevision
		}
	}
	return revision
}
