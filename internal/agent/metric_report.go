package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	metricReportStateFile      = "metric-reports.json"
	metricReportSampleInterval = time.Minute
	metricReportRetryInterval  = 10 * time.Second
	metricReportMaxPending     = 2048
	metricReportRetention      = 35 * 24 * time.Hour
)

type metricReportLocalState struct {
	Pending []model.MetricReport `json:"pending"`
}

func (r *Runner) metricReportStatePath() string {
	return r.statePath(metricReportStateFile)
}

func (r *Runner) loadMetricReportStateLocked() {
	if r.metricReportStateLoaded {
		return
	}
	r.metricReportStateLoaded = true
	data, err := r.stateReadPath(r.metricReportStatePath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logging.Errorf("read metric report queue: %v", err)
		}
		return
	}
	var state metricReportLocalState
	if err := json.Unmarshal(data, &state); err != nil {
		logging.Errorf("invalid metric report queue: %v", err)
		return
	}
	r.metricReportState = state
	now := time.Now().UTC()
	if r.clock != nil {
		now = r.clock.Now().UTC()
	}
	r.pruneMetricReportStateLocked(now)
}

func (r *Runner) persistMetricReportStateLocked() error {
	if err := os.MkdirAll(r.stateDir(), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(r.metricReportState)
	if err != nil {
		return err
	}
	return r.stateWritePath(r.metricReportStatePath(), data, 0o600)
}

func (r *Runner) pruneMetricReportStateLocked(now time.Time) int {
	cutoff := now.Add(-metricReportRetention)
	pending := r.metricReportState.Pending[:0]
	for _, report := range r.metricReportState.Pending {
		if report.SampledAt.Before(cutoff) {
			continue
		}
		pending = append(pending, report)
	}
	sort.SliceStable(pending, func(i, j int) bool {
		if pending[i].SampledAt.Equal(pending[j].SampledAt) {
			return pending[i].ReportID < pending[j].ReportID
		}
		return pending[i].SampledAt.Before(pending[j].SampledAt)
	})
	dropped := len(r.metricReportState.Pending) - len(pending)
	if len(pending) > metricReportMaxPending {
		dropped += len(pending) - metricReportMaxPending
		pending = pending[len(pending)-metricReportMaxPending:]
	}
	r.metricReportState.Pending = pending
	return dropped
}

func newMetricReportID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func metricReportFromHealth(reportID string, health model.HealthReport) model.MetricReport {
	return model.MetricReport{
		ReportID:           reportID,
		SampledAt:          health.Timestamp.UTC(),
		CPUUsagePercent:    health.CPUUsagePercent,
		MemoryUsedBytes:    health.MemoryUsedBytes,
		MemoryTotalBytes:   health.MemoryTotalBytes,
		SwapUsedBytes:      health.SwapUsedBytes,
		SwapTotalBytes:     health.SwapTotalBytes,
		DiskUsedBytes:      health.DiskBytes,
		DiskTotalBytes:     health.DiskTotalBytes,
		TCPConnectionCount: health.TCPConnectionCount,
		UDPConnectionCount: health.UDPConnectionCount,
		ProcessCount:       health.ProcessCount,
		NetworkUploadBPS:   health.NetworkUploadBPS,
		NetworkDownloadBPS: health.NetworkDownloadBPS,
	}
}

func (r *Runner) queueMetricReport(report model.MetricReport, now time.Time) (int, error) {
	r.metricReportMu.Lock()
	defer r.metricReportMu.Unlock()
	r.loadMetricReportStateLocked()
	previous := append([]model.MetricReport(nil), r.metricReportState.Pending...)
	r.metricReportState.Pending = append(r.metricReportState.Pending, report)
	dropped := r.pruneMetricReportStateLocked(now)
	if err := r.persistMetricReportStateLocked(); err != nil {
		r.metricReportState.Pending = previous
		return 0, err
	}
	r.notifyMetricReportSender()
	return dropped, nil
}

func (r *Runner) nextPendingMetricReport() (model.MetricReport, bool) {
	r.metricReportMu.Lock()
	defer r.metricReportMu.Unlock()
	r.loadMetricReportStateLocked()
	if len(r.metricReportState.Pending) == 0 {
		return model.MetricReport{}, false
	}
	return r.metricReportState.Pending[0], true
}

func (r *Runner) ackMetricReport(reportID string) error {
	r.metricReportMu.Lock()
	defer r.metricReportMu.Unlock()
	r.loadMetricReportStateLocked()
	if len(r.metricReportState.Pending) == 0 || r.metricReportState.Pending[0].ReportID != reportID {
		return nil
	}
	previous := append([]model.MetricReport(nil), r.metricReportState.Pending...)
	r.metricReportState.Pending = append([]model.MetricReport(nil), r.metricReportState.Pending[1:]...)
	if err := r.persistMetricReportStateLocked(); err != nil {
		r.metricReportState.Pending = previous
		return err
	}
	r.notifyMetricReportSender()
	return nil
}

func (r *Runner) notifyMetricReportSender() {
	if r.metricReportWake == nil {
		return
	}
	select {
	case r.metricReportWake <- struct{}{}:
	default:
	}
}

func (r *Runner) collectMetricReport(now time.Time) error {
	reportID, err := newMetricReportID()
	if err != nil {
		return err
	}
	report := metricReportFromHealth(reportID, r.Probe(false))
	sampledAt := now.UTC()
	if r.clock != nil {
		sampledAt = r.clock.Now().UTC()
	}
	report.SampledAt = sampledAt
	dropped, err := r.queueMetricReport(report, sampledAt)
	if err != nil {
		return err
	}
	if dropped > 0 {
		logging.Warnf("metric report queue pruned: dropped=%d pending_limit=%d", dropped, metricReportMaxPending)
	}
	return nil
}

func (r *Runner) startMetricReportLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(metricReportSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := r.collectMetricReport(now.UTC()); err != nil {
					logging.Errorf("queue metric report: %v", err)
				}
			}
		}
	}()
}
