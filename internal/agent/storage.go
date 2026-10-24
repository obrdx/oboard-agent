package agent

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

type StorageProfile string

const (
	StorageProfileAuto     StorageProfile = "auto"
	StorageProfileTiny     StorageProfile = "tiny"
	StorageProfileSmall    StorageProfile = "small"
	StorageProfileStandard StorageProfile = "standard"
)

type StorageFilesystemStats struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
}

type StorageDiskInfo struct {
	TotalBytes     uint64         `json:"total_bytes"`
	AvailableBytes uint64         `json:"available_bytes"`
	UsagePercent   float64        `json:"usage_percent"`
	StorageProfile StorageProfile `json:"storage_profile"`
	Pressure       string         `json:"pressure"`
}

func validStorageProfile(p string) bool {
	switch StorageProfile(strings.ToLower(strings.TrimSpace(p))) {
	case "", StorageProfileAuto, StorageProfileTiny, StorageProfileSmall, StorageProfileStandard:
		return true
	default:
		return false
	}
}

func filesystemStats(path string) (StorageFilesystemStats, error) {
	check := strings.TrimSpace(path)
	if check == "" {
		check = "/"
	}
	info, err := os.Stat(check)
	if err != nil {
		if !os.IsNotExist(err) {
			return StorageFilesystemStats{}, err
		}
		check = filepath.Dir(check)
	} else if !info.IsDir() {
		check = filepath.Dir(check)
	}
	total, avail, used, err := filesystemUsage(check)
	if err != nil {
		return StorageFilesystemStats{}, err
	}
	var pct float64
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return StorageFilesystemStats{
		TotalBytes:     total,
		AvailableBytes: avail,
		UsedBytes:      used,
		UsagePercent:   pct,
	}, nil
}

func detectStorageProfile(autoPath string, explicit StorageProfile) StorageProfile {
	if explicit != "" && explicit != StorageProfileAuto {
		return explicit
	}
	// Auto detection based on filesystem total and available.
	// Check stateDir, logDir, install filesystem - use most constrained.
	paths := []string{autoPath, "/var/log", "/usr/local/bin"}
	var minTotal uint64 = ^uint64(0)
	var minAvail uint64 = ^uint64(0)
	for _, p := range paths {
		stats, err := filesystemStats(p)
		if err != nil {
			continue
		}
		if stats.TotalBytes > 0 && stats.TotalBytes < minTotal {
			minTotal = stats.TotalBytes
		}
		if stats.AvailableBytes < minAvail {
			minAvail = stats.AvailableBytes
		}
	}
	if minTotal == ^uint64(0) {
		minTotal = 0
	}
	if minAvail == ^uint64(0) {
		minAvail = 0
	}
	// Tiny: total <=1GiB OR available <=256MiB
	if minTotal > 0 && minTotal <= 1<<30 {
		return StorageProfileTiny
	}
	if minAvail <= 256<<20 {
		return StorageProfileTiny
	}
	// Small: total <=4GiB OR available <=1GiB
	if minTotal > 0 && minTotal <= 4<<30 {
		return StorageProfileSmall
	}
	if minAvail <= 1<<30 {
		return StorageProfileSmall
	}
	return StorageProfileStandard
}

func storageProfileFromConfig(cfg Config) StorageProfile {
	raw := StorageProfile(strings.ToLower(strings.TrimSpace(cfg.StorageProfile)))
	if !validStorageProfile(string(raw)) {
		raw = StorageProfileAuto
	}
	if raw == "" {
		raw = StorageProfileAuto
	}
	if raw == StorageProfileAuto {
		return detectStorageProfile(cfg.StateDir, raw)
	}
	return raw
}

func logBudgetForProfile(profile StorageProfile, explicitAgentMax, explicitAgentBackups, explicitCoreMax, explicitCoreBackups *int) (agentMax, agentBackups, coreMax, coreBackups int) {
	// defaults per profile
	var defAgentMax, defAgentBackups, defCoreMax, defCoreBackups int
	switch profile {
	case StorageProfileTiny:
		defAgentMax, defAgentBackups, defCoreMax, defCoreBackups = 1, 1, 4, 1
	case StorageProfileSmall:
		defAgentMax, defAgentBackups, defCoreMax, defCoreBackups = 2, 2, 8, 2
	default:
		defAgentMax, defAgentBackups, defCoreMax, defCoreBackups = 4, 3, 16, 3
	}
	if explicitAgentMax != nil {
		agentMax = *explicitAgentMax
	} else {
		agentMax = defAgentMax
	}
	if explicitAgentBackups != nil {
		agentBackups = *explicitAgentBackups
	} else {
		agentBackups = defAgentBackups
	}
	if explicitCoreMax != nil {
		coreMax = *explicitCoreMax
	} else {
		coreMax = defCoreMax
	}
	if explicitCoreBackups != nil {
		coreBackups = *explicitCoreBackups
	} else {
		coreBackups = defCoreBackups
	}
	return
}

func logMaintenanceIntervalForProfile(profile StorageProfile) time.Duration {
	switch profile {
	case StorageProfileTiny:
		return 5 * time.Second
	case StorageProfileSmall:
		return 15 * time.Second
	default:
		return 30 * time.Second
	}
}

func diskPressureLevel(avail, total uint64) string {
	if avail < 64<<20 {
		return "critical"
	}
	if total > 0 && float64(avail)/float64(total) < 0.05 {
		return "critical"
	}
	if total > 0 && float64(avail)/float64(total) < 0.15 {
		return "warning"
	}
	return "normal"
}

func (r *Runner) storageProfile() StorageProfile {
	cfg := r.Config()
	return storageProfileFromConfig(cfg)
}

func (r *Runner) storageDiskInfo() StorageDiskInfo {
	cfg := r.Config()
	profile := storageProfileFromConfig(cfg)
	stats, err := filesystemStats(cfg.StateDir)
	if err != nil {
		stats, _ = filesystemStats("/var/log")
	}
	pressure := diskPressureLevel(stats.AvailableBytes, stats.TotalBytes)
	return StorageDiskInfo{
		TotalBytes:     stats.TotalBytes,
		AvailableBytes: stats.AvailableBytes,
		UsagePercent:   stats.UsagePercent,
		StorageProfile: profile,
		Pressure:       pressure,
	}
}

func (r *Runner) enforceEmergencyDiskCleanup() {
	info := r.storageDiskInfo()
	if info.Pressure != "critical" {
		return
	}
	// Delete old log backups first
	for _, policy := range r.managedLogs() {
		_ = pruneLogBackups(policy.Path, 0) // keep only current
		// Shrink current log to tail if too large
		safeTailBytes := int64(1 << 20)
		if policy.Service == "core" {
			safeTailBytes = 4 << 20
		}
		if st, err := os.Stat(policy.Path); err == nil && st.Size() > safeTailBytes {
			_ = truncateLogToTail(policy.Path, safeTailBytes)
		}
	}
	// Clean stale update artifacts
	if targets, err := r.signedReleaseTargets(); err == nil {
		prefix := r.updateStagingPrefix()
		r.removeStaleReleaseSidecars(filepath.Dir(targets.Agent), prefix)
		if filepath.Dir(targets.Core) != filepath.Dir(targets.Agent) {
			r.removeStaleReleaseSidecars(filepath.Dir(targets.Core), prefix)
		}
		// Clean private temp staging dirs older than 24h
		cleanStalePrivateUpdateTemps()
	}
	// Clean candidate/tmp
	_ = r.cleanStaleCandidateFiles()
}

func cleanStalePrivateUpdateTemps() {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "oboard-signed-update.") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > 24*time.Hour {
			_ = os.RemoveAll(filepath.Join(os.TempDir(), e.Name()))
		}
	}
}

func truncateLogToTail(path string, maxBytes int64) error {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() <= maxBytes {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	start := fi.Size() - maxBytes
	if _, err := f.Seek(start, 0); err != nil {
		return err
	}
	tmp := path + ".tmp-truncate"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := copyWithLimit(out, f, maxBytes); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	_ = out.Sync()
	_ = out.Close()
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func copyWithLimit(dst *os.File, src *os.File, limit int64) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for total < limit {
		remaining := limit - total
		if int64(len(buf)) > remaining {
			buf = buf[:remaining]
		}
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}

func (r *Runner) cleanStaleCandidateFiles() error {
	dir := r.stateDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".candidate") || strings.HasSuffix(name, ".tmp") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if time.Since(info.ModTime()) > 24*time.Hour {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}
	return nil
}

func (r *Runner) MaintainStorage() []LogFileState {
	profile := r.storageProfile()
	// Enforce log limits with profile budgets
	states := r.enforceLogLimits(false)
	// Emergency cleanup if critical
	if diskPressureLevel(r.storageDiskInfo().AvailableBytes, r.storageDiskInfo().TotalBytes) == "critical" {
		r.enforceEmergencyDiskCleanup()
	}
	_ = profile
	return states
}

func (r *Runner) reconcileUpdateArtifacts() {
	// Startup recovery cleanup: remove stale update sidecars and temps older than 24h.
	// Do not delete files with recovery_required marker (not implemented as separate file).
	now := time.Now()
	if targets, err := r.signedReleaseTargets(); err == nil {
		for _, dir := range []string{filepath.Dir(targets.Agent), filepath.Dir(targets.Core)} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				name := e.Name()
				if !strings.HasPrefix(name, ".oboard-update-") {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				// Keep recent sidecars (<24h) in case update just happened and rollback needed
				if now.Sub(info.ModTime()) < 24*time.Hour {
					continue
				}
				_ = os.RemoveAll(filepath.Join(dir, name))
			}
		}
	}
	cleanStalePrivateUpdateTemps()
	_ = r.cleanStaleCandidateFiles()
}
