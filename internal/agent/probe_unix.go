//go:build !windows

package agent

import (
	"runtime"
	"syscall"
	"time"
)

func linuxDiskUsage(path string) (used, total uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	return diskUsedBytes(st.Blocks, st.Bfree, int64(st.Bsize)), diskTotalBytes(st.Blocks, int64(st.Bsize))
}

func filesystemUsage(path string) (total, available, used uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, err
	}
	bsize := int64(st.Bsize)
	if bsize <= 0 {
		bsize = 4096
	}
	total = uint64(st.Blocks) * uint64(bsize)
	available = uint64(st.Bavail) * uint64(bsize)
	if st.Blocks > st.Bfree {
		used = (st.Blocks - st.Bfree) * uint64(bsize)
	}
	return total, available, used, nil
}

func hostDiskUsage() (used, total uint64) {
	return linuxDiskUsage("/")
}

func hostMemory() (total, used uint64) {
	return linuxMemory()
}

func sampleHostNetwork(previous networkCounterSample, now time.Time) (systemProbe, networkCounterSample) {
	return sampleLinuxNetwork(previous, now)
}

// platformHostStaticInfo keeps the portable defaults on development hosts
// (macOS, BSD); only Linux and Windows are supported node platforms.
func platformHostStaticInfo(info hostStaticInfo) hostStaticInfo {
	return info
}

func platformKernelVersion() string {
	return runtime.GOOS
}

func samplePlatformSystemProbe(p systemProbe, _ procCPU) (systemProbe, procCPU) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	p.AgentMemoryBytes = mem.Sys
	p.MemoryUsedBytes = mem.Sys
	return p, procCPU{}
}

// Only Linux exposes /proc/uptime; other Unix builds report it as unknown.
func platformHostUptimeSeconds() uint64 { return 0 }
