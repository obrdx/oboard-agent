//go:build windows

package agent

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modKernel32                = windows.NewLazySystemDLL("kernel32.dll")
	modIPHelper                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGlobalMemoryStatusEx   = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes         = modKernel32.NewProc("GetSystemTimes")
	procK32GetProcessMemInfo   = modKernel32.NewProc("K32GetProcessMemoryInfo")
	procGetTCPStatisticsEx     = modIPHelper.NewProc("GetTcpStatisticsEx")
	procGetUDPStatisticsEx     = modIPHelper.NewProc("GetUdpStatisticsEx")
	windowsSystemDriveFallback = `C:\`
)

// memoryStatusEx mirrors MEMORYSTATUSEX.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func hostMemory() (total, used uint64) {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if ok, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status))); ok == 0 {
		return 0, 0
	}
	if status.TotalPhys > status.AvailPhys {
		used = status.TotalPhys - status.AvailPhys
	}
	return status.TotalPhys, used
}

func agentWorkingSet() uint64 {
	counters := processMemoryCounters{CB: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	ok, _, _ := procK32GetProcessMemInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&counters)), uintptr(counters.CB))
	if ok == 0 {
		return 0
	}
	return uint64(counters.WorkingSetSize)
}

func windowsSystemDrive() string {
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if drive == "" {
		return windowsSystemDriveFallback
	}
	return strings.TrimRight(drive, `\`) + `\`
}

func filesystemUsage(path string) (total, available, used uint64, err error) {
	root, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, 0, err
	}
	var free uint64
	if err := windows.GetDiskFreeSpaceEx(root, &available, &total, &free); err != nil {
		return 0, 0, 0, err
	}
	if total > free {
		used = total - free
	}
	return total, available, used, nil
}

func hostDiskUsage() (used, total uint64) {
	root, err := windows.UTF16PtrFromString(windowsSystemDrive())
	if err != nil {
		return 0, 0
	}
	var available, size, free uint64
	if err := windows.GetDiskFreeSpaceEx(root, &available, &size, &free); err != nil || size == 0 {
		return 0, 0
	}
	if size > free {
		used = size - free
	}
	return used, size
}

// readSystemCPU returns cumulative idle and total CPU time. GetSystemTimes
// reports kernel time including idle, so total is kernel plus user.
func readSystemCPU() (procCPU, bool) {
	var idle, kernelTime, userTime windows.Filetime
	ok, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernelTime)), uintptr(unsafe.Pointer(&userTime)))
	if ok == 0 {
		return procCPU{}, false
	}
	value := func(ft windows.Filetime) uint64 { return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime) }
	total := value(kernelTime) + value(userTime)
	if total == 0 {
		return procCPU{}, false
	}
	return procCPU{idle: value(idle), total: total}, true
}

// connectionCounts sums the TCP connection table and UDP endpoint table sizes
// for IPv4 and IPv6, matching the /proc/net/{tcp,udp}[6] line counts on Linux.
func connectionCounts() (tcp, udp uint64) {
	for _, family := range []uintptr{windows.AF_INET, windows.AF_INET6} {
		var tcpStats [15]uint32
		if rc, _, _ := procGetTCPStatisticsEx.Call(uintptr(unsafe.Pointer(&tcpStats[0])), family); rc == 0 {
			tcp += uint64(tcpStats[14])
		}
		var udpStats [5]uint32
		if rc, _, _ := procGetUDPStatisticsEx.Call(uintptr(unsafe.Pointer(&udpStats[0])), family); rc == 0 {
			udp += uint64(udpStats[4])
		}
	}
	return tcp, udp
}

func processCount() uint64 {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var count uint64
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		count++
	}
	return count
}

func samplePlatformSystemProbe(p systemProbe, previousCPU procCPU) (systemProbe, procCPU) {
	if total, used := hostMemory(); total > 0 {
		p.MemoryTotalBytes = total
		p.MemoryUsedBytes = used
	}
	p.AgentMemoryBytes = agentWorkingSet()
	if used, total := hostDiskUsage(); total > 0 {
		p.DiskUsedBytes = used
		p.DiskTotalBytes = total
	}
	p.TCPConnectionCount, p.UDPConnectionCount = connectionCounts()
	p.ProcessCount = processCount()
	currentCPU, ok := readSystemCPU()
	if !ok {
		return p, previousCPU
	}
	if previousCPU.total == 0 {
		time.Sleep(firstCPUSampleWait)
		if second, okSecond := readSystemCPU(); okSecond {
			if usage, valid := cpuUsageBetween(currentCPU, second); valid {
				p.CPUUsagePercent = clampCPUPercent(usage)
			}
			return p, second
		}
		return p, currentCPU
	}
	if usage, valid := cpuUsageBetween(previousCPU, currentCPU); valid {
		p.CPUUsagePercent = clampCPUPercent(usage)
	}
	return p, currentCPU
}

// monitoredWindowsInterface keeps physical and virtual machine NICs and drops
// loopback, tunnels, and NDIS filter stacks, which would otherwise count the
// same bytes several times.
func monitoredWindowsInterface(row *windows.MibIfRow2) bool {
	const filterInterfaceFlag = 0x02
	if row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK || row.Type == windows.IF_TYPE_TUNNEL {
		return false
	}
	if row.InterfaceAndOperStatusFlags&filterInterfaceFlag != 0 || row.OperStatus != windows.IfOperStatusUp {
		return false
	}
	return monitorNetworkInterface(windows.UTF16ToString(row.Alias[:]))
}

func windowsNetworkTotals() (upload, download uint64, ok bool) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil || table == nil {
		return 0, 0, false
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	rows := unsafe.Slice(&table.Table[0], table.NumEntries)
	for i := range rows {
		if !monitoredWindowsInterface(&rows[i]) {
			continue
		}
		download += rows[i].InOctets
		upload += rows[i].OutOctets
		ok = true
	}
	return upload, download, ok
}

func sampleHostNetwork(previous networkCounterSample, now time.Time) (systemProbe, networkCounterSample) {
	upload, download, ok := windowsNetworkTotals()
	if !ok {
		return systemProbe{}, previous
	}
	current := networkCounterSample{UploadBytes: upload, DownloadBytes: download, SampledAt: now, Valid: true}
	result := systemProbe{NetworkTotalUploadBytes: upload, NetworkTotalDownloadBytes: download}
	result.NetworkUploadBPS, result.NetworkDownloadBPS = networkRatesBetween(previous, current)
	return result, current
}

func readRegistryString(root registry.Key, path, name string) string {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func platformHostStaticInfo(info hostStaticInfo) hostStaticInfo {
	if name := readRegistryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString"); name != "" {
		info.CPUName = name
	}
	const currentVersion = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	product := readRegistryString(registry.LOCAL_MACHINE, currentVersion, "ProductName")
	display := readRegistryString(registry.LOCAL_MACHINE, currentVersion, "DisplayVersion")
	version := windows.RtlGetVersion()
	info.Distro = distroInfo{
		ID:             "windows",
		Version:        fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber),
		Name:           strings.TrimSpace(firstNonEmpty(product, "Windows") + " " + display),
		Libc:           "msvcrt",
		ServiceManager: detectServiceManager(),
		PackageManager: "none",
	}
	return info
}

func platformKernelVersion() string {
	version := windows.RtlGetVersion()
	return fmt.Sprintf("windows-nt-%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber)
}

func platformHostUptimeSeconds() uint64 {
	return uint64(windows.DurationSinceBoot() / time.Second)
}
