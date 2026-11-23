//go:build linux

package agent

import (
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// platformBootClock returns the kernel boot identity and CLOCK_BOOTTIME. Both
// are shared by every process of one boot and are never moved by a wall-clock
// step, so they measure time across an Agent restart without trusting the host
// clock that the logical clock exists to correct.
func platformBootClock() (string, time.Duration, bool) {
	// #nosec G304 -- fixed kernel path.
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", 0, false
	}
	bootID := strings.TrimSpace(string(data))
	var ts unix.Timespec
	if bootID == "" || unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return "", 0, false
	}
	return bootID, time.Duration(ts.Nano()), true
}
