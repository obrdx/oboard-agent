//go:build !linux

package agent

import "time"

// platformBootClock has no boot-scoped clock on this platform; a restored
// logical clock then stays unverified until the Controller time confirms it.
func platformBootClock() (string, time.Duration, bool) { return "", 0, false }
