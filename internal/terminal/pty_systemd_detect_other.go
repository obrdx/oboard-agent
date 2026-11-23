//go:build !linux && !windows

package terminal

var detectServiceLauncher = func() (serviceLauncher, bool) { return serviceLauncher{}, false }
