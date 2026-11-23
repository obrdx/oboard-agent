//go:build linux

package terminal

import "os"

var detectServiceLauncher = func() (serviceLauncher, bool) {
	if os.Geteuid() != 0 {
		return serviceLauncher{}, false
	}
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		return serviceLauncher{}, false
	}
	run := firstExecutable("/usr/bin/systemd-run", "/bin/systemd-run")
	ctl := firstExecutable("/usr/bin/systemctl", "/bin/systemctl")
	if run == "" || ctl == "" {
		return serviceLauncher{}, false
	}
	return serviceLauncher{systemdRun: run, systemctl: ctl, envDir: "/run"}, true
}

func firstExecutable(paths ...string) string {
	for _, path := range paths {
		if shellExecutable(path) {
			return path
		}
	}
	return ""
}
