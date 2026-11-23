//go:build !windows

package terminal

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSystemdRunArgsLeaveTheAgentSandboxWithoutLeakingEnvironment(t *testing.T) {
	spec := SessionSpec{Shell: "/bin/bash", ShellArgs: []string{"-l"}, WorkDir: "/root", Env: []string{"HOME=/root", "SECRET_TOKEN=do-not-show"}}
	args := systemdRunArgs(serviceLauncher{}, spec, "pty-0123456789abcdef.service", "/run/.pty-1.env")
	for _, want := range []string{"--pty", "--wait", "--collect", "--unit=pty-0123456789abcdef.service", "--service-type=exec", "--property=EnvironmentFile=/run/.pty-1.env", "--property=WorkingDirectory=-/root", "--property=KillMode=control-group", "--property=IgnoreSIGPIPE=no", "--property=UMask=0022"} {
		if !slices.Contains(args, want) {
			t.Fatalf("systemd-run args missing %q: %q", want, args)
		}
	}
	separator := slices.Index(args, "--")
	if separator < 0 || !slices.Equal(args[separator+1:], []string{"/bin/bash", "-l"}) {
		t.Fatalf("shell command must follow --: %q", args)
	}
	for _, arg := range args {
		if strings.Contains(arg, "do-not-show") {
			t.Fatalf("environment value leaked onto the command line: %q", arg)
		}
		if strings.HasPrefix(arg, "--property=User") || strings.HasPrefix(arg, "--property=PAMName") || strings.HasPrefix(arg, "--property=NoNewPrivileges") {
			t.Fatalf("unit must keep the Agent identity without PAM or a sandbox: %q", arg)
		}
	}
}

func TestWriteUnitEnvironmentIsPrivateAndEscaped(t *testing.T) {
	dir := t.TempDir()
	path, err := writeUnitEnvironment(dir, []string{"HOME=/root", `ODD=a"b\c$d` + "`e", "BROKEN=line\nnext", "1BAD=x", "PATH=/usr/bin:/bin"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || filepath.Dir(path) != dir {
		t.Fatalf("environment file %s mode %o", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "HOME=\"/root\"\nODD=\"a\\\"b\\\\c\\$d\\`e\"\nPATH=\"/usr/bin:/bin\"\n"
	if string(data) != want {
		t.Fatalf("environment file =\n%s\nwant\n%s", data, want)
	}
}

func TestStartThroughServiceLauncherStopsUnitAndRemovesEnvironment(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "systemctl.log")
	fakeRun := filepath.Join(dir, "systemd-run")
	fakeCtl := filepath.Join(dir, "systemctl")
	// The fake systemd-run records its argv and then runs the shell after "--".
	writeScript(t, fakeRun, "#!/bin/sh\nprintf '%s\\n' \"$@\" > "+filepath.Join(dir, "run.args")+"\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n")
	writeScript(t, fakeCtl, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+log+"\n")
	previous := detectServiceLauncher
	detectServiceLauncher = func() (serviceLauncher, bool) {
		return serviceLauncher{systemdRun: fakeRun, systemctl: fakeCtl, envDir: dir}, true
	}
	t.Cleanup(func() { detectServiceLauncher = previous })

	session, err := Start(SessionSpec{Shell: "/bin/sh", ShellArgs: []string{"-c", "sleep 30"}, WorkDir: dir, Env: []string{"HOME=" + dir}})
	if err != nil {
		t.Fatal(err)
	}
	unixSession := session.(*unixSession)
	if !strings.HasPrefix(unixSession.unit, "pty-") || unixSession.envFile == "" {
		t.Fatalf("session not launched as a transient unit: %#v", unixSession)
	}
	if _, err := os.Stat(unixSession.envFile); err != nil {
		t.Fatalf("environment file missing while the session runs: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unixSession.envFile); !os.IsNotExist(err) {
		t.Fatalf("environment file must be removed on close: %v", err)
	}
	data, _ := os.ReadFile(log)
	if strings.TrimSpace(string(data)) != "stop --no-block "+unixSession.unit {
		t.Fatalf("systemctl calls = %q", data)
	}
}

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath(path); err != nil {
		t.Fatal(err)
	}
}
