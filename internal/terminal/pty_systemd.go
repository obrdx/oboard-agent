//go:build !windows

package terminal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// serviceLauncher starts the shell as a transient unit of the host service
// manager. A shell forked by the Agent would inherit the Agent unit's sandbox
// (NoNewPrivileges, seccomp filters, ProtectHome, PrivateTmp, a 0077 umask),
// which breaks ordinary root work such as apt dropping to _apt, sudo, su or
// JIT runtimes. The terminal already runs as the Agent's own identity, so the
// sandbox protects nothing here; the shell gets the host's normal context.
type serviceLauncher struct {
	systemdRun string
	systemctl  string
	envDir     string
}

func newTransientUnitName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "pty-" + hex.EncodeToString(b[:]) + ".service", nil
}

// writeUnitEnvironment stores the sanitized session environment in a 0600
// file read by the service manager, so values never appear on a command line.
func writeUnitEnvironment(dir string, env []string) (string, error) {
	file, err := os.CreateTemp(dir, ".pty-*.env")
	if err != nil {
		return "", err
	}
	path := file.Name()
	var b strings.Builder
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !validEnvKey(key) || strings.ContainsAny(value, "\x00\n\r") {
			continue
		}
		b.WriteString(key)
		b.WriteString(`="`)
		for _, r := range value {
			if strings.ContainsRune("\"\\`$", r) {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		b.WriteString("\"\n")
	}
	if err := file.Chmod(0o600); err == nil {
		_, err = file.WriteString(b.String())
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			return path, nil
		}
	} else {
		_ = file.Close()
	}
	_ = os.Remove(path)
	return "", errors.New("write terminal environment: " + err.Error())
}

func systemdRunArgs(launcher serviceLauncher, spec SessionSpec, unit, envFile string) []string {
	workDir := strings.TrimSpace(spec.WorkDir)
	if workDir == "" {
		workDir = "/"
	}
	args := []string{
		"--quiet", "--pty", "--wait", "--collect",
		"--unit=" + unit,
		"--service-type=exec",
		"--property=EnvironmentFile=" + envFile,
		"--property=ExecStartPost=-/bin/rm -f " + envFile,
		"--property=WorkingDirectory=-" + workDir,
		"--property=KillMode=control-group",
		"--property=SendSIGHUP=yes",
		"--property=IgnoreSIGPIPE=no",
		"--property=UMask=0022",
		"--",
		spec.Shell,
	}
	return append(args, spec.ShellArgs...)
}

func (l serviceLauncher) command(spec SessionSpec) (*exec.Cmd, string, string, error) {
	unit, err := newTransientUnitName()
	if err != nil {
		return nil, "", "", err
	}
	envFile, err := writeUnitEnvironment(l.envDir, spec.Env)
	if err != nil {
		return nil, "", "", err
	}
	cmd := exec.Command(l.systemdRun, systemdRunArgs(l, spec, unit, envFile)...)
	cmd.Dir = "/"
	cmd.Env = append([]string{}, spec.Env...)
	return cmd, unit, envFile, nil
}

func (l serviceLauncher) stop(unit, envFile string) {
	if envFile != "" {
		_ = os.Remove(envFile)
	}
	if unit == "" || l.systemctl == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, l.systemctl, "stop", "--no-block", unit).Run()
}
