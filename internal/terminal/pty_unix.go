//go:build !windows

package terminal

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// terminateGrace bounds how long the shell's process group may take to exit
// after SIGTERM before it is killed.
const terminateGrace = 2 * time.Second

// Spawn starts the shell as a direct child of the Agent on a new PTY.
func Spawn(spec SessionSpec) (*os.File, *exec.Cmd, error) {
	cmd := exec.Command(spec.Shell, spec.ShellArgs...)
	cmd.Dir = spec.WorkDir
	cmd.Env = append([]string{}, spec.Env...)
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	return startOnPTY(cmd, spec)
}

func startOnPTY(cmd *exec.Cmd, spec SessionSpec) (*os.File, *exec.Cmd, error) {
	cols, rows := spec.Cols, spec.Rows
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 32
	}
	// pty.StartWithSize sets Setsid and Setctty. Do not also set Setpgid:
	// a session leader cannot change its process group (EPERM).
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	return ptmx, cmd, err
}

// Start spawns the login shell on a Unix pseudo terminal. Under systemd the
// shell runs as its own transient unit so it does not inherit the Agent
// service sandbox; elsewhere it is a direct child of the Agent.
func Start(spec SessionSpec) (Session, error) {
	if launcher, ok := detectServiceLauncher(); ok {
		cmd, unit, envFile, err := launcher.command(spec)
		if err != nil {
			return nil, err
		}
		ptmx, cmd, err := startOnPTY(cmd, spec)
		if err != nil {
			if ptmx != nil {
				_ = ptmx.Close()
			}
			launcher.stop(unit, envFile)
			return nil, err
		}
		return &unixSession{ptmx: ptmx, cmd: cmd, launcher: launcher, unit: unit, envFile: envFile}, nil
	}
	ptmx, cmd, err := Spawn(spec)
	if err != nil {
		if ptmx != nil {
			_ = ptmx.Close()
		}
		return nil, err
	}
	return &unixSession{ptmx: ptmx, cmd: cmd}, nil
}

type unixSession struct {
	ptmx *os.File
	cmd  *exec.Cmd
	once sync.Once
	// launcher, unit and envFile are set when the shell runs as a transient
	// service-manager unit; Close stops that unit as well.
	launcher serviceLauncher
	unit     string
	envFile  string
}

func (s *unixSession) Read(p []byte) (int, error)  { return s.ptmx.Read(p) }
func (s *unixSession) Write(p []byte) (int, error) { return s.ptmx.Write(p) }

func (s *unixSession) Resize(cols, rows int) error {
	return pty.Setsize(s.ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// File exposes the pseudo terminal master for platform-specific tests.
func (s *unixSession) File() *os.File { return s.ptmx }

// Command exposes the started process for platform-specific tests.
func (s *unixSession) Command() *exec.Cmd { return s.cmd }

// Close releases the terminal and ends the shell's process group. The shell is
// a session leader (pty.StartWithSize sets Setsid), so its PID is also the
// group ID of everything it started.
func (s *unixSession) Close() error {
	s.once.Do(func() {
		_ = s.ptmx.Close()
		if s.unit != "" || s.envFile != "" {
			defer s.launcher.stop(s.unit, s.envFile)
		}
		if s.cmd == nil || s.cmd.Process == nil {
			return
		}
		group := -s.cmd.Process.Pid
		if syscall.Kill(group, syscall.SIGTERM) != nil {
			return
		}
		deadline := time.Now().Add(terminateGrace)
		for time.Now().Before(deadline) {
			if syscall.Kill(group, 0) != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = syscall.Kill(group, syscall.SIGKILL)
	})
	return nil
}

func (s *unixSession) ExitCode() int {
	if s.cmd == nil || s.cmd.ProcessState == nil {
		return -1
	}
	return s.cmd.ProcessState.ExitCode()
}

func buildPlatformSession(Mode, Request) (SessionSpec, bool, error) {
	return SessionSpec{}, false, nil
}
