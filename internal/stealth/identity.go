package stealth

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// namePattern is the shape every generated identity name must have.
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9]{9}$`)

// ValidName reports whether name is an acceptable generated identity name.
func ValidName(name string) bool {
	return namePattern.MatchString(name)
}

// Identity is the set of random names one stealth installation uses. The
// names are generated once (at install or when stealth is enabled remotely)
// and then persist inside the encrypted agent config, so they survive every
// update.
type Identity struct {
	// AgentName is used for both the Agent binary and its service unit.
	AgentName string `json:"agent_name"`
	// InstallDirName is the installation directory basename under the
	// install parent (normally /opt). Empty on layouts created before the
	// directory was randomized: those keep the fixed install directory and
	// the runtime resolves the directory from the executable path anyway.
	InstallDirName string `json:"install_dir_name,omitempty"`
	// CoreName is used for both the kernel binary and its service unit.
	CoreName string `json:"core_name"`
	// RealmName is the port-forward binary name.
	RealmName string `json:"realm_name"`
	// ConfigDirName is the config directory basename under the config parent.
	ConfigDirName string `json:"config_dir_name"`
	// StateDirName is the state directory basename under the state parent.
	StateDirName string `json:"state_dir_name"`
	// AgentLogName is the Agent log basename (without .log) under /var/log.
	AgentLogName string `json:"agent_log_name"`
	// CoreLogName is the kernel log basename (without .log) under /var/log.
	CoreLogName string `json:"core_log_name"`
	// SocketName is the kernel local API socket basename under /run.
	SocketName string `json:"socket_name"`
	// SshdName is the managed tunnel sshd process/link name.
	SshdName string `json:"sshd_name"`
	// SshName is the tunnel ssh client process/link name.
	SshName string `json:"ssh_name"`
	// StagingPrefix replaces the ".oboard-update" prefix for update staging
	// files so a half-finished update leaves no OBoard-named sidecars.
	StagingPrefix string `json:"staging_prefix"`
	// ConfigFileName is the encrypted config basename inside the config dir.
	ConfigFileName string `json:"config_file_name"`
	// KeyFileName is the key file basename inside the config dir.
	KeyFileName string `json:"key_file_name"`
}

// Validate checks every name. It is called when loading a config written by
// another code path (bootstrap, migration) so a corrupted identity fails
// before any file is touched.
func (i Identity) Validate() error {
	fields := []struct {
		name  string
		value string
	}{
		{"agent_name", i.AgentName},
		{"install_dir_name", i.InstallDirName},
		{"core_name", i.CoreName},
		{"realm_name", i.RealmName},
		{"config_dir_name", i.ConfigDirName},
		{"state_dir_name", i.StateDirName},
		{"agent_log_name", i.AgentLogName},
		{"core_log_name", i.CoreLogName},
		{"socket_name", i.SocketName},
		{"sshd_name", i.SshdName},
		{"ssh_name", i.SshName},
		{"staging_prefix", i.StagingPrefix},
		{"config_file_name", i.ConfigFileName},
		{"key_file_name", i.KeyFileName},
	}
	seen := map[string]string{}
	for _, field := range fields {
		// install_dir_name may be empty: layouts created before the
		// randomized install directory keep running from the fixed one.
		if field.name == "install_dir_name" && field.value == "" {
			continue
		}
		if !ValidName(field.value) {
			return fmt.Errorf("stealth identity field %s is not a valid generated name", field.name)
		}
		if other, dup := seen[field.value]; dup && other != field.name {
			return fmt.Errorf("stealth identity reuses name %q for %s and %s", field.value, other, field.name)
		}
		seen[field.value] = field.name
	}
	return nil
}

// CollisionCheck describes the filesystem locations a fresh identity must not
// clash with. It is a struct rather than a spread of parameters so callers
// (bootstrap, remote enable, tests) stay readable.
type CollisionCheck struct {
	// InstallDir is where the three binaries live.
	InstallDir string
	// InstallParent is the parent of the installation directory; the
	// randomized install directory is created inside it.
	InstallParent string
	// ConfigParent is the parent of the config directory (normally /etc).
	ConfigParent string
	// StateParent is the parent of the state directory (normally /var/lib).
	StateParent string
	// LogDir is where the two log files live (normally /var/log).
	LogDir string
	// RunDir is where the kernel socket lives (normally /run).
	RunDir string
	// SystemdUnits and InitDir locate existing service definitions; empty
	// means that manager is not present and is skipped.
	SystemdUnits string
	InitDir      string
}

func (c CollisionCheck) taken(name string) bool {
	if c.InstallDir != "" {
		if _, err := os.Lstat(filepath.Join(c.InstallDir, name)); err == nil {
			return true
		}
	}
	if c.InstallParent != "" {
		if _, err := os.Lstat(filepath.Join(c.InstallParent, name)); err == nil {
			return true
		}
	}
	if c.ConfigParent != "" {
		if _, err := os.Lstat(filepath.Join(c.ConfigParent, name)); err == nil {
			return true
		}
	}
	if c.StateParent != "" {
		if _, err := os.Lstat(filepath.Join(c.StateParent, name)); err == nil {
			return true
		}
	}
	if c.LogDir != "" {
		if _, err := os.Lstat(filepath.Join(c.LogDir, name+".log")); err == nil {
			return true
		}
	}
	if c.RunDir != "" {
		if _, err := os.Lstat(filepath.Join(c.RunDir, name+".sock")); err == nil {
			return true
		}
	}
	if c.SystemdUnits != "" {
		if _, err := os.Lstat(filepath.Join(c.SystemdUnits, name+".service")); err == nil {
			return true
		}
	}
	if c.InitDir != "" {
		if _, err := os.Lstat(filepath.Join(c.InitDir, name)); err == nil {
			return true
		}
	}
	return false
}

// GenerateIdentity creates a fresh identity whose names are free on this
// filesystem right now. It retries a bounded number of times; a persistent
// clash is treated as an error rather than silently reusing a name.
func GenerateIdentity(check CollisionCheck) (Identity, error) {
	const attempts = 8
	pick := func() (string, error) {
		for i := 0; i < attempts; i++ {
			name, err := randomName()
			if err != nil {
				return "", err
			}
			if !check.taken(name) {
				return name, nil
			}
		}
		return "", fmt.Errorf("could not find a free stealth name in %d attempts", attempts)
	}
	identity := Identity{}
	var err error
	fields := []*string{
		&identity.AgentName,
		&identity.InstallDirName,
		&identity.CoreName,
		&identity.RealmName,
		&identity.ConfigDirName,
		&identity.StateDirName,
		&identity.AgentLogName,
		&identity.CoreLogName,
		&identity.SocketName,
		&identity.SshdName,
		&identity.SshName,
		&identity.StagingPrefix,
		&identity.ConfigFileName,
		&identity.KeyFileName,
	}
	for _, field := range fields {
		if *field, err = pick(); err != nil {
			return Identity{}, err
		}
	}
	if err := identity.Validate(); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

// Layout resolves an identity into concrete paths for one installation.
type Layout struct {
	AgentBinary  string
	CoreBinary   string
	RealmBinary  string
	AgentService string
	CoreService  string
	ConfigDir    string
	StateDir     string
	ConfigPath   string
	KeyPath      string
	AgentLog     string
	CoreLog      string
	CoreSocket   string
}

// ResolveLayout maps an identity onto concrete paths. configParent and
// stateParent are normally /etc and /var/lib; they are parameters so a
// server with a custom state location keeps its parent (and its disk) when
// stealth is enabled, and so tests can relocate everything.
func ResolveLayout(identity Identity, installDir, configParent, stateParent string) Layout {
	configDir := filepath.Join(configParent, identity.ConfigDirName)
	stateDir := filepath.Join(stateParent, identity.StateDirName)
	return Layout{
		AgentBinary:  filepath.Join(installDir, identity.AgentName),
		CoreBinary:   filepath.Join(installDir, identity.CoreName),
		RealmBinary:  filepath.Join(installDir, identity.RealmName),
		AgentService: identity.AgentName,
		CoreService:  identity.CoreName,
		ConfigDir:    configDir,
		StateDir:     stateDir,
		ConfigPath:   filepath.Join(configDir, identity.ConfigFileName),
		KeyPath:      filepath.Join(configDir, identity.KeyFileName),
		AgentLog:     filepath.Join("/var/log", identity.AgentLogName+".log"),
		CoreLog:      filepath.Join("/var/log", identity.CoreLogName+".log"),
		CoreSocket:   filepath.Join("/run", identity.SocketName+".sock"),
	}
}

// Settings is the persisted stealth section of the agent config. Identity,
// key path, and (only while a switch is settling) the layout to clean up
// after the restart live here. Everything else (state dir, core binary,
// service names, socket) stays in the top-level config fields so existing
// validation and update paths keep working.
type Settings struct {
	Identity Identity `json:"identity"`
	KeyPath  string   `json:"key_path"`
	// ControllerAddr is read only while migrating previous encrypted configurations.
	// Current configurations keep the transport independently of the layout.
	ControllerAddr string `json:"controller_addr,omitempty"`
	// ControllerCertSHA256 pins the listener certificate.
	ControllerCertSHA256 string          `json:"controller_cert_sha256,omitempty"`
	Previous             *PreviousLayout `json:"previous,omitempty"`
	// Origin records the standard layout this installation switched away
	// from. It survives the post-switch cleanup so a later disable can
	// restore the exact original paths (a custom install root must not be
	// reset to the defaults).
	Origin *PreviousLayout `json:"origin,omitempty"`
}

// PreviousLayout records the layout a completed stealth switch has left
// behind. The agent that starts after the switch removes these paths once,
// then drops the section. Paths that match the current layout are skipped.
type PreviousLayout struct {
	// InstallDir is the directory the previous layout's binaries lived in;
	// the post-switch cleanup removes it once its known contents are gone.
	InstallDir   string `json:"install_dir,omitempty"`
	AgentBinary  string `json:"agent_binary,omitempty"`
	CoreBinary   string `json:"core_binary,omitempty"`
	RealmBinary  string `json:"realm_binary,omitempty"`
	AgentService string `json:"agent_service,omitempty"`
	CoreService  string `json:"core_service,omitempty"`
	ConfigDir    string `json:"config_dir,omitempty"`
	ConfigPath   string `json:"config_path,omitempty"`
	KeyPath      string `json:"key_path,omitempty"`
	StateDir     string `json:"state_dir,omitempty"`
	AgentLog     string `json:"agent_log,omitempty"`
	CoreLog      string `json:"core_log,omitempty"`
	CoreSocket   string `json:"core_socket,omitempty"`
	// Stealth records which kind of layout this was, so cleanup knows
	// whether a key file and HMAC-named state are part of it.
	Stealth bool `json:"stealth,omitempty"`
}

// Validate checks the settings beyond the identity itself.
func (s Settings) Validate() error {
	if err := s.Identity.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(s.KeyPath) == "" {
		return fmt.Errorf("stealth key path must not be empty")
	}
	return nil
}

// NormalizeInstallDir cleans an installation directory for layout
// resolution, rejecting empty or relative values.
func NormalizeInstallDir(dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", fmt.Errorf("install dir must not be empty")
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("install dir must be absolute")
	}
	return filepath.Clean(dir), nil
}
