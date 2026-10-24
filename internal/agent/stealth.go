package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/agentsecurity"
	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

// This file implements the security-process ("stealth") lifecycle: the
// installer bootstrap that creates a hidden layout from scratch, the
// apply_stealth task that switches an enrolled server between the standard
// and hidden layouts, and the post-restart cleanup that removes the layout
// left behind by a completed switch.
//
// The hidden layout is fully described by one encrypted config plus one key
// file; every state file name is HMAC-derived from the key, so nothing on
// the Agent disk records the mapping. A switch never destroys the old layout
// before the new one is running: files are copied (not moved), the new units are
// verified, and only the process that starts after the switch removes the
// previous layout.

// stealthBootstrapOptions configures RunStealthBootstrap. The parent
// directories are parameters so tests can relocate the whole layout; the
// installer passes the production defaults.
type stealthBootstrapOptions struct {
	InstallDir       string
	Manager          string // systemd | openrc
	ControllerURL    string
	UpdateSource     string
	AllowPanelUpdate bool
	UpdateRepo       string
	ConfigParent     string
	StateParent      string
	UnitDir          string
	LogDir           string
	RunDir           string
	Identity         *stealth.Identity
	// ControllerAddr is the dedicated binary-transport listener (host:port).
	// When set, the generated config routes the control channel and every
	// callback through it instead of the panel's HTTP surface.
	ControllerAddr string
	// ControllerCertSHA256 pins the transport certificate.
	ControllerCertSHA256 string
}

func (o stealthBootstrapOptions) withDefaults() stealthBootstrapOptions {
	if o.ConfigParent == "" {
		o.ConfigParent = "/etc"
	}
	if o.StateParent == "" {
		o.StateParent = "/var/lib"
	}
	if o.UnitDir == "" {
		if o.Manager == "openrc" {
			o.UnitDir = "/etc/init.d"
		} else {
			o.UnitDir = "/etc/systemd/system"
		}
	}
	if o.LogDir == "" {
		o.LogDir = "/var/log"
	}
	if o.RunDir == "" {
		o.RunDir = "/run"
	}
	return o
}

// RunStealthBootstrap converts a freshly downloaded standard install (the
// three oboard-named binaries in InstallDir) into a hidden layout: it
// accepts the Controller-issued identity and generates the key, then moves
// the binaries into a randomly named installation directory beside InstallDir,
// writes the encrypted config,
// and installs the service units. It does not start anything; the caller
// enrolls and starts the agent service afterwards.
func RunStealthBootstrap(opts stealthBootstrapOptions) (stealth.Layout, error) {
	opts = opts.withDefaults()
	if opts.Manager != "systemd" && opts.Manager != "openrc" {
		return stealth.Layout{}, fmt.Errorf("unsupported service manager %q", opts.Manager)
	}
	installDir, err := stealth.NormalizeInstallDir(opts.InstallDir)
	if err != nil {
		return stealth.Layout{}, err
	}
	for _, name := range []string{"oboard-agent", "oboard-sb", "oboard-realm"} {
		if info, statErr := os.Lstat(filepath.Join(installDir, name)); statErr != nil || info.IsDir() {
			return stealth.Layout{}, fmt.Errorf("%s binary is missing from %s", name, installDir)
		}
	}
	installParent := filepath.Dir(installDir)
	if installParent == "/" || installDir == "/" {
		return stealth.Layout{}, fmt.Errorf("install dir %s must be nested below a parent directory so the hidden layout can randomize it", installDir)
	}
	var identity stealth.Identity
	if opts.Identity != nil {
		if err := opts.Identity.Validate(); err != nil {
			return stealth.Layout{}, err
		}
		identity = *opts.Identity
	} else {
		var err error
		identity, err = stealth.GenerateIdentity(stealth.CollisionCheck{
			InstallDir:    installDir,
			InstallParent: installParent,
			ConfigParent:  opts.ConfigParent,
			StateParent:   opts.StateParent,
			LogDir:        opts.LogDir,
			RunDir:        opts.RunDir,
			SystemdUnits:  unitDirIf(opts.Manager == "systemd", opts.UnitDir),
			InitDir:       unitDirIf(opts.Manager == "openrc", opts.UnitDir),
		})
		if err != nil {
			return stealth.Layout{}, err
		}
	}
	hiddenInstallDir := filepath.Join(installParent, identity.InstallDirName)
	if _, statErr := os.Lstat(hiddenInstallDir); statErr == nil {
		return stealth.Layout{}, fmt.Errorf("refusing to reuse existing directory %s", hiddenInstallDir)
	} else if !os.IsNotExist(statErr) {
		return stealth.Layout{}, statErr
	}
	if opts.Identity != nil {
		unitSuffix := ".service"
		if opts.Manager == "openrc" {
			unitSuffix = ""
		}
		for _, path := range []string{
			filepath.Join(opts.ConfigParent, identity.ConfigDirName),
			filepath.Join(opts.StateParent, identity.StateDirName),
			filepath.Join(opts.UnitDir, identity.AgentName+unitSuffix),
			filepath.Join(opts.UnitDir, identity.CoreName+unitSuffix),
			filepath.Join(opts.LogDir, identity.AgentLogName+".log"),
			filepath.Join(opts.LogDir, identity.CoreLogName+".log"),
			filepath.Join(opts.RunDir, identity.SocketName+".sock"),
		} {
			if _, err := os.Lstat(path); err == nil {
				return stealth.Layout{}, fmt.Errorf("security-process layout path already exists: %s", path)
			} else if !os.IsNotExist(err) {
				return stealth.Layout{}, err
			}
		}
	}
	if err := os.Mkdir(hiddenInstallDir, 0o755); err != nil {
		return stealth.Layout{}, err
	}
	layout := stealth.ResolveLayout(identity, hiddenInstallDir, opts.ConfigParent, opts.StateParent)
	layout.AgentLog = filepath.Join(opts.LogDir, identity.AgentLogName+".log")
	layout.CoreLog = filepath.Join(opts.LogDir, identity.CoreLogName+".log")
	layout.CoreSocket = filepath.Join(opts.RunDir, identity.SocketName+".sock")

	key, err := stealth.GenerateKey()
	if err != nil {
		return stealth.Layout{}, err
	}
	// Move the binaries into the hidden directory. Nothing references the
	// old names yet.
	for _, pair := range []struct{ from, to string }{
		{filepath.Join(installDir, "oboard-agent"), layout.AgentBinary},
		{filepath.Join(installDir, "oboard-sb"), layout.CoreBinary},
		{filepath.Join(installDir, "oboard-realm"), layout.RealmBinary},
	} {
		if _, statErr := os.Lstat(pair.to); statErr == nil {
			return stealth.Layout{}, fmt.Errorf("refusing to overwrite existing file %s", pair.to)
		}
		if err := os.Rename(pair.from, pair.to); err != nil {
			return stealth.Layout{}, err
		}
	}
	// The staging directory held only the three binaries (plus, on a
	// reinstall over a removed standard layout, its helper symlink); drop
	// both so the fixed OBoard path does not survive the install. Remove
	// only succeeds while the directory is empty, so anything else an
	// operator keeps there stays.
	obagPath := filepath.Join(installDir, "obag")
	if target, linkErr := os.Readlink(obagPath); linkErr == nil && filepath.Clean(target) == filepath.Join(installDir, "oboard-agent") {
		_ = os.Remove(obagPath)
	}
	if removeErr := os.Remove(installDir); removeErr != nil {
		logging.Infof("stealth bootstrap: staging directory %s kept: %v", installDir, removeErr)
	}
	if err := os.MkdirAll(layout.ConfigDir, 0o700); err != nil {
		return stealth.Layout{}, err
	}
	if err := os.MkdirAll(layout.StateDir, 0o700); err != nil {
		return stealth.Layout{}, err
	}
	if err := stealth.SaveKey(layout.KeyPath, key); err != nil {
		return stealth.Layout{}, err
	}
	cfg := Config{
		ConfigPath:           layout.ConfigPath,
		ControllerURL:        strings.TrimSpace(opts.ControllerURL),
		ControllerAddr:       strings.TrimSpace(opts.ControllerAddr),
		ControllerCertSHA256: strings.TrimSpace(opts.ControllerCertSHA256),
		StateDir:             layout.StateDir,
		CoreBinary:           layout.CoreBinary,
		CoreService:          layout.CoreService,
		AgentService:         layout.AgentService,
		CoreSocket:           layout.CoreSocket,
		Stealth: &stealth.Settings{
			Identity: identity,
			KeyPath:  layout.KeyPath,
		},
		UpdateSource:     strings.TrimSpace(opts.UpdateSource),
		AllowPanelUpdate: opts.AllowPanelUpdate,
		UpdateRepo:       strings.TrimSpace(opts.UpdateRepo),
	}
	if cfg.UpdateSource == "" {
		cfg.UpdateSource = "panel"
	}
	if cfg.UpdateRepo == "" {
		cfg.UpdateRepo = defaultUpdateRepo
	}
	cfg = normalizeConfig(cfg)
	if err := cfg.Validate(); err != nil {
		return stealth.Layout{}, err
	}
	// Re-validate core_binary with the hidden installation directory
	// allowed: the bootstrap just created it beside the operator-chosen
	// install root and placed the binaries there. At runtime the agent
	// runs from the same directory, so its own validation accepts it.
	if err := validateManagedPath("core_binary", cfg.CoreBinary, map[string][]string{
		"basenames": {identity.CoreName},
		"coreDirs":  {hiddenInstallDir},
	}); err != nil {
		return stealth.Layout{}, err
	}
	if err := SaveConfigWithKey(layout.ConfigPath, cfg, key); err != nil {
		return stealth.Layout{}, err
	}
	units := stealthUnits{
		Layout:   layout,
		Identity: identity,
		Manager:  opts.Manager,
		UnitDir:  opts.UnitDir,
		KeyPath:  layout.KeyPath,
		key:      key,
	}
	if err := units.write(); err != nil {
		return stealth.Layout{}, err
	}
	if err := units.enable(); err != nil {
		return stealth.Layout{}, err
	}
	return layout, nil
}

func unitDirIf(condition bool, dir string) string {
	if condition {
		return dir
	}
	return ""
}

// stealthUnits renders and installs the two service units of a hidden layout.
type stealthUnits struct {
	Layout   stealth.Layout
	Identity stealth.Identity
	Manager  string
	UnitDir  string
	KeyPath  string
	// key holds the raw stealth key so unit rendering can derive the kernel
	// config path without re-reading the key file.
	key []byte
}

func (u stealthUnits) agentUnitPath() string {
	if u.Manager == "openrc" {
		return filepath.Join(u.UnitDir, u.Layout.AgentService)
	}
	return filepath.Join(u.UnitDir, u.Layout.AgentService+".service")
}

func (u stealthUnits) coreUnitPath() string {
	if u.Manager == "openrc" {
		return filepath.Join(u.UnitDir, u.Layout.CoreService)
	}
	return filepath.Join(u.UnitDir, u.Layout.CoreService+".service")
}

func (u stealthUnits) write() error {
	agentUnit := u.agentUnit()
	coreUnit := u.coreUnit()
	if u.Manager == "openrc" {
		if err := os.MkdirAll(u.UnitDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(u.agentUnitPath(), []byte(agentUnit), 0o755); err != nil {
			return err
		}
		return os.WriteFile(u.coreUnitPath(), []byte(coreUnit), 0o755)
	}
	if err := os.MkdirAll(u.UnitDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(u.agentUnitPath(), []byte(agentUnit), 0o644); err != nil {
		return err
	}
	return os.WriteFile(u.coreUnitPath(), []byte(coreUnit), 0o644)
}

func (u stealthUnits) enable() error {
	if u.Manager == "systemd" {
		if err := stealthCommandRunner(15*time.Second, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := stealthCommandRunner(15*time.Second, "systemctl", "enable", u.Layout.AgentService, u.Layout.CoreService); err != nil {
			return err
		}
		return nil
	}
	if err := stealthCommandRunner(15*time.Second, "rc-update", "add", u.Layout.AgentService, "default"); err != nil {
		return err
	}
	return stealthCommandRunner(15*time.Second, "rc-update", "add", u.Layout.CoreService, "default")
}

func (u stealthUnits) disable() error {
	if u.Manager == "systemd" {
		if err := stealthCommandRunner(15*time.Second, "systemctl", "disable", u.Layout.AgentService, u.Layout.CoreService); err != nil {
			return err
		}
		return stealthCommandRunner(15*time.Second, "systemctl", "daemon-reload")
	}
	if err := stealthCommandRunner(15*time.Second, "rc-update", "del", u.Layout.AgentService, "default"); err != nil {
		return err
	}
	return stealthCommandRunner(15*time.Second, "rc-update", "del", u.Layout.CoreService, "default")
}

// coreConfigPath derives the kernel config path inside the stealth state
// directory. It is a free function so both bootstrap and the switch flows
// share one derivation.
func stealthCoreConfigPath(stateDir string, key []byte) string {
	return filepath.Join(stateDir, stealth.PhysicalName(key, singBoxConfigFile))
}

// stealthKey returns the key held by the unit renderer.
func (u stealthUnits) stealthKey() []byte {
	return u.key
}

func (u stealthUnits) coreUnit() string {
	if u.Manager == "openrc" {
		return fmt.Sprintf(`#!/sbin/openrc-run

description=%q
command=%s
command_args="-config %s -key %s -api unix:%s"
supervisor=supervise-daemon
pidfile="/run/${RC_SVCNAME}.pid"
output_log=%s
error_log=%s
respawn_delay=3
respawn_max=0

depend() {
  need net
  after firewall
}

start_pre() {
  checkpath -d -m 0700 %s
}
`, u.Layout.CoreService, u.Layout.CoreBinary, stealthCoreConfigPath(u.Layout.StateDir, u.stealthKey()), u.KeyPath, u.Layout.CoreSocket, u.Layout.CoreLog, u.Layout.CoreLog, u.Layout.StateDir)
	}
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -config %s -key %s -api unix:%s
StandardOutput=append:%s
StandardError=append:%s
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=%s /var/log /run
LockPersonality=true
ProtectKernelTunables=false
ProtectControlGroups=false
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, u.Layout.CoreService, u.Layout.CoreBinary, stealthCoreConfigPath(u.Layout.StateDir, u.stealthKey()), u.KeyPath, u.Layout.CoreSocket, u.Layout.CoreLog, u.Layout.CoreLog, u.Layout.StateDir)
}

func (u stealthUnits) agentUnit() string {
	if u.Manager == "openrc" {
		return fmt.Sprintf(`#!/sbin/openrc-run

description=%q
command=%s
command_args="-config %s -key %s"
supervisor=supervise-daemon
pidfile="/run/${RC_SVCNAME}.pid"
output_log=%s
error_log=%s
respawn_delay=5
respawn_max=0

depend() {
  need net
  after firewall
}

start_pre() {
  checkpath -d -m 0700 %s %s
}
`, u.Layout.AgentService, u.Layout.AgentBinary, u.Layout.ConfigPath, u.KeyPath, u.Layout.AgentLog, u.Layout.AgentLog, u.Layout.ConfigDir, u.Layout.StateDir)
	}
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s -config %s -key %s
StandardOutput=append:%s
StandardError=append:%s
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=false
ProtectHome=true
ReadWritePaths=%s %s %s /var/log /run
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
ProtectKernelTunables=false
ProtectControlGroups=false
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, u.Layout.AgentService, u.Layout.AgentBinary, u.Layout.ConfigPath, u.KeyPath, u.Layout.AgentLog, u.Layout.AgentLog, filepath.Dir(u.Layout.AgentBinary), u.Layout.ConfigDir, u.Layout.StateDir)
}

// stateTopLevelFiles lists every top-level logical state file name the agent
// and kernel create. The disable migration is list-driven because physical
// names cannot be reversed without it. Entries with a derived suffix (the
// traffic backup and the authorization deny watermark) are handled by
// statePhysicalName below.
var stateTopLevelFiles = []string{
	runtimeSecurityFile, runtimeSecurityPendingFile, runtimeSecurityDesiredFile, runtimeSecretsKey, runtimeStorageReady, runtimeSecurityReportFile,
	runtimeReleaseProofFile,
	singBoxConfigFile,
	singBoxLastGoodFile,
	"last-applied-version.json",
	"controller-link.json",
	"core-watchdog.json",
	"traffic-state.json",
	"metric-reports.json",
	"latency-probe.json",
	"connection-audit-state.json",
	"authorization.json",
	"kernel-authorization.json",
	"kernel-users.json",
	"kernel-proxy-dscp.json",
	"runtime-users.json",
	sshInboundsCurrent,
	sshInboundsLastGood,
	sshInboundHostKey,
	portForwardsCurrent,
	portForwardsLastGood,
	realmConfigFile,
	realmPIDFile,
	realmLogFile,
	tunnelsCurrent,
	tunnelsLastGood,
	"dns-benchmark.json",
	runtimeClockStateFile,
	"socket-tuning.json",
	"host-power-journal.json",
	hostCoreLockName,
}

// stateTopLevelDirs lists the top-level logical state directories. Their
// inner structure keeps its relative names; only content is transformed.
var stateTopLevelDirs = []string{
	tunnelsDir,
	"warp",
	"managed-assets",
	"remote-exec",
	"acme",
}

// statePhysicalName maps a logical top-level entry to its stealth physical
// name, including the suffix variants the code derives from a resolved path.
func statePhysicalName(key []byte, logical string) string {
	switch logical {
	case "traffic-state.json.bak":
		return stealth.PhysicalName(key, "traffic-state.json") + ".bak"
	case "authorization.json.denied.json":
		return stealth.PhysicalName(key, "authorization.json") + ".denied.json"
	case "kernel-authorization.json.denied.json":
		return stealth.PhysicalName(key, "kernel-authorization.json") + ".denied.json"
	default:
		return stealth.PhysicalName(key, logical)
	}
}

// allStateTopLevelFiles extends the fixed list with the suffix variants.
func allStateTopLevelFiles() []string {
	files := append([]string(nil), stateTopLevelFiles...)
	return append(files,
		"traffic-state.json.bak",
		"authorization.json.denied.json",
		"kernel-authorization.json.denied.json",
	)
}

// stealthSwitchEuid is a seam for the root check of a layout switch.
var stealthSwitchEuid = os.Geteuid

// applyStealthTask executes the apply_stealth task. The switch itself runs
// under the core lifecycle locks; the restart is armed and executed by the
// task worker after the result is acknowledged, exactly like update_agent.
func (r *Runner) applyStealthTask(payloadJSON string) (map[string]any, error) {
	var payload model.ApplyStealthTaskPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if stealthSwitchEuid() != 0 {
		return map[string]any{"message": "stealth switch requires root"}, errors.New("stealth switch requires root")
	}
	if !r.managedRestartEnabled() {
		return map[string]any{"message": "stealth switch requires a managed service restart"}, errors.New("restart_command is \"none\"; a stealth switch needs the service manager")
	}
	manager := serviceManager()
	if manager != "systemd" && manager != "openrc" {
		return map[string]any{"message": "stealth switch requires a service manager"}, errors.New("supported service manager is unavailable")
	}
	r.coreLifecycleMu.Lock()
	defer r.coreLifecycleMu.Unlock()
	hostLock, hostLockErr := r.acquireHostCoreLock(hostCoreLockWait)
	if hostLockErr != nil {
		return map[string]any{"message": "stealth switch deferred"}, hostLockErr
	}
	defer hostLock.release()
	if payload.Enable {
		return r.enableStealthLocked(manager)
	}
	return r.disableStealthLocked(manager)
}

// enableStealthLocked switches a standard installation into the hidden
// layout. Nothing of the old layout is destroyed here: binaries are copied,
// state is copied (encrypted), and the old units are only disabled. The
// process that starts after the switch removes the leftovers.
func (r *Runner) enableStealthLocked(manager string) (map[string]any, error) {
	cfg := r.Config()
	if r.stealthOn() {
		return map[string]any{"message": "already running in the security-process layout", "stealth_enabled": true, "idempotent_replay": true, "agent_service": r.agentService(), "core_service": r.coreService()}, nil
	}
	agentPath, err := selfExecutablePath()
	if err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	installDir := filepath.Dir(agentPath)
	installParent := filepath.Dir(installDir)
	if installParent == "/" || installDir == "/" {
		return map[string]any{"message": "stealth switch failed"}, fmt.Errorf("install dir %s must be nested below a parent directory so the hidden layout can randomize it", installDir)
	}
	configParent := filepath.Dir(r.configPath())
	stateParent := filepath.Dir(r.stateDir())
	identity, err := stealth.GenerateIdentity(stealth.CollisionCheck{
		InstallDir:    installDir,
		InstallParent: installParent,
		ConfigParent:  configParent,
		StateParent:   stateParent,
		LogDir:        "/var/log",
		RunDir:        "/run",
		SystemdUnits:  unitDirIf(manager == "systemd", "/etc/systemd/system"),
		InitDir:       unitDirIf(manager == "openrc", "/etc/init.d"),
	})
	if err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	hiddenInstallDir := filepath.Join(installParent, identity.InstallDirName)
	if _, statErr := os.Lstat(hiddenInstallDir); statErr == nil {
		return map[string]any{"message": "stealth switch failed"}, fmt.Errorf("refusing to reuse existing directory %s", hiddenInstallDir)
	}
	if err := os.Mkdir(hiddenInstallDir, 0o755); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	layout := stealth.ResolveLayout(identity, hiddenInstallDir, configParent, stateParent)
	key, err := stealth.GenerateKey()
	if err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	// Quiesce the managed child processes so their PID files and logs stop
	// moving while the state tree is copied; the new process restores them.
	if err := r.stopStealthManagedProcesses(); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	_ = r.persistTrafficCheckpointBeforeRuntimeTransition(context.Background())
	// Copy binaries under their new names.
	for _, pair := range []struct{ from, to string }{
		{agentPath, layout.AgentBinary},
		{r.coreBinary(), layout.CoreBinary},
		{r.realmBinary(), layout.RealmBinary},
	} {
		if pair.from == "" {
			continue
		}
		if _, statErr := os.Lstat(pair.to); statErr == nil {
			return map[string]any{"message": "stealth switch failed"}, fmt.Errorf("refusing to overwrite existing file %s", pair.to)
		}
		if err := copyFileMode(pair.from, pair.to, 0o755); err != nil {
			return map[string]any{"message": "stealth switch failed"}, err
		}
	}
	if err := os.MkdirAll(layout.ConfigDir, 0o700); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if err := os.MkdirAll(layout.StateDir, 0o700); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if err := stealth.SaveKey(layout.KeyPath, key); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	// Migrate the state tree: every file is copied encrypted under its
	// derived physical name; the acme home keeps its external-tool format.
	if err := migrateStateTreeEncrypt(r.stateDir(), layout.StateDir, key); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	// Migrate local-security.json into the new config directory.
	if err := migrateLocalSecurity(r.configPath(), layout.ConfigDir, key, true); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	next := cfg
	next.ConfigPath = layout.ConfigPath
	next.StateDir = layout.StateDir
	next.CoreBinary = layout.CoreBinary
	next.CoreService = layout.CoreService
	next.AgentService = layout.AgentService
	next.CoreSocket = layout.CoreSocket
	previousConfigDir := "/etc/oboard-agent"
	if strings.TrimSpace(configParent) != "" {
		previousConfigDir = configParent
	}
	previousLayout := stealth.PreviousLayout{
		InstallDir:   installDir,
		AgentBinary:  agentPath,
		CoreBinary:   r.coreBinary(),
		RealmBinary:  r.realmBinary(),
		AgentService: "oboard-agent",
		CoreService:  r.coreService(),
		ConfigDir:    previousConfigDir,
		ConfigPath:   r.configPath(),
		StateDir:     r.stateDir(),
		AgentLog:     r.agentLogPath(),
		CoreLog:      r.coreLogPath(),
		CoreSocket:   coreSocketOrDefault(cfg.CoreSocket),
	}
	next.Stealth = &stealth.Settings{
		Identity: identity,
		KeyPath:  layout.KeyPath,
		Previous: &previousLayout,
		Origin:   &previousLayout,
	}
	next.StealthKey = key
	if err := next.Validate(); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if err := SaveConfigWithKey(layout.ConfigPath, next, key); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	// Self-verification before anything is stopped: the new config must load
	// and validate with the key we just wrote.
	if _, err := LoadConfigWithKey(layout.ConfigPath, key); err != nil {
		return map[string]any{"message": "stealth switch failed"}, fmt.Errorf("verify new encrypted config: %w", err)
	}
	units := stealthUnits{Layout: layout, Identity: identity, Manager: manager, UnitDir: unitDirForManager(manager), KeyPath: layout.KeyPath, key: key}
	if err := units.write(); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if err := units.enable(); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	// From here the runner speaks the new layout.
	r.storeConfig(next)
	// Switch the kernel onto the new unit. The configuration bytes are
	// identical, so this is a restart, not a redeploy.
	coreSwitch := r.switchCoreService(manager, r.coreService(), layout.CoreService, layout)
	if coreSwitch != nil {
		return map[string]any{"message": "stealth switch failed", "agent_service": layout.AgentService, "core_service": layout.CoreService}, coreSwitch
	}
	// Disable the old units so a reboot cannot start both layouts.
	disableServiceUnits(manager, "oboard-agent", r.Config().Stealth.Previous.CoreService)
	r.armStealthSwitchFinalizer("oboard-agent", layout.AgentService, manager)
	logging.Infof("stealth layout enabled agent_service=%s core_service=%s", layout.AgentService, layout.CoreService)
	return map[string]any{
		"message":         "安全进程布局已启用，Agent 将在回执后重启",
		"stealth_enabled": true,
		"agent_service":   layout.AgentService,
		"core_service":    layout.CoreService,
		"restart":         "after_result_acknowledged",
	}, nil
}

// disableStealthLocked restores the standard layout from a hidden one.
func (r *Runner) disableStealthLocked(manager string) (result map[string]any, switchErr error) {
	cfg := r.Config()
	if !r.stealthOn() || cfg.Stealth == nil {
		return map[string]any{"message": "not running in the security-process layout", "stealth_enabled": false, "idempotent_replay": true}, nil
	}
	key := cfg.StealthKey
	agentPath, err := selfExecutablePath()
	if err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	installDir := filepath.Dir(agentPath)
	// Restore the layout this installation switched away from. Origin is
	// recorded at enable time; the defaults cover a config that predates it.
	configPath := "/etc/oboard-agent/config.json"
	configDir := "/etc/oboard-agent"
	stateDir := "/var/lib/oboard-agent"
	originAgentBinary := filepath.Join(installDir, "oboard-agent")
	originCoreBinary := filepath.Join(installDir, "oboard-sb")
	originRealmBinary := filepath.Join(installDir, "oboard-realm")
	if origin := cfg.Stealth.Origin; origin != nil {
		if strings.TrimSpace(origin.ConfigPath) != "" {
			configPath = origin.ConfigPath
			configDir = filepath.Dir(configPath)
		}
		if strings.TrimSpace(origin.StateDir) != "" {
			stateDir = origin.StateDir
		}
		if strings.TrimSpace(origin.AgentBinary) != "" {
			originAgentBinary = origin.AgentBinary
		}
		if strings.TrimSpace(origin.CoreBinary) != "" {
			originCoreBinary = origin.CoreBinary
		}
		if strings.TrimSpace(origin.RealmBinary) != "" {
			originRealmBinary = origin.RealmBinary
		}
	}
	// A failed handoff may have started the replacement. Verify its origin
	// before stopping it, and never resume the old core alongside it.
	if restored, err := LoadConfig(configPath); err == nil && restored.Stealth != nil && restored.Stealth.Previous != nil {
		if restored.Stealth.Previous.ConfigPath != cfg.ConfigPath || restored.Stealth.Identity != cfg.Stealth.Identity {
			return map[string]any{"message": "stealth switch failed"}, errors.New("restored layout belongs to another installation")
		}
		if err := stealthServiceAction(manager, "oboard-sb", "stop"); err != nil {
			return map[string]any{"message": "stealth switch failed"}, err
		}
	}
	_ = r.persistTrafficCheckpointBeforeRuntimeTransition(context.Background())
	if err := stealthServiceAction(manager, cfg.CoreService, "stop"); err != nil {
		return map[string]any{"message": "stealth switch failed"}, fmt.Errorf("stop previous core: %w", err)
	}
	unitsChanged := false
	defer func() {
		if switchErr == nil {
			return
		}
		if r.coreService() != cfg.CoreService {
			stopErr := stealthServiceAction(manager, "oboard-sb", "stop")
			r.storeConfig(cfg)
			if stopErr != nil {
				switchErr = errors.Join(switchErr, fmt.Errorf("rollback refused to restart previous core: %w", stopErr))
				return
			}
		}
		if unitsChanged {
			standard := stealthUnits{Manager: manager, Layout: stealth.Layout{AgentService: "oboard-agent", CoreService: "oboard-sb"}}
			previous := stealthUnits{Manager: manager, Layout: stealth.Layout{AgentService: cfg.AgentService, CoreService: cfg.CoreService}}
			switchErr = errors.Join(switchErr, standard.disable(), previous.enable())
		}
		if deployed, err := r.stateRead(singBoxConfigFile); err == nil && len(deployed) > 0 {
			switchErr = errors.Join(switchErr, stealthServiceAction(manager, cfg.CoreService, "start"))
		}
	}()
	if err := r.stopStealthManagedProcesses(); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	// The origin install directory may have been removed by the post-enable
	// cleanup; recreate it before the binaries are restored into it.
	if err := os.MkdirAll(filepath.Dir(originAgentBinary), 0o755); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	for _, pair := range []struct{ from, to string }{
		{agentPath, originAgentBinary},
		{r.coreBinary(), originCoreBinary},
		{r.realmBinary(), originRealmBinary},
	} {
		if pair.from == "" {
			continue
		}
		if err := copyStealthRestoreBinary(pair.from, pair.to); err != nil {
			return map[string]any{"message": "stealth switch failed"}, err
		}
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	// Migrate state back: list-driven, decrypting each entry to its logical
	// name in the standard state directory.
	if err := migrateStateTreeDecrypt(r.stateDir(), stateDir, key); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if err := migrateLocalSecurity(r.configPath(), configDir, key, false); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	next := cfg
	next.ConfigPath = configPath
	next.StateDir = stateDir
	next.CoreBinary = originCoreBinary
	next.CoreService = "oboard-sb"
	next.AgentService = "oboard-agent"
	next.CoreSocket = ""
	next.StealthKey = nil
	next.Stealth = &stealth.Settings{
		Identity: cfg.Stealth.Identity,
		KeyPath:  cfg.Stealth.KeyPath,
		// Origin survives the disable so the restored standard layout keeps
		// its operator-chosen install root trusted while this process still
		// runs from the hidden directory.
		Origin: cfg.Stealth.Origin,
		Previous: &stealth.PreviousLayout{
			InstallDir:   installDir,
			AgentBinary:  agentPath,
			CoreBinary:   r.coreBinary(),
			RealmBinary:  r.realmBinary(),
			AgentService: cfg.AgentService,
			CoreService:  cfg.CoreService,
			ConfigDir:    filepath.Dir(cfg.ConfigPath),
			ConfigPath:   cfg.ConfigPath,
			KeyPath:      cfg.Stealth.KeyPath,
			StateDir:     r.stateDir(),
			AgentLog:     r.agentLogPath(),
			CoreLog:      r.coreLogPath(),
			CoreSocket:   coreSocketOrDefault(cfg.CoreSocket),
			Stealth:      true,
		},
	}
	if err := next.Validate(); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if err := SaveConfig(configPath, next); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	if _, err := LoadConfig(configPath); err != nil {
		return map[string]any{"message": "stealth switch failed"}, fmt.Errorf("verify restored config: %w", err)
	}
	if err := writeStandardUnits(manager, filepath.Dir(originAgentBinary), configPath, stateDir, originAgentBinary, originCoreBinary); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	unitsChanged = true
	if err := enableStandardUnits(manager); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	r.storeConfig(next)
	coreSwitch := r.switchCoreService(manager, cfg.CoreService, "oboard-sb", stealth.Layout{CoreSocket: coreAPISocket, StateDir: stateDir})
	if coreSwitch != nil {
		return map[string]any{"message": "stealth switch failed"}, coreSwitch
	}
	stealthIdentity := cfg.Stealth.Identity
	units := stealthUnits{Layout: stealth.ResolveLayout(stealthIdentity, installDir, filepath.Dir(cfg.ConfigPath), filepath.Dir(cfg.StateDir)), Identity: stealthIdentity, Manager: manager, UnitDir: unitDirForManager(manager), KeyPath: cfg.Stealth.KeyPath, key: key}
	if err := units.disable(); err != nil {
		return map[string]any{"message": "stealth switch failed"}, err
	}
	r.armStealthSwitchFinalizer(cfg.AgentService, "oboard-agent", manager)
	logging.Infof("stealth layout disabled; standard layout restored")
	return map[string]any{
		"message":         "安全进程布局已停用，Agent 将在回执后重启",
		"stealth_enabled": false,
		"agent_service":   "oboard-agent",
		"core_service":    "oboard-sb",
		"restart":         "after_result_acknowledged",
	}, nil
}

// stopStealthManagedProcesses quiesces the agent-managed child processes
// (realm forwarding and tunnel sshd/ssh clients) before a layout switch so
// their state files stop moving while the tree is copied. The desired state
// is preserved; the restarted agent restores them.
func (r *Runner) stopStealthManagedProcesses() error {
	if err := stopManagedProcess(r.statePath(realmPIDFile)); err != nil {
		return err
	}
	dir := r.stateDirPath(tunnelsDir)
	result := tunnelApplyResult{Capabilities: detectTunnelCapabilities(), Tunnels: map[string]string{}, Warnings: []string{}}
	if err := r.stopManagedTunnels(dir, &result); err != nil {
		return err
	}
	return nil
}

// copyStealthRestoreBinary publishes a complete copy without overwriting an
// unrelated file. An identical regular file is a completed step of a retry.
func copyStealthRestoreBinary(from, to string) error {
	if info, err := os.Lstat(to); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
			return fmt.Errorf("refusing to overwrite existing file %s", to)
		}
		source, err := stealthFileDigest(from)
		if err != nil {
			return err
		}
		target, err := stealthFileDigest(to)
		if err != nil {
			return err
		}
		if source != target {
			return fmt.Errorf("refusing to overwrite existing file %s", to)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(to), ".restore-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	defer os.Remove(tmp)
	if err := copyFileMode(from, tmp, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Link(tmp, to)
}

func stealthFileDigest(path string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	file, err := os.Open(path)
	if err != nil {
		return digest, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return digest, err
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func stealthServiceAction(manager, service, action string) error {
	if manager == "systemd" {
		return stealthCommandRunner(20*time.Second, "systemctl", action, service)
	}
	if manager == "openrc" {
		return stealthCommandRunner(20*time.Second, "rc-service", service, action)
	}
	return errors.New("supported service manager is unavailable")
}

func copyFileMode(from, to string, perm os.FileMode) error {
	// #nosec G304 -- from/to are managed installation paths resolved by the caller.
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// rawCopyTree copies a directory tree verbatim (used for the acme home,
// whose files belong to an external tool and cannot be transformed).
func rawCopyTree(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstDir, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return copyFileMode(path, target, info.Mode().Perm())
	})
}

// migrateStateTreeEncrypt copies a standard (plaintext) state directory into
// a stealth one: top-level entries move to derived physical names, file
// contents become envelopes, and the acme home is copied verbatim.
func migrateStateTreeEncrypt(srcDir, dstDir string, key []byte) error {
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	encrypted := func(data []byte) ([]byte, error) { return stealth.Encrypt(key, data) }
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		src := filepath.Join(srcDir, name)
		if entry.IsDir() {
			dst := filepath.Join(dstDir, stealth.PhysicalName(key, name))
			if name == "acme" {
				if err := rawCopyTree(src, dst); err != nil {
					return err
				}
				continue
			}
			if err := transformTree(src, dst, encrypted); err != nil {
				return err
			}
			continue
		}
		if !entry.Type().IsRegular() {
			continue
		}
		// Transient deployment candidates are not worth carrying over.
		if strings.HasPrefix(name, "sing-box.") && strings.HasSuffix(name, ".json") && name != singBoxConfigFile && name != singBoxLastGoodFile {
			continue
		}
		data, err := os.ReadFile(src) // #nosec G304 -- src is inside the managed state directory.
		if err != nil {
			return err
		}
		physical := statePhysicalName(key, name)
		if plaintextStateFile(name) {
			if err := os.WriteFile(filepath.Join(dstDir, physical), data, 0o600); err != nil {
				return err
			}
			continue
		}
		sealed, err := encrypted(data)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dstDir, physical), sealed, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// plaintextStateFile reports whether a state file stays unencrypted: PID
// records and the flock target carry no secrets and are read by generic code.
func plaintextStateFile(name string) bool {
	return strings.HasSuffix(name, ".pid") || name == hostCoreLockName
}

// transformTree copies a directory tree keeping relative names, transforming
// regular file content with fn. PID files stay verbatim.
func transformTree(srcDir, dstDir string, fn func([]byte) ([]byte, error)) error {
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(srcDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dstDir, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path) // #nosec G304 -- path is inside the managed state tree.
		if err != nil {
			return err
		}
		if plaintextStateFile(entry.Name()) {
			return os.WriteFile(target, data, info.Mode().Perm())
		}
		transformed, err := fn(data)
		if err != nil {
			return err
		}
		return os.WriteFile(target, transformed, 0o600)
	})
}

// migrateStateTreeDecrypt restores a stealth state directory to the standard
// plaintext layout. It is list-driven: every known logical entry (including
// the suffix variants) is read from its derived physical name, decrypted, and
// written under its logical name. Unknown leftovers are skipped and logged.
func migrateStateTreeDecrypt(srcDir, dstDir string, key []byte) error {
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	decrypted := func(data []byte) ([]byte, error) {
		if !stealth.IsEncrypted(data) {
			return data, nil
		}
		return stealth.Decrypt(key, data)
	}
	for _, name := range allStateTopLevelFiles() {
		physical := statePhysicalName(key, name)
		src := filepath.Join(srcDir, physical)
		data, err := os.ReadFile(src) // #nosec G304 -- src is inside the managed state directory.
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		plain, err := decrypted(data)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, name), plain, 0o600); err != nil {
			return err
		}
	}
	for _, name := range stateTopLevelDirs {
		src := filepath.Join(srcDir, stealth.PhysicalName(key, name))
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(dstDir, name)
		if name == "acme" {
			if err := rawCopyTree(src, dst); err != nil {
				return err
			}
			continue
		}
		if err := transformTree(src, dst, decrypted); err != nil {
			return err
		}
	}
	// Report (but do not fail on) entries the list did not cover.
	entries, err := os.ReadDir(srcDir)
	if err == nil {
		known := map[string]bool{}
		for _, name := range allStateTopLevelFiles() {
			known[statePhysicalName(key, name)] = true
		}
		for _, name := range stateTopLevelDirs {
			known[stealth.PhysicalName(key, name)] = true
		}
		for _, entry := range entries {
			if !known[entry.Name()] {
				logging.Warnf("stealth disable: skipping unmapped state entry %s", entry.Name())
			}
		}
	}
	return nil
}

// migrateLocalSecurity moves local-security.json between layouts. In the
// stealth layout it lives under a derived name with encrypted content.
func migrateLocalSecurity(oldConfigPath, newConfigDir string, key []byte, encrypt bool) error {
	if encrypt {
		raw, err := os.ReadFile(agentsecurity.PathForConfig(oldConfigPath)) // #nosec G304 -- derived from the managed config path.
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if len(raw) == 0 {
			return nil
		}
		sealed, err := stealth.Encrypt(key, raw)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(newConfigDir, stealth.PhysicalName(key, "local-security.json")), sealed, 0o600)
	}
	sealed, err := os.ReadFile(filepath.Join(filepath.Dir(oldConfigPath), stealth.PhysicalName(key, "local-security.json"))) // #nosec G304 -- derived from the managed config path.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	plain := sealed
	if stealth.IsEncrypted(sealed) {
		if plain, err = stealth.Decrypt(key, sealed); err != nil {
			return err
		}
	}
	return os.WriteFile(agentsecurity.PathForConfig(filepath.Join(newConfigDir, "config.json")), plain, 0o600)
}

// unitDirForManager resolves the unit directory for a manager. It is a var
// so tests can redirect unit writes away from the real /etc.
var unitDirForManager = func(manager string) string {
	if manager == "openrc" {
		return "/etc/init.d"
	}
	return "/etc/systemd/system"
}

func serviceUnitPath(manager, service string) string {
	if manager == "openrc" {
		return filepath.Join("/etc/init.d", service)
	}
	return filepath.Join("/etc/systemd/system", service+".service")
}

// disableServiceUnits disables (but does not remove) units so a reboot cannot
// start both layouts; removal happens in the post-switch cleanup.
// stealthCommandRunner is a seam so tests can observe (and neutralize) the
// service-manager invocations of a layout switch.
var stealthCommandRunner = runCommand

func disableServiceUnits(manager string, services ...string) {
	for _, service := range services {
		if strings.TrimSpace(service) == "" {
			continue
		}
		if manager == "systemd" {
			_ = stealthCommandRunner(15*time.Second, "systemctl", "disable", service)
			continue
		}
		_ = stealthCommandRunner(15*time.Second, "rc-update", "del", service, "default")
	}
	if manager == "systemd" {
		_ = stealthCommandRunner(15*time.Second, "systemctl", "daemon-reload")
	}
}

// switchCoreService stops the old core unit and starts the new one, then
// verifies the running kernel still serves the deployed configuration. A nil
// return means the kernel is serving on the new unit (or no configuration is
// deployed yet, in which case the new unit simply stays enabled).
func (r *Runner) switchCoreService(manager, oldService, newService string, layout stealth.Layout) error {
	if oldService == newService {
		return nil
	}
	if deployed, err := r.stateRead(singBoxConfigFile); err != nil || len(deployed) == 0 {
		// Nothing deployed yet: the new unit starts with the first apply.
		return nil
	}
	if err := stealthServiceAction(manager, oldService, "stop"); err != nil {
		return fmt.Errorf("stop core service %s: %w", oldService, err)
	}
	if err := stealthServiceAction(manager, newService, "start"); err != nil {
		return fmt.Errorf("start core service %s: %w", newService, err)
	}
	if err := r.waitCoreServiceStable(10 * time.Second); err != nil {
		return fmt.Errorf("core service %s did not stay running: %w", newService, err)
	}
	desired, err := r.stateRead(singBoxConfigFile)
	if err != nil {
		return err
	}
	check := r.awaitCoreRuntimeConfig(context.Background(), desired, r.coreRuntimeVerifyWindow())
	if check.drift() {
		return fmt.Errorf("core runs configuration %s after the switch, expected %s", check.LoadedDigest, check.DesiredDigest)
	}
	return nil
}

// armStealthSwitchFinalizer records the pending service handoff. The task
// worker executes it after the result is acknowledged: the old agent unit is
// stopped and the new one started, so the two layouts never run at once.
func (r *Runner) armStealthSwitchFinalizer(oldService, newService, manager string) {
	r.stealthSwitchMu.Lock()
	defer r.stealthSwitchMu.Unlock()
	pending := &stealthSwitchFinalizer{OldService: oldService, NewService: newService, Manager: manager, NewCore: r.coreService()}
	if cfg := r.Config(); cfg.Stealth != nil && cfg.Stealth.Previous != nil {
		pending.OldCore = cfg.Stealth.Previous.CoreService
		deployed, err := r.stateRead(singBoxConfigFile)
		pending.RestoreCore = err == nil && len(deployed) > 0
	}
	r.stealthSwitchPending = pending
}

type stealthSwitchFinalizer struct {
	OldService  string
	NewService  string
	Manager     string
	OldCore     string
	NewCore     string
	RestoreCore bool
}

func (p stealthSwitchFinalizer) handoffCommand() string {
	service := func(name, action string) string {
		if p.Manager == "systemd" {
			return "systemctl " + action + " " + shellQuoteValue(name)
		}
		return "rc-service " + shellQuoteValue(name) + " " + action
	}
	unit := func(name string, enable bool) string {
		if name == "" {
			return ""
		}
		action := "disable"
		if enable {
			action = "enable"
		}
		if p.Manager == "systemd" {
			return "systemctl " + action + " " + shellQuoteValue(name) + " || exit 1; "
		}
		action = "del"
		if enable {
			action = "add"
		}
		return "rc-update " + action + " " + shellQuoteValue(name) + " default || exit 1; "
	}
	rollback := service(p.NewService, "stop") + " || exit 1; "
	if p.NewCore != "" && p.NewCore != p.OldCore {
		rollback += service(p.NewCore, "stop") + " || exit 1; "
	}
	rollback += unit(p.NewService, false) + unit(p.NewCore, false) + unit(p.OldService, true) + unit(p.OldCore, true)
	if p.RestoreCore && p.OldCore != "" && p.NewCore != p.OldCore {
		rollback += service(p.OldCore, "start") + " || exit 1; "
	}
	rollback += service(p.OldService, "start") + "; exit 1"
	return service(p.OldService, "stop") + " || exit 1; if " + service(p.NewService, "restart") + "; then exit 0; fi; " + rollback
}

// runStealthSwitchFinalizer schedules the one-shot handoff five seconds out,
// mirroring the update restart: report first, then switch processes.
func (r *Runner) runStealthSwitchFinalizer() error {
	r.stealthSwitchMu.Lock()
	pending := r.stealthSwitchPending
	r.stealthSwitchMu.Unlock()
	if pending == nil {
		return nil
	}
	command := ""
	switch pending.Manager {
	case "systemd":
		command = pending.handoffCommand()
		unit := fmt.Sprintf("%s-switch-%d", pending.NewService, os.Getpid())
		return stealthCommandRunner(10*time.Second, "systemd-run", "--quiet", "--collect", "--on-active=5s", "--unit", unit, "/bin/sh", "-c", command)
	case "openrc":
		command = "sleep 5; " + pending.handoffCommand()
		return stealthCommandRunner(5*time.Second, "sh", "-c", "nohup sh -c "+shellQuoteValue(command)+" >/dev/null 2>&1 &")
	default:
		return fmt.Errorf("supported service manager is unavailable; restart %s manually", pending.NewService)
	}
}

// reconcileStealthSwitchCleanup runs at agent start and removes the layout a
// completed switch left behind. It only acts when this process already runs
// from the new layout, so a stale old process can never delete the new one.
func (r *Runner) reconcileStealthSwitchCleanup() {
	cfg := r.Config()
	if cfg.Stealth == nil || cfg.Stealth.Previous == nil {
		return
	}
	previous := *cfg.Stealth.Previous
	selfPath, err := selfExecutablePath()
	if err != nil {
		return
	}
	// A process holding this config but still running from the previous
	// binary is not the switched agent (for example an old unit that came
	// back); it must not delete the layout it is part of.
	if previous.AgentBinary != "" && previous.AgentBinary == selfPath {
		logging.Infof("stealth cleanup skipped: still running from the previous binary %s", selfPath)
		return
	}
	manager := serviceManager()
	// Stop and remove the previous units first so a later reboot cannot
	// resurrect them.
	if manager == "systemd" || manager == "openrc" {
		if previous.AgentService != "" && previous.AgentService != r.agentService() {
			if err := stealthServiceAction(manager, previous.AgentService, "stop"); err != nil {
				logging.Errorf("stealth cleanup: stop previous service: %v", err)
				return
			}
		}
		if previous.CoreService != "" && previous.CoreService != r.coreService() {
			if err := stealthServiceAction(manager, previous.CoreService, "stop"); err != nil {
				logging.Errorf("stealth cleanup: stop previous service: %v", err)
				return
			}
		}
		disableServiceUnits(manager, previous.AgentService, previous.CoreService)
		for _, service := range []string{previous.AgentService, previous.CoreService} {
			if service == "" || service == r.agentService() || service == r.coreService() {
				continue
			}
			_ = os.Remove(serviceUnitPath(manager, service))
		}
		if manager == "systemd" {
			_ = runCommand(15*time.Second, "systemctl", "daemon-reload")
		}
	}
	// Remove previous binaries, directories, logs, socket, and key file.
	current := map[string]bool{
		selfPath:        true,
		r.coreBinary():  true,
		r.realmBinary(): true,
		r.configPath():  true,
		r.stateDir():    true,
		agentsecurity.PathForConfig(r.configPath()): true,
	}
	if cfg.Stealth != nil {
		current[cfg.Stealth.KeyPath] = true
	}
	removeIfNotIn(previous.AgentBinary, current)
	removeIfNotIn(previous.CoreBinary, current)
	removeIfNotIn(previous.RealmBinary, current)
	removeIfNotIn(previous.ConfigPath, current)
	removeIfNotIn(previous.KeyPath, current)
	removeIfNotIn(previous.StateDir, current)
	removeIfNotIn(previous.AgentLog, current)
	removeIfNotIn(previous.CoreLog, current)
	removeIfNotIn(previous.CoreSocket, current)
	if previous.ConfigDir != "" && previous.ConfigDir != filepath.Dir(r.configPath()) {
		removeIfNotIn(previous.ConfigDir, current)
	}
	// Remove the previous installation directory once its known contents
	// are gone. os.Remove only succeeds on an empty directory, so anything
	// else an operator keeps there survives; the standard layout's obag
	// helper symlink is a known leftover of the switched-away layout.
	if previous.InstallDir != "" && previous.InstallDir != "/" && previous.InstallDir != filepath.Dir(selfPath) {
		if target, linkErr := os.Readlink(filepath.Join(previous.InstallDir, "obag")); linkErr == nil && filepath.Clean(target) == previous.AgentBinary {
			_ = os.Remove(filepath.Join(previous.InstallDir, "obag"))
		}
		if err := os.Remove(previous.InstallDir); err == nil {
			logging.Infof("stealth cleanup removed the previous install directory %s", previous.InstallDir)
		}
	}
	// Drop the previous record so cleanup runs exactly once; Origin survives
	// so a later disable still restores the original layout.
	next := cfg
	next.Stealth = &stealth.Settings{Identity: cfg.Stealth.Identity, KeyPath: cfg.Stealth.KeyPath, Origin: cfg.Stealth.Origin}
	if err := r.saveAgentConfig(next); err != nil {
		logging.Warnf("stealth cleanup: persist config without previous layout: %v", err)
		return
	}
	r.storeConfig(next)
	logging.Infof("stealth cleanup removed the previous layout")
}

func removeIfNotIn(path string, keep map[string]bool) {
	path = strings.TrimSpace(path)
	if path == "" || keep[path] || path == "/" {
		return
	}
	if err := os.RemoveAll(path); err != nil {
		logging.Warnf("stealth cleanup: remove %s: %v", path, err)
	}
}

// writeStandardUnits writes the standard (oboard-named) service units used by
// the standard layout. They mirror the Controller installer's units.
func writeStandardUnits(manager, installDir, configPath, stateDir, agentBinary, coreBinary string) error {
	if manager == "openrc" {
		agentUnit := fmt.Sprintf(`#!/sbin/openrc-run

description="OBoard Agent"
command=%s
command_args="-config %s"
supervisor=supervise-daemon
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/${RC_SVCNAME}.log"
error_log="/var/log/${RC_SVCNAME}.log"
respawn_delay=5
respawn_max=0

depend() {
  need net
  after firewall
}

start_pre() {
  checkpath -d -m 0700 %s %s
}
`, agentBinary, configPath, filepath.Dir(configPath), stateDir)
		coreUnit := fmt.Sprintf(`#!/sbin/openrc-run

description="OBoard optimized sing-box kernel"
command=%s
command_args="-config %s -api unix:%s"
supervisor=supervise-daemon
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/${RC_SVCNAME}.log"
error_log="/var/log/${RC_SVCNAME}.log"
respawn_delay=3
respawn_max=0

depend() {
  need net
  after firewall
}

start_pre() {
  checkpath -d -m 0700 %s
}
`, coreBinary, filepath.Join(stateDir, "sing-box.json"), coreAPISocket, stateDir)
		unitDir := unitDirForManager("openrc")
		if err := os.MkdirAll(unitDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(unitDir, "oboard-agent"), []byte(agentUnit), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(unitDir, "oboard-sb"), []byte(coreUnit), 0o755)
	}
	agentUnit := fmt.Sprintf(`[Unit]
Description=OBoard Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s -config %s
StandardOutput=append:/var/log/oboard-agent.log
StandardError=append:/var/log/oboard-agent.log
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=false
ProtectHome=true
ReadWritePaths=%s %s %s /var/log /run
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
ProtectKernelTunables=false
ProtectControlGroups=false
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, agentBinary, configPath, installDir, filepath.Dir(configPath), stateDir)
	coreUnit := fmt.Sprintf(`[Unit]
Description=OBoard optimized sing-box kernel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -config %s -api unix:%s
StandardOutput=append:/var/log/oboard-sb.log
StandardError=append:/var/log/oboard-sb.log
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=%s /var/log /run
LockPersonality=true
ProtectKernelTunables=false
ProtectControlGroups=false
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, coreBinary, filepath.Join(stateDir, "sing-box.json"), coreAPISocket, stateDir)
	unitDir := unitDirForManager("systemd")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(unitDir, "oboard-agent.service"), []byte(agentUnit), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(unitDir, "oboard-sb.service"), []byte(coreUnit), 0o644)
}

func enableStandardUnits(manager string) error {
	if manager == "systemd" {
		if err := stealthCommandRunner(15*time.Second, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		return stealthCommandRunner(15*time.Second, "systemctl", "enable", "oboard-agent", "oboard-sb")
	}
	if err := stealthCommandRunner(15*time.Second, "rc-update", "add", "oboard-agent", "default"); err != nil {
		return err
	}
	return stealthCommandRunner(15*time.Second, "rc-update", "add", "oboard-sb", "default")
}

// LoadStealthKeyFile reads a stealth key file (the -key flag target).
func LoadStealthKeyFile(path string) ([]byte, error) {
	return stealth.LoadKey(path)
}

// StealthBootstrapOptions is the exported form of stealthBootstrapOptions for
// the installer verb in cmd/agent.
type StealthBootstrapOptions = stealthBootstrapOptions
