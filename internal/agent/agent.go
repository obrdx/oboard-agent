package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OboardProject/oboard-agent/internal/agentlink"
	"github.com/OboardProject/oboard-agent/internal/authorization"
	"github.com/OboardProject/oboard-agent/internal/core"
	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/nexttrace"
	"github.com/OboardProject/oboard-agent/internal/redact"
	"github.com/OboardProject/oboard-agent/internal/securefile"
	"github.com/OboardProject/oboard-agent/internal/security"
	"github.com/OboardProject/oboard-agent/internal/stealth"
	"github.com/OboardProject/oboard-agent/internal/version"
)

type Config struct {
	agentLinkMigrationPending bool
	ConfigPath                string                   `json:"-"`
	ControllerAddr            string                   `json:"controller_addr"`
	ControllerCertSHA256      string                   `json:"controller_cert_sha256"`
	ControllerURL             string                   `json:"controller_url"`
	ServerID                  int64                    `json:"server_id"`
	AgentID                   string                   `json:"agent_id"`
	AgentToken                string                   `json:"agent_token"`
	StateDir                  string                   `json:"state_dir"`
	CoreBinary                string                   `json:"core_binary"`
	CoreService               string                   `json:"core_service"`
	AgentService              string                   `json:"agent_service,omitempty"`
	CoreSocket                string                   `json:"core_socket,omitempty"`
	Stealth                   *stealth.Settings        `json:"stealth,omitempty"`
	ResourceProfile           string                   `json:"resource_profile"`
	CommandTimeoutSeconds     int                      `json:"command_timeout_seconds"`
	ReloadCommand             string                   `json:"reload_command"`
	RestartCommand            string                   `json:"restart_command"`
	TimeSyncCommand           string                   `json:"time_sync_command"`
	TimeCorrectionMode        model.TimeCorrectionMode `json:"time_correction_mode"`
	LogLevel                  string                   `json:"log_level"`
	LogLevelExpiresAt         string                   `json:"log_level_expires_at,omitempty"`
	LogMaxMB                  int                      `json:"log_max_mb"`
	LogBackups                int                      `json:"log_backups"`
	CoreLogMaxMB              int                      `json:"core_log_max_mb"`
	CoreLogBackups            int                      `json:"core_log_backups"`
	LogBackupsSet             bool                     `json:"-"`
	CoreLogBackupsSet         bool                     `json:"-"`
	LogMaxMBSet               bool                     `json:"-"`
	CoreLogMaxMBSet           bool                     `json:"-"`
	StorageProfile            string                   `json:"storage_profile"`
	WarpCommand               string                   `json:"warp_command"`
	UpdateSource              string                   `json:"update_source"`
	AllowPanelUpdate          bool                     `json:"allow_panel_update"`
	AllowInsecureController   bool                     `json:"allow_insecure_controller"`
	UpdateRepo                string                   `json:"update_repo,omitempty"`
	ConnectionAuditEnabled    bool                     `json:"connection_audit_enabled"`
	// StealthKey holds the raw stealth key at runtime when the agent was
	// started with -key. It is never serialized: the key lives only in the
	// key file and in memory.
	StealthKey []byte `json:"-"`
}

type Runner struct {
	nextTraceOnce               sync.Once
	nextTraceGeo                *nexttrace.Client
	runtimeSecurityMu           sync.Mutex
	runtimeStorageMu            sync.RWMutex
	runtimeSecurityReport       atomic.Pointer[model.RuntimeSecurityReport]
	runtimeSecurityIntegrity    atomic.Pointer[[]model.RuntimeSecurityCheck]
	authorizationMu             sync.Mutex
	authorizationStore          *authorization.Store
	authorizationApplyMu        sync.Mutex
	authorizationSyncWake       chan struct{}
	vpngateOnce                 sync.Once
	vpngateState                *vpngateState
	runtimeUsersMu              sync.Mutex
	runtimeUsersApplyMu         sync.Mutex
	runtimeUsersCurrent         *model.UsersInstallRequest
	runtimeUsersApplied         *model.UsersAppliedSnapshot
	runtimeUsersBootID          string
	usersSyncWake               chan struct{}
	config                      atomic.Pointer[Config]
	client                      *http.Client
	coreClient                  *http.Client
	mu                          sync.Mutex
	probeMu                     sync.Mutex
	trafficMu                   sync.Mutex
	trafficReportWake           chan struct{}
	connectionAuditMu           sync.Mutex
	latencyProbeMu              sync.Mutex
	metricReportMu              sync.Mutex
	connectionAuditCoreMu       sync.Mutex
	deploymentMu                sync.Mutex
	sshInboundLifecycleMu       sync.Mutex
	tunnelLifecycleMu           sync.Mutex
	coreLifecycleMu             sync.Mutex
	forwardLifecycleMu          sync.Mutex
	logMu                       sync.Mutex
	syncLogMu                   sync.Mutex
	syncLogStates               map[string]syncLogState
	trafficHealthMu             sync.Mutex
	controllerAuth              controllerAuthBackoff
	trafficReportFailures       int
	trafficReportFailingSince   time.Time
	trafficReportLastLoggedAt   time.Time
	logDir                      string
	logMaintenanceEvery         time.Duration
	trafficState                trafficLocalState
	trafficStateLoaded          bool
	connectionAuditState        connectionAuditLocalState
	connectionAuditStateLoaded  bool
	latencyProbeState           latencyProbeLocalState
	latencyProbeStateLoaded     bool
	metricReportState           metricReportLocalState
	metricReportStateLoaded     bool
	metricReportWake            chan struct{}
	connectionAudit             *connectionAuditAccumulator
	connectionAuditCoreKnown    bool
	connectionAuditCoreEnabled  bool
	presenceCapabilityKnown     bool
	presenceCapabilityEnabled   bool
	presenceSequence            atomic.Uint64
	presencePendingMu           sync.Mutex
	presencePendingEvents       []connectionPresenceEvent
	presencePendingDropped      int64
	lastProbe                   model.HealthReport
	lastProbeAt                 time.Time
	lastLocalMetricsAt          time.Time
	lastPublicIPAt              time.Time
	lastPublicIPv4              string
	lastPublicIPv6              string
	lastRegionCode              string
	lastCoreVersion             string
	lastKernelCapabilities      []string
	lastCoreVersionAt           time.Time
	hostInfo                    hostStaticInfo
	lastCPUSample               procCPU
	lastNetworkSample           networkCounterSample
	monitoringMode              string
	coreBinaryCache             string
	coreServiceCache            string
	coreBinaryIdentityMu        sync.Mutex
	coreBinaryIdentity          coreBinaryIdentityCache
	forwardProbeRules           []model.PortForward
	lastForwardProbe            map[int64]time.Time
	clock                       *runtimeClock
	controllerClockMu           sync.RWMutex
	controllerReference         time.Time
	controllerReferenceAnchor   time.Time
	resources                   ResourceInfo
	tuning                      RuntimeTuning
	sshInboundManager           *sshInboundManager
	sshOutboundRelayDial        outboundRelayDialFunc
	sshRouteRelayDial           routeRelayDialFunc
	forwardDesiredState         string
	tunnelDesiredState          string
	sshInboundDesiredState      string
	sshInboundPendingPolicyPlan *model.SSHInboundPlan
	remoteExecMu                sync.Mutex
	remoteExecRuns              map[string]*remoteExecRun
	remoteExecLog               *remoteExecJournal
	interactiveMu               sync.Mutex
	terminalSessions            map[string]*terminalSession
	interactiveNonces           map[string]time.Time
	controlMu                   sync.Mutex
	controlSend                 func(payload any, wait bool) error
	agentRestartScheduled       atomic.Bool
	agentRestartCommand         func() error
	// coreRestartCommand overrides the service-manager restart in tests. A
	// nil value keeps the managed presets.
	coreRestartCommand func() error
	// coreServiceActiveCheck overrides the service liveness probe in tests.
	coreServiceActiveCheck func() error
	controllerLinkMu       sync.Mutex
	controllerLink         controllerLinkDiagnostics
	controlSessionMu       sync.Mutex
	controlSessionLink     *agentlink.Session
	stealthSwitchMu        sync.Mutex
	stealthSwitchPending   *stealthSwitchFinalizer

	// coreClockPID is the kernel process last given the logical clock; guarded by coreLifecycleMu.
	coreClockPID int
}

const (
	commandOutputLimit      = 64 << 10
	controllerResponseLimit = 2 << 20
)

func coreSocketOrDefault(socket string) string {
	if socket = strings.TrimSpace(socket); socket != "" {
		return socket
	}
	return coreAPISocket
}

const defaultUpdateRepo = "obrdx/oboard-agent"

func New(cfg Config) *Runner {
	cfg = normalizeConfig(cfg)
	resources := DetectResourceInfo(cfg.ResourceProfile)
	tuning := agentRuntimeTuning(resources)
	clock := newRuntimeClock(cfg.StateDir, cfg.StealthKey)
	profile := StorageProfile(strings.ToLower(strings.TrimSpace(cfg.StorageProfile)))
	if profile == StorageProfileAuto {
		profile = detectStorageProfile(cfg.StateDir, StorageProfileAuto)
	}
	runner := &Runner{coreClient: unixHTTPClient(coreSocketOrDefault(cfg.CoreSocket)), lastForwardProbe: map[int64]time.Time{}, resources: resources, tuning: tuning, hostInfo: detectHostStaticInfo(), logDir: platformLogDir(), logMaintenanceEvery: logMaintenanceIntervalForProfile(profile), monitoringMode: "lightweight", metricReportWake: make(chan struct{}, 1), authorizationSyncWake: make(chan struct{}, 1), trafficReportWake: make(chan struct{}, 1), usersSyncWake: make(chan struct{}, 1), connectionAudit: newConnectionAuditAccumulator(cfg.ConnectionAuditEnabled, clock.Now), clock: clock}
	runner.client = &http.Client{Timeout: 20 * time.Second, Transport: runner.lowOverheadTransport()}
	runner.storeConfig(cfg)
	runner.refreshLogLevel()
	return runner
}

func (cfg Config) Validate() error {
	if strings.TrimSpace(cfg.ControllerURL) != "" {
		if _, err := security.ValidateControllerURL(cfg.ControllerURL, version.IsDev(), cfg.AllowInsecureController); err != nil {
			return err
		}
	}
	if err := ValidateManagedCommand("reload_command", cfg.ReloadCommand); err != nil {
		return err
	}
	if err := ValidateManagedCommand("restart_command", cfg.RestartCommand); err != nil {
		return err
	}
	if err := ValidateManagedCommand("time_sync_command", cfg.TimeSyncCommand); err != nil {
		return err
	}
	if err := validateManagedPath("state_dir", cfg.StateDir); err != nil {
		return err
	}
	if err := cfg.validateCoreBinaryPath(); err != nil {
		return err
	}
	if err := validateServiceName(cfg.CoreService); err != nil {
		return err
	}
	if err := validateServiceName(cfg.AgentService); err != nil {
		return err
	}
	if err := validateSocketPath(cfg.CoreSocket); err != nil {
		return err
	}
	if cfg.Stealth != nil {
		if err := cfg.Stealth.Validate(); err != nil {
			return fmt.Errorf("stealth: %w", err)
		}
		if cfg.Stealth.KeyPath == cfg.ConfigPath {
			return fmt.Errorf("stealth key path must differ from the config path")
		}
	}
	if err := validateWarpCommand(cfg.WarpCommand); err != nil {
		return err
	}
	if !validResourceProfile(cfg.ResourceProfile) {
		return fmt.Errorf("resource_profile must be auto, small, or large")
	}
	if !validStorageProfile(cfg.StorageProfile) {
		return fmt.Errorf("storage_profile must be auto, tiny, small, or standard")
	}
	if cfg.CommandTimeoutSeconds < 5 || cfg.CommandTimeoutSeconds > 120 {
		return fmt.Errorf("command_timeout_seconds must be between 5 and 120")
	}
	if normalizeTimeCorrectionMode(cfg.TimeCorrectionMode) == "" {
		return fmt.Errorf("time_correction_mode must be off, auto, or ntp")
	}
	if cfg.LogMaxMB < 1 || cfg.LogMaxMB > 1024 {
		return fmt.Errorf("log_max_mb must be between 1 and 1024")
	}
	if cfg.CoreLogMaxMB < 1 || cfg.CoreLogMaxMB > 1024 {
		return fmt.Errorf("core_log_max_mb must be between 1 and 1024")
	}
	if cfg.LogBackups < 0 || cfg.LogBackups > 20 {
		return fmt.Errorf("log_backups must be between 0 and 20")
	}
	if cfg.CoreLogBackups < 0 || cfg.CoreLogBackups > 20 {
		return fmt.Errorf("core_log_backups must be between 0 and 20")
	}
	if _, ok := logging.ParseLevel(cfg.LogLevel); !ok {
		return fmt.Errorf("log_level must be trace, debug, info, warn, or error")
	}
	if cfg.LogLevelExpiresAt != "" {
		if _, err := time.Parse(logLevelExpiryLayout, cfg.LogLevelExpiresAt); err != nil {
			return fmt.Errorf("log_level_expires_at must be an RFC 3339 timestamp")
		}
	}
	return nil
}

func (r *Runner) Config() Config {
	if cfg := r.config.Load(); cfg != nil {
		return *cfg
	}
	return Config{}
}

func (r *Runner) storeConfig(cfg Config) {
	copy := cfg
	r.config.Store(&copy)
}

func (r *Runner) setControlSend(send func(payload any, wait bool) error) {
	r.controlMu.Lock()
	r.controlSend = send
	r.controlMu.Unlock()
}

func (r *Runner) sendControl(payload any) {
	r.controlMu.Lock()
	send := r.controlSend
	r.controlMu.Unlock()
	if send == nil {
		return
	}
	_ = send(payload, false)
}

func (r *Runner) stateDir() string {
	if stateDir := strings.TrimSpace(r.Config().StateDir); stateDir != "" {
		return stateDir
	}
	return DefaultStateDir()
}

// stealthOn reports whether this runner was started with a stealth key and
// therefore stores state files encrypted under derived physical names.
func (r *Runner) stealthOn() bool {
	return len(r.Config().StealthKey) == stealth.KeyLen
}

// statePath maps a logical state-file name to its on-disk path. In standard
// mode the logical name is the file name; in stealth mode it is the
// HMAC-derived physical name, so no OBoard marker ever appears on disk.
func (r *Runner) statePath(logical string) string {
	if r.stealthOn() {
		return filepath.Join(r.stateDir(), stealth.PhysicalName(r.Config().StealthKey, logical))
	}
	return filepath.Join(r.stateDir(), logical)
}

// stateDirPath maps a logical state-directory name ("tunnels", "warp", ...)
// to its on-disk directory path.
func (r *Runner) stateDirPath(logical string) string {
	return r.statePath(logical)
}

// stateRead reads a state file by logical name, decrypting when needed.
// A plaintext file in stealth mode is returned as-is (sniffed) so a crash
// between migration steps cannot wedge the agent on unreadable state.
func (r *Runner) stateRead(logical string) ([]byte, error) {
	return r.stateReadPath(r.statePath(logical))
}

// stateReadPath reads a state file by physical path, decrypting an envelope
// when the runner is in stealth mode.
func (r *Runner) stateReadPath(path string) ([]byte, error) {
	r.runtimeStorageMu.RLock()
	defer r.runtimeStorageMu.RUnlock()
	return r.stateReadPathUnlocked(path)
}
func (r *Runner) stateReadPathUnlocked(path string) ([]byte, error) {
	// #nosec G304 -- paths are derived from the agent state directory.
	data, err := securefile.Read(path, 32<<20)
	if err != nil {
		return nil, err
	}
	if r.stealthOn() && stealth.IsEncrypted(data) {
		data, err = stealth.Decrypt(r.Config().StealthKey, data)
		if err != nil {
			return nil, err
		}
	}
	return r.openRuntimeState(path, data)
}

// stateWrite writes a state file by logical name, encrypting in stealth mode.
func (r *Runner) stateWrite(logical string, data []byte, perm os.FileMode) error {
	return r.stateWritePath(r.statePath(logical), data, perm)
}

// stateWritePath writes a state file by physical path, encrypting in stealth
// mode. The temporary file used by the atomic rename is removed again, so no
// plaintext bytes survive on disk.
func (r *Runner) stateWritePath(path string, data []byte, perm os.FileMode) error {
	r.runtimeStorageMu.RLock()
	defer r.runtimeStorageMu.RUnlock()
	return r.stateWritePathUnlocked(path, data, perm)
}
func (r *Runner) stateWritePathUnlocked(path string, data []byte, perm os.FileMode) error {
	var protectErr error
	data, protectErr = r.protectRuntimeState(path, data)
	if protectErr != nil {
		return protectErr
	}
	if r.stealthOn() {
		encrypted, err := stealth.Encrypt(r.Config().StealthKey, data)
		if err != nil {
			return err
		}
		data = encrypted
	}
	return atomicWriteFile(path, data, perm)
}

// stateWritePathSynced writes a state file by physical path with an fsync
// before rename, encrypting in stealth mode. Used by traffic accounting,
// whose checkpoints must not be lost on a crash.
func (r *Runner) stateWritePathSynced(path string, data []byte, perm os.FileMode) error {
	r.runtimeStorageMu.RLock()
	defer r.runtimeStorageMu.RUnlock()
	return r.stateWritePathSyncedUnlocked(path, data, perm)
}
func (r *Runner) stateWritePathSyncedUnlocked(path string, data []byte, perm os.FileMode) error {
	var protectErr error
	data, protectErr = r.protectRuntimeState(path, data)
	if protectErr != nil {
		return protectErr
	}
	if r.stealthOn() {
		encrypted, err := stealth.Encrypt(r.Config().StealthKey, data)
		if err != nil {
			return err
		}
		data = encrypted
	}
	return atomicWriteFileWithSync(path, data, perm)
}

// agentService returns the agent's own service name.
func (r *Runner) agentService() string {
	if service := strings.TrimSpace(r.Config().AgentService); service != "" {
		return service
	}
	return "oboard-agent"
}

// coreAPISocketPath returns the kernel local API socket path.
func (r *Runner) coreAPISocketPath() string {
	if socket := strings.TrimSpace(r.Config().CoreSocket); socket != "" {
		return socket
	}
	return coreAPISocket
}

func LoadConfig(path string) (Config, error) {
	return loadConfigBytes(path, nil)
}

// LoadConfigWithKey reads a config that may be a stealth envelope. A nil key
// keeps legacy plaintext reading; a key decrypts an envelope and rejects a
// plaintext file so a missing key file can never silently downgrade an
// installation to plaintext.
func LoadConfigWithKey(path string, key []byte) (Config, error) {
	if len(key) == 0 {
		return LoadConfig(path)
	}
	cfg, err := loadConfigBytes(path, key)
	if err != nil {
		return Config{}, err
	}
	cfg.StealthKey = key
	return cfg, nil
}

func loadConfigBytes(path string, key []byte) (Config, error) {
	// #nosec G304,G703 -- path is an explicit local CLI flag, not a Controller task field.
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if len(key) > 0 {
		if !stealth.IsEncrypted(b) {
			return Config{}, errors.New("config file is not encrypted but a stealth key was provided")
		}
		if b, err = stealth.Decrypt(key, b); err != nil {
			return Config{}, err
		}
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err == nil {
		_, cfg.LogBackupsSet = fields["log_backups"]
		_, cfg.CoreLogBackupsSet = fields["core_log_backups"]
		_, cfg.LogMaxMBSet = fields["log_max_mb"]
		_, cfg.CoreLogMaxMBSet = fields["core_log_max_mb"]
	}
	return cfg, nil
}

func SaveConfig(path string, cfg Config) error {
	return saveConfigBytes(path, cfg, nil)
}

// SaveConfigWithKey writes the config as a stealth envelope when a key is
// present. The caller keeps ownership of the key; nothing here persists it.
func SaveConfigWithKey(path string, cfg Config, key []byte) error {
	return saveConfigBytes(path, cfg, key)
}

func saveConfigBytes(path string, cfg Config, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if len(key) > 0 {
		if b, err = stealth.Encrypt(key, b); err != nil {
			return err
		}
	}
	return securefile.Write(path, b, 0o600, true)
}

// saveAgentConfig persists cfg to the configured path, applying stealth
// encryption when this runner holds a key.
func (r *Runner) saveAgentConfig(cfg Config) error {
	path := strings.TrimSpace(cfg.ConfigPath)
	if path == "" {
		path = DefaultConfigPath()
	}
	return saveConfigBytes(path, cfg, r.Config().StealthKey)
}

func normalizeConfig(cfg Config) Config {
	// Preserve the certificate pin from the previous encrypted layout configuration.
	if cfg.Stealth != nil && (cfg.Stealth.ControllerAddr != "" || cfg.Stealth.ControllerCertSHA256 != "") {
		if cfg.ControllerAddr == "" && cfg.ControllerCertSHA256 == "" {
			cfg.ControllerAddr = cfg.Stealth.ControllerAddr
			cfg.ControllerCertSHA256 = cfg.Stealth.ControllerCertSHA256
		}
		previous := *cfg.Stealth
		previous.ControllerAddr, previous.ControllerCertSHA256 = "", ""
		cfg.Stealth = &previous
		cfg.agentLinkMigrationPending = true
	}

	if cfg.StateDir == "" {
		cfg.StateDir = DefaultStateDir()
	}
	if cfg.ResourceProfile == "" {
		cfg.ResourceProfile = string(ResourceProfileAuto)
	}
	cfg.ResourceProfile = strings.ToLower(strings.TrimSpace(cfg.ResourceProfile))
	if cfg.CommandTimeoutSeconds <= 0 {
		cfg.CommandTimeoutSeconds = 20
	}
	if cfg.RestartCommand == "" {
		cfg.RestartCommand = "auto"
	}
	if cfg.ReloadCommand == "" {
		cfg.ReloadCommand = "auto"
	}
	if cfg.TimeSyncCommand == "" {
		cfg.TimeSyncCommand = "auto"
	}
	if normalizeTimeCorrectionMode(cfg.TimeCorrectionMode) == "" {
		cfg.TimeCorrectionMode = model.TimeCorrectionOff
	}
	if cfg.StorageProfile == "" {
		cfg.StorageProfile = string(StorageProfileAuto)
	}
	cfg.StorageProfile = strings.ToLower(strings.TrimSpace(cfg.StorageProfile))
	// Apply storage-profile defaults when user did not explicitly set log limits.
	storageProfile := StorageProfile(cfg.StorageProfile)
	if storageProfile == StorageProfileAuto {
		storageProfile = detectStorageProfile(cfg.StateDir, StorageProfileAuto)
	}
	var explicitAgentMax, explicitCoreMax *int
	var explicitAgentBackups, explicitCoreBackups *int
	if cfg.LogMaxMBSet {
		v := cfg.LogMaxMB
		explicitAgentMax = &v
	}
	if cfg.CoreLogMaxMBSet {
		v := cfg.CoreLogMaxMB
		explicitCoreMax = &v
	}
	if cfg.LogBackupsSet {
		v := cfg.LogBackups
		explicitAgentBackups = &v
	}
	if cfg.CoreLogBackupsSet {
		v := cfg.CoreLogBackups
		explicitCoreBackups = &v
	}
	defAgentMax, defAgentBackups, defCoreMax, defCoreBackups := logBudgetForProfile(storageProfile, explicitAgentMax, explicitAgentBackups, explicitCoreMax, explicitCoreBackups)
	if !cfg.LogMaxMBSet {
		if cfg.LogMaxMB <= 0 {
			cfg.LogMaxMB = defAgentMax
		}
	}
	if !cfg.LogBackupsSet {
		if cfg.LogBackups < 0 {
			cfg.LogBackups = 0
		} else if cfg.LogBackups == 0 {
			cfg.LogBackups = defAgentBackups
		}
	}
	if !cfg.CoreLogMaxMBSet {
		if cfg.CoreLogMaxMB <= 0 {
			cfg.CoreLogMaxMB = defCoreMax
		}
	}
	if !cfg.CoreLogBackupsSet {
		if cfg.CoreLogBackups < 0 {
			cfg.CoreLogBackups = 0
		} else if cfg.CoreLogBackups == 0 {
			cfg.CoreLogBackups = defCoreBackups
		}
	}
	cfg = normalizeLogLevelPolicy(cfg, time.Now())
	cfg.UpdateSource = strings.ToLower(strings.TrimSpace(cfg.UpdateSource))
	if cfg.UpdateRepo = strings.TrimSpace(cfg.UpdateRepo); cfg.UpdateRepo == "" {
		cfg.UpdateRepo = defaultUpdateRepo
	}
	if cfg.UpdateSource == "" || (cfg.UpdateSource != "panel" && cfg.UpdateSource != "github") {
		if version.IsDev() {
			cfg.UpdateSource = "panel"
			cfg.AllowPanelUpdate = true
		} else {
			cfg.UpdateSource = "github"
		}
	}
	return cfg
}

func validateManagedPath(field, value string, opts ...map[string][]string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	var allowedBasenames, allowedCoreDirs []string
	for _, opt := range opts {
		allowedBasenames = append(allowedBasenames, opt["basenames"]...)
		allowedCoreDirs = append(allowedCoreDirs, opt["coreDirs"]...)
	}
	basenameAllowed := func(base string) bool {
		for _, allowed := range allowedBasenames {
			if base == allowed {
				return true
			}
		}
		return false
	}
	coreDirAllowed := func(dir string) bool {
		if allowedCoreBinaryDir(dir) {
			return true
		}
		for _, allowed := range allowedCoreDirs {
			if dir == allowed {
				return true
			}
		}
		return false
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be an absolute path", field)
	}
	cleaned := filepath.Clean(value)
	if cleaned != value || strings.Contains(cleaned, "..") {
		return fmt.Errorf("%s must be a cleaned absolute path without dot-dot segments", field)
	}
	if i := strings.IndexFunc(cleaned, unsafeManagedPathRune); i >= 0 {
		return fmt.Errorf("%s must not contain %q", field, cleaned[i:i+1])
	}
	switch field {
	case "state_dir":
		for _, blocked := range []string{"/", "/etc", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/boot", "/dev", "/proc", "/sys", "/root"} {
			if cleaned == blocked || strings.HasPrefix(cleaned, blocked+string(filepath.Separator)) {
				// Allow /usr only as exact? /usr blocks /usr/local - too broad for nothing since state shouldn't be there.
				if blocked == "/usr" && (cleaned == "/usr/local" || strings.HasPrefix(cleaned, "/usr/local"+string(filepath.Separator))) {
					continue
				}
				return fmt.Errorf("state_dir must not be under %s", blocked)
			}
		}
	case "core_binary":
		base := filepath.Base(cleaned)
		// sing-box basename is retained as a one-release compatibility for
		// hosts that still reference the upstream binary name after the
		// rename to oboard-sb. New installs must use oboard-sb; remove the
		// sing-box alternative after the first stable release with enforced
		// oldest direct-upgrade version. Stealth installations carry a
		// generated name from their identity instead.
		if name := executableBase(base); name != "oboard-sb" && name != "sing-box" && !basenameAllowed(base) {
			return fmt.Errorf("core_binary base name must be oboard-sb or sing-box")
		}
		// The Agent executes this path as root, so a matching base name is not
		// sufficient: a writable directory such as /tmp lets a local user plant
		// the file and gain root. Restrict it to root-owned system locations.
		if !coreDirAllowed(filepath.Dir(cleaned)) {
			return fmt.Errorf("core_binary must live in a system binary directory")
		}
	case "realm_binary":
		// Unlike core_binary this path never comes from configuration: it is
		// always derived from the running executable, and self-update installs
		// it into that same directory. Anyone able to write there already owns
		// the Agent binary, so a directory allowlist would add no protection
		// while making the install and execution paths disagree. Stealth
		// installations carry a generated name from their identity instead.
		if executableBase(cleaned) != "oboard-realm" && !basenameAllowed(filepath.Base(cleaned)) {
			return fmt.Errorf("realm_binary base name must be oboard-realm")
		}
	}
	return nil
}

// unsafeManagedPathRune reports whether a rune must never appear in a managed
// path. Uninstall renders these paths into a root /bin/sh script, so a quote or
// substitution character would only ever be an attempt to escape the quoting
// rather than a legitimate installation directory.
func unsafeManagedPathRune(r rune) bool {
	if r < 0x20 || r == 0x7f {
		return true
	}
	return strings.ContainsRune(managedPathUnsafeChars, r)
}

// allowedCoreBinaryDir reports whether a directory is an acceptable location
// for the root-executed kernel binary.
func allowedCoreBinaryDir(dir string) bool {
	dir = filepath.Clean(strings.TrimSpace(dir))
	for _, allowed := range []string{"/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/opt/oboard"} {
		allowed = filepath.Clean(allowed)
		if dir == allowed {
			return true
		}
		if allowed == "/opt/oboard" && strings.HasPrefix(dir, allowed+string(filepath.Separator)) {
			return true
		}
	}
	for _, allowed := range platformCoreBinaryDirs() {
		if strings.EqualFold(dir, filepath.Clean(allowed)) {
			return true
		}
	}
	return false
}

func InstalledCoreBinary(executablePath string) string {
	executablePath = strings.TrimSpace(executablePath)
	if executablePath == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(executablePath); err == nil {
		executablePath = resolved
	}
	absolute, err := filepath.Abs(executablePath)
	if err != nil {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(absolute), executableName("oboard-sb"))
	if validateManagedPath("core_binary", candidate) != nil {
		return ""
	}
	return candidate
}

// InstalledRealmBinary resolves the bundled port-forwarding binary that ships
// beside the Agent. realm is no longer taken from the host PATH, so this is the
// only path the Agent will execute.
func InstalledRealmBinary(executablePath string) string {
	executablePath = strings.TrimSpace(executablePath)
	if executablePath == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(executablePath); err == nil {
		executablePath = resolved
	}
	absolute, err := filepath.Abs(executablePath)
	if err != nil {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(absolute), executableName("oboard-realm"))
	if validateManagedPath("realm_binary", candidate) != nil {
		return ""
	}
	return candidate
}

func validateWarpCommand(value string) error {
	value = strings.TrimSpace(value)
	switch value {
	case "", "auto", "none":
		return nil
	default:
		if !filepath.IsAbs(value) {
			return fmt.Errorf("warp_command custom path must be absolute")
		}
		cleaned := filepath.Clean(value)
		if cleaned != value || strings.Contains(cleaned, "..") {
			return fmt.Errorf("warp_command must be a cleaned absolute path")
		}
		if filepath.Base(cleaned) != "wgcf" {
			return fmt.Errorf("warp_command custom binary base name must be wgcf")
		}
		// Executed as root, so the directory must not be user-writable.
		if !allowedCoreBinaryDir(filepath.Dir(cleaned)) {
			return fmt.Errorf("warp_command must live in a system binary directory")
		}
		return nil
	}
}

func validateServiceName(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if len(value) > 64 {
		return fmt.Errorf("core_service name is too long")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("core_service must match [A-Za-z0-9._-]+")
	}
	return nil
}

// validateCoreBinaryPath validates core_binary with the stealth identity
// name allowed when this configuration describes a hidden layout. A stealth
// core may also live beside the running agent executable: the operator chose
// that directory for the agent binary itself, so it carries the same trust,
// and custom install roots must keep working after a switch. While a hidden
// layout is being created, this process still runs from the staging
// directory but the binaries are already moving into
// <install parent>/<identity.InstallDirName>; that directory carries the
// same trust for the same reason.
func (cfg Config) validateCoreBinaryPath() error {
	if cfg.Stealth != nil {
		if err := validateManagedPath("core_binary", cfg.CoreBinary, map[string][]string{"basenames": {cfg.Stealth.Identity.CoreName}}); err != nil {
			if executable, exeErr := selfExecutablePath(); exeErr == nil {
				coreDir := filepath.Dir(filepath.Clean(strings.TrimSpace(cfg.CoreBinary)))
				if filepath.Dir(executable) == coreDir {
					return nil
				}
				if name := cfg.Stealth.Identity.InstallDirName; name != "" {
					if hidden := filepath.Join(filepath.Dir(filepath.Dir(executable)), name); hidden == coreDir {
						return nil
					}
				}
				// While a hidden layout is being disabled, this process still runs
				// from the hidden directory but the configuration already points
				// at the restored standard layout; its directory was chosen by the
				// operator for the agent binary before the switch.
				if origin := cfg.Stealth.Origin; origin != nil && origin.AgentBinary != "" && filepath.Dir(origin.AgentBinary) == coreDir {
					return nil
				}
			}
			return err
		}
		return nil
	}
	return validateManagedPath("core_binary", cfg.CoreBinary)
}

func validateSocketPath(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("core_socket must be an absolute path")
	}
	cleaned := filepath.Clean(value)
	if cleaned != value || strings.Contains(cleaned, "..") {
		return fmt.Errorf("core_socket must be a cleaned absolute path")
	}
	if i := strings.IndexFunc(cleaned, unsafeManagedPathRune); i >= 0 {
		return fmt.Errorf("core_socket must not contain %q", cleaned[i:i+1])
	}
	return nil
}

func ValidateManagedCommand(field, value string) error {
	switch strings.TrimSpace(value) {
	case "", "auto", "none", "systemd-reload", "systemd-restart", "openrc-reload", "openrc-restart", "chrony", "systemd-timesyncd":
		return nil
	default:
		return fmt.Errorf("%s only allows auto, none, or a managed preset", field)
	}
}

func (r *Runner) lowOverheadTransport() *http.Transport {
	return lowOverheadTransportWithClock(time.Now)
}

func lowOverheadTransport() *http.Transport {
	return lowOverheadTransportWithClock(time.Now)
}

func lowOverheadTransportWithClock(now func() time.Time) *http.Transport {
	if now == nil {
		now = time.Now
	}
	// TLS verification must use wall-clock time. The logical/runtime clock is
	// only for trusted_forward/mieru/replay windows and must never affect
	// certificate validity checks; using a skewed logical clock would accept
	// expired certificates or reject valid ones.
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   1,
		MaxConnsPerHost:       2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, Time: time.Now},
	}
}

func (r *Runner) Enroll(ctx context.Context, enrollmentToken string) error {
	cfg := r.Config()
	if err := cfg.validateAgentLink(); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.ConfigPath) != "" {
		if err := r.saveAgentConfig(cfg); err != nil {
			return fmt.Errorf("save enrollment bootstrap config: %w", err)
		}
	}
	return r.enrollAgentLink(ctx, cfg.ControllerAddr, cfg.ControllerCertSHA256, enrollmentToken)
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.ensureAgentLink(ctx); err != nil {
		return err
	}
	cfg := r.Config()
	if cfg.AgentID == "" || cfg.AgentToken == "" {
		return errors.New("agent is not enrolled")
	}
	r.tuning = ApplyRuntimeTuning(r.resources)
	r.reconcileStealthSwitchCleanup()
	if err := r.recoverRuntimeSecurity(); err != nil {
		logging.Warnf("runtime security recovery could not be verified; inspect the local policy and service")
	}
	go r.runtimeSecurityLoop(ctx)
	r.logStartupSummary(cfg)
	r.applyLowMemorySocketTuning()
	r.reconcileUpdateArtifacts()
	r.reconcileInstalledAgentBuild()
	if err := r.restoreManagedPortForwardsOnStartup(); err != nil {
		logging.Errorf("restore managed port forwards: %v", err)
	}
	if err := r.restoreManagedTunnelsOnStartup(); err != nil {
		logging.Errorf("restore managed tunnels: %v", err)
	}
	if err := r.restoreManagedSSHInboundsOnStartup(); err != nil {
		logging.Errorf("restore managed SSH inbounds: %v", err)
	}
	if r.sshInboundPolicyReconcilePending() {
		go r.startSSHInboundPolicyReconciler(ctx)
	}
	if err := r.restoreTrafficRuntimePolicies(ctx); err != nil {
		logging.Errorf("restore traffic runtime policies: %v", err)
	}
	r.startLogMaintenance(ctx)
	r.startTrafficLoop(ctx)
	r.startAuthorizationSyncLoop(ctx)
	r.startUsersSyncLoop(ctx)
	r.startVPNGateLoop(ctx)
	r.startLatencyProbeLoop(ctx)
	r.startMetricReportLoop(ctx)
	_ = r.configureCoreConnectionAudit(ctx, cfg.ConnectionAuditEnabled)
	_ = r.configureCoreClock(ctx)
	go r.startCoreWatchdog(ctx)
	failures := 0
	firstAfterDrop := false
	for {
		started := time.Now()
		err := r.connect(ctx)
		if ctx.Err() != nil {
			return nil
		}
		lived := time.Since(started)
		authFailure := isAuthReconnectError(err)
		// The realtime channel and the HTTP callbacks share one identity, so
		// they share one verdict about it: a rejected handshake quiets the
		// callbacks too, and a session that actually ran proves the identity
		// is valid and releases them.
		if authFailure {
			var linkAuth *agentlink.AuthError
			if errors.As(err, &linkAuth) {
				r.controllerAuth.armAgentLink(time.Now())
			} else {
				_, _, status, _ := classifyControllerLinkError(err)
				r.controllerAuth.armWithStatus(time.Now(), status)
			}
		} else if lived >= 60*time.Second {
			// The same threshold the reconnect counter already treats as a
			// real session: it can only be reached after the Controller
			// accepted this identity.
			r.controllerAuth.clear()
		}
		link := r.recordControllerLinkClosed(time.Now().UTC(), lived, err)
		if lived >= 60*time.Second {
			failures = 0
			firstAfterDrop = true
		} else if !authFailure {
			failures++
		}
		cfg := r.Config()
		delay := reconnectDelay(cfg.AgentID, cfg.ControllerURL, max(0, failures-1), firstAfterDrop, authFailure)
		firstAfterDrop = false
		if err != nil && (failures <= 1 || failures%20 == 0 || authFailure) {
			logging.Warnf("controller connection failed: attempt=%d class=%s http_status=%d close_code=%d connected_ms=%d reconnects=%d consecutive_failures=%d next_retry=%s detail=%q",
				failures, link.DisconnectClass, link.HandshakeHTTPStatus, link.WebSocketCloseCode, link.LastConnectedDurationMS, link.ReconnectCount, link.ConsecutiveFailures, delay, link.DisconnectDetail)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

func (r *Runner) logStartupSummary(cfg Config) {
	coreBinary := strings.TrimSpace(cfg.CoreBinary)
	if coreBinary == "" {
		coreBinary = "oboard-sb"
	}
	coreService := strings.TrimSpace(r.coreService())
	if coreService == "" {
		coreService = "oboard-sb"
	}
	logging.Infof("agent starting version=%s server_id=%d controller=%s state_dir=%s core_binary=%s core_service=%s update_source=%s update_repo=%s monitoring=%s", version.String(), cfg.ServerID, displayControllerURL(cfg.ControllerURL), cfg.StateDir, coreBinary, coreService, cfg.UpdateSource, cfg.UpdateRepo, r.monitoringMode)
}

// controlConn is the transport-neutral control channel the agent session
// loop runs over: the standard WebSocket or the stealth binary protocol.
type controlConn interface {
	Close() error
	RemoteAddr() string
	// WriteJSON sends one message envelope.
	WriteJSON(payload any) error
	// ReadMessage returns the next raw message envelope bytes.
	ReadMessage() ([]byte, error)
	// SetReadDeadline extends the read deadline after any traffic.
	SetReadDeadline(t time.Time) error
}

func (r *Runner) connect(ctx context.Context) error {
	return r.connectAgentLink(ctx)
}

// runControlSession drives the shared session loop over one transport.
func (r *Runner) runControlSession(ctx context.Context, conn controlConn) error {
	cfg := r.Config()
	r.recordControllerLinkConnected(time.Now().UTC())
	defer r.setControllerDisconnected(true)
	logging.Debugf("controller connection peer: server_id=%d remote=%s", cfg.ServerID, conn.RemoteAddr())
	defer conn.Close()
	connectionCtx, cancelConnection := context.WithCancel(ctx)
	defer cancelConnection()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer r.closeAllTerminalSessions("controller_disconnect")
	type websocketWriteRequest struct {
		payload any
		done    chan error
	}
	writes := make(chan websocketWriteRequest, 128)
	// Authorization acknowledgements and task acks bypass the health/metric
	// backlog: the writer drains priorityWrites first whenever one is ready.
	priorityWrites := make(chan websocketWriteRequest, 32)
	writerErrors := make(chan error, 1)
	go func() {
		write := func(request websocketWriteRequest) bool {
			// A Controller that stopped reading would otherwise park this
			// writer forever, filling the queue and stalling every task ack.
			err := conn.WriteJSON(request.payload)
			if request.done != nil {
				request.done <- err
			}
			if err != nil {
				select {
				case writerErrors <- err:
				default:
				}
				_ = conn.Close()
				return false
			}
			return true
		}
		for {
			select {
			case <-connectionCtx.Done():
				return
			case request := <-priorityWrites:
				if !write(request) {
					return
				}
				continue
			default:
			}
			select {
			case <-connectionCtx.Done():
				return
			case request := <-priorityWrites:
				if !write(request) {
					return
				}
			case request := <-writes:
				if !write(request) {
					return
				}
			}
		}
	}()
	enqueue := func(queue chan websocketWriteRequest, payload any, wait bool) error {
		request := websocketWriteRequest{payload: payload}
		if wait {
			request.done = make(chan error, 1)
		}
		select {
		case queue <- request:
		case err := <-writerErrors:
			return err
		case <-connectionCtx.Done():
			return connectionCtx.Err()
		}
		if request.done == nil {
			return nil
		}
		select {
		case err := <-request.done:
			return err
		case err := <-writerErrors:
			return err
		case <-connectionCtx.Done():
			return connectionCtx.Err()
		}
	}
	writeMessage := func(payload any, wait bool) error { return enqueue(writes, payload, wait) }
	writePriority := func(payload any, wait bool) error { return enqueue(priorityWrites, payload, wait) }
	r.setControlSend(writeMessage)
	defer r.setControlSend(nil)
	if err := writeMessage(map[string]any{"type": "health_report", "health_report": r.Probe(false)}, false); err != nil {
		return err
	}
	// Authorization envelopes are applied by their own goroutine so a revoke is
	// never queued behind the single task worker. Only the newest envelope is
	// kept: an older one is superseded by construction.
	authorizationCh := make(chan model.AuthorizationEnvelope, 1)
	usersCh := make(chan model.UsersEnvelope, 64)
	go func() {
		for {
			select {
			case <-connectionCtx.Done():
				return
			case envelope := <-authorizationCh:
				ack := r.applyAuthorizationEnvelope(connectionCtx, envelope)
				if err := writePriority(ack, true); err != nil {
					logging.Errorf("acknowledge authorization message %s: %v", envelope.MessageID, err)
					cancelConnection()
					return
				}
			}
		}
	}()
	go func() {
		var pending *model.UsersEnvelope
		timer := time.NewTimer(usersMergeDebounce)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		flush := func() {
			if pending == nil {
				return
			}
			envelope := *pending
			pending = nil
			ack := r.applyUsersEnvelope(connectionCtx, envelope)
			if err := writePriority(ack, true); err != nil {
				logging.Errorf("acknowledge users message %s: %v", envelope.MessageID, err)
				cancelConnection()
			}
		}
		for {
			select {
			case <-connectionCtx.Done():
				return
			case envelope := <-usersCh:
				req, err := r.verifyUsersEnvelope(envelope)
				if err != nil || usersInstallIsRevoke(req) || req.Chunk != nil {
					pending = nil
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					ack := r.applyUsersEnvelope(connectionCtx, envelope)
					if err := writePriority(ack, true); err != nil {
						logging.Errorf("acknowledge users message %s: %v", envelope.MessageID, err)
						cancelConnection()
						return
					}
					continue
				}
				pending = &envelope
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(usersMergeDebounce)
			case <-timer.C:
				flush()
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		lastSent := ""
		lastSentAt := time.Time{}
		for {
			select {
			case <-connectionCtx.Done():
				return
			case <-ticker.C:
				report, ok := r.nextPendingLatencyProbeReport()
				if !ok {
					lastSent = ""
					lastSentAt = time.Time{}
					continue
				}
				if report.ReportID == lastSent && time.Since(lastSentAt) < 10*time.Second {
					continue
				}
				if writeMessage(map[string]any{"type": "latency_probe_report", "latency_probe_report": report}, false) != nil {
					return
				}
				lastSent = report.ReportID
				lastSentAt = time.Now()
			}
		}
	}()
	go func() {
		retry := time.NewTicker(metricReportRetryInterval)
		defer retry.Stop()
		lastSent := ""
		lastSentAt := time.Time{}
		sendNext := func() bool {
			report, ok := r.nextPendingMetricReport()
			if !ok {
				lastSent = ""
				lastSentAt = time.Time{}
				return true
			}
			if report.ReportID == lastSent && time.Since(lastSentAt) < metricReportRetryInterval {
				return true
			}
			if writeMessage(map[string]any{"type": "metric_report", "metric_report": report}, true) != nil {
				return false
			}
			lastSent = report.ReportID
			lastSentAt = time.Now()
			return true
		}
		for {
			select {
			case <-connectionCtx.Done():
				return
			case <-r.metricReportWake:
				if !sendNext() {
					return
				}
			case <-retry.C:
				if !sendNext() {
					return
				}
			}
		}
	}()
	r.notifyMetricReportSender()
	go func() {
		ticker := time.NewTicker(connectionPresencePollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-connectionCtx.Done():
				return
			case <-ticker.C:
				pollCtx, cancel := context.WithTimeout(connectionCtx, connectionPresencePollInterval)
				delta, _ := r.collectConnectionPresenceDelta(pollCtx)
				cancel()
				if len(delta.Events) == 0 && delta.DroppedCount == 0 {
					continue
				}
				if r.sendConnectionPresenceDelta(delta, writeMessage) != nil {
					return
				}
			}
		}
	}()
	type pendingControlTask struct {
		task model.AgentTask
	}
	taskCh := make(chan pendingControlTask, 1)
	go func() {
		for {
			select {
			case <-connectionCtx.Done():
				return
			case item, ok := <-taskCh:
				if !ok {
					return
				}
				status, result := r.ExecuteAgentTask(item.task)
				if item.task.Type == "update_agent" && agentUpdateInstalled(status, result) {
					// The executable has already been replaced. Reporting the
					// result first keeps the Controller informed, but the link
					// is at its most fragile right after an update, and losing
					// it below must not leave this process running from the
					// unlinked inode with no restart armed.
					defer func() {
						if err := r.scheduleAgentRestart(); err != nil {
							logging.Errorf("restart agent onto the installed build: %v", err)
						}
					}()
				}
				health := r.taskResultHealth()
				if err := r.ReportTaskResult(ctx, item.task.ID, status, result, health); err != nil {
					logging.Errorf("report task %d result: %v", item.task.ID, err)
					cancelConnection()
					return
				}
				if err := writePriority(map[string]any{"type": "task_ack", "task_id": item.task.ID}, true); err != nil {
					logging.Errorf("acknowledge task %d: %v", item.task.ID, err)
					cancelConnection()
					return
				}
				if item.task.Type == "update_agent" && agentUpdateInstalled(status, result) {
					if err := r.scheduleAgentRestart(); err != nil {
						logging.Errorf("schedule agent restart after update: %v", err)
						cancelConnection()
						return
					}
				}
				if item.task.Type == model.AgentTaskTypeApplyStealth && status == "succeeded" {
					if err := r.runStealthSwitchFinalizer(); err != nil {
						logging.Errorf("schedule stealth switch handoff: %v", err)
						cancelConnection()
						return
					}
				}
				if item.task.Type == model.AgentTaskTypeUninstallAgent && status == "succeeded" {
					if err := r.finalizeAgentUninstall(); err != nil {
						logging.Errorf("schedule agent uninstall finalizer: %v", err)
					}
				}
			}
		}
	}()
	for {
		data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		// Any Controller frame proves the link, not just a ping.
		_ = conn.SetReadDeadline(time.Now().Add(controllerSocketReadTimeout))
		var typed struct {
			Type                   string                         `json:"type"`
			Task                   *model.AgentTask               `json:"task"`
			Signature              string                         `json:"signature"`
			SignatureVersion       int                            `json:"signature_version"`
			ServerID               int64                          `json:"server_id"`
			MonitoringMode         string                         `json:"monitoring_mode"`
			LatencyProbePlan       *model.LatencyProbeTargetsPlan `json:"latency_probe_plan"`
			ReportID               string                         `json:"report_id"`
			RequestID              string                         `json:"request_id"`
			SessionID              string                         `json:"session_id"`
			ConnectionAuditEnabled bool                           `json:"connection_audit_enabled"`
			AuditCollection        *auditCollectionPolicy         `json:"audit_collection"`
			ControllerTime         time.Time                      `json:"ts"`
		}
		if err := json.Unmarshal(data, &typed); err != nil {
			return err
		}
		if !typed.ControllerTime.IsZero() {
			r.setControllerReference(typed.ControllerTime)
		}
		switch typed.Type {
		case "hello":
			if err := r.bindServerIdentity(typed.ServerID); err != nil {
				return err
			}
			r.setMonitoringPolicy(typed.MonitoringMode)
			r.applyControllerLatencyProbePlan(typed.LatencyProbePlan)
			r.setConnectionAuditPolicy(typed.ConnectionAuditEnabled)
			r.setAuditCollectionPolicy(typed.AuditCollection)
			// A reconnect may have missed a revoke pushed while the link was
			// down; the independent lane pulls the current snapshot now.
			r.wakeAuthorizationSync()
			r.wakeTrafficReport()
			r.wakeUsersSync()
		case model.AgentControlAuthorizationUpdate:
			var envelope model.AuthorizationEnvelope
			if err := json.Unmarshal(data, &envelope); err != nil {
				logging.Warnf("authorization_update decode failed: %v", err)
				continue
			}
			// Replace a not-yet-applied envelope: the newest one supersedes it.
			select {
			case authorizationCh <- envelope:
			default:
				select {
				case <-authorizationCh:
				default:
				}
				select {
				case authorizationCh <- envelope:
				default:
				}
			}
		case model.AgentControlUsersUpdate:
			var envelope model.UsersEnvelope
			if err := json.Unmarshal(data, &envelope); err != nil {
				logging.Warnf("users_update decode failed: %v", err)
				continue
			}
			var peek struct {
				Chunk *model.UsersInstallChunk `json:"chunk"`
			}
			_ = json.Unmarshal([]byte(envelope.UsersJSON), &peek)
			if peek.Chunk != nil {
				select {
				case usersCh <- envelope:
				case <-connectionCtx.Done():
				}
				continue
			}
			select {
			case usersCh <- envelope:
			default:
				select {
				case <-usersCh:
				default:
				}
				select {
				case usersCh <- envelope:
				default:
				}
			}
		case "task_request":
			if typed.Task == nil {
				continue
			}
			if err := r.acceptControlTask(*typed.Task, typed.SignatureVersion, typed.Signature); err != nil {
				if rejectErr := r.rejectControlTask(ctx, *typed.Task, err, writePriority); rejectErr != nil {
					return rejectErr
				}
				continue
			}
			select {
			case taskCh <- pendingControlTask{task: *typed.Task}:
			case <-connectionCtx.Done():
				return connectionCtx.Err()
			default:
				logging.Warnf("ignoring task %d because the single task worker is busy", typed.Task.ID)
			}
		case "heartbeat":
			r.setMonitoringPolicy(typed.MonitoringMode)
			r.applyControllerLatencyProbePlan(typed.LatencyProbePlan)
			r.setConnectionAuditPolicy(typed.ConnectionAuditEnabled)
			r.setAuditCollectionPolicy(typed.AuditCollection)
			_ = r.maybeRunPeriodicDNSBenchmark(ctx)
			_ = r.maybeRunPeriodicForwardProbes(ctx)
			_ = writeMessage(map[string]any{"type": "health_report", "health_report": r.Probe(false)}, false)
		case "interactive_prepare":
			var env model.InteractivePrepareEnvelope
			if err := json.Unmarshal(data, &env); err != nil {
				logging.Warnf("interactive_prepare decode failed: %v", err)
				continue
			}
			if err := r.handleInteractivePrepare(env); err != nil {
				logging.Warnf("interactive_prepare rejected session=%s: %v", env.SessionID, err)
			}
		case "interactive_close":
			if typed.SessionID != "" {
				r.closeTerminalSession(typed.SessionID, "controller_close")
			}
		case "remote_exec_cancel":
			if typed.RequestID != "" {
				_ = r.cancelRemoteExec(typed.RequestID)
			}
		case "latency_probe_ack":
			if typed.ReportID != "" {
				if err := r.ackLatencyProbeReport(typed.ReportID); err != nil {
					return err
				}
			}
		case "metric_report_ack":
			if typed.ReportID != "" {
				if err := r.ackMetricReport(typed.ReportID); err != nil {
					return err
				}
			}
		}
	}
}

func (r *Runner) bindServerIdentity(serverID int64) error {
	if serverID <= 0 {
		return errors.New("controller hello did not include a valid server_id")
	}
	cfg := r.Config()
	if cfg.ServerID != 0 && cfg.ServerID != serverID {
		return fmt.Errorf("controller server_id %d does not match enrolled server_id %d", serverID, cfg.ServerID)
	}
	if cfg.ServerID == serverID {
		return nil
	}
	logging.Infof("agent identity bound: server_id=%d", serverID)
	cfg.ServerID = serverID
	if strings.TrimSpace(cfg.ConfigPath) != "" {
		// Persist through the key-aware writer: a stealth installation must
		// never let this runtime write downgrade the encrypted envelope to
		// plaintext, or the next start (and the reinstall cleanup) rejects it.
		if err := r.saveAgentConfig(cfg); err != nil {
			return fmt.Errorf("persist enrolled server_id: %w", err)
		}
	}
	r.storeConfig(cfg)
	return nil
}

func (r *Runner) validateTaskServerID(task model.AgentTask) error {
	serverID := r.Config().ServerID
	if serverID <= 0 {
		return errors.New("agent server identity is not bound")
	}
	if task.ServerID != serverID {
		return fmt.Errorf("task %d belongs to server %d, enrolled server is %d", task.ID, task.ServerID, serverID)
	}
	return nil
}

func (r *Runner) applyControllerLatencyProbePlan(plan *model.LatencyProbeTargetsPlan) {
	if plan == nil {
		return
	}
	if err := r.setLatencyProbePlan(*plan); err != nil {
		// A stale or conflicting probe plan must not take down the control
		// channel. Remote terminal, authorization, and task delivery share
		// this socket.
		logging.Warnf("latency probe plan rejected: %v", err)
	}
}

func (r *Runner) acceptControlTask(task model.AgentTask, signatureVersion int, signature string) error {
	if signatureVersion != 2 {
		return fmt.Errorf("controller task signature version %d is not supported", signatureVersion)
	}
	if !r.verifyTaskSignature(task, signature) {
		return fmt.Errorf("controller task signature verification failed for task %d", task.ID)
	}
	return r.validateTaskServerID(task)
}

func (r *Runner) rejectControlTask(ctx context.Context, task model.AgentTask, reason error, writePriority func(any, bool) error) error {
	logging.Warnf("rejecting task %d: %v", task.ID, reason)
	if err := r.ReportTaskResult(ctx, task.ID, "failed", jsonResult(reason.Error()), r.taskResultHealth()); err != nil {
		logging.Errorf("report rejected task %d: %v", task.ID, err)
	}
	if err := writePriority(map[string]any{"type": "task_ack", "task_id": task.ID}, true); err != nil {
		return err
	}
	return nil
}

func (r *Runner) setMonitoringPolicy(mode string) {
	if strings.EqualFold(strings.TrimSpace(mode), "standard") {
		mode = "standard"
	} else {
		mode = "lightweight"
	}
	r.mu.Lock()
	r.monitoringMode = mode
	r.mu.Unlock()
}

func (r *Runner) verifyTaskSignature(task model.AgentTask, signature string) bool {
	secret := security.HashSecret(r.Config().AgentToken)
	return security.VerifyTaskEnvelopeSignature(secret, security.TaskEnvelope{ID: task.ID, ServerID: task.ServerID, Type: task.Type, ConfigVersion: task.ConfigVersion, Nonce: task.Nonce, PayloadJSON: task.PayloadJSON}, signature)
}

func (r *Runner) ExecuteAgentTask(task model.AgentTask) (string, string) {
	started := time.Now()
	status, result := r.executeAgentTask(task)
	logging.Infof("task id=%d type=%s version=%d result=%s duration_ms=%d", task.ID, task.Type, task.ConfigVersion, status, time.Since(started).Milliseconds())
	return status, result
}

func (r *Runner) executeAgentTask(task model.AgentTask) (string, string) {
	switch task.Type {
	case model.AgentTaskTypeApplyDeployment:
		var payload model.DeploymentTaskPayload
		if err := json.Unmarshal([]byte(task.PayloadJSON), &payload); err != nil {
			return "failed", jsonResult(err.Error())
		}
		if payload.Version == 0 {
			payload.Version = task.ConfigVersion
		}
		return r.executeDeploymentTask(payload)
	case model.AgentTaskTypeApplyCoreConfig:
		var payload model.ApplyCoreConfigTaskPayload
		if err := json.Unmarshal([]byte(task.PayloadJSON), &payload); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.applyCoreConfigTask(task.ConfigVersion, payload)
		if err != nil {
			result["error"] = err.Error()
			return "failed", jsonMap(result)
		}
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeApplyTrafficPolicy:
		var payload model.ApplyTrafficPolicyTaskPayload
		if err := json.Unmarshal([]byte(task.PayloadJSON), &payload); err != nil {
			return "failed", jsonResult(err.Error())
		}
		if payload.PolicyRevision == 0 {
			payload.PolicyRevision = task.ConfigVersion
		}
		result, err := r.applyTrafficPolicyTask(payload)
		if err != nil {
			result["error"] = err.Error()
			return "failed", jsonMap(result)
		}
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeUpdateAgentConfig:
		var patch Config
		if err := json.Unmarshal([]byte(task.PayloadJSON), &patch); err != nil {
			return "failed", jsonResult(err.Error())
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(task.PayloadJSON), &fields); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.updateAgentConfig(patch, fields)
		if err != nil {
			result["error"] = err.Error()
			return "failed", jsonMap(result)
		}
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeUpdateAgent:
		result, err := r.updateAgentBinary(task.PayloadJSON)
		if err != nil {
			result["error"] = err.Error()
			return "failed", jsonMap(result)
		}
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeUninstallAgent:
		r.coreLifecycleMu.Lock()
		defer r.coreLifecycleMu.Unlock()
		result, err := r.uninstallAgent(task.PayloadJSON)
		if err != nil {
			result["error"] = err.Error()
			return "failed", jsonMap(result)
		}
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeProxyDSCP:
		value, err := r.applyProxyDSCP(task.PayloadJSON)
		if err != nil {
			return "failed", jsonMap(map[string]any{"message": err.Error()})
		}
		return "succeeded", jsonMap(value)
	case model.AgentTaskTypeRuntimeSecurity:
		value, err := r.applyRuntimeSecurity(task.PayloadJSON)
		if err != nil {
			if value == nil {
				value = map[string]any{"message": err.Error()}
			}
			return "failed", jsonMap(value)
		}
		return "succeeded", jsonMap(value)
	case model.AgentTaskTypeApplyStealth:
		result, err := r.applyStealthTask(task.PayloadJSON)
		if err != nil {
			result["error"] = err.Error()
			return "failed", jsonMap(result)
		}
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeNetworkPing, model.AgentTaskTypeNetworkTrace, model.AgentTaskTypeNetworkTCP, model.AgentTaskTypeNetworkDNS, model.AgentTaskTypeNetworkHTTP, model.AgentTaskTypeGoogleRegion:
		return r.executeNetworkDiagnosticTask(task)
	case model.AgentTaskTypeDiagnoseNetwork:
		result := r.runNetworkDiagnostics(task.PayloadJSON)
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeListNetworkInterfaces:
		interfaces, err := listNetworkInterfaces()
		if err != nil {
			return "failed", jsonResult(err.Error())
		}
		return "succeeded", jsonMap(map[string]any{"message": "network interfaces listed", "interfaces": interfaces})
	case model.AgentTaskTypeProbeInbounds:
		var plan model.InboundProbePlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.runInboundProbeTask(context.Background(), plan)
		if err != nil {
			return "failed", jsonMap(map[string]any{"message": "inbound probe failed", "error": err.Error(), "probes": result})
		}
		return "succeeded", jsonMap(map[string]any{"message": "inbound probe completed", "probes": result})
	case model.AgentTaskTypeApplyVPNGatePool:
		var plan model.VPNGatePoolPlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.applyVPNGatePool(context.Background(), plan)
		if err != nil {
			return "failed", jsonResult(err.Error())
		}
		r.wakeVPNGate()
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeProbeVPNGate:
		var plan model.VPNGateProbePlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		report, err := r.probeVPNGate(context.Background(), plan)
		raw, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			return "failed", jsonResult(marshalErr.Error())
		}
		if err != nil {
			return "failed", jsonMap(map[string]any{"message": "vpngate probe failed", "error": boundedExternalEgressProbeError(err.Error()), "report": report})
		}
		return "succeeded", string(raw)
	case model.AgentTaskTypeProbeExternalEgress:
		var plan model.ExternalEgressProbePlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.runExternalEgressProbeTask(context.Background(), plan)
		raw, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return "failed", jsonResult(marshalErr.Error())
		}
		if err != nil {
			return "failed", string(raw)
		}
		return "succeeded", string(raw)
	case model.AgentTaskTypeProbeLatencyTargets:
		var plan model.LatencyProbeTargetsPlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.runLatencyProbeTask(context.Background(), plan)
		raw, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return "failed", jsonResult(marshalErr.Error())
		}
		if err != nil {
			return "failed", string(raw)
		}
		return "succeeded", string(raw)
	case model.AgentTaskTypeCollectLogs:
		result := r.collectLogs(task.PayloadJSON)
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeManageLogs:
		result, err := r.manageLogs(task.PayloadJSON)
		if err != nil {
			result["error"] = err.Error()
			return "failed", jsonMap(result)
		}
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeCheckTime:
		var plan model.TimeCheckPlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.runTimeCheckTask(context.Background(), plan)
		raw, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return "failed", jsonResult(marshalErr.Error())
		}
		if err != nil {
			return "failed", string(raw)
		}
		return "succeeded", string(raw)
	case model.AgentTaskTypeDetectMTU:
		var plan model.MTUDetectionPlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.runMTUDetectionTask(context.Background(), plan)
		if err != nil {
			return "failed", jsonMap(map[string]any{"message": "mtu detection failed", "error": err.Error(), "mtu": result})
		}
		return "succeeded", jsonMap(map[string]any{"message": "mtu detection completed", "mtu": result})
	case model.AgentTaskTypeBenchmarkDNS:
		var plan model.DNSBenchmarkPlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.runDNSBenchmarkTask(context.Background(), plan, true)
		if err != nil {
			return "failed", jsonMap(map[string]any{"message": "dns benchmark failed", "error": err.Error(), "dns": result})
		}
		return "succeeded", jsonMap(map[string]any{"message": "dns benchmark completed", "dns": result})
	case model.AgentTaskTypeProbePortForwards:
		var plan model.PortForwardPlan
		if err := json.Unmarshal([]byte(task.PayloadJSON), &plan); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.runForwardProbeTask(context.Background(), plan.Rules, "task")
		if err != nil {
			return "failed", jsonMap(map[string]any{"message": "port forward probe failed", "error": err.Error(), "probe": result})
		}
		return "succeeded", jsonMap(map[string]any{"message": "port forward probe completed", "probe": result})
	case model.AgentTaskTypeIssueCertificateHTTP:
		var payload model.IssueCertificateHTTPTaskPayload
		if err := json.Unmarshal([]byte(task.PayloadJSON), &payload); err != nil {
			return "failed", jsonResult(err.Error())
		}
		result, err := r.issueCertificateHTTP(task.ID, payload)
		if err != nil {
			return "failed", jsonMap(map[string]any{"message": "HTTP-01 certificate issuance failed", "error": err.Error(), "certificate_id": payload.CertificateID})
		}
		return "succeeded", jsonMap(result)
	case model.AgentTaskTypeRemoteExec:
		return r.executeRemoteExecTask(task)
	case model.AgentTaskTypeRemoteOperation:
		return r.executeRemoteOperationTask(task)
	default:
		return "failed", jsonResult("unknown task type")
	}
}

func (r *Runner) updateAgentBinary(payloadJSON string) (map[string]any, error) {
	var payload model.UpdateAgentTaskPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return map[string]any{"message": "agent update failed"}, err
	}
	source := strings.ToLower(strings.TrimSpace(payload.Source))
	if source == "" || source == "auto" {
		source = strings.ToLower(strings.TrimSpace(r.Config().UpdateSource))
	}
	if source == "" {
		if version.IsDev() {
			source = "panel"
		} else {
			source = "github"
		}
	}
	repo := strings.TrimSpace(payload.GitHubRepo)
	if repo == "" {
		repo = strings.TrimSpace(r.Config().UpdateRepo)
	}
	if repo == "" {
		repo = defaultUpdateRepo
	}
	if !updateRepoAllowed(repo) {
		return map[string]any{"message": "agent update failed", "source": source, "github_repo": repo}, fmt.Errorf("github repo %s is not allowed", repo)
	}
	controllerURL := strings.TrimRight(strings.TrimSpace(payload.ControllerURL), "/")
	if controllerURL == "" {
		controllerURL = strings.TrimRight(strings.TrimSpace(r.Config().ControllerURL), "/")
	}
	switch source {
	case "panel":
		if controllerURL == "" {
			return map[string]any{"message": "agent update failed", "source": source}, errors.New("controller_url missing")
		}
		if !r.Config().AllowPanelUpdate && !version.IsDev() {
			return map[string]any{"message": "agent update blocked", "source": source}, errors.New("当前 Agent 未允许从面板更新，请使用 GitHub 更新，或重新安装时勾选允许从面板更新")
		}
		if _, err := security.ValidateControllerURL(controllerURL, version.IsDev(), r.Config().AllowInsecureController); err != nil {
			return map[string]any{"message": "agent update failed", "source": source}, err
		}
	case "github":
		if _, err := security.ValidateControllerURL(controllerURL, version.IsDev(), r.Config().AllowInsecureController); err != nil {
			return map[string]any{"message": "agent update failed", "source": source}, err
		}
	default:
		return map[string]any{"message": "agent update failed", "source": source}, fmt.Errorf("unsupported update source %q", source)
	}
	r.coreLifecycleMu.Lock()
	defer r.coreLifecycleMu.Unlock()
	hostLock, hostLockErr := r.acquireHostCoreLock(hostCoreLockWait)
	if hostLockErr != nil {
		return map[string]any{"message": "agent update deferred", "source": source, "installed": false}, hostLockErr
	}
	defer hostLock.release()
	beforeAgent := version.String()
	beforeCore := strings.TrimSpace(commandText(3*time.Second, r.coreBinary(), "-version"))
	targets, err := r.signedReleaseTargets()
	if err != nil {
		return map[string]any{"message": "agent update failed", "source": source}, err
	}
	outcome, err := r.downloadAndInstallSignedReleaseOverTransport(context.Background(), repo, payload.ExpectedBuild, targets, r.updateStagingPrefix())
	return r.updateAgentResult(err, outcome, source, controllerURL, payload, targets, beforeAgent, beforeCore)
}

// updateAgentResult assembles the update task result and runs kernel
// activation after a successful install. Both download paths share it.
func (r *Runner) updateAgentResult(err error, outcome releaseInstallOutcome, source, controllerURL string, payload model.UpdateAgentTaskPayload, targets signedReleaseTargets, beforeAgent, beforeCore string) (map[string]any, error) {
	manifest := outcome.Manifest
	result := map[string]any{
		"message":        "agent update completed",
		"controller_url": controllerURL,
		"expected_build": payload.ExpectedBuild,
		"source":         source,
		"github_repo":    "",
		"before_agent":   beforeAgent,
		"before_core":    beforeCore,
		"installed":      false,
		"restart":        "after_result_acknowledged",
	}
	if outcome.CorePreflight != "" {
		result["core_preflight"] = outcome.CorePreflight
	}
	if outcome.CorePreflightNote != "" {
		result["core_preflight_note"] = outcome.CorePreflightNote
	}
	if err != nil {
		result["message"] = "agent update failed"
		return result, err
	}
	result["installed"] = true
	result["release_version"] = manifest.Version
	result["release_build"] = manifest.Build
	result["release_commit"] = manifest.Commit

	// Installing the release only replaced files. The Agent restarts itself
	// once the Controller has acknowledged this result, but nothing else would
	// ever restart the kernel: without this step the old oboard-sb process
	// keeps serving traffic on its original inode indefinitely.
	afterCore := strings.TrimSpace(commandText(3*time.Second, r.coreBinary(), "-version"))
	result["after_core"] = afterCore
	activation, activationErr := r.activateInstalledCoreLocked(context.Background(), true)
	for key, value := range activation {
		result[key] = value
	}
	if activationErr != nil {
		result["message"] = "agent update installed but the new kernel was not activated"
		return result, activationErr
	}
	return result, nil
}

// agentUpdateInstalled reports whether an update task replaced the binaries on
// disk. Activating the new kernel can fail after a successful install, and this
// Agent still has to restart onto its own new executable in that case, so the
// task status alone is not the right gate.
func agentUpdateInstalled(status, result string) bool {
	if status == "succeeded" {
		return true
	}
	var payload struct {
		Installed bool `json:"installed"`
	}
	if json.Unmarshal([]byte(result), &payload) != nil {
		return false
	}
	return payload.Installed
}

// scheduleAgentRestart arms a one-shot restart of this Agent. The transient
// systemd unit is named after the process, so a second call inside the same
// process would collide with a timer that has not been collected yet. One
// scheduled restart per process is also the correct behaviour: queueing several
// would restart the Agent repeatedly after a single update.
func (r *Runner) scheduleAgentRestart() error {
	if schedule := r.agentRestartCommand; schedule != nil {
		return r.scheduleAgentRestartWith(schedule)
	}
	return r.scheduleAgentRestartWith(r.scheduleAgentRestartCommand)
}

func (r *Runner) scheduleAgentRestartWith(schedule func() error) error {
	if !r.agentRestartScheduled.CompareAndSwap(false, true) {
		return nil
	}
	err := schedule()
	if err != nil {
		r.agentRestartScheduled.Store(false)
	}
	return err
}

// scheduleAgentRestartCommand arms this process's single self-restart. The
// service name comes from the config so a stealth installation restarts its
// own generated unit; the PID suffix stays (one restart per process).
func (r *Runner) scheduleAgentRestartCommand() error {
	service := r.agentService()
	switch detectServiceManager() {
	case serviceManagerWindows:
		return scheduleWindowsAgentRestart(service)
	case "systemd":
		unit := fmt.Sprintf("%s-restart-%d", service, os.Getpid())
		return runCommand(10*time.Second, "systemd-run", "--quiet", "--collect", "--on-active=5s", "--unit", unit, "systemctl", "restart", service)
	case "openrc":
		return runCommand(5*time.Second, "sh", "-c", "nohup sh -c "+shellQuoteValue("sleep 5; rc-service "+service+" restart")+" >/dev/null 2>&1 &")
	default:
		return fmt.Errorf("supported service manager is unavailable; restart %s manually to activate the update", service)
	}
}

func updateRepoAllowed(repo string) bool {
	repo = strings.TrimSpace(repo)
	allowed := map[string]bool{
		defaultUpdateRepo: true,
		// Controllers that still send the pre-rename repository name.
		"OboardProject/oboard-agent": true,
	}
	for _, item := range strings.Split(os.Getenv("OBOARD_UPDATE_REPO_ALLOWLIST"), ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			allowed[item] = true
		}
	}
	return allowed[repo]
}

func isLocalSecurityField(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "_", "")
	return strings.Contains(normalized, "localsecurity")
}

// isStealthIdentityField reports whether a config key belongs to the stealth
// identity. These fields are bound to the installed unit files and binary
// names; a remote patch would desynchronize the config from the running
// layout, so they are rejected like local-security fields.
func isStealthIdentityField(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "_", "")
	return strings.Contains(normalized, "stealth") || normalized == "agentservice" || normalized == "coresocket"
}

func (r *Runner) updateAgentConfig(patch Config, fields map[string]json.RawMessage) (map[string]any, error) {
	for key := range fields {
		if isLocalSecurityField(key) {
			return map[string]any{"message": "agent config update rejected"}, errors.New("update_agent_config cannot modify local-security.json")
		}
		if isStealthIdentityField(key) {
			return map[string]any{"message": "agent config update rejected"}, errors.New("update_agent_config cannot modify the stealth layout; use the apply_stealth task")
		}
	}
	current := r.Config()
	if r.stealthOn() {
		// The stealth layout binds state_dir, core_binary, and core_service to
		// the installed unit files; a remote change would break the next
		// restart.
		if (strings.TrimSpace(patch.StateDir) != "" && strings.TrimSpace(patch.StateDir) != current.StateDir) ||
			(strings.TrimSpace(patch.CoreBinary) != "" && strings.TrimSpace(patch.CoreBinary) != current.CoreBinary) ||
			(strings.TrimSpace(patch.CoreService) != "" && strings.TrimSpace(patch.CoreService) != current.CoreService) {
			return map[string]any{"message": "agent config update rejected"}, errors.New("state_dir, core_binary, and core_service are fixed by the stealth layout; use the apply_stealth task to change it")
		}
	}
	currentCoreService := r.coreService()
	oldController := current.ControllerURL
	oldStateDir := current.StateDir
	next := current
	if strings.TrimSpace(patch.ControllerURL) != "" {
		next.ControllerURL = strings.TrimSpace(patch.ControllerURL)
	}
	if strings.TrimSpace(patch.StateDir) != "" {
		next.StateDir = strings.TrimSpace(patch.StateDir)
	}
	if strings.TrimSpace(patch.CoreBinary) != "" {
		next.CoreBinary = strings.TrimSpace(patch.CoreBinary)
	}
	if strings.TrimSpace(patch.CoreService) != "" {
		next.CoreService = strings.TrimSpace(patch.CoreService)
	}
	if patch.CommandTimeoutSeconds > 0 {
		next.CommandTimeoutSeconds = patch.CommandTimeoutSeconds
	}
	if strings.TrimSpace(patch.ReloadCommand) != "" {
		next.ReloadCommand = strings.TrimSpace(patch.ReloadCommand)
	}
	if strings.TrimSpace(patch.RestartCommand) != "" {
		next.RestartCommand = strings.TrimSpace(patch.RestartCommand)
	}
	if strings.TrimSpace(patch.TimeSyncCommand) != "" {
		next.TimeSyncCommand = strings.TrimSpace(patch.TimeSyncCommand)
	}
	if normalizeTimeCorrectionMode(patch.TimeCorrectionMode) != "" {
		next.TimeCorrectionMode = normalizeTimeCorrectionMode(patch.TimeCorrectionMode)
	}
	if _, ok := fields["log_level"]; ok {
		next.LogLevel = strings.TrimSpace(patch.LogLevel)
		// A level change always restarts the verbose deadline: reusing the old
		// one would let a second debug request inherit an expiry that has
		// almost run out, or none at all.
		next.LogLevelExpiresAt = strings.TrimSpace(patch.LogLevelExpiresAt)
	} else if _, ok := fields["log_level_expires_at"]; ok {
		next.LogLevelExpiresAt = strings.TrimSpace(patch.LogLevelExpiresAt)
	}
	if _, ok := fields["log_max_mb"]; ok {
		next.LogMaxMB = patch.LogMaxMB
		next.LogMaxMBSet = true
	}
	if _, ok := fields["log_backups"]; ok {
		next.LogBackups = patch.LogBackups
		next.LogBackupsSet = true
	}
	if _, ok := fields["core_log_max_mb"]; ok {
		next.CoreLogMaxMB = patch.CoreLogMaxMB
		next.CoreLogMaxMBSet = true
	}
	if _, ok := fields["core_log_backups"]; ok {
		next.CoreLogBackups = patch.CoreLogBackups
		next.CoreLogBackupsSet = true
	}
	if _, ok := fields["storage_profile"]; ok {
		next.StorageProfile = strings.TrimSpace(patch.StorageProfile)
	}
	if _, ok := fields["resource_profile"]; ok {
		next.ResourceProfile = strings.TrimSpace(patch.ResourceProfile)
	}
	if _, ok := fields["connection_audit_enabled"]; ok {
		next.ConnectionAuditEnabled = patch.ConnectionAuditEnabled
	}
	if strings.TrimSpace(patch.UpdateSource) != "" {
		next.UpdateSource = strings.TrimSpace(patch.UpdateSource)
		// allow_panel_update records the host operator's consent to install
		// binaries served by the Controller. Letting a Controller task raise it
		// would let the Controller grant itself a permission the operator
		// withheld, so it may only be lowered remotely.
		if !patch.AllowPanelUpdate {
			next.AllowPanelUpdate = false
		}
	}
	if strings.TrimSpace(patch.UpdateRepo) != "" {
		next.UpdateRepo = strings.TrimSpace(patch.UpdateRepo)
	}
	next = normalizeConfig(next)
	if err := next.Validate(); err != nil {
		return map[string]any{"message": "agent config update rejected"}, err
	}
	nextCoreService := strings.TrimSpace(next.CoreService)
	if nextCoreService == "" {
		nextCoreService = "oboard-sb"
	}
	coreServiceChanged := currentCoreService != nextCoreService
	coreIdentityChanged := current.CoreBinary != next.CoreBinary || current.CoreService != next.CoreService
	path := next.ConfigPath
	if path == "" {
		path = DefaultConfigPath()
	}
	r.coreLifecycleMu.Lock()
	stoppedPreviousService := false
	previousServiceManager := ""
	if coreServiceChanged && r.managedRestartEnabled() {
		previousServiceManager = serviceManager()
		if previousServiceManager != "" && managedServiceActive(previousServiceManager, currentCoreService) == nil {
			if err := stopManagedService(previousServiceManager, currentCoreService); err != nil {
				r.coreLifecycleMu.Unlock()
				return map[string]any{"message": "agent config update rejected", "core_service": currentCoreService}, fmt.Errorf("stop previous core service %s: %w", currentCoreService, err)
			}
			stoppedPreviousService = true
		}
	}
	if err := r.saveAgentConfig(next); err != nil {
		if stoppedPreviousService {
			_ = startManagedService(previousServiceManager, currentCoreService)
		}
		r.coreLifecycleMu.Unlock()
		return map[string]any{"message": "agent config update failed", "path": path}, err
	}
	r.storeConfig(next)
	// A repaired controller URL / identity must be allowed to retry immediately
	// instead of waiting out a stale auth or throttle pause.
	r.controllerAuth.clear()
	if coreIdentityChanged {
		r.mu.Lock()
		r.coreBinaryCache = ""
		r.coreServiceCache = ""
		r.mu.Unlock()
	}
	r.coreLifecycleMu.Unlock()
	r.connectionAudit.setEnabled(next.ConnectionAuditEnabled)
	coreAuditErr := r.configureCoreConnectionAudit(context.Background(), next.ConnectionAuditEnabled)
	if !next.ConnectionAuditEnabled {
		r.connectionAuditMu.Lock()
		r.connectionAuditState = connectionAuditLocalState{}
		r.connectionAuditStateLoaded = false
		_ = os.Remove(r.connectionAuditStatePath())
		_ = r.clearAccountActivityPending()
		r.connectionAuditMu.Unlock()
	}
	if current.LogLevel != next.LogLevel || current.LogLevelExpiresAt != next.LogLevelExpiresAt {
		level := r.refreshLogLevel()
		logging.Warnf("agent log level set to %s expires_at=%q", level, r.Config().LogLevelExpiresAt)
	}
	logSettingsChanged := current.LogMaxMB != next.LogMaxMB || current.LogBackups != next.LogBackups || current.CoreLogMaxMB != next.CoreLogMaxMB || current.CoreLogBackups != next.CoreLogBackups || current.StorageProfile != next.StorageProfile || current.ResourceProfile != next.ResourceProfile || current.LogLevel != next.LogLevel
	if logSettingsChanged {
		// Refresh interval from new profile
		if profile := storageProfileFromConfig(next); profile != "" {
			r.logMaintenanceEvery = logMaintenanceIntervalForProfile(profile)
		}
		r.enforceLogLimits(false)
	}
	if oldStateDir != next.StateDir {
		r.trafficMu.Lock()
		r.trafficState = trafficLocalState{}
		r.trafficStateLoaded = false
		r.trafficMu.Unlock()
		r.connectionAuditMu.Lock()
		r.connectionAuditState = connectionAuditLocalState{}
		r.connectionAuditStateLoaded = false
		r.connectionAuditMu.Unlock()
	}
	result := map[string]any{
		"message":                  "agent config updated",
		"path":                     path,
		"controller_changed":       oldController != "" && next.ControllerURL != oldController,
		"restart_recommended":      oldController != "" && next.ControllerURL != oldController,
		"connection_audit_enabled": next.ConnectionAuditEnabled,
		"previous_core_service":    currentCoreService,
		"core_service":             nextCoreService,
		"previous_service_stopped": stoppedPreviousService,
	}
	if coreAuditErr != nil {
		result["connection_audit_core_sync_error"] = coreAuditErr.Error()
	}
	return result, nil
}

func (r *Runner) runNetworkDiagnostics(payloadJSON string) map[string]any {
	var payload model.DiagnoseNetworkTaskPayload
	_ = json.Unmarshal([]byte(payloadJSON), &payload)
	result := map[string]any{
		"message":       "network diagnostics completed",
		"version":       payload.Version,
		"server_id":     payload.ServerID,
		"agent_version": version.Version,
		"agent_build":   version.Build,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"time":          time.Now().UTC().Format(time.RFC3339Nano),
	}
	result["controller"] = r.diagnoseControllerConnectivity()
	result["entry_targets"] = r.diagnoseEntryTargets(payload.EntryTargets)
	commands := map[string]any{
		"ip_addr":            diagnosticCommand("ip", "-br", "addr"),
		"ip_route_v4":        diagnosticCommand("ip", "route"),
		"ip_route_v6":        diagnosticCommand("ip", "-6", "route"),
		"ss_tcp_listen":      diagnosticCommand("ss", "-lntup"),
		"ss_udp_listen":      diagnosticCommand("ss", "-lnup"),
		"sysctl_rp_filter":   diagnosticCommand("sysctl", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"),
		"nft_ruleset":        diagnosticCommand("nft", "list", "ruleset"),
		"iptables_save":      diagnosticCommand("iptables-save"),
		"ip6tables_save":     diagnosticCommand("ip6tables-save"),
		"ufw_status":         diagnosticCommand("ufw", "status", "verbose"),
		"public_ipv4":        diagnosticCommand("curl", "-4", "-fsS", "--max-time", "5", "https://api-ipv4.ip.sb/ip"),
		"public_ipv6":        diagnosticCommand("curl", "-6", "-fsS", "--max-time", "5", "https://api-ipv6.ip.sb/ip"),
		"tcp_socket_buffers": diagnosticCommand("sysctl", "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem"),
	}
	agentService := r.agentService()
	switch serviceManager() {
	case "systemd":
		commands["oboard_sb_active"] = diagnosticCommand("systemctl", "is-active", r.coreService())
		commands["oboard_sb_status"] = diagnosticCommand("systemctl", "--no-pager", "--full", "status", r.coreService())
		commands["oboard_agent_status"] = diagnosticCommand("systemctl", "--no-pager", "--full", "status", agentService)
		commands["oboard_sb_journal"] = diagnosticCommand("journalctl", "-u", r.coreService(), "-n", "80", "--no-pager")
		commands["oboard_agent_journal"] = diagnosticCommand("journalctl", "-u", agentService, "-n", "80", "--no-pager")
	case "openrc":
		commands["openrc_status"] = diagnosticCommand("rc-status", "-s")
		commands["oboard_sb_status"] = diagnosticCommand("rc-service", r.coreService(), "status")
		commands["oboard_agent_status"] = diagnosticCommand("rc-service", agentService, "status")
	case serviceManagerWindows:
		commands["oboard_sb_status"] = windowsServiceDiagnostic(r.coreService())
		commands["oboard_agent_status"] = windowsServiceDiagnostic(agentService)
	}
	result["commands"] = commands
	resourceCtx, resourceCancel := context.WithTimeout(context.Background(), 3*time.Second)
	result["core_resources"] = r.coreResourceSnapshot(resourceCtx)
	resourceCancel()
	files := map[string]any{
		"agent_config":          r.readDiagnosticConfigFile(r.configPath()),
		"sing_box_config":       readDiagnosticDecrypted(r, r.statePath(singBoxConfigFile)),
		"core_watchdog":         readDiagnosticDecrypted(r, r.statePath("core-watchdog.json")),
		"socket_tuning":         readDiagnosticDecrypted(r, r.statePath("socket-tuning.json")),
		"traffic_sync":          r.trafficSyncDiagnostics(),
		"cgroup_memory_events":  readDiagnosticFile("/sys/fs/cgroup/memory.events"),
		"cgroup_memory_current": readDiagnosticFile("/sys/fs/cgroup/memory.current"),
		"cgroup_memory_peak":    readDiagnosticFile("/sys/fs/cgroup/memory.peak"),
		"cgroup_memory_stat":    readDiagnosticFile("/sys/fs/cgroup/memory.stat"),
		"socket_memory_v4":      readDiagnosticFile("/proc/net/sockstat"),
		"socket_memory_v6":      readDiagnosticFile("/proc/net/sockstat6"),
	}
	// The service log files are the only place either process writes its own
	// diagnostics: both units redirect stdout and stderr there, so the systemd
	// journal carries lifecycle lines only. Attach them on every service
	// manager, not just OpenRC.
	files["oboard_agent_log"] = readDiagnosticTail(r.agentLogPath(), 80)
	files["oboard_sb_log"] = readDiagnosticTail(r.coreLogPath(), 80)
	result["files"] = files
	result["log_policy"] = r.logPolicySummary()
	result["ssh_inbounds"] = r.currentSSHDiagnostics()
	return result
}

func (r *Runner) diagnoseControllerConnectivity() map[string]any {
	cfg := r.Config()
	out := map[string]any{"transport": "agentlink", "controller_addr": cfg.ControllerAddr}
	host, port, err := net.SplitHostPort(cfg.ControllerAddr)
	if err != nil {
		out["error"] = "AgentLink 专用地址未配置或无效"
		return out
	}
	out["tcp"] = tcpDiagnosticProbe(host, port)
	return out
}

func (r *Runner) diagnoseEntryTargets(targets []model.DiagnosticTarget) []map[string]any {
	out := make([]map[string]any, 0, len(targets))
	for _, target := range targets {
		item := map[string]any{
			"name":     target.Name,
			"protocol": target.Protocol,
			"host":     target.Host,
			"port":     target.Port,
		}
		if strings.TrimSpace(target.Host) != "" && target.Port > 0 {
			if err := core.ValidateSafeHost(target.Host); err != nil {
				item["error"] = err.Error()
				out = append(out, item)
				continue
			}
			port := fmt.Sprint(target.Port)
			item["tcp_self_probe"] = tcpDiagnosticProbe(target.Host, port)
			item["route"] = diagnosticCommand("ip", "route", "get", target.Host)
			if strings.Contains(target.Host, ":") {
				item["route"] = diagnosticCommand("ip", "-6", "route", "get", target.Host)
			}
		}
		out = append(out, item)
	}
	return out
}

func (r *Runner) configPath() string {
	if configPath := strings.TrimSpace(r.Config().ConfigPath); configPath != "" {
		return configPath
	}
	return DefaultConfigPath()
}

// agentLogPath returns the agent service log path. In stealth mode the log
// file carries the generated service name.
func (r *Runner) agentLogPath() string {
	return filepath.Join(platformLogDir(), r.agentService()+".log")
}

// coreLogPath returns the kernel service log path.
func (r *Runner) coreLogPath() string {
	return filepath.Join(platformLogDir(), r.coreService()+".log")
}

func (r *Runner) collectLogs(payloadJSON string) map[string]any {
	maintenance := r.enforceLogLimits(false)
	var payload model.CollectLogsTaskPayload
	_ = json.Unmarshal([]byte(payloadJSON), &payload)
	if payload.Lines <= 0 {
		payload.Lines = 120
	}
	if payload.Lines > 2000 {
		payload.Lines = 2000
	}
	services := strings.ToLower(strings.TrimSpace(payload.Services))
	if services == "" {
		services = "all"
	}
	result := map[string]any{
		"message":       "logs collected",
		"agent_version": version.Version,
		"agent_build":   version.Build,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"time":          time.Now().UTC().Format(time.RFC3339Nano),
		"lines":         payload.Lines,
		"services":      services,
		"policy":        r.logPolicySummary(),
		"maintenance":   maintenance,
		"versions": map[string]any{
			"agent": version.String(),
			"core":  strings.TrimSpace(commandText(3*time.Second, r.coreBinary(), "-version")),
		},
	}
	logs := map[string]any{}
	if services == "all" || services == "agent" {
		logs["agent"] = r.collectServiceLog(r.agentService(), payload.Lines)
	}
	if services == "all" || services == "core" {
		logs["core"] = r.collectServiceLog(r.coreService(), payload.Lines)
	}
	result["logs"] = logs
	return result
}

func (r *Runner) collectServiceLog(service string, lines int) map[string]any {
	logPath := r.serviceLogPath(service)
	backups := r.Config().CoreLogBackups
	if service == r.agentService() {
		backups = r.Config().LogBackups
	}
	logFile := readManagedLogTail(logPath, backups, lines)
	item := map[string]any{"service": service, "log_path": logPath, "log_file": logFile}
	if strings.TrimSpace(service) == "" {
		item["ok"] = false
		item["error"] = "empty service"
		return item
	}
	switch serviceManager() {
	case "systemd":
		item["manager"] = "systemd"
		item["active"] = diagnosticCommand("systemctl", "is-active", service)
		item["status"] = diagnosticCommand("systemctl", "--no-pager", "--full", "status", service)
		fileOK, _ := logFile["ok"].(bool)
		if !fileOK {
			if _, err := exec.LookPath("journalctl"); err == nil {
				item["journal"] = diagnosticCommand("journalctl", "-u", service, "-n", fmt.Sprint(lines), "--no-pager")
			} else {
				item["system_log"] = readOpenRCSystemLogFallback(service, lines)
			}
		}
		item["ok"] = true
		return item
	case serviceManagerWindows:
		item["manager"] = serviceManagerWindows
		item["status"] = windowsServiceDiagnostic(service)
		item["ok"] = true
		return item
	case "openrc":
		item["manager"] = "openrc"
		item["status"] = diagnosticCommand("rc-service", service, "status")
		item["openrc_status"] = diagnosticCommand("rc-status", "-s")
		fileOK, _ := logFile["ok"].(bool)
		if !fileOK {
			item["system_log"] = readOpenRCSystemLogFallback(service, lines)
		}
		item["ok"] = true
		return item
	}
	item["ok"] = false
	item["error"] = "no supported service manager found"
	return item
}

// serviceManagerOverride is a test seam for the detected service manager.
var serviceManagerOverride func() string

func serviceManager() string {
	if serviceManagerOverride != nil {
		return serviceManagerOverride()
	}
	if runtime.GOOS == "windows" {
		return serviceManagerWindows
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		if st, statErr := os.Stat("/run/systemd/system"); statErr == nil && st.IsDir() {
			return "systemd"
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		return "openrc"
	}
	return ""
}

func commandText(timeout time.Duration, name string, args ...string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	out, err := commandOutput(timeout, name, args...)
	if err != nil && strings.TrimSpace(out) == "" {
		return err.Error()
	}
	return scrubDiagnosticOutput(out)
}

// windowsServiceDiagnostic reports an SCM service state in the same shape as
// diagnosticCommand, since Windows has no status command to capture.
func windowsServiceDiagnostic(service string) map[string]any {
	item := map[string]any{"command": "scm query " + service, "available": true}
	if err := windowsServiceActive(service); err != nil {
		item["ok"] = false
		item["error"] = err.Error()
		item["output"] = "inactive"
		return item
	}
	item["ok"] = true
	item["output"] = "active"
	return item
}

func diagnosticCommand(name string, args ...string) map[string]any {
	item := map[string]any{"command": strings.Join(append([]string{name}, args...), " ")}
	if _, err := exec.LookPath(name); err != nil {
		item["available"] = false
		item["error"] = err.Error()
		return item
	}
	start := time.Now()
	out, err := commandOutput(6*time.Second, name, args...)
	item["available"] = true
	item["duration_ms"] = time.Since(start).Milliseconds()
	item["output"] = scrubDiagnosticOutput(out)
	if err != nil {
		item["ok"] = false
		item["error"] = err.Error()
	} else {
		item["ok"] = true
	}
	return item
}

// readDiagnosticDecrypted reads a state file for diagnostics, decrypting it
// in stealth mode so the operator still gets useful content. The output is
// scrubbed like every other diagnostic.
func readDiagnosticDecrypted(r *Runner, path string) map[string]any {
	item := map[string]any{"path": path}
	data, err := r.stateReadPath(path)
	if err != nil {
		item["ok"] = false
		item["error"] = err.Error()
		return item
	}
	if len(data) > commandOutputLimit {
		data = data[:commandOutputLimit]
		item["truncated"] = true
	}
	item["ok"] = true
	item["content"] = scrubDiagnosticOutput(string(data))
	return item
}

// readDiagnosticConfigFile reads the agent config for diagnostics, decrypting
// it when the runner holds a stealth key.
func (r *Runner) readDiagnosticConfigFile(path string) map[string]any {
	if r.stealthOn() {
		return readDiagnosticDecrypted(r, path)
	}
	return readDiagnosticFile(path)
}

func readDiagnosticFile(path string) map[string]any {
	item := map[string]any{"path": path}
	if strings.TrimSpace(path) == "" {
		item["ok"] = false
		item["error"] = "empty path"
		return item
	}
	// #nosec G304 -- diagnostics intentionally read an operator-requested local path under the documented root-equivalent trust boundary.
	b, err := os.ReadFile(path)
	if err != nil {
		item["ok"] = false
		item["error"] = err.Error()
		return item
	}
	if len(b) > commandOutputLimit {
		b = b[:commandOutputLimit]
		item["truncated"] = true
	}
	item["ok"] = true
	item["content"] = scrubDiagnosticOutput(string(b))
	return item
}

func readDiagnosticTail(path string, lines int) map[string]any {
	item := map[string]any{"path": path, "tail_lines": normalizedLogLines(lines)}
	if strings.TrimSpace(path) == "" {
		item["ok"] = false
		item["error"] = "empty path"
		return item
	}
	content, truncated, err := readTailContent(path, commandOutputLimit)
	if err != nil {
		item["ok"] = false
		item["error"] = err.Error()
		return item
	}
	item["ok"] = true
	item["truncated"] = truncated
	item["content"] = scrubDiagnosticOutput(lastLines(content, normalizedLogLines(lines)))
	return item
}

func readOpenRCSystemLogFallback(service string, lines int) map[string]any {
	for _, path := range []string{"/var/log/messages", "/var/log/syslog"} {
		item := readDiagnosticTailMatching(path, []string{service, "oboard"}, lines)
		if ok, _ := item["ok"].(bool); ok {
			return item
		}
	}
	return map[string]any{
		"ok":    false,
		"paths": []string{"/var/log/messages", "/var/log/syslog"},
		"error": "no common OpenRC system log found",
	}
}

func readDiagnosticTailMatching(path string, patterns []string, lines int) map[string]any {
	item := map[string]any{"path": path, "tail_lines": normalizedLogLines(lines), "patterns": patterns}
	content, truncated, err := readTailContent(path, commandOutputLimit)
	if err != nil {
		item["ok"] = false
		item["error"] = err.Error()
		return item
	}
	lowerPatterns := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if p := strings.ToLower(strings.TrimSpace(pattern)); p != "" {
			lowerPatterns = append(lowerPatterns, p)
		}
	}
	var matched []string
	for _, line := range strings.Split(content, "\n") {
		lower := strings.ToLower(line)
		for _, pattern := range lowerPatterns {
			if strings.Contains(lower, pattern) {
				matched = append(matched, line)
				break
			}
		}
	}
	item["ok"] = true
	item["truncated"] = truncated
	item["content"] = scrubDiagnosticOutput(lastLines(strings.Join(matched, "\n"), normalizedLogLines(lines)))
	return item
}

func readTailContent(path string, maxBytes int) (string, bool, error) {
	if strings.TrimSpace(path) == "" {
		return "", false, errors.New("empty path")
	}
	// #nosec G304 -- diagnostics intentionally tail an operator-requested local path under the documented root-equivalent trust boundary.
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", false, err
	}
	size := st.Size()
	if maxBytes <= 0 || maxBytes > commandOutputLimit {
		maxBytes = commandOutputLimit
	}
	start := int64(0)
	truncated := false
	if size > int64(maxBytes) {
		start = size - int64(maxBytes)
		truncated = true
	}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return "", false, err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	if err != nil {
		return "", false, err
	}
	if truncated {
		if idx := bytes.IndexByte(b, '\n'); idx >= 0 && idx+1 < len(b) {
			b = b[idx+1:]
		}
	}
	return string(b), truncated, nil
}

func lastLines(content string, lines int) string {
	lines = normalizedLogLines(lines)
	content = strings.TrimRight(content, "\n")
	if content == "" {
		return ""
	}
	parts := strings.Split(content, "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

func normalizedLogLines(lines int) int {
	if lines <= 0 {
		return 120
	}
	if lines > 2000 {
		return 2000
	}
	return lines
}

func tcpDiagnosticProbe(host, port string) map[string]any {
	address := net.JoinHostPort(strings.Trim(host, "[]"), port)
	item := map[string]any{"address": address}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, 4*time.Second)
	item["duration_ms"] = time.Since(start).Milliseconds()
	if err != nil {
		item["ok"] = false
		item["error"] = err.Error()
		return item
	}
	defer conn.Close()
	item["ok"] = true
	item["local_addr"] = conn.LocalAddr().String()
	item["remote_addr"] = conn.RemoteAddr().String()
	return item
}

var diagnosticSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)("?(?:password|token|secret|private_key|agent_token|enrollment_token|uuid|psk)"?\s*[:=]\s*"?)[^",\s}]+`),
	regexp.MustCompile(`(?i)("key"\s*:\s*")[^"]+`),
}

func scrubDiagnosticOutput(out string) string {
	trimmed := strings.TrimSpace(out)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var value any
		if json.Unmarshal([]byte(trimmed), &value) == nil {
			scrubDiagnosticValue(value)
			if encoded, err := json.Marshal(value); err == nil {
				return string(encoded)
			}
		}
	}
	for _, pattern := range diagnosticSecretPatterns {
		out = pattern.ReplaceAllString(out, `${1}[redacted]`)
	}
	return redact.Text(out)
}

func scrubDiagnosticValue(value any) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") ||
				strings.Contains(lower, "private") || strings.Contains(lower, "uuid") || lower == "key" || lower == "psk" {
				node[key] = "[redacted]"
				continue
			}
			if text, ok := child.(string); ok {
				trimmed := strings.TrimSpace(text)
				if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
					var nested any
					if json.Unmarshal([]byte(trimmed), &nested) == nil {
						scrubDiagnosticValue(nested)
						if encoded, err := json.Marshal(nested); err == nil {
							node[key] = string(encoded)
							continue
						}
					}
				}
			}
			scrubDiagnosticValue(child)
		}
	case []any:
		for _, child := range node {
			scrubDiagnosticValue(child)
		}
	}
}

func (r *Runner) applyCoreConfigTask(version int64, payload model.ApplyCoreConfigTaskPayload) (map[string]any, error) {
	r.deploymentMu.Lock()
	defer r.deploymentMu.Unlock()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return map[string]any{"message": "config payload rejected", "version": version}, err
	}
	verdict, applied, err := r.checkAppliedVersion(model.AgentTaskTypeApplyCoreConfig, version, payloadBytes)
	if err != nil {
		return map[string]any{"message": "config apply rejected", "version": version}, err
	}
	// A newer configuration already runs here, so this task describes a past
	// intent and is skipped as a success. Managed assets are deliberately left
	// alone: pruning against a stale asset list would delete files the newer
	// configuration still references.
	if verdict == appliedVersionSuperseded {
		return supersededVersionResult(model.AgentTaskTypeApplyCoreConfig, version, applied), nil
	}
	// A replay may only be answered from local bookkeeping when the running
	// kernel actually serves what was recorded. Otherwise fall through to the
	// full apply, which re-verifies the runtime and restarts a drifted kernel.
	if verdict == appliedVersionReplay && payload.SSHInbounds == nil && r.coreRuntimeConverged(context.Background()) {
		if err := r.applyConfigAuthorization(context.Background(), []byte(payload.Config)); err != nil {
			return nil, err
		}
		if err := r.cleanupManagedAssets(payload.Assets); err != nil {
			return map[string]any{"message": "managed asset cleanup failed", "version": version, "idempotent_replay": true, "reload_strategy": "unchanged"}, err
		}
		result := map[string]any{"message": "config already applied", "version": version, "idempotent_replay": true, "reload_strategy": "unchanged", "managed_assets_changed": false}
		r.annotateActiveCoreRuntime(context.Background(), result)
		return result, nil
	}
	resolvedConfig, assetsChanged, err := r.syncManagedAssets(context.Background(), payload.Assets, payload.Config)
	if err != nil {
		return map[string]any{"message": "managed asset sync failed", "version": version, "managed_assets_changed": false}, err
	}
	result, err := r.applyCoreConfigUnlocked(version, resolvedConfig, false)
	if err != nil {
		return result, err
	}
	result["managed_assets_changed"] = assetsChanged
	if payload.SSHInbounds != nil {
		sshResult, err := r.applySSHInbounds(*payload.SSHInbounds)
		result["ssh_inbounds"] = sshResult
		if err != nil {
			return result, err
		}
	}
	if err := r.persistAppliedVersion(model.AgentTaskTypeApplyCoreConfig, version, payloadBytes); err != nil {
		return result, fmt.Errorf("persist applied config version: %w", err)
	}
	if err := r.cleanupManagedAssets(payload.Assets); err != nil {
		return result, fmt.Errorf("cleanup managed assets: %w", err)
	}
	return result, nil
}

func (r *Runner) applyCoreConfigUnlocked(version int64, config string, forceRestart bool) (map[string]any, error) {
	r.coreLifecycleMu.Lock()
	defer r.coreLifecycleMu.Unlock()
	// An operator running the shell update at the same moment is replacing the
	// kernel binary and restarting the service outside this process. Applying
	// on top of that races the file it is installing.
	hostLock, hostLockErr := r.acquireHostCoreLock(hostCoreLockWait)
	if hostLockErr != nil {
		return map[string]any{"message": "config apply deferred", "version": version, "reload_strategy": "host_lock_busy"}, hostLockErr
	}
	defer hostLock.release()
	if err := r.stageConfigAuthorization([]byte(config)); err != nil {
		return map[string]any{"message": "authorization rejected"}, err
	}
	r.forwardLifecycleMu.Lock()
	defer r.forwardLifecycleMu.Unlock()
	result := map[string]any{
		"message":             "config apply started",
		"version":             version,
		"validated":           false,
		"reload_strategy":     "pending",
		"connection_draining": true,
		"connection_note":     "oboard-sb has no in-process reload; an operational change is applied with a controlled restart and verified against the running kernel",
	}
	finishOperationalApply := func(message, strategy string, draining bool) (map[string]any, error) {
		if err := r.applyConfigAuthorization(context.Background(), []byte(config)); err != nil {
			return result, err
		}
		if err := r.reapplyPersistedRuntimeUsers(context.Background(), []byte(config)); err != nil {
			result["runtime_users_error"] = err.Error()
		}
		result["message"] = message
		result["reload_strategy"] = strategy
		result["connection_draining"] = draining
		if err := r.reconcileSharedCoreAndSSHTrafficPolicies(context.Background(), []byte(config)); err != nil {
			result["runtime_policy_error"] = err.Error()
			return result, fmt.Errorf("sync shared core/SSH runtime policy: %w", err)
		}
		if err := r.configureCoreClock(context.Background()); err != nil {
			result["runtime_clock_error"] = err.Error()
		}
		return result, nil
	}
	stateDir := r.stateDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return result, err
	}
	current := r.statePath(singBoxConfigFile)
	backup := r.statePath(singBoxLastGoodFile)
	var previousConfig []byte
	if b, err := r.stateReadPath(current); err == nil {
		previousConfig = b
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	ctx := context.Background()
	// A deployment is only converged when the process that serves traffic runs
	// the desired operational configuration. Matching bytes on disk are not
	// evidence of that, so the running kernel is asked directly and restarted
	// when it turns out to be stale.
	recoverRuntimeDrift := func(check coreRuntimeCheck) (map[string]any, error) {
		logging.Warnf("core runtime drift: loaded=%s desired=%s; restarting %s", check.LoadedDigest, check.DesiredDigest, r.coreService())
		recovered, err := r.restartCoreForRuntimeDrift(ctx, []byte(config))
		recovered.annotate(result)
		// The recovery is reported as a drift even when it succeeded, so the
		// task result records that the kernel had to be brought back.
		result["runtime_drift"] = true
		result["runtime_drift_recovered"] = err == nil && !recovered.drift()
		if err != nil {
			result["reload_strategy"] = "runtime_drift_restart_failed"
			return result, fmt.Errorf("restart core after runtime drift: %w", err)
		}
		if recovered.drift() {
			result["reload_strategy"] = "runtime_drift_restart_failed"
			return result, fmt.Errorf("core still runs configuration %s after restart, expected %s", recovered.LoadedDigest, recovered.DesiredDigest)
		}
		return finishOperationalApply("core restarted after runtime configuration drift", "runtime_drift_restart", false)
	}
	if !forceRestart && len(previousConfig) > 0 && bytes.Equal(bytes.TrimSpace(previousConfig), bytes.TrimSpace([]byte(config))) {
		result["validated"] = true
		result["unchanged"] = true
		check := r.checkCoreRuntimeConfig(ctx, []byte(config))
		check.annotate(result)
		if check.drift() {
			return recoverRuntimeDrift(check)
		}
		return finishOperationalApply("core config already active", "unchanged", false)
	}
	if len(previousConfig) > 0 {
		if err := r.stateWritePath(backup, previousConfig, 0o600); err != nil {
			return result, err
		}
	}
	candidateLogical := fmt.Sprintf("sing-box.%d.json", version)
	candidate := r.statePath(candidateLogical)
	if err := r.stateWritePath(candidate, []byte(config), 0o600); err != nil {
		return result, err
	}
	defer os.Remove(candidate)
	if err := r.validateSingBox(r.coreBinary(), candidate, r.commandTimeout()); err != nil {
		result["reload_strategy"] = "validation_failed"
		return result, err
	}
	result["validated"] = true
	if err := r.stateWritePath(current, []byte(config), 0o600); err != nil {
		return result, err
	}
	metadataOnly, metadataErr := coreRuntimeMetadataOnlyChange(previousConfig, []byte(config))
	if metadataErr != nil {
		if restoreErr := r.restoreCoreConfigFile(current, previousConfig); restoreErr != nil {
			result["rollback_error"] = restoreErr.Error()
		}
		result["reload_strategy"] = "metadata_compare_failed"
		return result, metadataErr
	}
	if metadataOnly && !forceRestart {
		// Runtime policy is pushed into the live process, so it must not be
		// used to skip a restart while that process still runs an older
		// operational configuration.
		check := r.checkCoreRuntimeConfig(ctx, []byte(config))
		check.annotate(result)
		if check.drift() {
			return recoverRuntimeDrift(check)
		}
		policies, err := embeddedCoreTrafficPolicies([]byte(config))
		if err != nil {
			if restoreErr := r.restoreCoreConfigFile(current, previousConfig); restoreErr != nil {
				result["rollback_error"] = restoreErr.Error()
			}
			result["reload_strategy"] = "runtime_policy_parse_failed"
			return result, err
		}
		if err := r.pushTrafficPolicies(context.Background(), policies, r.trafficAcknowledgements()); err != nil {
			if restoreErr := r.restoreCoreConfigFile(current, previousConfig); restoreErr != nil {
				result["rollback_error"] = restoreErr.Error()
			}
			result["reload_strategy"] = "runtime_policy_sync_failed"
			return result, fmt.Errorf("sync runtime-only core policy: %w", err)
		}
		// The lease is part of the runtime policy the live process enforces:
		// a snapshot that only changed grants must still reach the kernel.
		if err := r.applyConfigAuthorization(context.Background(), []byte(config)); err != nil {
			result["reload_strategy"] = "runtime_authorization_sync_failed"
			return result, fmt.Errorf("sync runtime-only authorization: %w", err)
		}
		if err := r.reapplyPersistedRuntimeUsers(context.Background(), []byte(config)); err != nil {
			result["runtime_users_error"] = err.Error()
		}
		result["message"] = "runtime policy updated without core reload"
		result["reload_strategy"] = "runtime_policy_only"
		result["connection_draining"] = false
		return result, nil
	}
	forwardHandoff, err := r.suspendConflictingForwards([]byte(config))
	if err != nil {
		if len(previousConfig) > 0 {
			if restoreErr := atomicWriteFile(current, previousConfig, 0o600); restoreErr != nil {
				result["rollback_error"] = restoreErr.Error()
			}
		} else if removeErr := os.Remove(current); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			result["rollback_error"] = removeErr.Error()
		}
		result["reload_strategy"] = "forward_handoff_failed"
		return result, err
	}
	if forwardHandoff != nil {
		result["forward_handoff"] = true
		result["suspended_forward_ids"] = forwardHandoff.conflictIDs()
		result["suspended_forward_ports"] = forwardHandoff.conflictPorts()
	}
	rollbackForwards := func() {
		if forwardHandoff == nil {
			return
		}
		if restoreErr := r.rollbackForwardHandoff(forwardHandoff); restoreErr != nil {
			result["forward_rollback_error"] = restoreErr.Error()
		}
	}
	commitForwards := func() error {
		if forwardHandoff == nil {
			return nil
		}
		return r.commitForwardHandoff(forwardHandoff)
	}
	rollbackConfig := func() {
		if len(previousConfig) == 0 {
			if removeErr := os.Remove(current); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				result["rollback_error"] = removeErr.Error()
			}
			return
		}
		if restoreErr := atomicWriteFile(current, previousConfig, 0o600); restoreErr != nil {
			result["rollback_error"] = restoreErr.Error()
			return
		}
		r.restoreCoreRuntime(ctx, previousConfig, result)
	}
	removedListenResources := removedInboundListenResources(previousConfig, []byte(config))
	if len(removedListenResources) > 0 {
		result["reload_strategy"] = "restart_required"
		result["restart_reason"] = "inbound listen resource removed or changed"
		result["removed_listen_resources"] = removedListenResources
	} else {
		// Core capability decides this, not the service-manager wiring. An
		// unmanaged reload_command used to skip the capability check entirely,
		// which reported "hot_reload" for oboard-sb even though nothing had
		// reloaded it.
		canReload := r.coreHotReloadSupported()
		if !canReload {
			result["reload_error"] = "the configured core has no in-process configuration reload; applying with a controlled restart"
		} else if r.managedReloadEnabled() {
			if err := r.coreServiceActive(); err != nil {
				canReload = false
				result["reload_error"] = "core service is not running: " + err.Error()
			}
		}
		if canReload {
			if err := r.reloadCore(); err == nil {
				if !r.managedReloadEnabled() || r.waitCoreServiceStable(3*time.Second) == nil {
					if err := commitForwards(); err != nil {
						result["reload_strategy"] = "rollback"
						result["forward_commit_error"] = err.Error()
						rollbackConfig()
						rollbackForwards()
						return result, fmt.Errorf("persist forward handoff: %w", err)
					}
					check := r.awaitCoreRuntimeConfig(ctx, []byte(config), r.coreRuntimeVerifyWindow())
					check.annotate(result)
					if check.drift() {
						return recoverRuntimeDrift(check)
					}
					return finishOperationalApply("config applied with hot reload", "hot_reload", true)
				}
				result["reload_error"] = "core service stopped after reload"
			} else {
				result["reload_error"] = err.Error()
			}
		}
	}
	if err := r.restartCore(); err != nil {
		result["reload_strategy"] = "rollback"
		rollbackConfig()
		rollbackForwards()
		return result, err
	}
	if r.managedRestartEnabled() {
		if err := r.waitCoreServiceStable(3 * time.Second); err != nil {
			result["reload_strategy"] = "rollback"
			result["restart_error"] = err.Error()
			rollbackConfig()
			rollbackForwards()
			return result, fmt.Errorf("core did not stay running after restart: %w", err)
		}
	}
	if err := commitForwards(); err != nil {
		result["reload_strategy"] = "rollback"
		result["forward_commit_error"] = err.Error()
		rollbackConfig()
		rollbackForwards()
		return result, fmt.Errorf("persist forward handoff: %w", err)
	}
	check := r.awaitCoreRuntimeConfig(ctx, []byte(config), r.coreRuntimeVerifyWindow())
	check.annotate(result)
	if check.drift() {
		result["reload_strategy"] = "restart_verification_failed"
		return result, fmt.Errorf("core still runs configuration %s after restart, expected %s", check.LoadedDigest, check.DesiredDigest)
	}
	return finishOperationalApply("config applied with restart fallback", "restart_fallback", false)
}

func (r *Runner) restoreCoreConfigFile(path string, previous []byte) error {
	if len(previous) > 0 {
		return r.stateWritePath(path, previous, 0o600)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func embeddedCoreTrafficPolicies(config []byte) (map[string]interface{}, error) {
	var root struct {
		OBoard struct {
			RateLimits struct {
				Users    map[string]json.RawMessage `json:"users"`
				Inbounds map[string]json.RawMessage `json:"inbounds"`
			} `json:"rate_limits"`
		} `json:"_oboard"`
	}
	if err := json.Unmarshal(config, &root); err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	collect := func(items map[string]json.RawMessage) error {
		for _, raw := range items {
			var policy model.TrafficRuntimePolicy
			if err := json.Unmarshal(raw, &policy); err != nil {
				return err
			}
			if policy.UserID > 0 {
				out[fmt.Sprintf("user:%d", policy.UserID)] = policy
			}
		}
		return nil
	}
	if err := collect(root.OBoard.RateLimits.Users); err != nil {
		return nil, err
	}
	if err := collect(root.OBoard.RateLimits.Inbounds); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Runner) managedReloadEnabled() bool {
	return strings.TrimSpace(r.Config().ReloadCommand) != "none"
}

func (r *Runner) managedRestartEnabled() bool {
	return strings.TrimSpace(r.Config().RestartCommand) != "none"
}

// coreHotReloadSupported reports whether the configured core really implements
// an in-process configuration reload.
//
// oboard-sb does not: cmd/oboard-sb only installs SIGINT/SIGTERM handlers, so a
// reload signal is never a reload. Every oboard-sb configuration change and
// every rollback therefore goes through a controlled restart that is verified
// against GET /runtime/status. Operators pointing Agent at a third-party core
// keep the reload path. This must stay false for oboard-sb until the kernel
// advertises a real runtime-reload capability.
func (r *Runner) coreHotReloadSupported() bool {
	// In stealth mode the core is always the OBoard kernel under a generated
	// name, so the reload path must stay closed exactly as for oboard-sb.
	if r.stealthOn() {
		return false
	}
	binary := strings.ToLower(executableBase(strings.TrimSpace(r.coreBinary())))
	service := strings.ToLower(strings.TrimSpace(r.coreService()))
	return binary != "oboard-sb" && service != "oboard-sb"
}

func (r *Runner) coreServiceActive() error {
	if active := r.coreServiceActiveCheck; active != nil {
		return active()
	}
	return managedServiceActive(detectServiceManager(), r.coreService())
}

func managedServiceActive(manager, service string) error {
	switch manager {
	case serviceManagerWindows:
		return windowsServiceActive(service)
	case "systemd":
		return runCommand(3*time.Second, "systemctl", "is-active", "--quiet", service)
	case "openrc":
		return runCommand(3*time.Second, "rc-service", service, "status")
	default:
		return errors.New("supported service manager is unavailable")
	}
}

func startManagedService(manager, service string) error {
	if manager == serviceManagerWindows {
		return windowsServiceStart(service, 20*time.Second)
	}
	if manager == "systemd" {
		return runCommand(20*time.Second, "systemctl", "start", service)
	}
	if manager == "openrc" {
		return runCommand(20*time.Second, "rc-service", service, "start")
	}
	return fmt.Errorf("supported service manager is unavailable")
}

func (r *Runner) waitCoreServiceStable(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	stableChecks := 0
	var lastErr error
	for time.Now().Before(deadline) {
		if err := r.coreServiceActive(); err == nil {
			stableChecks++
			if stableChecks >= 3 {
				return nil
			}
		} else {
			stableChecks = 0
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("service did not remain active")
	}
	return lastErr
}

func removedInboundListenResources(previous, next []byte) []string {
	previousResources := inboundListenResources(previous)
	if len(previousResources) == 0 {
		return nil
	}
	nextResources := inboundListenResources(next)
	removed := []string{}
	for resource := range previousResources {
		if _, ok := nextResources[resource]; !ok {
			removed = append(removed, resource)
		}
	}
	sort.Strings(removed)
	return removed
}

func inboundListenResources(raw []byte) map[string]struct{} {
	resources := map[string]struct{}{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return resources
	}
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return resources
	}
	for _, inbound := range cfg.Inbounds {
		listen := strings.TrimSpace(fmt.Sprint(inbound["listen"]))
		if listen == "" || listen == "<nil>" {
			listen = "0.0.0.0"
		}
		port := fmt.Sprint(inbound["listen_port"])
		if port == "" || port == "<nil>" {
			continue
		}
		resources[fmt.Sprintf("%s/%s/%s:%s", fmt.Sprint(inbound["tag"]), fmt.Sprint(inbound["type"]), listen, port)] = struct{}{}
	}
	return resources
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return securefile.Write(path, data, perm, false)
}

func (r *Runner) coreBinary() string {
	if coreBinary := r.Config().CoreBinary; coreBinary != "" {
		return coreBinary
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.coreBinaryCache != "" {
		return r.coreBinaryCache
	}
	r.coreBinaryCache = "oboard-sb"
	return r.coreBinaryCache
}

// realmBinary returns the bundled oboard-realm binary installed beside the
// Agent. It is deliberately not configurable: the binary is delivered by the
// signed release, so accepting an operator- or Controller-supplied path would
// only add a way to run an unverified root process.
func (r *Runner) realmBinary() string {
	executable, err := selfExecutablePath()
	if err != nil {
		return ""
	}
	if r.stealthOn() && r.Config().Stealth != nil {
		return filepath.Join(filepath.Dir(executable), r.Config().Stealth.Identity.RealmName)
	}
	return InstalledRealmBinary(executable)
}

func (r *Runner) coreService() string {
	if coreService := r.Config().CoreService; coreService != "" {
		return coreService
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.coreServiceCache != "" {
		return r.coreServiceCache
	}
	r.coreServiceCache = "oboard-sb"
	return r.coreServiceCache
}

func (r *Runner) restartCore() error {
	if err := r.persistTrafficCheckpointBeforeRuntimeTransition(context.Background()); err != nil {
		return err
	}
	if restart := r.coreRestartCommand; restart != nil {
		return restart()
	}
	restartCommand := strings.TrimSpace(r.Config().RestartCommand)
	switch restartCommand {
	case "", "auto":
		switch detectServiceManager() {
		case serviceManagerWindows:
			return windowsServiceRestart(r.coreService(), r.commandTimeout())
		case "systemd":
			return runCommand(r.commandTimeout(), "systemctl", "restart", r.coreService())
		case "openrc":
			return runCommand(r.commandTimeout(), "rc-service", r.coreService(), "restart")
		default:
			return errors.New("supported service manager is unavailable; set restart_command to \"none\" for container-managed cores")
		}
	case "none":
		return nil
	case "systemd-restart":
		return runCommand(r.commandTimeout(), "systemctl", "restart", r.coreService())
	case "openrc-restart":
		return runCommand(r.commandTimeout(), "rc-service", r.coreService(), "restart")
	default:
		return fmt.Errorf("restart_command %q is not an allowed managed preset", restartCommand)
	}
}

func (r *Runner) reloadCore() error {
	if err := r.persistTrafficCheckpointBeforeRuntimeTransition(context.Background()); err != nil {
		return err
	}
	reloadCommand := strings.TrimSpace(r.Config().ReloadCommand)
	switch reloadCommand {
	case "", "auto":
		switch detectServiceManager() {
		case "systemd":
			return runCommand(r.commandTimeout(), "systemctl", "reload", r.coreService())
		case "openrc":
			return runCommand(r.commandTimeout(), "rc-service", r.coreService(), "reload")
		default:
			return errors.New("supported service manager reload is unavailable")
		}
	case "none":
		return nil
	case "systemd-reload":
		return runCommand(r.commandTimeout(), "systemctl", "reload", r.coreService())
	case "openrc-reload":
		return runCommand(r.commandTimeout(), "rc-service", r.coreService(), "reload")
	default:
		return fmt.Errorf("reload_command %q is not an allowed managed preset", reloadCommand)
	}
}

// singBoxConfigFile and singBoxLastGoodFile are the logical state names for
// the kernel configuration. In stealth mode they map to derived physical
// names; the constants exist so every reader agrees on the logical name.
const (
	singBoxConfigFile   = "sing-box.json"
	singBoxLastGoodFile = "sing-box.last-good.json"
)

// stealthKeyPath returns the on-disk key file path when running in stealth
// mode, for subprocesses (-check, -operational-digest) that must decrypt the
// configuration themselves.
func (r *Runner) stealthKeyPath() string {
	if !r.stealthOn() {
		return ""
	}
	return r.Config().Stealth.KeyPath
}

func (r *Runner) validateSingBox(binary, path string, timeout time.Duration) error {
	raw, err := r.stateReadPath(path)
	if err != nil {
		return err
	}
	if err := validateSnellCoreConfig(raw); err != nil {
		return err
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil
	}
	// In stealth mode the core is always the OBoard kernel (third-party cores
	// cannot read an encrypted configuration), so the oboard-sb flag style is
	// correct regardless of the renamed binary.
	if r.stealthOn() {
		args := []string{"-check", "-config", path}
		if keyPath := r.stealthKeyPath(); keyPath != "" {
			args = append(args, "-key", keyPath)
		}
		return runCommand(timeout, binary, args...)
	}
	if executableBase(binary) == "oboard-sb" {
		return runCommand(timeout, binary, "-check", "-config", path)
	}
	return runCommand(timeout, binary, "check", "-c", path)
}

func (r *Runner) ReportTaskResult(ctx context.Context, id int64, status, result string, health *model.HealthReport) error {
	return r.postControllerJSON(ctx, "/api/v1/agent/task-results", model.AgentTaskResultReport{TaskID: id, Status: status, ResultJSON: result, HealthReport: health}, nil, true)
}

func (r *Runner) postControllerJSON(ctx context.Context, path string, body any, out any, auth bool) error {
	return r.controllerJSON(ctx, http.MethodPost, path, nil, body, out, auth)
}

// controllerJSON performs one authenticated Controller callback. A nil body
// sends no request body (GET); extra headers are added verbatim. In stealth
// mode the callback travels as an RPC frame over the binary transport
// instead of HTTP: the agent never touches the panel's HTTP surface.
func (r *Runner) controllerJSON(ctx context.Context, method, path string, headers http.Header, body any, out any, auth bool) error {
	return r.controllerJSONOverTransport(ctx, method, path, headers, body, out, auth)
}

// Task completion must not wait for public-IP discovery or another health probe.
func (r *Runner) taskResultHealth() *model.HealthReport {
	r.mu.Lock()
	health := r.lastProbe
	r.mu.Unlock()
	if health.AgentID == "" {
		return nil
	}
	if applied, err := r.loadAppliedVersion(); err == nil {
		health.AppliedConfigVersion = applied.Version
		health.AppliedConfigDigest = applied.PayloadID
	}
	health.AppliedAuthorization = r.appliedAuthorization()
	health.AppliedUsers = r.appliedUsers()
	health.AppliedLatencyProbe = r.appliedLatencyProbe()
	return &health
}

func (r *Runner) Probe(force bool) model.HealthReport {
	// Serializing probes prevents duplicate public-IP TLS handshakes when
	// reconnect and heartbeat events arrive together, and keeps CPU samples
	// strictly sequential.
	r.probeMu.Lock()
	defer r.probeMu.Unlock()

	now := time.Now().UTC()
	publicInterval := r.resources.PublicIPProbeInterval()

	r.mu.Lock()
	monitoringMode := r.monitoringMode
	localMin := monitoringLocalMetricsInterval(monitoringMode)
	reuseLocal := !force && !r.lastLocalMetricsAt.IsZero() && now.Sub(r.lastLocalMetricsAt) < localMin && r.lastProbe.AgentID != ""
	cached := r.lastProbe
	lastCPU := r.lastCPUSample
	lastNetwork := r.lastNetworkSample
	lastIPv4, lastIPv6, lastRegionCode := r.lastPublicIPv4, r.lastPublicIPv6, r.lastRegionCode
	lastPublicAt := r.lastPublicIPAt
	lastCoreVersion, lastKernelCapabilities, lastCoreVersionAt := r.lastCoreVersion, append([]string(nil), r.lastKernelCapabilities...), r.lastCoreVersionAt
	r.mu.Unlock()

	var probe systemProbe
	if reuseLocal {
		// Keep the last local metrics, but still refresh the timestamp and any
		// public-IP cache expiry below so heartbeats stay current.
		probe = systemProbe{
			CPUName:                   firstNonEmpty(cached.CPU, r.hostInfo.CPUName),
			CPUUsagePercent:           cached.CPUUsagePercent,
			MemoryUsedBytes:           cached.MemoryUsedBytes,
			MemoryTotalBytes:          cached.MemoryTotalBytes,
			AgentMemoryBytes:          cached.AgentMemoryBytes,
			DiskUsedBytes:             cached.DiskBytes,
			DiskTotalBytes:            cached.DiskTotalBytes,
			TCPConnectionCount:        cached.TCPConnectionCount,
			UDPConnectionCount:        cached.UDPConnectionCount,
			ProcessCount:              cached.ProcessCount,
			NetworkUploadBPS:          cached.NetworkUploadBPS,
			NetworkDownloadBPS:        cached.NetworkDownloadBPS,
			NetworkTotalUploadBytes:   cached.NetworkTotalUploadBytes,
			NetworkTotalDownloadBytes: cached.NetworkTotalDownloadBytes,
		}
	} else {
		var currentCPU procCPU
		probe, currentCPU = sampleSystemProbe(r.hostInfo.CPUName, lastCPU)
		networkProbe, currentNetwork := sampleHostNetwork(lastNetwork, now)
		if currentNetwork.Valid {
			probe.NetworkUploadBPS = networkProbe.NetworkUploadBPS
			probe.NetworkDownloadBPS = networkProbe.NetworkDownloadBPS
			probe.NetworkTotalUploadBytes = networkProbe.NetworkTotalUploadBytes
			probe.NetworkTotalDownloadBytes = networkProbe.NetworkTotalDownloadBytes
		} else {
			probe.NetworkUploadBPS = cached.NetworkUploadBPS
			probe.NetworkDownloadBPS = cached.NetworkDownloadBPS
			probe.NetworkTotalUploadBytes = cached.NetworkTotalUploadBytes
			probe.NetworkTotalDownloadBytes = cached.NetworkTotalDownloadBytes
		}
		// If the short sample window produced no usage (counter flat or first
		// sample failed), keep the previous non-zero reading so the panel does
		// not flicker back to "—" / 0 between heartbeats.
		if probe.CPUUsagePercent == 0 && cached.CPUUsagePercent > 0 && lastCPU.total > 0 {
			probe.CPUUsagePercent = cached.CPUUsagePercent
		}
		r.mu.Lock()
		r.lastCPUSample = currentCPU
		if currentNetwork.Valid {
			r.lastNetworkSample = currentNetwork
		}
		r.lastLocalMetricsAt = now
		r.mu.Unlock()
	}

	if limit := r.resources.CgroupMemoryLimitBytes; limit > 0 && (probe.MemoryTotalBytes == 0 || limit < probe.MemoryTotalBytes) {
		probe.MemoryTotalBytes = limit
		if !reuseLocal {
			if usage := detectedCgroupMemoryUsage(); usage > 0 {
				probe.MemoryUsedBytes = usage
			} else if probe.MemoryUsedBytes > limit {
				probe.MemoryUsedBytes = limit
			}
		}
	}

	publicIPv4, publicIPv6, regionCode := lastIPv4, lastIPv6, lastRegionCode
	refreshPublic := force || lastPublicAt.IsZero() || now.Sub(lastPublicAt) >= publicInterval
	if refreshPublic {
		var detectedIPv4, detectedIPv6, detectedRegionCode string
		var publicWG sync.WaitGroup
		publicWG.Add(2)
		go func() {
			defer publicWG.Done()
			detectedIPv4, detectedIPv6 = detectPublicIPs(3 * time.Second)
		}()
		go func() {
			defer publicWG.Done()
			detectedRegionCode = detectEgressRegionCode(3 * time.Second)
		}()
		publicWG.Wait()
		publicIPv4, publicIPv6 = detectedIPv4, detectedIPv6
		// Prefer a successful previous family if the new probe timed out on one side.
		if publicIPv4 == "" {
			publicIPv4 = lastIPv4
		}
		if publicIPv6 == "" {
			publicIPv6 = lastIPv6
		}
		if detectedRegionCode != "" {
			regionCode = detectedRegionCode
		}
		r.mu.Lock()
		r.lastPublicIPv4, r.lastPublicIPv6 = publicIPv4, publicIPv6
		r.lastRegionCode = regionCode
		r.lastPublicIPAt = now
		r.mu.Unlock()
	}

	coreVersion := lastCoreVersion
	kernelCapabilities := lastKernelCapabilities
	refreshCore := force || lastCoreVersion == "" || lastCoreVersionAt.IsZero() || now.Sub(lastCoreVersionAt) >= publicInterval
	if refreshCore {
		coreVersion, kernelCapabilities = r.coreIdentity()
		r.mu.Lock()
		r.lastCoreVersion = coreVersion
		r.lastKernelCapabilities = append([]string(nil), kernelCapabilities...)
		r.lastCoreVersionAt = now
		r.mu.Unlock()
	}

	health := buildHealthReport(r.coreBinary(), r.commandTimeout(), r.hostInfo, probe, publicIPv4, publicIPv6, coreVersion, r.agentCapabilities(kernelCapabilities))
	health.AgentID = r.Config().AgentID
	health.RegionCode = regionCode
	health.NetworkUploadBPS = probe.NetworkUploadBPS
	health.NetworkDownloadBPS = probe.NetworkDownloadBPS
	health.NetworkTotalUploadBytes = probe.NetworkTotalUploadBytes
	health.NetworkTotalDownloadBytes = probe.NetworkTotalDownloadBytes
	health.Timestamp = now
	health.RemoteAccess = r.remoteAccessReport()
	health.RuntimeSecurity = r.cachedRuntimeSecurity()
	health.VPNGatePools = r.cachedVPNGateStatus()
	for _, capability := range kernelCapabilities {
		if capability == model.ProxyDSCPKernelCapability {
			health.ProxyDSCP = r.proxyDSCPHealth()
			break
		}
	}
	health.AppliedAuthorization = r.appliedAuthorization()
	health.AppliedUsers = r.appliedUsers()
	health.AppliedLatencyProbe = r.appliedLatencyProbe()
	diskInfo := r.storageDiskInfo()
	health.DiskAvailableBytes = diskInfo.AvailableBytes
	health.DiskPressure = diskInfo.Pressure
	health.StorageProfile = string(diskInfo.StorageProfile)
	health.Storage = &model.StorageDiskInfo{
		TotalBytes:     diskInfo.TotalBytes,
		AvailableBytes: diskInfo.AvailableBytes,
		UsagePercent:   diskInfo.UsagePercent,
		StorageProfile: string(diskInfo.StorageProfile),
		Pressure:       diskInfo.Pressure,
	}
	// Opportunistic emergency cleanup on health probe interval (cheap statfs, not du)
	if diskInfo.Pressure == "critical" {
		go r.enforceEmergencyDiskCleanup()
	}
	if applied, appliedErr := r.loadAppliedVersion(); appliedErr == nil {
		health.AppliedConfigVersion = applied.Version
		health.AppliedConfigDigest = applied.PayloadID
	}

	r.mu.Lock()
	r.lastProbe = health
	r.lastProbeAt = now
	r.mu.Unlock()
	return health
}

func monitoringLocalMetricsInterval(mode string) time.Duration {
	if strings.EqualFold(strings.TrimSpace(mode), "standard") {
		return 9 * time.Second
	}
	return 19 * time.Second
}

func (r *Runner) commandTimeout() time.Duration {
	seconds := r.Config().CommandTimeoutSeconds
	if seconds <= 0 {
		seconds = 20
	}
	return time.Duration(seconds) * time.Second
}

func buildHealthReport(binary string, timeout time.Duration, host hostStaticInfo, probe systemProbe, publicIPv4, publicIPv6, coreVersion string, kernelCapabilities []string) model.HealthReport {
	if publicIPv4 == "" && publicIPv6 == "" {
		// First-run paths detect public addresses here before the probe cache is warm.
		publicIPv4, publicIPv6 = detectPublicIPs(timeout)
	}
	if coreVersion == "" {
		coreVersion, kernelCapabilities = singBoxIdentity(binary, timeout)
	}
	tfoState, tfoValue := detectTCPFastOpen()
	return model.HealthReport{
		Status:             model.ServerOnline,
		OS:                 runtime.GOOS,
		DistroID:           host.Distro.ID,
		DistroVersion:      host.Distro.Version,
		DistroName:         host.Distro.Name,
		Libc:               host.Distro.Libc,
		ServiceManager:     host.Distro.ServiceManager,
		PackageManager:     host.Distro.PackageManager,
		Arch:               runtime.GOARCH,
		Kernel:             host.Kernel,
		CPU:                firstNonEmpty(probe.CPUName, host.CPUName, runtime.GOARCH),
		CPUCores:           host.CPUCores,
		MemoryBytes:        probe.MemoryUsedBytes,
		CPUUsagePercent:    probe.CPUUsagePercent,
		MemoryUsedBytes:    probe.MemoryUsedBytes,
		MemoryTotalBytes:   probe.MemoryTotalBytes,
		AgentMemoryBytes:   probe.AgentMemoryBytes,
		DiskBytes:          probe.DiskUsedBytes,
		DiskTotalBytes:     probe.DiskTotalBytes,
		TCPConnectionCount: probe.TCPConnectionCount,
		UDPConnectionCount: probe.UDPConnectionCount,
		ProcessCount:       probe.ProcessCount,
		PublicIPv4:         publicIPv4,
		PublicIPv6:         publicIPv6,
		InterfaceIPv6:      detectInterfaceIPv6(),
		AgentVersion:       version.Version,
		AgentBuild:         version.Build,
		SingBoxVersion:     coreVersion,
		KernelCapabilities: kernelCapabilities,

		TCPFastOpenState: tfoState,
		TCPFastOpenValue: tfoValue,
		Timestamp:        time.Now().UTC(),
	}
}

// agentCapabilities merges the kernel capabilities with the agent's own.
// stealth_v1 is advertised by every agent that understands the apply_stealth
// task; stealth_active_v1 only while actually running in the hidden layout,
// so the Controller can show desired versus actual state.
func (r *Runner) agentCapabilities(kernelCapabilities []string) []string {
	capabilities := append(append([]string(nil), kernelCapabilities...),
		"agentlink_v1",
		model.AgentCapabilityTrafficPolicy,
		model.AgentCapabilityAuthorizationControl,
		"offline_service_control_v1",
		model.AgentCapabilityRuntimeUsers,
		"runtime_users_snell_psk_control_v1",
		model.AgentCapabilityStealth, model.RuntimeSecurityCapability, model.ProxyDSCPCapability)
	capabilities = append(capabilities, networkDiagnosticCapabilities()...)
	for _, capability := range kernelCapabilities {
		if capability == "account_activity_local_v1" {
			capabilities = append(capabilities, "account_activity_v1")
			break
		}
	}
	if r.stealthOn() {
		capabilities = append(capabilities, model.AgentCapabilityStealthActive)
	}
	sort.Strings(capabilities)
	return capabilities
}

// detectInterfaceIPv6 returns one global unicast IPv6 address assigned to any
// local interface, or "" when the host has no IPv6 inbound capability. Unlike
// detectPublicIPs this never touches the network, so it also covers hosts
// whose IPv6 works inbound-only (egress probes would never detect it).
func detectInterfaceIPv6() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var candidates []netip.Addr
	for _, addr := range addrs {
		var ip netip.Addr
		switch value := addr.(type) {
		case *net.IPNet:
			ip, _ = netip.ParseAddr(value.IP.String())
		case *net.IPAddr:
			ip, _ = netip.ParseAddr(value.IP.String())
		}
		if !ip.IsValid() || !ip.Is6() || ip.Is4In6() || !ip.IsGlobalUnicast() ||
			ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		candidates = append(candidates, ip)
	}
	found, ok := selectGlobalIPv6(candidates)
	if !ok {
		return ""
	}
	return found.String()
}

// selectGlobalIPv6 picks the smallest global unicast IPv6 address so the
// reported value is deterministic regardless of interface enumeration order.
func selectGlobalIPv6(candidates []netip.Addr) (netip.Addr, bool) {
	var found netip.Addr
	for _, ip := range candidates {
		if !found.IsValid() || ip.Compare(found) < 0 {
			found = ip
		}
	}
	return found, found.IsValid()
}

func detectPublicIPs(timeout time.Duration) (string, string) {
	if os.Getenv("OBOARD_DISABLE_PUBLIC_IP_DETECT") == "1" {
		return "", ""
	}
	if timeout <= 0 || timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	return detectPublicIPsWithProbe(timeout, probePublicIPFamily)
}

var egressRegionSources = []string{
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://api.ip.sb/geoip",
}

func detectEgressRegionCode(timeout time.Duration) string {
	if os.Getenv("OBOARD_DISABLE_PUBLIC_IP_DETECT") == "1" {
		return ""
	}
	if timeout <= 0 || timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	transport := lowOverheadTransport()
	transport.Proxy = nil
	transport.MaxIdleConns = 1
	transport.MaxConnsPerHost = 1
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, source := range egressRegionSources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			continue
		}
		req.Header.Set("user-agent", "OBoard-Agent/"+version.Version)
		res, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ""
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 16<<10))
		_ = res.Body.Close()
		if readErr != nil || res.StatusCode < 200 || res.StatusCode >= 300 {
			continue
		}
		if code := parseEgressRegionCode(body); code != "" {
			return code
		}
	}
	return ""
}

func parseEgressRegionCode(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "loc") {
			return normalizeEgressRegionCode(value)
		}
	}
	var payload struct {
		CountryCode string `json:"country_code"`
	}
	if json.Unmarshal(body, &payload) == nil {
		return normalizeEgressRegionCode(payload.CountryCode)
	}
	return ""
}

func normalizeEgressRegionCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return code
}

var publicIPv4Sources = []string{
	"https://api-ipv4.ip.sb/ip",
	"https://v4.ident.me",
	"https://api.ip.sb/ip",
	"https://icanhazip.com",
}

var publicIPv6Sources = []string{
	"https://api-ipv6.ip.sb/ip",
	"https://v6.ident.me",
	"https://api.ip.sb/ip",
	"https://icanhazip.com",
}

type publicIPProbe func(context.Context, string, []string) string

func detectPublicIPsWithProbe(timeout time.Duration, probe publicIPProbe) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type result struct {
		family string
		value  string
	}
	results := make(chan result, 2)
	for _, family := range []struct {
		name    string
		sources []string
	}{{"ipv4", publicIPv4Sources}, {"ipv6", publicIPv6Sources}} {
		family := family
		go func() {
			results <- result{family: family.name, value: probe(ctx, family.name, family.sources)}
		}()
	}
	var ipv4, ipv6 string
	for completed := 0; completed < 2; completed++ {
		select {
		case result := <-results:
			if result.family == "ipv4" {
				ipv4 = result.value
			} else {
				ipv6 = result.value
			}
		case <-ctx.Done():
			return ipv4, ipv6
		}
	}
	return ipv4, ipv6
}

func probePublicIPFamily(ctx context.Context, family string, sources []string) string {
	network := "tcp4"
	if family == "ipv6" {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := lowOverheadTransport()
	transport.Proxy = nil
	transport.MaxIdleConns = 1
	transport.MaxConnsPerHost = 1
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, source := range sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			continue
		}
		req.Header.Set("user-agent", "OBoard-Agent/"+version.Version)
		res, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ""
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 128))
		_ = res.Body.Close()
		if readErr != nil || res.StatusCode < 200 || res.StatusCode >= 300 {
			continue
		}
		if value := parsePublicIP(string(body), family); value != "" {
			return value
		}
	}
	return ""
}

func parsePublicIP(value, family string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return ""
	}
	addr = addr.Unmap()
	if family == "ipv4" && !addr.Is4() {
		return ""
	}
	if family == "ipv6" && !addr.Is6() {
		return ""
	}
	return addr.String()
}

func singBoxVersion(binary string, timeout time.Duration) string {
	version, _ := singBoxIdentity(binary, timeout)
	return version
}

func singBoxIdentity(binary string, timeout time.Duration) (string, []string) {
	if binary == "" {
		binary = detectCoreBinary()
	}
	out, err := commandOutput(timeout, binary, "-version")
	if err != nil && executableBase(binary) == "oboard-sb" {
		out, err = commandOutput(timeout, "sing-box", "version")
	}
	if err != nil {
		return "not-installed", nil
	}
	return formatCoreVersion(out), parseKernelCapabilities(out)
}

func parseKernelCapabilities(out string) []string {
	out = strings.TrimSpace(out)
	if !strings.HasPrefix(out, "{") {
		return nil
	}
	var payload struct {
		Capabilities []string `json:"capabilities"`
	}
	if json.Unmarshal([]byte(out), &payload) != nil {
		return nil
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(payload.Capabilities))
	for _, capability := range payload.Capabilities {
		capability = strings.TrimSpace(capability)
		if capability == "" || len(capability) > 64 || seen[capability] || len(result) >= 64 {
			continue
		}
		seen[capability] = true
		result = append(result, capability)
	}
	sort.Strings(result)
	return result
}

func formatCoreVersion(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return "unknown"
	}
	if strings.HasPrefix(out, "{") {
		var payload struct {
			Name           string `json:"name"`
			Version        string `json:"version"`
			Build          string `json:"build"`
			SingBoxVersion string `json:"sing_box_version"`
		}
		if err := json.Unmarshal([]byte(out), &payload); err == nil {
			parts := []string{}
			name := strings.TrimSpace(payload.Name)
			if name == "" {
				name = "oboard-sb"
			}
			if payload.Version != "" {
				parts = append(parts, name+" "+payload.Version)
			} else {
				parts = append(parts, name)
			}
			if payload.Build != "" {
				parts = append(parts, "build "+payload.Build)
			}
			if payload.SingBoxVersion != "" && payload.SingBoxVersion != "unknown" {
				parts = append(parts, "sing-box "+payload.SingBoxVersion)
			}
			return strings.Join(parts, " / ")
		}
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0])
}

func detectCoreBinary() string {
	return "oboard-sb"
}

func kernel() string {
	if runtime.GOOS == "windows" {
		return platformKernelVersion()
	}
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	out, err := commandOutput(3*time.Second, "uname", "-r")
	if err != nil || strings.TrimSpace(out) == "" {
		return runtime.GOOS
	}
	return strings.TrimSpace(out)
}

func runCommand(timeout time.Duration, name string, args ...string) error {
	out, err := commandOutput(timeout, name, args...)
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}

func commandOutput(timeout time.Duration, name string, args ...string) (string, error) {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- unexported callers supply fixed system tools or validated absolute binaries; arguments are never passed through a shell.
	cmd := exec.CommandContext(ctx, name, args...)
	var out limitBuffer
	out.limit = commandOutputLimit
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.String(), fmt.Errorf("command timed out after %s", timeout)
	}
	return out.String(), err
}

type limitBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitBuffer) String() string { return b.buf.String() }

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) <= remaining {
			_, _ = b.buf.Write(p)
		} else {
			_, _ = b.buf.Write(p[:remaining])
		}
	}
	return len(p), nil
}

func jsonResult(message string) string {
	b, _ := json.Marshal(map[string]string{"message": message})
	return string(b)
}

func jsonMap(v map[string]any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
