package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/OboardProject/oboard-agent/internal/redact"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/OboardProject/oboard-agent/internal/agent"
	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/stealth"
	"github.com/OboardProject/oboard-agent/internal/version"
)

func main() {
	log.SetOutput(redact.Writer{Output: log.Writer()})
	args := os.Args[1:]
	if len(args) >= 1 && strings.EqualFold(args[0], "maintenance") {
		// Lightweight offline maintenance: no controller connection, no state sync.
		configPath := defaultConfig()
		keyPath := ""
		for i, a := range args {
			if a == "-config" && i+1 < len(args) {
				configPath = args[i+1]
			}
			if a == "-key" && i+1 < len(args) {
				keyPath = args[i+1]
			}
			if strings.HasPrefix(a, "-config=") {
				configPath = strings.TrimPrefix(a, "-config=")
			}
			if strings.HasPrefix(a, "--config=") {
				configPath = strings.TrimPrefix(a, "--config=")
			}
			if strings.HasPrefix(a, "-key=") {
				keyPath = strings.TrimPrefix(a, "-key=")
			}
			if strings.HasPrefix(a, "--key=") {
				keyPath = strings.TrimPrefix(a, "--key=")
			}
		}
		if len(args) >= 2 && args[1] == "storage" {
			var cfg agent.Config
			var err error
			if keyPath != "" {
				var key []byte
				if key, err = agent.LoadStealthKeyFile(keyPath); err == nil {
					cfg, err = agent.LoadConfigWithKey(configPath, key)
				}
			} else {
				cfg, err = agent.LoadConfig(configPath)
			}
			if err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "load config %s: %v\n", configPath, err)
				os.Exit(1)
			}
			// Normalize to apply profile defaults
			// Use a minimal runner just for storage maintenance.
			runner := agent.New(cfg)
			states := runner.MaintainStorage()
			for _, s := range states {
				fmt.Fprintf(os.Stdout, "%s: %s max=%d backups=%d rotated=%v err=%s\n", s.Service, s.Path, s.MaxBytes, s.Backups, s.Rotated, s.Error)
			}
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "usage: %s maintenance storage [-config path]\n", os.Args[0])
		os.Exit(2)
	}
	if len(args) >= 1 && args[0] == "-stealth-bootstrap" {
		os.Exit(runStealthBootstrap(args[1:]))
	}
	if filepath.Base(os.Args[0]) == "obag" || isManagementCommand(args) {
		os.Exit(agent.RunManagementConsole(defaultConfig(), args, os.Stdin, os.Stdout, os.Stderr))
	}
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", defaultConfig(), "agent config path")
	keyPath := flag.String("key", "", "stealth key file; decrypts the encrypted agent config and state")
	controllerAddr := flag.String("controller-addr", "", "AgentLink listener host:port")
	controllerPin := flag.String("controller-pin", "", "AgentLink certificate SHA-256 pin")
	controllerURL := flag.String("controller", "", "controller URL")
	enrollOnly := flag.Bool("enroll-only", false, "enroll, save config, and exit")
	stateDir := flag.String("state-dir", agent.DefaultStateDir(), "agent state directory")
	coreBinary := flag.String("core-binary", "", "proxy core binary; defaults to the oboard-sb binary installed beside the Agent")
	coreService := flag.String("core-service", "", "system service to restart; defaults to oboard-sb")
	resourceProfile := flag.String("resource-profile", "", "resource profile: auto, small, or large; default auto-detects memory and containers")
	commandTimeout := flag.Int("command-timeout", 20, "external command timeout in seconds")
	reloadCommand := flag.String("reload-command", "auto", "core hot reload preset: auto, none, systemd-reload, or openrc-reload")
	restartCommand := flag.String("restart-command", "auto", "core restart preset: auto, none, systemd-restart, or openrc-restart")
	timeSyncCommand := flag.String("time-sync-command", "auto", "time sync preset: auto, none, chrony, or systemd-timesyncd")
	timeCorrectionMode := flag.String("time-correction-mode", "off", "time correction mode: off, auto, or ntp")
	updateSource := flag.String("update-source", "", "agent update source: panel or github")
	allowPanelUpdate := flag.Bool("allow-panel-update", false, "allow future Agent updates from the controller panel")
	updateRepo := flag.String("update-repo", "", "GitHub repository used for release updates, for example obrdx/oboard-agent")
	stagedCore := flag.String("staged-core", "", "signed staged kernel file for local update preflight")
	preflightCoreUpdate := flag.Bool("preflight-core-update", false, "verify a staged core against the local security profile and deployed configuration")
	recordReleaseProof := flag.Bool("record-release-proof", false, "retain signed release evidence in managed local state")
	verifyRelease := flag.Bool("verify-release", false, "verify a downloaded Agent release manifest and files")
	verifyManifest := flag.String("verify-manifest", "", "release manifest path")
	verifySignature := flag.String("verify-signature", "", "release manifest signature path")
	verifyBaseDir := flag.String("verify-base-dir", "", "directory containing release files")
	verifyOS := flag.String("verify-os", "", "release OS")
	verifyArch := flag.String("verify-arch", "", "release architecture")
	verifyCoreRuntime := flag.Bool("verify-core-runtime", false, "verify that the running kernel serves the deployed configuration and the installed build, then exit")
	install := flag.Bool("install", false, "print a systemd unit template")
	logFile := flag.String("log-file", "", "append Agent output to this file; used where no service manager captures stdout")
	flag.Parse()
	enrollToken := consumeEnrollToken()
	provided := providedFlags()
	if *showVersion {
		fmt.Println("OBoard Agent", version.String())
		return
	}
	if err := redirectProcessOutput(*logFile); err != nil {
		log.Fatal(err)
	}
	if *install {
		printSystemd(*configPath)
		return
	}
	if *verifyRelease {
		if err := agent.VerifyReleaseFiles(*verifyManifest, *verifySignature, *verifyBaseDir, *verifyOS, *verifyArch, flag.Args()); err != nil {
			log.Fatal(err)
		}
		fmt.Println("release verification ok")
		return
	}
	var stealthKey []byte
	if strings.TrimSpace(*keyPath) != "" {
		loaded, keyErr := agent.LoadStealthKeyFile(*keyPath)
		if keyErr != nil {
			log.Fatalf("load stealth key: %v", keyErr)
		}
		stealthKey = loaded
	}
	var cfg agent.Config
	if len(stealthKey) > 0 {
		loaded, cfgErr := agent.LoadConfigWithKey(*configPath, stealthKey)
		if cfgErr != nil {
			log.Fatalf("load encrypted config: %v", cfgErr)
		}
		cfg = loaded
	} else {
		loaded, cfgErr := agent.LoadConfig(*configPath)
		if cfgErr != nil && (*recordReleaseProof || *preflightCoreUpdate) {
			log.Fatal("local configuration unavailable")
		}
		cfg = loaded
	}
	cfg.ConfigPath = *configPath
	if *controllerAddr != "" {
		cfg.ControllerAddr = *controllerAddr
	}
	if *controllerPin != "" {
		cfg.ControllerCertSHA256 = *controllerPin
	}
	if *controllerURL != "" {
		cfg.ControllerURL = *controllerURL
	}
	if provided["state-dir"] && *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	if *coreBinary != "" {
		cfg.CoreBinary = *coreBinary
	}
	if *coreService != "" {
		cfg.CoreService = *coreService
	}
	if provided["resource-profile"] {
		cfg.ResourceProfile = *resourceProfile
	}
	if provided["command-timeout"] {
		cfg.CommandTimeoutSeconds = *commandTimeout
	}
	if provided["reload-command"] {
		cfg.ReloadCommand = *reloadCommand
	}
	if provided["restart-command"] {
		cfg.RestartCommand = *restartCommand
	}
	if provided["time-sync-command"] {
		cfg.TimeSyncCommand = *timeSyncCommand
	}
	if provided["time-correction-mode"] {
		cfg.TimeCorrectionMode = model.TimeCorrectionMode(*timeCorrectionMode)
	}
	if provided["update-source"] {
		cfg.UpdateSource = *updateSource
	}
	if provided["allow-panel-update"] {
		cfg.AllowPanelUpdate = *allowPanelUpdate
	}
	if provided["update-repo"] {
		cfg.UpdateRepo = *updateRepo
	}
	executablePath, _ := os.Executable()
	cfg = fillLocalCoreDefaults(cfg, executablePath)
	runner := agent.New(cfg)
	if *preflightCoreUpdate {
		summary, err := runner.PreflightCoreUpdate(*stagedCore, *verifyManifest, *verifySignature)
		fmt.Println(summary)
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runner.Config().Validate(); err != nil {
		log.Fatal(err)
	}
	if *recordReleaseProof {
		if err := runner.RecordReleaseProof(*verifyManifest, *verifySignature); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *verifyCoreRuntime {
		summary, err := runner.VerifyCoreRuntime(context.Background())
		fmt.Println(summary)
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, serviceDone := runUnderServiceManager(ctx, runner.Config().AgentService)
	defer serviceDone()
	if enrollToken != "" {
		if runner.Config().ControllerAddr == "" {
			log.Fatal("-controller-addr and -controller-pin are required when OBOARD_ENROLL_TOKEN is set")
		}
		if err := runner.Enroll(ctx, enrollToken); err != nil {
			log.Fatal(err)
		}
		logging.Infof("agent enrolled and config saved to %s", *configPath)
		if *enrollOnly {
			return
		}
	}
	if err := runner.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func fillLocalCoreDefaults(cfg agent.Config, executablePath string) agent.Config {
	if strings.TrimSpace(cfg.CoreBinary) == "" && strings.TrimSpace(executablePath) != "" {
		if cfg.Stealth != nil && cfg.Stealth.Identity.CoreName != "" {
			cfg.CoreBinary = filepath.Join(filepath.Dir(executablePath), cfg.Stealth.Identity.CoreName)
		} else {
			cfg.CoreBinary = agent.InstalledCoreBinary(executablePath)
		}
	}
	if strings.TrimSpace(cfg.CoreService) == "" {
		if cfg.Stealth != nil && cfg.Stealth.Identity.CoreName != "" {
			cfg.CoreService = cfg.Stealth.Identity.CoreName
		} else {
			cfg.CoreService = "oboard-sb"
		}
	}
	return cfg
}

// isManagementCommand reports whether the first argument selects the local
// management console so the binary works even without the obag symlink.
func isManagementCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "status", "start", "stop", "restart", "logs", "log", "check", "connection", "controller", "help", "remote-access":
		return true
	default:
		return false
	}
}

func defaultConfig() string {
	if runtime.GOOS == "windows" {
		return agent.DefaultConfigPath()
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return "/etc/oboard-agent/config.json"
	}
	return filepath.Join(home, ".oboard-agent", "config.json")
}

func providedFlags() map[string]bool {
	provided := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	return provided
}

func consumeEnrollToken() string {
	value := os.Getenv("OBOARD_ENROLL_TOKEN")
	_ = os.Unsetenv("OBOARD_ENROLL_TOKEN")
	return value
}

func printSystemd(configPath string) {
	fmt.Printf(`[Unit]
Description=OBoard Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Intentionally privileged host-management service; see README privilege boundary.
User=root
ExecStart=/usr/local/bin/oboard-agent -config %s
StandardOutput=append:/var/log/oboard-agent.log
StandardError=append:/var/log/oboard-agent.log
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=false
ProtectHome=true
ReadWritePaths=/usr/local/bin /etc/oboard-agent /var/lib/oboard-agent /var/log /run
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
`, configPath)
}

// runStealthBootstrap implements the -stealth-bootstrap installer verb: it
// converts the freshly downloaded standard install into the hidden layout
// and prints shell-sourceable variables describing it. The installer script
// consumes the printed lines to enroll and start the service.
func runStealthBootstrap(args []string) int {
	fs := flag.NewFlagSet("stealth-bootstrap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	installDir := fs.String("install-dir", "/usr/local/bin", "directory holding the downloaded oboard-agent, oboard-sb, and oboard-realm binaries")
	manager := fs.String("manager", "", "service manager: systemd or openrc")
	cleanupExisting := fs.Bool("cleanup-existing", false, "remove previous managed installations after replacement is running")
	listExisting := fs.Bool("list-existing", false, "list verified previous managed services before starting the replacement")
	reuseExisting := fs.Bool("reuse-existing", false, "verify and reuse the Controller-issued security-process layout")
	keepConfig := fs.String("keep-config", "", "configuration of the replacement installation to preserve")
	controllerURL := fs.String("controller-url", "", "Controller base URL recorded in the encrypted config")
	updateSource := fs.String("update-source", "panel", "agent update source: panel or github")
	allowPanelUpdate := fs.Bool("allow-panel-update", true, "allow future Agent updates from the controller panel")
	updateRepo := fs.String("update-repo", "obrdx/oboard-agent", "GitHub repository used for release updates")
	configParent := fs.String("config-parent", "/etc", "parent directory for the generated config directory")
	stateParent := fs.String("state-parent", "/var/lib", "parent directory for the generated state directory")
	controllerAddr := fs.String("controller-addr", "", "dedicated stealth transport listener (host:port)")
	controllerPin := fs.String("controller-pin", "", "SHA-256 pin of the stealth transport certificate")
	identityJSON := fs.String("identity-json", "", "Controller-issued security-process identity")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cleanupExisting {
		if err := agent.CleanupPreviousAgentInstalls(*manager, *keepConfig); err != nil {
			fmt.Fprintf(os.Stderr, "previous Agent cleanup failed: %v\n", err)
			return 1
		}
		return 0
	}
	if *listExisting {
		services, err := agent.ListPreviousAgentServices(*manager, *keepConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "previous Agent service discovery failed: %v\n", err)
			return 1
		}
		for _, service := range services {
			fmt.Println(service)
		}
		return 0
	}
	if *identityJSON == "" {
		fmt.Fprintln(os.Stderr, "Controller-issued security-process identity is required")
		return 2
	}
	identity := new(stealth.Identity)
	if err := json.Unmarshal([]byte(*identityJSON), identity); err != nil {
		fmt.Fprintf(os.Stderr, "invalid stealth identity: %v\n", err)
		return 2
	}
	if *reuseExisting {
		layout, err := agent.InspectExistingStealthInstall(agent.StealthBootstrapOptions{InstallDir: *installDir, Manager: *manager, ConfigParent: *configParent, StateParent: *stateParent}, *identity)
		if err != nil {
			fmt.Fprintf(os.Stderr, "existing stealth layout verification failed: %v\n", err)
			return 1
		}
		printStealthBootstrapLayout(layout)
		return 0
	}
	layout, err := agent.RunStealthBootstrap(agent.StealthBootstrapOptions{
		InstallDir:           *installDir,
		Manager:              *manager,
		ControllerURL:        *controllerURL,
		UpdateSource:         *updateSource,
		AllowPanelUpdate:     *allowPanelUpdate,
		UpdateRepo:           *updateRepo,
		ConfigParent:         *configParent,
		StateParent:          *stateParent,
		ControllerAddr:       *controllerAddr,
		ControllerCertSHA256: *controllerPin,
		Identity:             identity,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "stealth bootstrap failed: %v\n", err)
		return 1
	}
	printStealthBootstrapLayout(layout)
	return 0
}

func printStealthBootstrapLayout(layout stealth.Layout) {
	// Shell-sourceable output for the installer script. Paths are validated
	// generated names without quotes or expansions.
	fmt.Printf("STEALTH_AGENT_BIN=%s\n", layout.AgentBinary)
	fmt.Printf("STEALTH_CORE_BIN=%s\n", layout.CoreBinary)
	fmt.Printf("STEALTH_CONFIG_PATH=%s\n", layout.ConfigPath)
	fmt.Printf("STEALTH_KEY_PATH=%s\n", layout.KeyPath)
	fmt.Printf("STEALTH_AGENT_SERVICE=%s\n", layout.AgentService)
	fmt.Printf("STEALTH_CORE_SERVICE=%s\n", layout.CoreService)
}
