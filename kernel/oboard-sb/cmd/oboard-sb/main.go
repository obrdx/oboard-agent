package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/vpngatepool"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/proxydscp"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/redact"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeguard"
	singService "github.com/sagernet/sing/service"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/stealth"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version"
	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
)

var kernelCapabilities = []string{proxydscp.Capability, "runtime_security_v1", "authorization_lease_v1", "offline_service_v1", "authorization_control_v1", "runtime_users_v1", "runtime_users:vless", "runtime_users:hysteria2", "runtime_users:shadowsocks-multi", "runtime_users:snell-psk", "snell_multi_psk_v4_v1", "snell_multi_psk_v6_v1", "runtime_users_snell_psk_v1", "outbound_egress_probe_v1", "outbound_relay_v1", "route_relay_v1", "runtime_clock_v1", "connection_presence_v1", "family_selector_v1", "traffic_ledger", "runtime_config_digest_v1", "runtime_build_identity_v1", "dns_doq_v1", "dns_group_v1", "account_activity_local_v1", "openvpn_outbound_v1", "vpngate_pool_v1", "http_outbound_v1"}

// runtimeConfigState is the payload-free identity of the configuration this
// process actually loaded. Agent compares it with the desired configuration so
// a deployment cannot report success while the kernel still runs older state.
//
// Started is set only once the box has started and runtime users have been
// restored. Until then the configuration is loaded but not serving, so the
// status endpoint must not let Agent treat the process as converged.
type runtimeConfigState struct {
	OperationalDigest string
	StartedAt         time.Time
	Generation        uint64
	Started           *atomic.Bool
}

func main() {
	preparePrivateRuntimeFiles()
	log.SetOutput(redact.Writer{Output: log.Writer()})
	config := flag.String("config", "config.json", "sing-box config path")
	keyPath := flag.String("key", "", "optional stealth key file; decrypts the configuration and sibling state files")
	check := flag.Bool("check", false, "validate config and exit")
	operationalDigest := flag.Bool("operational-digest", false, "print the operational configuration digest for the config file and exit")
	api := flag.String("api", "", "optional local health API listen address; supports unix:/path.sock")
	resourceProfile := flag.String("resource-profile", "auto", "resource profile: auto, small, or large")
	gomaxprocs := flag.Int("gomaxprocs", 0, "runtime GOMAXPROCS override; 0 uses the resource profile")
	memoryLimit := flag.Int64("memory-limit-bytes", 0, "Go runtime memory target override; 0 uses the resource profile")
	hy2UpMbps := flag.Int("hy2-up-mbps", 0, "override Hysteria2 inbound advertised upload bandwidth in Mbps")
	hy2DownMbps := flag.Int("hy2-down-mbps", 0, "override Hysteria2 inbound advertised download bandwidth in Mbps")
	hy2IgnoreClientBandwidth := flag.Bool("hy2-ignore-client-bandwidth", false, "force Hysteria2 server bandwidth settings instead of client-advertised bandwidth")
	hy2BrutalDebug := flag.Bool("hy2-brutal-debug", false, "enable Hysteria2 brutal congestion debug logging")
	securityCheck := flag.Bool("runtime-security-check", false, "check the native enhanced profile in this isolated process and exit")
	showVersion := flag.Bool("version", false, "print version and supported protocols")
	logFile := flag.String("log-file", "", "append process output to this file; used where no service manager captures stdout")
	flag.Parse()
	runtimeguard.SetLocalAPI(*api)

	if *securityCheck {
		if err := runtimeguard.Apply("enhanced"); err != nil {
			log.Fatal("runtime security profile unsupported")
		}
		_ = json.NewEncoder(os.Stdout).Encode(runtimeguard.Snapshot())
		return
	}
	if *showVersion {
		printVersion()
		return
	}
	if err := redirectProcessOutput(*logFile); err != nil {
		log.Fatal(err)
	}
	stealthKey, keyErr := loadStealthKey(*keyPath)
	if keyErr != nil {
		log.Fatal(keyErr)
	}
	if *operationalDigest {
		digest, err := minibox.OperationalConfigDigestFile(*config, stealthKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(digest)
		return
	}

	runtimeTuning, err := minibox.ApplyRuntimeDefaults(*resourceProfile, *gomaxprocs, *memoryLimit)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("kernel resource profile=%s memory_class=%s virtualization=%s container=%t effective_memory=%d gomaxprocs=%d gogc=%d gomemlimit=%d", runtimeTuning.Profile, runtimeTuning.MemoryClass, runtimeTuning.Virtualization, runtimeTuning.Container, runtimeTuning.EffectiveMemoryBytes, runtime.GOMAXPROCS(0), runtimeTuning.GCPercent, runtimeTuning.MemoryLimitBytes)
	tuning := minibox.HY2Tuning{
		Enabled:               *hy2UpMbps > 0 || *hy2DownMbps > 0 || *hy2IgnoreClientBandwidth || *hy2BrutalDebug,
		UpMbps:                *hy2UpMbps,
		DownMbps:              *hy2DownMbps,
		IgnoreClientBandwidth: *hy2IgnoreClientBandwidth,
		BrutalDebug:           *hy2BrutalDebug,
	}
	opts, runtimeMetadata, err := minibox.LoadConfig(*config, stealthKey, tuning)
	if err != nil {
		log.Fatal(err)
	}
	if *check {
		checkCtx := minibox.Context(context.Background(), minibox.NewRuntimeClock())
		instance, err := box.New(box.Options{Context: checkCtx, Options: opts})
		if err != nil {
			log.Fatal(err)
		}
		if err := instance.Close(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("configuration is valid for oboard-sb")
		return
	}

	stopLog, logErr := startRedactedRuntimeOutput()
	if logErr != nil {
		log.Fatal("cannot initialize protected runtime logging")
	}
	defer stopLog()
	if err := applyRuntimeSecurityPolicy(*config, stealthKey); err != nil {
		log.Fatal("runtime security policy could not be applied")
	}
	loadedOperationalDigest, err := minibox.OperationalConfigDigestFile(*config, stealthKey)
	if err != nil {
		log.Fatal(err)
	}
	runtimeConfig := runtimeConfigState{OperationalDigest: loadedOperationalDigest, StartedAt: time.Now().UTC(), Generation: 1, Started: new(atomic.Bool)}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, serviceDone := runUnderServiceManager(ctx, "oboard-sb")
	defer serviceDone()
	memoryReclaimer := minibox.StartMemoryReclaimer(ctx, runtimeTuning)
	runtimeClock := minibox.NewRuntimeClock()
	boxCtx := minibox.Context(context.Background(), runtimeClock)
	dscp, err := proxydscp.New(kernelStatePath(*config, stealthKey, "kernel-proxy-dscp.json"), stealthKey)
	if err != nil {
		log.Print("proxy DSCP policy unavailable; continuing without marking")
	}
	singService.MustRegister[*proxydscp.Manager](boxCtx, dscp)
	b, err := box.New(box.Options{Context: boxCtx, Options: opts})
	if err != nil {
		log.Fatal(err)
	}
	tracker := minibox.AttachRuntimeTrackers(boxCtx, runtimeMetadata)
	if err := tracker.InitializeAuthorization(kernelStatePath(*config, stealthKey, "kernel-authorization.json"), stealthKey, runtimeMetadata.Authorization); err != nil {
		log.Fatal(err)
	}
	agentLease, err := authorization.NewStore(kernelStatePath(*config, stealthKey, "authorization.json"), stealthKey).Snapshot()
	if err != nil {
		log.Fatal(err)
	}
	if err := tracker.UpdateAuthorization(agentLease); err != nil {
		log.Fatal(err)
	}
	var declaredUsers []string
	if runtimeMetadata.RuntimeUsers != nil {
		declaredUsers = runtimeMetadata.RuntimeUsers.Inbounds
	}
	runtimeUsers := minibox.NewRuntimeUsers(kernelStatePath(*config, stealthKey, "kernel-users.json"), stealthKey, b, tracker, declaredUsers)
	go tracker.RunAuthorizationReaper(ctx)
	socketGovernor := minibox.StartAdaptiveSocketGovernor(ctx, runtimeTuning)
	tracker.SetSocketGovernor(socketGovernor)
	if *api != "" {
		go func() {
			if err := serveHealth(ctx, *api, b, tracker, runtimeUsers, runtimeClock, runtimeTuning, memoryReclaimer, socketGovernor, runtimeConfig, dscp); err != nil && ctx.Err() == nil {
				log.Println(err)
			}
		}()
	}
	if err := b.Start(); err != nil {
		log.Fatal(err)
	}
	if err := runtimeUsers.Restore(); err != nil {
		log.Fatal(err)
	}
	runtimeConfig.Started.Store(true)
	<-ctx.Done()
	if err := b.Close(); err != nil {
		log.Println(err)
	}
}

// loadStealthKey reads the optional key file. An empty path means plaintext
// mode and returns a nil key.
func loadStealthKey(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	return stealth.LoadKey(path)
}

// kernelStatePath resolves a sibling state file of the configuration. In
// stealth mode the Agent stores every state file under a key-derived physical
// name, so the kernel must derive the same name; in plaintext mode the
// logical name is the file name.
func kernelStatePath(configPath string, key []byte, logical string) string {
	if len(key) > 0 {
		return filepath.Join(filepath.Dir(configPath), stealth.PhysicalName(key, logical))
	}
	return filepath.Join(filepath.Dir(configPath), logical)
}

func printVersion() {
	payload := map[string]any{
		"name":                "oboard-sb",
		"version":             version.Version,
		"build":               version.Build,
		"commit":              version.Commit,
		"built_at":            version.Date,
		"sing_box_version":    C.Version,
		"supported_protocols": minibox.SupportedProtocols,
		"capabilities":        kernelCapabilities,
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(data))
}

func serveHealth(ctx context.Context, listen string, instance *box.Box, tracker *minibox.RateLimitTracker, runtimeUsers *minibox.RuntimeUsers, runtimeClock *minibox.RuntimeClock, tuning minibox.RuntimeTuning, memoryReclaimer *minibox.MemoryReclaimer, socketGovernor *minibox.SocketBufferGovernor, runtimeConfig runtimeConfigState, dscp ...*proxydscp.Manager) error {
	if err := validateLocalAPIListen(listen); err != nil {
		return err
	}
	mux := http.NewServeMux()
	if len(dscp) > 0 && strings.HasPrefix(listen, "unix:") {
		mux.HandleFunc("/proxy/dscp", dscp[0].Handler)
	}
	registerRuntimeStatusHandler(mux, runtimeConfig)
	registerOutboundEgressHandler(mux, instance)
	registerOutboundRelayHandlers(mux, listen, instance)
	registerRouteRelayHandlers(mux, listen, instance)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "oboard-sb", "version": version.Version, "build": version.Build, "commit": version.Commit, "built_at": version.Date, "sing_box_version": C.Version, "supported_protocols": minibox.SupportedProtocols, "capabilities": kernelCapabilities, "resource_profile": tuning.Profile, "memory_class": tuning.MemoryClass, "virtualization": tuning.Virtualization, "container": tuning.Container, "effective_memory_bytes": tuning.EffectiveMemoryBytes, "gomaxprocs": runtime.GOMAXPROCS(0), "gc_percent": tuning.GCPercent, "memory_limit_bytes": tuning.MemoryLimitBytes, "memory_reclaimer": memoryReclaimer.Snapshot(), "socket_governor": socketGovernor.Snapshot()})
	})
	mux.HandleFunc("/resources", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource_profile": tuning.Profile, "memory_class": tuning.MemoryClass, "effective_memory_bytes": tuning.EffectiveMemoryBytes, "gomaxprocs": runtime.GOMAXPROCS(0), "gc_percent": tuning.GCPercent, "memory_limit_bytes": tuning.MemoryLimitBytes, "memory_reclaimer": memoryReclaimer.Snapshot(), "socket_governor": socketGovernor.Snapshot()})
	})
	mux.HandleFunc("/traffic/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": tracker.Snapshot(), "time": runtimeClock.Now().UTC().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("/connections/drain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tracker.DrainConnectionAuditSnapshot())
	})
	mux.HandleFunc("/connections/presence/drain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tracker.DrainConnectionPresenceEvents())
	})
	mux.HandleFunc("/connections/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tracker.SetConnectionAuditEnabled(req.Enabled)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "enabled": tracker.ConnectionAuditEnabled()})
	})
	mux.HandleFunc("/traffic/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req struct {
			Policies     map[string]minibox.RuntimeUserLimit              `json:"policies"`
			Acknowledged map[string]minibox.TrafficCounterAcknowledgement `json:"acknowledged"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The Controller baseline already contains accepted reports. Advance the
		// local counter checkpoints first so a policy refresh cannot momentarily
		// double count and disconnect healthy sessions.
		tracker.AcknowledgeTraffic(req.Acknowledged)
		tracker.UpdatePolicies(req.Policies)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	registerActivityHandlers(mux, listen, tracker)
	registerClockConfigHandler(mux, listen, runtimeClock)
	registerAuthorizationHandler(mux, listen, tracker)
	registerUsersHandler(mux, listen, runtimeUsers)
	registerVPNGateHandlers(mux, listen, vpngatepool.Lookup, vpngatepool.Snapshot)

	var (
		ln         net.Listener
		err        error
		socketPath string
	)
	if strings.HasPrefix(listen, "unix:") {
		socketPath = strings.TrimPrefix(listen, "unix:")
		_ = os.Remove(socketPath)
		ln, err = net.Listen("unix", socketPath)
	} else {
		ln, err = net.Listen("tcp", listen)
	}
	if err != nil {
		return err
	}
	if socketPath != "" {
		defer os.Remove(socketPath)
		if err := restrictLocalSocket(socketPath); err != nil {
			_ = ln.Close()
			return err
		}
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	// #nosec G118 -- serverCtx is the caller's lifecycle context; the fresh timeout is only for bounded shutdown after cancellation.
	go func(serverCtx context.Context) {
		<-serverCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}(ctx)
	return srv.Serve(ln)
}

// registerRuntimeStatusHandler exposes the identity of the configuration this
// process loaded and of the executable it was started from. It returns digests
// and build identifiers only; configuration content, credentials, and file
// paths never leave the kernel.
//
// The local API serves before the box starts, because Agent pushes the clock,
// DSCP, authorization, and pool members into a starting kernel. Until start
// and runtime-user restore succeed the endpoint answers 503 with
// state=starting and no configuration identity: a loaded configuration whose
// inbounds are not listening yet, or whose start is about to fail, is not a
// converged kernel. The runtime security profile is already applied by then
// and is reported in both states.
//
// The build identity is what makes an upgrade verifiable. Replacing the binary
// on disk does not touch the running process, so Agent has to be able to ask
// which build is actually serving traffic instead of inferring it from the file
// it just installed.
func registerRuntimeStatusHandler(mux *http.ServeMux, runtimeConfig runtimeConfigState) {
	mux.HandleFunc("/runtime/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if runtimeConfig.Started != nil && !runtimeConfig.Started.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"state":            "starting",
				"runtime_security": runtimeguard.Snapshot(),
				"pid":              os.Getpid(),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"state":                     "running",
			"runtime_security":          runtimeguard.Snapshot(),
			"operational_config_sha256": runtimeConfig.OperationalDigest,
			"started_at":                runtimeConfig.StartedAt.Format(time.RFC3339Nano),
			"pid":                       os.Getpid(),
			"generation":                runtimeConfig.Generation,
			"version":                   version.Version,
			"build":                     version.Build,
			"commit":                    version.Commit,
		})
	})
}

func registerClockConfigHandler(mux *http.ServeMux, listen string, runtimeClock *minibox.RuntimeClock) {
	if !strings.HasPrefix(listen, "unix:") {
		return
	}
	mux.HandleFunc("/clock/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var config minibox.RuntimeClockConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := runtimeClock.Configure(config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "clock": runtimeClock.Snapshot()})
	})
}

func validateLocalAPIListen(listen string) error {
	if strings.HasPrefix(listen, "unix:") {
		if strings.TrimSpace(strings.TrimPrefix(listen, "unix:")) == "" {
			return fmt.Errorf("local API unix socket path is empty")
		}
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("local API TCP address must be loopback, got %q", host)
	}
	return nil
}
