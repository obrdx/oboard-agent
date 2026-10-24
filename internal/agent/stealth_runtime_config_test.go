package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

// A stealth installation keeps its agent config in an encrypted envelope, and
// LoadConfigWithKey rejects a plaintext file when a key is provided. Every
// runtime path that persists the config must therefore keep the envelope: a
// single plaintext write bricks the next start and hides the installation from
// the reinstall cleanup.

func stealthRuntimeFixture(t *testing.T, mutate func(*Config)) (*Runner, string, []byte) {
	t.Helper()
	key, err := stealth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	cfg := normalizeConfig(Config{
		ConfigPath:  configPath,
		StateDir:    filepath.Join(root, "state"),
		CoreBinary:  filepath.Join(root, "core"),
		CoreService: "core-svc",
	})
	cfg.StealthKey = key
	if mutate != nil {
		mutate(&cfg)
	}
	if err := SaveConfigWithKey(configPath, cfg, key); err != nil {
		t.Fatal(err)
	}
	runner := newTestRunner(t, cfg)
	return runner, configPath, key
}

func assertConfigStillEncrypted(t *testing.T, configPath string, key []byte) Config {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !stealth.IsEncrypted(data) {
		t.Fatalf("config at %s was downgraded to plaintext by a runtime write", configPath)
	}
	cfg, err := LoadConfigWithKey(configPath, key)
	if err != nil {
		t.Fatalf("encrypted config no longer loads: %v", err)
	}
	return cfg
}

func TestRuntimeConfigWritesKeepStealthEncryption(t *testing.T) {
	t.Run("bind_server_identity", func(t *testing.T) {
		runner, configPath, key := stealthRuntimeFixture(t, nil)
		if err := runner.bindServerIdentity(45); err != nil {
			t.Fatal(err)
		}
		if cfg := assertConfigStillEncrypted(t, configPath, key); cfg.ServerID != 45 {
			t.Fatalf("server_id = %d, want 45", cfg.ServerID)
		}
	})
	t.Run("connection_audit_policy", func(t *testing.T) {
		runner, configPath, key := stealthRuntimeFixture(t, nil)
		runner.setConnectionAuditPolicy(true)
		if cfg := assertConfigStillEncrypted(t, configPath, key); !cfg.ConnectionAuditEnabled {
			t.Fatal("connection_audit_enabled was not persisted")
		}
		runner.setConnectionAuditPolicy(false)
		if cfg := assertConfigStillEncrypted(t, configPath, key); cfg.ConnectionAuditEnabled {
			t.Fatal("connection_audit_enabled was not cleared")
		}
	})
	t.Run("log_level_expiry", func(t *testing.T) {
		expired := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		runner, configPath, key := stealthRuntimeFixture(t, nil)
		next := runner.Config()
		next.LogLevel = logging.LevelTrace.String()
		next.LogLevelExpiresAt = expired
		runner.storeConfig(next)
		if _, expiredNow := resolveLogLevel(runner.Config(), time.Now()); !expiredNow {
			t.Fatal("fixture did not produce an expired verbose level")
		}
		runner.refreshLogLevel()
		cfg := assertConfigStillEncrypted(t, configPath, key)
		if cfg.LogLevel != logging.DefaultLevel.String() || cfg.LogLevelExpiresAt != "" {
			t.Fatalf("expired level not retired: %s %s", cfg.LogLevel, cfg.LogLevelExpiresAt)
		}
	})
	t.Run("time_correction_mode", func(t *testing.T) {
		runner, configPath, key := stealthRuntimeFixture(t, nil)
		if err := runner.persistTimeCorrectionMode(model.TimeCorrectionNTP); err != nil {
			t.Fatal(err)
		}
		if cfg := assertConfigStillEncrypted(t, configPath, key); cfg.TimeCorrectionMode != model.TimeCorrectionNTP {
			t.Fatalf("time_correction_mode = %s", cfg.TimeCorrectionMode)
		}
	})
}

// Non-stealth runners keep plaintext persistence; the key-aware writer must
// not change that behavior.
func TestRuntimeConfigWritesStayPlaintextWithoutKey(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	cfg := normalizeConfig(Config{ConfigPath: configPath, StateDir: filepath.Join(root, "state")})
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	runner := newTestRunner(t, cfg)
	if err := runner.bindServerIdentity(7); err != nil {
		t.Fatal(err)
	}
	saved, err := LoadConfig(configPath)
	if err != nil || saved.ServerID != 7 {
		t.Fatalf("plaintext persistence changed: err=%v server_id=%d", err, saved.ServerID)
	}
}
