package agentsecurity

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestPluginLocalPolicyDefaults(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{{model.RemoteAccessModeStandard, true}, {model.RemoteAccessModeHardened, false}} {
		t.Run(tc.mode, func(t *testing.T) {
			store := NewStore(filepath.Join(t.TempDir(), "local-security.json"), nil)
			policy, err := store.Load()
			if err != nil || !policy.Allows("plugins") {
				t.Fatalf("missing policy file must allow plugins: %+v %v", policy, err)
			}
			if err := store.SetMode(tc.mode); err != nil {
				t.Fatal(err)
			}
			if policy, err = store.Load(); err != nil {
				t.Fatal(err)
			}
			if policy.Allows("plugins") != tc.want || policy.ReportedAllow().PluginsEnabled != tc.want {
				t.Fatalf("default plugin gate in %s = %v, want %v", tc.mode, policy.Allows("plugins"), tc.want)
			}
		})
	}
}

func TestPluginLocalPolicyExplicitAllowAndDeny(t *testing.T) {
	for _, mode := range []string{model.RemoteAccessModeStandard, model.RemoteAccessModeHardened} {
		t.Run(mode, func(t *testing.T) {
			store := NewStore(filepath.Join(t.TempDir(), "local-security.json"), nil)
			if err := store.SetMode(mode); err != nil {
				t.Fatal(err)
			}
			for _, allow := range []bool{false, true, false} {
				if err := store.SetAllow("plugins", allow); err != nil {
					t.Fatal(err)
				}
				policy, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				for _, feature := range []string{"plugins", "plugins_enabled"} {
					if policy.Allows(feature) != allow {
						t.Fatalf("feature=%s grant=%v policy=%+v", feature, allow, policy)
					}
				}
				if policy.ReportedAllow().PluginsEnabled != allow {
					t.Fatalf("reported plugin gate = %v, want %v", policy.ReportedAllow().PluginsEnabled, allow)
				}
				raw, err := json.Marshal(policy)
				if err != nil || !strings.Contains(string(raw), `"plugins_enabled":`) || strings.Contains(string(raw), "scripts_enabled") {
					t.Fatalf("policy JSON: %s, %v", raw, err)
				}
				for _, old := range []string{"scripts", "scripts_enabled"} {
					if policy.Allows(old) || store.SetAllow(old, true) == nil {
						t.Fatalf("retired gate %s must not be accepted", old)
					}
				}
			}
		})
	}
}

func TestPluginLocalPolicyDoesNotImportRetiredGrant(t *testing.T) {
	var policy Policy
	if err := json.Unmarshal([]byte(`{"version":1,"mode":"hardened","allow":{"scripts_enabled":true}}`), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Allows("plugins") {
		t.Fatal("retired script grant must not grant plugin access")
	}
}

func TestLANLocalGateIsClosedByDefaultAndNeedsPlugins(t *testing.T) {
	for _, mode := range []string{model.RemoteAccessModeStandard, model.RemoteAccessModeHardened} {
		t.Run(mode, func(t *testing.T) {
			store := NewStore(filepath.Join(t.TempDir(), "local-security.json"), nil)
			if err := store.SetMode(mode); err != nil {
				t.Fatal(err)
			}
			policy, _ := store.Load()
			if policy.Allows("lan") || policy.ReportedAllow().LANRequests {
				t.Fatalf("lan gate must default closed in %s", mode)
			}
			if err := store.SetAllow("lan", true); err != nil {
				t.Fatal(err)
			}
			policy, _ = store.Load()
			if mode == model.RemoteAccessModeHardened && policy.Allows("lan") {
				t.Fatal("lan gate must also require the plugins gate")
			}
			if err := store.SetAllow("plugins", true); err != nil {
				t.Fatal(err)
			}
			policy, _ = store.Load()
			if !policy.Allows("lan") || !policy.ReportedAllow().LANRequests {
				t.Fatalf("explicit allow must open the lan gate in %s", mode)
			}
			if err := store.SetAllow("plugins", false); err != nil {
				t.Fatal(err)
			}
			policy, _ = store.Load()
			if policy.Allows("lan") || policy.ReportedAllow().LANRequests {
				t.Fatal("denying plugins must close the lan gate")
			}
		})
	}
}
