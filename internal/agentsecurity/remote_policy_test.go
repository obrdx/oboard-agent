package agentsecurity

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func TestApplyRemoteStandardOpensAndCloses(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "local-security.json"), nil)
	policy, changed, err := store.ApplyRemote(model.LocalPolicyFeatureLAN, true)
	if err != nil || !changed || !policy.Allows("lan") || !policy.Allows("plugins") {
		t.Fatalf("standard mode must let Controller open lan: %+v %v %v", policy, changed, err)
	}
	if _, changed, err := store.ApplyRemote(model.LocalPolicyFeatureLAN, true); err != nil || changed {
		t.Fatalf("repeating the same change must be idempotent: %v %v", changed, err)
	}
	policy, changed, err = store.ApplyRemote(model.LocalPolicyFeaturePlugins, false)
	if err != nil || !changed || policy.Allows("plugins") || policy.Allows("lan") {
		t.Fatalf("closing plugins must close lan too: %+v %v %v", policy, changed, err)
	}
	policy, _, err = store.ApplyRemote(model.LocalPolicyFeaturePlugins, true)
	if err != nil || !policy.Allows("plugins") || policy.Allows("lan") {
		t.Fatalf("reopening plugins must not reopen lan: %+v %v", policy, err)
	}
	if _, _, err := store.ApplyRemote("terminal", true); err == nil {
		t.Fatal("only plugins and lan may be set remotely")
	}
}

func TestApplyRemoteHardenedOnlyCloses(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "local-security.json"), nil)
	if err := store.SetMode(model.RemoteAccessModeHardened); err != nil {
		t.Fatal(err)
	}
	for _, feature := range []string{model.LocalPolicyFeaturePlugins, model.LocalPolicyFeatureLAN} {
		if _, _, err := store.ApplyRemote(feature, true); !errors.Is(err, ErrHardenedLocalOnly) {
			t.Fatalf("hardened mode must refuse remote open of %s: %v", feature, err)
		}
	}
	if err := store.SetAllow("plugins", true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetAllow("lan", true); err != nil {
		t.Fatal(err)
	}
	policy, changed, err := store.ApplyRemote(model.LocalPolicyFeatureLAN, false)
	if err != nil || !changed || policy.Allows("lan") || !policy.Allows("plugins") {
		t.Fatalf("hardened mode must accept a remote close: %+v %v %v", policy, changed, err)
	}
	if _, _, err := store.ApplyRemote(model.LocalPolicyFeatureLAN, true); !errors.Is(err, ErrHardenedLocalOnly) {
		t.Fatalf("a remotely closed hardened gate must stay closed: %v", err)
	}
	if policy, _ := store.Load(); policy.Mode != model.RemoteAccessModeHardened {
		t.Fatal("a remote change must never leave hardened mode")
	}
}
