package agent

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/OboardProject/oboard-agent/internal/agentsecurity"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

func (r *Runner) localSecurityStore() *agentsecurity.Store {
	return agentsecurity.NewStore(r.localSecurityPath(), r.Config().StealthKey)
}

// localSecurityPath resolves the local-security file for this installation:
// the standard name beside the config in standard mode, a key-derived name in
// stealth mode.
func (r *Runner) localSecurityPath() string {
	configPath := r.configPath()
	if !r.stealthOn() {
		return agentsecurity.PathForConfig(configPath)
	}
	return filepath.Join(filepath.Dir(configPath), stealth.PhysicalName(r.Config().StealthKey, "local-security.json"))
}

func (r *Runner) localSecurityPolicy() agentsecurity.Policy {
	policy, err := r.localSecurityStore().Load()
	if err != nil {
		return agentsecurity.Policy{Version: 1, Mode: model.RemoteAccessModeHardened}
	}
	return policy
}

func (r *Runner) remoteAccessReport() model.RemoteAccessReport {
	policy := r.localSecurityPolicy()
	return model.RemoteAccessReport{
		Capabilities: []string{
			model.RemoteAccessCapabilityTerminal,
			model.RemoteAccessCapabilityTerminalLoginEnv,
			model.RemoteAccessCapabilityExec,
			model.RemoteAccessCapabilityInteractiveMCP,
			model.RemoteAccessCapabilityLocalGate,
		},
		LocalMode:  policy.Mode,
		LocalAllow: policy.ReportedAllow(),
	}
}

func (r *Runner) localGateAllows(feature string) bool {
	return r.localSecurityPolicy().Allows(feature)
}

func localGateFeatureForExec(origin, mode string) string {
	return "mcp_enabled"
}

// applyLocalPolicy handles the signed apply_agent_local_policy task. The
// enforced gates are reported in the result and in every later hello and
// heartbeat, so Controller always acts on what the node enforces.
func (r *Runner) applyLocalPolicy(payload string) (string, string) {
	var plan model.AgentLocalPolicyPlan
	if err := json.Unmarshal([]byte(payload), &plan); err != nil {
		return "failed", jsonResult(err.Error())
	}
	result := model.AgentLocalPolicyResult{Feature: plan.Feature, Allow: plan.Allow}
	policy, changed, err := r.localSecurityStore().ApplyRemote(plan.Feature, plan.Allow)
	if err != nil {
		current := r.localSecurityPolicy()
		result.LocalMode, result.LocalAllow, result.Message = current.Mode, current.ReportedAllow(), err.Error()
		if errors.Is(err, agentsecurity.ErrHardenedLocalOnly) {
			result.Error = model.LocalPolicyErrorHardened
		}
		raw, _ := json.Marshal(result)
		return "failed", string(raw)
	}
	result.Changed, result.LocalMode, result.LocalAllow = changed, policy.Mode, policy.ReportedAllow()
	raw, _ := json.Marshal(result)
	return "succeeded", string(raw)
}
