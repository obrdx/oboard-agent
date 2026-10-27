//go:build !linux

package agent

import "github.com/OboardProject/oboard-agent/internal/model"

// networkDiagnosticCapabilities lists the plugin diagnostics this platform
// implements natively. Raw-socket ping and trace are Linux-only; other
// platforms report them as unsupported rather than falling back to programs.
func networkDiagnosticCapabilities() []string {
	return []string{
		model.AgentCapabilityGoogleRegionProbe, model.AgentCapabilityNetworkTCPMonitor, model.AgentCapabilityNetworkDiagnostics, model.AgentCapabilityNetworkTCPProbe,
		model.AgentCapabilityNetworkDNSLookup, model.AgentCapabilityNetworkHTTPProbe,
	}
}
