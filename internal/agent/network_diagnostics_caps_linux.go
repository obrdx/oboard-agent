//go:build linux

package agent

import "github.com/OboardProject/oboard-agent/internal/model"

// networkDiagnosticCapabilities lists the diagnostics this platform
// implements natively.
func networkDiagnosticCapabilities() []string {
	return []string{
		"external_outbound_check_v1",
		model.AgentCapabilityRouteMonitor, model.AgentCapabilityGoogleRegionProbe, model.AgentCapabilityNetworkTCPMonitor,
		model.AgentCapabilityNetworkDiagnostics, model.AgentCapabilityNetworkPing,
		model.AgentCapabilityNetworkTraceICMP, model.AgentCapabilityNetworkTraceUDP, model.AgentCapabilityNetworkTraceTCP,
		model.AgentCapabilityNetworkTCPProbe, model.AgentCapabilityNetworkDNSLookup, model.AgentCapabilityNetworkHTTPProbe,
	}
}
