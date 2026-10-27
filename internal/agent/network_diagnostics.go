package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/netdiag"
	"github.com/OboardProject/oboard-agent/internal/nexttrace"
)

func isNetworkDiagnosticTask(taskType string) bool {
	switch taskType {
	case model.AgentTaskTypeNetworkPing, model.AgentTaskTypeNetworkTrace, model.AgentTaskTypeNetworkTCP, model.AgentTaskTypeNetworkDNS, model.AgentTaskTypeNetworkHTTP, model.AgentTaskTypeGoogleRegion:
		return true
	default:
		return false
	}
}

func decodeDiagnosticPayload(raw string, target any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if dec.More() {
		return errTrailingDiagnosticData
	}
	return nil
}

type diagnosticDecodeError string

func (e diagnosticDecodeError) Error() string { return string(e) }

const errTrailingDiagnosticData = diagnosticDecodeError("trailing data")

func diagnosticFailure(code, message string) (string, string) {
	return "failed", jsonMap(map[string]any{"code": code, "error": message})
}

// validateDiagnosticEnvelope applies the checks common to every
// probe_network_* task. Plugin diagnostics require the node's explicit local
// plugins gate; the Controller can never raise it remotely.
func (r *Runner) validateDiagnosticEnvelope(envelope model.NetworkDiagnosticEnvelope) (string, string, bool) {
	switch {
	case envelope.ProtocolVersion != model.NetworkDiagnosticProtocolVersion:
		status, result := diagnosticFailure(model.NetworkDiagnosticCodeUnsupported, "unsupported diagnostic protocol version")
		return status, result, false
	case envelope.Origin != model.NetworkDiagnosticOriginPlugin && envelope.Origin != model.NetworkDiagnosticOriginMonitor:
		status, result := diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "diagnostic origin must be plugin or monitor")
		return status, result, false
	case envelope.OperationID == "" || len(envelope.OperationID) > 64 || strings.ContainsAny(envelope.OperationID, " \t\r\n"):
		status, result := diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "operation_id is invalid")
		return status, result, false
	case envelope.ExpiresAt.IsZero() || !r.diagnosticNow().Before(envelope.ExpiresAt):
		status, result := diagnosticFailure(model.NetworkDiagnosticCodeExpired, "the diagnostic expired before it could start")
		return status, result, false
	case envelope.Origin == model.NetworkDiagnosticOriginMonitor && (envelope.PluginID != "" || envelope.InstanceID != 0 || envelope.RunID != ""):
		status, result := diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "monitor diagnostics cannot carry plugin identity")
		return status, result, false
	case envelope.Origin == model.NetworkDiagnosticOriginPlugin && !r.localGateAllows("plugins"):
		status, result := diagnosticFailure(model.NetworkDiagnosticCodeLocalGateDenied, "agent local security policy does not allow plugin diagnostics")
		return status, result, false
	}
	return "", "", true
}

func (r *Runner) diagnosticNow() time.Time {
	if r.clock != nil {
		return r.clock.Now()
	}
	return time.Now()
}

// executeNetworkDiagnosticTask runs one structured diagnostic with native Go
// sockets. It never executes ping, traceroute, curl or any other program,
// Plugin operations use NetworkDiagnosticMaxDurationMS; native monitors allow
// 60 seconds, which covers bounded NextTrace API enrichment for route traces.
func (r *Runner) executeNetworkDiagnosticTask(task model.AgentTask) (string, string) {
	var envelope model.NetworkDiagnosticEnvelope
	decoded := json.Unmarshal([]byte(task.PayloadJSON), &envelope) == nil
	if decoded && envelope.Origin == model.NetworkDiagnosticOriginMonitor && task.Type != model.AgentTaskTypeNetworkTrace && task.Type != model.AgentTaskTypeGoogleRegion && task.Type != model.AgentTaskTypeNetworkTCP {
		return diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "monitor origin is restricted to route traces, TCP probes and Google region probes")
	}
	if task.Type == model.AgentTaskTypeGoogleRegion && (!decoded || envelope.Origin != model.NetworkDiagnosticOriginMonitor) {
		return diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "Google region probes require the monitor origin")
	}
	budget := time.Duration(model.NetworkDiagnosticMaxDurationMS) * time.Millisecond
	if envelope.Origin == model.NetworkDiagnosticOriginMonitor {
		budget = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	resolver := netdiag.Resolver(net.DefaultResolver)
	dialer := &net.Dialer{}
	var (
		result any
		err    error
	)
	switch task.Type {
	case model.AgentTaskTypeNetworkPing:
		var payload model.NetworkPingTaskPayload
		if decodeErr := decodeDiagnosticPayload(task.PayloadJSON, &payload); decodeErr != nil {
			return diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "malformed ping payload")
		}
		if status, failure, ok := r.validateDiagnosticEnvelope(payload.NetworkDiagnosticEnvelope); !ok {
			return status, failure
		}
		result, err = netdiag.Ping(ctx, resolver, netdiag.OpenRawTransport, payload)
	case model.AgentTaskTypeNetworkTrace:
		var payload model.NetworkTraceTaskPayload
		if decodeErr := decodeDiagnosticPayload(task.PayloadJSON, &payload); decodeErr != nil {
			return diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "malformed trace payload")
		}
		if status, failure, ok := r.validateDiagnosticEnvelope(payload.NetworkDiagnosticEnvelope); !ok {
			return status, failure
		}
		trace, traceErr := netdiag.Trace(ctx, resolver, netdiag.OpenRawTransport, netdiag.TCPTracer, payload)
		if traceErr == nil && payload.Origin == model.NetworkDiagnosticOriginMonitor {
			r.nextTraceOnce.Do(func() { r.nextTraceGeo = nexttrace.New(r.diagnosticNow, os.Getenv("OBOARD_NEXTTRACE_API_TOKEN")) })
			r.nextTraceGeo.Enrich(ctx, &trace)
		}
		result, err = trace, traceErr
	case model.AgentTaskTypeNetworkTCP:
		var payload model.NetworkTCPProbeTaskPayload
		if decodeErr := decodeDiagnosticPayload(task.PayloadJSON, &payload); decodeErr != nil {
			return diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "malformed TCP probe payload")
		}
		if status, failure, ok := r.validateDiagnosticEnvelope(payload.NetworkDiagnosticEnvelope); !ok {
			return status, failure
		}
		result, err = netdiag.TCPProbe(ctx, resolver, dialer, payload)
	case model.AgentTaskTypeNetworkDNS:
		var payload model.NetworkDNSLookupTaskPayload
		if decodeErr := decodeDiagnosticPayload(task.PayloadJSON, &payload); decodeErr != nil {
			return diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "malformed DNS lookup payload")
		}
		if status, failure, ok := r.validateDiagnosticEnvelope(payload.NetworkDiagnosticEnvelope); !ok {
			return status, failure
		}
		result, err = netdiag.DNSLookup(ctx, resolver, payload)
	case model.AgentTaskTypeNetworkHTTP:
		var payload model.NetworkHTTPProbeTaskPayload
		if decodeErr := decodeDiagnosticPayload(task.PayloadJSON, &payload); decodeErr != nil {
			return diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "malformed HTTP probe payload")
		}
		if status, failure, ok := r.validateDiagnosticEnvelope(payload.NetworkDiagnosticEnvelope); !ok {
			return status, failure
		}
		result, err = netdiag.HTTPProbe(ctx, resolver, dialer, payload)
	case model.AgentTaskTypeGoogleRegion:
		var payload model.GoogleRegionTaskPayload
		if decodeErr := decodeDiagnosticPayload(task.PayloadJSON, &payload); decodeErr != nil {
			return diagnosticFailure(model.NetworkDiagnosticCodeInvalidInput, "malformed Google region payload")
		}
		if status, failure, ok := r.validateDiagnosticEnvelope(payload.NetworkDiagnosticEnvelope); !ok {
			return status, failure
		}
		result, err = netdiag.GoogleRegion(ctx, resolver, dialer, payload)
	default:
		return diagnosticFailure(model.NetworkDiagnosticCodeUnsupported, "unsupported diagnostic")
	}
	if err != nil {
		return diagnosticFailure(netdiag.CodeOf(err), err.Error())
	}
	raw, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return diagnosticFailure(model.NetworkDiagnosticCodeFailed, "cannot encode diagnostic result")
	}
	return "succeeded", string(raw)
}
