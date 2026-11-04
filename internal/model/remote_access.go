package model

import "time"

const (
	RemoteAccessModeStandard = "standard"
	RemoteAccessModeHardened = "hardened"

	RemoteAccessCapabilityTerminal         = "remote_terminal_v1"
	RemoteAccessCapabilityTerminalLoginEnv = "terminal_login_env_v1"
	RemoteAccessCapabilityExec             = "remote_exec_v1"
	RemoteAccessCapabilityInteractiveMCP   = "remote_interactive_mcp_v1"
	RemoteAccessCapabilityLocalGate        = "remote_access_local_gate_v1"

	RemoteExecOriginMCP   = "mcp"
	RemoteExecOriginPanel = "panel"
	RemoteExecModeArgv    = "argv"
	RemoteExecModeShell   = "shell"

	PrivilegeRemoteOperations  = "remote_operations"
	PrivilegeRemoteExec        = "remote_exec"
	PrivilegeRemoteShell       = "remote_shell"
	PrivilegeRemoteInteractive = "remote_interactive"

	RemoteOperationSystemInfo     = "system_info"
	RemoteOperationNetworkInfo    = "network_info"
	RemoteOperationDiskUsage      = "disk_usage"
	RemoteOperationListeners      = "listeners"
	RemoteOperationServiceStatus  = "service_status"
	RemoteOperationServiceRestart = "service_restart"
	RemoteOperationLogs           = "logs"
	RemoteOperationDiagnostics    = "diagnostics"
)

type RemoteAccessReport struct {
	Capabilities []string               `json:"capabilities,omitempty"`
	LocalMode    string                 `json:"local_mode,omitempty"`
	LocalAllow   RemoteAccessLocalAllow `json:"local_allow,omitempty"`
}

type RemoteAccessLocalAllow struct {
	RemoteTerminal bool `json:"remote_terminal"`
	MCPEnabled     bool `json:"mcp_enabled"`
	PluginsEnabled bool `json:"plugins_enabled"`
	// LANRequests is the separate local switch for plugin lan.request. It is
	// closed by default in every mode. `obag remote-access allow lan` opens it
	// locally; in Standard mode Controller may also open it with the signed
	// apply_agent_local_policy task, in Hardened mode Controller may only
	// close it.
	LANRequests bool `json:"lan_requests_enabled"`
}

type RemoteExecCommand struct {
	Mode  string   `json:"mode"`
	Argv  []string `json:"argv,omitempty"`
	Shell string   `json:"shell,omitempty"`
	Cwd   string   `json:"cwd,omitempty"`
}

type RemoteExecLimits struct {
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	StdoutBytes    int `json:"stdout_bytes,omitempty"`
	StderrBytes    int `json:"stderr_bytes,omitempty"`
}

type RemoteExecResult struct {
	ExitCode        int    `json:"exit_code"`
	DurationMS      int64  `json:"duration_ms"`
	StdoutBytes     int    `json:"stdout_bytes"`
	StderrBytes     int    `json:"stderr_bytes"`
	StdoutSHA256    string `json:"stdout_sha256"`
	StderrSHA256    string `json:"stderr_sha256"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	Cancelled       bool   `json:"cancelled,omitempty"`
	Error           string `json:"error,omitempty"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
}

type RemoteExecTaskPayload struct {
	RequestID string            `json:"request_id"`
	Origin    string            `json:"origin"`
	Privilege string            `json:"privilege"`
	ActorRef  string            `json:"actor_ref,omitempty"`
	GrantID   int64             `json:"grant_id,omitempty"`
	ServerID  int64             `json:"server_id"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Command   RemoteExecCommand `json:"command"`
	Limits    RemoteExecLimits  `json:"limits"`
}

type RemoteOperationTaskPayload struct {
	RequestID string    `json:"request_id"`
	Origin    string    `json:"origin"`
	Kind      string    `json:"kind"`
	ActorRef  string    `json:"actor_ref,omitempty"`
	GrantID   int64     `json:"grant_id,omitempty"`
	ServerID  int64     `json:"server_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Service   string    `json:"service,omitempty"`
	Lines     int       `json:"lines,omitempty"`
}

type InteractivePrepareEnvelope struct {
	Type             string `json:"type"`
	SignatureVersion int    `json:"signature_version"`
	ServerID         int64  `json:"server_id"`
	SessionID        string `json:"session_id"`
	Nonce            string `json:"nonce"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	Kind             string `json:"kind"`
	Origin           string `json:"origin,omitempty"`
	Cols             int    `json:"cols"`
	Rows             int    `json:"rows"`
	Mode             string `json:"mode,omitempty"`
	Signature        string `json:"signature,omitempty"`
}

const (
	InteractiveOriginHuman = "human"
	InteractiveOriginMCP   = "mcp"
)

// AgentCapabilityLocalPolicyRemote is advertised by Agents that accept the
// signed apply_agent_local_policy task for the plugins and lan gates.
const AgentCapabilityLocalPolicyRemote = "agent_local_policy_remote_v1"

// Local policy features Controller may set remotely.
const (
	LocalPolicyFeaturePlugins = "plugins"
	LocalPolicyFeatureLAN     = "lan"
)

// LocalPolicyErrorHardened is the result error when Controller asks a
// Hardened Agent to open a gate; only the node operator can do that.
const LocalPolicyErrorHardened = "hardened_local_only"

// AgentLocalPolicyPlan is the apply_agent_local_policy payload. Opening lan
// also opens plugins, which lan depends on; closing plugins closes lan.
type AgentLocalPolicyPlan struct {
	Feature string `json:"feature"`
	Allow   bool   `json:"allow"`
}

// AgentLocalPolicyResult reports the enforced gates after the change.
type AgentLocalPolicyResult struct {
	Feature    string                 `json:"feature"`
	Allow      bool                   `json:"allow"`
	Changed    bool                   `json:"changed"`
	LocalMode  string                 `json:"local_mode"`
	LocalAllow RemoteAccessLocalAllow `json:"local_allow"`
	Error      string                 `json:"error,omitempty"`
	Message    string                 `json:"message,omitempty"`
}
