package agentsecurity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/securefile"
	"github.com/OboardProject/oboard-agent/internal/stealth"
)

const (
	DefaultPath = "/etc/oboard-agent/local-security.json"
	FileMode    = 0o600
)

type Policy struct {
	Version int                          `json:"version"`
	Mode    string                       `json:"mode"`
	Allow   model.RemoteAccessLocalAllow `json:"allow"`
	Deny    LocalDeny                    `json:"deny"`
}

// LocalDeny records explicit operator denials for gates that are open by
// default in Standard mode.
type LocalDeny struct {
	Plugins bool `json:"plugins_enabled"`
}

func DefaultPolicy() Policy {
	return Policy{Version: 1, Mode: model.RemoteAccessModeStandard}
}

func (p Policy) Normalized() Policy {
	if p.Version == 0 {
		p.Version = 1
	}
	switch strings.ToLower(strings.TrimSpace(p.Mode)) {
	case model.RemoteAccessModeHardened:
		p.Mode = model.RemoteAccessModeHardened
	default:
		p.Mode = model.RemoteAccessModeStandard
	}
	return p
}

func (p Policy) Allows(feature string) bool {
	p = p.Normalized()
	switch feature {
	case "plugins", "plugins_enabled":
		if p.Deny.Plugins {
			return false
		}
		return p.Mode != model.RemoteAccessModeHardened || p.Allow.PluginsEnabled
	case "lan", "lan_requests", "lan_requests_enabled":
		return p.Allow.LANRequests && p.Allows("plugins")
	case "remote_terminal":
		return p.Mode != model.RemoteAccessModeHardened || p.Allow.RemoteTerminal
	case "mcp_remote_operations", "mcp_structured_exec", "mcp_raw_shell", "mcp_interactive_terminal", "mcp_interactive", "mcp_enabled":
		return p.Mode != model.RemoteAccessModeHardened || p.Allow.MCPEnabled
	default:
		return false
	}
}

type Store struct {
	mu   sync.Mutex
	path string
	// key encrypts the policy file at rest in stealth mode. An empty key
	// keeps the plaintext JSON file.
	key []byte
}

func NewStore(path string, key []byte) *Store {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath
	}
	return &Store{path: path, key: append([]byte(nil), key...)}
}

func PathForConfig(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return DefaultPath
	}
	return filepath.Join(filepath.Dir(configPath), "local-security.json")
}

func (s *Store) Path() string { return s.path }

func (s *Store) Load() (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (Policy, error) {
	// #nosec G304 -- s.path is derived from the agent config directory.
	raw, err := securefile.Read(s.path, 64<<10)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultPolicy(), nil
		}
		return Policy{}, err
	}
	if len(s.key) > 0 && stealth.IsEncrypted(raw) {
		if raw, err = stealth.Decrypt(s.key, raw); err != nil {
			return Policy{}, err
		}
	}
	var policy Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return Policy{}, err
	}
	if policy.Version != 1 || (policy.Mode != model.RemoteAccessModeStandard && policy.Mode != model.RemoteAccessModeHardened) {
		return Policy{}, errors.New("invalid local security policy")
	}
	return policy.Normalized(), nil
}

// ReportedAllow is the allow set sent to Controller. The plugin and LAN gates
// are reported as enforced because Controller uses them directly as gates.
func (p Policy) ReportedAllow() model.RemoteAccessLocalAllow {
	allow := p.Allow
	allow.PluginsEnabled = p.Allows("plugins")
	allow.LANRequests = p.Allows("lan")
	return allow
}

func (s *Store) Save(policy Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy = policy.Normalized()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	if len(s.key) > 0 {
		if sealed, err := stealth.Encrypt(s.key, append(raw, '\n')); err != nil {
			return err
		} else {
			raw = sealed
		}
	} else {
		raw = append(raw, '\n')
	}
	return securefile.Write(s.path, raw, FileMode, true)
}

func (s *Store) SetMode(mode string) error {
	policy, err := s.Load()
	if err != nil {
		return err
	}
	policy.Mode = mode
	return s.Save(policy)
}

func (s *Store) SetAllow(feature string, allow bool) error {
	policy, err := s.Load()
	if err != nil {
		return err
	}
	switch feature {
	case "terminal", "remote_terminal":
		policy.Allow.RemoteTerminal = allow
	case "mcp-operations", "mcp_remote_operations", "mcp-exec", "mcp_structured_exec", "mcp-shell", "mcp_raw_shell", "mcp_interactive_terminal", "mcp_interactive", "mcp-interactive", "mcp_enabled", "mcp":
		policy.Allow.MCPEnabled = allow
	case "plugins", "plugins_enabled":
		policy.Allow.PluginsEnabled = allow
		policy.Deny.Plugins = !allow
	case "lan", "lan_requests", "lan_requests_enabled":
		policy.Allow.LANRequests = allow
	default:
		return errors.New("unknown remote-access feature")
	}
	return s.Save(policy)
}
