package agent

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestManagementConsoleMenuExit(t *testing.T) {
	var out bytes.Buffer
	code := RunManagementConsole("/missing/config.json", nil, strings.NewReader("0\n"), &out, &out)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	text := out.String()
	if !strings.Contains(text, "OBoard Agent 管理") || !strings.Contains(text, "检查与主控的连接") {
		t.Fatalf("unexpected menu output: %s", text)
	}
}

func TestManagementConsoleCommandHelpAndUnknown(t *testing.T) {
	var out bytes.Buffer
	code := RunManagementConsole("/missing/config.json", []string{"help"}, nil, &out, &out)
	if code != 0 {
		t.Fatalf("help exit code = %d", code)
	}
	if !strings.Contains(out.String(), "obag status") {
		t.Fatalf("help output does not list obag commands: %s", out.String())
	}
	out.Reset()
	code = RunManagementConsole("/missing/config.json", []string{"bogus-command"}, nil, &out, &out)
	if code != 2 {
		t.Fatalf("unknown command exit code = %d", code)
	}
}

func TestManagementControllerCheck(t *testing.T) {
	addr, pin := agentLinkFixture(t, func(conn net.Conn) {
		_, _, err := readAgentLinkFixture(conn)
		if err == nil {
			_ = writeAgentLinkFixture(conn, 3, nil)
		}
	})
	result := checkManagementController(Config{ControllerAddr: addr, ControllerCertSHA256: pin, AgentID: "a", AgentToken: "t"})
	if !result.OK || len(result.Items) != 1 || !result.Items[0].OK {
		t.Fatalf("AgentLink verification failed: %#v", result)
	}
}

func TestDisplayControllerURLRemovesSensitiveParts(t *testing.T) {
	got := displayControllerURL("https://user:pass@example.com:8443/path?token=secret")
	if got != "https://example.com:8443/path" {
		t.Fatalf("display URL = %q", got)
	}
}

func TestManagementControllerCheckKeepsBasePath(t *testing.T) {
	addr, pin := agentLinkFixture(t, func(conn net.Conn) {
		_, _, err := readAgentLinkFixture(conn)
		if err == nil {
			_ = writeAgentLinkFixture(conn, 3, nil)
		}
	})
	result := checkManagementController(Config{ControllerURL: "https://unreachable.invalid/qzq", ControllerAddr: addr, ControllerCertSHA256: pin, AgentID: "a", AgentToken: "t"})
	if !result.OK {
		t.Fatalf("AgentLink depended on panel base path: %#v", result)
	}
}
