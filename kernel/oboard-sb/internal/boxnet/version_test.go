package boxnet

import (
	"os"
	"strings"
	"testing"
)

func TestSocketAdapterUpstreamPin(t *testing.T) {
	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "github.com/sagernet/sing-box v1.14.4\n") {
		t.Fatal("rebase the local socket adapters when updating sing-box; see UPSTREAM")
	}
}
