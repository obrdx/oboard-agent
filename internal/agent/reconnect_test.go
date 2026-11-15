package agent

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestReconnectSpreadDelayIsStableAndBounded(t *testing.T) {
	first := reconnectSpreadDelay("agent-1", "https://controller.example")
	second := reconnectSpreadDelay("agent-1", "https://controller.example")
	if first != second {
		t.Fatalf("spread delay is not stable: %s vs %s", first, second)
	}
	if first < 0 || first >= 5*time.Second {
		t.Fatalf("spread delay = %s, want [0, 5s)", first)
	}
	other := reconnectSpreadDelay("agent-2", "https://controller.example")
	if first == other {
		t.Fatal("different agent ids should usually spread differently")
	}
}

func TestReconnectFailureDelayCapsAtSixtySeconds(t *testing.T) {
	for attempt := 0; attempt <= 8; attempt++ {
		delay := reconnectFailureDelay(attempt)
		max := time.Second << attempt
		if attempt >= 6 || max > 60*time.Second {
			max = 60 * time.Second
		}
		if delay < 0 || delay > max {
			t.Fatalf("attempt %d delay = %s, want <= %s", attempt, delay, max)
		}
	}
}

func TestReconnectDelayClassifiesAuthVsNetwork(t *testing.T) {
	auth := reconnectDelay("agent-1", "https://c", 0, false, true)
	if auth < reconnectAuthMin || auth > reconnectAuthMax {
		t.Fatalf("auth delay = %s", auth)
	}
	first := reconnectDelay("agent-1", "https://c", 0, true, false)
	if first < 0 || first >= 5*time.Second {
		t.Fatalf("first-after-drop delay = %s", first)
	}
	if !isAuthReconnectError(errors.New("websocket: bad handshake: 401 Unauthorized")) {
		t.Fatal("401 should be classified as auth")
	}
	if isAuthReconnectError(errors.New("403 Forbidden")) {
		t.Fatal("a resource 403 is not an identity rejection")
	}
	if !isAuthReconnectError(errors.New("controller rejected agent identity code=token_mismatch")) {
		t.Fatal("token mismatch should be classified as auth")
	}
	if isAuthReconnectError(errors.New("dial tcp: connection refused")) {
		t.Fatal("connection refused should use network jitter")
	}
	if websocketDialStatus(errors.New("401")) != http.StatusUnauthorized {
		t.Fatal("expected 401 status")
	}
}

func TestReconnectStormFiftyAgentsStayWithinFiveSeconds(t *testing.T) {
	latest := time.Duration(0)
	for i := 0; i < 50; i++ {
		id := "agent-" + string(rune('a'+i%26)) + string(rune('0'+i%10))
		delay := reconnectSpreadDelay(id, "https://controller.example/api")
		if delay > latest {
			latest = delay
		}
	}
	if latest >= 5*time.Second {
		t.Fatalf("storm spread %s exceeds 5s", latest)
	}
}
