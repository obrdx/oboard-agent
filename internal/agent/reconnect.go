package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/OboardProject/oboard-agent/internal/agentlink"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	reconnectAuthMin = 2 * time.Minute
	reconnectAuthMax = 5 * time.Minute
)

func reconnectDelay(agentID, controllerURL string, failures int, firstAfterDrop, authFailure bool) time.Duration {
	if authFailure {
		span := reconnectAuthMax - reconnectAuthMin
		return reconnectAuthMin + time.Duration(rand.Int63n(int64(span)+1))
	}
	if firstAfterDrop {
		return reconnectSpreadDelay(agentID, controllerURL)
	}
	return reconnectFailureDelay(failures)
}

func reconnectSpreadDelay(agentID, controllerURL string) time.Duration {
	sum := sha256.Sum256([]byte(strings.TrimSpace(agentID) + "\x00" + strings.TrimSpace(controllerURL)))
	ms := binary.BigEndian.Uint16(sum[:2]) % 5000
	return time.Duration(ms) * time.Millisecond
}

func reconnectFailureDelay(failures int) time.Duration {
	if failures < 0 {
		failures = 0
	}
	max := time.Second
	if failures >= 6 {
		max = 60 * time.Second
	} else if failures > 0 {
		max = time.Second << failures
		if max > 60*time.Second {
			max = 60 * time.Second
		}
	}
	return time.Duration(rand.Int63n(int64(max) + 1))
}

func isAuthReconnectError(err error) bool {
	if err == nil {
		return false
	}
	var authError *agentlink.AuthError
	if errors.As(err, &authError) {
		return true
	}
	if status := websocketDialStatus(err); status == http.StatusUnauthorized || status == http.StatusForbidden {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "identity") {
		return true
	}
	return false
}

func websocketDialStatus(err error) int {
	var closeErr *websocket.CloseError
	if err != nil {
		_ = closeErr
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "401"):
		return http.StatusUnauthorized
	case strings.Contains(msg, "403"):
		return http.StatusForbidden
	}
	return 0
}

func isNetworkReconnectError(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(net.Error); ok {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "no such host") || strings.Contains(msg, "temporarily unavailable")
}
