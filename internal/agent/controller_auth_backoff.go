package agent

import (
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/internal/logging"
)

const (
	controllerAuthBackoffBase   = 30 * time.Second
	controllerAuthBackoffCap    = 5 * time.Minute
	controllerAuthLogWindow     = 2 * time.Minute
	controllerThrottleDefault   = 30 * time.Second
	controllerThrottleJitterMax = 5 * time.Second
	controllerThrottleMaxDefer  = 5 * time.Minute
)

// controllerAuthBackoff pauses authenticated Controller callbacks by error
// class after the Controller refuses this Agent's identity or asks it to slow
// down.
//
// The realtime channel already backs off for two to five minutes on 401/403,
// because a rejected identity does not become valid by retrying sooner. The
// HTTP callbacks did not: traffic, connection audit and asset polling each ran
// on their own timer and kept posting regardless of the answer. A node that was
// deleted or re-enrolled therefore kept a stale token pointed at the Controller
// indefinitely, spending a credential lookup per attempt on an identity that no
// longer exists.
//
// Classes:
//   - auth (401/403): exponential backoff with jitter; a successful
//     update_agent_config clears the pause so a repaired token can retry
//     immediately
//   - throttle (429/503): honor Retry-After (bounded) plus a small jitter so a
//     fleet does not resume in lockstep
type controllerAuthBackoff struct {
	mu sync.Mutex

	until      time.Time
	class      string // "", "auth", "throttle"
	authStep   int
	restricted bool

	suppressed int
	lastLogAt  time.Time
}

// remaining reports how long callbacks stay paused, or zero when they may run.
func (b *controllerAuthBackoff) remaining(now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.until.IsZero() || !now.Before(b.until) {
		return 0
	}
	return b.until.Sub(now)
}

// arm starts or extends the pause. Prefer armWithResponse so Retry-After and
// status-specific classes are applied.
func (b *controllerAuthBackoff) arm(now time.Time) {
	b.armWithResponse(now, http.StatusUnauthorized, nil)
}

func (b *controllerAuthBackoff) armWithStatus(now time.Time, status int) {
	b.armWithResponse(now, status, nil)
}

func (b *controllerAuthBackoff) armWithResponse(now time.Time, status int, header http.Header) {
	b.armWithClass(now, controllerBackoffClass(status), status, header)
}

func (b *controllerAuthBackoff) armAgentLink(now time.Time) {
	b.armWithClass(now, "auth", 0, nil)
}

func (b *controllerAuthBackoff) armWithClass(now time.Time, class string, status int, header http.Header) {
	if class == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	authStep := 0
	if class == "auth" {
		authStep = b.authStep
	}
	delay := controllerBackoffDelay(class, status, header, authStep)
	until := now.Add(delay)
	if class == "auth" {
		b.authStep++
	}
	first := !b.restricted
	sameClass := b.class == class
	if until.After(b.until) {
		b.until = until
	}
	b.class = class
	b.restricted = true

	wait := b.until.Sub(now).Round(time.Second)
	if first {
		logging.Warnf("controller access restricted: class=%s http_status=%d callbacks=paused retry_in=%s; credential and traffic-limit renewal may be interrupted", class, status, wait)
		b.lastLogAt = now
		b.suppressed = 0
		return
	}
	b.suppressed++
	if now.Sub(b.lastLogAt) >= controllerAuthLogWindow {
		logging.Warnf("controller access still restricted: class=%s http_status=%d suppressed=%d retry_in=%s same_class=%v", class, status, b.suppressed, wait, sameClass)
		b.lastLogAt = now
		b.suppressed = 0
	}
}

// clear resumes callbacks after the Controller accepts the identity again, or
// after a local config update repairs credentials / controller URL.
func (b *controllerAuthBackoff) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.restricted {
		detail := ""
		if b.suppressed > 0 {
			detail = " suppressed_while_paused=" + strconv.Itoa(b.suppressed)
		}
		logging.Infof("controller access recovered: authenticated callbacks resumed class=%s%s", b.class, detail)
		b.restricted = false
	}
	b.until = time.Time{}
	b.class = ""
	b.authStep = 0
	b.suppressed = 0
	b.lastLogAt = time.Time{}
}

func controllerBackoffClass(status int) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "auth"
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return "throttle"
	default:
		return ""
	}
}

// isControllerAuthRejection reports whether a Controller status means this
// Agent should stop calling for a while rather than retry on its own timer.
func isControllerAuthRejection(status int) bool {
	return controllerBackoffClass(status) != ""
}

func controllerBackoffDelay(class string, status int, header http.Header, authStep int) time.Duration {
	switch class {
	case "auth":
		// Exponential: 30s, 60s, 120s, ... capped at five minutes, with ±20% jitter.
		exp := float64(controllerAuthBackoffBase) * math.Pow(2, float64(authStep))
		if exp > float64(controllerAuthBackoffCap) {
			exp = float64(controllerAuthBackoffCap)
		}
		base := time.Duration(exp)
		jitterSpan := base / 5
		if jitterSpan < time.Second {
			jitterSpan = time.Second
		}
		return base - jitterSpan/2 + time.Duration(rand.Int63n(int64(jitterSpan)+1))
	case "throttle":
		delay := parseRetryAfter(header, controllerThrottleDefault)
		if delay > controllerThrottleMaxDefer {
			delay = controllerThrottleMaxDefer
		}
		if delay < time.Second {
			delay = time.Second
		}
		// Spread fleet retries that share the same Retry-After value.
		return delay + time.Duration(rand.Int63n(int64(controllerThrottleJitterMax)+1))
	default:
		_ = status
		return controllerThrottleDefault
	}
}

func parseRetryAfter(header http.Header, fallback time.Duration) time.Duration {
	if header == nil {
		return fallback
	}
	raw := strings.TrimSpace(header.Get("Retry-After"))
	if raw == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds < 0 {
			return fallback
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(raw); err == nil {
		delay := time.Until(when)
		if delay > 0 {
			return delay
		}
	}
	return fallback
}
