package netdiag

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

func lanPayload(mutate func(*model.LANRequestTaskPayload)) model.LANRequestTaskPayload {
	p := model.LANRequestTaskPayload{
		NetworkDiagnosticEnvelope: model.NetworkDiagnosticEnvelope{ProtocolVersion: 1, OperationID: "op-1", Origin: model.NetworkDiagnosticOriginPlugin, ExpiresAt: time.Now().Add(time.Minute)},
		TargetID:                  "router", Scheme: "http", Address: "10.10.18.1", Port: 5000, PathPrefix: "/change", Method: "POST", Path: "/change?to=b",
		TimeoutMS: 2000,
	}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func noLocal() ([]netip.Addr, error) { return nil, nil }

func TestValidateLANRequestRefusesEverythingOutsideTheTarget(t *testing.T) {
	cases := map[string]func(*model.LANRequestTaskPayload){
		"public":         func(p *model.LANRequestTaskPayload) { p.Address = "1.1.1.1" },
		"loopback":       func(p *model.LANRequestTaskPayload) { p.Address = "127.0.0.1" },
		"metadata":       func(p *model.LANRequestTaskPayload) { p.Address = "169.254.169.254" },
		"link-local v6":  func(p *model.LANRequestTaskPayload) { p.Address = "fe80::1" },
		"hostname":       func(p *model.LANRequestTaskPayload) { p.Address = "router.lan" },
		"prefix sibling": func(p *model.LANRequestTaskPayload) { p.Path = "/changes" },
		"dot segment":    func(p *model.LANRequestTaskPayload) { p.Path = "/change/../admin" },
		"encoded dot":    func(p *model.LANRequestTaskPayload) { p.Path = "/change/%2e%2e/admin" },
		"host header":    func(p *model.LANRequestTaskPayload) { p.Headers = map[string]string{"Host": "x"} },
		"header newline": func(p *model.LANRequestTaskPayload) { p.Headers = map[string]string{"X-A": "a\r\nb: c"} },
		"insecure http":  func(p *model.LANRequestTaskPayload) { p.InsecureTLS = true },
		"method":         func(p *model.LANRequestTaskPayload) { p.Method = "CONNECT" },
		"response limit": func(p *model.LANRequestTaskPayload) { p.MaxResponseBytes = model.LANRequestMaxResponseBytes + 1 },
	}
	for name, mutate := range cases {
		if _, err := ValidateLANRequest(lanPayload(mutate), noLocal); err == nil {
			t.Fatalf("%s: expected refusal", name)
		}
	}
	own := func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.10.18.1")}, nil }
	if _, err := ValidateLANRequest(lanPayload(nil), own); CodeOf(err) != model.NetworkDiagnosticCodeTargetNotAllowed {
		t.Fatalf("an address of this server must be refused, got %v", err)
	}
	if _, err := ValidateLANRequest(lanPayload(nil), noLocal); err != nil {
		t.Fatalf("valid payload refused: %v", err)
	}
}

// redirectDialer sends every dial to the test server, standing in for the
// private address.
type redirectDialer struct{ address string }

func (d redirectDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func TestLANRequestReturnsBoundedBodyAndNeverFollowsRedirects(t *testing.T) {
	var seen *http.Request
	var seenBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/change/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
			return
		}
		seen = r
		raw, _ := io.ReadAll(r.Body)
		seenBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=secret")
		_, _ = w.Write([]byte(`{"status":"ok","outbound":"b"}` + strings.Repeat(" ", 100)))
	}))
	defer server.Close()
	dialer := redirectDialer{address: strings.TrimPrefix(server.URL, "http://")}
	p := lanPayload(func(p *model.LANRequestTaskPayload) {
		p.Headers = map[string]string{"Content-Type": "application/json"}
		p.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(`{"to":"b"}`))
		p.MaxResponseBytes = 30
	})
	result, err := LANRequest(context.Background(), dialer, noLocal, p)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(result.BodyBase64)
	if result.StatusCode != 200 || string(body) != `{"status":"ok","outbound":"b"}` || !result.Truncated || result.BodyBytes != 30 {
		t.Fatalf("unexpected result %+v body=%q", result, body)
	}
	if _, leaked := result.Headers["set-cookie"]; leaked || result.Headers["content-type"] != "application/json" {
		t.Fatalf("unexpected headers %+v", result.Headers)
	}
	if seen.Method != "POST" || seen.URL.RequestURI() != "/change?to=b" || seen.Host != "10.10.18.1:"+strconv.Itoa(5000) || seenBody != `{"to":"b"}` {
		t.Fatalf("unexpected request %s %s host=%s body=%s", seen.Method, seen.URL.RequestURI(), seen.Host, seenBody)
	}
	redirected, err := LANRequest(context.Background(), dialer, noLocal, lanPayload(func(p *model.LANRequestTaskPayload) { p.Method = "GET"; p.Path = "/change/redirect" }))
	if err != nil || redirected.StatusCode != http.StatusFound {
		t.Fatalf("redirect must be returned, not followed: %+v %v", redirected, err)
	}
}
