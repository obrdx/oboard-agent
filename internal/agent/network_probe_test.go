package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const networkProbePlanFixture = `{"version":42,"resource_version":"public","mode":"icmp","enabled":true,"interval_seconds":60,"sample_count":1,"targets":[{"probe_id":"public-cloudflare","kind":"public","host":"cp.cloudflare.com","port":0},{"probe_id":"t1-0","kind":"custom","task_id":1,"task_name":"TCP","mode":"tcp","host":"example.com","port":8443,"interval_seconds":300},{"probe_id":"t2-0","kind":"custom","task_id":2,"task_name":"Ping","mode":"icmp","host":"1.1.1.1","ip":"1.1.1.1","port":0,"interval_seconds":60},{"probe_id":"t3-0","kind":"custom","task_id":3,"task_name":"HTTP","mode":"http","url":"https://example.com/health","host":"example.com","port":443,"interval_seconds":900}]}`

func TestNetworkProbeMixedMethodWirePlan(t *testing.T) {
	var plan model.LatencyProbeTargetsPlan
	if err := json.Unmarshal([]byte(networkProbePlanFixture), &plan); err != nil {
		t.Fatal(err)
	}
	runner := New(Config{AgentID: "network", StateDir: t.TempDir(), ResourceProfile: "large"})
	if err := runner.setLatencyProbePlan(plan); err != nil {
		t.Fatal(err)
	}
	report, err := runner.runLatencyProbeTaskWithProbe(context.Background(), plan, func(context.Context, string, int, int, time.Duration, time.Duration) ([]int64, []string) {
		return []int64{12}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"icmp", "tcp", "icmp", "http"} {
		if report.Items[i].Mode != want || !report.Items[i].Available || report.Items[i].TaskID != plan.Targets[i].TaskID || report.Items[i].Port != plan.Targets[i].Port {
			t.Fatalf("result %d: %#v", i, report.Items[i])
		}
	}
	changed := plan
	changed.Targets = append([]model.LatencyProbeTarget(nil), plan.Targets...)
	changed.Targets[3].URL = "https://example.com/other"
	if err := runner.setLatencyProbePlan(changed); err == nil {
		t.Fatal("different URL accepted at same version")
	}
	restarted := New(Config{AgentID: "network", StateDir: runner.stateDir(), ResourceProfile: "large"})
	restarted.latencyProbeMu.Lock()
	restarted.loadLatencyProbeStateLocked()
	restarted.latencyProbeMu.Unlock()
	if restarted.latencyProbeState.Plan.Targets[3].URL != plan.Targets[3].URL {
		t.Fatal("HTTP URL lost on restart")
	}
}

func TestNetworkProbeHTTPValidation(t *testing.T) {
	for _, address := range []string{"ftp://example.com", "https://user:pass@example.com", "https://example.com/#x", "https://other.example.com/", "https://example.com:8443/", "https://example.com:65536/"} {
		target := model.LatencyProbeTarget{Kind: "custom", Host: "example.com", Port: 443, URL: address}
		if err := validateLatencyProbeTarget(target, model.LatencyProbeModeHTTP); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
}

func TestNetworkProbeHTTPStatusRedirectAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "OBoard-Network-Probe" {
			t.Error("probe user agent missing")
		}
		if r.URL.Path == "/wait" {
			<-r.Context().Done()
			return
		}
		if n, _ := strconv.Atoi(r.URL.Query().Get("redirects")); n > 0 {
			http.Redirect(w, r, "/?redirects="+strconv.Itoa(n-1), http.StatusFound)
			return
		}
		code, _ := strconv.Atoi(r.URL.Query().Get("status"))
		if code == 0 {
			code = 204
		}
		w.WriteHeader(code)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second
	client.CheckRedirect = networkProbeHTTPClient(time.Second, time.Now).CheckRedirect
	for _, tc := range []struct {
		query   string
		success bool
	}{{"?status=204", true}, {"?status=500", false}, {"?status=404", false}, {"?redirects=3", true}, {"?redirects=4", false}} {
		samples, failures := httpProbeSamplesWithClient(context.Background(), server.URL+"/"+tc.query, 1, 0, client)
		if (len(samples) == 1) != tc.success || (len(failures) == 0) != tc.success {
			t.Fatalf("%s: %v %v", tc.query, samples, failures)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	samples, failures := httpProbeSamplesWithClient(ctx, server.URL+"/wait", 3, time.Second, client)
	if len(samples) != 0 || len(failures) == 0 {
		t.Fatalf("cancelled HTTP probe succeeded: %v %v", samples, failures)
	}
}

func TestNetworkProbeInternalTargets(t *testing.T) {
	for _, host := range []string{"localhost", "router", "router.lan", "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fd00::1", "fe80::1%eth0"} {
		target := model.LatencyProbeTarget{ProbeID: "custom", Kind: "custom", Host: host, Port: 80}
		if addr, err := netip.ParseAddr(host); err == nil {
			target.IP = addr.String()
			resolved, err := resolveLatencyProbeIP(context.Background(), host)
			if err != nil || resolved != addr {
				t.Fatalf("resolve %s: %s %v", host, resolved, err)
			}
		}
		for _, mode := range []model.LatencyProbeMode{model.LatencyProbeModeTCP, model.LatencyProbeModeICMP} {
			if err := validateLatencyProbeTarget(target, mode); err != nil {
				t.Fatalf("validate %s %s: %v", mode, host, err)
			}
		}
	}
}

func TestNetworkProbeHTTPInternalTargetsAndProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	client := networkProbeHTTPClient(time.Second, func() time.Time { return now })
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.TLSClientConfig.Time().Equal(now) {
		t.Fatal("HTTP transport inherited a proxy or ignored logical time")
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp6" {
				address = "[::1]:0"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "/health", http.StatusFound)
				}
			}))
			server.Listener.Close()
			server.Listener = listener
			server.Start()
			defer server.Close()
			samples, failures := httpProbeSamplesWithClient(context.Background(), server.URL+"/redirect", 1, 0, client)
			if len(samples) != 1 || len(failures) != 0 {
				t.Fatalf("HTTP internal probe: %v %v", samples, failures)
			}
			host, portText, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			samples, failures = tcpProbeSamplesContext(context.Background(), host, port, 1, 0, time.Second)
			if len(samples) != 1 || len(failures) != 0 {
				t.Fatalf("TCP internal probe: %v %v", samples, failures)
			}
		})
	}
}
