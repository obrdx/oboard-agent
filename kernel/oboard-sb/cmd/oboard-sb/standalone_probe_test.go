package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
)

func TestStandaloneProbeActuallyUsesAuthenticatedHTTPProxy(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "8.8.8.8") }))
	defer source.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:secret")) {
			http.Error(w, "authentication required", 407)
			return
		}
		upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, "upstream failed", 502)
			return
		}
		defer upstream.Close()
		client, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, client); close(done) }()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
		_ = upstream.Close()
		<-done
	}))
	defer proxy.Close()
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(proxy.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	outbound := map[string]any{"type": "http", "tag": "external-probe", "server": host, "server_port": port, "username": "user", "password": "secret"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, err := probeStandaloneOutbound(ctx, outbound, []string{source.URL}, minibox.NewRuntimeClock())
	if err != nil || ip != "8.8.8.8" {
		t.Fatalf("proxy probe ip=%q err=%v", ip, err)
	}
	outbound["password"] = "wrong"
	if ip, err := probeStandaloneOutbound(ctx, outbound, []string{source.URL}, minibox.NewRuntimeClock()); err == nil || ip != "" {
		t.Fatal("wrong proxy credentials accepted")
	}
}

func TestStandaloneProbeRefusesPrivateAndUnsafeOutbounds(t *testing.T) {
	for _, raw := range []string{
		`{"type":"http","tag":"external-probe","server":"127.0.0.1","server_port":8080}`,
		`{"type":"direct","tag":"external-probe","server":"1.1.1.1","server_port":8080}`,
		`{"type":"http","tag":"external-probe","server":"1.1.1.1","server_port":8080,"detour":"direct"}`,
		`{"type":"http","tag":"external-probe","server":"1.1.1.1","server_port":8080,"tls":{"enabled":true,"certificate_path":"/etc/passwd"}}`,
	} {
		recorder := httptest.NewRecorder()
		newStandaloneOutboundCheckHandler(minibox.NewRuntimeClock()).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/outbounds/check", strings.NewReader(raw)))
		if recorder.Code != 400 {
			t.Fatalf("unsafe probe accepted: status=%d", recorder.Code)
		}
	}
}

func TestStandaloneProbeCommandRejectsUnsafeInput(t *testing.T) {
	for _, raw := range []string{
		`{}`, strings.Repeat(" ", 65537),
		`{"type":"http","tag":"external-probe","server":"127.0.0.1","server_port":8080,"password":"must-not-leak"}`,
		`{"type":"http","tag":"external-probe","server":"1.1.1.1","server_port":8080,"detour":"direct"}`,
		`{"type":"http","tag":"external-probe","server":"1.1.1.1","server_port":8080} {}`,
	} {
		var output bytes.Buffer
		err := runStandaloneOutboundCheck(strings.NewReader(raw), &output)
		if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "must-not-leak") {
			t.Fatalf("unsafe command: %v %q", err, output.String())
		}
	}
}

const probeWireGuardKey = "YNXtAzepDqRv9H52osJVDQnznT5AL11IUmHwhGvYPXE="

func probeWireGuardEndpoint(peerAddress string, extra string) string {
	return `{"type":"wireguard","tag":"external-probe","address":["172.16.0.2/32"],"private_key":"` + probeWireGuardKey + `","mtu":1280` + extra +
		`,"peers":[{"address":"` + peerAddress + `","port":51820,"public_key":"` + probeWireGuardKey + `","allowed_ips":["0.0.0.0/0","::/0"]}]}`
}

func TestStandaloneProbeAcceptsOnlyASinglePeerWireGuardEndpoint(t *testing.T) {
	decode := func(raw string) map[string]any {
		var outbound map[string]any
		if err := json.Unmarshal([]byte(raw), &outbound); err != nil {
			t.Fatal(err)
		}
		return outbound
	}
	if !standaloneOutboundAllowed(decode(probeWireGuardEndpoint("162.159.192.1", ""))) {
		t.Fatal("single-peer WireGuard endpoint rejected")
	}
	for _, raw := range []string{
		probeWireGuardEndpoint("162.159.192.1", `,"detour":"direct"`),
		probeWireGuardEndpoint("162.159.192.1", `,"system":true`),
		probeWireGuardEndpoint("162.159.192.1", `,"server":"1.1.1.1","server_port":1`),
		`{"type":"wireguard","tag":"external-probe","private_key":"` + probeWireGuardKey + `","peers":[]}`,
		`{"type":"wireguard","tag":"external-probe","private_key":"` + probeWireGuardKey + `","peers":[{"address":"1.1.1.1","port":1},{"address":"1.1.1.2","port":1}]}`,
		`{"type":"http","tag":"external-probe","server":"1.1.1.1","server_port":8080,"peers":[{"address":"1.1.1.1","port":1}]}`,
	} {
		if standaloneOutboundAllowed(decode(raw)) {
			t.Fatalf("unsafe WireGuard probe accepted: %s", raw)
		}
	}
	recorder := httptest.NewRecorder()
	newStandaloneOutboundCheckHandler(minibox.NewRuntimeClock()).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/outbounds/check", strings.NewReader(probeWireGuardEndpoint("127.0.0.1", ""))))
	if recorder.Code != 400 {
		t.Fatalf("private WireGuard peer accepted: status=%d", recorder.Code)
	}
}

func TestStandaloneProbeStartsWireGuardAsEndpoint(t *testing.T) {
	var outbound map[string]any
	if err := json.Unmarshal([]byte(probeWireGuardEndpoint("192.0.2.1", "")), &outbound); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := probeStandaloneOutbound(ctx, outbound, []string{"https://192.0.2.2/"}, minibox.NewRuntimeClock())
	if err == nil {
		t.Fatal("unreachable WireGuard peer returned an exit IP")
	}
	for _, setup := range []string{"invalid proxy configuration", "proxy initialization failed", "proxy start failed", "proxy unavailable"} {
		if err.Error() == setup {
			t.Fatalf("WireGuard endpoint was not built: %v", err)
		}
	}
}
