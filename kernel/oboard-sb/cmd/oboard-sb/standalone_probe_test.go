package main

import (
	"context"
	"encoding/base64"
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
