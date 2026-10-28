package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	badjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var pathOutboundTagPattern = regexp.MustCompile(`^path-[1-9][0-9]*-step-[1-9][0-9]*$`)

var outboundEgressSources = []string{
	"https://api.ip.sb/ip",
	"https://icanhazip.com",
}

type outboundEgressLookup func(tag string) (N.Dialer, bool)

func registerOutboundEgressHandler(mux *http.ServeMux, instance *box.Box) {
	lookup := func(tag string) (N.Dialer, bool) {
		if instance == nil {
			return nil, false
		}
		outbound, loaded := instance.Outbound().Outbound(tag)
		if !loaded {
			return nil, false
		}
		return outbound, true
	}
	mux.Handle("/outbounds/egress-ip", newOutboundEgressHandler(lookup, outboundEgressSources))
}

func newOutboundEgressHandler(lookup outboundEgressLookup, sources []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var request struct {
			OutboundTag string `json:"outbound_tag"`
		}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		request.OutboundTag = strings.TrimSpace(request.OutboundTag)
		if !pathOutboundTagPattern.MatchString(request.OutboundTag) {
			http.Error(w, "outbound tag is not probeable", http.StatusBadRequest)
			return
		}
		dialer, loaded := lookup(request.OutboundTag)
		if !loaded || dialer == nil {
			http.Error(w, "outbound not found", http.StatusNotFound)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		exitIP, err := probeOutboundEgressIP(ctx, dialer, sources)
		if err != nil {
			http.Error(w, "egress probe failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"exit_ip": exitIP})
	})
}

func probeOutboundEgressIP(ctx context.Context, dialer N.Dialer, sources []string, clocks ...func() time.Time) (string, error) {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxConnsPerHost:       1,
		IdleConnTimeout:       time.Second,
	}
	if len(clocks) > 0 {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, Time: clocks[0]}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are disabled")
		},
	}
	var lastErr error
	for _, source := range sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			lastErr = err
			continue
		}
		res, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 257))
		_ = res.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if res.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("source returned status %d", res.StatusCode)
			continue
		}
		if len(body) > 256 {
			lastErr = errors.New("source response is too large")
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
		if err != nil {
			lastErr = errors.New("source returned an invalid IP")
			continue
		}
		addr = addr.Unmap()
		if !isPublicOutboundEgressAddr(addr) {
			lastErr = errors.New("source returned a non-public IP")
			continue
		}
		return addr.String(), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no egress probe sources configured")
	}
	return "", lastErr
}

func isPublicOutboundEgressAddr(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, raw := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"2001:2::/48", "2001:10::/28", "2001:db8::/32",
	} {
		if netip.MustParsePrefix(raw).Contains(addr) {
			return false
		}
	}
	return true
}

func newStandaloneOutboundCheckHandler(clock *minibox.RuntimeClock) http.Handler {
	slot := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
		default:
			http.Error(w, "probe busy", 409)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		var outbound map[string]any
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&outbound) != nil || !standaloneOutboundAllowed(outbound) {
			http.Error(w, "invalid probe outbound", 400)
			return
		}
		host := outbound["server"].(string)
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			http.Error(w, "proxy address lookup failed", 400)
			return
		}
		for _, address := range addresses {
			if !isPublicOutboundEgressAddr(address.Unmap()) {
				http.Error(w, "proxy address must be public", 400)
				return
			}
		}
		// Pin the validated address so the isolated adapter cannot resolve it again.
		sort.SliceStable(addresses, func(i, j int) bool { return addresses[i].Unmap().Is4() && !addresses[j].Unmap().Is4() })
		outbound["server"] = addresses[0].Unmap().String()
		if tls, ok := outbound["tls"].(map[string]any); ok && tls["enabled"] == true && (tls["server_name"] == nil || tls["server_name"] == "") {
			tls["server_name"] = host
		}
		var exitIP string
		for i, address := range addresses {
			if i >= 2 {
				break
			}
			outbound["server"] = address.Unmap().String()
			attempt, cancelAttempt := context.WithTimeout(ctx, 5*time.Second)
			exitIP, err = probeStandaloneOutbound(attempt, outbound, outboundEgressSources, clock)
			cancelAttempt()
			if err == nil {
				break
			}
		}
		if err != nil {
			http.Error(w, "proxy authentication or exit request failed", http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"exit_ip": exitIP})
	})
}

func probeStandaloneOutbound(ctx context.Context, outbound map[string]any, sources []string, clock *minibox.RuntimeClock) (string, error) {
	boxCtx := minibox.Context(ctx, clock)
	encoded, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "outbounds": []any{outbound}})
	opts, err := badjson.UnmarshalExtendedContext[option.Options](boxCtx, encoded)
	if err != nil {
		return "", errors.New("invalid proxy configuration")
	}
	instance, err := box.New(box.Options{Context: boxCtx, Options: opts})
	if err != nil {
		return "", errors.New("proxy initialization failed")
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		return "", errors.New("proxy start failed")
	}
	dialer, ok := instance.Outbound().Outbound("external-probe")
	if !ok {
		return "", errors.New("proxy unavailable")
	}
	return probeOutboundEgressIP(ctx, dialer, sources, clock.Now)
}

func standaloneOutboundAllowed(outbound map[string]any) bool {
	switch outbound["type"] {
	case "http", "socks", "vless", "hysteria2", "shadowsocks", "anytls", "snell", "mieru":
	default:
		return false
	}
	host, ok := outbound["server"].(string)
	if !ok || strings.TrimSpace(host) == "" || outbound["tag"] != "external-probe" {
		return false
	}
	port, ok := outbound["server_port"].(float64)
	if !ok || port < 1 || port > 65535 || port != float64(int(port)) {
		return false
	}
	for _, key := range []string{"detour", "bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "domain_resolver", "netns"} {
		if _, exists := outbound[key]; exists {
			return false
		}
	}
	return !probeContainsFileReference(outbound)
}

func probeContainsFileReference(value any) bool {
	switch item := value.(type) {
	case map[string]any:
		for key, value := range item {
			if strings.HasSuffix(key, "_path") || key == "path" && item["type"] == "unix" || probeContainsFileReference(value) {
				return true
			}
		}
	case []any:
		for _, value := range item {
			if probeContainsFileReference(value) {
				return true
			}
		}
	}
	return false
}
