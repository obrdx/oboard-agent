package minibox

import (
	"fmt"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/snell"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"

	mieruprotocol "github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/mieru"
	sourceprefixprotocol "github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/sourceprefix"
)

func TestSupportedProtocolsRemainMinimal(t *testing.T) {
	want := []string{"vless", "hysteria2", "anytls", "shadowsocks", "mieru", "snell", "socks", "http", "wireguard", "source-prefix", "family-selector", "user-selector", "vpngate-pool"}
	if !slices.Equal(SupportedProtocols, want) {
		t.Fatalf("supported protocols = %v, want %v", SupportedProtocols, want)
	}
}

func TestLoadConfigRejectsExcludedProtocols(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "vmess inbound", raw: `{"inbounds":[{"type":"vmess","tag":"excluded","listen":"127.0.0.1","listen_port":10001}]}`},
		{name: "tuic inbound", raw: `{"inbounds":[{"type":"tuic","tag":"excluded","listen":"127.0.0.1","listen_port":10002}]}`},
		{name: "http inbound", raw: `{"inbounds":[{"type":"http","tag":"excluded","listen":"127.0.0.1","listen_port":10003}]}`},
		{name: "trojan outbound", raw: `{"outbounds":[{"type":"trojan","tag":"excluded","server":"127.0.0.1","server_port":443}]}`},
		{name: "tailscale endpoint", raw: `{"endpoints":[{"type":"tailscale","tag":"excluded"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(test.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := LoadConfig(path, nil, HY2Tuning{}); err == nil {
				t.Fatal("excluded protocol config was accepted")
			}
		})
	}
}

func TestLoadConfigAcceptsHTTPOutbound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"outbounds":[
			{"type":"http","tag":"http-plain","server":"127.0.0.1","server_port":8080,"username":"u","password":"p"},
			{"type":"http","tag":"http-tls","server":"127.0.0.1","server_port":8443,"tls":{"enabled":true,"server_name":"proxy.example.com"}}
		]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Outbounds) != 2 || opts.Outbounds[0].Type != "http" || opts.Outbounds[1].Type != "http" {
		t.Fatalf("http outbounds not loaded: %#v", opts.Outbounds)
	}
}

func TestLoadConfigStripsRuntimeMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
		"_oboard":{"rate_limits":{"users":{"alice":{"speed_limit_mbps":20}}}},
		"log":{"level":"info"},
		"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{"final":"direct"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, metadata, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Log == nil || opts.Log.Level != "info" {
		t.Fatalf("log options not loaded: %#v", opts.Log)
	}
	if got := metadata.RateLimits.Users["alice"].SpeedLimitMbps; got != 20 {
		t.Fatalf("speed limit = %d, want 20", got)
	}
}

func TestLoadConfigAcceptsManagedWireGuardEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
		"endpoints":[{
			"type":"wireguard",
			"tag":"warp-1",
			"address":["172.16.0.2/32"],
			"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"peers":[{
				"address":"engage.cloudflareclient.com",
				"port":2408,
				"public_key":"bmXOC+F1sQvdD4mp8yt3l7wY6/3mpYBvn04zP65yzM8=",
				"allowed_ips":["0.0.0.0/0","::/0"]
			}]
		}],
		"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{"final":"warp-1"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Endpoints) != 1 || opts.Endpoints[0].Type != "wireguard" || opts.Endpoints[0].Tag != "warp-1" {
		t.Fatalf("wireguard endpoint not loaded: %#v", opts.Endpoints)
	}
}

func TestLoadConfigAcceptsShadowsocksUoTContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
		"inbounds":[{
			"type":"shadowsocks",
			"tag":"ss-in",
			"listen":"0.0.0.0",
			"listen_port":8388,
			"network":"tcp",
			"method":"chacha20-ietf-poly1305",
			"password":"server-pass"
		}],
		"outbounds":[{
			"type":"shadowsocks",
			"tag":"ss-out",
			"server":"127.0.0.1",
			"server_port":8388,
			"method":"chacha20-ietf-poly1305",
			"password":"server-pass",
			"udp_over_tcp":{"enabled":true}
		}],
		"route":{"final":"ss-out"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	inbound, ok := opts.Inbounds[0].Options.(*option.ShadowsocksInboundOptions)
	if !ok || len(inbound.Network.Build()) != 1 || inbound.Network.Build()[0] != "tcp" {
		t.Fatalf("shadowsocks inbound is not TCP-only: %#v", opts.Inbounds[0].Options)
	}
	outbound, ok := opts.Outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	if !ok || outbound.UDPOverTCP == nil || !outbound.UDPOverTCP.Enabled {
		t.Fatalf("shadowsocks outbound UoT was not decoded: %#v", opts.Outbounds[0].Options)
	}
}

func TestLoadConfigAcceptsAuthenticatedSocks5InboundAndOutbound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"inbounds":[{
			"type":"socks",
			"tag":"socks-in",
			"listen":"0.0.0.0",
			"listen_port":1080,
			"users":[{"username":"alice","password":"secret"}]
		}],
		"outbounds":[{
			"type":"socks",
			"tag":"socks-out",
			"server":"127.0.0.1",
			"server_port":1080,
			"version":"5",
			"username":"alice",
			"password":"secret"
		}],
		"route":{"final":"socks-out"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	inbound, ok := opts.Inbounds[0].Options.(*option.SocksInboundOptions)
	if !ok || len(inbound.Users) != 1 || inbound.Users[0].Username != "alice" || inbound.Users[0].Password != "secret" {
		t.Fatalf("SOCKS5 inbound options not decoded: %#v", opts.Inbounds[0].Options)
	}
	outbound, ok := opts.Outbounds[0].Options.(*option.SOCKSOutboundOptions)
	if !ok || outbound.Version != "5" || outbound.Username != "alice" || outbound.Password != "secret" {
		t.Fatalf("SOCKS5 outbound options not decoded: %#v", opts.Outbounds[0].Options)
	}
}

func TestLoadConfigAcceptsAnyTLSPaddingScheme(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"inbounds":[{
			"type":"anytls",
			"tag":"anytls-in",
			"listen":"127.0.0.1",
			"listen_port":443,
			"users":[{"name":"alice","password":"secret"}],
			"padding_scheme":["stop=3","0=900-1400","1=900-1400","2=900-1400"],
			"tls":{"enabled":true,"certificate_path":"/tmp/cert.pem","key_path":"/tmp/key.pem"}
		}],
		"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{"final":"direct"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	inbound, ok := opts.Inbounds[0].Options.(*option.AnyTLSInboundOptions)
	want := []string{"stop=3", "0=900-1400", "1=900-1400", "2=900-1400"}
	if !ok || !slices.Equal(inbound.PaddingScheme, want) {
		t.Fatalf("AnyTLS padding scheme not decoded: %#v", opts.Inbounds[0].Options)
	}
}

func TestLoadConfigAcceptsMieruOptionsFromLocalRegistry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
		"inbounds":[{
			"type":"mieru",
			"tag":"mieru-in",
			"listen":"127.0.0.1",
			"listen_port":8964,
			"listen_ports":["8965-8966"],
			"transport":"TCP",
			"users":[{"name":"oboard-u7","password":"server-pass"}],
			"user_hint_is_mandatory":true
		}],
		"outbounds":[{
			"type":"mieru",
			"tag":"mieru-out",
			"server":"edge.example.com",
			"server_port":8964,
			"server_ports":["8965-8966"],
			"transport":"TCP",
			"username":"oboard-u7",
			"password":"server-pass",
			"multiplexing":"MULTIPLEXING_DEFAULT"
		}],
		"route":{"final":"mieru-out"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	inboundOptions, ok := opts.Inbounds[0].Options.(*mieruprotocol.InboundOptions)
	if !ok || inboundOptions.Transport != "TCP" || len(inboundOptions.ListenPortRanges) != 1 {
		t.Fatalf("mieru inbound options not decoded: %#v", opts.Inbounds[0].Options)
	}
	outboundOptions, ok := opts.Outbounds[0].Options.(*mieruprotocol.OutboundOptions)
	if !ok || outboundOptions.Username != "oboard-u7" || len(outboundOptions.ServerPortRanges) != 1 {
		t.Fatalf("mieru outbound options not decoded: %#v", opts.Outbounds[0].Options)
	}
}

func TestLoadConfigAcceptsSnellOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"inbounds":[{
			"type":"snell",
			"tag":"snell-in",
			"listen":"0.0.0.0",
			"listen_port":6160,
			"version":5,
			"auth_mode":"multi_psk","users":[{"name":"alice","psk":"server-psk"}],
			"obfs_mode":"http"
		}],
		"outbounds":[{
			"type":"snell",
			"tag":"snell-out",
			"server":"127.0.0.1",
			"server_port":6160,
			"version":4,
			"psk":"server-psk",
			"obfs_mode":"http",
			"obfs_host":"bing.com"
		}],
		"route":{"final":"snell-out"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	inboundOptions, ok := opts.Inbounds[0].Options.(*snell.InboundOptions)
	if !ok || inboundOptions.Version != 5 || inboundOptions.AuthMode != "multi_psk" || inboundOptions.PSK != "" || inboundOptions.Mode != "" {
		t.Fatalf("snell inbound options not decoded: %#v", opts.Inbounds[0].Options)
	}
	outboundOptions, ok := opts.Outbounds[0].Options.(*option.SnellOutboundOptions)
	if !ok || outboundOptions.Version != 4 || outboundOptions.PSK != "server-psk" || outboundOptions.ObfsOptions.ObfsHost != "bing.com" {
		t.Fatalf("snell outbound options not decoded: %#v", opts.Outbounds[0].Options)
	}
}

func TestLoadConfigKeepsGeneratedSnellSharedListeners(t *testing.T) {
	for _, version := range []int{5, 6} {
		path := filepath.Join(t.TempDir(), "config.json")
		raw := fmt.Sprintf(`{"inbounds":[{"type":"snell","tag":"in-2","listen":"0.0.0.0","listen_port":6160,"version":%d,"auth_mode":"multi_psk","users":[]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, version)
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		opts, _, err := LoadConfig(path, nil, HY2Tuning{})
		if err != nil {
			t.Fatal(err)
		}
		listener, ok := opts.Inbounds[0].Options.(*snell.InboundOptions)
		if !ok || listener.AuthMode != "multi_psk" || listener.PSK != "" || listener.ListenPort != 6160 || len(listener.Users) != 0 {
			t.Fatalf("shared Snell listener corrupted: %#v", listener)
		}
	}
}

func TestLoadConfigAcceptsSnellV6Options(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"inbounds":[{
			"type":"snell",
			"tag":"snell-v6-in",
			"listen":"0.0.0.0",
			"listen_port":7177,
			"version":6,
			"auth_mode":"multi_psk","users":[{"name":"alice","psk":"v6-psk-123456"}],
			"mode":"unshaped"
		}],
		"outbounds":[{
			"type":"snell",
			"tag":"snell-v6-out",
			"server":"127.0.0.1",
			"server_port":7177,
			"version":6,
			"psk":"v6-psk",
			"mode":"unsafe-raw",
			"reuse":true
		}],
		"route":{"final":"snell-v6-out"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	inboundOptions, ok := opts.Inbounds[0].Options.(*snell.InboundOptions)
	if !ok || inboundOptions.Version != 6 || inboundOptions.Mode != "unshaped" {
		t.Fatalf("snell v6 inbound options not decoded: %#v", opts.Inbounds[0].Options)
	}
	outboundOptions, ok := opts.Outbounds[0].Options.(*option.SnellOutboundOptions)
	if !ok || outboundOptions.Version != 6 || outboundOptions.V6Options.Mode != "unsafe-raw" || !outboundOptions.Reuse {
		t.Fatalf("snell v6 outbound options not decoded: %#v", opts.Outbounds[0].Options)
	}
}

func TestLoadConfigAcceptsSourcePrefixOutbound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"outbounds":[{
			"type":"source-prefix",
			"tag":"dynamic-v6",
			"prefix":"2001:db8:55::/64"
		}],
		"route":{"final":"dynamic-v6"}
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, err := LoadConfig(path, nil, HY2Tuning{})
	if err != nil {
		t.Fatal(err)
	}
	outboundOptions, ok := opts.Outbounds[0].Options.(*sourceprefixprotocol.OutboundOptions)
	if !ok || outboundOptions.Prefix != "2001:db8:55::/64" {
		t.Fatalf("source-prefix outbound options not decoded: %#v", opts.Outbounds[0].Options)
	}
}
