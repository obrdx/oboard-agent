package socks_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	singbufio "github.com/sagernet/sing/common/bufio"
	badjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type recordedSocksServer struct {
	listener    net.Listener
	udpConn     *net.UDPConn
	mu          sync.Mutex
	tcpTargets  []M.Socksaddr
	udpTargets  []M.Socksaddr
	tcpDone     chan M.Socksaddr
	udpDone     chan M.Socksaddr
	closeOnce   sync.Once
	closed      chan struct{}
}

func startRecordedSocksServer(t *testing.T) *recordedSocksServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	srv := &recordedSocksServer{
		listener: listener,
		udpConn:  udpConn,
		tcpDone:  make(chan M.Socksaddr, 8),
		udpDone:  make(chan M.Socksaddr, 8),
		closed:   make(chan struct{}),
	}
	go srv.serveTCP()
	go srv.serveUDP()
	t.Cleanup(srv.Close)
	return srv
}

func (s *recordedSocksServer) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.listener.Close()
		_ = s.udpConn.Close()
	})
}

func (s *recordedSocksServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *recordedSocksServer) serveTCP() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(conn)
	}
}

func (s *recordedSocksServer) handleTCP(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	authReq, err := socks5.ReadAuthRequest(reader)
	if err != nil {
		return
	}
	_ = authReq
	if err := socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: socks5.AuthTypeNotRequired}); err != nil {
		return
	}
	req, err := socks5.ReadRequest(reader)
	if err != nil {
		return
	}
	switch req.Command {
	case socks5.CommandConnect:
		s.mu.Lock()
		s.tcpTargets = append(s.tcpTargets, req.Destination)
		s.mu.Unlock()
		select {
		case s.tcpDone <- req.Destination:
		default:
		}
		_ = socks5.WriteResponse(conn, socks5.Response{
			ReplyCode: socks5.ReplyCodeSuccess,
			Bind:      M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 0),
		})
		_, _ = io.Copy(io.Discard, reader)
	case socks5.CommandUDPAssociate:
		udpAddr := s.udpConn.LocalAddr().(*net.UDPAddr)
		_ = socks5.WriteResponse(conn, socks5.Response{
			ReplyCode: socks5.ReplyCodeSuccess,
			Bind:      M.SocksaddrFromNet(udpAddr).Unwrap(),
		})
		_, _ = io.Copy(io.Discard, reader)
	}
}

func (s *recordedSocksServer) serveUDP() {
	raw := make([]byte, 2048)
	for {
		n, _, err := s.udpConn.ReadFromUDP(raw)
		if err != nil {
			return
		}
		if n < 4 {
			continue
		}
		packet := buf.As(raw[3:n])
		dest, err := M.SocksaddrSerializer.ReadAddrPort(packet)
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.udpTargets = append(s.udpTargets, dest)
		s.mu.Unlock()
		select {
		case s.udpDone <- dest:
		default:
		}
	}
}

func startTestBox(t *testing.T, config map[string]any) *box.Box {
	t.Helper()
	ctx := minibox.Context(context.Background(), minibox.NewRuntimeClock())
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := badjson.UnmarshalExtendedContext[option.Options](ctx, encoded)
	if err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		t.Fatalf("box.Start: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

func TestSocksOutboundRemoteAndLocalDNSModes(t *testing.T) {
	srv := startRecordedSocksServer(t)
	resolvedIP := netip.MustParseAddr("198.51.100.42")

	for _, tc := range []struct {
		name         string
		remoteDNS    *bool
		wantDomain   bool
		wantAddr     netip.Addr
	}{
		{name: "default_socks5h", remoteDNS: nil, wantDomain: true},
		{name: "explicit_socks5h", remoteDNS: boolPtr(true), wantDomain: true},
		{name: "explicit_local_dns", remoteDNS: boolPtr(false), wantDomain: false, wantAddr: resolvedIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outbound := map[string]any{
				"type":        "socks",
				"tag":         "test-socks",
				"server":      "127.0.0.1",
				"server_port": srv.port(),
				"version":     "5",
			}
			if tc.remoteDNS != nil {
				outbound["remote_dns"] = *tc.remoteDNS
			}
			instance := startTestBox(t, map[string]any{
				"log": map[string]any{"disabled": true},
				"dns": map[string]any{
					"servers": []any{
						map[string]any{
							"type": "hosts",
							"tag":  "static-hosts",
							"predefined": map[string]any{
								"target.example.test": []string{resolvedIP.String()},
							},
						},
					},
					"final": "static-hosts",
				},
				"outbounds": []any{outbound},
			})

			out, ok := instance.Outbound().Outbound("test-socks")
			if !ok {
				t.Fatal("missing test-socks outbound")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// TCP CONNECT verification
			conn, err := out.DialContext(ctx, "tcp", M.Socksaddr{Fqdn: "target.example.test", Port: 443})
			if err != nil {
				t.Fatalf("tcp dial failed: %v", err)
			}
			_ = conn.Close()
			select {
			case got := <-srv.tcpDone:
				if tc.wantDomain {
					if !got.IsDomain() || got.Fqdn != "target.example.test" || got.Port != 443 {
						t.Fatalf("tcp target = %v, want FQDN target.example.test:443", got)
					}
				} else {
					if got.IsDomain() || got.Addr != tc.wantAddr || got.Port != 443 {
						t.Fatalf("tcp target = %v, want IP %s:443", got, tc.wantAddr)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for TCP CONNECT target")
			}

			// UDP ASSOCIATE packet verification
			packetConn, err := out.ListenPacket(ctx, M.Socksaddr{Fqdn: "target.example.test", Port: 5353})
			if err != nil {
				t.Fatalf("udp listen failed: %v", err)
			}
			defer packetConn.Close()
			wrapped := singbufio.NewPacketConn(packetConn)
			pkt := buf.NewPacket()
			pkt.Resize(N.CalculateFrontHeadroom(wrapped), 0)
			_, _ = pkt.Write([]byte("ping"))
			if err := wrapped.WritePacket(pkt, M.Socksaddr{Fqdn: "target.example.test", Port: 5353}); err != nil {
				t.Fatalf("udp write packet failed: %v", err)
			}
			select {
			case got := <-srv.udpDone:
				if tc.wantDomain {
					if !got.IsDomain() || got.Fqdn != "target.example.test" || got.Port != 5353 {
						t.Fatalf("udp target = %v, want FQDN target.example.test:5353", got)
					}
				} else {
					if got.IsDomain() || got.Addr != tc.wantAddr || got.Port != 5353 {
						t.Fatalf("udp target = %v, want IP %s:5353", got, tc.wantAddr)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for UDP ASSOCIATE target")
			}
		})
	}
}

func TestSocks4RejectsRemoteDNS(t *testing.T) {
	ctx := minibox.Context(context.Background(), minibox.NewRuntimeClock())
	encoded, _ := json.Marshal(map[string]any{
		"log": map[string]any{"disabled": true},
		"outbounds": []any{
			map[string]any{
				"type":        "socks",
				"tag":         "bad-socks4",
				"server":      "127.0.0.1",
				"server_port": 1080,
				"version":     "4",
				"remote_dns":  true,
			},
		},
	})
	opts, err := badjson.UnmarshalExtendedContext[option.Options](ctx, encoded)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if instance, err := box.New(box.Options{Context: ctx, Options: opts}); err == nil {
		_ = instance.Close()
		t.Fatal("expected socks4 with remote_dns=true to be rejected")
	}
}

func TestDetouredSocks5WithoutDomainResolverDelegatesNextHopHostname(t *testing.T) {
	hop1 := startRecordedSocksServer(t)
	instance := startTestBox(t, map[string]any{
		"log": map[string]any{"disabled": true},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{
					"type": "hosts",
					"tag":  "static-hosts",
					"predefined": map[string]any{
						"hop2.internal.test": []string{"198.51.100.99"},
					},
				},
			},
			"final": "static-hosts",
		},
		"outbounds": []any{
			map[string]any{
				"type":        "socks",
				"tag":         "hop-1",
				"server":      "127.0.0.1",
				"server_port": hop1.port(),
				"version":     "5",
			},
			map[string]any{
				"type":        "socks",
				"tag":         "hop-2",
				"server":      "hop2.internal.test",
				"server_port": 1080,
				"version":     "5",
				"detour":      "hop-1",
			},
		},
	})

	hop2, ok := instance.Outbound().Outbound("hop-2")
	if !ok {
		t.Fatal("missing hop-2 outbound")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Dialing hop-2 initiates a TCP connect through hop-1 to hop2.internal.test:1080.
	// Our mock hop1 discards after accepting CONNECT, so hop2's inner SOCKS handshake
	// will fail with EOF, which is expected; we assert hop1 received the FQDN intact.
	conn, _ := hop2.DialContext(ctx, "tcp", M.Socksaddr{Fqdn: "final.example.test", Port: 443})
	if conn != nil {
		_ = conn.Close()
	}
	select {
	case got := <-hop1.tcpDone:
		if !got.IsDomain() || got.Fqdn != "hop2.internal.test" || got.Port != 1080 {
			t.Fatalf("hop-1 received %v, want FQDN hop2.internal.test:1080 (must not resolve locally on server)", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for hop-1 to receive hop-2 domain")
	}
}

func boolPtr(v bool) *bool { return &v }
