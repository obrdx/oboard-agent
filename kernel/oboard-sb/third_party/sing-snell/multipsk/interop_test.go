package multipsk_test

import (
	"context"
	"errors"
	"fmt"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/multipsk"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type echo struct {
	users chan string
	wg    sync.WaitGroup
}

func (h *echo) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, done N.CloseHandlerFunc) {
	name, _ := auth.UserFromContext[string](ctx)
	h.users <- name
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		_, err := io.Copy(c, c)
		_ = c.Close()
		if done != nil {
			done(err)
		}
	}()
}
func (h *echo) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, done N.CloseHandlerFunc) {
	name, _ := auth.UserFromContext[string](ctx)
	h.users <- name
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer c.Close()
		defer func() {
			if done != nil {
				done(nil)
			}
		}()
		for {
			b := buf.NewPacket()
			a, e := c.ReadPacket(b)
			if e != nil {
				b.Release()
				return
			}
			reply := buf.NewSize(4096 + b.Len())
			reply.Resize(2048, 0)
			_, _ = reply.Write(b.Bytes())
			b.Release()
			if e = c.WritePacket(reply, a); e != nil {
				return
			}
		}
	}()
}

type multiService interface {
	snell.Service
	UpdatePSKs([]multipsk.User) error
}
type fragmented struct {
	net.Conn
	size int
}

func (c fragmented) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		k, e := c.Conn.Write(p[:min(len(p), c.size)])
		n += k
		if e != nil {
			return n, e
		}
		p = p[k:]
	}
	return n, nil
}
func fixture(t testing.TB, version int, mode snellv6.Mode, obfs snell.ObfsMode) (multiService, *echo) {
	t.Helper()
	h := &echo{users: make(chan string, 128)}
	var s multiService
	var e error
	ns := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	if version == 4 {
		s, e = snellv5.NewPSKService(snellv5.ServiceOptions{ObfsMode: obfs, Handler: h}, ns, nil)
	} else {
		s, e = snellv6.NewPSKService(snellv6.ServerOptions{Mode: mode, Handler: h}, ns, nil)
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(h.wg.Wait)
	return s, h
}
func method(t testing.TB, version int, mode snellv6.Mode, obfs snell.ObfsMode, psk, spoof string) snell.Method {
	t.Helper()
	var m snell.Method
	var e error
	if version == 4 {
		m, e = snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(psk), UserKey: []byte(spoof), ObfsMode: obfs, ObfsHost: "bing.com"})
	} else {
		m, e = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk), UserKey: []byte(spoof), Mode: mode})
	}
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestIndependentPSKsTCPUDPAndFragmentation(t *testing.T) {
	for _, tc := range []struct {
		version int
		mode    snellv6.Mode
		obfs    snell.ObfsMode
	}{{4, 0, 0}, {4, 0, snell.ObfsModeHTTP}, {6, 0, 0}, {6, snellv6.ModeUnshaped, 0}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			s, h := fixture(t, tc.version, tc.mode, tc.obfs)
			users := []multipsk.User{{Name: "alice-branch1", PSK: []byte("alice-branch1-independent-key")}, {Name: "alice-branch2", PSK: []byte("alice-branch2-independent-key")}, {Name: "bob", PSK: []byte("bob-independent-key")}}
			if e := s.UpdatePSKs(users); e != nil {
				t.Fatal(e)
			}
			for idx, u := range users {
				for _, fragment := range []int{1, 7, 4096} {
					for _, udp := range []bool{false, true} {
						client, server := net.Pipe()
						_ = client.SetDeadline(time.Now().Add(3 * time.Second))
						done := make(chan error, 1)
						go func() {
							e := s.NewConnection(context.Background(), server, M.ParseSocksaddr(fmt.Sprintf("192.0.2.%d:9000", idx+fragment%253+1)), nil)
							if e != nil {
								server.Close()
							}
							done <- e
						}()
						m := method(t, tc.version, tc.mode, tc.obfs, string(u.PSK), "forged-other-user")
						raw := fragmented{client, fragment}
						dst := M.ParseSocksaddr("example.com:443")
						if udp {
							c, e := m.DialPacketConn(raw)
							if e != nil {
								t.Fatal(e)
							}
							if _, e = c.WriteTo([]byte("payload"), M.ParseSocksaddr("192.0.2.200:443").UDPAddr()); e != nil {
								t.Fatal(e)
							}
							b := make([]byte, 64)
							n, _, e := c.ReadFrom(b)
							if e != nil || string(b[:n]) != "payload" {
								t.Fatalf("udp payload %q err %v", b[:n], e)
							}
							c.Close()
						} else {
							c := m.DialEarlyConn(raw, dst)
							if _, e := c.Write([]byte("payload")); e != nil {
								t.Fatal(e)
							}
							b := make([]byte, 7)
							if _, e := io.ReadFull(c, b); e != nil || string(b) != "payload" {
								t.Fatalf("tcp payload %q err %v", b, e)
							}
							c.Close()
						}
						select {
						case got := <-h.users:
							if got != u.Name {
								t.Fatalf("spoofed identity: %s", got)
							}
						case <-time.After(time.Second):
							t.Fatal("no authenticated identity")
						}
						server.Close()
						client.Close()
						select {
						case <-done:
						case <-time.After(time.Second):
							t.Fatal("session leaked")
						}
					}
				}
			}
		})
	}
}
func TestZeroUsersAndDuplicateAreFailClosed(t *testing.T) {
	for _, v := range []int{4, 6} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			s, h := fixture(t, v, 0, 0)
			good := multipsk.User{Name: "one", PSK: []byte("test-independent-psk")}
			if e := s.UpdatePSKs([]multipsk.User{good}); e != nil {
				t.Fatal(e)
			}
			if e := s.UpdatePSKs([]multipsk.User{good, {Name: "two", PSK: good.PSK}}); !errors.Is(e, multipsk.ErrDuplicate) {
				t.Fatal(e)
			}
			if e := s.UpdatePSKs(nil); e != nil {
				t.Fatal(e)
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			if e := s.NewConnection(context.Background(), b, M.ParseSocksaddr("192.0.2.1:1"), nil); !errors.Is(e, multipsk.ErrCredential) {
				t.Fatal(e)
			}
			select {
			case <-h.users:
				t.Fatal("zero users admitted")
			default:
			}
			if e := s.UpdatePSKs([]multipsk.User{good}); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestV6LongRequestPSKService(t *testing.T) {
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped} {
		t.Run(mode.String(), func(t *testing.T) {
			s, h := fixture(t, 6, mode, 0)
			u := multipsk.User{Name: "long-request", PSK: []byte("audit-snell-v6-psk-0")}
			if err := s.UpdatePSKs([]multipsk.User{u}); err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			done := make(chan error, 1)
			go func() {
				err := s.NewConnection(context.Background(), server, M.ParseSocksaddr("192.0.2.1:1234"), nil)
				if err != nil {
					server.Close()
				}
				done <- err
			}()
			c := method(t, 6, mode, 0, string(u.PSK), strings.Repeat("x", 255)).DialEarlyConn(client, M.ParseSocksaddr(domain+":443"))
			if _, err := c.Write([]byte("payload")); err != nil {
				t.Fatal(err)
			}
			out := make([]byte, 7)
			if _, err := io.ReadFull(c, out); err != nil || string(out) != "payload" {
				t.Fatalf("payload=%q err=%v", out, err)
			}
			if got := <-h.users; got != u.Name {
				t.Fatalf("identity=%q", got)
			}
			c.Close()
			server.Close()
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("session leaked")
			}
		})
	}
}
