package minibox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

// Every target reads and returns the entire payload before closing, allowing
// the client to check EOF and native parent reuse, not just TCP establishment.
func snellPayloadTarget(t *testing.T, payload []byte) M.Socksaddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(c, got); err != nil {
					return
				}
				_, _ = c.Write(got)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return M.SocksaddrFromNet(ln.Addr())
}

func reserveSnellTestPorts(t *testing.T, count int) ([]int, func()) {
	t.Helper()
	// Keep every reservation open so ephemeral allocation cannot return one port twice.
	var listeners []net.Listener
	release := func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
		listeners = nil
	}
	t.Cleanup(release)
	ports := make([]int, count)
	for i := range ports {
		ln, err := net.Listen("tcp", "[::]:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, ln)
		ports[i] = ln.Addr().(*net.TCPAddr).Port
	}
	return ports, release
}

func TestReserveSnellTestPorts(t *testing.T) {
	ports, release := reserveSnellTestPorts(t, 2)
	if ports[0] == ports[1] {
		t.Fatal("reserved ports must be distinct")
	}
	for _, port := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf("[::]:%d", port))
		if err == nil {
			_ = ln.Close()
			t.Fatalf("reserved port %d was available before release", port)
		}
	}
	release()
	for _, port := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf("[::]:%d", port))
		if err != nil {
			t.Fatalf("bind released port %d: %v", port, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
	}
}

func TestSnellConcurrentPayloadRamp(t *testing.T) {
	levels, counts := []int{32, 128}, []int{1, 64}
	sources := []bool{false}
	if os.Getenv("OBOARD_SNELL_STRESS") == "1" {
		levels, counts = []int{1, 4, 8, 16, 32, 64, 128}, []int{1, 8, 32, 64}
		sources = []bool{false, true}
	}
	payload := bytes.Repeat([]byte("snell-complete-payload\x00"), 2048)
	cohort := 0
	for _, version := range []int{5, 6} {
		for _, chain := range []bool{false, true} {
			for _, reuse := range []bool{false, true} {
				// Darwin has 16K ephemeral ports by default. Let TIME_WAIT expire between
				// stress cohorts so socket churn does not masquerade as authentication loss.
				if os.Getenv("OBOARD_SNELL_STRESS") == "1" && runtime.GOOS == "darwin" && cohort > 0 {
					t.Log("waiting for Darwin TIME_WAIT between stress cohorts")
					time.Sleep(31 * time.Second)
				}
				cohort++
				for _, count := range counts {
					for _, multisource := range sources {
						t.Run(fmt.Sprintf("v%d/ss_%t/reuse_%t/users_%d/multi_source_%t", version, chain, reuse, count, multisource), func(t *testing.T) {
							target := snellPayloadTarget(t, payload)
							ports, releasePorts := reserveSnellTestPorts(t, 2)
							port, ssPort := ports[0], ports[1]
							inbounds := []map[string]any{{"type": "snell", "tag": "in-1", "version": version, "auth_mode": "multi_psk", "listen": "::", "listen_port": port, "users": []any{}}}
							outbounds := []map[string]any{{"type": "direct", "tag": "direct"}}
							outbound := "direct"
							if chain {
								inbounds = append(inbounds, map[string]any{"type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": ssPort, "method": "2022-blake3-aes-128-gcm", "password": "MDEyMzQ1Njc4OWFiY2RlZg=="})
								outbounds = append(outbounds, map[string]any{"type": "shadowsocks", "tag": "ss-out", "server": "127.0.0.1", "server_port": ssPort, "method": "2022-blake3-aes-128-gcm", "password": "MDEyMzQ1Njc4OWFiY2RlZg=="})
								outbound = "ss-out"
							}
							outbounds = append(outbounds, map[string]any{"type": "user-selector", "tag": "userselector-in-1", "users": map[string]string{}})
							config, err := json.Marshal(map[string]any{"log": map[string]any{"level": "error"}, "inbounds": inbounds, "outbounds": outbounds, "route": map[string]any{"final": "direct", "rules": []map[string]any{{"inbound": []string{"in-1"}, "action": "route", "outbound": "userselector-in-1"}}}})
							if err != nil {
								t.Fatal(err)
							}
							path := filepath.Join(t.TempDir(), "config.json")
							if err := os.WriteFile(path, config, 0600); err != nil {
								t.Fatal(err)
							}
							opts, _, err := LoadConfig(path, nil, HY2Tuning{})
							if err != nil {
								t.Fatal(err)
							}
							ctx, cancel := context.WithCancel(Context(context.Background()))
							defer cancel()
							b, err := box.New(box.Options{Context: ctx, Options: opts})
							if err != nil {
								t.Fatal(err)
							}
							defer b.Close()
							tracker := AttachRuntimeTrackers(ctx, RuntimeMetadata{RuntimeUsers: &RuntimeUsersMeta{Inbounds: []string{"in-1"}}})
							users := NewRuntimeUsers(filepath.Join(t.TempDir(), "users.json"), nil, b, tracker, []string{"in-1"})
							releasePorts()
							if err := b.Start(); err != nil {
								t.Fatal(err)
							}
							entries := make([]UserInstallEntry, count)
							grants := make(map[string]string)
							now := time.Now().UTC()
							for i := range entries {
								key := fmt.Sprintf("key-%d", i)
								entries[i] = snellTestEntry(fmt.Sprintf("user-%d", i), key, fmt.Sprintf("independent-ramp-credential-%04d", i), int64(i+1))
								entries[i].RouteOutbound = outbound
								grants[key] = now.Add(4 * time.Minute).Format(time.RFC3339Nano)
							}
							installSnellTest(t, users, 1, entries)
							if err := tracker.UpdateAuthorization(&authorization.Lease{Revision: 1, IssuedAt: now.Format(time.RFC3339Nano), Grants: grants}); err != nil {
								t.Fatal(err)
							}
							inbound, _ := b.Inbound().Get("in-1")
							metrics := inbound.(interface{ AuthenticationMetrics() map[string]uint64 })
							waitPending := func(t *testing.T, want uint64) {
								t.Helper()
								deadline := time.Now().Add(time.Second)
								for metrics.AuthenticationMetrics()["pending"] != want {
									if time.Now().After(deadline) {
										t.Fatalf("pending handshakes = %d, want %d", metrics.AuthenticationMetrics()["pending"], want)
									}
									time.Sleep(time.Millisecond)
								}
							}
							for _, concurrency := range levels {
								t.Run(fmt.Sprint(concurrency), func(t *testing.T) {
									waitPending(t, 0)
									attempts := metrics.AuthenticationMetrics()["candidate_attempts"]
									// Keep the old listener capacity occupied by peers that send no header.
									slow := make([]net.Conn, 0, 16)
									defer func() {
										for _, c := range slow {
											c.Close()
										}
									}()
									for i := 0; i < 16; i++ {
										c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
										if err != nil {
											t.Fatal(err)
										}
										slow = append(slow, c)
									}
									waitPending(t, 16)
									if got := metrics.AuthenticationMetrics()["candidate_attempts"]; got != attempts {
										t.Fatal("idle sockets consumed derivation work")
									}
									var wg sync.WaitGroup
									start := make(chan struct{})
									for i := 0; i < concurrency; i++ {
										// Start with the final candidate so the first burst is cold even at n=1.
										psk := []byte(entries[count-1-i%count].Credential.PSK)
										host := "127.0.0.1"
										if multisource && i%2 == 1 {
											host = "::1"
										}
										server := M.ParseSocksaddr(net.JoinHostPort(host, fmt.Sprint(port)))
										dialer := &snellLoopbackDialer{}
										var client nativeSnellClient
										var err error
										if version == 5 {
											client, err = snellv4.NewClient(snellv4.ClientOptions{PSK: psk, Reuse: reuse, Dialer: dialer, Server: server})
										} else {
											client, err = snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Reuse: reuse, Dialer: dialer, Server: server})
										}
										if err != nil {
											t.Fatal(err)
										}
										wg.Add(1)
										go func() {
											defer wg.Done()
											defer client.Close()
											<-start
											for round := 0; round < 2; round++ {
												ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
												c, err := client.DialContext(ctx, target)
												if err == nil {
													_ = c.SetDeadline(time.Now().Add(10 * time.Second))
													_, err = c.Write(payload)
													if err == nil {
														var got []byte
														got, err = io.ReadAll(io.LimitReader(c, int64(len(payload)+1)))
														if err == nil && !bytes.Equal(got, payload) {
															err = fmt.Errorf("payload mismatch: received %d of %d bytes", len(got), len(payload))
														}
													}
													c.Close()
												}
												cancel()
												if err != nil {
													t.Errorf("client %d round %d: %v", i, round, err)
													return
												}
											}
											want := int64(2)
											if reuse {
												want = 1
											}
											if got := dialer.count.Load(); got != want {
												t.Errorf("client %d used %d TCP parents, want %d", i, got, want)
											}
										}()
									}
									close(start)
									wg.Wait()
									if got := metrics.AuthenticationMetrics(); got["budget_rejected"] != 0 || got["timeout"] != 0 {
										t.Fatalf("authentication budget/timeout failure: %v", got)
									}
								})
							}
						})
					}
				}
			}
		}
	}
}
