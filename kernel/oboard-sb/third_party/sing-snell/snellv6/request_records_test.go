package snellv6

import (
	"bytes"
	"fmt"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"strings"
	"testing"
)

func TestRequestAcrossRecords(t *testing.T) {
	var psk []byte
	var profile *Profile
	for i := 0; i < 10000; i++ {
		psk = []byte(fmt.Sprintf("audit-snell-v6-psk-%d", i))
		profile = NewProfile(psk)
		if profile.firstRecordCap < 259 {
			break
		}
	}
	if profile.firstRecordCap >= 259 {
		t.Fatal("no short first-record profile")
	}
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, mode := range []Mode{ModeDefault, ModeUnshaped} {
		for _, idLen := range []int{0, 255} {
			for _, command := range []byte{snell.CommandConnect, snell.CommandConnectV2, snell.CommandUDP} {
				t.Run(fmt.Sprintf("%s/id%d/cmd%d", mode.String(), idLen, command), func(t *testing.T) {
					req := snell.Request{Command: command, ClientID: bytes.Repeat([]byte{'x'}, idLen)}
					if command != snell.CommandUDP {
						req.Destination = M.ParseSocksaddr(domain + ":443")
					}
					payload := buf.NewSize(req.Len() + 7)
					defer payload.Release()
					if err := req.Write(payload); err != nil {
						t.Fatal(err)
					}
					if command != snell.CommandUDP {
						_, _ = payload.WriteString("payload")
					}
					var wire bytes.Buffer
					writer, err := writeFirstRecord(&wire, mode, psk, profile, payload.Bytes())
					if err != nil {
						t.Fatal(err)
					}
					// Subsequent reused requests may also span record boundaries.
					for _, part := range [][]byte{payload.Bytes()[:2], payload.Bytes()[2:]} {
						if _, err = writer.Write(part); err != nil {
							t.Fatal(err)
						}
					}
					reader, record, err := readFirstRecord(&wire, mode, psk, profile, N.ReadWaitOptions{})
					if err != nil {
						t.Fatal(err)
					}
					service := &Service{}
					for turn := 0; turn < 2; turn++ {
						if turn > 0 {
							record, err = reader.ReadRecord()
							if err != nil {
								t.Fatal(err)
							}
						}
						got, last, err := service.readRequestRecords(reader, record)
						if err != nil {
							last.Release()
							t.Fatal(err)
						}
						if got.Command != req.Command || !bytes.Equal(got.ClientID, req.ClientID) || got.Destination != req.Destination {
							last.Release()
							t.Fatalf("request changed: %+v", got)
						}
						if command != snell.CommandUDP {
							reader.SetCache(last)
							out := make([]byte, 7)
							if _, err = io.ReadFull(reader, out); err != nil || string(out) != "payload" {
								t.Fatalf("payload=%q err=%v", out, err)
							}
							reader.ReleaseCache()
						} else {
							if !last.IsEmpty() {
								t.Fatal("unexpected UDP payload")
							}
							last.Release()
						}
					}
				})
			}
		}
	}
}

func TestRequestRejectsTruncationAndEmptyBoundary(t *testing.T) {
	psk := []byte("test-request-record-psk")
	for _, emptyBoundary := range []bool{false, true} {
		var wire bytes.Buffer
		writer, err := writeFirstRecord(&wire, ModeUnshaped, psk, nil, []byte{snell.RequestVersion, snell.CommandConnect, 2, 'x'})
		if err != nil {
			t.Fatal(err)
		}
		if emptyBoundary {
			if err = writer.WriteZeroChunk(); err != nil {
				t.Fatal(err)
			}
			_, _ = writer.Write([]byte{'y', 1, 'a', 0, 80})
		}
		reader, record, err := readFirstRecord(&wire, ModeUnshaped, psk, nil, N.ReadWaitOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, last, err := (&Service{}).readRequestRecords(reader, record)
		last.Release()
		if err == nil {
			t.Fatalf("accepted incomplete request (empty boundary=%v)", emptyBoundary)
		}
	}
}
