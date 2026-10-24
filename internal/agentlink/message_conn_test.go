package agentlink

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestApplicationFramesSupportSharedMessageLimit(t *testing.T) {
	for _, kind := range []byte{frameTypeMessage, frameTypeRequest, frameTypeResponse} {
		var buf bytes.Buffer
		data := bytes.Repeat([]byte("x"), maxFramePayload+1)
		if err := writeFrame(&buf, frame{frameType: kind, payload: data}); err != nil {
			t.Fatal(err)
		}
		f, err := readFrame(&buf)
		if err != nil || len(f.payload) != len(data) {
			t.Fatalf("application frame truncated: %v", err)
		}
	}
	header := make([]byte, frameHeaderLen)
	header[0] = frameTypeMessage
	binary.BigEndian.PutUint32(header[2:], MaxMessageBytes+1)
	if _, err := readFrame(bytes.NewReader(header)); err != ErrFrameTooLarge {
		t.Fatal("oversize application frame accepted")
	}
	binary.BigEndian.PutUint32(header[2:], InteractiveMaxMessage*2+1)
	if _, err := readFrameLimited(bytes.NewReader(header), InteractiveMaxMessage*2); err != ErrFrameTooLarge {
		t.Fatal("terminal frame allocated before size check")
	}
}
