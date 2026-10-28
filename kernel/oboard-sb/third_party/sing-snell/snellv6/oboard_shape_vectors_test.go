package snellv6

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"os"
	"testing"

	snell "github.com/sagernet/sing-snell"
)

// OBoard Controller selects per-identity v6 PSKs by the first record their
// derived profile produces. These vectors pin that derivation; the Controller
// keeps an identical copy and must be regenerated together with this file.

type shapeVectorRecord struct {
	PayloadLen int `json:"payload_len"`
	TotalLen   int `json:"total_len"`
	FixedOnes  int `json:"fixed_ones"`
	RandomLen  int `json:"random_len"`
}

type shapeVector struct {
	PSK            string              `json:"psk"`
	Generator      uint32              `json:"generator"`
	PadMax         int                 `json:"pad_max"`
	FirstRecordCap int                 `json:"first_record_cap"`
	Records        []shapeVectorRecord `json:"records"`
}

var shapeVectorPayloadLens = []int{0, 8, 20, 40, 70, 120, 200, 300, 400, 520, 768}

const shapeVectorFile = "testdata/oboard_shape_vectors.json"

func shapeVectorPSKs() []string {
	psks := []string{"TestPSK-gamma-3333", "OboardTestPSK-2026-FirewallProbe", "kiWmPJ6YYnviquK-dIQ2Sv8M", "bOrvSieA225alejnW7gGDw87", "123456789012"}
	for i := range 27 {
		sum := sha256.Sum256(fmt.Appendf(nil, "oboard-snell-v6-shape-vector-%d", i))
		psks = append(psks, base64.RawURLEncoding.EncodeToString(sum[:]))
	}
	return psks
}

func firstRecordPayloadCap(p *Profile) int {
	return max(1, min(p.chunkPayloadLimit(0, p.chunkInitial), p.firstRecordCap, maxPayload))
}

func computeShapeVector(psk string) shapeVector {
	p := NewProfile([]byte(psk))
	limit := firstRecordPayloadCap(p)
	v := shapeVector{PSK: psk, Generator: p.generator, PadMax: p.padMax, FirstRecordCap: limit}
	for _, requested := range shapeVectorPayloadLens {
		payloadLen := min(requested, limit)
		prefixLen := p.recordPrefixLen(0)
		saltPrefixLen := p.saltBlockLen - saltLen
		paddingLen := p.paddingLen(0, payloadLen, prefixLen, saltPrefixLen, p.saltBlockLen)
		block := make([]byte, p.saltBlockLen)
		p.fillPadding(0xffffffff, block)
		perm := shufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), len(block))
		salt := make([]bool, len(block))
		for i := range saltLen {
			salt[perm[i]] = true
		}
		ones := 0
		for i, b := range block {
			if !salt[i] {
				ones += bits.OnesCount8(b)
			}
		}
		fixed := make([]byte, prefixLen+paddingLen)
		p.fillPadding(0, fixed[:prefixLen])
		p.fillPadding(0, fixed[prefixLen:])
		for _, b := range fixed {
			ones += bits.OnesCount8(b)
		}
		payloadCipherLen := 0
		if payloadLen > 0 {
			payloadCipherLen = payloadLen + snell.AEADTagLen
		}
		v.Records = append(v.Records, shapeVectorRecord{
			PayloadLen: payloadLen,
			TotalLen:   p.saltBlockLen + prefixLen + snell.HeaderCipherLen + paddingLen + payloadCipherLen,
			FixedOnes:  ones,
			RandomLen:  saltLen + snell.HeaderCipherLen + payloadCipherLen,
		})
	}
	return v
}

func TestOBoardShapeVectors(t *testing.T) {
	var got []shapeVector
	for _, psk := range shapeVectorPSKs() {
		got = append(got, computeShapeVector(psk))
	}
	encoded := []byte("[\n")
	for i, vector := range got {
		line, err := json.Marshal(vector)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, line...)
		if i < len(got)-1 {
			encoded = append(encoded, ',')
		}
		encoded = append(encoded, '\n')
	}
	encoded = append(encoded, "]\n"...)
	if os.Getenv("OBOARD_WRITE_SHAPE_VECTORS") == "1" {
		if err := os.WriteFile(shapeVectorFile, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(shapeVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, encoded) {
		t.Fatal("snell v6 profile derivation changed; regenerate the vectors and update the OBoard Controller copy")
	}
}

// The vector layout must describe what the encoder really writes.
func TestOBoardShapeVectorsMatchEncoder(t *testing.T) {
	for _, psk := range shapeVectorPSKs()[:16] {
		v := computeShapeVector(psk)
		p := NewProfile([]byte(psk))
		for _, record := range v.Records {
			var out bytes.Buffer
			payload := make([]byte, record.PayloadLen)
			rand.Read(payload)
			if _, err := writeFirstRecord(&out, ModeDefault, []byte(psk), p, payload); err != nil {
				t.Fatal(err)
			}
			if out.Len() != record.TotalLen {
				t.Fatalf("%s payload %d: wrote %d bytes, vector says %d", psk, record.PayloadLen, out.Len(), record.TotalLen)
			}
			ones := 0
			for _, b := range out.Bytes() {
				ones += bits.OnesCount8(b)
			}
			// Random bytes contribute Binomial(8n, 1/2) ones; allow eight standard deviations.
			deviation := float64(ones - record.FixedOnes - 4*record.RandomLen)
			limit := 8 * 0.5 * math.Sqrt(float64(8*record.RandomLen))
			if deviation > limit || deviation < -limit {
				t.Fatalf("%s payload %d: ones %d deviate from fixed %d + random %d", psk, record.PayloadLen, ones, record.FixedOnes, record.RandomLen)
			}
		}
	}
}
