package aire

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"
)

//go:embed testdata/vectors-v0.1.json
var conformanceVectorsJSON []byte

type conformanceVector struct {
	ID          string `json:"id"`
	Section     string `json:"section"`
	Description string `json:"description"`
	EncodedHex  string `json:"encoded_hex"`
	Frame       struct {
		Type       uint8  `json:"type"`
		TypeName   string `json:"type_name"`
		Flags      uint8  `json:"flags"`
		OpID       uint64 `json:"op_id"`
		PayloadHex string `json:"payload_hex"`
	} `json:"frame"`
}

type conformanceVectorFile struct {
	Version string              `json:"version"`
	Spec    string              `json:"spec"`
	Vectors []conformanceVector `json:"vectors"`
}

// TestConformance_VectorsV01 verifies every vector in the spec's
// vectors/v0.1.json round-trips byte-for-byte through this implementation.
//
// The vendored copy at testdata/vectors-v0.1.json must stay in sync with
// the canonical file in github.com/aire-protocol/aire-spec.
func TestConformance_VectorsV01(t *testing.T) {
	var file conformanceVectorFile
	if err := json.Unmarshal(conformanceVectorsJSON, &file); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	if file.Version != "v0.1" {
		t.Errorf("vectors version = %q, want v0.1", file.Version)
	}
	if len(file.Vectors) == 0 {
		t.Fatalf("no vectors loaded")
	}

	for _, v := range file.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			wantBytes, err := hex.DecodeString(v.EncodedHex)
			if err != nil {
				t.Fatalf("decode encoded_hex: %v", err)
			}
			payloadBytes, err := hex.DecodeString(v.Frame.PayloadHex)
			if err != nil {
				t.Fatalf("decode payload_hex: %v", err)
			}

			// Decode side: encoded_hex → Frame, must match declared fields.
			gotFrame, n, err := Decode(wantBytes)
			if err != nil {
				t.Fatalf("Decode(%q): %v", v.EncodedHex, err)
			}
			if n != len(wantBytes) {
				t.Errorf("Decode consumed %d, want %d", n, len(wantBytes))
			}
			if uint8(gotFrame.Type) != v.Frame.Type {
				t.Errorf("decoded Type = %d, want %d", gotFrame.Type, v.Frame.Type)
			}
			if gotFrame.Flags != v.Frame.Flags {
				t.Errorf("decoded Flags = %d, want %d", gotFrame.Flags, v.Frame.Flags)
			}
			if gotFrame.OpID != v.Frame.OpID {
				t.Errorf("decoded OpID = %d, want %d", gotFrame.OpID, v.Frame.OpID)
			}
			if !bytes.Equal(gotFrame.Payload, payloadBytes) && !(len(gotFrame.Payload) == 0 && len(payloadBytes) == 0) {
				t.Errorf("decoded Payload mismatch:\n  want: %x\n  got:  %x", payloadBytes, gotFrame.Payload)
			}

			// Encode side: declared Frame → bytes, must match encoded_hex exactly.
			built := Frame{
				Type:    FrameType(v.Frame.Type),
				Flags:   v.Frame.Flags,
				OpID:    v.Frame.OpID,
				Payload: payloadBytes,
			}
			gotBytes := built.Encode()
			if !bytes.Equal(gotBytes, wantBytes) {
				t.Errorf("Encode mismatch:\n  want: %s\n  got:  %s", v.EncodedHex, hex.EncodeToString(gotBytes))
			}
		})
	}
}
