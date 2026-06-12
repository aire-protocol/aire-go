package aire

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"
)

//go:embed testdata/vectors-v0.3.json
var v03VectorsJSON []byte

type v03Vector struct {
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
	Decoded json.RawMessage `json:"decoded"`
}

type v03File struct {
	Version string      `json:"version"`
	Vectors []v03Vector `json:"vectors"`
}

func loadV03(t *testing.T) v03File {
	t.Helper()
	var f v03File
	if err := json.Unmarshal(v03VectorsJSON, &f); err != nil {
		t.Fatalf("unmarshal v0.3 vectors: %v", err)
	}
	return f
}

func TestCancel_RoundTrip(t *testing.T) {
	cases := []Cancel{
		{Reason: ReasonUserCancelled, Detail: ""},
		{Reason: ReasonUpstreamCancelled, Detail: "parent: ABORT"},
		{Reason: ReasonBudgetExceeded, Detail: "tokens=0"},
		{Reason: ReasonInternal, Detail: "panic: nil pointer dereference"},
	}
	for _, c := range cases {
		encoded := c.Encode()
		got, err := DecodeCancel(encoded)
		if err != nil {
			t.Fatalf("decode %+v: %v", c, err)
		}
		if got != c {
			t.Errorf("roundtrip: got %+v, want %+v", got, c)
		}
	}
}

func TestCancel_DecodeEmptyPayloadIsV01Compat(t *testing.T) {
	// §7.2.1: an empty payload is equivalent to USER_CANCELLED, no detail.
	got, err := DecodeCancel(nil)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	want := Cancel{Reason: ReasonUserCancelled, Detail: ""}
	if got != want {
		t.Errorf("empty payload decoded to %+v, want %+v", got, want)
	}
}

func TestCancel_ConformanceVectors(t *testing.T) {
	want := map[string]Cancel{
		"cancel-user-no-detail":       {Reason: ReasonUserCancelled, Detail: ""},
		"cancel-upstream-with-detail": {Reason: ReasonUpstreamCancelled, Detail: "parent: ABORT"},
	}
	for _, v := range loadV03(t).Vectors {
		if v.Frame.TypeName != "CANCEL" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			payload, _ := hex.DecodeString(v.Frame.PayloadHex)
			got, err := DecodeCancel(payload)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != want[v.ID] {
				t.Errorf("decoded %+v, want %+v", got, want[v.ID])
			}

			encoded := got.Encode()
			if !bytes.Equal(encoded, payload) {
				t.Errorf("encode mismatch:\n  want: %x\n  got:  %x", payload, encoded)
			}

			// Full frame round-trip.
			frame := Frame{Type: FrameType(v.Frame.Type), Flags: v.Frame.Flags, OpID: v.Frame.OpID, Payload: encoded}
			frameBytes := frame.Encode()
			wantFrame, _ := hex.DecodeString(v.EncodedHex)
			if !bytes.Equal(frameBytes, wantFrame) {
				t.Errorf("frame encode mismatch:\n  want: %x\n  got:  %x", wantFrame, frameBytes)
			}
		})
	}
}

func TestOperationErrorCodes(t *testing.T) {
	want := map[string]uint64{
		"CANCELLED":         0x0A,
		"BUDGET_EXCEEDED":   0x0B,
		"DEADLINE_EXCEEDED": 0x0C,
		"DELEGATE_FAILED":   0x0D,
	}
	got := map[string]uint64{
		"CANCELLED":         ErrCodeCancelled,
		"BUDGET_EXCEEDED":   ErrCodeBudgetExceeded,
		"DEADLINE_EXCEEDED": ErrCodeDeadlineExceeded,
		"DELEGATE_FAILED":   ErrCodeDelegateFailed,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = 0x%02x, want 0x%02x", k, got[k], v)
		}
	}
}
