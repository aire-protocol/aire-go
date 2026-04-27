package aire

import (
	"bytes"
	"errors"
	"testing"
)

// Test vectors are reproduced verbatim from SPEC.md §2.6.
// Implementations MUST round-trip these byte-for-byte.

func TestVector1_EmptyHello(t *testing.T) {
	want := []byte{0x01, 0x00, 0x00, 0x00}
	frame := Frame{Type: FrameHello}

	got := frame.Encode()
	if !bytes.Equal(got, want) {
		t.Errorf("encode mismatch:\n  want: %x\n  got:  %x", want, got)
	}

	decoded, n, err := Decode(want)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if n != len(want) {
		t.Errorf("decode consumed %d, want %d", n, len(want))
	}
	if decoded.Type != FrameHello || decoded.Flags != 0 || decoded.OpID != 0 || len(decoded.Payload) != 0 {
		t.Errorf("decode mismatch: %+v", decoded)
	}
}

func TestVector2_InvokeWithShortPayload(t *testing.T) {
	want := []byte{0x03, 0x00, 0x2A, 0x02, 0x68, 0x69}
	frame := Frame{
		Type:    FrameInvoke,
		OpID:    42,
		Payload: []byte("hi"),
	}

	got := frame.Encode()
	if !bytes.Equal(got, want) {
		t.Errorf("encode mismatch:\n  want: %x\n  got:  %x", want, got)
	}

	decoded, n, err := Decode(want)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if n != len(want) {
		t.Errorf("decode consumed %d, want %d", n, len(want))
	}
	if decoded.Type != FrameInvoke || decoded.OpID != 42 || string(decoded.Payload) != "hi" {
		t.Errorf("decode mismatch: %+v", decoded)
	}
}

func TestVector3_StreamLargeOpID(t *testing.T) {
	header := []byte{0x04, 0x00, 0x80, 0x00, 0x40, 0x00, 0x40, 0x64}
	payload := bytes.Repeat([]byte{0xAB}, 100)
	want := append(append([]byte{}, header...), payload...)

	frame := Frame{
		Type:    FrameStream,
		OpID:    16384,
		Payload: payload,
	}

	got := frame.Encode()
	if !bytes.Equal(got, want) {
		t.Errorf("encode mismatch (lengths got=%d want=%d)", len(got), len(want))
	}

	decoded, n, err := Decode(want)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if n != len(want) {
		t.Errorf("decode consumed %d, want %d", n, len(want))
	}
	if decoded.Type != FrameStream || decoded.OpID != 16384 || !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("decode mismatch")
	}
}

func TestVector4_TwoHellosConcatenated(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}

	first, n1, err := Decode(data)
	if err != nil {
		t.Fatalf("first decode error: %v", err)
	}
	if n1 != 4 {
		t.Errorf("first decode consumed %d, want 4", n1)
	}
	if first.Type != FrameHello {
		t.Errorf("first frame type = %v, want HELLO", first.Type)
	}

	second, n2, err := Decode(data[n1:])
	if err != nil {
		t.Fatalf("second decode error: %v", err)
	}
	if n2 != 4 {
		t.Errorf("second decode consumed %d, want 4", n2)
	}
	if second.Type != FrameHello {
		t.Errorf("second frame type = %v, want HELLO", second.Type)
	}
}

func TestVarint_RoundTrip(t *testing.T) {
	cases := []struct {
		value uint64
		size  int
	}{
		{0, 1},
		{1, 1},
		{63, 1},        // max 1-byte
		{64, 2},        // min 2-byte
		{16383, 2},     // max 2-byte
		{16384, 4},     // min 4-byte
		{1<<30 - 1, 4}, // max 4-byte
		{1 << 30, 8},   // min 8-byte
		{MaxVarint, 8}, // max representable
	}

	for _, c := range cases {
		buf := AppendVarint(nil, c.value)
		if len(buf) != c.size {
			t.Errorf("varint(%d): encoded size = %d, want %d", c.value, len(buf), c.size)
		}
		v, n, err := ReadVarint(buf)
		if err != nil {
			t.Fatalf("varint(%d): read error: %v", c.value, err)
		}
		if n != c.size {
			t.Errorf("varint(%d): read consumed %d, want %d", c.value, n, c.size)
		}
		if v != c.value {
			t.Errorf("varint(%d): round-trip got %d", c.value, v)
		}
	}
}

func TestVarint_PanicsOnTooLarge(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on AppendVarint(>MaxVarint)")
		}
	}()
	AppendVarint(nil, MaxVarint+1)
}

func TestDecode_ShortBuffer(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x01},                               // type only
		{0x01, 0x00},                         // missing opid
		{0x01, 0x00, 0x00},                   // missing payloadlen
		{0x03, 0x00, 0x2A, 0x05, 0x68, 0x69}, // payload says 5, only 2 present
	}
	for i, data := range cases {
		_, _, err := Decode(data)
		if !errors.Is(err, ErrShortBuffer) {
			t.Errorf("case %d (%x): got err=%v, want ErrShortBuffer", i, data, err)
		}
	}
}

func TestDecode_FrameTooLarge(t *testing.T) {
	// Frame claiming PayloadLen = 2 MiB (>1 MiB cap).
	// 4-byte varint for 0x200000: top bits 10, value 0x00200000 → 0x80 0x20 0x00 0x00
	data := []byte{
		0x03, 0x00, // INVOKE, flags=0
		0x01,                   // OpID=1
		0x80, 0x20, 0x00, 0x00, // PayloadLen=2097152
	}
	_, _, err := Decode(data)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("got err=%v, want ErrFrameTooLarge", err)
	}
}
