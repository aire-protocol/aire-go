package aire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

//go:embed testdata/vectors-v0.2.json
var v02VectorsJSON []byte

type v02Vector struct {
	ID     string `json:"id"`
	Inputs struct {
		SeedHex      string `json:"seed_hex"`
		PublicKeyHex string `json:"public_key_hex"`
		DID          string `json:"did"`
		VMID         string `json:"verification_method_id"`
		NonceHex     string `json:"nonce_hex"`
		TimestampMS  int64  `json:"timestamp_ms"`
	} `json:"inputs"`
	InnerPayloadHex string `json:"inner_payload_hex"`
	SignatureBlock  struct {
		AlgID        uint8  `json:"alg_id"`
		VMID         string `json:"vmid"`
		NonceHex     string `json:"nonce_hex"`
		TimestampMS  int64  `json:"timestamp_ms"`
		SignatureHex string `json:"signature_hex"`
	} `json:"signature_block"`
	DomainSeparatorHex string `json:"domain_separator_hex"`
	SignedMessageHex   string `json:"signed_message_hex"`
	EncodedHex         string `json:"encoded_hex"`
}

type v02File struct {
	Version string      `json:"version"`
	Vectors []v02Vector `json:"vectors"`
}

func loadV02(t *testing.T) v02File {
	t.Helper()
	var f v02File
	if err := json.Unmarshal(v02VectorsJSON, &f); err != nil {
		t.Fatalf("unmarshal v0.2 vectors: %v", err)
	}
	return f
}

func TestMultibaseEd25519_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mb := encodeMultibaseEd25519(pub)
	if len(mb) == 0 || mb[0] != 'z' {
		t.Fatalf("multibase must start with 'z', got %q", mb)
	}
	got, err := decodeMultibaseEd25519(mb)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestDIDKey_MatchesVector(t *testing.T) {
	v := loadV02(t).Vectors[0]
	pub, err := hex.DecodeString(v.Inputs.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	got := MakeDIDKey(ed25519.PublicKey(pub))
	if got != v.Inputs.DID {
		t.Errorf("MakeDIDKey:\n  want %s\n  got  %s", v.Inputs.DID, got)
	}
	parsed, err := ParseDIDKey(v.Inputs.DID)
	if err != nil {
		t.Fatalf("ParseDIDKey: %v", err)
	}
	if !bytes.Equal(parsed, pub) {
		t.Errorf("ParseDIDKey returned wrong key")
	}
	if vmid := DIDKeyVMID(v.Inputs.DID); vmid != v.Inputs.VMID {
		t.Errorf("DIDKeyVMID:\n  want %s\n  got  %s", v.Inputs.VMID, vmid)
	}
}

func TestSignatureBlock_RoundTrip(t *testing.T) {
	sb := SignatureBlock{
		Algorithm:   SigAlgEd25519,
		VMID:        "did:key:z6Mkfoo#z6Mkfoo",
		Nonce:       [16]byte{0xAA, 0xBB},
		TimestampMS: 1781568000000,
		Signature:   bytes.Repeat([]byte{0x42}, 64),
	}
	encoded := sb.Encode()
	got, n, err := DecodeSignatureBlock(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(encoded) {
		t.Errorf("DecodeSignatureBlock consumed %d, want %d", n, len(encoded))
	}
	if got.Algorithm != sb.Algorithm || got.VMID != sb.VMID || got.Nonce != sb.Nonce || got.TimestampMS != sb.TimestampMS || !bytes.Equal(got.Signature, sb.Signature) {
		t.Errorf("roundtrip mismatch:\n  want %+v\n  got  %+v", sb, got)
	}
}

func TestConformance_VectorsV02_VerifyAndRoundTrip(t *testing.T) {
	for _, v := range loadV02(t).Vectors {
		t.Run(v.ID, func(t *testing.T) {
			frameBytes, err := hex.DecodeString(v.EncodedHex)
			if err != nil {
				t.Fatal(err)
			}

			f, n, err := Decode(frameBytes)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if n != len(frameBytes) {
				t.Errorf("Decode consumed %d, want %d", n, len(frameBytes))
			}
			if f.Type != FrameHello {
				t.Fatalf("frame type %d, want HELLO", f.Type)
			}

			ver, nodeID, caps, sigBytes, err := decodeHelloPayloadV02(f.Payload)
			if err != nil {
				t.Fatalf("decodeHelloPayloadV02: %v", err)
			}
			if ver.Major != 0 || ver.Minor != 2 {
				t.Errorf("version %v, want 0.2", ver)
			}
			if nodeID != v.Inputs.DID {
				t.Errorf("NodeID = %q, want %q", nodeID, v.Inputs.DID)
			}
			if len(caps) != 1 {
				t.Fatalf("caps len = %d, want 1", len(caps))
			}

			block, _, err := DecodeSignatureBlock(sigBytes)
			if err != nil {
				t.Fatalf("DecodeSignatureBlock: %v", err)
			}

			wantSig, _ := hex.DecodeString(v.SignatureBlock.SignatureHex)
			if !bytes.Equal(block.Signature, wantSig) {
				t.Errorf("sig bytes mismatch:\n  want %x\n  got  %x", wantSig, block.Signature)
			}

			pub, err := ed25519.PublicKey(mustHex(t, v.Inputs.PublicKeyHex)), error(nil)
			_ = err
			if !VerifyEd25519(pub, mustHex(t, v.SignedMessageHex), block.Signature) {
				t.Error("signature failed to verify against signed_message bytes")
			}

			inner := mustHex(t, v.InnerPayloadHex)
			sep := mustHex(t, v.DomainSeparatorHex)
			meta := block.metaBytes()
			recomputed := append(append(append([]byte{}, sep...), inner...), meta...)
			if !bytes.Equal(recomputed, mustHex(t, v.SignedMessageHex)) {
				t.Errorf("signed-message reconstruction mismatch")
			}
		})
	}
}

func TestSignAndVerify_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519DIDKeySigner(priv)
	if signer.DID() != MakeDIDKey(pub) {
		t.Errorf("signer DID mismatch")
	}

	msg := []byte("hello AIRE")
	sig := signer.Sign(msg)
	if !VerifyEd25519(pub, msg, sig) {
		t.Error("self-signed message failed to verify")
	}

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 1
	if VerifyEd25519(pub, tampered, sig) {
		t.Error("tampered message verified")
	}
}

func TestVerifier_DIDKey_VerifiesAndCachesNonces(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519DIDKeySigner(priv)

	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	v := NewVerifier()
	v.Clock = func() time.Time { return now }

	nonce := [16]byte{1, 2, 3}
	signedMsg := []byte("payload")
	sig := signer.Sign(signedMsg)
	block := SignatureBlock{
		Algorithm:   SigAlgEd25519,
		VMID:        signer.VMID(),
		Nonce:       nonce,
		TimestampMS: now.UnixMilli(),
		Signature:   sig,
	}

	if err := v.Verify(context.Background(), block, signedMsg); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := v.Verify(context.Background(), block, signedMsg); !errors.Is(err, ErrReplayedNonce) {
		t.Errorf("second verify: got %v, want ErrReplayedNonce", err)
	}
}

func TestVerifier_StaleTimestamp(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519DIDKeySigner(priv)

	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	v := NewVerifier()
	v.Clock = func() time.Time { return now }

	signedMsg := []byte("payload")
	block := SignatureBlock{
		Algorithm:   SigAlgEd25519,
		VMID:        signer.VMID(),
		Nonce:       [16]byte{1, 2, 3},
		TimestampMS: now.Add(-10 * time.Minute).UnixMilli(), // outside 5-min window
		Signature:   signer.Sign(signedMsg),
	}
	if err := v.Verify(context.Background(), block, signedMsg); !errors.Is(err, ErrStaleTimestamp) {
		t.Errorf("got %v, want ErrStaleTimestamp", err)
	}
}

func TestVerifier_BadSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519DIDKeySigner(priv)

	v := NewVerifier()
	v.Clock = func() time.Time { return time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC) }

	signedMsg := []byte("payload")
	sig := signer.Sign(signedMsg)
	sig[0] ^= 1 // tamper
	block := SignatureBlock{
		Algorithm:   SigAlgEd25519,
		VMID:        signer.VMID(),
		Nonce:       [16]byte{9},
		TimestampMS: v.Clock().UnixMilli(),
		Signature:   sig,
	}
	if err := v.Verify(context.Background(), block, signedMsg); !errors.Is(err, ErrBadSignature) {
		t.Errorf("got %v, want ErrBadSignature", err)
	}
}

func TestNewErrorCodesExist(t *testing.T) {
	// §5.4.7 — sanity check the constants are wired up.
	codes := map[string]uint64{
		"BAD_SIGNATURE":    ErrCodeBadSignature,
		"STALE_TIMESTAMP":  ErrCodeStaleTimestamp,
		"REPLAYED_NONCE":   ErrCodeReplayedNonce,
		"UNRESOLVABLE_DID": ErrCodeUnresolvableDID,
		"KEY_MISMATCH":     ErrCodeKeyMismatch,
	}
	want := map[string]uint64{
		"BAD_SIGNATURE":    0x05,
		"STALE_TIMESTAMP":  0x06,
		"REPLAYED_NONCE":   0x07,
		"UNRESOLVABLE_DID": 0x08,
		"KEY_MISMATCH":     0x09,
	}
	for k, v := range want {
		if codes[k] != v {
			t.Errorf("code %s = 0x%02x, want 0x%02x", k, codes[k], v)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}
