package aire

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Signature algorithm identifiers per spec §5.4.1.
const (
	SigAlgEd25519 uint8 = 0x01
)

// DomainSeparator is the §5.4.4 prefix bound into every signed message.
// The final byte (frame type) is appended at signing time.
const DomainSeparator = "AIRE-SIG-v1\x00"

// ed25519PubMulticodec is the multicodec varint prefix for an Ed25519
// public key (codec 0xED, encoded as the varint bytes 0xED 0x01).
var ed25519PubMulticodec = []byte{0xED, 0x01}

// ReplayWindow is the §5.4.6 timestamp acceptance window.
const ReplayWindow = 300 * time.Second

// §5.4.7 error codes (extend the §4.7 registry).
const (
	ErrCodeBadSignature    uint64 = 0x05
	ErrCodeStaleTimestamp  uint64 = 0x06
	ErrCodeReplayedNonce   uint64 = 0x07
	ErrCodeUnresolvableDID uint64 = 0x08
	ErrCodeKeyMismatch     uint64 = 0x09
)

// Identity error sentinels.
var (
	ErrBadSignature    = errors.New("aire: bad signature")
	ErrStaleTimestamp  = errors.New("aire: stale timestamp")
	ErrReplayedNonce   = errors.New("aire: replayed nonce")
	ErrUnresolvableDID = errors.New("aire: unresolvable DID")
	ErrKeyMismatch     = errors.New("aire: key mismatch")
)

// SignatureBlock is the §5.4.3 signature trailer carried in a signed frame's
// payload. The zero value is not usable.
type SignatureBlock struct {
	Algorithm   uint8
	VMID        string
	Nonce       [16]byte
	TimestampMS int64
	Signature   []byte
}

// Encode serializes the block to its wire form (§5.4.3).
func (sb SignatureBlock) Encode() []byte {
	out := sb.metaBytes()
	out = AppendVarint(out, uint64(len(sb.Signature)))
	out = append(out, sb.Signature...)
	return out
}

// metaBytes is the slice of the block that is covered by the signature —
// AlgID || encoded(VMID) || Nonce || Timestamp — excluding SigLen and
// SigBytes (§5.4.4).
func (sb SignatureBlock) metaBytes() []byte {
	out := []byte{sb.Algorithm}
	out = appendString(out, sb.VMID)
	out = append(out, sb.Nonce[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(sb.TimestampMS))
	return append(out, ts[:]...)
}

// DecodeSignatureBlock parses a signature block from data, returning the
// block and the number of bytes consumed.
func DecodeSignatureBlock(data []byte) (SignatureBlock, int, error) {
	if len(data) < 1 {
		return SignatureBlock{}, 0, ErrShortBuffer
	}
	pos := 0
	sb := SignatureBlock{Algorithm: data[pos]}
	pos++

	vmid, n, err := readString(data[pos:])
	if err != nil {
		return SignatureBlock{}, 0, fmt.Errorf("sig block VMID: %w", err)
	}
	sb.VMID = vmid
	pos += n

	if len(data)-pos < 16 {
		return SignatureBlock{}, 0, fmt.Errorf("sig block Nonce: %w", ErrShortBuffer)
	}
	copy(sb.Nonce[:], data[pos:pos+16])
	pos += 16

	if len(data)-pos < 8 {
		return SignatureBlock{}, 0, fmt.Errorf("sig block Timestamp: %w", ErrShortBuffer)
	}
	sb.TimestampMS = int64(binary.BigEndian.Uint64(data[pos : pos+8]))
	pos += 8

	sigLen, n, err := ReadVarint(data[pos:])
	if err != nil {
		return SignatureBlock{}, 0, fmt.Errorf("sig block SigLen: %w", err)
	}
	pos += n
	if uint64(len(data)-pos) < sigLen {
		return SignatureBlock{}, 0, fmt.Errorf("sig block SigBytes: %w", ErrShortBuffer)
	}
	sb.Signature = make([]byte, sigLen)
	copy(sb.Signature, data[pos:pos+int(sigLen)])
	pos += int(sigLen)
	return sb, pos, nil
}

// signedMessageBytes builds the byte sequence over which the signature for a
// frame of type ft is computed, per §5.4.4.
func signedMessageBytes(ft FrameType, inner []byte, block SignatureBlock) []byte {
	sep := append([]byte(DomainSeparator), byte(ft))
	out := make([]byte, 0, len(sep)+len(inner)+1+len(block.VMID)+16+8)
	out = append(out, sep...)
	out = append(out, inner...)
	out = append(out, block.metaBytes()...)
	return out
}

// Signer represents an identity that can sign AIRE frames on behalf of a DID.
type Signer interface {
	DID() string
	VMID() string
	Sign(message []byte) []byte
}

// Ed25519DIDKeySigner is a Signer backed by a did:key Ed25519 keypair.
type Ed25519DIDKeySigner struct {
	priv ed25519.PrivateKey
	did  string
	vmid string
}

// NewEd25519DIDKeySigner wraps priv in a Signer whose DID is the canonical
// did:key form of the corresponding public key.
func NewEd25519DIDKeySigner(priv ed25519.PrivateKey) *Ed25519DIDKeySigner {
	pub := priv.Public().(ed25519.PublicKey)
	did := MakeDIDKey(pub)
	return &Ed25519DIDKeySigner{
		priv: priv,
		did:  did,
		vmid: DIDKeyVMID(did),
	}
}

func (s *Ed25519DIDKeySigner) DID() string            { return s.did }
func (s *Ed25519DIDKeySigner) VMID() string           { return s.vmid }
func (s *Ed25519DIDKeySigner) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }
func (s *Ed25519DIDKeySigner) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// VerifyEd25519 is the raw Ed25519 signature check (RFC 8032).
func VerifyEd25519(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

// Verifier resolves DIDs to verification keys and enforces §5.4.6 replay
// protection. The zero value is not usable; build with NewVerifier.
type Verifier struct {
	// Resolver fetches did:web Documents. If nil, did:web verification fails.
	Resolver *Resolver
	// Clock returns the receiver's current time; defaults to time.Now.
	Clock func() time.Time
	// Window is the timestamp acceptance window per §5.4.6.
	Window time.Duration

	mu    sync.Mutex
	cache map[string]map[[16]byte]int64 // signing-DID → nonce → timestamp_ms
}

// NewVerifier returns a Verifier with sensible defaults.
func NewVerifier() *Verifier {
	return &Verifier{
		Clock:  time.Now,
		Window: ReplayWindow,
		cache:  make(map[string]map[[16]byte]int64),
	}
}

// Verify checks the signature, timestamp window, and replay cache for a
// parsed signature block against the bytes the signature covers.
//
// On a successful verification, Verify records the (DID, Nonce) pair so a
// later replay returns ErrReplayedNonce.
func (v *Verifier) Verify(ctx context.Context, block SignatureBlock, signedMessage []byte) error {
	if block.Algorithm != SigAlgEd25519 {
		return fmt.Errorf("%w: unknown algorithm 0x%02x", ErrBadSignature, block.Algorithm)
	}

	now := v.Clock()
	sigTime := time.UnixMilli(block.TimestampMS)
	skew := now.Sub(sigTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > v.Window {
		return fmt.Errorf("%w: skew=%s", ErrStaleTimestamp, skew)
	}

	did, _, _ := strings.Cut(block.VMID, "#")
	if did == "" {
		return fmt.Errorf("%w: VMID missing DID portion: %q", ErrUnresolvableDID, block.VMID)
	}

	v.mu.Lock()
	nonces, ok := v.cache[did]
	if !ok {
		nonces = make(map[[16]byte]int64)
		v.cache[did] = nonces
	}
	if _, seen := nonces[block.Nonce]; seen {
		v.mu.Unlock()
		return fmt.Errorf("%w: did=%s", ErrReplayedNonce, did)
	}
	cutoff := now.Add(-v.Window).UnixMilli()
	for n, ts := range nonces {
		if ts < cutoff {
			delete(nonces, n)
		}
	}
	nonces[block.Nonce] = block.TimestampMS
	v.mu.Unlock()

	pub, err := v.ResolveKey(ctx, block.VMID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnresolvableDID, err)
	}
	if !ed25519.Verify(pub, signedMessage, block.Signature) {
		return fmt.Errorf("%w: did=%s", ErrBadSignature, did)
	}
	return nil
}

// ResolveKey returns the Ed25519 public key referenced by a VMID. did:key
// resolution is purely algorithmic; did:web fetches the DID Document via
// the Resolver and locates the matching verificationMethod entry.
func (v *Verifier) ResolveKey(ctx context.Context, vmid string) (ed25519.PublicKey, error) {
	did, fragment, _ := strings.Cut(vmid, "#")
	switch {
	case strings.HasPrefix(did, "did:key:"):
		return ParseDIDKey(did)
	case strings.HasPrefix(did, "did:web:"):
		if fragment == "" {
			return nil, fmt.Errorf("did:web VMID missing fragment: %q", vmid)
		}
		r := v.Resolver
		if r == nil {
			return nil, fmt.Errorf("did:web resolution requires a Resolver")
		}
		docURL, err := didWebToURL(did)
		if err != nil {
			return nil, err
		}
		doc, err := r.fetchDIDDocument(ctx, docURL)
		if err != nil {
			return nil, err
		}
		want := did + "#" + fragment
		for _, vm := range doc.VerificationMethod {
			if vm.ID == want && vm.Type == "Ed25519VerificationKey2020" {
				return decodeMultibaseEd25519(vm.PublicKeyMultibase)
			}
		}
		return nil, fmt.Errorf("verification method %s not found in document", want)
	default:
		return nil, fmt.Errorf("unsupported DID method: %q", did)
	}
}

// Multibase z-base58btc encoding of an Ed25519 public key per the W3C
// Multikey conventions: "z" || base58btc(0xED 0x01 || pub).
func encodeMultibaseEd25519(pub ed25519.PublicKey) string {
	raw := make([]byte, 0, len(ed25519PubMulticodec)+len(pub))
	raw = append(raw, ed25519PubMulticodec...)
	raw = append(raw, pub...)
	return "z" + base58btcEncode(raw)
}

func decodeMultibaseEd25519(s string) (ed25519.PublicKey, error) {
	if len(s) < 2 || s[0] != 'z' {
		return nil, fmt.Errorf("multibase must start with 'z': %q", s)
	}
	raw, err := base58btcDecode(s[1:])
	if err != nil {
		return nil, err
	}
	if len(raw) < 2 || raw[0] != 0xED || raw[1] != 0x01 {
		return nil, fmt.Errorf("not an Ed25519 multikey")
	}
	if len(raw)-2 != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 pubkey length %d, want %d", len(raw)-2, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw[2:]), nil
}

const didKeyPrefix = "did:key:"

// MakeDIDKey returns the canonical did:key form of an Ed25519 public key.
func MakeDIDKey(pub ed25519.PublicKey) string {
	return didKeyPrefix + encodeMultibaseEd25519(pub)
}

// ParseDIDKey extracts the Ed25519 public key from a did:key identifier.
func ParseDIDKey(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, didKeyPrefix) {
		return nil, fmt.Errorf("not a did:key: %q", did)
	}
	return decodeMultibaseEd25519(did[len(didKeyPrefix):])
}

// DIDKeyVMID returns the canonical verification-method ID for a did:key DID
// (`<did>#<multibase-id>`, where the fragment equals the DID's identifier).
func DIDKeyVMID(did string) string {
	return did + "#" + did[len(didKeyPrefix):]
}

// base58btc using the Bitcoin alphabet — used to encode Ed25519 multikey
// values per the multibase 'z' prefix.
const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58btcEncode(data []byte) string {
	n := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	rem := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.QuoRem(n, base, rem)
		out = append(out, b58Alphabet[rem.Int64()])
	}
	for _, b := range data {
		if b == 0 {
			out = append(out, '1')
		} else {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58btcDecode(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(b58Alphabet, s[i])
		if idx < 0 {
			return nil, fmt.Errorf("base58btc: invalid character %q", s[i])
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	out := n.Bytes()
	lead := 0
	for lead < len(s) && s[lead] == '1' {
		lead++
	}
	if lead > 0 {
		out = append(make([]byte, lead), out...)
	}
	return out, nil
}
