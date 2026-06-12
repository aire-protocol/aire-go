// Package aire is the reference Go implementation of the AIRE protocol.
//
// AIRE (Agent Interchange Runtime Envelope) is a QUIC-native application-layer
// protocol for agent-to-agent communication. See the spec at
// https://github.com/aire-protocol/aire-spec.
package aire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// FrameType identifies an AIRE frame variant on the wire (spec §3).
type FrameType uint8

const (
	FrameHello    FrameType = 0x01
	FrameInvoke   FrameType = 0x03
	FrameStream   FrameType = 0x04
	FrameCancel   FrameType = 0x05
	FrameBudget   FrameType = 0x06
	FrameDelegate FrameType = 0x07
	FrameError    FrameType = 0x08
	FrameGoodbye  FrameType = 0x09
	// Frame code 0x02 is reserved per spec §3 / §4.5.5. v0.2 receivers
	// MUST treat an incoming 0x02 frame as a protocol violation.
)

// MaxVarint is the largest value representable in a QUIC-style varint
// (2^62 − 1), per spec §2.2.
const MaxVarint uint64 = (1 << 62) - 1

// MaxFrameSize is the default upper bound on Payload length for v0.1, per
// spec §2.5. Receivers MUST accept up to 2^16; this implementation defaults
// to the negotiable cap of 2^20 (1 MiB) to bound allocations on receive.
const MaxFrameSize uint64 = 1 << 20

// Frame is the on-wire envelope for every AIRE message (spec §2.1).
type Frame struct {
	Type    FrameType
	Flags   uint8
	OpID    uint64
	Payload []byte
}

// Errors returned by Decode and varint readers.
var (
	ErrShortBuffer   = errors.New("aire: short buffer")
	ErrFrameTooLarge = errors.New("aire: frame exceeds MaxFrameSize")
)

// Encode serializes f to its on-wire byte representation per spec §2.1.
func (f Frame) Encode() []byte {
	return f.AppendEncode(nil)
}

// AppendEncode appends the wire encoding of f to dst, returning the extended
// slice. Useful for callers building up a stream of frames.
func (f Frame) AppendEncode(dst []byte) []byte {
	dst = append(dst, byte(f.Type), f.Flags)
	dst = AppendVarint(dst, f.OpID)
	dst = AppendVarint(dst, uint64(len(f.Payload)))
	dst = append(dst, f.Payload...)
	return dst
}

// Decode parses a single frame from data. It returns the parsed frame and
// the number of bytes consumed; subsequent frames (if present) begin at
// data[n:]. Returns ErrShortBuffer if data is incomplete and ErrFrameTooLarge
// if the declared PayloadLen exceeds MaxFrameSize.
func Decode(data []byte) (Frame, int, error) {
	if len(data) < 2 {
		return Frame{}, 0, ErrShortBuffer
	}
	pos := 0
	f := Frame{
		Type:  FrameType(data[pos]),
		Flags: data[pos+1],
	}
	pos += 2

	opid, n, err := ReadVarint(data[pos:])
	if err != nil {
		return Frame{}, 0, err
	}
	f.OpID = opid
	pos += n

	plen, n, err := ReadVarint(data[pos:])
	if err != nil {
		return Frame{}, 0, err
	}
	pos += n

	if plen > MaxFrameSize {
		return Frame{}, 0, ErrFrameTooLarge
	}
	if uint64(len(data)-pos) < plen {
		return Frame{}, 0, ErrShortBuffer
	}
	if plen > 0 {
		f.Payload = make([]byte, plen)
		copy(f.Payload, data[pos:pos+int(plen)])
	}
	pos += int(plen)

	return f, pos, nil
}

// AppendVarint appends a QUIC-style variable-length integer encoding of v
// to dst (spec §2.2). Panics if v exceeds MaxVarint.
func AppendVarint(dst []byte, v uint64) []byte {
	if v > MaxVarint {
		panic(fmt.Sprintf("aire: AppendVarint: value %d exceeds MaxVarint (2^62-1)", v))
	}
	switch {
	case v < 1<<6:
		return append(dst, byte(v))
	case v < 1<<14:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v))
		b[0] |= 0x80
		return append(dst, b[:]...)
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		b[0] |= 0xC0
		return append(dst, b[:]...)
	}
}

// ReadVarint reads a QUIC-style variable-length integer from data, returning
// the decoded value and number of bytes consumed. Returns ErrShortBuffer if
// data is too short for the encoded length.
func ReadVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrShortBuffer
	}
	switch data[0] >> 6 {
	case 0:
		return uint64(data[0] & 0x3F), 1, nil
	case 1:
		if len(data) < 2 {
			return 0, 0, ErrShortBuffer
		}
		return uint64(data[0]&0x3F)<<8 | uint64(data[1]), 2, nil
	case 2:
		if len(data) < 4 {
			return 0, 0, ErrShortBuffer
		}
		return uint64(data[0]&0x3F)<<24 |
			uint64(data[1])<<16 |
			uint64(data[2])<<8 |
			uint64(data[3]), 4, nil
	default: // case 3
		if len(data) < 8 {
			return 0, 0, ErrShortBuffer
		}
		return uint64(data[0]&0x3F)<<56 |
			uint64(data[1])<<48 |
			uint64(data[2])<<40 |
			uint64(data[3])<<32 |
			uint64(data[4])<<24 |
			uint64(data[5])<<16 |
			uint64(data[6])<<8 |
			uint64(data[7]), 8, nil
	}
}
