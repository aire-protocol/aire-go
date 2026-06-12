package aire

import (
	"context"
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
)

// CurrentVersion is the AIRE protocol version this implementation speaks.
var CurrentVersion = Version{Major: 0, Minor: 1}

// Version is an AIRE protocol version (spec §11).
type Version struct {
	Major uint64
	Minor uint64
}

// String formats the version as "Major.Minor".
func (v Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// NodeConfig configures the local AIRE node for the §4 handshake.
type NodeConfig struct {
	NodeID       string
	Capabilities []Capability
}

// HandshakeState records the negotiated outcome of the §4 handshake.
type HandshakeState struct {
	PeerNodeID         string
	NegotiatedMinor    uint64       // major matches CurrentVersion.Major
	ActiveCapabilities []Capability // name-matched, minor = min(local, peer) per spec §4.5.4
}

// Handshake error codes from spec §4.6.
const (
	ErrCodeIncompatibleVersion       uint64 = 0x01
	ErrCodeMissingRequiredCapability uint64 = 0x02
	ErrCodeMalformedFrame            uint64 = 0x03
	ErrCodeProtocolViolation         uint64 = 0x04
)

// Handshake error sentinels. Wrapped errors retain context via fmt.Errorf %w.
var (
	ErrIncompatibleVersion       = errors.New("aire: incompatible protocol version")
	ErrMissingRequiredCapability = errors.New("aire: missing required capability")
	ErrMalformedHello            = errors.New("aire: malformed HELLO")
	ErrProtocolViolation         = errors.New("aire: protocol violation")
)

// encodeHelloPayload encodes a HELLO frame payload per spec §4.1.
func encodeHelloPayload(cfg NodeConfig) []byte {
	var buf []byte
	buf = AppendVarint(buf, CurrentVersion.Major)
	buf = AppendVarint(buf, CurrentVersion.Minor)
	buf = appendString(buf, cfg.NodeID)
	buf = AppendVarint(buf, uint64(len(cfg.Capabilities)))
	for _, c := range cfg.Capabilities {
		buf = appendString(buf, c.Name)
		buf = AppendVarint(buf, c.Version)
		if c.Required {
			buf = append(buf, 0x01)
		} else {
			buf = append(buf, 0x00)
		}
	}
	return buf
}

// decodeHelloPayloadV02 parses a HELLO payload (§4.1) and returns any
// trailing bytes after the capability array. v0.1 HELLOs have no trailing
// bytes; v0.2+ HELLOs carry a signature block trailer (§5.4.3) the caller
// parses via DecodeSignatureBlock.
func decodeHelloPayloadV02(payload []byte) (Version, string, []Capability, []byte, error) {
	pos := 0
	major, n, err := ReadVarint(payload[pos:])
	if err != nil {
		return Version{}, "", nil, nil, fmt.Errorf("%w: VerMajor: %v", ErrMalformedHello, err)
	}
	pos += n

	minor, n, err := ReadVarint(payload[pos:])
	if err != nil {
		return Version{}, "", nil, nil, fmt.Errorf("%w: VerMinor: %v", ErrMalformedHello, err)
	}
	pos += n

	nodeID, n, err := readString(payload[pos:])
	if err != nil {
		return Version{}, "", nil, nil, fmt.Errorf("%w: NodeID: %v", ErrMalformedHello, err)
	}
	pos += n

	numCaps, n, err := ReadVarint(payload[pos:])
	if err != nil {
		return Version{}, "", nil, nil, fmt.Errorf("%w: NumCaps: %v", ErrMalformedHello, err)
	}
	pos += n

	caps := make([]Capability, 0, numCaps)
	for i := uint64(0); i < numCaps; i++ {
		name, n, err := readString(payload[pos:])
		if err != nil {
			return Version{}, "", nil, nil, fmt.Errorf("%w: cap[%d].name: %v", ErrMalformedHello, i, err)
		}
		pos += n

		ver, n, err := ReadVarint(payload[pos:])
		if err != nil {
			return Version{}, "", nil, nil, fmt.Errorf("%w: cap[%d].version: %v", ErrMalformedHello, i, err)
		}
		pos += n

		if pos >= len(payload) {
			return Version{}, "", nil, nil, fmt.Errorf("%w: cap[%d].required: missing byte", ErrMalformedHello, i)
		}
		var req bool
		switch payload[pos] {
		case 0x00:
			req = false
		case 0x01:
			req = true
		default:
			return Version{}, "", nil, nil, fmt.Errorf("%w: cap[%d].required: invalid value 0x%02x", ErrMalformedHello, i, payload[pos])
		}
		pos++
		caps = append(caps, Capability{Name: name, Version: ver, Required: req})
	}
	return Version{Major: major, Minor: minor}, nodeID, caps, payload[pos:], nil
}

// appendString appends a length-prefixed UTF-8 string to dst (spec §4.2).
func appendString(dst []byte, s string) []byte {
	dst = AppendVarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// readString reads a length-prefixed UTF-8 string from data.
func readString(data []byte) (string, int, error) {
	length, n, err := ReadVarint(data)
	if err != nil {
		return "", 0, err
	}
	if uint64(len(data)-n) < length {
		return "", 0, ErrShortBuffer
	}
	end := n + int(length)
	return string(data[n:end]), end, nil
}

// runHandshake executes the §4 HELLO exchange on the control stream and
// returns the negotiated state. Both sides call this with their local config;
// the protocol is symmetric (both peers send and receive HELLO).
func runHandshake(ctrl *Stream, local NodeConfig) (*HandshakeState, error) {
	if err := ctrl.SendFrame(Frame{Type: FrameHello, Payload: encodeHelloPayload(local)}); err != nil {
		return nil, fmt.Errorf("aire: handshake: send HELLO: %w", err)
	}

	f, err := ctrl.RecvFrame()
	if err != nil {
		return nil, fmt.Errorf("aire: handshake: recv first frame: %w", err)
	}
	if f.Type != FrameHello {
		return nil, fmt.Errorf("%w: expected HELLO, got frame type 0x%02x", ErrProtocolViolation, f.Type)
	}
	if f.OpID != 0 {
		return nil, fmt.Errorf("%w: HELLO had non-zero OpID %d", ErrProtocolViolation, f.OpID)
	}

	peerVer, peerNodeID, peerCaps, _, err := decodeHelloPayloadV02(f.Payload)
	if err != nil {
		return nil, err
	}

	if peerVer.Major != CurrentVersion.Major {
		return nil, fmt.Errorf("%w: peer major=%d local major=%d", ErrIncompatibleVersion, peerVer.Major, CurrentVersion.Major)
	}

	negotiatedMinor := CurrentVersion.Minor
	if peerVer.Minor < negotiatedMinor {
		negotiatedMinor = peerVer.Minor
	}

	active, err := NegotiateCapabilities(local.Capabilities, peerCaps)
	if err != nil {
		return nil, err
	}

	return &HandshakeState{
		PeerNodeID:         peerNodeID,
		NegotiatedMinor:    negotiatedMinor,
		ActiveCapabilities: active,
	}, nil
}

// Handshake performs the §4 HELLO exchange on the connection. Must be called
// exactly once per Conn before any other AIRE operation. On the client side
// (Conn returned by Dial) it opens the control stream; on the server side
// (Conn returned by Listener.Accept) it accepts the control stream.
//
// On error, the connection is closed. The returned error wraps one of
// ErrIncompatibleVersion, ErrMissingRequiredCapability, ErrMalformedHello, or
// ErrProtocolViolation, plus generic transport errors.
func (c *Conn) Handshake(ctx context.Context, cfg NodeConfig) (*HandshakeState, error) {
	if c.state != nil {
		return nil, errors.New("aire: handshake already completed")
	}

	var qs *quic.Stream
	var err error
	if c.isClient {
		qs, err = c.qc.OpenStreamSync(ctx)
	} else {
		qs, err = c.qc.AcceptStream(ctx)
	}
	if err != nil {
		_ = c.qc.CloseWithError(0, "")
		return nil, fmt.Errorf("aire: handshake: control stream: %w", err)
	}
	c.ctrl = &Stream{qs: qs}

	state, err := runHandshake(c.ctrl, cfg)
	if err != nil {
		_ = c.qc.CloseWithError(0, err.Error())
		return nil, err
	}
	c.state = state
	return state, nil
}

// State returns the negotiated handshake state, or nil if Handshake has not
// completed.
func (c *Conn) State() *HandshakeState {
	return c.state
}
