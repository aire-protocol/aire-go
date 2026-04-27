// Package aire is the reference Go implementation of the AIRE protocol.
//
// AIRE (Agent Interchange Runtime Envelope) is a QUIC-native application-layer
// protocol for agent-to-agent communication. See the spec at
// https://github.com/aire-protocol/aire-spec.
package aire

// FrameType identifies an AIRE frame variant on the wire.
type FrameType uint8

const (
	FrameHello      FrameType = 0x01
	FrameCapability FrameType = 0x02
	FrameInvoke     FrameType = 0x03
	FrameStream     FrameType = 0x04
	FrameCancel     FrameType = 0x05
	FrameBudget     FrameType = 0x06
	FrameDelegate   FrameType = 0x07
	FrameError      FrameType = 0x08
	FrameGoodbye    FrameType = 0x09
)

// Frame is the common envelope for every AIRE message.
//
// Wire encoding is defined in SPEC.md §2.
type Frame struct {
	Type    FrameType
	OpID    uint64
	Payload []byte
}
