package aire

import (
	"context"
	"fmt"
)

// Operation is a single logical AIRE task: one QUIC stream carrying one OpID
// (spec §2.4). Frames sent through the Operation are stamped with op.OpID;
// frames received are validated against it.
type Operation struct {
	OpID   uint64
	stream *Stream
	conn   *Conn
}

// PeerNodeID returns the authenticated NodeID (DID) of the connection peer,
// as established by the signed HELLO (§5.4). Identity is bound per stream to
// the connection's handshake; exposing it here lets the receiving side of an
// Operation authorize against who is actually on the wire. Empty before the
// handshake completes (which cannot happen for Operations obtained via
// NewOperation/AcceptOperation, since both require a completed handshake).
func (op *Operation) PeerNodeID() string {
	if op.conn == nil || op.conn.state == nil {
		return ""
	}
	return op.conn.state.PeerNodeID
}

// NewOperation opens a new stream on the connection and binds it to an
// Operation. The OpID is the underlying QUIC stream ID, guaranteed unique
// per connection and never zero (zero is reserved for the control stream).
//
// Handshake MUST have completed on c before calling NewOperation.
func (c *Conn) NewOperation(ctx context.Context) (*Operation, error) {
	if c.state == nil {
		return nil, fmt.Errorf("aire: NewOperation: handshake not completed")
	}
	stream, err := c.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &Operation{
		OpID:   uint64(stream.qs.StreamID()),
		stream: stream,
		conn:   c,
	}, nil
}

// AcceptOperation blocks until the peer opens a new operation stream and
// returns the Operation handle. The first frame is not yet read; call Recv
// on the returned Operation to consume it.
//
// Handshake MUST have completed on c before calling AcceptOperation.
func (c *Conn) AcceptOperation(ctx context.Context) (*Operation, error) {
	if c.state == nil {
		return nil, fmt.Errorf("aire: AcceptOperation: handshake not completed")
	}
	stream, err := c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &Operation{
		OpID:   uint64(stream.qs.StreamID()),
		stream: stream,
		conn:   c,
	}, nil
}

// Send transmits f on the operation. The frame's OpID is overwritten with
// op.OpID to enforce per-operation framing per spec §2.4.
func (op *Operation) Send(f Frame) error {
	f.OpID = op.OpID
	return op.stream.SendFrame(f)
}

// Recv reads the next frame from the operation and validates that its OpID
// matches the operation's OpID. A mismatch is treated as a protocol violation
// (spec §2.4 requires all frames on one stream share an OpID).
func (op *Operation) Recv() (Frame, error) {
	f, err := op.stream.RecvFrame()
	if err != nil {
		return f, err
	}
	if f.OpID != op.OpID {
		return f, fmt.Errorf("%w: frame OpID %d, operation OpID %d", ErrProtocolViolation, f.OpID, op.OpID)
	}
	return f, nil
}

// Close closes the send-side of the operation (FIN). The operation is
// finished from the local side; the receive-side stays open until the peer
// FINs.
func (op *Operation) Close() error {
	return op.stream.Close()
}
