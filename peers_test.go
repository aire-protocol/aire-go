package aire

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

// TestPeers_AgentOnANodeDelegatesToAgentOnBNode proves that an agent running
// on Node A can, while handling an inbound Operation, open an outbound AIRE
// Operation to a peer Node B, invoke an agent there, and forward the result
// back to its own caller. This is the core "two Vega instances collaborating
// over AIRE" topology — two independent Nodes wired only by a QUIC connection.
func TestPeers_AgentOnANodeDelegatesToAgentOnBNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodeB := NewNode(NodeConfig{NodeID: "vega-B"})
	defer func() { _ = nodeB.Stop() }()
	if err := nodeB.RegisterAgent("worker", AgentFunc(func(_ context.Context, inv *Invoke) error {
		return inv.Op.Send(Frame{Type: FrameStream, Payload: append([]byte("B:"), inv.Args...)})
	})); err != nil {
		t.Fatalf("nodeB.RegisterAgent: %v", err)
	}
	if err := nodeB.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("nodeB.Listen: %v", err)
	}

	bConn, err := Dial(ctx, nodeB.Addr(), DevTLSConfig())
	if err != nil {
		t.Fatalf("dial B from A: %v", err)
	}
	defer func() { _ = bConn.Close() }()
	bState, err := bConn.Handshake(ctx, NodeConfig{NodeID: "vega-A"})
	if err != nil {
		t.Fatalf("A→B handshake: %v", err)
	}
	if bState.PeerNodeID != "vega-B" {
		t.Errorf("A sees peer NodeID = %q, want vega-B", bState.PeerNodeID)
	}

	nodeA := NewNode(NodeConfig{NodeID: "vega-A"})
	defer func() { _ = nodeA.Stop() }()
	if err := nodeA.RegisterAgent("coordinator", AgentFunc(func(ctx context.Context, inv *Invoke) error {
		op, err := bConn.Invoke(ctx, "worker", "do", inv.Args)
		if err != nil {
			return err
		}
		_ = op.Close()
		f, err := op.Recv()
		if err != nil {
			return err
		}
		return inv.Op.Send(Frame{Type: FrameStream, Payload: append([]byte("A→"), f.Payload...)})
	})); err != nil {
		t.Fatalf("nodeA.RegisterAgent: %v", err)
	}
	if err := nodeA.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("nodeA.Listen: %v", err)
	}

	clientConn, err := Dial(ctx, nodeA.Addr(), DevTLSConfig())
	if err != nil {
		t.Fatalf("client dial A: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	if _, err := clientConn.Handshake(ctx, NodeConfig{NodeID: "client"}); err != nil {
		t.Fatalf("client handshake A: %v", err)
	}

	op, err := clientConn.Invoke(ctx, "coordinator", "go", []byte("ping"))
	if err != nil {
		t.Fatalf("client.Invoke: %v", err)
	}
	_ = op.Close()

	f, err := op.Recv()
	if err != nil {
		t.Fatalf("client.Recv: %v", err)
	}
	want := []byte("A→B:ping")
	if !bytes.Equal(f.Payload, want) {
		t.Errorf("payload = %q, want %q", f.Payload, want)
	}
}

// TestPeers_FanOutToBHasNoHeadOfLineBlocking proves that when an agent on
// Node A opens multiple parallel Operations to peer Node B, a slow Operation
// does not delay a fast one — they ride independent QUIC streams. The fast
// agent on B finishes well before the slow one; the coordinator on A forwards
// results in arrival order, and the fast result reaches the client first.
func TestPeers_FanOutToBHasNoHeadOfLineBlocking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const slowDelay = 200 * time.Millisecond
	const fastDelay = 10 * time.Millisecond

	nodeB := NewNode(NodeConfig{NodeID: "vega-B"})
	defer func() { _ = nodeB.Stop() }()
	if err := nodeB.RegisterAgent("slow", AgentFunc(func(_ context.Context, inv *Invoke) error {
		time.Sleep(slowDelay)
		return inv.Op.Send(Frame{Type: FrameStream, Payload: []byte("slow")})
	})); err != nil {
		t.Fatalf("nodeB.Register slow: %v", err)
	}
	if err := nodeB.RegisterAgent("fast", AgentFunc(func(_ context.Context, inv *Invoke) error {
		time.Sleep(fastDelay)
		return inv.Op.Send(Frame{Type: FrameStream, Payload: []byte("fast")})
	})); err != nil {
		t.Fatalf("nodeB.Register fast: %v", err)
	}
	if err := nodeB.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("nodeB.Listen: %v", err)
	}

	bConn, err := Dial(ctx, nodeB.Addr(), DevTLSConfig())
	if err != nil {
		t.Fatalf("dial B from A: %v", err)
	}
	defer func() { _ = bConn.Close() }()
	if _, err := bConn.Handshake(ctx, NodeConfig{NodeID: "vega-A"}); err != nil {
		t.Fatalf("A→B handshake: %v", err)
	}

	nodeA := NewNode(NodeConfig{NodeID: "vega-A"})
	defer func() { _ = nodeA.Stop() }()
	if err := nodeA.RegisterAgent("coordinator", AgentFunc(func(ctx context.Context, inv *Invoke) error {
		var wg sync.WaitGroup
		out := make(chan []byte, 2)
		for _, target := range []string{"slow", "fast"} {
			wg.Add(1)
			go func(agentID string) {
				defer wg.Done()
				op, err := bConn.Invoke(ctx, agentID, "go", nil)
				if err != nil {
					return
				}
				_ = op.Close()
				f, err := op.Recv()
				if err != nil {
					return
				}
				out <- f.Payload
			}(target)
		}
		go func() { wg.Wait(); close(out) }()
		for chunk := range out {
			if err := inv.Op.Send(Frame{Type: FrameStream, Payload: chunk}); err != nil {
				return err
			}
		}
		return nil
	})); err != nil {
		t.Fatalf("nodeA.Register: %v", err)
	}
	if err := nodeA.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("nodeA.Listen: %v", err)
	}

	clientConn, err := Dial(ctx, nodeA.Addr(), DevTLSConfig())
	if err != nil {
		t.Fatalf("client dial A: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	if _, err := clientConn.Handshake(ctx, NodeConfig{NodeID: "client"}); err != nil {
		t.Fatalf("client handshake A: %v", err)
	}

	start := time.Now()
	op, err := clientConn.Invoke(ctx, "coordinator", "go", nil)
	if err != nil {
		t.Fatalf("client.Invoke: %v", err)
	}
	_ = op.Close()

	first, err := op.Recv()
	if err != nil {
		t.Fatalf("client.Recv first: %v", err)
	}
	firstAt := time.Since(start)

	second, err := op.Recv()
	if err != nil {
		t.Fatalf("client.Recv second: %v", err)
	}
	secondAt := time.Since(start)

	if string(first.Payload) != "fast" {
		t.Errorf("first chunk = %q, want fast (HOL blocking suspected)", first.Payload)
	}
	if string(second.Payload) != "slow" {
		t.Errorf("second chunk = %q, want slow", second.Payload)
	}

	// fast must arrive well before slow finishes; if a single shared stream
	// were serializing them, both would arrive after slowDelay.
	if firstAt > slowDelay/2 {
		t.Errorf("fast chunk arrived after %v, expected well under %v "+
			"(suggests fan-out is being serialized)", firstAt, slowDelay/2)
	}
	if secondAt < slowDelay-50*time.Millisecond {
		t.Errorf("slow chunk arrived at %v, expected ≥ %v", secondAt, slowDelay-50*time.Millisecond)
	}
}
