package aire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestNode_RegisterAgent_Validations(t *testing.T) {
	node := NewNode(NodeConfig{})
	if err := node.RegisterAgent("", AgentFunc(func(context.Context, *Invoke) error { return nil })); err == nil {
		t.Errorf("empty ID should error")
	}
	if err := node.RegisterAgent("x", nil); err == nil {
		t.Errorf("nil agent should error")
	}
	if err := node.RegisterAgent("x", AgentFunc(func(context.Context, *Invoke) error { return nil })); err != nil {
		t.Errorf("first register: %v", err)
	}
	if err := node.RegisterAgent("x", AgentFunc(func(context.Context, *Invoke) error { return nil })); err == nil {
		t.Errorf("duplicate register should error")
	}
}

func TestNode_DispatchInvoke(t *testing.T) {
	node := NewNode(NodeConfig{})
	defer func() { _ = node.Stop() }()

	got := make(chan *Invoke, 1)
	if err := node.RegisterAgent("echo", AgentFunc(func(_ context.Context, inv *Invoke) error {
		got <- inv
		return inv.Op.Send(Frame{Type: FrameStream, Payload: append([]byte("echo:"), inv.Args...)})
	})); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	if err := node.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, node.Addr(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Handshake(ctx, NodeConfig{}); err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	op, err := conn.Invoke(ctx, "echo", "answer", []byte("hello"))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	_ = op.Close()

	select {
	case inv := <-got:
		if inv.AgentID != "echo" {
			t.Errorf("inv.AgentID = %q, want echo", inv.AgentID)
		}
		if inv.Operation != "answer" {
			t.Errorf("inv.Operation = %q, want answer", inv.Operation)
		}
		if !bytes.Equal(inv.Args, []byte("hello")) {
			t.Errorf("inv.Args = %q, want hello", inv.Args)
		}
	case <-ctx.Done():
		t.Fatalf("agent never invoked: %v", ctx.Err())
	}

	resp, err := op.Recv()
	if err != nil {
		t.Fatalf("op.Recv: %v", err)
	}
	if !bytes.Equal(resp.Payload, []byte("echo:hello")) {
		t.Errorf("resp.Payload = %q, want echo:hello", resp.Payload)
	}
}

func TestNode_UnknownAgent_ClosesOperation(t *testing.T) {
	node := NewNode(NodeConfig{})
	defer func() { _ = node.Stop() }()
	if err := node.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, node.Addr(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Handshake(ctx, NodeConfig{}); err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	op, err := conn.Invoke(ctx, "nonexistent", "foo", nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	_ = op.Close()

	// Server FINs the stream when the agent isn't found; client sees EOF.
	if _, err := op.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after unknown-agent close, got %v", err)
	}
}

func TestNode_MultipleAgents_RouteCorrectly(t *testing.T) {
	node := NewNode(NodeConfig{})
	defer func() { _ = node.Stop() }()

	a1Hits := make(chan struct{}, 4)
	a2Hits := make(chan struct{}, 4)
	mustRegister := func(id string, ch chan<- struct{}) {
		err := node.RegisterAgent(id, AgentFunc(func(_ context.Context, inv *Invoke) error {
			ch <- struct{}{}
			return inv.Op.Send(Frame{Type: FrameStream, Payload: []byte(id)})
		}))
		if err != nil {
			t.Fatalf("RegisterAgent %q: %v", id, err)
		}
	}
	mustRegister("alpha", a1Hits)
	mustRegister("beta", a2Hits)

	if err := node.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, node.Addr(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Handshake(ctx, NodeConfig{}); err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	// Issue invokes to alpha (3x) and beta (1x).
	type call struct{ agent string }
	calls := []call{{"alpha"}, {"alpha"}, {"alpha"}, {"beta"}}
	var wg sync.WaitGroup
	for _, c := range calls {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			op, err := conn.Invoke(ctx, target, "x", nil)
			if err != nil {
				t.Errorf("Invoke %s: %v", target, err)
				return
			}
			_ = op.Close()
			resp, err := op.Recv()
			if err != nil {
				t.Errorf("Recv from %s: %v", target, err)
				return
			}
			if string(resp.Payload) != target {
				t.Errorf("response from %s = %q, want %q", target, resp.Payload, target)
			}
		}(c.agent)
	}
	wg.Wait()

	if len(a1Hits) != 3 {
		t.Errorf("alpha hits = %d, want 3", len(a1Hits))
	}
	if len(a2Hits) != 1 {
		t.Errorf("beta hits = %d, want 1", len(a2Hits))
	}
}

func TestNode_Stop_IsIdempotent(t *testing.T) {
	node := NewNode(NodeConfig{})
	if err := node.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := node.Stop(); err != nil {
		t.Errorf("first Stop: %v", err)
	}
	if err := node.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestInvokePayload_RoundTrip(t *testing.T) {
	cases := []struct {
		agent, op string
		args      []byte
	}{
		{"a", "b", nil},
		{"agent.id", "operation.name", []byte{}},
		{"x", "y", []byte("some args")},
		{"long.agent.id.with.dots", "do-it", bytes.Repeat([]byte{0xAB}, 200)},
	}
	for i, c := range cases {
		payload := encodeInvokePayload(c.agent, c.op, c.args)
		gotAgent, gotOp, gotArgs, err := decodeInvokePayload(payload)
		if err != nil {
			t.Fatalf("case %d decode: %v", i, err)
		}
		if gotAgent != c.agent {
			t.Errorf("case %d agent: got %q want %q", i, gotAgent, c.agent)
		}
		if gotOp != c.op {
			t.Errorf("case %d op: got %q want %q", i, gotOp, c.op)
		}
		if !bytes.Equal(gotArgs, c.args) && !(len(gotArgs) == 0 && len(c.args) == 0) {
			t.Errorf("case %d args: got %x want %x", i, gotArgs, c.args)
		}
	}
}
