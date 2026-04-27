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

// handshookPair returns a connected (client, server) Conn pair that have
// both completed the §4 handshake. The caller is responsible for closing
// both conns and the listener (returned via cleanup).
func handshookPair(t *testing.T) (client, server *Conn, cleanup func()) {
	t.Helper()
	listener := mustListen(t)

	type srvResult struct {
		conn *Conn
		err  error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		c, err := listener.Accept(context.Background())
		if err != nil {
			srvCh <- srvResult{nil, err}
			return
		}
		if _, err := c.Handshake(context.Background(), NodeConfig{NodeID: "server"}); err != nil {
			srvCh <- srvResult{nil, err}
			return
		}
		srvCh <- srvResult{c, nil}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, listener.Addr().String(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := client.Handshake(ctx, NodeConfig{NodeID: "client"}); err != nil {
		t.Fatalf("client Handshake: %v", err)
	}

	srv := <-srvCh
	if srv.err != nil {
		t.Fatalf("server: %v", srv.err)
	}

	cleanup = func() {
		_ = client.Close()
		_ = srv.conn.Close()
		_ = listener.Close()
	}
	return client, srv.conn, cleanup
}

func TestOperation_RoundTrip(t *testing.T) {
	client, server, cleanup := handshookPair(t)
	defer cleanup()

	go func() {
		op, err := server.AcceptOperation(context.Background())
		if err != nil {
			t.Errorf("server AcceptOperation: %v", err)
			return
		}
		f, err := op.Recv()
		if err != nil {
			t.Errorf("server op.Recv: %v", err)
			return
		}
		// Echo back; Send will stamp op.OpID
		if err := op.Send(Frame{Type: FrameStream, Payload: f.Payload}); err != nil {
			t.Errorf("server op.Send: %v", err)
		}
		_ = op.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	op, err := client.NewOperation(ctx)
	if err != nil {
		t.Fatalf("NewOperation: %v", err)
	}

	if op.OpID == 0 {
		t.Errorf("OpID = 0; should be > 0 (control stream is OpID 0)")
	}

	if err := op.Send(Frame{Type: FrameInvoke, Payload: []byte("ping")}); err != nil {
		t.Fatalf("op.Send: %v", err)
	}
	if err := op.Close(); err != nil {
		t.Fatalf("op.Close: %v", err)
	}

	got, err := op.Recv()
	if err != nil {
		t.Fatalf("op.Recv: %v", err)
	}
	if got.OpID != op.OpID {
		t.Errorf("recv OpID = %d, want %d", got.OpID, op.OpID)
	}
	if !bytes.Equal(got.Payload, []byte("ping")) {
		t.Errorf("recv payload = %q, want ping", got.Payload)
	}

	// Drain to confirm clean FIN.
	if _, err := op.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("expected EOF after one echo, got %v", err)
	}
}

func TestOperation_StampsOpIDOnSend(t *testing.T) {
	client, server, cleanup := handshookPair(t)
	defer cleanup()

	srvOpID := make(chan uint64, 1)
	go func() {
		op, err := server.AcceptOperation(context.Background())
		if err != nil {
			t.Errorf("AcceptOperation: %v", err)
			srvOpID <- 0
			return
		}
		f, err := op.Recv()
		if err != nil {
			t.Errorf("Recv: %v", err)
			srvOpID <- 0
			return
		}
		srvOpID <- f.OpID
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	op, err := client.NewOperation(ctx)
	if err != nil {
		t.Fatalf("NewOperation: %v", err)
	}

	// Send with a deliberately-wrong OpID; Operation must overwrite it.
	if err := op.Send(Frame{Type: FrameInvoke, OpID: 999, Payload: []byte("x")}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got := <-srvOpID; got != op.OpID {
		t.Errorf("server saw OpID %d, want %d (caller's 999 should have been overwritten)", got, op.OpID)
	}
}

func TestOperation_RejectsMismatchedRecvOpID(t *testing.T) {
	client, server, cleanup := handshookPair(t)
	defer cleanup()

	go func() {
		// Server accepts the stream raw, then writes a frame with a wrong OpID.
		s, err := server.AcceptStream(context.Background())
		if err != nil {
			t.Errorf("AcceptStream: %v", err)
			return
		}
		// Read whatever the client sent first
		_, _ = s.RecvFrame()
		// Send a frame with a clearly-wrong OpID (0, which is reserved for control).
		_ = s.SendFrame(Frame{Type: FrameStream, OpID: 0, Payload: []byte("bogus")})
		_ = s.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	op, err := client.NewOperation(ctx)
	if err != nil {
		t.Fatalf("NewOperation: %v", err)
	}
	if err := op.Send(Frame{Type: FrameInvoke}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	_ = op.Close()

	_, err = op.Recv()
	if !errors.Is(err, ErrProtocolViolation) {
		t.Errorf("got err=%v, want ErrProtocolViolation", err)
	}
}

func TestOperation_ParallelOperations(t *testing.T) {
	client, server, cleanup := handshookPair(t)
	defer cleanup()

	const N = 5
	var srvWG sync.WaitGroup
	srvWG.Add(N)
	go func() {
		for i := 0; i < N; i++ {
			op, err := server.AcceptOperation(context.Background())
			if err != nil {
				t.Errorf("AcceptOperation: %v", err)
				return
			}
			go func(op *Operation) {
				defer srvWG.Done()
				f, err := op.Recv()
				if err != nil {
					t.Errorf("Recv: %v", err)
					return
				}
				if err := op.Send(Frame{Type: FrameStream, Payload: f.Payload}); err != nil {
					t.Errorf("Send: %v", err)
				}
				_ = op.Close()
			}(op)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var clientWG sync.WaitGroup
	clientWG.Add(N)
	seenOpIDs := sync.Map{}
	for i := 0; i < N; i++ {
		go func(i int) {
			defer clientWG.Done()
			op, err := client.NewOperation(ctx)
			if err != nil {
				t.Errorf("NewOperation: %v", err)
				return
			}
			if _, dup := seenOpIDs.LoadOrStore(op.OpID, true); dup {
				t.Errorf("duplicate OpID %d allocated", op.OpID)
				return
			}
			payload := []byte{byte(i)}
			if err := op.Send(Frame{Type: FrameInvoke, Payload: payload}); err != nil {
				t.Errorf("Send: %v", err)
				return
			}
			_ = op.Close()
			got, err := op.Recv()
			if err != nil {
				t.Errorf("Recv: %v", err)
				return
			}
			if !bytes.Equal(got.Payload, payload) {
				t.Errorf("op %d echo mismatch: got %x want %x", op.OpID, got.Payload, payload)
			}
		}(i)
	}
	clientWG.Wait()
	srvWG.Wait()
}

func TestOperation_RejectsBeforeHandshake(t *testing.T) {
	listener := mustListen(t)
	defer func() { _ = listener.Close() }()

	go func() {
		// Server accepts and idles — never finishes handshake.
		_, _ = listener.Accept(context.Background())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, listener.Addr().String(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.NewOperation(ctx); err == nil {
		t.Errorf("NewOperation before Handshake should fail; got nil")
	}
	if _, err := conn.AcceptOperation(ctx); err == nil {
		t.Errorf("AcceptOperation before Handshake should fail; got nil")
	}
}
