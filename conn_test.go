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

func TestALPN_Constant(t *testing.T) {
	// Lock the ALPN value. Changing it is a wire-incompatible change.
	if ALPN != "aire/v0" {
		t.Errorf("ALPN = %q, want %q", ALPN, "aire/v0")
	}
}

func TestDevTLSConfig_Shape(t *testing.T) {
	c := DevTLSConfig()
	if len(c.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(c.Certificates))
	}
	if !c.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = false, want true (dev helper)")
	}
	if len(c.NextProtos) != 1 || c.NextProtos[0] != ALPN {
		t.Errorf("NextProtos = %v, want [%q]", c.NextProtos, ALPN)
	}
}

func TestQUICTransport_RoundTripFrame(t *testing.T) {
	listener, err := Listen("127.0.0.1:0", DevTLSConfig())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runEchoServer(t, listener)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, listener.Addr().String(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	sent := Frame{
		Type:    FrameInvoke,
		OpID:    42,
		Payload: []byte("hello"),
	}
	if err := stream.SendFrame(sent); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close: %v", err)
	}

	got, err := stream.RecvFrame()
	if err != nil {
		t.Fatalf("RecvFrame: %v", err)
	}
	if got.Type != sent.Type || got.OpID != sent.OpID || !bytes.Equal(got.Payload, sent.Payload) {
		t.Errorf("frame mismatch:\n  sent: %+v\n  got:  %+v", sent, got)
	}

	// Drain to EOF to confirm the server FIN'd cleanly.
	if _, err := stream.RecvFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after echo, got %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestQUICTransport_MultipleFramesOneStream(t *testing.T) {
	listener, err := Listen("127.0.0.1:0", DevTLSConfig())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runEchoServer(t, listener)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, listener.Addr().String(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	frames := []Frame{
		{Type: FrameHello},
		{Type: FrameInvoke, OpID: 1, Payload: []byte("a")},
		{Type: FrameStream, OpID: 1, Payload: []byte("bcd")},
		{Type: FrameInvoke, OpID: 2, Payload: bytes.Repeat([]byte{0xCC}, 200)},
	}
	for _, f := range frames {
		if err := stream.SendFrame(f); err != nil {
			t.Fatalf("SendFrame: %v", err)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close: %v", err)
	}

	for i, want := range frames {
		got, err := stream.RecvFrame()
		if err != nil {
			t.Fatalf("RecvFrame[%d]: %v", i, err)
		}
		if got.Type != want.Type || got.OpID != want.OpID || !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("frame[%d] mismatch:\n  want: %+v\n  got:  %+v", i, want, got)
		}
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestQUICTransport_MultipleStreams(t *testing.T) {
	listener, err := Listen("127.0.0.1:0", DevTLSConfig())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		ctx := context.Background()
		conn, err := listener.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				t.Errorf("AcceptStream: %v", err)
				return
			}
			wg.Add(1)
			go func(s *Stream) {
				defer wg.Done()
				f, err := s.RecvFrame()
				if err != nil {
					t.Errorf("RecvFrame: %v", err)
					return
				}
				if err := s.SendFrame(f); err != nil {
					t.Errorf("SendFrame: %v", err)
					return
				}
				_ = s.Close()
			}(s)
		}
		wg.Wait()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, listener.Addr().String(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(opid uint64) {
			defer wg.Done()
			s, err := conn.OpenStream(ctx)
			if err != nil {
				t.Errorf("OpenStream: %v", err)
				return
			}
			sent := Frame{Type: FrameInvoke, OpID: opid, Payload: []byte{byte(opid)}}
			if err := s.SendFrame(sent); err != nil {
				t.Errorf("SendFrame: %v", err)
				return
			}
			_ = s.Close()
			got, err := s.RecvFrame()
			if err != nil {
				t.Errorf("RecvFrame: %v", err)
				return
			}
			if got.OpID != sent.OpID || !bytes.Equal(got.Payload, sent.Payload) {
				t.Errorf("stream %d: got %+v want %+v", opid, got, sent)
			}
		}(uint64(i + 1))
	}
	wg.Wait()
	<-serverDone
}

// runEchoServer accepts a single connection, accepts a single stream, and
// echoes every frame received until the peer FINs.
func runEchoServer(t *testing.T, l *Listener) error {
	t.Helper()
	ctx := context.Background()
	conn, err := l.Accept(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()

	for {
		f, err := stream.RecvFrame()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.SendFrame(f); err != nil {
			return err
		}
	}
}
