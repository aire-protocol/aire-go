package aire

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func mustSigner(t testing.TB) *Ed25519DIDKeySigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	return NewEd25519DIDKeySigner(priv)
}

func TestHandshake_E2E_Success(t *testing.T) {
	listener := mustListen(t)
	defer func() { _ = listener.Close() }()

	serverSig := mustSigner(t)
	clientSig := mustSigner(t)

	serverCfg := NodeConfig{
		Signer: serverSig,
		Capabilities: []Capability{
			{Name: "com.example.streaming/1", Version: 1, Required: true},
		},
	}
	clientCfg := NodeConfig{
		Signer: clientSig,
		Capabilities: []Capability{
			{Name: "com.example.streaming/1", Version: 1, Required: true},
			{Name: "com.example.budget/1", Version: 1, Required: false}, // unknown to server, optional
		},
	}

	type result struct {
		state *HandshakeState
		err   error
	}
	serverRes := make(chan result, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverRes <- result{nil, err}
			return
		}
		defer func() { _ = conn.Close() }()
		state, err := conn.Handshake(context.Background(), serverCfg)
		serverRes <- result{state, err}
		<-conn.Context().Done()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, listener.Addr().String(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	clientState, err := conn.Handshake(ctx, clientCfg)
	if err != nil {
		t.Fatalf("client Handshake: %v", err)
	}

	if clientState.PeerNodeID != serverSig.DID() {
		t.Errorf("client.PeerNodeID = %q, want %q", clientState.PeerNodeID, serverSig.DID())
	}
	if clientState.NegotiatedMinor != CurrentVersion.Minor {
		t.Errorf("client.NegotiatedMinor = %d, want %d", clientState.NegotiatedMinor, CurrentVersion.Minor)
	}
	if len(clientState.ActiveCapabilities) != 1 || clientState.ActiveCapabilities[0].Name != "com.example.streaming/1" {
		t.Errorf("client.ActiveCapabilities = %+v, want [com.example.streaming/1]", clientState.ActiveCapabilities)
	}

	if conn.State() != clientState {
		t.Errorf("State() != returned state from Handshake")
	}

	_ = conn.Close()

	srv := <-serverRes
	if srv.err != nil {
		t.Fatalf("server Handshake: %v", srv.err)
	}
	if srv.state.PeerNodeID != clientSig.DID() {
		t.Errorf("server.PeerNodeID = %q, want %q", srv.state.PeerNodeID, clientSig.DID())
	}
	if len(srv.state.ActiveCapabilities) != 1 {
		t.Errorf("server.ActiveCapabilities len = %d, want 1", len(srv.state.ActiveCapabilities))
	}
}

func TestHandshake_E2E_MissingRequiredCapability(t *testing.T) {
	listener := mustListen(t)
	defer func() { _ = listener.Close() }()

	serverCfg := NodeConfig{
		Signer: mustSigner(t),
		Capabilities: []Capability{
			{Name: "com.example.must-have/1", Version: 1, Required: true},
		},
	}
	clientCfg := NodeConfig{
		Signer: mustSigner(t),
		Capabilities: []Capability{
			{Name: "com.example.something-else/1", Version: 1, Required: false},
		},
	}

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverErrCh <- err
			return
		}
		_, err = conn.Handshake(context.Background(), serverCfg)
		serverErrCh <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, listener.Addr().String(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, clientErr := conn.Handshake(ctx, clientCfg)
	srvErr := <-serverErrCh

	if clientErr == nil || srvErr == nil {
		t.Fatalf("expected both sides to fail; got client=%v server=%v", clientErr, srvErr)
	}
	if !errors.Is(clientErr, ErrMissingRequiredCapability) && !errors.Is(srvErr, ErrMissingRequiredCapability) {
		t.Errorf("neither side reported ErrMissingRequiredCapability:\n  client=%v\n  server=%v", clientErr, srvErr)
	}
}

// TestHandshake_E2E_IncompatibleVersion sends a HELLO with major=99 and no
// signature block. The receiver's version check fires before signature
// verification, so it MUST surface as ErrIncompatibleVersion.
func TestHandshake_E2E_IncompatibleVersion(t *testing.T) {
	listener := mustListen(t)
	defer func() { _ = listener.Close() }()

	serverCfg := NodeConfig{Signer: mustSigner(t)}

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverErrCh <- err
			return
		}
		_, err = conn.Handshake(context.Background(), serverCfg)
		serverErrCh <- err
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
	var payload []byte
	payload = AppendVarint(payload, 99) // VerMajor — incompatible
	payload = AppendVarint(payload, 0)  // VerMinor
	payload = appendString(payload, "did:key:zEvil")
	payload = AppendVarint(payload, 0) // NumCaps=0
	if err := stream.SendFrame(Frame{Type: FrameHello, Payload: payload}); err != nil {
		t.Fatalf("SendFrame HELLO: %v", err)
	}

	srvErr := <-serverErrCh
	if !errors.Is(srvErr, ErrIncompatibleVersion) {
		t.Errorf("server got err=%v, want ErrIncompatibleVersion", srvErr)
	}
}

// TestHandshake_E2E_BadSignature sends a v0.2 HELLO with a tampered signature.
// The receiver MUST surface as ErrBadSignature.
func TestHandshake_E2E_BadSignature(t *testing.T) {
	listener := mustListen(t)
	defer func() { _ = listener.Close() }()

	serverCfg := NodeConfig{Signer: mustSigner(t)}
	clientSig := mustSigner(t)

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverErrCh <- err
			return
		}
		_, err = conn.Handshake(context.Background(), serverCfg)
		serverErrCh <- err
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

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	payload := buildSignedHello(clientSig, nil, nonce, time.Now())
	// Tamper the last byte (in the signature region).
	payload[len(payload)-1] ^= 0x01
	if err := stream.SendFrame(Frame{Type: FrameHello, Payload: payload}); err != nil {
		t.Fatalf("SendFrame HELLO: %v", err)
	}

	srvErr := <-serverErrCh
	if !errors.Is(srvErr, ErrBadSignature) {
		t.Errorf("server got err=%v, want ErrBadSignature", srvErr)
	}
}

func mustListen(t *testing.T) *Listener {
	t.Helper()
	l, err := Listen("127.0.0.1:0", DevTLSConfig())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	return l
}
