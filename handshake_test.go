package aire

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// TestHelloEncoding_MatchesSpecVector verifies our HELLO encoding matches
// the canonical 30-byte vector in SPEC.md §4.7 exactly.
func TestHelloEncoding_MatchesSpecVector(t *testing.T) {
	cfg := NodeConfig{
		NodeID: "node1",
		Capabilities: []Capability{
			{Name: "core.streaming", Version: 1, Required: true},
		},
	}
	payload := encodeHelloPayload(cfg)

	// Per spec §4.7: 26 bytes of payload.
	wantPayload := []byte{
		0x00,                               // VerMajor=0
		0x01,                               // VerMinor=1
		0x05, 0x6E, 0x6F, 0x64, 0x65, 0x31, // NodeID "node1"
		0x01,                                                                                     // NumCaps=1
		0x0E, 0x63, 0x6F, 0x72, 0x65, 0x2E, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6D, 0x69, 0x6E, 0x67, // cap name "core.streaming"
		0x01, // cap version=1
		0x01, // cap required=true
	}
	if !bytes.Equal(payload, wantPayload) {
		t.Errorf("HELLO payload mismatch:\n  want: %x\n  got:  %x", wantPayload, payload)
	}

	// Wrap in frame envelope and compare against the full 30-byte vector.
	frame := Frame{Type: FrameHello, Payload: payload}
	got := frame.Encode()
	want := append([]byte{0x01, 0x00, 0x00, 0x1A}, wantPayload...)
	if !bytes.Equal(got, want) {
		t.Errorf("full HELLO frame mismatch:\n  want: %x\n  got:  %x", want, got)
	}
}

func TestHelloPayload_RoundTrip(t *testing.T) {
	cases := []NodeConfig{
		{NodeID: "x", Capabilities: nil},
		{NodeID: "node1", Capabilities: []Capability{
			{Name: "core.streaming", Version: 1, Required: true},
		}},
		{NodeID: "really-long-node-id-with-dashes-and-stuff", Capabilities: []Capability{
			{Name: "a.b.c", Version: 0, Required: false},
			{Name: "x.y", Version: 999, Required: true},
			{Name: "empty", Version: 0, Required: false},
		}},
	}
	for i, cfg := range cases {
		payload := encodeHelloPayload(cfg)
		ver, nodeID, caps, err := decodeHelloPayload(payload)
		if err != nil {
			t.Fatalf("case %d decode error: %v", i, err)
		}
		if ver != CurrentVersion {
			t.Errorf("case %d version: got %v want %v", i, ver, CurrentVersion)
		}
		if nodeID != cfg.NodeID {
			t.Errorf("case %d nodeID: got %q want %q", i, nodeID, cfg.NodeID)
		}
		if len(caps) != len(cfg.Capabilities) {
			t.Errorf("case %d caps len: got %d want %d", i, len(caps), len(cfg.Capabilities))
			continue
		}
		for j, c := range caps {
			if c != cfg.Capabilities[j] {
				t.Errorf("case %d cap[%d]: got %+v want %+v", i, j, c, cfg.Capabilities[j])
			}
		}
	}
}

func TestNegotiateCapabilities_Intersection(t *testing.T) {
	local := []Capability{
		{Name: "a", Version: 1},
		{Name: "b", Version: 2},
		{Name: "c", Version: 1},
	}
	peer := []Capability{
		{Name: "a", Version: 1}, // active
		{Name: "b", Version: 99},
		{Name: "d", Version: 1},
	}
	active, err := negotiateCapabilities(local, peer)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(active) != 1 || active[0].Name != "a" {
		t.Errorf("active = %+v, want [a v1]", active)
	}
}

func TestNegotiateCapabilities_RequiredMissing(t *testing.T) {
	local := []Capability{
		{Name: "must-have", Version: 1, Required: true},
	}
	peer := []Capability{
		{Name: "other", Version: 1},
	}
	_, err := negotiateCapabilities(local, peer)
	if !errors.Is(err, ErrMissingRequiredCapability) {
		t.Errorf("got err=%v, want ErrMissingRequiredCapability", err)
	}
}

func TestNegotiateCapabilities_PeerRequiredMissing(t *testing.T) {
	local := []Capability{
		{Name: "other", Version: 1},
	}
	peer := []Capability{
		{Name: "must-have", Version: 1, Required: true},
	}
	_, err := negotiateCapabilities(local, peer)
	if !errors.Is(err, ErrMissingRequiredCapability) {
		t.Errorf("got err=%v, want ErrMissingRequiredCapability", err)
	}
}

func TestNegotiateCapabilities_RequiredVersionMismatch(t *testing.T) {
	local := []Capability{
		{Name: "x", Version: 1, Required: true},
	}
	peer := []Capability{
		{Name: "x", Version: 2}, // wrong version, no match
	}
	_, err := negotiateCapabilities(local, peer)
	if !errors.Is(err, ErrMissingRequiredCapability) {
		t.Errorf("got err=%v, want ErrMissingRequiredCapability", err)
	}
}

func TestHandshake_E2E_Success(t *testing.T) {
	listener := mustListen(t)
	defer func() { _ = listener.Close() }()

	serverCfg := NodeConfig{
		NodeID: "server-node",
		Capabilities: []Capability{
			{Name: "core.streaming", Version: 1, Required: true},
		},
	}
	clientCfg := NodeConfig{
		NodeID: "client-node",
		Capabilities: []Capability{
			{Name: "core.streaming", Version: 1, Required: true},
			{Name: "core.budget", Version: 1, Required: false}, // unknown to server, optional
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
		// keep the goroutine alive until peer closes
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

	// Client sees server's identity.
	if clientState.PeerNodeID != "server-node" {
		t.Errorf("client.PeerNodeID = %q, want server-node", clientState.PeerNodeID)
	}
	if clientState.NegotiatedMinor != 1 {
		t.Errorf("client.NegotiatedMinor = %d, want 1", clientState.NegotiatedMinor)
	}
	if len(clientState.ActiveCapabilities) != 1 || clientState.ActiveCapabilities[0].Name != "core.streaming" {
		t.Errorf("client.ActiveCapabilities = %+v, want [core.streaming]", clientState.ActiveCapabilities)
	}

	// State() accessor returns same pointer.
	if conn.State() != clientState {
		t.Errorf("State() != returned state from Handshake")
	}

	_ = conn.Close()

	srv := <-serverRes
	if srv.err != nil {
		t.Fatalf("server Handshake: %v", srv.err)
	}
	if srv.state.PeerNodeID != "client-node" {
		t.Errorf("server.PeerNodeID = %q, want client-node", srv.state.PeerNodeID)
	}
	if len(srv.state.ActiveCapabilities) != 1 {
		t.Errorf("server.ActiveCapabilities len = %d, want 1", len(srv.state.ActiveCapabilities))
	}
}

func TestHandshake_E2E_MissingRequiredCapability(t *testing.T) {
	listener := mustListen(t)
	defer func() { _ = listener.Close() }()

	// Server requires a capability the client does not advertise.
	serverCfg := NodeConfig{
		NodeID: "server",
		Capabilities: []Capability{
			{Name: "must.have", Version: 1, Required: true},
		},
	}
	clientCfg := NodeConfig{
		NodeID: "client",
		Capabilities: []Capability{
			{Name: "something.else", Version: 1, Required: false},
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

	// Per §4.5 both peers can independently validate; in practice one detects
	// it locally and closes, the other sees the remote close. We require
	// (a) both sides fail, and (b) at least one reports the canonical error.
	if clientErr == nil || srvErr == nil {
		t.Fatalf("expected both sides to fail; got client=%v server=%v", clientErr, srvErr)
	}
	if !errors.Is(clientErr, ErrMissingRequiredCapability) && !errors.Is(srvErr, ErrMissingRequiredCapability) {
		t.Errorf("neither side reported ErrMissingRequiredCapability:\n  client=%v\n  server=%v", clientErr, srvErr)
	}
}

// TestHandshake_E2E_IncompatibleVersion has a malicious client send a HELLO
// claiming major=99. The server's Handshake must reject.
func TestHandshake_E2E_IncompatibleVersion(t *testing.T) {
	listener := mustListen(t)
	defer func() { _ = listener.Close() }()

	serverCfg := NodeConfig{NodeID: "server"}

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

	// Open the control stream manually and send a HELLO with major=99.
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	var payload []byte
	payload = AppendVarint(payload, 99) // VerMajor — incompatible
	payload = AppendVarint(payload, 0)  // VerMinor
	payload = appendString(payload, "evil-client")
	payload = AppendVarint(payload, 0) // NumCaps=0
	if err := stream.SendFrame(Frame{Type: FrameHello, Payload: payload}); err != nil {
		t.Fatalf("SendFrame HELLO: %v", err)
	}

	srvErr := <-serverErrCh
	if !errors.Is(srvErr, ErrIncompatibleVersion) {
		t.Errorf("server got err=%v, want ErrIncompatibleVersion", srvErr)
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
