package aire

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// TestInvoke_CarriesAuthenticatedPeerNodeID proves a server-side Agent can
// learn the DID of the peer whose signed HELLO authenticated the connection
// carrying the INVOKE. Identity is bound per §5; this exposes it at the
// dispatch surface so applications can authorize against it.
func TestInvoke_CarriesAuthenticatedPeerNodeID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	clientSigner := NewEd25519DIDKeySigner(ed25519.NewKeyFromSeed(seed))

	got := make(chan string, 1)
	node := NewNode(NodeConfig{})
	defer func() { _ = node.Stop() }()
	if err := node.RegisterAgent("who", AgentFunc(func(_ context.Context, inv *Invoke) error {
		got <- inv.PeerNodeID
		return inv.Op.Send(Frame{Type: FrameStream, Payload: []byte("ok")})
	})); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if err := node.Listen("127.0.0.1:0", DevTLSConfig()); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	conn, err := Dial(ctx, node.Addr(), DevTLSConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Handshake(ctx, NodeConfig{Signer: clientSigner}); err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	op, err := conn.Invoke(ctx, "who", "go", nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	_ = op.Close()
	if _, err := op.Recv(); err != nil {
		t.Fatalf("Recv: %v", err)
	}

	select {
	case did := <-got:
		if did != clientSigner.DID() {
			t.Errorf("Invoke.PeerNodeID = %q, want the caller's DID %q", did, clientSigner.DID())
		}
	case <-ctx.Done():
		t.Fatal("agent never observed the invoke")
	}

	// The client side sees the server's (ephemeral) DID on its operations too.
	if !strings.HasPrefix(op.PeerNodeID(), "did:") {
		t.Errorf("client-side op.PeerNodeID() = %q, want a DID", op.PeerNodeID())
	}
}
