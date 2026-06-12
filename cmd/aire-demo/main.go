// Command aire-demo is the canonical v0.1 demo: two AIRE nodes in one
// process, streaming a fixed-length token sequence over a single Operation,
// with the client tearing the connection down mid-stream.
//
// Real per-Operation CANCEL semantics arrive in v0.3 (spec §7); for v0.1 we
// approximate by closing the entire connection from the client side, which
// causes the server agent's next Send to fail and the agent to exit.
package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	aire "github.com/aire-protocol/aire-go"
)

const (
	nTokens     = 5
	cancelAfter = 3
	interval    = 200 * time.Millisecond
)

func main() {
	header()

	// 1. Server node with a "stream" agent.
	server := aire.NewNode(aire.NodeConfig{})
	if err := server.RegisterAgent("stream", aire.AgentFunc(streamAgent)); err != nil {
		log.Fatalf("RegisterAgent: %v", err)
	}
	if err := server.Listen("127.0.0.1:0", aire.DevTLSConfig()); err != nil {
		log.Fatalf("Listen: %v", err)
	}
	defer func() { _ = server.Stop() }()
	logf("server listening at %s", server.Addr())

	// 2. Client dials, handshakes, invokes.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := aire.Dial(ctx, server.Addr(), aire.DevTLSConfig())
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}

	state, err := conn.Handshake(ctx, aire.NodeConfig{})
	if err != nil {
		log.Fatalf("client Handshake: %v", err)
	}
	logf("client handshake complete (peer=%s, negotiated=0.%d)", state.PeerNodeID, state.NegotiatedMinor)

	op, err := conn.Invoke(ctx, "stream", "tokens", []byte(strconv.Itoa(nTokens)))
	if err != nil {
		log.Fatalf("Invoke: %v", err)
	}
	_ = op.Close() // FIN our send-side; agent stays alive on its write side
	logf("client invoked stream/tokens (n=%d)", nTokens)

	// 3. Receive cancelAfter tokens, then tear down the connection.
	for i := 1; i <= cancelAfter; i++ {
		f, err := op.Recv()
		if err != nil {
			log.Fatalf("Recv token %d: %v", i, err)
		}
		logf("  client recv token %d: %q", i, f.Payload)
	}

	logf("client cancelling: closing connection after %d/%d tokens", cancelAfter, nTokens)
	logf("(real per-op CANCEL is v0.3; v0.1 simulates by closing the conn)")
	if err := conn.Close(); err != nil {
		logf("client conn.Close: %v", err)
	}

	// Give the server agent a moment to notice the close on its next Send.
	time.Sleep(2 * interval)

	footer()
}

// streamAgent emits n tokens at fixed interval. Returns when its Send fails,
// which happens when the client tears down the connection.
func streamAgent(_ context.Context, inv *aire.Invoke) error {
	n, err := strconv.Atoi(string(inv.Args))
	if err != nil {
		return fmt.Errorf("parse args: %w", err)
	}
	logf("server.stream agent invoked: n=%d", n)

	for i := 1; i <= n; i++ {
		time.Sleep(interval)
		msg := []byte(fmt.Sprintf("token-%d", i))
		if err := inv.Op.Send(aire.Frame{Type: aire.FrameStream, Payload: msg}); err != nil {
			logf("  server send token %d FAILED (client gone): %v", i, err)
			return err
		}
		logf("  server sent token %d", i)
	}
	logf("server.stream agent finished cleanly (n=%d)", n)
	return nil
}

func header() {
	fmt.Println()
	fmt.Println("==========================================================")
	fmt.Println(" AIRE v0.1 demo — two nodes, stream of tokens, cancel-ish")
	fmt.Println("==========================================================")
	fmt.Println()
}

func footer() {
	fmt.Println()
	fmt.Println("==========================================================")
	fmt.Println(" demo complete")
	fmt.Println("==========================================================")
	fmt.Println()
}

func logf(format string, args ...any) {
	prefix := time.Now().Format("15:04:05.000") + " "
	fmt.Printf(prefix+format+"\n", args...)
}
