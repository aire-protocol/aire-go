// Command aire-peers demonstrates two AIRE Nodes — modelling two independent
// Vega-style runtimes — collaborating over AIRE.
//
// Topology:
//
//	[client] ──QUIC──► [vega-A]
//	                      └── coordinator agent
//	                          fans out in parallel to:
//	                            [vega-A] ──QUIC──► [vega-B]
//	                                                  ├── wordcount agent
//	                                                  └── reverse   agent
//
// vega-A's "coordinator" agent, on receiving a request, opens two outbound
// AIRE Operations to vega-B in parallel — one per worker agent. Each rides
// its own QUIC stream, so the faster worker's reply reaches the coordinator
// (and the client) without waiting on the slower one. No head-of-line block.
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	aire "github.com/aire-protocol/aire-go"
)

func main() {
	header()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	vegaB := aire.NewNode(aire.NodeConfig{NodeID: "vega-B"})
	defer func() { _ = vegaB.Stop() }()
	must(vegaB.RegisterAgent("wordcount", aire.AgentFunc(wordcountAgent)))
	must(vegaB.RegisterAgent("reverse", aire.AgentFunc(reverseAgent)))
	must(vegaB.Listen("127.0.0.1:0", aire.DevTLSConfig()))
	logf("[vega-B]   listening at %s   agents=[wordcount, reverse]", vegaB.Addr())

	bConn, err := aire.Dial(ctx, vegaB.Addr(), aire.DevTLSConfig())
	if err != nil {
		log.Fatalf("vega-A → vega-B dial: %v", err)
	}
	defer func() { _ = bConn.Close() }()
	bState, err := bConn.Handshake(ctx, aire.NodeConfig{NodeID: "vega-A"})
	if err != nil {
		log.Fatalf("vega-A → vega-B handshake: %v", err)
	}
	logf("[vega-A]   peer link established to %s (negotiated 0.%d)",
		bState.PeerNodeID, bState.NegotiatedMinor)

	vegaA := aire.NewNode(aire.NodeConfig{NodeID: "vega-A"})
	defer func() { _ = vegaA.Stop() }()
	must(vegaA.RegisterAgent("coordinator", aire.AgentFunc(coordinatorAgent(bConn))))
	must(vegaA.Listen("127.0.0.1:0", aire.DevTLSConfig()))
	logf("[vega-A]   listening at %s   agents=[coordinator]", vegaA.Addr())

	cConn, err := aire.Dial(ctx, vegaA.Addr(), aire.DevTLSConfig())
	if err != nil {
		log.Fatalf("client dial: %v", err)
	}
	defer func() { _ = cConn.Close() }()
	cState, err := cConn.Handshake(ctx, aire.NodeConfig{NodeID: "client"})
	if err != nil {
		log.Fatalf("client handshake: %v", err)
	}
	logf("[client]   handshake complete with %s (negotiated 0.%d)",
		cState.PeerNodeID, cState.NegotiatedMinor)

	sentence := "the quick brown fox jumps over the lazy dog"
	fmt.Println()
	logf("[client]   ▶ invoke coordinator/process(%q)", sentence)

	op, err := cConn.Invoke(ctx, "coordinator", "process", []byte(sentence))
	if err != nil {
		log.Fatalf("client invoke: %v", err)
	}
	_ = op.Close()

	for i := 1; i <= 2; i++ {
		f, err := op.Recv()
		if err != nil {
			log.Fatalf("client recv chunk %d: %v", i, err)
		}
		logf("[client]   ◀ chunk %d: %s", i, f.Payload)
	}

	footer()
}

func coordinatorAgent(bConn *aire.Conn) aire.AgentFunc {
	return func(ctx context.Context, inv *aire.Invoke) error {
		logf(`  [vega-A coord]   received "%s"`, inv.Args)
		logf(`  [vega-A coord]   fanning out to vega-B (parallel) → wordcount + reverse`)

		var wg sync.WaitGroup
		out := make(chan []byte, 2)

		for _, target := range []string{"wordcount", "reverse"} {
			wg.Add(1)
			go func(agentID string) {
				defer wg.Done()
				op, err := bConn.Invoke(ctx, agentID, "go", inv.Args)
				if err != nil {
					logf(`  [vega-A coord]   invoke %s failed: %v`, agentID, err)
					return
				}
				_ = op.Close()
				f, err := op.Recv()
				if err != nil {
					logf(`  [vega-A coord]   recv %s failed: %v`, agentID, err)
					return
				}
				logf(`  [vega-A coord]   got %s reply → forwarding to client`, agentID)
				out <- fmt.Appendf(nil, "%s=%s", agentID, f.Payload)
			}(target)
		}
		go func() { wg.Wait(); close(out) }()

		for chunk := range out {
			if err := inv.Op.Send(aire.Frame{Type: aire.FrameStream, Payload: chunk}); err != nil {
				return err
			}
		}
		return nil
	}
}

func wordcountAgent(_ context.Context, inv *aire.Invoke) error {
	logf(`    [vega-B wordcount]   processing "%s" (simulated work: 200ms)`, inv.Args)
	time.Sleep(200 * time.Millisecond)
	n := len(strings.Fields(string(inv.Args)))
	logf(`    [vega-B wordcount]   → %d`, n)
	return inv.Op.Send(aire.Frame{Type: aire.FrameStream, Payload: fmt.Appendf(nil, "%d", n)})
}

func reverseAgent(_ context.Context, inv *aire.Invoke) error {
	logf(`    [vega-B reverse]     processing "%s" (simulated work: 30ms)`, inv.Args)
	time.Sleep(30 * time.Millisecond)
	r := []rune(string(inv.Args))
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	logf(`    [vega-B reverse]     → "%s"`, string(r))
	return inv.Op.Send(aire.Frame{Type: aire.FrameStream, Payload: []byte(string(r))})
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func logf(format string, args ...any) {
	fmt.Printf(time.Now().Format("15:04:05.000")+"  "+format+"\n", args...)
}

func header() {
	fmt.Println()
	fmt.Println("==================================================================")
	fmt.Println(" AIRE peer demo — two Vega-style nodes collaborating over QUIC")
	fmt.Println("==================================================================")
	fmt.Println()
}

func footer() {
	fmt.Println()
	fmt.Println("==================================================================")
	fmt.Println(" demo complete — agent on vega-A used AIRE to delegate to agents")
	fmt.Println(" on vega-B. fan-out rode independent QUIC streams: the fast")
	fmt.Println(" reply (reverse, 30ms) returned without waiting on the slow one")
	fmt.Println(" (wordcount, 200ms). this is what HTTP cannot give you.")
	fmt.Println("==================================================================")
	fmt.Println()
}
