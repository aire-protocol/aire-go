package aire

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
)

// Agent handles AIRE operations addressed to it. The Handle method is called
// once per inbound Operation after the INVOKE frame has been received and
// decoded.
type Agent interface {
	Handle(ctx context.Context, inv *Invoke) error
}

// AgentFunc adapts a function to the Agent interface.
type AgentFunc func(ctx context.Context, inv *Invoke) error

// Handle calls f.
func (f AgentFunc) Handle(ctx context.Context, inv *Invoke) error {
	return f(ctx, inv)
}

// Invoke is the decoded contents of an INVOKE frame plus the live Operation
// over which the agent can stream responses, read further client frames, or
// emit errors.
type Invoke struct {
	AgentID   string
	Operation string
	Args      []byte
	Op        *Operation

	// PeerNodeID is the authenticated DID of the peer that sent the INVOKE,
	// as established by the connection's signed HELLO (§5.4). Agents SHOULD
	// authorize against this rather than any identity claimed in Args.
	PeerNodeID string
}

// Node is a local AIRE runtime: it listens for inbound connections, completes
// the §4 handshake, accepts incoming Operations, and dispatches them to
// registered Agents based on the AgentID in each INVOKE frame.
type Node struct {
	cfg      NodeConfig
	listener *Listener

	mu     sync.RWMutex
	agents map[string]Agent

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	started bool
	stopped bool
}

// NewNode creates a Node with the given configuration.
func NewNode(cfg NodeConfig) *Node {
	ctx, cancel := context.WithCancel(context.Background())
	return &Node{
		cfg:    cfg,
		agents: make(map[string]Agent),
		ctx:    ctx,
		cancel: cancel,
	}
}

// RegisterAgent registers an Agent under the given ID. Returns an error if
// the ID is empty or already registered.
func (n *Node) RegisterAgent(id string, a Agent) error {
	if id == "" {
		return errors.New("aire: RegisterAgent: empty ID")
	}
	if a == nil {
		return errors.New("aire: RegisterAgent: nil Agent")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, exists := n.agents[id]; exists {
		return fmt.Errorf("aire: RegisterAgent: %q already registered", id)
	}
	n.agents[id] = a
	return nil
}

// Listen starts the Node accepting inbound connections on addr. Returns when
// the listener is set up; the accept loop runs in the background until Stop.
func (n *Node) Listen(addr string, tlsConf *tls.Config) error {
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return errors.New("aire: Listen: already started")
	}
	if n.stopped {
		n.mu.Unlock()
		return errors.New("aire: Listen: node already stopped")
	}
	n.started = true
	n.mu.Unlock()

	listener, err := Listen(addr, tlsConf)
	if err != nil {
		return err
	}
	n.listener = listener

	n.wg.Add(1)
	go n.acceptLoop()
	return nil
}

// Addr returns the listener's network address. Only valid after Listen.
func (n *Node) Addr() string {
	if n.listener == nil {
		return ""
	}
	return n.listener.Addr().String()
}

// Stop stops the Node. The listener is closed and the accept loop exits;
// in-flight Operations are allowed to continue until they complete naturally
// or their connection's context is cancelled by peer close.
func (n *Node) Stop() error {
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return nil
	}
	n.stopped = true
	n.mu.Unlock()

	n.cancel()
	if n.listener != nil {
		_ = n.listener.Close()
	}
	n.wg.Wait()
	return nil
}

func (n *Node) acceptLoop() {
	defer n.wg.Done()
	for {
		conn, err := n.listener.Accept(n.ctx)
		if err != nil {
			return
		}
		n.wg.Add(1)
		go n.handleConn(conn)
	}
}

func (n *Node) handleConn(conn *Conn) {
	defer n.wg.Done()
	defer func() { _ = conn.Close() }()

	if _, err := conn.Handshake(n.ctx, n.cfg); err != nil {
		return
	}

	for {
		op, err := conn.AcceptOperation(n.ctx)
		if err != nil {
			return
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.handleOperation(op)
		}()
	}
}

func (n *Node) handleOperation(op *Operation) {
	f, err := op.Recv()
	if err != nil {
		_ = op.Close()
		return
	}
	if f.Type != FrameInvoke {
		_ = op.Close()
		return
	}
	agentID, opName, args, err := decodeInvokePayload(f.Payload)
	if err != nil {
		_ = op.Close()
		return
	}

	n.mu.RLock()
	agent, ok := n.agents[agentID]
	n.mu.RUnlock()
	if !ok {
		_ = op.Close()
		return
	}

	inv := &Invoke{
		AgentID:    agentID,
		Operation:  opName,
		Args:       args,
		Op:         op,
		PeerNodeID: op.PeerNodeID(),
	}
	_ = agent.Handle(n.ctx, inv)
	_ = op.Close()
}

// encodeInvokePayload encodes an INVOKE frame payload as
// <agent-id: string><operation: string><args: remaining bytes>.
func encodeInvokePayload(agentID, opName string, args []byte) []byte {
	var buf []byte
	buf = appendString(buf, agentID)
	buf = appendString(buf, opName)
	buf = append(buf, args...)
	return buf
}

// decodeInvokePayload decodes the INVOKE payload encoded by encodeInvokePayload.
func decodeInvokePayload(payload []byte) (string, string, []byte, error) {
	agentID, n, err := readString(payload)
	if err != nil {
		return "", "", nil, fmt.Errorf("aire: INVOKE: agent-id: %w", err)
	}
	opName, m, err := readString(payload[n:])
	if err != nil {
		return "", "", nil, fmt.Errorf("aire: INVOKE: operation: %w", err)
	}
	args := append([]byte(nil), payload[n+m:]...)
	return agentID, opName, args, nil
}

// Invoke opens a new operation on c and emits an INVOKE frame addressed to
// the given agent and operation name with the given args. The returned
// Operation is the handle for receiving responses and (optionally) sending
// further frames.
func (c *Conn) Invoke(ctx context.Context, agentID, opName string, args []byte) (*Operation, error) {
	op, err := c.NewOperation(ctx)
	if err != nil {
		return nil, err
	}
	payload := encodeInvokePayload(agentID, opName, args)
	if err := op.Send(Frame{Type: FrameInvoke, Payload: payload}); err != nil {
		_ = op.Close()
		return nil, err
	}
	return op, nil
}
