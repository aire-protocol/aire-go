package aire

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ALPN is the TLS Application-Layer Protocol Negotiation identifier for AIRE.
const ALPN = "aire/v0"

// DevTLSConfig returns a self-signed TLS config suitable for development and
// tests. NOT FOR PRODUCTION USE: it sets InsecureSkipVerify on the client side
// and uses an in-memory ephemeral certificate.
func DevTLSConfig() *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("aire: DevTLSConfig: ecdsa.GenerateKey: %v", err))
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "aire-dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost", "aire-dev"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		panic(fmt.Sprintf("aire: DevTLSConfig: CreateCertificate: %v", err))
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic(fmt.Sprintf("aire: DevTLSConfig: MarshalECPrivateKey: %v", err))
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(fmt.Sprintf("aire: DevTLSConfig: X509KeyPair: %v", err))
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, //nolint:gosec // dev helper
		NextProtos:         []string{ALPN},
		MinVersion:         tls.VersionTLS13,
	}
}

// Listener accepts incoming AIRE connections over QUIC.
type Listener struct {
	ql *quic.Listener
}

// Listen binds an AIRE listener to addr (e.g., ":4433"). The TLS config's
// NextProtos MUST include ALPN.
func Listen(addr string, tlsConf *tls.Config) (*Listener, error) {
	ql, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		return nil, fmt.Errorf("aire: Listen %s: %w", addr, err)
	}
	return &Listener{ql: ql}, nil
}

// Accept blocks until an incoming AIRE connection arrives.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	qc, err := l.ql.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("aire: Accept: %w", err)
	}
	return &Conn{qc: qc}, nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.ql.Addr()
}

// Close stops the listener.
func (l *Listener) Close() error {
	return l.ql.Close()
}

// Conn is an AIRE connection riding on a single QUIC connection between two
// nodes (spec §1.3).
type Conn struct {
	qc *quic.Conn
}

// Dial opens an AIRE connection to addr.
func Dial(ctx context.Context, addr string, tlsConf *tls.Config) (*Conn, error) {
	qc, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		return nil, fmt.Errorf("aire: Dial %s: %w", addr, err)
	}
	return &Conn{qc: qc}, nil
}

// OpenStream opens a new bidirectional QUIC stream within the connection.
// Each AIRE Operation gets its own stream (spec §2.4).
func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	qs, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("aire: OpenStream: %w", err)
	}
	return &Stream{qs: qs}, nil
}

// AcceptStream blocks until the peer opens a new stream.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	qs, err := c.qc.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("aire: AcceptStream: %w", err)
	}
	return &Stream{qs: qs}, nil
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.qc.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.qc.RemoteAddr()
}

// Close gracefully closes the connection with QUIC application error code 0.
func (c *Conn) Close() error {
	return c.qc.CloseWithError(0, "")
}

// Stream is a QUIC stream within an AIRE connection. It carries a sequence
// of AIRE frames per spec §2.3 and §2.4.
type Stream struct {
	qs *quic.Stream
}

// SendFrame writes f to the stream, encoded per spec §2.1.
func (s *Stream) SendFrame(f Frame) error {
	if _, err := s.qs.Write(f.Encode()); err != nil {
		return fmt.Errorf("aire: SendFrame: %w", err)
	}
	return nil
}

// RecvFrame reads the next frame from the stream. Returns io.EOF if the peer
// FINs the stream cleanly between frames.
func (s *Stream) RecvFrame() (Frame, error) {
	return readFrame(s.qs)
}

// Close closes the send-side of the stream (FIN). The receive-side closes
// when the peer sends its FIN.
func (s *Stream) Close() error {
	return s.qs.Close()
}

// readFrame reads a single frame from r in a streaming manner.
func readFrame(r io.Reader) (Frame, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	f := Frame{
		Type:  FrameType(header[0]),
		Flags: header[1],
	}
	opid, err := readVarintFrom(r)
	if err != nil {
		return Frame{}, err
	}
	f.OpID = opid
	plen, err := readVarintFrom(r)
	if err != nil {
		return Frame{}, err
	}
	if plen > MaxFrameSize {
		return Frame{}, ErrFrameTooLarge
	}
	if plen > 0 {
		f.Payload = make([]byte, plen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// readVarintFrom reads a QUIC-style varint from r, consuming the appropriate
// number of bytes based on the leading 2 bits of the first byte.
func readVarintFrom(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	var size int
	switch first[0] >> 6 {
	case 0:
		return uint64(first[0] & 0x3F), nil
	case 1:
		size = 2
	case 2:
		size = 4
	case 3:
		size = 8
	}
	buf := make([]byte, size)
	buf[0] = first[0]
	if _, err := io.ReadFull(r, buf[1:]); err != nil {
		return 0, err
	}
	v, _, err := ReadVarint(buf)
	return v, err
}
