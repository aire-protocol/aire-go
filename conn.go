package aire

// Conn is an AIRE connection riding on a single QUIC connection between two
// nodes. A Conn multiplexes many Operations across QUIC streams.
type Conn struct{}
