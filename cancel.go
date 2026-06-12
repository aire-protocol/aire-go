package aire

import (
	"errors"
	"fmt"
)

// CancelReason is a CANCEL frame reason code per spec §7.2.2.
type CancelReason uint64

const (
	ReasonUserCancelled     CancelReason = 0x00
	ReasonDeadlineExceeded  CancelReason = 0x01
	ReasonBudgetExceeded    CancelReason = 0x02
	ReasonUpstreamCancelled CancelReason = 0x03
	ReasonResourceExhausted CancelReason = 0x04
	ReasonInternal          CancelReason = 0x05
)

// String returns the spec name for a reason code, or "vendor(0xNN)" /
// "reserved(0xNN)" for codes outside the standard range.
func (r CancelReason) String() string {
	switch r {
	case ReasonUserCancelled:
		return "USER_CANCELLED"
	case ReasonDeadlineExceeded:
		return "DEADLINE_EXCEEDED"
	case ReasonBudgetExceeded:
		return "BUDGET_EXCEEDED"
	case ReasonUpstreamCancelled:
		return "UPSTREAM_CANCELLED"
	case ReasonResourceExhausted:
		return "RESOURCE_EXHAUSTED"
	case ReasonInternal:
		return "INTERNAL"
	default:
		if r >= 0x40 {
			return fmt.Sprintf("vendor(0x%02x)", uint64(r))
		}
		return fmt.Sprintf("reserved(0x%02x)", uint64(r))
	}
}

// Cancel is the parsed payload of a CANCEL frame per spec §7.2.1.
type Cancel struct {
	Reason CancelReason
	Detail string
}

// Encode serializes c to its wire form per §7.2.1.
//
// Always emits the v0.3 form (Reason + DetailLen + Detail), even when both
// fields are empty. v0.3 receivers MUST accept this; v0.1 receivers will
// silently treat the trailing bytes as opaque.
func (c Cancel) Encode() []byte {
	out := AppendVarint(nil, uint64(c.Reason))
	out = appendString(out, c.Detail)
	return out
}

// DecodeCancel parses a CANCEL frame payload per §7.2.1. An empty payload
// is the v0.1 compatibility form and decodes to USER_CANCELLED with no
// detail.
func DecodeCancel(payload []byte) (Cancel, error) {
	if len(payload) == 0 {
		return Cancel{Reason: ReasonUserCancelled}, nil
	}
	reason, n, err := ReadVarint(payload)
	if err != nil {
		return Cancel{}, fmt.Errorf("aire: CANCEL Reason: %w", err)
	}
	detail, m, err := readString(payload[n:])
	if err != nil {
		return Cancel{}, fmt.Errorf("aire: CANCEL Detail: %w", err)
	}
	if n+m != len(payload) {
		return Cancel{}, fmt.Errorf("aire: CANCEL: %d trailing bytes after Detail", len(payload)-(n+m))
	}
	return Cancel{Reason: CancelReason(reason), Detail: detail}, nil
}

// Operation error codes per spec §7.2.6. These share the §4.7 / §5.4.7
// registry (a single ERROR-frame `code` namespace).
const (
	ErrCodeCancelled        uint64 = 0x0A
	ErrCodeBudgetExceeded   uint64 = 0x0B
	ErrCodeDeadlineExceeded uint64 = 0x0C
	ErrCodeDelegateFailed   uint64 = 0x0D
)

// Operation error sentinels.
var (
	ErrCancelled        = errors.New("aire: operation cancelled")
	ErrBudgetExceeded   = errors.New("aire: budget exceeded")
	ErrDeadlineExceeded = errors.New("aire: deadline exceeded")
	ErrDelegateFailed   = errors.New("aire: delegate failed")
)
