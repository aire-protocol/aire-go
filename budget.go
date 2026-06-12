package aire

import (
	"encoding/binary"
	"fmt"
)

// BUDGET frame field identifiers per spec §8.2.
const (
	BudgetFieldTokensRemaining         uint8 = 0x01
	BudgetFieldCostMicrounitsRemaining uint8 = 0x02
	BudgetFieldCurrency                uint8 = 0x03
	BudgetFieldDeadlineMS              uint8 = 0x04
)

// Budget is a parsed BUDGET frame payload per spec §8.
//
// Each pointer field is nil when the corresponding entry was absent from
// the wire. Currency is the empty string when absent. A receiver MAY
// interpret an absent field as "no constraint declared on this dimension."
type Budget struct {
	Tokens         *uint64 // §8.2 TOKENS_REMAINING
	CostMicrounits *uint64 // §8.2 COST_MICROUNITS_REMAINING (currency in Currency)
	Currency       string  // §8.2 CURRENCY (ISO 4217 ASCII, e.g. "USD")
	DeadlineMS     *int64  // §8.2 DEADLINE_MS (UTC milliseconds since epoch)
}

// Encode serializes b to its wire form per §8.1.
//
// Entries are emitted in canonical FieldID order to keep encodings
// deterministic. The order matters only for byte-level conformance; a
// receiver MUST accept entries in any order (§8.1).
func (b Budget) Encode() []byte {
	type entry struct {
		fid   uint8
		value []byte
	}
	var entries []entry
	if b.Tokens != nil {
		entries = append(entries, entry{BudgetFieldTokensRemaining, AppendVarint(nil, *b.Tokens)})
	}
	if b.CostMicrounits != nil {
		entries = append(entries, entry{BudgetFieldCostMicrounitsRemaining, AppendVarint(nil, *b.CostMicrounits)})
	}
	if b.Currency != "" {
		entries = append(entries, entry{BudgetFieldCurrency, []byte(b.Currency)})
	}
	if b.DeadlineMS != nil {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(*b.DeadlineMS))
		entries = append(entries, entry{BudgetFieldDeadlineMS, buf[:]})
	}
	out := AppendVarint(nil, uint64(len(entries)))
	for _, e := range entries {
		out = append(out, e.fid)
		out = AppendVarint(out, uint64(len(e.value)))
		out = append(out, e.value...)
	}
	return out
}

// DecodeBudget parses a BUDGET frame payload per §8.1.
//
// Returns an error if the payload contains zero entries (§8.1 requires at
// least one), if any FieldID appears more than once (§8.1 forbids
// duplicates), or if the structure is truncated. Unknown FieldIDs are
// skipped via their Length (§8.1).
func DecodeBudget(payload []byte) (Budget, error) {
	num, n, err := ReadVarint(payload)
	if err != nil {
		return Budget{}, fmt.Errorf("aire: BUDGET NumEntry: %w", err)
	}
	if num == 0 {
		return Budget{}, fmt.Errorf("aire: BUDGET payload has zero entries")
	}
	pos := n

	var b Budget
	seen := make(map[uint8]bool, num)
	for i := uint64(0); i < num; i++ {
		if pos >= len(payload) {
			return Budget{}, fmt.Errorf("aire: BUDGET entry %d: missing FieldID", i)
		}
		fid := payload[pos]
		pos++
		length, m, err := ReadVarint(payload[pos:])
		if err != nil {
			return Budget{}, fmt.Errorf("aire: BUDGET entry %d Length: %w", i, err)
		}
		pos += m
		if uint64(len(payload)-pos) < length {
			return Budget{}, fmt.Errorf("aire: BUDGET entry %d Value: short", i)
		}
		value := payload[pos : pos+int(length)]
		pos += int(length)

		if seen[fid] {
			return Budget{}, fmt.Errorf("aire: BUDGET entry %d: duplicate FieldID 0x%02x", i, fid)
		}
		seen[fid] = true

		switch fid {
		case BudgetFieldTokensRemaining:
			v, _, err := ReadVarint(value)
			if err != nil {
				return Budget{}, fmt.Errorf("aire: BUDGET TOKENS_REMAINING value: %w", err)
			}
			b.Tokens = &v
		case BudgetFieldCostMicrounitsRemaining:
			v, _, err := ReadVarint(value)
			if err != nil {
				return Budget{}, fmt.Errorf("aire: BUDGET COST_MICROUNITS value: %w", err)
			}
			b.CostMicrounits = &v
		case BudgetFieldCurrency:
			if len(value) != 3 {
				return Budget{}, fmt.Errorf("aire: BUDGET CURRENCY value length %d, want 3 (ISO 4217)", len(value))
			}
			b.Currency = string(value)
		case BudgetFieldDeadlineMS:
			if len(value) != 8 {
				return Budget{}, fmt.Errorf("aire: BUDGET DEADLINE_MS value length %d, want 8", len(value))
			}
			d := int64(binary.BigEndian.Uint64(value))
			b.DeadlineMS = &d
		default:
			// Unknown FieldID — already skipped via Length.
		}
	}
	if pos != len(payload) {
		return Budget{}, fmt.Errorf("aire: BUDGET: %d trailing bytes after entries", len(payload)-pos)
	}
	return b, nil
}
