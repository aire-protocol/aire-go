package aire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBudget_RoundTrip(t *testing.T) {
	cases := []Budget{
		{Tokens: ptrU64(1000)},
		{CostMicrounits: ptrU64(5000), Currency: "USD"},
		{Tokens: ptrU64(1000), CostMicrounits: ptrU64(5000), Currency: "USD"},
		{DeadlineMS: ptrI64(1798761599999)},
		{Tokens: ptrU64(42), DeadlineMS: ptrI64(1798761599999)},
	}
	for _, c := range cases {
		encoded := c.Encode()
		got, err := DecodeBudget(encoded)
		if err != nil {
			t.Fatalf("decode %+v: %v", c, err)
		}
		if !budgetEqual(got, c) {
			t.Errorf("roundtrip:\n  want %+v\n  got  %+v", c, got)
		}
	}
}

func TestBudget_EmptyPayloadIsMalformed(t *testing.T) {
	// §8.1: a BUDGET payload MUST contain at least one entry. NumEntry=0
	// is malformed.
	_, err := DecodeBudget([]byte{0x00})
	if err == nil {
		t.Errorf("expected error for empty BUDGET, got nil")
	}
}

func TestBudget_DuplicateFieldIDIsMalformed(t *testing.T) {
	// NumEntry=2, both TOKENS_REMAINING — §8.1 says reject.
	payload := []byte{
		0x02,             // NumEntry = 2
		0x01, 0x01, 0x05, // Entry 1: TOKENS, Length=1, Value=5
		0x01, 0x01, 0x07, // Entry 2: TOKENS again, Length=1, Value=7 — duplicate
	}
	if _, err := DecodeBudget(payload); err == nil {
		t.Errorf("expected error for duplicate FieldID, got nil")
	}
}

func TestBudget_UnknownFieldIDTolerated(t *testing.T) {
	// §8.1: receivers MUST tolerate unknown FieldIDs by skipping via Length.
	payload := []byte{
		0x02,                   // NumEntry = 2
		0x7F, 0x02, 0xDE, 0xAD, // Entry 1: unknown FieldID=0x7F, Length=2, 2 bytes value
		0x01, 0x01, 0x2A, // Entry 2: TOKENS=42
	}
	got, err := DecodeBudget(payload)
	if err != nil {
		t.Fatalf("decode with unknown FieldID: %v", err)
	}
	if got.Tokens == nil || *got.Tokens != 42 {
		t.Errorf("expected Tokens=42, got %+v", got.Tokens)
	}
}

func TestBudget_ConformanceVectors(t *testing.T) {
	want := map[string]Budget{
		"budget-tokens-cost-currency": {
			Tokens:         ptrU64(1000),
			CostMicrounits: ptrU64(5000),
			Currency:       "USD",
		},
		"budget-deadline-only": {
			DeadlineMS: ptrI64(1798761599999),
		},
	}
	for _, v := range loadV03(t).Vectors {
		if v.Frame.TypeName != "BUDGET" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			payload, _ := hex.DecodeString(v.Frame.PayloadHex)
			got, err := DecodeBudget(payload)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !budgetEqual(got, want[v.ID]) {
				t.Errorf("decoded %+v, want %+v", got, want[v.ID])
			}
			encoded := got.Encode()
			if !bytes.Equal(encoded, payload) {
				t.Errorf("encode mismatch:\n  want: %x\n  got:  %x", payload, encoded)
			}
		})
	}
}

func TestBudgetFieldIDs(t *testing.T) {
	want := map[string]uint8{
		"TOKENS_REMAINING":          0x01,
		"COST_MICROUNITS_REMAINING": 0x02,
		"CURRENCY":                  0x03,
		"DEADLINE_MS":               0x04,
	}
	got := map[string]uint8{
		"TOKENS_REMAINING":          BudgetFieldTokensRemaining,
		"COST_MICROUNITS_REMAINING": BudgetFieldCostMicrounitsRemaining,
		"CURRENCY":                  BudgetFieldCurrency,
		"DEADLINE_MS":               BudgetFieldDeadlineMS,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = 0x%02x, want 0x%02x", k, got[k], v)
		}
	}
}

func ptrU64(v uint64) *uint64 { return &v }
func ptrI64(v int64) *int64   { return &v }

func budgetEqual(a, b Budget) bool {
	return ptrU64Eq(a.Tokens, b.Tokens) &&
		ptrU64Eq(a.CostMicrounits, b.CostMicrounits) &&
		a.Currency == b.Currency &&
		ptrI64Eq(a.DeadlineMS, b.DeadlineMS)
}

func ptrU64Eq(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func ptrI64Eq(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
