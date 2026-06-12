package aire

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateCapabilityName_Valid(t *testing.T) {
	cases := []string{
		"aire.did-method.web/1",
		"aire.did-method.key/1",
		"com.example.foo/1",
		"com.example.foo/0",
		"a/1",
		"a.b/9",
		"com.example.feature-x.y2/12345",
	}
	for _, c := range cases {
		if err := ValidateCapabilityName(c); err != nil {
			t.Errorf("ValidateCapabilityName(%q) = %v, want nil", c, err)
		}
	}
}

func TestValidateCapabilityName_Invalid(t *testing.T) {
	cases := []struct {
		name string
		why  string
	}{
		{"", "empty"},
		{"foo", "missing major"},
		{"foo/", "empty major"},
		{"foo/01", "leading-zero major"},
		{"foo/-1", "negative major"},
		{"foo/bar", "non-numeric major"},
		{".foo/1", "leading dot"},
		{"foo./1", "trailing dot"},
		{"foo..bar/1", "double dot"},
		{"foo/1/2", "multiple slashes"},
		{"1foo/1", "label starts with digit"},
		{"-foo/1", "label starts with dash"},
		{"foo bar/1", "space in label"},
		{strings.Repeat("a.", 130) + "x/1", "exceeds 255 bytes"},
	}
	for _, c := range cases {
		if err := ValidateCapabilityName(c.name); err == nil {
			t.Errorf("ValidateCapabilityName(%q) = nil, want error (%s)", c.name, c.why)
		}
	}
}

func TestIsReservedNamespace(t *testing.T) {
	cases := []struct {
		name     string
		reserved bool
	}{
		{"aire.foo/1", true},
		{"aire.did-method.web/1", true},
		{"aire/1", true}, // first label is exactly "aire"
		{"airetech.foo/1", false},
		{"com.example.foo/1", false},
		{"com.aire.foo/1", false},
	}
	for _, c := range cases {
		if got := IsReservedNamespace(c.name); got != c.reserved {
			t.Errorf("IsReservedNamespace(%q) = %v, want %v", c.name, got, c.reserved)
		}
	}
}

func TestNegotiateCapabilities_NameOnlyMatch_MinorDowngrade(t *testing.T) {
	local := []Capability{{Name: "com.example.foo/1", Version: 5}}
	peer := []Capability{{Name: "com.example.foo/1", Version: 2}}
	active, err := NegotiateCapabilities(local, peer)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("active len = %d, want 1; got %+v", len(active), active)
	}
	if active[0].Name != "com.example.foo/1" || active[0].Version != 2 {
		t.Errorf("active[0] = %+v, want {com.example.foo/1, minor=2}", active[0])
	}
}

func TestNegotiateCapabilities_DifferentMajors_NoMatch(t *testing.T) {
	local := []Capability{{Name: "com.example.foo/1", Version: 0}}
	peer := []Capability{{Name: "com.example.foo/2", Version: 0}}
	active, err := NegotiateCapabilities(local, peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Errorf("active = %+v, want empty (different majors)", active)
	}
}

func TestNegotiateCapabilities_RequiredSatisfiedOnNameMatch(t *testing.T) {
	// Per §4.5.3: required check is name-only. Minor mismatch does not fail it.
	local := []Capability{{Name: "com.example.foo/1", Version: 5, Required: true}}
	peer := []Capability{{Name: "com.example.foo/1", Version: 2}}
	active, err := NegotiateCapabilities(local, peer)
	if err != nil {
		t.Fatalf("required-on-name should be satisfied: %v", err)
	}
	if len(active) != 1 || active[0].Version != 2 {
		t.Errorf("active = %+v, want minor=2", active)
	}
}

func TestNegotiateCapabilities_RequiredFails_DifferentMajor(t *testing.T) {
	local := []Capability{{Name: "com.example.foo/1", Version: 0, Required: true}}
	peer := []Capability{{Name: "com.example.foo/2", Version: 0}}
	_, err := NegotiateCapabilities(local, peer)
	if !errors.Is(err, ErrMissingRequiredCapability) {
		t.Errorf("got err=%v, want ErrMissingRequiredCapability", err)
	}
}

func TestNegotiateCapabilities_PeerRequiredFails(t *testing.T) {
	local := []Capability{{Name: "other/1", Version: 0}}
	peer := []Capability{{Name: "must-have/1", Version: 0, Required: true}}
	_, err := NegotiateCapabilities(local, peer)
	if !errors.Is(err, ErrMissingRequiredCapability) {
		t.Errorf("got err=%v, want ErrMissingRequiredCapability", err)
	}
}

func TestNegotiateCapabilities_DuplicateNameLocal_Malformed(t *testing.T) {
	local := []Capability{
		{Name: "com.example.foo/1", Version: 0},
		{Name: "com.example.foo/1", Version: 0},
	}
	peer := []Capability{{Name: "com.example.foo/1", Version: 0}}
	_, err := NegotiateCapabilities(local, peer)
	if !errors.Is(err, ErrMalformedHello) {
		t.Errorf("got err=%v, want ErrMalformedHello (duplicate name in local)", err)
	}
}

func TestNegotiateCapabilities_DuplicateNamePeer_Malformed(t *testing.T) {
	local := []Capability{{Name: "com.example.foo/1", Version: 0}}
	peer := []Capability{
		{Name: "com.example.foo/1", Version: 0},
		{Name: "com.example.foo/1", Version: 0},
	}
	_, err := NegotiateCapabilities(local, peer)
	if !errors.Is(err, ErrMalformedHello) {
		t.Errorf("got err=%v, want ErrMalformedHello (duplicate name in peer)", err)
	}
}

func TestNegotiateCapabilities_MultipleMajors_DistinctMatches(t *testing.T) {
	// Same namespace at multiple majors is two distinct capabilities.
	local := []Capability{
		{Name: "com.example.foo/1", Version: 0},
		{Name: "com.example.foo/2", Version: 0},
	}
	peer := []Capability{
		{Name: "com.example.foo/1", Version: 0},
		{Name: "com.example.foo/2", Version: 0},
	}
	active, err := NegotiateCapabilities(local, peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Errorf("active len = %d, want 2; got %+v", len(active), active)
	}
}

func TestNegotiateCapabilities_NonConformingNamesTolerated(t *testing.T) {
	// Receivers MUST accept any UTF-8 bytes in name (§4.5.1). Non-conforming
	// names that match byte-for-byte still appear in the active set.
	local := []Capability{{Name: "core.streaming", Version: 1}}
	peer := []Capability{{Name: "core.streaming", Version: 1}}
	active, err := NegotiateCapabilities(local, peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Name != "core.streaming" {
		t.Errorf("active = %+v, want [core.streaming]", active)
	}
}

func TestStandardCapabilityNames(t *testing.T) {
	// §4.6 registry — confirm exported constants exist and validate.
	for _, name := range []string{CapDIDMethodWeb, CapDIDMethodKey} {
		if err := ValidateCapabilityName(name); err != nil {
			t.Errorf("standard capability %q invalid: %v", name, err)
		}
		if !IsReservedNamespace(name) {
			t.Errorf("standard capability %q must be under reserved aire. namespace", name)
		}
	}
}
