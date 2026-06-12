package aire

import (
	"errors"
	"fmt"
	"strings"
)

// Capability is one capability advertisement, per spec §4.3.
//
// The advertisement carries three fields on the wire: the full Name (which
// includes the major version as the "/<N>" suffix per §4.5.1), a Version
// varint that carries the minor version, and a Required bit.
//
// In the active set returned by NegotiateCapabilities, the Version field
// holds the negotiated minor min(local, peer), and the Required field is
// unused.
type Capability struct {
	Name     string
	Version  uint64
	Required bool
}

// Standard capabilities registered by the AIRE specification (§4.6).
const (
	CapDIDMethodWeb = "aire.did-method.web/1"
	CapDIDMethodKey = "aire.did-method.key/1"
)

// MaxCapabilityNameBytes is the upper bound on a capability name's UTF-8
// byte length per spec §4.5.1.
const MaxCapabilityNameBytes = 255

// ValidateCapabilityName checks name against the §4.5.1 grammar. Returns
// nil for conforming names and a descriptive error otherwise.
//
// Receivers MUST tolerate non-conforming names from peers (treating them
// as opaque and unmatched); this function is for senders verifying their
// own configuration before advertising.
func ValidateCapabilityName(name string) error {
	if name == "" {
		return errors.New("aire: capability name is empty")
	}
	if len(name) > MaxCapabilityNameBytes {
		return fmt.Errorf("aire: capability name %q exceeds %d bytes", name, MaxCapabilityNameBytes)
	}
	slash := strings.IndexByte(name, '/')
	if slash < 0 {
		return fmt.Errorf("aire: capability name %q missing '/<major>' suffix", name)
	}
	namespace := name[:slash]
	major := name[slash+1:]
	if namespace == "" {
		return fmt.Errorf("aire: capability name %q has empty namespace", name)
	}
	if major == "" {
		return fmt.Errorf("aire: capability name %q has empty major", name)
	}
	if strings.IndexByte(major, '/') >= 0 {
		return fmt.Errorf("aire: capability name %q contains multiple '/' separators", name)
	}
	if err := validateNamespace(namespace); err != nil {
		return fmt.Errorf("aire: capability name %q: %w", name, err)
	}
	if err := validateMajor(major); err != nil {
		return fmt.Errorf("aire: capability name %q: %w", name, err)
	}
	return nil
}

func validateNamespace(ns string) error {
	if ns == "" {
		return errors.New("empty namespace")
	}
	labels := strings.Split(ns, ".")
	for i, label := range labels {
		if label == "" {
			return fmt.Errorf("namespace has empty label at position %d", i)
		}
		if !isAlpha(label[0]) {
			return fmt.Errorf("namespace label %q must begin with ALPHA", label)
		}
		for _, b := range []byte(label[1:]) {
			if !isAlpha(b) && !isDigit(b) && b != '-' {
				return fmt.Errorf("namespace label %q has invalid byte 0x%02x", label, b)
			}
		}
	}
	return nil
}

func validateMajor(s string) error {
	if s == "" {
		return errors.New("empty major")
	}
	if len(s) > 1 && s[0] == '0' {
		return fmt.Errorf("major %q has leading zero", s)
	}
	for _, b := range []byte(s) {
		if !isDigit(b) {
			return fmt.Errorf("major %q has non-digit byte 0x%02x", s, b)
		}
	}
	return nil
}

func isAlpha(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// IsReservedNamespace reports whether name's first namespace label is
// exactly "aire" — the namespace reserved for capabilities defined by the
// AIRE specification (§4.5.1, §4.6). Implementations other than the spec
// MUST NOT advertise names under this namespace.
//
// Non-conforming names (those that would not pass ValidateCapabilityName)
// still get a best-effort check on their first dotted label.
func IsReservedNamespace(name string) bool {
	ns := name
	if slash := strings.IndexByte(ns, '/'); slash >= 0 {
		ns = ns[:slash]
	}
	first := ns
	if dot := strings.IndexByte(ns, '.'); dot >= 0 {
		first = ns[:dot]
	}
	return first == "aire"
}

// NegotiateCapabilities computes the active capability set per spec §4.5.
//
// Two advertisements match iff their full Name fields are byte-equal
// (different majors are different capabilities). The negotiated minor is
// min(local.Version, peer.Version). If either side advertised a name with
// Required=true and that name is not in the active set, the call returns
// ErrMissingRequiredCapability. Duplicate names within either side's list
// return ErrMalformedHello.
//
// The active set order mirrors local's order for deterministic display.
func NegotiateCapabilities(local, peer []Capability) ([]Capability, error) {
	localByName, err := indexCapabilities(local, "local")
	if err != nil {
		return nil, err
	}
	peerByName, err := indexCapabilities(peer, "peer")
	if err != nil {
		return nil, err
	}

	active := make([]Capability, 0, len(local))
	for _, lc := range local {
		pc, ok := peerByName[lc.Name]
		if !ok {
			continue
		}
		minor := lc.Version
		if pc.Version < minor {
			minor = pc.Version
		}
		active = append(active, Capability{Name: lc.Name, Version: minor})
	}

	for _, lc := range local {
		if !lc.Required {
			continue
		}
		if _, ok := peerByName[lc.Name]; !ok {
			return nil, fmt.Errorf("%w: local requires %q", ErrMissingRequiredCapability, lc.Name)
		}
	}
	for _, pc := range peer {
		if !pc.Required {
			continue
		}
		if _, ok := localByName[pc.Name]; !ok {
			return nil, fmt.Errorf("%w: peer requires %q", ErrMissingRequiredCapability, pc.Name)
		}
	}
	return active, nil
}

func indexCapabilities(caps []Capability, side string) (map[string]Capability, error) {
	idx := make(map[string]Capability, len(caps))
	for _, c := range caps {
		if _, dup := idx[c.Name]; dup {
			return nil, fmt.Errorf("%w: %s side has duplicate capability name %q", ErrMalformedHello, side, c.Name)
		}
		idx[c.Name] = c
	}
	return idx, nil
}
