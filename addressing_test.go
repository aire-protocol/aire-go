package aire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// === pure-function tests ===

func TestDidWebToURL(t *testing.T) {
	cases := []struct {
		did  string
		want string
	}{
		{"did:web:example.com", "https://example.com/.well-known/did.json"},
		{"did:web:example.com:agents:alice", "https://example.com/agents/alice/did.json"},
		{"did:web:example.com%3A8443:u:bob", "https://example.com:8443/u/bob/did.json"},
		{"did:web:aire.example.com:agents:summarizer", "https://aire.example.com/agents/summarizer/did.json"},
	}
	for _, c := range cases {
		got, err := didWebToURL(c.did)
		if err != nil {
			t.Errorf("didWebToURL(%q): unexpected err: %v", c.did, err)
			continue
		}
		if got != c.want {
			t.Errorf("didWebToURL(%q) = %q, want %q", c.did, got, c.want)
		}
	}
}

func TestDidWebToURL_Errors(t *testing.T) {
	bad := []string{"", "did:web:", "did:key:abc", "did:web"}
	for _, s := range bad {
		if _, err := didWebToURL(s); err == nil {
			t.Errorf("didWebToURL(%q) expected error", s)
		}
	}
}

func TestParseHandle(t *testing.T) {
	cases := []struct {
		in              string
		wantLocal, wantDomain string
		wantErr         bool
	}{
		{"summarizer@aire.example.com", "summarizer", "aire.example.com", false},
		{"@summarizer@aire.example.com", "summarizer", "aire.example.com", false},
		{"x@y", "x", "y", false},
		{"a.b-c_d@host.tld", "a.b-c_d", "host.tld", false},
		{"", "", "", true},
		{"@", "", "", true},
		{"noat", "", "", true},
		{"@noat", "", "", true},
		{"too@many@", "", "", true},
		{"@local@", "", "", true},
	}
	for _, c := range cases {
		l, d, err := parseHandle(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseHandle(%q) expected error, got (%q, %q)", c.in, l, d)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseHandle(%q): unexpected err: %v", c.in, err)
			continue
		}
		if l != c.wantLocal || d != c.wantDomain {
			t.Errorf("parseHandle(%q) = (%q, %q), want (%q, %q)", c.in, l, d, c.wantLocal, c.wantDomain)
		}
	}
}

func TestParseTXTDIDValue(t *testing.T) {
	if got, err := parseTXTDIDValue("did=did:web:example.com"); err != nil || got != "did:web:example.com" {
		t.Errorf("parseTXTDIDValue ok case: got (%q, %v)", got, err)
	}
	for _, bad := range []string{"", "did=", "did:web:nope", "DID=did:web:x", "  did=x"} {
		if _, err := parseTXTDIDValue(bad); err == nil {
			t.Errorf("parseTXTDIDValue(%q) expected error", bad)
		}
	}
}

func TestPickAIREv1(t *testing.T) {
	doc := &didDocument{
		ID: "did:web:aire.example.com:agents:summarizer",
		Service: []serviceEntry{
			{Type: "Other", ServiceEndpoint: []serviceEndpoint{{URI: "ignored"}}},
			{Type: "AIREv1", ServiceEndpoint: []serviceEndpoint{
				{URI: "aire://aire.example.com:4433", Accept: []string{"aire/v0.2", "aire/v0.1"}, AgentID: "summarizer"},
			}},
		},
	}
	addr, err := pickAIREv1(doc, "")
	if err != nil {
		t.Fatalf("pickAIREv1: %v", err)
	}
	if addr.Endpoint != "aire.example.com:4433" {
		t.Errorf("Endpoint = %q, want aire.example.com:4433", addr.Endpoint)
	}
	if addr.AgentID != "summarizer" {
		t.Errorf("AgentID = %q, want summarizer", addr.AgentID)
	}
	if !reflect.DeepEqual(addr.Accept, []string{"aire/v0.2", "aire/v0.1"}) {
		t.Errorf("Accept = %v", addr.Accept)
	}
}

func TestPickAIREv1_DefaultAgentID(t *testing.T) {
	doc := &didDocument{
		Service: []serviceEntry{
			{Type: "AIREv1", ServiceEndpoint: []serviceEndpoint{
				{URI: "aire://x.example.com", Accept: []string{"aire/v0.2"}},
			}},
		},
	}
	addr, err := pickAIREv1(doc, "fallback")
	if err != nil {
		t.Fatalf("pickAIREv1: %v", err)
	}
	if addr.AgentID != "fallback" {
		t.Errorf("AgentID = %q, want fallback (default)", addr.AgentID)
	}
	if addr.Endpoint != "x.example.com:4433" {
		t.Errorf("Endpoint = %q, want default port 4433", addr.Endpoint)
	}
}

func TestPickAIREv1_NoEntry(t *testing.T) {
	doc := &didDocument{Service: []serviceEntry{{Type: "DIDCommMessaging"}}}
	if _, err := pickAIREv1(doc, ""); !errors.Is(err, ErrNoAIREv1Service) {
		t.Errorf("expected ErrNoAIREv1Service, got %v", err)
	}
}

func TestVerifyAlsoKnownAs(t *testing.T) {
	doc := &didDocument{AlsoKnownAs: []string{"https://other", "aire://summarizer@aire.example.com"}}
	if err := verifyAlsoKnownAs(doc, "summarizer", "aire.example.com"); err != nil {
		t.Errorf("ok case: %v", err)
	}
	if err := verifyAlsoKnownAs(doc, "other", "aire.example.com"); !errors.Is(err, ErrAlsoKnownAsMismatch) {
		t.Errorf("missing case: expected ErrAlsoKnownAsMismatch, got %v", err)
	}
	if err := verifyAlsoKnownAs(&didDocument{}, "x", "y"); !errors.Is(err, ErrAlsoKnownAsMismatch) {
		t.Errorf("empty alsoKnownAs: expected ErrAlsoKnownAsMismatch, got %v", err)
	}
}

func TestParseAIREURI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"aire://host.example.com:4433", "host.example.com:4433"},
		{"aire://host.example.com", "host.example.com:4433"},
		{"aire://10.0.0.1:5000", "10.0.0.1:5000"},
		{"aire://[2001:db8::1]:5000", "[2001:db8::1]:5000"},
	}
	for _, c := range cases {
		got, err := parseAIREURI(c.in)
		if err != nil {
			t.Errorf("parseAIREURI(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseAIREURI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", "https://x", "aire://", "not a url"} {
		if _, err := parseAIREURI(bad); err == nil {
			t.Errorf("parseAIREURI(%q) expected error", bad)
		}
	}
}

// === integration tests (httptest + injected DNS) ===

// canonicalDIDDoc returns a DID Document matching the spec §6.8.5 vector.
// didWebHost is the percent-encoded host:port used in the did:web identifier
// (e.g., "127.0.0.1%3A54321"); rawHandleHost is the raw host:port used in the
// aire:// URI for alsoKnownAs (e.g., "127.0.0.1:54321"). The aire serviceEndpoint
// URI is independent of the test server and points at a stable canonical address.
func canonicalDIDDoc(didWebHost, rawHandleHost string) string {
	return fmt.Sprintf(`{
  "id": "did:web:%s:agents:summarizer",
  "alsoKnownAs": ["aire://summarizer@%s"],
  "service": [{
    "id": "did:web:%s:agents:summarizer#aire-1",
    "type": "AIREv1",
    "serviceEndpoint": [{
      "uri": "aire://aire.example.com:4433",
      "accept": ["aire/v0.2", "aire/v0.1"],
      "agentId": "summarizer"
    }]
  }]
}`, didWebHost, rawHandleHost, didWebHost)
}

func newAddressingTestServer(t *testing.T, didWebHost, rawHandleHost *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/agents/summarizer/did.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, canonicalDIDDoc(*didWebHost, *rawHandleHost))
	})
	mux.HandleFunc("/.well-known/aire-did", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "summarizer" {
			http.Error(w, "no such handle", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, "did:web:"+*didWebHost+":agents:summarizer\n")
	})
	return httptest.NewTLSServer(mux)
}

func TestResolver_DIDWeb_FullPath(t *testing.T) {
	var didWebHost, rawHandleHost string
	ts := newAddressingTestServer(t, &didWebHost, &rawHandleHost)
	defer ts.Close()
	rawHandleHost = strings.TrimPrefix(ts.URL, "https://")
	didWebHost = encodeDIDWebHost(rawHandleHost)

	r := &Resolver{HTTPClient: ts.Client()}

	addr, err := r.Resolve(context.Background(), "did:web:"+didWebHost+":agents:summarizer")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if addr.AgentID != "summarizer" {
		t.Errorf("AgentID = %q", addr.AgentID)
	}
	if addr.Endpoint != "aire.example.com:4433" {
		t.Errorf("Endpoint = %q, want aire.example.com:4433", addr.Endpoint)
	}
}

func TestResolver_Handle_TXTPath(t *testing.T) {
	var didWebHost, rawHandleHost string
	ts := newAddressingTestServer(t, &didWebHost, &rawHandleHost)
	defer ts.Close()
	rawHandleHost = strings.TrimPrefix(ts.URL, "https://")
	didWebHost = encodeDIDWebHost(rawHandleHost)

	r := &Resolver{
		HTTPClient: ts.Client(),
		LookupTXT: func(_ context.Context, name string) ([]string, error) {
			if name == "_aire.summarizer."+rawHandleHost {
				return []string{"did=did:web:" + didWebHost + ":agents:summarizer"}, nil
			}
			return nil, fmt.Errorf("no TXT")
		},
	}

	addr, err := r.Resolve(context.Background(), "@summarizer@"+rawHandleHost)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if addr.AgentID != "summarizer" {
		t.Errorf("AgentID = %q", addr.AgentID)
	}
	if !strings.Contains(addr.DID, "did:web:") {
		t.Errorf("DID = %q, want did:web:...", addr.DID)
	}
}

func TestResolver_Handle_WellKnownPath(t *testing.T) {
	var didWebHost, rawHandleHost string
	ts := newAddressingTestServer(t, &didWebHost, &rawHandleHost)
	defer ts.Close()
	rawHandleHost = strings.TrimPrefix(ts.URL, "https://")
	didWebHost = encodeDIDWebHost(rawHandleHost)

	r := &Resolver{
		HTTPClient: ts.Client(),
		LookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return nil, fmt.Errorf("no DNS for test") // force fall-through to well-known
		},
	}

	addr, err := r.Resolve(context.Background(), "summarizer@"+rawHandleHost)
	if err != nil {
		t.Fatalf("Resolve via well-known: %v", err)
	}
	if addr.AgentID != "summarizer" {
		t.Errorf("AgentID = %q", addr.AgentID)
	}
}

func TestResolver_Handle_AlsoKnownAsMismatch_Fails(t *testing.T) {
	var didWebHost, rawHandleHost string

	mux := http.NewServeMux()
	mux.HandleFunc("/agents/summarizer/did.json", func(w http.ResponseWriter, r *http.Request) {
		// alsoKnownAs intentionally points at a different localpart.
		fmt.Fprintf(w, `{
  "id": "did:web:%s:agents:summarizer",
  "alsoKnownAs": ["aire://imposter@%s"],
  "service": [{
    "type": "AIREv1",
    "serviceEndpoint": [{"uri": "aire://aire.example.com:4433", "accept": ["aire/v0.2"]}]
  }]
}`, didWebHost, rawHandleHost)
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	rawHandleHost = strings.TrimPrefix(ts.URL, "https://")
	didWebHost = encodeDIDWebHost(rawHandleHost)

	r := &Resolver{
		HTTPClient: ts.Client(),
		LookupTXT: func(_ context.Context, _ string) ([]string, error) {
			return []string{"did=did:web:" + didWebHost + ":agents:summarizer"}, nil
		},
	}

	_, err := r.Resolve(context.Background(), "summarizer@"+rawHandleHost)
	if !errors.Is(err, ErrAlsoKnownAsMismatch) {
		t.Errorf("expected ErrAlsoKnownAsMismatch, got %v", err)
	}
}

func TestResolver_DIDKey_DescriptiveError(t *testing.T) {
	r := &Resolver{}
	_, err := r.Resolve(context.Background(), "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	if !errors.Is(err, ErrUnsupportedDIDMethod) {
		t.Errorf("expected ErrUnsupportedDIDMethod, got %v", err)
	}
	if !strings.Contains(err.Error(), "did:key") {
		t.Errorf("error should mention did:key for clarity, got %v", err)
	}
}

// encodeDIDWebHost encodes a host:port into the did:web percent-encoded form.
func encodeDIDWebHost(hostport string) string {
	return strings.Replace(hostport, ":", "%3A", 1)
}
