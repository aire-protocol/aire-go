package aire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Address is a fully resolved AIRE peer address: cryptographic identity (DID),
// QUIC dial target (Endpoint), agent identifier for INVOKE (AgentID), and the
// peer's advertised AIRE protocol versions (Accept) per spec §6.7.
type Address struct {
	DID      string
	Endpoint string
	AgentID  string
	Accept   []string
}

// Sentinel errors returned by the Resolver.
var (
	ErrNoAIREv1Service      = errors.New("aire: no AIREv1 service entry in DID Document")
	ErrAlsoKnownAsMismatch  = errors.New("aire: handle not in DID Document alsoKnownAs")
	ErrUnsupportedDIDMethod = errors.New("aire: unsupported DID method for endpoint resolution")
	ErrMalformedHandle      = errors.New("aire: malformed handle")
	ErrMalformedDIDWeb      = errors.New("aire: malformed did:web")
)

// Resolver resolves DIDs and handles to AIRE Addresses per spec §6.7 / §6.8.
// Both fields are optional; defaults use the standard library.
type Resolver struct {
	HTTPClient *http.Client
	LookupTXT  func(ctx context.Context, name string) ([]string, error)
}

// Resolve takes a reference and returns the resolved Address. The reference is
// either a DID (e.g., "did:web:example.com:agents:alice") or a handle
// (e.g., "summarizer@aire.example.com" or "@summarizer@aire.example.com").
// For handles, bidirectional alsoKnownAs verification (§6.8.3) is mandatory.
func (r *Resolver) Resolve(ctx context.Context, ref string) (*Address, error) {
	if strings.HasPrefix(ref, "did:") {
		addr, _, err := r.resolveDID(ctx, ref, "")
		return addr, err
	}
	local, domain, err := parseHandle(ref)
	if err != nil {
		return nil, err
	}
	did, err := r.resolveHandle(ctx, local, domain)
	if err != nil {
		return nil, err
	}
	addr, doc, err := r.resolveDID(ctx, did, local)
	if err != nil {
		return nil, err
	}
	if err := verifyAlsoKnownAs(doc, local, domain); err != nil {
		return nil, err
	}
	return addr, nil
}

// Resolve uses a default Resolver. Convenience for callers that don't need
// to inject an HTTP client or a DNS lookup function.
func Resolve(ctx context.Context, ref string) (*Address, error) {
	return (&Resolver{}).Resolve(ctx, ref)
}

func (r *Resolver) httpClient() *http.Client {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return http.DefaultClient
}

func (r *Resolver) lookupTXT(ctx context.Context, name string) ([]string, error) {
	if r.LookupTXT != nil {
		return r.LookupTXT(ctx, name)
	}
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func (r *Resolver) resolveDID(ctx context.Context, did, defaultAgentID string) (*Address, *didDocument, error) {
	switch {
	case strings.HasPrefix(did, "did:web:"):
		return r.resolveDIDWeb(ctx, did, defaultAgentID)
	case strings.HasPrefix(did, "did:key:"):
		return nil, nil, fmt.Errorf("%w: did:key has no service entry; provide an explicit endpoint", ErrUnsupportedDIDMethod)
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedDIDMethod, methodOf(did))
	}
}

func (r *Resolver) resolveDIDWeb(ctx context.Context, did, defaultAgentID string) (*Address, *didDocument, error) {
	docURL, err := didWebToURL(did)
	if err != nil {
		return nil, nil, err
	}
	doc, err := r.fetchDIDDocument(ctx, docURL)
	if err != nil {
		return nil, nil, err
	}
	addr, err := pickAIREv1(doc, defaultAgentID)
	if err != nil {
		return nil, nil, err
	}
	addr.DID = did
	return addr, doc, nil
}

func (r *Resolver) fetchDIDDocument(ctx context.Context, docURL string) (*didDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("aire: fetch %s: %w", docURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aire: fetch %s: status %d", docURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("aire: read %s: %w", docURL, err)
	}
	var doc didDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("aire: parse DID Document: %w", err)
	}
	return &doc, nil
}

func (r *Resolver) resolveHandle(ctx context.Context, local, domain string) (string, error) {
	if did, err := r.resolveHandleViaTXT(ctx, local, domain); err == nil {
		return did, nil
	}
	return r.resolveHandleViaWellKnown(ctx, local, domain)
}

func (r *Resolver) resolveHandleViaTXT(ctx context.Context, local, domain string) (string, error) {
	name := "_aire." + local + "." + domain
	records, err := r.lookupTXT(ctx, name)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("aire: no TXT records at %s", name)
	}
	if len(records) > 1 {
		return "", fmt.Errorf("aire: multiple TXT records at %s; ambiguous", name)
	}
	return parseTXTDIDValue(records[0])
}

func (r *Resolver) resolveHandleViaWellKnown(ctx context.Context, local, domain string) (string, error) {
	wkURL := "https://" + domain + "/.well-known/aire-did?name=" + url.QueryEscape(local)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wkURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("aire: fetch %s: %w", wkURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("aire: well-known %s: status %d", wkURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("aire: read %s: %w", wkURL, err)
	}
	did := strings.TrimRight(strings.TrimSpace(string(body)), "\n")
	if did == "" || !strings.HasPrefix(did, "did:") {
		return "", fmt.Errorf("aire: well-known %s: body is not a DID: %q", wkURL, body)
	}
	return did, nil
}

// didWebToURL maps a did:web identifier to its DID Document URL per spec §5.3.
func didWebToURL(did string) (string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", fmt.Errorf("%w: not a did:web", ErrMalformedDIDWeb)
	}
	rest := strings.TrimPrefix(did, "did:web:")
	if rest == "" {
		return "", fmt.Errorf("%w: empty identifier", ErrMalformedDIDWeb)
	}
	parts := strings.Split(rest, ":")
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", fmt.Errorf("%w: host: %v", ErrMalformedDIDWeb, err)
	}
	if host == "" {
		return "", fmt.Errorf("%w: empty host", ErrMalformedDIDWeb)
	}
	if len(parts) == 1 {
		return "https://" + host + "/.well-known/did.json", nil
	}
	pathParts := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		decoded, err := url.PathUnescape(p)
		if err != nil {
			return "", fmt.Errorf("%w: path segment: %v", ErrMalformedDIDWeb, err)
		}
		pathParts = append(pathParts, decoded)
	}
	return "https://" + host + "/" + strings.Join(pathParts, "/") + "/did.json", nil
}

func parseHandle(s string) (local, domain string, err error) {
	s = strings.TrimPrefix(s, "@")
	if s == "" {
		return "", "", fmt.Errorf("%w: empty", ErrMalformedHandle)
	}
	at := strings.IndexByte(s, '@')
	if at < 0 {
		return "", "", fmt.Errorf("%w: missing @: %q", ErrMalformedHandle, s)
	}
	local = s[:at]
	domain = s[at+1:]
	if local == "" || domain == "" {
		return "", "", fmt.Errorf("%w: empty part: %q", ErrMalformedHandle, s)
	}
	if strings.ContainsRune(domain, '@') {
		return "", "", fmt.Errorf("%w: too many @: %q", ErrMalformedHandle, s)
	}
	return local, domain, nil
}

func parseTXTDIDValue(s string) (string, error) {
	if !strings.HasPrefix(s, "did=") {
		return "", fmt.Errorf("aire: TXT record missing did= prefix: %q", s)
	}
	did := strings.TrimPrefix(s, "did=")
	if did == "" || !strings.HasPrefix(did, "did:") {
		return "", fmt.Errorf("aire: TXT record value is not a DID: %q", s)
	}
	return did, nil
}

func verifyAlsoKnownAs(doc *didDocument, local, domain string) error {
	expected := "aire://" + local + "@" + domain
	if slices.Contains(doc.AlsoKnownAs, expected) {
		return nil
	}
	return fmt.Errorf("%w: expected %s in alsoKnownAs", ErrAlsoKnownAsMismatch, expected)
}

func pickAIREv1(doc *didDocument, defaultAgentID string) (*Address, error) {
	for _, svc := range doc.Service {
		if svc.Type != "AIREv1" {
			continue
		}
		for _, ep := range svc.ServiceEndpoint {
			endpoint, err := parseAIREURI(ep.URI)
			if err != nil {
				continue
			}
			agentID := ep.AgentID
			if agentID == "" {
				agentID = defaultAgentID
			}
			return &Address{
				Endpoint: endpoint,
				AgentID:  agentID,
				Accept:   ep.Accept,
			}, nil
		}
	}
	return nil, ErrNoAIREv1Service
}

func parseAIREURI(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("aire: empty URI")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("aire: parse URI %q: %w", s, err)
	}
	if u.Scheme != "aire" {
		return "", fmt.Errorf("aire: not an aire URI: %q", s)
	}
	if u.Host == "" {
		return "", fmt.Errorf("aire: empty host in URI: %q", s)
	}
	if u.Port() == "" {
		return u.Host + ":4433", nil
	}
	return u.Host, nil
}

func methodOf(did string) string {
	parts := strings.SplitN(did, ":", 3)
	if len(parts) >= 2 {
		return "did:" + parts[1]
	}
	return did
}

type didDocument struct {
	ID          string         `json:"id"`
	AlsoKnownAs []string       `json:"alsoKnownAs"`
	Service     []serviceEntry `json:"service"`
}

type serviceEntry struct {
	ID              string            `json:"id"`
	Type            string            `json:"type"`
	ServiceEndpoint []serviceEndpoint `json:"serviceEndpoint"`
}

type serviceEndpoint struct {
	URI     string   `json:"uri"`
	Accept  []string `json:"accept"`
	AgentID string   `json:"agentId,omitempty"`
}
