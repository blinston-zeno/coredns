package zenet

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Registry wire protocol v1: JSON messages exchanged over a mangos REQ/REP
// socket between services and the in-plugin registry. A register message is
// also the heartbeat: it is an idempotent upsert that refreshes the lease of
// every listed endpoint. Names are canonicalized server-side (lowercase,
// trailing dot), so clients may send either "svc.cloud.zeno" or
// "svc.cloud.zeno.".

// protocolVersion is the registry protocol version this plugin implements.
// Requests may omit the version field, which is treated as version 1.
const protocolVersion = 1

// Protocol-level limits that are not Corefile-configurable.
const (
	maxNameLength      = 255
	maxMetaEntries     = 16
	maxMetaBytes       = 1024
	maxAltsPerEndpoint = 4
	maxAltURLBytes     = 256
)

// The closed set of alternate-transport keys an endpoint may carry is "ipc"
// (same-machine UNIX domain socket, nng ipc:// URL) and "tls" (TLS over TCP
// for consumers outside the already-WireGuard-encrypted tailnet, nng
// tls+tcp:// URL) — enforced by validateAltURL. Unknown keys are rejected
// loudly (consistent with parseEndpointURL's philosophy) so registry data
// stays trustworthy for every consumer.

// Protocol error codes returned in registryReply.Error. The set is closed;
// clients may rely on these strings.
const (
	errCodeBadRequest         = "bad_request"
	errCodeUnsupportedVersion = "unsupported_version"
	errCodeNameInvalid        = "name_invalid"
	errCodeEndpointInvalid    = "endpoint_invalid"
	errCodeTooManyEndpoints   = "too_many_endpoints"
	errCodeTooLarge           = "too_large"
	errCodeCapacity           = "capacity"
	errCodeUnauthorized       = "unauthorized" // reserved for future token auth
)

// registryRequest is a single protocol message. Exactly one of Register,
// Unregister or Discover must be set. Token is parsed but ignored in v1; it
// is reserved for a future shared-secret auth scheme.
type registryRequest struct {
	Version    int             `json:"version,omitempty"`
	Token      string          `json:"token,omitempty"`
	Register   *registerBody   `json:"register,omitempty"`
	Unregister *unregisterBody `json:"unregister,omitempty"`
	Discover   *discoverBody   `json:"discover,omitempty"`
}

// registerBody registers (or refreshes, as a heartbeat) endpoints for a name.
// Alts optionally attaches alternate-transport URLs to canonical endpoints:
// the outer key must equal one of Endpoints, the inner key is a transport from
// altTransports. Alts share their endpoint's lease and are replaced wholesale
// on every register (a heartbeat without alts clears them, mirroring meta).
type registerBody struct {
	Name      string                       `json:"name"`
	Endpoints []string                     `json:"endpoints"`
	TTL       uint32                       `json:"ttl"` // requested lease in seconds; clamped to [min_ttl, max_ttl]
	Meta      map[string]string            `json:"meta,omitempty"`
	Alts      map[string]map[string]string `json:"alts,omitempty"`
}

// unregisterBody removes the listed endpoints from a name. An empty or absent
// endpoint list removes the whole name.
type unregisterBody struct {
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints,omitempty"`
}

// discoverBody asks for the live endpoints of a name.
type discoverBody struct {
	Name string `json:"name"`
}

// registryReply is the response to any registryRequest. OK reports protocol
// success; "name not found" on discover is OK with Found=false, not an error.
// TTL is the smallest remaining lease in seconds across returned endpoints,
// truncated — 0 means less than one second remains. It is always present so
// a truthful 0 cannot be confused with an absent field.
type registryReply struct {
	OK        bool                         `json:"ok"`
	Error     string                       `json:"error,omitempty"`
	Detail    string                       `json:"detail,omitempty"`
	Found     *bool                        `json:"found,omitempty"`
	Endpoints []string                     `json:"endpoints,omitempty"`
	Meta      map[string]string            `json:"meta,omitempty"`
	Alts      map[string]map[string]string `json:"alts,omitempty"` // per-endpoint, never merged
	TTL       uint32                       `json:"ttl"`
}

// canonicalizeName validates a service name and returns its canonical DNS
// form (lowercase, fully qualified).
func canonicalizeName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty name")
	}
	if len(name) > maxNameLength {
		return "", fmt.Errorf("name exceeds %d octets", maxNameLength)
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return "", fmt.Errorf("not a valid domain name: %q", name)
	}
	return dns.CanonicalName(name), nil
}

// parseEndpointURL validates a CANONICAL registered endpoint URL and returns
// its host and port. Canonical endpoints deliberately accept only tcp:// with
// an IP-literal host and a numeric, non-zero port: A/AAAA synthesis needs IP
// literals, the port string surfaces verbatim in TXT answers (so service
// names like "http" must be rejected, not resolved), and rejecting loudly
// here beats silently serving no-data later. Alternate transports (ipc,
// tls+tcp) ride per-endpoint `alts` — see validateAltURL; ws/inproc remain
// future work.
func parseEndpointURL(raw string) (host, port string, err error) {
	rest, ok := strings.CutPrefix(raw, "tcp://")
	if !ok {
		return "", "", fmt.Errorf("endpoint %q: only tcp:// endpoints are supported", raw)
	}
	host, port, err = net.SplitHostPort(rest)
	if err != nil {
		return "", "", fmt.Errorf("endpoint %q: %v", raw, err)
	}
	if net.ParseIP(host) == nil {
		return "", "", fmt.Errorf("endpoint %q: host must be an IP literal", raw)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", "", fmt.Errorf("endpoint %q: port must be numeric in [1, 65535]: %q", raw, port)
	}
	return host, port, nil
}

// validateAltURL validates one alternate-transport URL for the given
// transport key. The rules differ from canonical endpoints on purpose:
//   - ipc: an nng ipc:// URL whose path must be absolute (ipc:///run/x.sock),
//     with no whitespace/control bytes (the URL surfaces verbatim in TXT
//     answers).
//   - tls: a tls+tcp:// URL whose host may be an IP literal OR a DNS name —
//     alts never feed A/AAAA synthesis (which is what forces canonical
//     endpoints to IP literals), and TLS clients generally need a DNS name
//     for SNI/certificate verification. Port rules match canonical tcp.
func validateAltURL(transport, raw string) error {
	if len(raw) > maxAltURLBytes {
		return fmt.Errorf("alt %s URL exceeds %d bytes", transport, maxAltURLBytes)
	}
	for _, r := range raw {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("alt %s URL %q: whitespace/control bytes not allowed", transport, raw)
		}
	}
	switch transport {
	case "ipc":
		path, ok := strings.CutPrefix(raw, "ipc://")
		if !ok {
			return fmt.Errorf("alt ipc URL %q: must be ipc://", raw)
		}
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("alt ipc URL %q: path must be absolute (ipc:///...)", raw)
		}
	case "tls":
		rest, ok := strings.CutPrefix(raw, "tls+tcp://")
		if !ok {
			return fmt.Errorf("alt tls URL %q: must be tls+tcp://", raw)
		}
		host, port, err := net.SplitHostPort(rest)
		if err != nil {
			return fmt.Errorf("alt tls URL %q: %v", raw, err)
		}
		if net.ParseIP(host) == nil {
			if _, ok := dns.IsDomainName(host); !ok {
				return fmt.Errorf("alt tls URL %q: host must be an IP literal or DNS name", raw)
			}
		}
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil || p == 0 {
			return fmt.Errorf("alt tls URL %q: port must be numeric in [1, 65535]: %q", raw, port)
		}
	default:
		return fmt.Errorf("unknown alt transport %q (supported: ipc, tls)", transport)
	}
	return nil
}

// validateAlts enforces the cross-rules on a register body's alts map: every
// outer key must equal one of the canonical endpoint URLs of the SAME body,
// the per-endpoint alt count is capped, and every URL passes validateAltURL.
func validateAlts(urls []string, alts map[string]map[string]string) error {
	if len(alts) == 0 {
		return nil
	}
	canonical := make(map[string]bool, len(urls))
	for _, u := range urls {
		canonical[u] = true
	}
	for epURL, m := range alts {
		if !canonical[epURL] {
			return fmt.Errorf("alts key %q does not match any registered endpoint", epURL)
		}
		if len(m) > maxAltsPerEndpoint {
			return fmt.Errorf("endpoint %q carries %d alts, max %d", epURL, len(m), maxAltsPerEndpoint)
		}
		for transport, raw := range m {
			if raw == "" {
				return fmt.Errorf("endpoint %q: empty alt %s URL", epURL, transport)
			}
			if err := validateAltURL(transport, raw); err != nil {
				return fmt.Errorf("endpoint %q: %v", epURL, err)
			}
		}
	}
	return nil
}

// validateMeta enforces the protocol bounds on a meta map.
func validateMeta(meta map[string]string) error {
	if len(meta) > maxMetaEntries {
		return fmt.Errorf("meta exceeds %d entries", maxMetaEntries)
	}
	size := 0
	for k, v := range meta {
		size += len(k) + len(v)
	}
	if size > maxMetaBytes {
		return fmt.Errorf("meta exceeds %d bytes", maxMetaBytes)
	}
	return nil
}
