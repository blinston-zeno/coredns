package zenet

import (
	"fmt"
	"net"
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
	maxNameLength  = 255
	maxMetaEntries = 16
	maxMetaBytes   = 1024
)

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
type registerBody struct {
	Name      string            `json:"name"`
	Endpoints []string          `json:"endpoints"`
	TTL       uint32            `json:"ttl"` // requested lease in seconds; clamped to [min_ttl, max_ttl]
	Meta      map[string]string `json:"meta,omitempty"`
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
// TTL is the smallest remaining lease in seconds across returned endpoints.
type registryReply struct {
	OK        bool              `json:"ok"`
	Error     string            `json:"error,omitempty"`
	Detail    string            `json:"detail,omitempty"`
	Found     *bool             `json:"found,omitempty"`
	Endpoints []string          `json:"endpoints,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	TTL       uint32            `json:"ttl,omitempty"`
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

// parseEndpointURL validates a registered endpoint URL and returns its host
// and port. v1 deliberately accepts only tcp:// with an IP-literal host and a
// non-zero port: A/AAAA synthesis needs IP literals, and rejecting hostnames
// loudly here beats silently serving no-data later. Other nng transports
// (ipc, inproc, tls+tcp, ws) are future work.
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
	p, err := net.LookupPort("tcp", port)
	if err != nil || p == 0 {
		return "", "", fmt.Errorf("endpoint %q: invalid port %q", raw, port)
	}
	return host, port, nil
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
