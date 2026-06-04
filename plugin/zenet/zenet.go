// Package zenet implements a plugin that resolves A, AAAA and TXT queries by
// forwarding them as JSON to a backend service over a nanomsg (mangos) REQ/REP
// socket.
package zenet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/fall"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/req"
	_ "go.nanomsg.org/mangos/v3/transport/tcp" // register the tcp transport
)

var log = clog.NewWithPlugin(pluginName)

// errLimitExceeded indicates that a query was rejected because the number of
// concurrent backend requests has exceeded max_concurrent.
var errLimitExceeded = errors.New("concurrent queries exceeded maximum")

// zenetMode selects how queries are answered: by forwarding to an external
// backend (resolver, the original behavior) or from the in-plugin service
// registry (registry).
type zenetMode int

const (
	modeResolver zenetMode = iota
	modeRegistry
)

// Zenet resolves queries against a backend service reachable over a mangos
// REQ socket (resolver mode), or directly from an in-memory service registry
// fed by a mangos REP registration listener (registry mode). In resolver
// mode each in-flight DNS query uses its own mangos context so that
// concurrent requests are multiplexed safely over the single socket.
type Zenet struct {
	Next  plugin.Handler
	Zones []string
	Fall  fall.F

	mode zenetMode

	// Resolver mode.
	addr          string
	timeout       time.Duration
	maxConcurrent int64
	sock          mangos.Socket
	sem           chan struct{}

	// Registry mode. store and runner are shared, reload-surviving objects
	// owned by the process-wide runner registry (see shared.go).
	regCfg registryConfig
	store  *RegistryStore
	runner *runner

	ttl uint32 // DNS record TTL; in registry mode the ceiling over the remaining lease
}

// resolverQuery is the JSON request sent to the backend.
type resolverQuery struct {
	Query struct {
		Name  string `json:"name"`
		QType string `json:"type"`
	} `json:"query"`
}

// backendReply is the JSON response received from the backend. Rcode is
// optional: absent or "NOERROR" means success; "NXDOMAIN" means the name does
// not exist (Query is ignored in that case).
type backendReply struct {
	Query []string `json:"query"`
	Rcode string   `json:"rcode,omitempty"`
}

// typeToString maps a DNS qtype to the backend's type string. The second
// return value reports whether the qtype is supported.
func typeToString(qtype uint16) (string, bool) {
	switch qtype {
	case dns.TypeA:
		return "A", true
	case dns.TypeAAAA:
		return "AAAA", true
	case dns.TypeTXT:
		return "TXT", true
	}
	return "", false
}

// OnStartup creates the mangos REQ socket and dials the backend
// asynchronously, so CoreDNS can start even when the backend is down; mangos
// reconnects in the background with backoff.
func (z *Zenet) OnStartup() error {
	sock, err := req.NewSocket()
	if err != nil {
		return fmt.Errorf("failed to create mangos socket: %w", err)
	}
	// The per-context recv deadline must fire before the REQ protocol's
	// automatic resend (default one minute) becomes the limiting factor.
	if err := sock.SetOption(mangos.OptionRetryTime, z.timeout); err != nil {
		sock.Close()
		return fmt.Errorf("failed to set retry time: %w", err)
	}
	if err := sock.DialOptions(z.addr, map[string]interface{}{
		mangos.OptionDialAsynch: true,
	}); err != nil {
		sock.Close()
		return fmt.Errorf("failed to dial %s: %w", z.addr, err)
	}
	z.sock = sock
	log.Infof("dialing backend %s (timeout %s)", z.addr, z.timeout)
	return nil
}

// OnShutdown closes the mangos socket.
func (z *Zenet) OnShutdown() error {
	if z.sock == nil {
		return nil
	}
	err := z.sock.Close()
	z.sock = nil
	return err
}

// Ready implements the ready.Readiness interface. Resolver mode is ready
// once the REQ socket exists (it dials asynchronously); registry mode is
// ready once the registration listener is bound.
func (z *Zenet) Ready() bool {
	if z.mode == modeRegistry {
		return z.runner != nil && z.runner.listening()
	}
	return z.sock != nil
}

// ServeDNS implements the plugin.Handler interface.
func (z *Zenet) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	server := metrics.WithServer(ctx)

	if zone := plugin.Zones(z.Zones).Matches(state.Name()); zone == "" {
		return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
	}

	qtype, supported := typeToString(state.QType())
	if !supported {
		errorsCount.WithLabelValues(server, "unsupported").Inc()
		return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
	}

	if err := ctx.Err(); err != nil {
		errorsCount.WithLabelValues(server, "canceled").Inc()
		return dns.RcodeServerFailure, err
	}

	if z.mode == modeRegistry {
		return z.serveFromStore(ctx, w, r, state, server, qtype)
	}

	select {
	case z.sem <- struct{}{}:
		defer func() { <-z.sem }()
	default:
		droppedCount.WithLabelValues(server).Inc()
		return dns.RcodeServerFailure, errLimitExceeded
	}

	start := time.Now()
	reply, errType, err := z.query(state.Name(), qtype)
	requestDuration.WithLabelValues(server).Observe(time.Since(start).Seconds())
	if err != nil {
		errorsCount.WithLabelValues(server, errType).Inc()
		log.Debugf("backend query for %q (%s) failed (%s): %v", state.Name(), qtype, errType, err)
		if (errType == "send" || errType == "recv" || errType == "timeout") && z.Fall.Through(state.Name()) {
			return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
		}
		return dns.RcodeServerFailure, err
	}

	if reply.Rcode == rcodeNXDomain {
		nxdomainCount.WithLabelValues(server).Inc()
		if z.Fall.Through(state.Name()) {
			return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		m.Authoritative = true
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeNameError, nil
	}

	values := reply.Query
	if len(values) == 0 {
		nodataCount.WithLabelValues(server).Inc()
		if z.Fall.Through(state.Name()) {
			return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeSuccess, nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch state.QType() {
	case dns.TypeA, dns.TypeAAAA:
		if err := appendIPAnswers(m, values, state.QName(), state.QType(), z.ttl); err != nil {
			errorsCount.WithLabelValues(server, "bad_ip").Inc()
			return dns.RcodeServerFailure, err
		}
	case dns.TypeTXT:
		appendTXTAnswers(m, values, state.QName(), z.ttl)
	}

	requestsCount.WithLabelValues(server, qtype).Inc()
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

// serveFromStore answers a query directly from the in-memory registry
// (registry mode). Negative answers mirror resolver mode: an unregistered
// name is an authoritative NXDOMAIN, a registered name with no records of
// the queried family is an authoritative no-data, and both honor
// fallthrough. There is no backend to fail, so the resolver mode's
// send/recv/timeout error class does not exist here.
func (z *Zenet) serveFromStore(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, state request.Request, server, qtype string) (int, error) {
	discoverCount.WithLabelValues("dns").Inc()
	eps, minRemaining, found := z.store.Discover(state.Name())

	if !found {
		nxdomainCount.WithLabelValues(server).Inc()
		if z.Fall.Through(state.Name()) {
			return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		m.Authoritative = true
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeNameError, nil
	}

	// The record TTL never outlives the smallest remaining lease, capped by
	// the configured ttl: a downstream cache must not hand out a replica
	// past its lease.
	ttl := uint32(minRemaining / time.Second)
	if ttl < 1 {
		ttl = 1
	}
	if ttl > z.ttl {
		ttl = z.ttl
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch state.QType() {
	case dns.TypeA, dns.TypeAAAA:
		appendStoreIPAnswers(m, eps, state.QName(), state.QType(), ttl)
	case dns.TypeTXT:
		appendStoreTXTAnswers(m, eps, state.QName(), ttl)
	}

	if len(m.Answer) == 0 {
		// The name is registered but has no records of the queried family
		// (e.g. an AAAA query against IPv4-only endpoints).
		nodataCount.WithLabelValues(server).Inc()
		if z.Fall.Through(state.Name()) {
			return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
		}
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeSuccess, nil
	}

	requestsCount.WithLabelValues(server, qtype).Inc()
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

// appendStoreIPAnswers appends one record per distinct endpoint IP matching
// the queried family. Hosts were validated as IP literals at registration;
// two replicas sharing an IP (different ports) yield a single record.
func appendStoreIPAnswers(m *dns.Msg, eps []endpoint, name string, qtype uint16, ttl uint32) {
	seen := make(map[string]bool, len(eps))
	for _, ep := range eps {
		ip := net.ParseIP(ep.host)
		if ip == nil || seen[ip.String()] {
			continue
		}
		switch {
		case qtype == dns.TypeA && ip.To4() != nil:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip.To4(),
			})
			seen[ip.String()] = true
		case qtype == dns.TypeAAAA && ip.To4() == nil:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip,
			})
			seen[ip.String()] = true
		}
	}
}

// appendStoreTXTAnswers appends one TXT record per endpoint exposing the
// full endpoint URL, the port and the registered metadata, so DNS-only
// tooling can see where a service actually listens.
func appendStoreTXTAnswers(m *dns.Msg, eps []endpoint, name string, ttl uint32) {
	for _, ep := range eps {
		parts := []string{"endpoint=" + ep.url, "port=" + ep.port}
		keys := make([]string, 0, len(ep.meta))
		for k := range ep.meta {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, k+"="+ep.meta[k])
		}
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: chunkTXT(strings.Join(parts, " ")),
		})
	}
}

// chunkTXT splits s into the 255-byte segments a TXT record requires.
func chunkTXT(s string) []string {
	if len(s) <= 255 {
		return []string{s}
	}
	var out []string
	for len(s) > 255 {
		out = append(out, s[:255])
		s = s[255:]
	}
	return append(out, s)
}

// Backend reply rcode values.
const (
	rcodeNoError  = "NOERROR"
	rcodeNXDomain = "NXDOMAIN"
)

// query sends a single request to the backend over a fresh mangos context and
// returns the parsed reply. The second return value is a short error type
// label for metrics: "context", "send", "timeout", "recv", "decode" or
// "bad_rcode".
func (z *Zenet) query(name, qtype string) (backendReply, string, error) {
	q := resolverQuery{}
	q.Query.Name = name
	q.Query.QType = qtype

	jsonData, err := json.Marshal(q)
	if err != nil {
		return backendReply{}, "encode", fmt.Errorf("failed to encode query as JSON: %w", err)
	}

	// Each context is an independent request slot multiplexed over the
	// socket; Socket.Send/Recv share one context and are not safe for
	// concurrent request/reply pairs.
	mctx, err := z.sock.OpenContext()
	if err != nil {
		return backendReply{}, "context", fmt.Errorf("failed to open mangos context: %w", err)
	}
	defer mctx.Close()

	if err := mctx.SetOption(mangos.OptionSendDeadline, z.timeout); err != nil {
		return backendReply{}, "context", fmt.Errorf("failed to set send deadline: %w", err)
	}
	if err := mctx.SetOption(mangos.OptionRecvDeadline, z.timeout); err != nil {
		return backendReply{}, "context", fmt.Errorf("failed to set recv deadline: %w", err)
	}

	if err := mctx.Send(jsonData); err != nil {
		return backendReply{}, "send", fmt.Errorf("failed to send query to backend: %w", err)
	}

	msg, err := mctx.Recv()
	if err != nil {
		if errors.Is(err, mangos.ErrRecvTimeout) {
			return backendReply{}, "timeout", fmt.Errorf("timeout waiting for backend reply: %w", err)
		}
		return backendReply{}, "recv", fmt.Errorf("failed to receive reply from backend: %w", err)
	}

	var reply backendReply
	if err := json.Unmarshal(msg, &reply); err != nil {
		return backendReply{}, "decode", fmt.Errorf("failed to decode backend reply: %w", err)
	}
	switch reply.Rcode {
	case "", rcodeNoError, rcodeNXDomain:
	default:
		return backendReply{}, "bad_rcode", fmt.Errorf("unknown rcode from backend: %q", reply.Rcode)
	}
	return reply, "", nil
}

// appendIPAnswers parses each value as an IP address and appends the records
// matching the queried family. Values of the other address family are
// skipped; an unparseable value is an error.
func appendIPAnswers(m *dns.Msg, values []string, name string, qtype uint16, ttl uint32) error {
	for _, v := range values {
		ip := net.ParseIP(v)
		if ip == nil {
			return fmt.Errorf("invalid IP address from backend: %q", v)
		}
		switch {
		case qtype == dns.TypeA && ip.To4() != nil:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip.To4(),
			})
		case qtype == dns.TypeAAAA && ip.To4() == nil:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip,
			})
		}
	}
	return nil
}

// appendTXTAnswers appends one TXT record per value.
func appendTXTAnswers(m *dns.Msg, values []string, name string, ttl uint32) {
	for _, txt := range values {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{txt},
		})
	}
}

// Name implements the plugin.Handler interface.
func (z *Zenet) Name() string { return pluginName }
