package zenet

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/rep"
	_ "go.nanomsg.org/mangos/v3/transport/inproc" // register the inproc transport for tests
)

// newTestBackend starts an in-process mangos REP backend on addr. For every
// request the handler returns the raw reply bytes; returning ok=false makes
// the backend stay silent (to exercise timeouts). workers contexts serve
// requests concurrently.
func newTestBackend(t *testing.T, addr string, workers int, handler func(q resolverQuery) ([]byte, bool)) {
	t.Helper()
	sock, err := rep.NewSocket()
	if err != nil {
		t.Fatalf("failed to create REP socket: %v", err)
	}
	if err := sock.Listen(addr); err != nil {
		t.Fatalf("failed to listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { sock.Close() })

	for i := 0; i < workers; i++ {
		cx, err := sock.OpenContext()
		if err != nil {
			t.Fatalf("failed to open REP context: %v", err)
		}
		go func(cx mangos.Context) {
			defer cx.Close()
			for {
				msg, err := cx.Recv()
				if err != nil {
					return // socket closed
				}
				var q resolverQuery
				if err := json.Unmarshal(msg, &q); err != nil {
					continue
				}
				reply, ok := handler(q)
				if !ok {
					continue
				}
				if err := cx.Send(reply); err != nil {
					return
				}
			}
		}(cx)
	}
}

// newTestZenet returns a started Zenet dialing addr, cleaned up with the test.
func newTestZenet(t *testing.T, addr string) *Zenet {
	t.Helper()
	z := &Zenet{
		Zones:         []string{"."},
		addr:          addr,
		timeout:       500 * time.Millisecond,
		ttl:           defaultTTL,
		maxConcurrent: 100,
		sem:           make(chan struct{}, 100),
	}
	if err := z.OnStartup(); err != nil {
		t.Fatalf("OnStartup failed: %v", err)
	}
	t.Cleanup(func() { z.OnShutdown() })
	return z
}

func jsonReply(values ...string) ([]byte, bool) {
	b, _ := json.Marshal(backendReply{Query: values})
	return b, true
}

func doQuery(t *testing.T, z *Zenet, qname string, qtype uint16) (int, error, *dns.Msg) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	code, err := z.ServeDNS(context.TODO(), rec, req)
	return code, err, rec.Msg
}

func TestServeDNSA(t *testing.T) {
	addr := "inproc://zenet-test-a"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		if q.Query.QType != "A" || q.Query.Name != "host.example.org." {
			t.Errorf("unexpected backend query: %+v", q)
		}
		return jsonReply("10.1.2.3")
	})
	z := newTestZenet(t, addr)

	code, err, msg := doQuery(t, z, "host.example.org.", dns.TypeA)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("expected success, got code=%d err=%v", code, err)
	}
	if !msg.Authoritative {
		t.Error("expected authoritative answer")
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.1.2.3" {
		t.Errorf("unexpected answer: %v", msg.Answer[0])
	}
	if a.Hdr.Ttl != defaultTTL {
		t.Errorf("expected ttl %d, got %d", defaultTTL, a.Hdr.Ttl)
	}
}

func TestServeDNSAAAA(t *testing.T) {
	addr := "inproc://zenet-test-aaaa"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		return jsonReply("fd00::1")
	})
	z := newTestZenet(t, addr)

	code, err, msg := doQuery(t, z, "host.example.org.", dns.TypeAAAA)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("expected success, got code=%d err=%v", code, err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
	aaaa, ok := msg.Answer[0].(*dns.AAAA)
	if !ok || aaaa.AAAA.String() != "fd00::1" {
		t.Errorf("unexpected answer: %v", msg.Answer[0])
	}
}

func TestServeDNSTXT(t *testing.T) {
	addr := "inproc://zenet-test-txt"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		return jsonReply("hello", "world")
	})
	z := newTestZenet(t, addr)

	code, err, msg := doQuery(t, z, "host.example.org.", dns.TypeTXT)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("expected success, got code=%d err=%v", code, err)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(msg.Answer))
	}
	for i, want := range []string{"hello", "world"} {
		txt, ok := msg.Answer[i].(*dns.TXT)
		if !ok || len(txt.Txt) != 1 || txt.Txt[0] != want {
			t.Errorf("answer %d: expected %q, got %v", i, want, msg.Answer[i])
		}
	}
}

// TestServeDNSEmptyReply is a regression test: the original code indexed
// Query[0] unconditionally and panicked on an empty backend reply.
func TestServeDNSEmptyReply(t *testing.T) {
	addr := "inproc://zenet-test-empty"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		return jsonReply() // {"query":[]}
	})
	z := newTestZenet(t, addr)

	code, err, msg := doQuery(t, z, "missing.example.org.", dns.TypeA)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR no-data, got code=%d err=%v", code, err)
	}
	if len(msg.Answer) != 0 {
		t.Errorf("expected empty answer, got %v", msg.Answer)
	}
}

func TestServeDNSNXDOMAIN(t *testing.T) {
	addr := "inproc://zenet-test-nxdomain"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		b, _ := json.Marshal(backendReply{Query: []string{}, Rcode: rcodeNXDomain})
		return b, true
	})
	z := newTestZenet(t, addr)

	code, err, msg := doQuery(t, z, "missing.example.org.", dns.TypeA)
	if err != nil || code != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got code=%d err=%v", code, err)
	}
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("expected response rcode NXDOMAIN, got %d", msg.Rcode)
	}
	if !msg.Authoritative {
		t.Error("expected authoritative answer")
	}
	if len(msg.Answer) != 0 {
		t.Errorf("expected empty answer, got %v", msg.Answer)
	}
}

// TestServeDNSNXDOMAINIgnoresValues verifies that rcode NXDOMAIN wins even if
// the backend also (contradictorily) returned values.
func TestServeDNSNXDOMAINIgnoresValues(t *testing.T) {
	addr := "inproc://zenet-test-nxdomain-values"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		b, _ := json.Marshal(backendReply{Query: []string{"10.1.2.3"}, Rcode: rcodeNXDomain})
		return b, true
	})
	z := newTestZenet(t, addr)

	code, err, msg := doQuery(t, z, "missing.example.org.", dns.TypeA)
	if err != nil || code != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got code=%d err=%v", code, err)
	}
	if len(msg.Answer) != 0 {
		t.Errorf("expected empty answer, got %v", msg.Answer)
	}
}

func TestServeDNSNXDOMAINFallthrough(t *testing.T) {
	addr := "inproc://zenet-test-nxdomain-fall"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		b, _ := json.Marshal(backendReply{Query: []string{}, Rcode: rcodeNXDomain})
		return b, true
	})
	z := newTestZenet(t, addr)
	z.Fall = fall.Root
	z.Next = test.NextHandler(dns.RcodeRefused, nil)

	code, err, _ := doQuery(t, z, "missing.example.org.", dns.TypeA)
	if err != nil || code != dns.RcodeRefused {
		t.Fatalf("expected fallthrough to next plugin (REFUSED), got code=%d err=%v", code, err)
	}
}

func TestServeDNSBadRcode(t *testing.T) {
	addr := "inproc://zenet-test-badrcode"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		return []byte(`{"query":[],"rcode":"WAT"}`), true
	})
	z := newTestZenet(t, addr)

	code, err, _ := doQuery(t, z, "host.example.org.", dns.TypeA)
	if err == nil || code != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL with error, got code=%d err=%v", code, err)
	}
}

// TestServeDNSExplicitNoError verifies an explicit "NOERROR" rcode behaves
// like an absent one.
func TestServeDNSExplicitNoError(t *testing.T) {
	addr := "inproc://zenet-test-noerror"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		b, _ := json.Marshal(backendReply{Query: []string{"10.1.2.3"}, Rcode: rcodeNoError})
		return b, true
	})
	z := newTestZenet(t, addr)

	code, err, msg := doQuery(t, z, "host.example.org.", dns.TypeA)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("expected success, got code=%d err=%v", code, err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answer))
	}
}

func TestServeDNSBadIP(t *testing.T) {
	addr := "inproc://zenet-test-badip"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		return jsonReply("not-an-ip")
	})
	z := newTestZenet(t, addr)

	code, err, _ := doQuery(t, z, "host.example.org.", dns.TypeA)
	if err == nil || code != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL with error, got code=%d err=%v", code, err)
	}
}

func TestServeDNSMalformedJSON(t *testing.T) {
	addr := "inproc://zenet-test-badjson"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		return []byte("not json"), true
	})
	z := newTestZenet(t, addr)

	code, err, _ := doQuery(t, z, "host.example.org.", dns.TypeA)
	if err == nil || code != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL with error, got code=%d err=%v", code, err)
	}
}

func TestServeDNSTimeout(t *testing.T) {
	addr := "inproc://zenet-test-timeout"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		return nil, false // never reply
	})
	z := newTestZenet(t, addr)

	start := time.Now()
	code, err, _ := doQuery(t, z, "host.example.org.", dns.TypeA)
	elapsed := time.Since(start)
	if err == nil || code != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL with error, got code=%d err=%v", code, err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("timeout took too long: %s", elapsed)
	}
}

// TestServeDNSUnsupportedQtype verifies unsupported query types fall through
// to the next plugin instead of returning NOTIMP.
func TestServeDNSUnsupportedQtype(t *testing.T) {
	addr := "inproc://zenet-test-unsupported"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		t.Error("backend should not be queried for unsupported qtype")
		return nil, false
	})
	z := newTestZenet(t, addr)
	z.Next = test.NextHandler(dns.RcodeRefused, nil)

	code, err, _ := doQuery(t, z, "host.example.org.", dns.TypeMX)
	if err != nil || code != dns.RcodeRefused {
		t.Fatalf("expected fallthrough to next plugin (REFUSED), got code=%d err=%v", code, err)
	}
}

// TestServeDNSZoneMiss verifies queries outside the configured zones pass to
// the next plugin untouched.
func TestServeDNSZoneMiss(t *testing.T) {
	addr := "inproc://zenet-test-zonemiss"
	newTestBackend(t, addr, 1, func(q resolverQuery) ([]byte, bool) {
		t.Error("backend should not be queried for a zone miss")
		return nil, false
	})
	z := newTestZenet(t, addr)
	z.Zones = []string{"example.org."}
	z.Next = test.NextHandler(dns.RcodeRefused, nil)

	code, err, _ := doQuery(t, z, "host.example.net.", dns.TypeA)
	if err != nil || code != dns.RcodeRefused {
		t.Fatalf("expected fallthrough to next plugin (REFUSED), got code=%d err=%v", code, err)
	}
}

// TestServeDNSFallthroughOnBackendDown verifies fallthrough applies on
// backend errors when configured.
func TestServeDNSFallthroughOnBackendDown(t *testing.T) {
	// No backend listening: send/recv times out.
	z := newTestZenet(t, "inproc://zenet-test-down")
	z.Fall = fall.Root
	z.Next = test.NextHandler(dns.RcodeRefused, nil)

	code, err, _ := doQuery(t, z, "host.example.org.", dns.TypeA)
	if err != nil || code != dns.RcodeRefused {
		t.Fatalf("expected fallthrough to next plugin (REFUSED), got code=%d err=%v", code, err)
	}
}

// TestServeDNSConcurrency proves replies are not cross-talked between
// concurrent queries. Each query expects a TXT value derived from its own
// qname; the shared-socket implementation without mangos contexts fails this.
func TestServeDNSConcurrency(t *testing.T) {
	addr := "inproc://zenet-test-concurrency"
	newTestBackend(t, addr, 8, func(q resolverQuery) ([]byte, bool) {
		time.Sleep(2 * time.Millisecond) // widen the race window
		return jsonReply("value-for-" + q.Query.Name)
	})
	z := newTestZenet(t, addr)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			qname := fmt.Sprintf("host%d.example.org.", i)
			code, err, msg := doQuery(t, z, qname, dns.TypeTXT)
			if err != nil || code != dns.RcodeSuccess {
				errs <- fmt.Errorf("%s: code=%d err=%v", qname, code, err)
				return
			}
			if len(msg.Answer) != 1 {
				errs <- fmt.Errorf("%s: expected 1 answer, got %d", qname, len(msg.Answer))
				return
			}
			txt := msg.Answer[0].(*dns.TXT)
			if want := "value-for-" + qname; txt.Txt[0] != want {
				errs <- fmt.Errorf("%s: got mismatched reply %q, want %q", qname, txt.Txt[0], want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
