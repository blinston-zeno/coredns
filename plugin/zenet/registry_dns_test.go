package zenet

import (
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// newTestRegistryZenet returns a registry-mode Zenet backed by a store with
// an injectable clock. The registration listener is not needed for DNS-path
// tests; the store is fed directly.
func newTestRegistryZenet(t *testing.T) (*Zenet, *RegistryStore, *fakeClock) {
	t.Helper()
	s, clk := newTestStore(t)
	z := &Zenet{
		Zones: []string{"."},
		mode:  modeRegistry,
		store: s,
		ttl:   defaultTTL,
	}
	return z, s, clk
}

func mustRegister(t *testing.T, s *RegistryStore, name string, urls []string, ttl time.Duration, meta map[string]string) {
	t.Helper()
	if err := s.Register(name, urls, ttl, meta); err != nil {
		t.Fatalf("Register(%s): %v", name, err)
	}
}

func TestStoreServeA(t *testing.T) {
	z, s, _ := newTestRegistryZenet(t)
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901", "tcp://10.0.0.2:40901"}, 30*time.Second, nil)

	code, err, msg := doQuery(t, z, "svc.cloud.zeno.", dns.TypeA)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("expected success, got code=%d err=%v", code, err)
	}
	if !msg.Authoritative {
		t.Error("expected authoritative answer")
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("expected 2 A records, got %d", len(msg.Answer))
	}
	got := map[string]bool{}
	for _, rr := range msg.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			t.Fatalf("expected A record, got %T", rr)
		}
		got[a.A.String()] = true
		// TTL is bounded by the remaining lease (30s), not the 3600s ceiling.
		if a.Hdr.Ttl != 30 {
			t.Errorf("expected TTL 30 (remaining lease), got %d", a.Hdr.Ttl)
		}
	}
	if !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Errorf("unexpected answer set: %v", got)
	}
}

func TestStoreServeTTLCeiling(t *testing.T) {
	z, s, _ := newTestRegistryZenet(t)
	z.ttl = 10 // ceiling below the lease
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901"}, 300*time.Second, nil)

	_, _, msg := doQuery(t, z, "svc.cloud.zeno.", dns.TypeA)
	if len(msg.Answer) != 1 || msg.Answer[0].Header().Ttl != 10 {
		t.Fatalf("expected TTL capped at 10, got %+v", msg.Answer)
	}
}

func TestStoreServeTTLTracksLease(t *testing.T) {
	z, s, clk := newTestRegistryZenet(t)
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, nil)

	clk.Advance(25 * time.Second) // 5s of lease left
	_, _, msg := doQuery(t, z, "svc.cloud.zeno.", dns.TypeA)
	if len(msg.Answer) != 1 || msg.Answer[0].Header().Ttl != 5 {
		t.Fatalf("expected TTL 5 (remaining lease), got %+v", msg.Answer)
	}
}

func TestStoreServeAAAA(t *testing.T) {
	z, s, _ := newTestRegistryZenet(t)
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://[fd00::1]:40901", "tcp://10.0.0.1:40901"}, 30*time.Second, nil)

	_, _, msg := doQuery(t, z, "svc.cloud.zeno.", dns.TypeAAAA)
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 AAAA record, got %d", len(msg.Answer))
	}
	aaaa, ok := msg.Answer[0].(*dns.AAAA)
	if !ok || aaaa.AAAA.String() != "fd00::1" {
		t.Fatalf("unexpected answer: %v", msg.Answer[0])
	}
}

func TestStoreServeNoData(t *testing.T) {
	z, s, _ := newTestRegistryZenet(t)
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, nil)

	// AAAA against an IPv4-only name: authoritative NOERROR with no answers.
	code, err, msg := doQuery(t, z, "svc.cloud.zeno.", dns.TypeAAAA)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("expected success, got code=%d err=%v", code, err)
	}
	if !msg.Authoritative || len(msg.Answer) != 0 || msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected authoritative no-data, got %+v", msg)
	}
}

func TestStoreServeNXDomain(t *testing.T) {
	z, _, _ := newTestRegistryZenet(t)

	code, err, msg := doQuery(t, z, "unknown.cloud.zeno.", dns.TypeA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != dns.RcodeNameError || msg.Rcode != dns.RcodeNameError || !msg.Authoritative {
		t.Fatalf("expected authoritative NXDOMAIN, got code=%d msg=%+v", code, msg)
	}
}

func TestStoreServeExpiredIsNXDomain(t *testing.T) {
	z, s, clk := newTestRegistryZenet(t)
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901"}, 5*time.Second, nil)

	clk.Advance(6 * time.Second)
	code, _, _ := doQuery(t, z, "svc.cloud.zeno.", dns.TypeA)
	if code != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for expired name, got %d", code)
	}
}

func TestStoreServeFallthrough(t *testing.T) {
	z, s, _ := newTestRegistryZenet(t)
	z.Fall = fall.Root
	z.Next = test.NextHandler(dns.RcodeRefused, nil)

	// Unknown name falls through.
	code, _, _ := doQuery(t, z, "unknown.cloud.zeno.", dns.TypeA)
	if code != dns.RcodeRefused {
		t.Fatalf("expected fallthrough on NXDOMAIN, got %d", code)
	}

	// No-data falls through.
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, nil)
	code, _, _ = doQuery(t, z, "svc.cloud.zeno.", dns.TypeAAAA)
	if code != dns.RcodeRefused {
		t.Fatalf("expected fallthrough on no-data, got %d", code)
	}

	// A positive answer does not fall through.
	code, _, msg := doQuery(t, z, "svc.cloud.zeno.", dns.TypeA)
	if code != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("expected direct answer, got code=%d answers=%d", code, len(msg.Answer))
	}
}

func TestStoreServeUnsupportedTypeFallsThrough(t *testing.T) {
	z, s, _ := newTestRegistryZenet(t)
	z.Next = test.NextHandler(dns.RcodeRefused, nil)
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, nil)

	code, _, _ := doQuery(t, z, "svc.cloud.zeno.", dns.TypeSRV)
	if code != dns.RcodeRefused {
		t.Fatalf("expected unsupported qtype to go to next plugin, got %d", code)
	}
}

func TestStoreServeTXT(t *testing.T) {
	z, s, _ := newTestRegistryZenet(t)
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, map[string]string{"proto": "rep0"})

	_, _, msg := doQuery(t, z, "svc.cloud.zeno.", dns.TypeTXT)
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 TXT record, got %d", len(msg.Answer))
	}
	txt, ok := msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("expected TXT, got %T", msg.Answer[0])
	}
	joined := strings.Join(txt.Txt, "")
	for _, want := range []string{"endpoint=tcp://10.0.0.1:40901", "port=40901", "proto=rep0"} {
		if !strings.Contains(joined, want) {
			t.Errorf("TXT %q missing %q", joined, want)
		}
	}
}

func TestStoreServeIPDedup(t *testing.T) {
	z, s, _ := newTestRegistryZenet(t)
	// Two replicas on the same host, different ports: one A record.
	mustRegister(t, s, "svc.cloud.zeno.", []string{"tcp://10.0.0.1:40901", "tcp://10.0.0.1:40902"}, 30*time.Second, nil)

	_, _, msg := doQuery(t, z, "svc.cloud.zeno.", dns.TypeA)
	if len(msg.Answer) != 1 {
		t.Fatalf("expected 1 deduplicated A record, got %d", len(msg.Answer))
	}
	// But TXT still exposes both endpoints.
	_, _, msg = doQuery(t, z, "svc.cloud.zeno.", dns.TypeTXT)
	if len(msg.Answer) != 2 {
		t.Fatalf("expected 2 TXT records, got %d", len(msg.Answer))
	}
}

func TestChunkTXT(t *testing.T) {
	if got := chunkTXT("short"); len(got) != 1 || got[0] != "short" {
		t.Fatalf("unexpected: %v", got)
	}
	long := strings.Repeat("x", 600)
	got := chunkTXT(long)
	if len(got) != 3 || len(got[0]) != 255 || len(got[1]) != 255 || len(got[2]) != 90 {
		t.Fatalf("unexpected chunking: %d segments", len(got))
	}
	if strings.Join(got, "") != long {
		t.Fatal("chunking lost data")
	}
}

func TestRegistryModeReady(t *testing.T) {
	z, _, _ := newTestRegistryZenet(t)
	if z.Ready() {
		t.Fatal("registry mode without a listener must not be ready")
	}

	addr := "inproc://zenet-reg-ready"
	z.runner = newTestRunner(t, addr)
	if !z.Ready() {
		t.Fatal("expected ready once the listener is bound")
	}
}
