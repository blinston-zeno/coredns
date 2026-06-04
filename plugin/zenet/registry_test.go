package zenet

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock is an injectable clock for deterministic TTL tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestStore(t *testing.T, mutate ...func(*registryConfig)) (*RegistryStore, *fakeClock) {
	t.Helper()
	cfg := defaultRegistryConfig()
	for _, m := range mutate {
		m(&cfg)
	}
	s := newRegistryStore(cfg)
	clk := newFakeClock()
	s.now = clk.Now
	return s, clk
}

func TestRegisterAndDiscover(t *testing.T) {
	s, _ := newTestStore(t)

	err := s.Register("svc.cloud.zeno", []string{"tcp://10.1.2.3:40901"}, 30*time.Second, map[string]string{"proto": "rep0"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	eps, remaining, found := s.Discover("svc.cloud.zeno.")
	if !found {
		t.Fatal("expected name to be found")
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].url != "tcp://10.1.2.3:40901" || eps[0].host != "10.1.2.3" || eps[0].port != "40901" {
		t.Fatalf("unexpected endpoint: %+v", eps[0])
	}
	if eps[0].meta["proto"] != "rep0" {
		t.Fatalf("expected meta to round-trip, got %v", eps[0].meta)
	}
	if remaining != 30*time.Second {
		t.Fatalf("expected 30s remaining, got %s", remaining)
	}
}

func TestNameCanonicalization(t *testing.T) {
	s, _ := newTestStore(t)

	if err := s.Register("SVC.Cloud.Zeno", []string{"tcp://10.1.2.3:40901"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Discoverable under any case, with or without trailing dot.
	for _, q := range []string{"svc.cloud.zeno", "svc.cloud.zeno.", "SVC.CLOUD.ZENO."} {
		if _, _, found := s.Discover(q); !found {
			t.Fatalf("expected %q to be found", q)
		}
	}
}

func TestRegisterIdempotentRefresh(t *testing.T) {
	s, clk := newTestStore(t)

	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.1.2.3:40901"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	clk.Advance(20 * time.Second)
	// Heartbeat: same URL again. Must refresh the lease, not duplicate.
	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.1.2.3:40901"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register (refresh): %v", err)
	}

	eps, remaining, found := s.Discover("svc.cloud.zeno")
	if !found || len(eps) != 1 {
		t.Fatalf("expected 1 endpoint after refresh, got %d (found=%v)", len(eps), found)
	}
	if remaining != 30*time.Second {
		t.Fatalf("expected refreshed lease of 30s, got %s", remaining)
	}
}

func TestPerEndpointExpiry(t *testing.T) {
	s, clk := newTestStore(t)

	// Endpoint A expires at t+30, endpoint B (registered 20s later) at t+50.
	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register A: %v", err)
	}
	clk.Advance(20 * time.Second)
	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.2:2222"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register B: %v", err)
	}

	clk.Advance(15 * time.Second) // t=35: A expired, B has 15s left
	eps, remaining, found := s.Discover("svc.cloud.zeno")
	if !found || len(eps) != 1 {
		t.Fatalf("expected only the fresh sibling to survive, got %d endpoints", len(eps))
	}
	if eps[0].url != "tcp://10.0.0.2:2222" {
		t.Fatalf("wrong survivor: %s", eps[0].url)
	}
	if remaining != 15*time.Second {
		t.Fatalf("expected 15s remaining, got %s", remaining)
	}

	// The sweeper reclaims exactly the dead endpoint.
	if got := s.Sweep(); got != 1 {
		t.Fatalf("expected Sweep to reclaim 1 endpoint, got %d", got)
	}
	names, endpoints := s.Stats()
	if names != 1 || endpoints != 1 {
		t.Fatalf("expected 1 name / 1 endpoint after sweep, got %d/%d", names, endpoints)
	}
}

func TestDiscoverAllExpiredIsNotFound(t *testing.T) {
	s, clk := newTestStore(t)

	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 5*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	clk.Advance(6 * time.Second)
	// Lazy expiry: not found even though the sweeper has not run.
	if _, _, found := s.Discover("svc.cloud.zeno"); found {
		t.Fatal("expected expired name to be not found before sweep")
	}
}

func TestUnregisterEndpointLeavesSiblings(t *testing.T) {
	s, _ := newTestStore(t)

	urls := []string{"tcp://10.0.0.1:1111", "tcp://10.0.0.2:2222"}
	if err := s.Register("svc.cloud.zeno", urls, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	s.Unregister("svc.cloud.zeno", []string{"tcp://10.0.0.1:1111"})

	eps, _, found := s.Discover("svc.cloud.zeno")
	if !found || len(eps) != 1 || eps[0].url != "tcp://10.0.0.2:2222" {
		t.Fatalf("expected only the sibling to remain, got %+v", eps)
	}
}

func TestUnregisterWholeName(t *testing.T) {
	s, _ := newTestStore(t)

	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:1111", "tcp://10.0.0.2:2222"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	s.Unregister("svc.cloud.zeno", nil)

	if _, _, found := s.Discover("svc.cloud.zeno"); found {
		t.Fatal("expected name to be gone after whole-name unregister")
	}
	// Unknown names and URLs are ignored, never panic.
	s.Unregister("svc.cloud.zeno", nil)
	s.Unregister("other.cloud.zeno", []string{"tcp://10.0.0.9:9999"})
}

func TestRegisterValidation(t *testing.T) {
	s, _ := newTestStore(t)

	cases := []struct {
		name string
		urls []string
		want error
	}{
		{"", []string{"tcp://10.0.0.1:1111"}, errNameInvalid},
		{"svc.cloud.zeno", nil, errEndpointInvalid},
		{"svc.cloud.zeno", []string{"ipc:///tmp/svc.sock"}, errEndpointInvalid},
		{"svc.cloud.zeno", []string{"tcp://example.com:1111"}, errEndpointInvalid}, // hostname, not IP literal
		{"svc.cloud.zeno", []string{"tcp://10.0.0.1"}, errEndpointInvalid},         // missing port
		{"svc.cloud.zeno", []string{"tcp://10.0.0.1:0"}, errEndpointInvalid},
		{"svc.cloud.zeno", []string{"tcp://10.0.0.1:notaport"}, errEndpointInvalid},
		{"svc.cloud.zeno", []string{"tcp://10.0.0.1:1111", "bogus"}, errEndpointInvalid},
	}
	for _, c := range cases {
		err := s.Register(c.name, c.urls, 30*time.Second, nil)
		if !errors.Is(err, c.want) {
			t.Errorf("Register(%q, %v): got %v, want %v", c.name, c.urls, err, c.want)
		}
	}
	// A rejected register must not partially apply.
	if _, _, found := s.Discover("svc.cloud.zeno"); found {
		t.Fatal("rejected register must not create the name")
	}

	// IPv6 endpoint is valid.
	if err := s.Register("v6.cloud.zeno", []string{"tcp://[fd00::1]:40901"}, 30*time.Second, nil); err != nil {
		t.Fatalf("IPv6 Register: %v", err)
	}
}

func TestCapacityNames(t *testing.T) {
	s, _ := newTestStore(t, func(c *registryConfig) { c.maxNames = 2 })

	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("svc%d.cloud.zeno", i)
		if err := s.Register(name, []string{"tcp://10.0.0.1:1111"}, 30*time.Second, nil); err != nil {
			t.Fatalf("Register %s: %v", name, err)
		}
	}
	err := s.Register("svc2.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 30*time.Second, nil)
	if !errors.Is(err, errCapacity) {
		t.Fatalf("expected errCapacity, got %v", err)
	}
	// Refreshing an existing name is always allowed at capacity.
	if err := s.Register("svc0.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 30*time.Second, nil); err != nil {
		t.Fatalf("refresh at capacity: %v", err)
	}
}

func TestTooManyEndpoints(t *testing.T) {
	s, _ := newTestStore(t, func(c *registryConfig) { c.maxEndpoints = 2 })

	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:1111", "tcp://10.0.0.2:2222"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.3:3333"}, 30*time.Second, nil)
	if !errors.Is(err, errTooManyEndpoints) {
		t.Fatalf("expected errTooManyEndpoints, got %v", err)
	}
	// Refreshing the existing endpoints never counts against the cap.
	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:1111", "tcp://10.0.0.2:2222"}, 30*time.Second, nil); err != nil {
		t.Fatalf("refresh at endpoint cap: %v", err)
	}
}

func TestTTLClamp(t *testing.T) {
	s, _ := newTestStore(t, func(c *registryConfig) {
		c.minTTL = 5 * time.Second
		c.maxTTL = 60 * time.Second
	})

	if err := s.Register("long.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, time.Hour, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, remaining, _ := s.Discover("long.cloud.zeno"); remaining != 60*time.Second {
		t.Fatalf("expected lease clamped to 60s, got %s", remaining)
	}

	if err := s.Register("short.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 0, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, remaining, _ := s.Discover("short.cloud.zeno"); remaining != 5*time.Second {
		t.Fatalf("expected lease clamped up to 5s, got %s", remaining)
	}
}

func TestSetBounds(t *testing.T) {
	s, _ := newTestStore(t, func(c *registryConfig) { c.maxNames = 1 })

	if err := s.Register("svc0.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.Register("svc1.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 30*time.Second, nil); !errors.Is(err, errCapacity) {
		t.Fatalf("expected errCapacity, got %v", err)
	}

	// Simulate a reload raising the bound: existing state must persist.
	cfg := defaultRegistryConfig()
	cfg.maxNames = 10
	s.SetBounds(cfg)

	if _, _, found := s.Discover("svc0.cloud.zeno"); !found {
		t.Fatal("existing registration lost after SetBounds")
	}
	if err := s.Register("svc1.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register after raising bound: %v", err)
	}
}

func TestDiscoverReturnsCopies(t *testing.T) {
	s, _ := newTestStore(t)

	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:1111"}, 30*time.Second, map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	eps, _, _ := s.Discover("svc.cloud.zeno")
	eps[0].meta["k"] = "mutated"
	eps[0].url = "mutated"

	eps2, _, _ := s.Discover("svc.cloud.zeno")
	if eps2[0].meta["k"] != "v" || eps2[0].url != "tcp://10.0.0.1:1111" {
		t.Fatal("Discover must return copies; caller mutation leaked into the store")
	}
}

func TestConcurrentStoreAccess(t *testing.T) {
	s, clk := newTestStore(t)

	const writers, readers, iters = 8, 8, 200
	var wg sync.WaitGroup

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			name := fmt.Sprintf("svc%d.cloud.zeno", w%4)
			url := fmt.Sprintf("tcp://10.0.0.%d:%d", w+1, 1000+w)
			for i := 0; i < iters; i++ {
				if err := s.Register(name, []string{url}, 30*time.Second, nil); err != nil {
					t.Errorf("Register: %v", err)
					return
				}
				if i%10 == 9 {
					s.Unregister(name, []string{url})
				}
			}
		}(w)
	}
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			name := fmt.Sprintf("svc%d.cloud.zeno", r%4)
			for i := 0; i < iters; i++ {
				s.Discover(name)
				s.Stats()
			}
		}(r)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			s.Sweep()
			clk.Advance(time.Millisecond)
		}
	}()

	wg.Wait()

	// Invariant: empty entries are always deleted, so every stored name has
	// at least one endpoint.
	names, endpoints := s.Stats()
	if endpoints < names {
		t.Fatalf("inconsistent stats after stress: %d names / %d endpoints", names, endpoints)
	}
}
