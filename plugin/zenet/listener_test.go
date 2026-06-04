package zenet

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/req"
)

// newTestRunner starts a registry runner on addr, cleaned up with the test.
func newTestRunner(t *testing.T, addr string, mutate ...func(*registryConfig)) *runner {
	t.Helper()
	cfg := defaultRegistryConfig()
	cfg.listen = addr
	cfg.workers = 2
	cfg.sweepInterval = 10 * time.Millisecond
	for _, m := range mutate {
		m(&cfg)
	}
	r := newRunner(cfg)
	if err := r.start(); err != nil {
		t.Fatalf("runner start: %v", err)
	}
	t.Cleanup(func() { r.stop() })
	return r
}

// newTestRegClient returns a REQ client dialing addr and a helper that sends
// one raw protocol message and returns the decoded reply.
func newTestRegClient(t *testing.T, addr string) func(raw string) registryReply {
	t.Helper()
	sock, err := req.NewSocket()
	if err != nil {
		t.Fatalf("req socket: %v", err)
	}
	if err := sock.SetOption(mangos.OptionSendDeadline, 2*time.Second); err != nil {
		t.Fatalf("send deadline: %v", err)
	}
	if err := sock.SetOption(mangos.OptionRecvDeadline, 2*time.Second); err != nil {
		t.Fatalf("recv deadline: %v", err)
	}
	if err := sock.Dial(addr); err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { sock.Close() })

	return func(raw string) registryReply {
		t.Helper()
		if err := sock.Send([]byte(raw)); err != nil {
			t.Fatalf("send: %v", err)
		}
		msg, err := sock.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		var reply registryReply
		if err := json.Unmarshal(msg, &reply); err != nil {
			t.Fatalf("decode reply %q: %v", msg, err)
		}
		return reply
	}
}

func TestListenerRegisterDiscoverUnregister(t *testing.T) {
	addr := "inproc://zenet-reg-happy"
	newTestRunner(t, addr)
	rpc := newTestRegClient(t, addr)

	reply := rpc(`{"version":1,"register":{"name":"svc.cloud.zeno","endpoints":["tcp://10.0.0.1:40901"],"ttl":30,"meta":{"proto":"rep0"}}}`)
	if !reply.OK {
		t.Fatalf("register failed: %+v", reply)
	}

	reply = rpc(`{"discover":{"name":"svc.cloud.zeno"}}`)
	if !reply.OK || reply.Found == nil || !*reply.Found {
		t.Fatalf("discover failed: %+v", reply)
	}
	if len(reply.Endpoints) != 1 || reply.Endpoints[0] != "tcp://10.0.0.1:40901" {
		t.Fatalf("unexpected endpoints: %v", reply.Endpoints)
	}
	if reply.Meta["proto"] != "rep0" {
		t.Fatalf("unexpected meta: %v", reply.Meta)
	}
	if reply.TTL == 0 || reply.TTL > 30 {
		t.Fatalf("unexpected ttl: %d", reply.TTL)
	}

	reply = rpc(`{"unregister":{"name":"svc.cloud.zeno"}}`)
	if !reply.OK {
		t.Fatalf("unregister failed: %+v", reply)
	}

	reply = rpc(`{"discover":{"name":"svc.cloud.zeno"}}`)
	if !reply.OK || reply.Found == nil || *reply.Found {
		t.Fatalf("expected not-found after unregister: %+v", reply)
	}
}

func TestListenerRegisterIsHeartbeat(t *testing.T) {
	addr := "inproc://zenet-reg-heartbeat"
	r := newTestRunner(t, addr)
	rpc := newTestRegClient(t, addr)

	for i := 0; i < 3; i++ {
		reply := rpc(`{"register":{"name":"svc.cloud.zeno","endpoints":["tcp://10.0.0.1:40901"],"ttl":30}}`)
		if !reply.OK {
			t.Fatalf("heartbeat %d failed: %+v", i, reply)
		}
	}
	if names, endpoints := r.store.Stats(); names != 1 || endpoints != 1 {
		t.Fatalf("heartbeats must not duplicate: %d names / %d endpoints", names, endpoints)
	}
}

func TestListenerErrorShapes(t *testing.T) {
	addr := "inproc://zenet-reg-errors"
	newTestRunner(t, addr, func(c *registryConfig) {
		c.maxPayload = 256
		c.maxEndpoints = 1
	})
	rpc := newTestRegClient(t, addr)

	cases := []struct {
		name string
		raw  string
		code string
	}{
		{"malformed JSON", `{not json`, errCodeBadRequest},
		{"no action", `{"version":1}`, errCodeBadRequest},
		{"two actions", `{"register":{"name":"a.b","endpoints":["tcp://10.0.0.1:1"],"ttl":1},"discover":{"name":"a.b"}}`, errCodeBadRequest},
		{"bad version", `{"version":2,"discover":{"name":"a.b"}}`, errCodeUnsupportedVersion},
		{"empty name", `{"register":{"name":"","endpoints":["tcp://10.0.0.1:1"],"ttl":1}}`, errCodeNameInvalid},
		{"discover bad name", `{"discover":{"name":""}}`, errCodeNameInvalid},
		{"unregister bad name", `{"unregister":{"name":""}}`, errCodeNameInvalid},
		{"hostname endpoint", `{"register":{"name":"a.b","endpoints":["tcp://example.com:1"],"ttl":1}}`, errCodeEndpointInvalid},
		{"non-tcp endpoint", `{"register":{"name":"a.b","endpoints":["ipc:///tmp/x"],"ttl":1}}`, errCodeEndpointInvalid},
		{"no endpoints", `{"register":{"name":"a.b","ttl":1}}`, errCodeEndpointInvalid},
		{"too many endpoints", `{"register":{"name":"a.b","endpoints":["tcp://10.0.0.1:1","tcp://10.0.0.2:2"],"ttl":1}}`, errCodeTooManyEndpoints},
		{"oversize payload", `{"register":{"name":"a.b","endpoints":["tcp://10.0.0.1:1"],"ttl":1,"meta":{"pad":"` + strings.Repeat("x", 300) + `"}}}`, errCodeTooLarge},
	}
	for _, c := range cases {
		reply := rpc(c.raw)
		if reply.OK {
			t.Errorf("%s: expected error, got OK", c.name)
			continue
		}
		if reply.Error != c.code {
			t.Errorf("%s: got code %q, want %q (detail: %s)", c.name, reply.Error, c.code, reply.Detail)
		}
	}
}

func TestListenerMetaLimits(t *testing.T) {
	addr := "inproc://zenet-reg-meta"
	newTestRunner(t, addr)
	rpc := newTestRegClient(t, addr)

	// More than maxMetaEntries keys.
	meta := map[string]string{}
	for i := 0; i <= maxMetaEntries; i++ {
		meta[fmt.Sprintf("k%d", i)] = "v"
	}
	body, _ := json.Marshal(registryRequest{Register: &registerBody{
		Name: "svc.cloud.zeno", Endpoints: []string{"tcp://10.0.0.1:1"}, TTL: 1, Meta: meta,
	}})
	reply := rpc(string(body))
	if reply.OK || reply.Error != errCodeBadRequest {
		t.Fatalf("expected bad_request for oversized meta, got %+v", reply)
	}
}

func TestListenerTokenIgnored(t *testing.T) {
	addr := "inproc://zenet-reg-token"
	newTestRunner(t, addr)
	rpc := newTestRegClient(t, addr)

	// v1 parses but ignores token; it must not be rejected.
	reply := rpc(`{"token":"whatever","register":{"name":"svc.cloud.zeno","endpoints":["tcp://10.0.0.1:1"],"ttl":1}}`)
	if !reply.OK {
		t.Fatalf("register with token failed: %+v", reply)
	}
}

func TestListenerSweeperReclaims(t *testing.T) {
	addr := "inproc://zenet-reg-sweep"
	r := newTestRunner(t, addr, func(c *registryConfig) { c.minTTL = 10 * time.Millisecond })
	rpc := newTestRegClient(t, addr)

	if reply := rpc(`{"register":{"name":"svc.cloud.zeno","endpoints":["tcp://10.0.0.1:1"],"ttl":0}}`); !reply.OK {
		t.Fatalf("register failed: %+v", reply)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if names, _ := r.store.Stats(); names == 0 {
			break // sweeper reclaimed the expired endpoint
		}
		if time.Now().After(deadline) {
			t.Fatal("sweeper did not reclaim the expired endpoint")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunnerStartIdempotentAndStopGraceful(t *testing.T) {
	addr := "inproc://zenet-reg-lifecycle"
	cfg := defaultRegistryConfig()
	cfg.listen = addr
	cfg.workers = 2
	cfg.sweepInterval = 10 * time.Millisecond
	r := newRunner(cfg)

	if err := r.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// A second start must not double-bind (inproc would error on rebind).
	if err := r.start(); err != nil {
		t.Fatalf("second start must be a no-op, got: %v", err)
	}
	if !r.listening() {
		t.Fatal("expected listening after start")
	}

	done := make(chan error, 1)
	go func() { done <- r.stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not return promptly")
	}
	if r.listening() {
		t.Fatal("expected not listening after stop")
	}
	// stop is idempotent (multiple server blocks register it as a hook).
	if err := r.stop(); err != nil {
		t.Fatalf("second stop must be a no-op, got: %v", err)
	}
}

// TestReloadAdoption simulates the CoreDNS reload sequence: the new plugin
// instance must adopt the existing runner (same store pointer, no re-bind)
// and registrations must survive.
func TestReloadAdoption(t *testing.T) {
	addr := "inproc://zenet-reg-reload"
	cfg := defaultRegistryConfig()
	cfg.listen = addr
	cfg.workers = 2
	rr := &runnerReg{m: make(map[string]*runner)}

	// First-ever startup: claim + OnStartup (reconcile is a no-op, then start).
	r1 := rr.claim(addr, func() *runner { return newRunner(cfg) })
	rr.reconcile()
	r1.store.SetBounds(cfg)
	if err := r1.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { r1.stop() })

	if err := r1.store.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Reload: old instance's OnRestart opens the generation...
	rr.beginGeneration()
	// ...the new instance parses a config with different bounds and adopts.
	cfg2 := cfg
	cfg2.maxNames = 42
	r2 := rr.claim(addr, func() *runner { return newRunner(cfg2) })
	if r2 != r1 {
		t.Fatal("new instance must adopt the existing runner, not create a new one")
	}
	// Committed reload: OnStartup runs reconcile, bounds, start (no-op).
	rr.reconcile()
	r2.store.SetBounds(cfg2)
	if err := r2.start(); err != nil { // no-ops via the started guard
		t.Fatalf("start after reload: %v", err)
	}

	// State survived and the listener still answers.
	if _, _, found := r2.store.Discover("svc.cloud.zeno"); !found {
		t.Fatal("registration lost across reload")
	}
	rpc := newTestRegClient(t, addr)
	if reply := rpc(`{"discover":{"name":"svc.cloud.zeno"}}`); !reply.OK || !*reply.Found {
		t.Fatalf("listener dead after reload: %+v", reply)
	}

	// Failed reload: OnRestartFailed revives (same runner, still running),
	// re-applies the old bounds and re-runs start — a no-op.
	rr.beginGeneration()
	_ = rr.claim(addr, func() *runner { return newRunner(cfg) }) // failed gen's setup
	revived := rr.revive(addr, cfg, r1.store)
	if revived != r1 {
		t.Fatal("revive must return the still-running runner")
	}
	revived.store.SetBounds(cfg)
	if err := revived.start(); err != nil {
		t.Fatalf("start after failed reload: %v", err)
	}
	if _, _, found := r1.store.Discover("svc.cloud.zeno"); !found {
		t.Fatal("registration lost across failed reload")
	}
}

// TestReloadAddressChange simulates a reload that moves the registry listen
// address: the new runner must inherit the registrations, the old listener
// must be stopped and removed, and the new listener must answer.
func TestReloadAddressChange(t *testing.T) {
	addrA := "inproc://zenet-reg-move-a"
	addrB := "inproc://zenet-reg-move-b"
	cfgA := defaultRegistryConfig()
	cfgA.listen = addrA
	cfgA.workers = 2
	rr := &runnerReg{m: make(map[string]*runner)}

	rA := rr.claim(addrA, func() *runner { return newRunner(cfgA) })
	rr.reconcile()
	if err := rA.start(); err != nil {
		t.Fatalf("start A: %v", err)
	}
	t.Cleanup(func() { rA.stop() })
	if err := rA.store.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Reload with the listen address moved to B.
	rr.beginGeneration()
	cfgB := cfgA
	cfgB.listen = addrB
	rB := rr.claim(addrB, func() *runner { return newRunner(cfgB) })
	if rB == rA {
		t.Fatal("address change must create a new runner")
	}
	rr.reconcile() // migrates A's store into B and stops A
	if err := rB.start(); err != nil {
		t.Fatalf("start B: %v", err)
	}
	t.Cleanup(func() { rB.stop() })

	if rA.listening() {
		t.Fatal("old listener must be stopped after the address change commits")
	}
	if _, ok := rr.m[addrA]; ok {
		t.Fatal("old runner must be removed from the registry")
	}
	if _, _, found := rB.store.Discover("svc.cloud.zeno"); !found {
		t.Fatal("registrations were not migrated to the new address")
	}
	rpc := newTestRegClient(t, addrB)
	if reply := rpc(`{"discover":{"name":"svc.cloud.zeno"}}`); !reply.OK || !*reply.Found {
		t.Fatalf("new listener not answering after address change: %+v", reply)
	}
}

// TestReloadAddressChangeRollback simulates an address-change reload that
// fails after the new generation's OnStartup already stopped the old runner:
// OnRestartFailed must re-bind the old address around the surviving store.
func TestReloadAddressChangeRollback(t *testing.T) {
	addrA := "inproc://zenet-reg-rollback-a"
	addrB := "inproc://zenet-reg-rollback-b"
	cfgA := defaultRegistryConfig()
	cfgA.listen = addrA
	cfgA.workers = 2
	rr := &runnerReg{m: make(map[string]*runner)}

	rA := rr.claim(addrA, func() *runner { return newRunner(cfgA) })
	rr.reconcile()
	if err := rA.start(); err != nil {
		t.Fatalf("start A: %v", err)
	}
	t.Cleanup(func() { rA.stop() })
	if err := rA.store.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Reload moves the address; OnStartup of the new generation runs...
	rr.beginGeneration()
	cfgB := cfgA
	cfgB.listen = addrB
	rB := rr.claim(addrB, func() *runner { return newRunner(cfgB) })
	rr.reconcile()
	if err := rB.start(); err != nil {
		t.Fatalf("start B: %v", err)
	}
	// ...but the restart fails afterwards (e.g. a server bind elsewhere).
	// The old instance's OnRestartFailed revives its runner.
	if err := rB.stop(); err != nil { // the failed instance is torn down
		t.Fatalf("stop B: %v", err)
	}
	revived := rr.revive(addrA, cfgA, rA.store)
	if revived == rA {
		t.Fatal("revive must build a fresh runner: the old one was stopped")
	}
	revived.store.SetBounds(cfgA)
	if err := revived.start(); err != nil {
		t.Fatalf("start revived: %v", err)
	}
	t.Cleanup(func() { revived.stop() })

	if _, _, found := revived.store.Discover("svc.cloud.zeno"); !found {
		t.Fatal("registrations lost across failed address-change reload")
	}
	rpc := newTestRegClient(t, addrA)
	if reply := rpc(`{"discover":{"name":"svc.cloud.zeno"}}`); !reply.OK || !*reply.Found {
		t.Fatalf("revived listener not answering: %+v", reply)
	}
}

// TestDiscoverRPCTTLSubSecond is a regression test mirroring the DNS-path
// rule on the RPC side: a lease in its final sub-second reports TTL 0, never
// rounded up to 1.
func TestDiscoverRPCTTLSubSecond(t *testing.T) {
	s, clk := newTestStore(t)
	r := newRunnerWithStore(defaultRegistryConfig(), s)

	if err := s.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:40901"}, 5*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	clk.Advance(4*time.Second + 700*time.Millisecond) // 300ms of lease left

	var reply registryReply
	if err := json.Unmarshal(r.handleDiscover(&discoverBody{Name: "svc.cloud.zeno"}), &reply); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reply.OK || reply.Found == nil || !*reply.Found {
		t.Fatalf("expected found reply, got %+v", reply)
	}
	if reply.TTL != 0 {
		t.Fatalf("expected TTL 0 for a sub-second lease, got %d", reply.TTL)
	}
}

// TestStartErrorPropagates is a regression test: a listener that cannot bind
// must fail OnStartup loudly, not be swallowed (the old uniq.ForEach wiring
// discarded start errors).
func TestStartErrorPropagates(t *testing.T) {
	cfg := defaultRegistryConfig()
	cfg.listen = "bogus://not-a-transport"
	cfg.workers = 2
	r := newRunner(cfg)
	if err := r.start(); err == nil {
		t.Fatal("expected a bind error from start()")
	}
	if r.listening() {
		t.Fatal("runner must not report listening after a failed start")
	}
	// The bind is retried on the next start call (e.g. the next reload).
	if err := r.start(); err == nil {
		t.Fatal("expected the retried start to fail again, not no-op")
	}
}

// TestReloadLoopGoroutineStability loops the reload simulation and asserts
// the goroutine count stays flat: keeping the listener alive across reloads
// must not leak workers.
func TestReloadLoopGoroutineStability(t *testing.T) {
	addr := "inproc://zenet-reg-reload-loop"
	cfg := defaultRegistryConfig()
	cfg.listen = addr
	cfg.workers = 2

	rr := &runnerReg{m: make(map[string]*runner)}
	r := rr.claim(addr, func() *runner { return newRunner(cfg) })
	rr.reconcile()
	if err := r.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { r.stop() })

	runtime.GC()
	baseline := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		rr.beginGeneration()
		got := rr.claim(addr, func() *runner { return newRunner(cfg) })
		if got != r {
			t.Fatal("adoption returned a different runner")
		}
		rr.reconcile()
		got.store.SetBounds(cfg)
		if err := got.start(); err != nil {
			t.Fatalf("start (iteration %d): %v", i, err)
		}
	}

	runtime.GC()
	if after := runtime.NumGoroutine(); after > baseline+3 {
		t.Fatalf("goroutine leak across reloads: baseline %d, after %d", baseline, after)
	}
}
