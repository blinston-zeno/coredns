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

	// First-ever startup.
	r1 := runners.getOrSet(addr, func() *runner { return newRunner(cfg) })
	regUniq.Set(addr, r1.start)
	if err := regUniq.ForEach(); err != nil {
		t.Fatalf("ForEach: %v", err)
	}
	t.Cleanup(func() { r1.stop() })

	if err := r1.store.Register("svc.cloud.zeno", []string{"tcp://10.0.0.1:40901"}, 30*time.Second, nil); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Reload: old instance's OnRestart resets the latch...
	regUniq.Unset(addr)
	// ...the new instance parses a config with different bounds and adopts.
	cfg2 := cfg
	cfg2.maxNames = 42
	r2 := runners.getOrSet(addr, func() *runner { return newRunner(cfg2) })
	if r2 != r1 {
		t.Fatal("new instance must adopt the existing runner, not create a new one")
	}
	r2.store.SetBounds(cfg2)
	regUniq.Set(addr, r2.start)
	if err := regUniq.ForEach(); err != nil { // start() no-ops via the started guard
		t.Fatalf("ForEach after reload: %v", err)
	}

	// State survived and the listener still answers.
	if _, _, found := r2.store.Discover("svc.cloud.zeno"); !found {
		t.Fatal("registration lost across reload")
	}
	rpc := newTestRegClient(t, addr)
	if reply := rpc(`{"discover":{"name":"svc.cloud.zeno"}}`); !reply.OK || !*reply.Found {
		t.Fatalf("listener dead after reload: %+v", reply)
	}

	// Failed reload: OnRestartFailed re-arms and runs start again — no-op.
	regUniq.Unset(addr)
	regUniq.Set(addr, r1.start)
	if err := regUniq.ForEach(); err != nil {
		t.Fatalf("ForEach after failed reload: %v", err)
	}
	if _, _, found := r1.store.Discover("svc.cloud.zeno"); !found {
		t.Fatal("registration lost across failed reload")
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

	r := runners.getOrSet(addr, func() *runner { return newRunner(cfg) })
	regUniq.Set(addr, r.start)
	if err := regUniq.ForEach(); err != nil {
		t.Fatalf("ForEach: %v", err)
	}
	t.Cleanup(func() { r.stop() })

	runtime.GC()
	baseline := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		regUniq.Unset(addr)
		got := runners.getOrSet(addr, func() *runner { return newRunner(cfg) })
		if got != r {
			t.Fatal("adoption returned a different runner")
		}
		got.store.SetBounds(cfg)
		regUniq.Set(addr, got.start)
		if err := regUniq.ForEach(); err != nil {
			t.Fatalf("ForEach (iteration %d): %v", i, err)
		}
	}

	runtime.GC()
	if after := runtime.NumGoroutine(); after > baseline+3 {
		t.Fatalf("goroutine leak across reloads: baseline %d, after %d", baseline, after)
	}
}
