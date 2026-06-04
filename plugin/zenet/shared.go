package zenet

import (
	"sync"

	"github.com/coredns/coredns/plugin/pkg/uniq"
)

// Reload safety. On a Corefile reload CoreDNS instantiates new plugin
// objects while the old instance still serves; the registry's REP listener
// and its in-memory registrations must survive that hand-over without a
// double-bind or state loss. The pattern mirrors plugin/metrics: a
// process-wide map keyed by listen address hands the existing runner to the
// new instance (adoption), and a uniq latch makes the bind-once start
// function run exactly once per address.
//
// Deliberate divergence from plugin/metrics: metrics stops its HTTP listener
// in OnRestart because the next instance cheaply rebuilds it. Our runner IS
// the state (the registration store hangs off it), so OnRestart only resets
// the uniq latch and the listener keeps running; real teardown happens in
// OnFinalShutdown only. Consequence: changing the registry listen address in
// a reload leaves the old listener bound until process restart (documented).

// runnerReg is the process-wide set of registry runners, keyed by listen
// address.
type runnerReg struct {
	sync.Mutex
	m map[string]*runner
}

// getOrSet returns the runner for addr, creating it with mk on first use.
// On reload the new plugin instance adopts the existing runner — same store,
// same bound socket.
func (rr *runnerReg) getOrSet(addr string, mk func() *runner) *runner {
	rr.Lock()
	defer rr.Unlock()
	if r, ok := rr.m[addr]; ok {
		return r
	}
	r := mk()
	rr.m[addr] = r
	return r
}

var (
	runners = &runnerReg{m: make(map[string]*runner)}
	regUniq = uniq.New()
)
