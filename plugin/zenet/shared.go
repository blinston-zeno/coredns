package zenet

import (
	"sync"
)

// Reload safety. On a Corefile reload CoreDNS instantiates new plugin
// objects while the old instance still serves; the registry's REP listener
// and its in-memory registrations must survive that hand-over without a
// double-bind or state loss. A process-wide map keyed by listen address hands
// the existing runner to the new instance (adoption); start() is idempotent,
// so every server block can call it and the socket can never double-bind.
//
// Config generations make address changes safe. caddy's reload sequence is:
// the old instance's OnRestart hooks run first, then the new config's setup()
// calls, then the new instance's OnStartup hooks; only if all of that
// succeeds is the old instance stopped (a failure rolls back to it and runs
// its OnRestartFailed hooks). We use those boundaries as follows:
//
//   - OnRestart (old instance)   -> beginGeneration: start tracking claims
//   - setup() (new instance)     -> claim: record which addresses the new
//     config references, adopting existing runners
//   - OnStartup (new instance)   -> reconcile: stop and remove runners whose
//     address is no longer claimed. When the operator moved the listen
//     address (exactly one stale runner, exactly one new runner) the stale
//     store's registrations are first migrated into the new runner so DNS
//     answers survive the move; services must re-dial the new address for
//     their next heartbeat.
//   - OnRestartFailed (old)      -> revive: re-bind this instance's runner if
//     reconcile of the failed generation stopped it, and re-apply its bounds.
//
// Bounds (SetBounds) are also applied in OnStartup, never at setup() time, so
// a reload that fails validation cannot leave the discarded config's bounds
// on the live store.

// runnerReg is the process-wide set of registry runners, keyed by listen
// address, plus the claim tracking for the config generation currently being
// applied.
type runnerReg struct {
	sync.Mutex
	m map[string]*runner

	genOpen bool
	claimed map[string]bool
	created map[string]*runner
}

// beginGeneration opens claim tracking for an incoming config generation.
// Called from OnRestart (which caddy runs before the new config's setup()
// calls); calling it more than once per reload is harmless.
func (rr *runnerReg) beginGeneration() {
	rr.Lock()
	defer rr.Unlock()
	rr.genOpen = true
	rr.claimed = make(map[string]bool)
	rr.created = make(map[string]*runner)
}

// claim returns the runner for addr, creating it with mk on first use, and
// records addr as referenced by the config generation being applied. On
// reload the new plugin instance adopts the existing runner — same store,
// same bound socket.
func (rr *runnerReg) claim(addr string, mk func() *runner) *runner {
	rr.Lock()
	defer rr.Unlock()
	if rr.claimed == nil {
		rr.claimed = make(map[string]bool)
	}
	rr.claimed[addr] = true
	if r, ok := rr.m[addr]; ok {
		return r
	}
	r := mk()
	rr.m[addr] = r
	if rr.created == nil {
		rr.created = make(map[string]*runner)
	}
	rr.created[addr] = r
	return r
}

// reconcile closes the open config generation: every runner whose address the
// new config did not claim is stopped and removed. If the generation replaced
// exactly one listener with exactly one new one (the operator moved the
// listen address), the stale store's registrations are migrated into the new
// runner first. Idempotent per generation; a no-op on first startup. Called
// from OnStartup, i.e. only when the new config actually commits.
func (rr *runnerReg) reconcile() {
	rr.Lock()
	if !rr.genOpen {
		rr.Unlock()
		return
	}
	rr.genOpen = false

	var stale []*runner
	for addr, r := range rr.m {
		if !rr.claimed[addr] {
			stale = append(stale, r)
			delete(rr.m, addr)
		}
	}
	var createdOne *runner
	if len(rr.created) == 1 {
		for _, r := range rr.created {
			createdOne = r
		}
	}
	rr.claimed, rr.created = nil, nil
	rr.Unlock()

	for _, old := range stale {
		if !old.isStarted() {
			continue // unstarted leftover of a failed reload; nothing to stop
		}
		if createdOne != nil && len(stale) == 1 {
			n := createdOne.store.adoptFrom(old.store)
			log.Warningf("registry listen address changed from %s to %s: migrated %d names; stopping the old listener (services must heartbeat the new address)",
				old.cfg.listen, createdOne.cfg.listen, n)
		} else {
			log.Warningf("registry listener %s is no longer in the config: stopping it; its registrations are dropped", old.cfg.listen)
		}
		if err := old.stop(); err != nil {
			log.Warningf("stopping stale registry listener %s: %v", old.cfg.listen, err)
		}
	}
}

// revive restores a runner for addr after a failed reload. The common case
// (address unchanged) returns the still-running runner. If the failed
// generation's reconcile stopped this runner as the stale side of an address
// change, a fresh runner re-wraps the surviving store and re-binds on the
// next start().
func (rr *runnerReg) revive(addr string, cfg registryConfig, store *RegistryStore) *runner {
	rr.Lock()
	defer rr.Unlock()
	if r, ok := rr.m[addr]; ok && !r.isStopped() {
		return r
	}
	r := newRunnerWithStore(cfg, store)
	rr.m[addr] = r
	return r
}

var runners = &runnerReg{m: make(map[string]*runner)}
