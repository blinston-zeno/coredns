package zenet

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/rep"
)

// shutdownTimeout bounds how long stop() waits for worker goroutines so a
// stuck worker cannot hang process exit.
const shutdownTimeout = 5 * time.Second

// runner bundles the long-lived registry state for one listen address: the
// store, the mangos REP listener and its worker/sweeper goroutines. A runner
// is created once per listen address and deliberately survives Corefile
// reloads (see shared.go); it is only torn down at final process shutdown.
type runner struct {
	cfg   registryConfig
	store *RegistryStore

	mu      sync.Mutex
	started bool
	stopped bool
	sock    mangos.Socket
	done    chan struct{}
	wg      sync.WaitGroup
}

func newRunner(cfg registryConfig) *runner {
	return newRunnerWithStore(cfg, newRegistryStore(cfg))
}

// newRunnerWithStore wraps an existing store; used by revive after a failed
// reload so the surviving registrations keep their runner.
func newRunnerWithStore(cfg registryConfig, store *RegistryStore) *runner {
	return &runner{cfg: cfg, store: store}
}

// start binds the REP socket and spawns the worker and sweeper goroutines.
// It is idempotent: a second call (e.g. via OnRestartFailed after a reload
// attempt) is a no-op, so the socket can never double-bind.
func (r *runner) start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return nil
	}

	sock, err := rep.NewSocket()
	if err != nil {
		return fmt.Errorf("failed to create registry REP socket: %w", err)
	}
	if err := sock.Listen(r.cfg.listen); err != nil {
		sock.Close()
		return fmt.Errorf("failed to listen on %s: %w", r.cfg.listen, err)
	}

	r.sock = sock
	r.done = make(chan struct{})

	for i := 0; i < r.cfg.workers; i++ {
		cx, err := sock.OpenContext()
		if err != nil {
			sock.Close()
			return fmt.Errorf("failed to open REP context: %w", err)
		}
		r.wg.Add(1)
		go r.serveWorker(cx)
	}

	r.wg.Add(1)
	go r.sweeper()

	r.started = true
	log.Infof("registry listening on %s (%d workers, sweep every %s)", r.cfg.listen, r.cfg.workers, r.cfg.sweepInterval)
	return nil
}

// stop closes the socket (which unblocks every worker's Recv), stops the
// sweeper and waits for all goroutines with a bounded timeout. Idempotent:
// multiple server blocks sharing one address each register stop as a
// final-shutdown hook.
func (r *runner) stop() error {
	r.mu.Lock()
	if !r.started || r.stopped {
		r.mu.Unlock()
		return nil
	}
	r.stopped = true
	sock, done := r.sock, r.done
	r.mu.Unlock()

	close(done)
	sock.Close()

	finished := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("registry listener on %s did not shut down within %s", r.cfg.listen, shutdownTimeout)
	}
}

// listening reports whether the REP socket is bound (used by Ready()).
func (r *runner) listening() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started && !r.stopped
}

func (r *runner) isStarted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started
}

func (r *runner) isStopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped
}

// serveWorker is one REP request slot: each context serves one request at a
// time, multiplexed over the shared socket (the same mechanism the resolver
// mode uses on the REQ side).
func (r *runner) serveWorker(cx mangos.Context) {
	defer r.wg.Done()
	defer cx.Close()
	for {
		msg, err := cx.Recv()
		if err != nil {
			return // socket closed
		}
		reply := r.handle(msg)
		if err := cx.Send(reply); err != nil {
			if errors.Is(err, mangos.ErrClosed) {
				return
			}
			// The requester vanished; drop the reply and keep serving.
			log.Debugf("registry reply send failed: %v", err)
		}
	}
}

// sweeper periodically reclaims expired endpoints and refreshes the gauges.
func (r *runner) sweeper() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cfg.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			// Sweep already visits every entry; it returns the surviving
			// counts so the gauges need no second full scan.
			reclaimed, names, endpoints := r.store.Sweep()
			if reclaimed > 0 {
				expirationsCount.Add(float64(reclaimed))
			}
			registryNames.Set(float64(names))
			registryEndpoints.Set(float64(endpoints))
		}
	}
}

// handle decodes one protocol message and dispatches it against the store.
// It always returns a marshalable reply; protocol failures never panic or
// close the connection.
func (r *runner) handle(msg []byte) []byte {
	if len(msg) > r.cfg.maxPayload {
		return errReply(errCodeTooLarge, fmt.Sprintf("payload %d > %d bytes", len(msg), r.cfg.maxPayload))
	}

	var req registryRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		return errReply(errCodeBadRequest, "malformed JSON")
	}
	if req.Version != 0 && req.Version != protocolVersion {
		return errReply(errCodeUnsupportedVersion, fmt.Sprintf("protocol version %d not supported", req.Version))
	}

	set := 0
	if req.Register != nil {
		set++
	}
	if req.Unregister != nil {
		set++
	}
	if req.Discover != nil {
		set++
	}
	if set != 1 {
		return errReply(errCodeBadRequest, "exactly one of register, unregister or discover must be set")
	}

	switch {
	case req.Register != nil:
		return r.handleRegister(req.Register)
	case req.Unregister != nil:
		return r.handleUnregister(req.Unregister)
	default:
		return r.handleDiscover(req.Discover)
	}
}

func (r *runner) handleRegister(b *registerBody) []byte {
	if err := validateMeta(b.Meta); err != nil {
		return errReply(errCodeBadRequest, err.Error())
	}
	err := r.store.Register(b.Name, b.Endpoints, time.Duration(b.TTL)*time.Second, b.Meta)
	if err != nil {
		return errReply(storeErrCode(err), err.Error())
	}
	registrationsCount.WithLabelValues("register").Inc()
	return okReply()
}

func (r *runner) handleUnregister(b *unregisterBody) []byte {
	if _, err := canonicalizeName(b.Name); err != nil {
		return errReply(errCodeNameInvalid, err.Error())
	}
	r.store.Unregister(b.Name, b.Endpoints)
	registrationsCount.WithLabelValues("unregister").Inc()
	return okReply()
}

func (r *runner) handleDiscover(b *discoverBody) []byte {
	if _, err := canonicalizeName(b.Name); err != nil {
		return errReply(errCodeNameInvalid, err.Error())
	}
	discoverCount.WithLabelValues("rpc").Inc()

	eps, minRemaining, found := r.store.Discover(b.Name)
	reply := registryReply{OK: true, Found: &found}
	if found {
		urls := make([]string, len(eps))
		merged := map[string]string{}
		for i, ep := range eps { // eps are sorted by URL; later URLs win on key conflicts
			urls[i] = ep.url
			for k, v := range ep.meta {
				merged[k] = v
			}
		}
		reply.Endpoints = urls
		if len(merged) > 0 {
			reply.Meta = merged
		}
		// Truncate, never round up: a sub-second remaining lease reports
		// TTL 0 so a consumer can never cache past the lease.
		reply.TTL = uint32(minRemaining / time.Second)
	}
	return marshalReply(reply)
}

// storeErrCode maps a store error onto its protocol error code.
func storeErrCode(err error) string {
	switch {
	case errors.Is(err, errNameInvalid):
		return errCodeNameInvalid
	case errors.Is(err, errEndpointInvalid):
		return errCodeEndpointInvalid
	case errors.Is(err, errTooManyEndpoints):
		return errCodeTooManyEndpoints
	case errors.Is(err, errCapacity):
		return errCodeCapacity
	}
	return errCodeBadRequest
}

func okReply() []byte {
	return marshalReply(registryReply{OK: true})
}

func errReply(code, detail string) []byte {
	registryErrorsCount.WithLabelValues(code).Inc()
	return marshalReply(registryReply{OK: false, Error: code, Detail: detail})
}

func marshalReply(reply registryReply) []byte {
	b, err := json.Marshal(reply)
	if err != nil {
		// Unreachable with these field types; never reply with garbage.
		return []byte(`{"ok":false,"error":"bad_request","detail":"internal marshal failure"}`)
	}
	return b
}
