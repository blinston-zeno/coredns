package zenet

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Registry store errors. The listener maps these onto protocol error codes.
var (
	errNameInvalid      = errors.New("invalid service name")
	errEndpointInvalid  = errors.New("invalid endpoint")
	errTooManyEndpoints = errors.New("too many endpoints for name")
	errCapacity         = errors.New("registry name capacity reached")
)

// registryConfig holds the registry-mode configuration parsed from the
// Corefile. The numeric bounds are copied into the store and may be refreshed
// on reload; listen, workers and sweepInterval are structural and require a
// process restart to change.
type registryConfig struct {
	listen        string
	minTTL        time.Duration
	maxTTL        time.Duration
	maxNames      int
	maxEndpoints  int
	maxPayload    int
	workers       int
	sweepInterval time.Duration
}

// Registry-mode defaults.
const (
	defaultRegistryListen = "tcp://0.0.0.0:40900"
	defaultMinTTL         = 1 * time.Second
	defaultMaxTTL         = 300 * time.Second
	defaultMaxNames       = 10000
	defaultMaxEndpoints   = 64
	defaultMaxPayload     = 16384
	defaultSweepInterval  = 1 * time.Second
)

// Worker pool bounds. The default is NumCPU clamped to [minDefaultWorkers,
// maxWorkers]; an explicit registry_workers value is validated against
// [1, maxWorkers] at parse time.
const (
	minDefaultWorkers = 4
	maxWorkers        = 64
)

// defaultWorkers sizes the REP handler pool: registration handling is a
// short in-memory map operation, so a small pool bounded by core count is
// plenty even at high heartbeat rates.
func defaultWorkers() int {
	n := runtime.NumCPU()
	if n < minDefaultWorkers {
		return minDefaultWorkers
	}
	if n > maxWorkers {
		return maxWorkers
	}
	return n
}

func defaultRegistryConfig() registryConfig {
	return registryConfig{
		listen:        defaultRegistryListen,
		minTTL:        defaultMinTTL,
		maxTTL:        defaultMaxTTL,
		maxNames:      defaultMaxNames,
		maxEndpoints:  defaultMaxEndpoints,
		maxPayload:    defaultMaxPayload,
		workers:       defaultWorkers(),
		sweepInterval: defaultSweepInterval,
	}
}

// endpoint is a single registered replica of a service. Host and Port are
// pre-parsed from URL at registration time so the DNS path never parses URLs.
type endpoint struct {
	url     string
	host    string
	port    string
	meta    map[string]string
	alts    map[string]string // transport key ("ipc"/"tls") -> alternate URL; shares the endpoint's lease
	expires time.Time
	lease   time.Duration
}

// serviceEntry is the set of registered endpoints for one name, keyed by
// endpoint URL so that a repeated register is an idempotent refresh.
type serviceEntry struct {
	eps map[string]*endpoint
}

// RegistryStore is the in-memory, TTL'd service registry. It is shared by the
// registration listener goroutines, the DNS handler goroutines and the expiry
// sweeper, guarded by a single RWMutex: every operation is a short map
// manipulation on a bounded dataset, so contention is not a concern at this
// scale. Expiry is enforced both lazily on read (Discover never returns a
// dead endpoint) and by the periodic Sweep (memory reclamation).
type RegistryStore struct {
	mu    sync.RWMutex
	names map[string]*serviceEntry
	now   func() time.Time

	minTTL       time.Duration
	maxTTL       time.Duration
	maxNames     int
	maxEndpoints int
}

func newRegistryStore(cfg registryConfig) *RegistryStore {
	return &RegistryStore{
		names:        make(map[string]*serviceEntry),
		now:          time.Now,
		minTTL:       cfg.minTTL,
		maxTTL:       cfg.maxTTL,
		maxNames:     cfg.maxNames,
		maxEndpoints: cfg.maxEndpoints,
	}
}

// SetBounds refreshes the numeric bounds from a (re-parsed) config. Called on
// Corefile reload when the new plugin instance adopts the existing store.
func (s *RegistryStore) SetBounds(cfg registryConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.minTTL = cfg.minTTL
	s.maxTTL = cfg.maxTTL
	s.maxNames = cfg.maxNames
	s.maxEndpoints = cfg.maxEndpoints
}

// Register upserts the given endpoint URLs under name, refreshing the lease
// of any endpoint already present (this is the heartbeat path). The name is
// canonicalized; every URL (canonical and alternate) is validated before
// anything is applied, so a rejected register never partially mutates the
// store. Refreshing existing endpoints never counts against the capacity
// bounds. Alts are replaced wholesale per endpoint on every register — a
// heartbeat without alts clears them, mirroring meta semantics.
func (s *RegistryStore) Register(name string, urls []string, ttl time.Duration, meta map[string]string, alts map[string]map[string]string) error {
	cname, err := canonicalizeName(name)
	if err != nil {
		return fmt.Errorf("%w: %v", errNameInvalid, err)
	}
	if len(urls) == 0 {
		return fmt.Errorf("%w: no endpoints", errEndpointInvalid)
	}

	type parsed struct{ url, host, port string }
	eps := make([]parsed, 0, len(urls))
	for _, u := range urls {
		host, port, err := parseEndpointURL(u)
		if err != nil {
			return fmt.Errorf("%w: %v", errEndpointInvalid, err)
		}
		eps = append(eps, parsed{url: u, host: host, port: port})
	}
	if err := validateAlts(urls, alts); err != nil {
		return fmt.Errorf("%w: %v", errEndpointInvalid, err)
	}

	if ttl < s.minTTL {
		ttl = s.minTTL
	}
	if ttl > s.maxTTL {
		ttl = s.maxTTL
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	entry, ok := s.names[cname]
	if !ok {
		if len(s.names) >= s.maxNames {
			// Expired-but-unswept entries may be holding name capacity;
			// reclaim before rejecting (rare: only at the capacity edge).
			s.sweepLocked(now)
			if len(s.names) >= s.maxNames {
				return errCapacity
			}
		}
		entry = &serviceEntry{eps: make(map[string]*endpoint)}
	} else {
		// Expired endpoints must not count against maxEndpoints: a dead
		// replica's slot is free as soon as its lease lapses, not only
		// after the next sweep.
		for url, ep := range entry.eps {
			if !ep.expires.After(now) {
				delete(entry.eps, url)
			}
		}
	}

	added := 0
	for _, p := range eps {
		if _, exists := entry.eps[p.url]; !exists {
			added++
		}
	}
	if len(entry.eps)+added > s.maxEndpoints {
		return fmt.Errorf("%w: %d existing + %d new > %d", errTooManyEndpoints, len(entry.eps), added, s.maxEndpoints)
	}

	expires := now.Add(ttl)
	for _, p := range eps {
		entry.eps[p.url] = &endpoint{
			url:     p.url,
			host:    p.host,
			port:    p.port,
			meta:    copyMeta(meta),
			alts:    copyAlts(alts[p.url]),
			expires: expires,
			lease:   ttl,
		}
	}
	if !ok {
		s.names[cname] = entry
	}
	return nil
}

// Unregister removes the listed endpoint URLs from name; an empty list
// removes the whole name. Unknown names and URLs are ignored: unregister is
// best-effort by design (the lease would expire anyway).
func (s *RegistryStore) Unregister(name string, urls []string) {
	cname, err := canonicalizeName(name)
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.names[cname]
	if !ok {
		return
	}
	if len(urls) == 0 {
		delete(s.names, cname)
		return
	}
	for _, u := range urls {
		delete(entry.eps, u)
	}
	if len(entry.eps) == 0 {
		delete(s.names, cname)
	}
}

// Discover returns copies of the live endpoints for name, sorted by URL for
// deterministic output, together with the smallest remaining lease (which
// bounds the DNS record TTL). Expired endpoints are skipped even if the
// sweeper has not reclaimed them yet; a name whose endpoints have all expired
// is reported as not found.
func (s *RegistryStore) Discover(name string) (eps []endpoint, minRemaining time.Duration, found bool) {
	cname, err := canonicalizeName(name)
	if err != nil {
		return nil, 0, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.names[cname]
	if !ok {
		return nil, 0, false
	}
	now := s.now()
	for _, ep := range entry.eps {
		remaining := ep.expires.Sub(now)
		if remaining <= 0 {
			continue
		}
		cp := *ep
		cp.meta = copyMeta(ep.meta)
		cp.alts = copyAlts(ep.alts)
		eps = append(eps, cp)
		if minRemaining == 0 || remaining < minRemaining {
			minRemaining = remaining
		}
	}
	if len(eps) == 0 {
		return nil, 0, false
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].url < eps[j].url })
	return eps, minRemaining, true
}

// Sweep removes all expired endpoints and empty names. It returns the number
// of endpoints reclaimed plus the surviving name and endpoint counts, so the
// sweeper can refresh its gauges without a second full scan.
func (s *RegistryStore) Sweep() (reclaimed, names, endpoints int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	reclaimed = s.sweepLocked(s.now())
	for _, entry := range s.names {
		endpoints += len(entry.eps)
	}
	return reclaimed, len(s.names), endpoints
}

// sweepLocked removes expired endpoints and empty names. Callers hold the
// write lock.
func (s *RegistryStore) sweepLocked(now time.Time) (reclaimed int) {
	for name, entry := range s.names {
		for url, ep := range entry.eps {
			if !ep.expires.After(now) {
				delete(entry.eps, url)
				reclaimed++
			}
		}
		if len(entry.eps) == 0 {
			delete(s.names, name)
		}
	}
	return reclaimed
}

// adoptFrom copies every registration from old into s (deep copy; the donor
// is left untouched). Used when a reload moves the registry listen address:
// the new runner's store inherits the live registrations so DNS answers
// survive the move. Returns the number of names copied.
func (s *RegistryStore) adoptFrom(old *RegistryStore) int {
	old.mu.RLock()
	defer old.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, entry := range old.names {
		ne := &serviceEntry{eps: make(map[string]*endpoint, len(entry.eps))}
		for url, ep := range entry.eps {
			cp := *ep
			cp.meta = copyMeta(ep.meta)
			cp.alts = copyAlts(ep.alts)
			ne.eps[url] = &cp
		}
		s.names[name] = ne
	}
	return len(old.names)
}

// Stats returns the number of stored names and endpoints (including any
// expired entries the sweeper has not reclaimed yet).
func (s *RegistryStore) Stats() (names, endpoints int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.names {
		endpoints += len(entry.eps)
	}
	return len(s.names), endpoints
}

func copyMeta(meta map[string]string) map[string]string {
	if len(meta) == 0 {
		return nil
	}
	cp := make(map[string]string, len(meta))
	for k, v := range meta {
		cp[k] = v
	}
	return cp
}

// copyAlts is copyMeta's twin for the per-endpoint alternate-transport map.
func copyAlts(alts map[string]string) map[string]string {
	if len(alts) == 0 {
		return nil
	}
	cp := make(map[string]string, len(alts))
	for k, v := range alts {
		cp[k] = v
	}
	return cp
}
