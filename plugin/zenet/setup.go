package zenet

import (
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const pluginName = "zenet"

const (
	defaultAddr          = "tcp://localhost:40899"
	defaultTimeout       = 2 * time.Second
	defaultTTL           = 3600
	defaultMaxConcurrent = 1000
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	z, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	if z.mode == modeRegistry {
		addr := z.regCfg.listen
		r := runners.claim(addr, func() *runner { return newRunner(z.regCfg) })
		z.store = r.store
		z.runner = r

		// Everything that mutates shared state runs in OnStartup, i.e. only
		// when this config generation actually commits: a reload that fails
		// validation must leave neither its bounds nor its listener changes
		// behind. reconcile stops listeners the new config no longer
		// references (migrating their registrations on an address change,
		// see shared.go); start is idempotent and reports bind errors, so a
		// dead listener fails startup loudly instead of silently.
		c.OnStartup(func() error {
			runners.reconcile()
			z.store.SetBounds(z.regCfg)
			return z.runner.start()
		})
		// OnRestart runs on the old instance before the new config is even
		// parsed: it marks the generation boundary for claim tracking.
		c.OnRestart(func() error { runners.beginGeneration(); return nil })
		// A failed reload rolls back to this instance; its OnStartup may
		// already have applied the discarded config's bounds or stopped this
		// runner as the stale side of an address change. Restore both.
		c.OnRestartFailed(func() error {
			z.runner = runners.revive(addr, z.regCfg, z.store)
			z.store.SetBounds(z.regCfg)
			return z.runner.start()
		})
		c.OnFinalShutdown(func() error { return z.runner.stop() })
	} else {
		c.OnStartup(z.OnStartup)
		c.OnShutdown(z.OnShutdown)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		z.Next = next
		return z
	})
	return nil
}

func parse(c *caddy.Controller) (*Zenet, error) {
	z := &Zenet{
		addr:          defaultAddr,
		timeout:       defaultTimeout,
		ttl:           defaultTTL,
		maxConcurrent: defaultMaxConcurrent,
		regCfg:        defaultRegistryConfig(),
	}

	if !c.Next() {
		return nil, c.ArgErr()
	}
	z.Zones = plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)

	registrySeen := false
	var resolverOpts, registryOpts []string

	for c.NextBlock() {
		switch strings.ToLower(c.Val()) {
		case "address":
			resolverOpts = append(resolverOpts, "address")
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			z.addr = c.Val()
			if c.NextArg() {
				return nil, c.ArgErr()
			}
		case "timeout":
			resolverOpts = append(resolverOpts, "timeout")
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			d, err := time.ParseDuration(c.Val())
			if err != nil {
				return nil, c.Errf("invalid timeout: %v", err)
			}
			if d <= 0 {
				return nil, c.Errf("timeout must be greater than zero: %s", c.Val())
			}
			z.timeout = d
			if c.NextArg() {
				return nil, c.ArgErr()
			}
		case "max_concurrent":
			resolverOpts = append(resolverOpts, "max_concurrent")
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			n, err := strconv.Atoi(c.Val())
			if err != nil {
				return nil, c.Errf("invalid max_concurrent: %v", err)
			}
			if n <= 0 {
				return nil, c.Errf("max_concurrent must be greater than zero: %d", n)
			}
			z.maxConcurrent = int64(n)
			if c.NextArg() {
				return nil, c.ArgErr()
			}
		case "ttl":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			n, err := strconv.Atoi(c.Val())
			if err != nil {
				return nil, c.Errf("invalid ttl: %v", err)
			}
			if n < 0 || n > 3600 {
				return nil, c.Errf("ttl must be in range [0, 3600]: %d", n)
			}
			z.ttl = uint32(n)
			if c.NextArg() {
				return nil, c.ArgErr()
			}
		case "registry":
			registrySeen = true
			if c.NextArg() {
				addr := c.Val()
				if !strings.Contains(addr, "://") {
					return nil, c.Errf("invalid registry listen address: %q", addr)
				}
				z.regCfg.listen = addr
				if c.NextArg() {
					return nil, c.ArgErr()
				}
			}
		case "registry_min_ttl", "registry_max_ttl", "registry_sweep_interval":
			opt := strings.ToLower(c.Val())
			registryOpts = append(registryOpts, opt)
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			d, err := time.ParseDuration(c.Val())
			if err != nil {
				return nil, c.Errf("invalid %s: %v", opt, err)
			}
			if d <= 0 {
				return nil, c.Errf("%s must be greater than zero: %s", opt, c.Val())
			}
			switch opt {
			case "registry_min_ttl":
				z.regCfg.minTTL = d
			case "registry_max_ttl":
				z.regCfg.maxTTL = d
			case "registry_sweep_interval":
				z.regCfg.sweepInterval = d
			}
			if c.NextArg() {
				return nil, c.ArgErr()
			}
		case "registry_max_names", "registry_max_endpoints", "registry_max_payload", "registry_workers":
			opt := strings.ToLower(c.Val())
			registryOpts = append(registryOpts, opt)
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			n, err := strconv.Atoi(c.Val())
			if err != nil {
				return nil, c.Errf("invalid %s: %v", opt, err)
			}
			if n <= 0 {
				return nil, c.Errf("%s must be greater than zero: %d", opt, n)
			}
			switch opt {
			case "registry_max_names":
				z.regCfg.maxNames = n
			case "registry_max_endpoints":
				z.regCfg.maxEndpoints = n
			case "registry_max_payload":
				z.regCfg.maxPayload = n
			case "registry_workers":
				if n > maxWorkers {
					return nil, c.Errf("registry_workers must be in [1, %d]: %d", maxWorkers, n)
				}
				z.regCfg.workers = n
			}
			if c.NextArg() {
				return nil, c.ArgErr()
			}
		case "fallthrough":
			z.Fall.SetZonesFromArgs(c.RemainingArgs())
		default:
			return nil, c.Errf("unknown property '%s'", c.Val())
		}
	}

	if registrySeen {
		if len(resolverOpts) > 0 {
			return nil, c.Errf("registry mode and resolver options are mutually exclusive: %s", strings.Join(resolverOpts, ", "))
		}
		if z.regCfg.minTTL > z.regCfg.maxTTL {
			return nil, c.Errf("registry_min_ttl (%s) must not exceed registry_max_ttl (%s)", z.regCfg.minTTL, z.regCfg.maxTTL)
		}
		z.mode = modeRegistry
		return z, nil
	}
	if len(registryOpts) > 0 {
		return nil, c.Errf("%s require the registry directive", strings.Join(registryOpts, ", "))
	}

	z.sem = make(chan struct{}, z.maxConcurrent)
	return z, nil
}
