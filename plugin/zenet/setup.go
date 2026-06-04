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

	c.OnStartup(z.OnStartup)
	c.OnShutdown(z.OnShutdown)

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
	}

	if !c.Next() {
		return nil, c.ArgErr()
	}
	z.Zones = plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)

	for c.NextBlock() {
		switch strings.ToLower(c.Val()) {
		case "address":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			z.addr = c.Val()
			if c.NextArg() {
				return nil, c.ArgErr()
			}
		case "timeout":
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
		case "fallthrough":
			z.Fall.SetZonesFromArgs(c.RemainingArgs())
		default:
			return nil, c.Errf("unknown property '%s'", c.Val())
		}
	}

	z.sem = make(chan struct{}, z.maxConcurrent)
	return z, nil
}
