package zenet

import (
	"testing"
	"time"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{`zenet`, false},
		{`zenet example.org`, false},
		{`zenet example.org example.net`, false},
		{`zenet {
			address tcp://backend:1234
			timeout 5s
			max_concurrent 50
			ttl 300
			fallthrough
		}`, false},
		{`zenet {
			fallthrough example.org
		}`, false},
		{`zenet {
			timeout abc
		}`, true},
		{`zenet {
			timeout -1s
		}`, true},
		{`zenet {
			max_concurrent 0
		}`, true},
		{`zenet {
			max_concurrent many
		}`, true},
		{`zenet {
			ttl 99999
		}`, true},
		{`zenet {
			ttl -1
		}`, true},
		{`zenet {
			address
		}`, true},
		{`zenet {
			address tcp://a:1 tcp://b:2
		}`, true},
		{`zenet {
			bogus
		}`, true},
	}

	for i, tc := range tests {
		c := caddy.NewTestController("dns", tc.input)
		err := setup(c)
		if tc.wantErr && err == nil {
			t.Errorf("test %d (%q): expected error, got none", i, tc.input)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("test %d (%q): unexpected error: %v", i, tc.input, err)
		}
	}
}

func TestParseDefaults(t *testing.T) {
	c := caddy.NewTestController("dns", `zenet`)
	z, err := parse(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if z.addr != defaultAddr {
		t.Errorf("expected addr %q, got %q", defaultAddr, z.addr)
	}
	if z.timeout != defaultTimeout {
		t.Errorf("expected timeout %s, got %s", defaultTimeout, z.timeout)
	}
	if z.ttl != defaultTTL {
		t.Errorf("expected ttl %d, got %d", defaultTTL, z.ttl)
	}
	if z.maxConcurrent != defaultMaxConcurrent {
		t.Errorf("expected max_concurrent %d, got %d", defaultMaxConcurrent, z.maxConcurrent)
	}
	if cap(z.sem) != defaultMaxConcurrent {
		t.Errorf("expected semaphore capacity %d, got %d", defaultMaxConcurrent, cap(z.sem))
	}
}

func TestParseOptions(t *testing.T) {
	c := caddy.NewTestController("dns", `zenet example.org {
		address tcp://backend:1234
		timeout 5s
		max_concurrent 50
		ttl 300
	}`)
	z, err := parse(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(z.Zones) != 1 || z.Zones[0] != "example.org." {
		t.Errorf("expected zones [example.org.], got %v", z.Zones)
	}
	if z.addr != "tcp://backend:1234" {
		t.Errorf("expected addr tcp://backend:1234, got %q", z.addr)
	}
	if z.timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %s", z.timeout)
	}
	if z.maxConcurrent != 50 {
		t.Errorf("expected max_concurrent 50, got %d", z.maxConcurrent)
	}
	if z.ttl != 300 {
		t.Errorf("expected ttl 300, got %d", z.ttl)
	}
}

func TestParseRegistry(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{`zenet cloud.zeno {
			registry
		}`, false},
		{`zenet cloud.zeno {
			registry tcp://10.0.0.5:40900
			registry_min_ttl 2s
			registry_max_ttl 60s
			registry_max_names 100
			registry_max_endpoints 8
			registry_max_payload 4096
			registry_workers 4
			registry_sweep_interval 500ms
			ttl 30
			fallthrough
		}`, false},
		// registry and resolver options are mutually exclusive.
		{`zenet {
			registry
			address tcp://backend:1234
		}`, true},
		{`zenet {
			address tcp://backend:1234
			registry
		}`, true},
		{`zenet {
			registry
			timeout 5s
		}`, true},
		{`zenet {
			registry
			max_concurrent 10
		}`, true},
		// registry_* options require the registry directive.
		{`zenet {
			registry_max_ttl 60s
		}`, true},
		// Validation of values.
		{`zenet {
			registry no-scheme-here
		}`, true},
		{`zenet {
			registry tcp://a:1 tcp://b:2
		}`, true},
		{`zenet {
			registry
			registry_min_ttl 60s
			registry_max_ttl 5s
		}`, true},
		{`zenet {
			registry
			registry_max_names 0
		}`, true},
		{`zenet {
			registry
			registry_workers -1
		}`, true},
		{`zenet {
			registry
			registry_sweep_interval 0s
		}`, true},
		{`zenet {
			registry
			registry_max_ttl notaduration
		}`, true},
	}

	for i, tc := range tests {
		c := caddy.NewTestController("dns", tc.input)
		_, err := parse(c)
		if tc.wantErr && err == nil {
			t.Errorf("test %d (%q): expected error, got none", i, tc.input)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("test %d (%q): unexpected error: %v", i, tc.input, err)
		}
	}
}

func TestParseRegistryConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `zenet cloud.zeno {
		registry tcp://10.0.0.5:40900
		registry_min_ttl 2s
		registry_max_ttl 60s
		registry_max_names 100
		registry_max_endpoints 8
		registry_max_payload 4096
		registry_workers 4
		registry_sweep_interval 500ms
		ttl 30
	}`)
	z, err := parse(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if z.mode != modeRegistry {
		t.Fatal("expected registry mode")
	}
	if z.sem != nil {
		t.Error("semaphore must not be built in registry mode")
	}
	cfg := z.regCfg
	if cfg.listen != "tcp://10.0.0.5:40900" {
		t.Errorf("listen: got %q", cfg.listen)
	}
	if cfg.minTTL != 2*time.Second || cfg.maxTTL != 60*time.Second {
		t.Errorf("ttl bounds: got %s/%s", cfg.minTTL, cfg.maxTTL)
	}
	if cfg.maxNames != 100 || cfg.maxEndpoints != 8 || cfg.maxPayload != 4096 || cfg.workers != 4 {
		t.Errorf("bounds: got %+v", cfg)
	}
	if cfg.sweepInterval != 500*time.Millisecond {
		t.Errorf("sweep_interval: got %s", cfg.sweepInterval)
	}
	if z.ttl != 30 {
		t.Errorf("dns ttl: got %d", z.ttl)
	}
}

func TestParseRegistryDefaults(t *testing.T) {
	c := caddy.NewTestController("dns", `zenet cloud.zeno {
		registry
	}`)
	z, err := parse(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if z.mode != modeRegistry {
		t.Fatal("expected registry mode")
	}
	want := defaultRegistryConfig()
	if z.regCfg.listen != want.listen {
		t.Errorf("expected default listen %q, got %q", want.listen, z.regCfg.listen)
	}
	if z.regCfg.minTTL != want.minTTL || z.regCfg.maxTTL != want.maxTTL {
		t.Errorf("expected default ttl bounds %s/%s, got %s/%s", want.minTTL, want.maxTTL, z.regCfg.minTTL, z.regCfg.maxTTL)
	}
	if z.regCfg.maxNames != want.maxNames || z.regCfg.maxEndpoints != want.maxEndpoints || z.regCfg.maxPayload != want.maxPayload {
		t.Errorf("expected default bounds, got %+v", z.regCfg)
	}
}
