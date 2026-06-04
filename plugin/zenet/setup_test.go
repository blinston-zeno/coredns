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
