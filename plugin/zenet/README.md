# zenet

## Name

*zenet* - resolves A, AAAA and TXT queries via a backend service over a nanomsg (mangos) REQ/REP
socket (resolver mode), or hosts an in-memory service registry that services register with directly
(registry mode).

## Description

The *zenet* plugin has two mutually exclusive modes.

**Resolver mode** (the default) forwards supported queries to an external resolver service as JSON
over a [mangos](https://github.com/nanomsg/mangos) REQ socket and synthesizes DNS answers from the
reply. Unsupported query types and names outside the configured zones are passed to the next plugin
in the chain.

Each in-flight DNS query uses its own mangos context (`Socket.OpenContext`), so concurrent queries
are multiplexed safely over a single socket. The number of simultaneous backend requests is bounded
by `max_concurrent`; excess queries fail fast with SERVFAIL rather than queueing.

The socket is dialed asynchronously at server startup, so CoreDNS starts (and keeps serving other
zones) even when the backend is down; mangos reconnects in the background.

**Registry mode** (enabled with the `registry` directive) embeds the service registry in the plugin
itself: services register their endpoints over a mangos REP socket using the registry protocol
below, and DNS queries are answered directly from the in-memory store — no external backend. A
registration is a lease: it expires unless refreshed, so a crashed service disappears from DNS
within its TTL. Multiple endpoints (replicas) per name are first-class; each endpoint expires
independently.

The registry survives Corefile reloads: the new plugin instance adopts the existing listener and
its registrations, and the numeric bounds (`registry_max_*`, `registry_min_ttl`,
`registry_max_ttl`) are re-applied when the reload commits — a reload that fails validation leaves
the running configuration untouched. Changing the registry listen address on reload migrates the
registrations to a new listener on the new address and stops the old one; services must heartbeat
the new address from then on (a warning is logged). Removing the registry block from the config
stops its listener and drops its registrations. `registry_workers` and `registry_sweep_interval`
are structural and keep their running values until a process restart.

## Syntax

Resolver mode:

~~~ txt
zenet [ZONES...] {
    address TRANSPORT://HOST:PORT
    timeout DURATION
    max_concurrent N
    ttl SECONDS
    fallthrough [ZONES...]
}
~~~

* **ZONES** zones the plugin is authoritative for. Defaults to the zones of the enclosing server block.
* `address` backend socket address. Default: `tcp://localhost:40899`.
* `timeout` per-request send/receive deadline for the backend round trip. Default: `2s`.
* `max_concurrent` maximum number of in-flight backend requests. Queries beyond this limit are
  rejected with SERVFAIL. Default: `1000`.
* `ttl` TTL in seconds for synthesized records, in the range [0, 3600]. Default: `3600`.
* `fallthrough` if a backend request fails (down, timeout) or returns no records, pass the query to
  the next plugin instead of answering. If **ZONES** are given, fall through only for those zones.

Registry mode:

~~~ txt
zenet [ZONES...] {
    registry [TRANSPORT://HOST:PORT]
    registry_min_ttl DURATION
    registry_max_ttl DURATION
    registry_max_names N
    registry_max_endpoints N
    registry_max_payload BYTES
    registry_workers N
    registry_sweep_interval DURATION
    ttl SECONDS
    fallthrough [ZONES...]
}
~~~

* `registry` enables registry mode and optionally sets the registration listen address.
  Default: `tcp://0.0.0.0:40900`. Mutually exclusive with `address`, `timeout` and `max_concurrent`.
* `registry_min_ttl`, `registry_max_ttl` bounds the lease a client may request; out-of-range
  requests are clamped. Defaults: `1s` and `300s`. A short maximum keeps failure detection fast:
  registrations are heartbeats, not durable state.
* `registry_max_names` maximum number of registered service names. Default: `10000`.
* `registry_max_endpoints` maximum endpoints (replicas) per name. Default: `64`.
* `registry_max_payload` maximum registry message size in bytes. Default: `16384`.
* `registry_workers` REP handler contexts serving registry messages, in the range [1, 64].
  Default: number of CPUs, clamped to [4, 64].
* `registry_sweep_interval` how often expired endpoints are reclaimed. Default: `1s`. (Expiry is
  also enforced lazily on every read, so this only affects memory reclamation.)
* `ttl` in registry mode is the *ceiling* for record TTLs: the actual TTL is the smaller of the
  remaining lease (truncated to whole seconds — a lease in its final sub-second serves TTL 0) and
  this value, so downstream caches never outlive a lease. `ttl 0` serves every answer with TTL 0
  (no caching).
* `fallthrough` as in resolver mode, for NXDOMAIN and no-data answers.

## Wire protocol (resolver mode)

Request, sent as JSON over the REQ socket:

~~~ json
{"query": {"name": "host.example.net.", "type": "A"}}
~~~

`type` is one of `A`, `AAAA` or `TXT`. Reply:

~~~ json
{"query": ["10.1.2.3"], "rcode": "NOERROR"}
~~~

* `query` - for `A`/`AAAA`, each array element must be an IP address; addresses of the other
  family are skipped. For `TXT`, each element becomes one TXT record. An empty array yields a
  NOERROR/no-data answer (the name exists but has no records of this type), or fallthrough if
  configured.
* `rcode` - optional. `"NOERROR"` (or absent) means success; `"NXDOMAIN"` means the name does not
  exist and is answered with an authoritative NXDOMAIN (or fallthrough, if configured), ignoring
  `query`. Any other value is treated as a backend error (SERVFAIL).

## Registry protocol (registry mode)

JSON messages over a mangos REQ/REP socket, one operation per message. Exactly one of `register`,
`unregister` or `discover` must be present. `version` is optional and defaults to `1`. `token` is
parsed but ignored in v1 (reserved for shared-secret authentication). Names are canonicalized
server-side (lowercase, trailing dot). Endpoint URLs must be `tcp://` with an IP-literal host and a
numeric port in [1, 65535] (service names like `:http` are rejected — the port string surfaces
verbatim in TXT answers).

Register (also the heartbeat — an idempotent upsert that refreshes the lease of every listed
endpoint):

~~~ json
{"version": 1, "register": {"name": "svc.cloud.zeno", "endpoints": ["tcp://10.0.0.12:40901"], "ttl": 30, "meta": {"proto": "rep0"}}}
~~~

Reply: `{"ok": true}`. The requested `ttl` (seconds) is clamped to
[`registry_min_ttl`, `registry_max_ttl`]. `meta` is limited to 16 entries / 1024 bytes.

Unregister (an empty or absent endpoint list removes the whole name; best-effort — the lease would
expire anyway):

~~~ json
{"unregister": {"name": "svc.cloud.zeno", "endpoints": ["tcp://10.0.0.12:40901"]}}
~~~

Reply: `{"ok": true}`.

Discover:

~~~ json
{"discover": {"name": "svc.cloud.zeno"}}
~~~

Reply when found (`ttl` is the smallest remaining lease in seconds, truncated — `0` means less
than one second remains; `endpoints` are sorted by URL):

~~~ json
{"ok": true, "found": true, "endpoints": ["tcp://10.0.0.12:40901", "tcp://10.0.0.13:40901"], "meta": {"proto": "rep0"}, "ttl": 27}
~~~

Reply when not found (not an error): `{"ok": true, "found": false}` — the `endpoints` key may be
absent; treat it as empty.

Errors (protocol/validation failures only):

~~~ json
{"ok": false, "error": "too_large", "detail": "payload 20480 > 16384 bytes"}
~~~

`error` is one of `bad_request`, `unsupported_version`, `name_invalid`, `endpoint_invalid`,
`too_many_endpoints`, `too_large`, `capacity`, `unauthorized` (reserved). `detail` is human-readable
and may change; `error` is stable.

DNS answers in registry mode: `A`/`AAAA` return the distinct endpoint IPs of the matching family
(replicas sharing an IP are deduplicated); `TXT` returns one record per endpoint of the form
`endpoint=tcp://10.0.0.12:40901 port=40901 key=value ...`, exposing ports and metadata to DNS-only
tooling. An unregistered (or fully expired) name is an authoritative NXDOMAIN; a registered name
with no records of the queried family is an authoritative no-data.

## Metrics

If monitoring is enabled (via the *prometheus* plugin) then the following metrics are exported:

* `coredns_zenet_requests_total{server, qtype}` - count of queries answered from the backend.
* `coredns_zenet_errors_total{server, type}` - count of failed queries, by error type
  (`unsupported`, `canceled`, `context`, `send`, `timeout`, `recv`, `decode`, `bad_rcode`, `bad_ip`).
* `coredns_zenet_dropped_total{server}` - count of queries rejected because `max_concurrent` was exceeded.
* `coredns_zenet_nxdomain_total{server}` - count of queries answered with NXDOMAIN.
* `coredns_zenet_nodata_total{server}` - count of queries that returned no records.
* `coredns_zenet_request_duration_seconds{server}` - histogram of backend round-trip time.

Registry mode additionally exports (no `server` label — the registration listener is not a CoreDNS
server block):

* `coredns_zenet_registrations_total{op}` - count of accepted registry operations (`register`,
  `unregister`); heartbeats count as `register`.
* `coredns_zenet_registry_errors_total{error}` - count of rejected registry messages, by error code.
* `coredns_zenet_registry_names` - gauge of currently registered names.
* `coredns_zenet_registry_endpoints` - gauge of currently registered endpoints.
* `coredns_zenet_expirations_total` - count of endpoints whose lease expired.
* `coredns_zenet_discover_total{source}` - count of discovery lookups (`rpc` for protocol discover
  messages, `dns` for DNS queries served from the store).

## Ready

In resolver mode this plugin reports readiness once the backend socket has been created. In
registry mode it reports readiness once the registration listener is bound.

## Security

The registration listener is **unauthenticated in v1**: any host that can reach the socket can
register, overwrite or unregister any name (including names registered by other services). Deploy
accordingly:

* Restrict reachability to the trusted service subnet with firewall / security-group rules.
* Prefer binding a specific internal interface (e.g. `registry tcp://10.0.0.5:40900`) over the
  `0.0.0.0` default.
* The resource bounds (`registry_max_names`, `registry_max_endpoints`, `registry_max_payload`) are
  the denial-of-service mitigation: a hostile or misbehaving client gets `capacity` / `too_large`
  errors instead of exhausting memory.
* The protocol reserves a `token` field and an `unauthorized` error code for a future shared-secret
  scheme; mangos TLS transports are a heavier option if needed later.

## Examples

Resolve `example.net` via a local backend, forwarding everything else upstream:

~~~ corefile
example.net:5353 {
    zenet
    log
    errors
}

.:5353 {
    forward . 8.8.8.8
    log
    errors
}
~~~

Custom backend address with fallthrough to a zone file when the backend has no answer:

~~~ corefile
example.net {
    zenet {
        address tcp://resolver.internal:40899
        timeout 1s
        fallthrough
    }
    file db.example.net
}
~~~

Service registry for cloud microservices: services register against port 40900 and are resolvable
under `cloud.zeno`:

~~~ corefile
cloud.zeno {
    zenet {
        registry tcp://0.0.0.0:40900
        registry_max_ttl 60s
        ttl 30
    }
    log
    errors
}
~~~

## Bugs

Negative answers (NXDOMAIN and no-data) carry no SOA record in the authority section, because the
backend has no zone/SOA concept; downstream resolvers therefore cannot negatively cache them
(RFC 2308).

If a single reload both adds and removes more than one registry listen address, registrations are
not migrated between them (the mapping would be ambiguous); the removed listeners are stopped and
their registrations dropped, with a warning logged.
