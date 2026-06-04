# zenet

## Name

*zenet* - resolves A, AAAA and TXT queries via a backend service over a nanomsg (mangos) REQ/REP socket.

## Description

The *zenet* plugin forwards supported queries to an external resolver service as JSON over a
[mangos](https://github.com/nanomsg/mangos) REQ socket and synthesizes DNS answers from the reply.
Unsupported query types and names outside the configured zones are passed to the next plugin in the
chain.

Each in-flight DNS query uses its own mangos context (`Socket.OpenContext`), so concurrent queries
are multiplexed safely over a single socket. The number of simultaneous backend requests is bounded
by `max_concurrent`; excess queries fail fast with SERVFAIL rather than queueing.

The socket is dialed asynchronously at server startup, so CoreDNS starts (and keeps serving other
zones) even when the backend is down; mangos reconnects in the background.

## Syntax

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

## Wire protocol

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

## Metrics

If monitoring is enabled (via the *prometheus* plugin) then the following metrics are exported:

* `coredns_zenet_requests_total{server, qtype}` - count of queries answered from the backend.
* `coredns_zenet_errors_total{server, type}` - count of failed queries, by error type
  (`unsupported`, `canceled`, `context`, `send`, `timeout`, `recv`, `decode`, `bad_rcode`, `bad_ip`).
* `coredns_zenet_dropped_total{server}` - count of queries rejected because `max_concurrent` was exceeded.
* `coredns_zenet_nxdomain_total{server}` - count of queries the backend answered with NXDOMAIN.
* `coredns_zenet_nodata_total{server}` - count of queries for which the backend returned no records.
* `coredns_zenet_request_duration_seconds{server}` - histogram of backend round-trip time.

## Ready

This plugin reports readiness to the *ready* plugin once the backend socket has been created.

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

## Bugs

Negative answers (NXDOMAIN and no-data) carry no SOA record in the authority section, because the
backend has no zone/SOA concept; downstream resolvers therefore cannot negatively cache them
(RFC 2308).
