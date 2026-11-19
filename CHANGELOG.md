# Changelog

Notable changes to xlate, newest first. Dates are release dates. The same notes are on the [Releases](https://github.com/dboudreau00/xlate/releases) page.

## [Unreleased]

### Added

- Field maps can address a body that is itself a JSON array. A path that starts with `[]` (`[].sku`) maps the elements, in a POST, PUT or PATCH body and in any answer. It applies only where a row addresses the top level: without one, a bare request body is still `400 bad_json` and a bare answer is still relayed raw.

### Changed

- Go 1.26.11 is pinned, in `go.mod` and in the Dockerfile's build image. It clears GO-2026-6859 in net/http, which govulncheck reported on 1.26.10.

## [0.5.0] - 2026-11-02

### Added

- GET, PUT, PATCH and DELETE on the data plane. Each side lists the methods it may send (`inbound_methods`, POST only by default) and the same method is replayed to the other side. GET and DELETE carry the translated query string and refuse a body. A method that is not on the list gets a 405 before the tripwire and authentication.
- Array addressing in field maps: `lines[].sku` to `items[].product_code`, both ways and on the return leg, up to 1,000 elements per addressed array. A malformed array is refused (422 `array_invalid` on a request, 502 `upstream_invalid` on a response) instead of being passed through.
- Per-account strict transform mode (`strict_transforms`): a failed transform refuses the message instead of passing the value through.
- Per-account rate limit (`rate_limit_per_min`): a token bucket per side, applied after authentication. Over the limit is a 429 `rate_limited`.

### Changed

- Redesigned console: the integration topology is drawn both ways with per-direction counts, plus node vitals and a rollup.
- Audit fsyncs are group-committed. In the README's benchmark, 16 concurrent refused requests went from about 750 to about 4,000 req/s.
- Go 1.26.10 is pinned. CI actions, tool installs and Docker bases are pinned by SHA, version or digest.

### Fixed

- Tripwire freeze mode wrote back the account as the request had loaded it. If an admin had rotated a token in the meantime, that restored the retired token and reverted other edits. Freeze now sets only the enabled flag. Found in an independent review.
- A query string appended to a failed forward no longer reaches the activity log or the audit trail.

## [0.4.1] - 2026-10-19

### Changed

- A pinned admin token (`-admin-token` or `XLATE_ADMIN_TOKEN`) must be 16 to 512 printable ASCII characters, or startup fails. Generated tokens are unaffected.
- Requests have a 30 second read timeout. A client that declares a body and stalls no longer holds a connection.
- The alert webhook no longer follows redirects. A 3xx counts as a failed delivery, so `X-Xlate-Signature` and the alert body never reach a `Location` target.
- Go 1.26.9 is pinned. It clears nine standard-library advisories that govulncheck reported on 1.26.7 (net/http, net/textproto, crypto/tls).

### Fixed

- Errors from failed forwards are redacted to `scheme://host` in the activity log and the audit trail, so a credential in a target URL's query string is not recorded.
- The request path is neutralised in admin-denied and panic log lines, so `%0a` cannot forge a log line.
- The admin console sends `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- The README documents that the forwarding client honours `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`.

## [0.4.0] - 2026-08-27

First public release.
