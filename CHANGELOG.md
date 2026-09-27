# Changelog

## 1.1.0

### Fixed

- A client that connected and then stopped sending (or stopped reading the
  response) could block `poll()` forever, over plain HTTP and during or after
  the TLS handshake. Socket timeouts are now treated as errors instead of
  being retried indefinitely.
- After a handler wrote its own `Connection: close` response, the server
  still waited for another request on the same connection. It now closes as
  soon as the handler returns unless the response advertised keep-alive.
- The `Connection` request header is parsed as a token list
  (`Upgrade, Keep-Alive`); `close` always wins.
- The wait for the next request on a keep-alive connection now honours
  `QUARKX_KEEPALIVE_MS`, as documented.
- Client connections whose socket cannot be made blocking or given a timeout
  are closed instead of being served unprotected.
- Build fixes: request-line parser const-correctness (strict C++ standard
  libraries) and missing includes in the `DualHttpHttps` example.

### Added

- `QUARKX_REQUEST_TIMEOUT_MS` (default `10000`): once a request has started,
  its line, headers and body must arrive within this time. Requests whose
  body cannot be read or drained in time are dropped without calling the
  handler.
- Host-side unit tests (`pio test -e native`).

### Changed

- `QUARKX_HEADER_MAX_COUNT` default raised from `16` to `24` (about 2 KB more
  stack per request while headers are parsed).

### Documentation

- README now describes the single-connection `poll()` model, what
  `QUARKX_MAX_CLIENTS` means, all timeouts, the keep-alive rules and the TLS
  heap footprint, and corrects several outdated statements.
