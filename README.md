# QuarkX Arduino Library

QuarkX is a minimal HTTP/HTTPS server tailored for ESP32-class boards using the Arduino framework. It focuses on small footprint, deterministic memory usage, and easy integration with the existing Arduino event loop. The library exposes the same routing API for both HTTP and TLS connections, so you decide at runtime whether a `quarkx::Server` instance should listen in plain text or over SSL.

## Features

- **Dual-stack**: spawn HTTP and HTTPS servers side by side, sharing the same handlers.
- **Keep-Alive aware**: configurable per-connection request limits and idle timers.
- **Bounded I/O**: silent, slow or non-reading clients are dropped after configurable timeouts, so `poll()` always returns.
- **Static routing**: register exact paths or prefix handlers without dynamic allocation.
- **Deterministic buffers**: all parsing uses fixed-size statically configurable buffers; no heap churn in the hot path.
- **Flexible TLS credentials**: accept PEM or DER certificates/keys from flash, LittleFS, or embedded resources.
- **Lightweight logging**: compile-time log levels and minimal serial output.

## Getting Started

```cpp
#include <LittleFS.h>
#include <QuarkX.h>

quarkx::Server httpServer(80, false);   // HTTP
quarkx::Server httpsServer(443, true);  // HTTPS

void setup() {
  Serial.begin(115200);
  LittleFS.begin(true);  // auto-format on first boot

  quarkx::TlsCreds creds{
      cert_buffer, cert_size, /*cert_is_pem=*/false,
      key_buffer, key_size,   /*key_is_pem=*/false};
  httpsServer.setTlsCredentials(creds);

  auto registerRoutes = [](quarkx::Server& srv) {
    srv.on("/echo", [](Stream& out, const String& method, const String& path) {
      uint8_t buf[QUARKX_MAX_BODY + 1];
      size_t bytes = quarkx::read_body(buf, QUARKX_MAX_BODY);
      buf[bytes] = '\0';
      quarkx::send_basic_response(out, 200, F("OK"),
                                  bytes ? String((const char*)buf) : F("No body"));
    });
  };

  registerRoutes(httpServer);
  registerRoutes(httpsServer);

  httpServer.begin();
  httpsServer.begin();
}

void loop() {
  httpServer.poll();
  httpsServer.poll();
  delay(1);
}
```

For a complete example, see [`examples/PostJson`](examples/PostJson/). The example demonstrates reading JSON payloads and sourcing TLS credentials from LittleFS (`/cert.der`, `/key.der`).

## Configuration

Every build-time option can be overridden with `-D` flags in `platformio.ini` or before including `QuarkX.h`. The table below lists the default values:

| Macro | Default | Description |
|-------|---------|-------------|
| `QUARKX_ENABLE_TLS` | `1` | Compile TLS support. Set to `0` if you want to exclude mbedTLS entirely. |
| `QUARKX_KEEP_ALIVE` | `1` | Enable keep-alive loop per connection. |
| `QUARKX_MAX_REQ_PER_CONN` | `4` | Maximum requests per connection when keep-alive is enabled. |
| `QUARKX_KEEPALIVE_MS` | `5000` | Idle time (ms) the server waits for the next request on a keep-alive connection. |
| `QUARKX_RECV_TIMEOUT_MS` | `5000` | Socket receive/send timeout (ms) for each I/O call, including the TLS handshake and the wait for the first request. |
| `QUARKX_REQUEST_TIMEOUT_MS` | `10000` | Maximum time (ms) to receive a request's line, headers and body once its first byte has arrived. |
| `QUARKX_MAX_CLIENTS` | `4` | Listen backlog: connections queued while one is being served (see [Concurrency](#concurrency)). |
| `QUARKX_MAX_BODY` | `512` | Maximum request body size buffered for handlers (`read_body`). |
| `QUARKX_HDR_LINE_MAX` | `512` | Maximum header line length accepted by the parser. |
| `QUARKX_HDR_NAME_MAX` | `48` | Maximum header field name length stored in the table. |
| `QUARKX_HDR_VALUE_MAX` | `210` | Maximum header field value length stored in the table. |
| `QUARKX_HEADER_MAX_COUNT` | `24` | Maximum number of headers parsed per request. |
| `QUARKX_ROUTE_MAX` | `8` | Number of exact-match route slots. |
| `QUARKX_PREFIX_MAX` | `4` | Number of prefix-route slots. |
| `QUARKX_LOG_LEVEL` | `0` | Log level (`0`=silent, `1`=error, `2`=info, `3`=debug). |

Macros can be added before `#include <QuarkX.h>` or in your build system:

```ini
build_flags =
  -DQUARKX_LOG_LEVEL=3
  -DQUARKX_MAX_BODY=1024
```

## TLS Credentials

- **PEM**: pass `cert_is_pem = true` (default) and `key_is_pem = true`. Ensure the buffers are null-terminated.
- **DER**: pass raw DER bytes and set `cert_is_pem = false`, `key_is_pem = false`. Useful when storing credentials in LittleFS.

You may load credentials from LittleFS, SPIFFS, PROGMEM, or embed them in code. When TLS is enabled, provide credentials before calling `Server::begin()`; without them `begin()` fails. The `DualHttpHttps` example shows how to fall back to the mbedTLS test certificate for development.

## Keep-Alive Behavior

When `QUARKX_KEEP_ALIVE` is enabled, a connection is kept open for another request only when both hold:

- the request's `Connection` header contains the `keep-alive` token (and no `close` token), and
- the response was sent with `send_basic_response()`, which then answers `Connection: keep-alive`.

Up to `QUARKX_MAX_REQ_PER_CONN` requests are served per connection, and the server waits at most `QUARKX_KEEPALIVE_MS` for the next one. A request without a `Connection` header is answered with `Connection: close`.

Handlers that write their own status line and headers should send `Connection: close` and a `Content-Length`; the server closes the connection as soon as such a handler returns.

## Timeouts

Every client socket is blocking with `QUARKX_RECV_TIMEOUT_MS` as receive and send timeout, so no single read or write waits longer than that. On top of it, once a request has started, its request line, headers and body must arrive within `QUARKX_REQUEST_TIMEOUT_MS`; clients that trickle data are dropped. Requests whose body cannot be read in time are dropped without calling the handler.

## Concurrency

`poll()` accepts at most one connection and serves it to completion before returning, in the calling task. While a client is being served (including a TLS handshake and a large response), other work in the same loop — other servers, DNS, application code — waits. Further connections queue in the listen backlog (`QUARKX_MAX_CLIENTS`) and are served by later `poll()` calls; `QUARKX_MAX_CLIENTS` is not a number of simultaneously served clients.

The timeouts above bound how long a single `poll()` call can take. If other work must keep running while clients are served, call `poll()` from a dedicated task.

## TLS Memory Footprint

Each TLS connection allocates mbedTLS record buffers for as long as it is served. With the default mbedTLS settings of Arduino-ESP32 this is roughly 40–50 KB of heap per connection, on top of the certificate and key parsed once at `begin()`. Only one connection is served at a time, so this is the peak cost of HTTPS.

The main knobs are ESP-IDF `sdkconfig` options: `CONFIG_MBEDTLS_ASYMMETRIC_CONTENT_LEN` with a smaller `CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN`, or `CONFIG_MBEDTLS_DYNAMIC_BUFFER`. Note that the standard Arduino-ESP32 core ships precompiled with a fixed `sdkconfig`; changing these requires building with ESP-IDF (for example Arduino as an ESP-IDF component or a hybrid PlatformIO setup).

## Logging

Logging uses the `QX_LOG*` macros underneath and is routed to `Serial`. Set `QUARKX_LOG_LEVEL` to control verbosity. Level `3` includes handshake diagnostics and keep-alive loop messages for debugging.

## Examples

- **`examples/MinimalHttp`** – smallest plain HTTP server.
- **`examples/DualHttpHttps`** – HTTP and HTTPS side by side, with TLS credentials from LittleFS or the mbedTLS test certificate.
- **`examples/PostJson`** – demonstrates reading JSON payloads, echoing responses, and using custom TLS credentials stored in LittleFS.
- More examples can be added by placing sketches under `examples/<ExampleName>`; PlatformIO/Arduino IDE will detect them automatically thanks to `library.json`.

## License

QuarkX is released under the MIT License. See [`LICENSE`](LICENSE) for details.
