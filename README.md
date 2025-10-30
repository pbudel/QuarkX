# QuarkX Arduino Library

QuarkX is a minimal HTTP/HTTPS server tailored for ESP32-class boards using the Arduino framework. It focuses on small footprint, deterministic memory usage, and easy integration with the existing Arduino event loop. The library exposes the same routing API for both HTTP and TLS connections, so you decide at runtime whether a `quarkx::Server` instance should listen in plain text or over SSL.

## Features

- **Dual-stack**: spawn HTTP and HTTPS servers side by side, sharing the same handlers.
- **Keep-Alive aware**: configurable per-connection request limits and idle timers.
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

  quarkx::Server::TlsCreds creds{
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

For a complete example, see [`examples/PostJson`](../../examples/PostJson/). The example demonstrates reading JSON payloads and sourcing TLS credentials from LittleFS (`/cert.der`, `/key.der`).

## Configuration

Every build-time option can be overridden with `-D` flags in `platformio.ini` or before including `QuarkX.h`. The table below lists the default values:

| Macro | Default | Description |
|-------|---------|-------------|
| `QUARKX_ENABLE_TLS` | `1` | Compile TLS support. Set to `0` if you want to exclude mbedTLS entirely. |
| `QUARKX_KEEP_ALIVE` | `1` | Enable keep-alive loop per connection. |
| `QUARKX_MAX_REQ_PER_CONN` | `4` | Maximum requests per connection when keep-alive is enabled. |
| `QUARKX_KEEPALIVE_MS` | `5000` | Idle timeout (ms) before a keep-alive connection is closed. |
| `QUARKX_RECV_TIMEOUT_MS` | `5000` | Receive timeout used during TLS handshakes and body reads. |
| `QUARKX_MAX_BODY` | `512` | Maximum request body size buffered for handlers (`read_body`). |
| `QUARKX_HDR_LINE_MAX` | `512` | Maximum header line length accepted by the parser. |
| `QUARKX_HDR_NAME_MAX` | `48` | Maximum header field name length stored in the table. |
| `QUARKX_HDR_VALUE_MAX` | `160` | Maximum header field value length stored in the table. |
| `QUARKX_HEADER_MAX_COUNT` | `16` | Maximum number of headers parsed per request. |
| `QUARKX_ROUTE_MAX` | `8` | Number of exact-match route slots. |
| `QUARKX_PREFIX_MAX` | `4` | Number of prefix-route slots. |
| `QUARKX_LOG_LEVEL` | `1` | Log level (`0`=silent, `1`=error, `2`=info, `3`=debug). |

Macros can be added before `#include <QuarkX.h>` or in your build system:

```ini
build_flags =
  -DQUARKX_LOG_LEVEL=3
  -DQUARKX_MAX_BODY=1024
```

## TLS Credentials

- **PEM**: pass `cert_is_pem = true` (default) and `key_is_pem = true`. Ensure the buffers are null-terminated.
- **DER**: pass raw DER bytes and set `cert_is_pem = false`, `key_is_pem = false`. Useful when storing credentials in LittleFS.

You may load credentials from LittleFS, SPIFFS, PROGMEM, or embed them in code. When TLS is enabled, provide credentials before calling `Server::begin()`. If credentials are missing, the server falls back to bundled PolarSSL test certificate/key for development.

## Keep-Alive Behavior

When `QUARKX_KEEP_ALIVE` is enabled the server:

- accepts up to `QUARKX_MAX_REQ_PER_CONN` sequential requests on the same socket,
- closes the connection after the limit or when the client doesn’t send new data for `QUARKX_KEEPALIVE_MS`.

The library updates the `Connection` header automatically (`keep-alive` or `close`), so handlers do not need to modify response headers manually.

## Logging

Logging uses the `QX_LOG*` macros underneath and is routed to `Serial`. Set `QUARKX_LOG_LEVEL` to control verbosity. Level `3` includes handshake diagnostics and keep-alive loop messages for debugging.

## Examples

- **`examples/PostJson`** – demonstrates reading JSON payloads, echoing responses, and using custom TLS credentials stored in LittleFS.
- More examples can be added by placing sketches under `examples/<ExampleName>`; PlatformIO/Arduino IDE will detect them automatically thanks to `library.json`.

## License

QuarkX is released under the MIT License. See [`LICENSE`](../../LICENSE) for details.
