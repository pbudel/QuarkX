/*
 * MIT License
 *
 * Copyright (c) 2024 QuarkX Authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef QUARKX_QUARKX_H
#define QUARKX_QUARKX_H

#include <Arduino.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#ifndef QUARKX_ENABLE_TLS
#define QUARKX_ENABLE_TLS 1
#endif

#if QUARKX_ENABLE_TLS
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#endif

#ifndef QUARKX_MAX_CLIENTS
#define QUARKX_MAX_CLIENTS 4
#endif

#ifndef QUARKX_ROUTE_MAX
#define QUARKX_ROUTE_MAX 8
#endif

#ifndef QUARKX_PREFIX_MAX
#define QUARKX_PREFIX_MAX 4
#endif

#ifndef QUARKX_RECV_BUFSZ
#define QUARKX_RECV_BUFSZ 1024
#endif

#ifndef QUARKX_SEND_BUFSZ
#define QUARKX_SEND_BUFSZ 1024
#endif

#ifndef QUARKX_MAX_BODY
#define QUARKX_MAX_BODY 512
#endif

#ifndef QUARKX_KEEP_ALIVE
#define QUARKX_KEEP_ALIVE 1
#endif

#ifndef QUARKX_MAX_REQ_PER_CONN
#define QUARKX_MAX_REQ_PER_CONN 4
#endif

#ifndef QUARKX_KEEPALIVE_MS
#define QUARKX_KEEPALIVE_MS 5000
#endif

#ifndef QUARKX_RECV_TIMEOUT_MS
#define QUARKX_RECV_TIMEOUT_MS 5000
#endif

#ifndef QUARKX_LOG_LEVEL
#define QUARKX_LOG_LEVEL 0
#endif

namespace quarkx
{

  namespace detail
  {
    class TlsTransport;
  }

  using Handler = std::function<void(Stream &out, const String &method,
                                     const String &path)>;

  struct TlsCreds
  {
    const uint8_t *cert;
    std::size_t cert_len;
    bool cert_is_pem;
    const uint8_t *key;
    std::size_t key_len;
    bool key_is_pem;
  };

  class Transport
  {
  public:
    virtual ~Transport() = default;
    virtual int recv(uint8_t *buf, std::size_t len) = 0;
    virtual int send(const uint8_t *buf, std::size_t len) = 0;
    virtual void shutdown() {}
  };

  /**
   * @brief Copy request body data into the caller-provided buffer.
   * @param buf Destination buffer.
   * @param max Maximum number of bytes to copy.
   * @return Number of bytes copied (0 if body unavailable or fully consumed).
   */
  size_t read_body(uint8_t *buf, size_t max);

  class Server
  {
  public:
    explicit Server(uint16_t port = 80, bool use_tls = false);
    ~Server();

    void setTlsCredentials(const TlsCreds &creds);

    void on(const String &path, Handler handler);

    /**
     * @brief Register a handler that triggers on matching path prefix.
     * @param prefix Path prefix (leading slash recommended).
     * @param handler Callback invoked for matching requests.
     */
    void onPrefix(const String &prefix, Handler handler);

    void onNotFound(Handler handler);

    bool begin();

    void poll();

    void end();

    Handler route(const String &path) const;

  private:
    struct RouteSlot
    {
      String path;
      Handler handler;
    };

    struct PrefixSlot
    {
      String prefix;
      Handler handler;
    };

    struct BodyState
    {
      size_t length;
      size_t cursor;
      bool valid;
      uint8_t buffer[QUARKX_MAX_BODY];
    };

    RouteSlot _routes[QUARKX_ROUTE_MAX];
    PrefixSlot _prefixes[QUARKX_PREFIX_MAX];
    Handler _notFound;
    uint16_t _port;
    bool _useTls;
    TlsCreds _tlsCreds;
    int _listenFd;
    bool _listening;
    BodyState _body;
#if QUARKX_KEEP_ALIVE
    bool _currentKeepAlive;
#endif
#if QUARKX_ENABLE_TLS
    struct TlsContext
    {
      bool ready;
      mbedtls_ssl_config conf;
      mbedtls_ctr_drbg_context ctr_drbg;
      mbedtls_entropy_context entropy;
      mbedtls_x509_crt cert;
      mbedtls_pk_context key;
      std::vector<uint8_t> cert_cache;
      std::vector<uint8_t> key_cache;

      TlsContext() : ready(false)
      {
        mbedtls_ssl_config_init(&conf);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
        mbedtls_x509_crt_init(&cert);
        mbedtls_pk_init(&key);
      }

      ~TlsContext()
      {
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_x509_crt_free(&cert);
        mbedtls_pk_free(&key);
      }
    };
    TlsContext *_tlsCtx;
    bool _ensureTlsContext();
#endif

#if QUARKX_ENABLE_TLS
    friend class detail::TlsTransport;
#endif

    Handler _findRoute(const String &path) const;
    bool _readRequestLine(Transport &transport, String &method, String &path);
    void _serveClient(int client_fd);
    void _resetBody();
    size_t _readBody(uint8_t *buf, size_t max);

    friend size_t read_body(uint8_t *buf, size_t max);
    friend void send_basic_response(Stream &out, int code,
                                    const __FlashStringHelper *status,
                                    const String &body);
  };

  void send_basic_response(Stream &out, int code,
                           const __FlashStringHelper *status,
                           const String &body);

} // namespace quarkx

#endif // QUARKX_QUARKX_H
