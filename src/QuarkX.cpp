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

#include "QuarkX.h"

#include "QuarkX_Headers.h"

#include <cstring>
#include <cstdlib>
#include <cctype>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#if defined(ESP_PLATFORM)
#include <lwip/inet.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#if QUARKX_ENABLE_TLS
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#endif

namespace quarkx
{
  namespace detail
  {

#ifndef QX_LOGE
#if QUARKX_LOG_LEVEL >= 1
#define QX_LOGE(fmt, ...) Serial.printf("[E] " fmt "\n", ##__VA_ARGS__)
#else
#define QX_LOGE(fmt, ...) \
  do                      \
  {                       \
  } while (0)
#endif
#endif

#ifndef QX_LOGI
#if QUARKX_LOG_LEVEL >= 2
#define QX_LOGI(fmt, ...) Serial.printf("[I] " fmt "\n", ##__VA_ARGS__)
#else
#define QX_LOGI(fmt, ...) \
  do                      \
  {                       \
  } while (0)
#endif
#endif

#ifndef QX_LOGD
#if QUARKX_LOG_LEVEL >= 3
#define QX_LOGD(fmt, ...) Serial.printf("[D] " fmt "\n", ##__VA_ARGS__)
#else
#define QX_LOGD(fmt, ...) \
  do                      \
  {                       \
  } while (0)
#endif
#endif

#if QUARKX_ENABLE_TLS
    constexpr const char kTlsPers[] = "quarkx_tls";

    static void log_mbedtls_error(const char *label, int code)
    {
      char buffer[128];
      mbedtls_strerror(code, buffer, sizeof(buffer));
      QX_LOGE("%s: %s (%d)", label, buffer, code);
    }
#endif

    class PlainTransport : public Transport
    {
    public:
      explicit PlainTransport(int fd) : _fd(fd) {}

      int fd() const { return _fd; }

      int recv(uint8_t *buf, size_t len) override
      {
        while (true)
        {
          const int ret = ::recv(_fd, reinterpret_cast<char *>(buf),
                                 static_cast<int>(len), 0);
          if (ret < 0)
          {
            if (errno == EINTR)
            {
              continue;
            }
#if defined(EWOULDBLOCK)
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              delay(1);
              continue;
            }
#else
            if (errno == EAGAIN)
            {
              delay(1);
              continue;
            }
#endif
          }
          return ret;
        }
      }

      int send(const uint8_t *buf, size_t len) override
      {
        while (true)
        {
          const int ret = ::send(_fd, reinterpret_cast<const char *>(buf),
                                 static_cast<int>(len), 0);
          if (ret < 0)
          {
            if (errno == EINTR)
            {
              continue;
            }
#if defined(EWOULDBLOCK)
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              delay(1);
              continue;
            }
#else
            if (errno == EAGAIN)
            {
              delay(1);
              continue;
            }
#endif
          }
          return ret;
        }
      }

    private:
      int _fd;
    };

#if QUARKX_ENABLE_TLS
    class TlsTransport : public Transport
    {
    public:
      TlsTransport(Server::TlsContext &ctx, int fd)
          : _ctx(ctx), _fd(fd)
      {
        mbedtls_ssl_init(&_ssl);
      }

      ~TlsTransport() override { mbedtls_ssl_free(&_ssl); }

      bool handshake()
      {
        int ret = mbedtls_ssl_setup(&_ssl, &_ctx.conf);
        if (ret != 0)
        {
          log_mbedtls_error("mbedtls_ssl_setup", ret);
          return false;
        }

        mbedtls_ssl_set_bio(
            &_ssl, this,
            [](void *ctx, const unsigned char *buf, size_t len)
            {
              auto *self = static_cast<TlsTransport *>(ctx);
              const int res = ::send(self->_fd, reinterpret_cast<const char *>(buf),
                                     static_cast<int>(len), 0);
              if (res < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
              {
                return MBEDTLS_ERR_SSL_WANT_WRITE;
              }
              if (res < 0)
              {
                return MBEDTLS_ERR_NET_SEND_FAILED;
              }
              return res;
            },
            [](void *ctx, unsigned char *buf, size_t len)
            {
              auto *self = static_cast<TlsTransport *>(ctx);
              const int res = ::recv(self->_fd, reinterpret_cast<char *>(buf),
                                     static_cast<int>(len), 0);
              if (res < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
              {
                return MBEDTLS_ERR_SSL_WANT_READ;
              }
              if (res < 0)
              {
                return MBEDTLS_ERR_NET_RECV_FAILED;
              }
              return res;
            },
            nullptr);

        do
        {
          ret = mbedtls_ssl_handshake(&_ssl);
        } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                 ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (ret != 0)
        {
          log_mbedtls_error("mbedtls_ssl_handshake", ret);
          return false;
        }
        return true;
      }

      int recv(uint8_t *buf, size_t len) override
      {
        while (true)
        {
          const int ret = mbedtls_ssl_read(&_ssl, buf, static_cast<int>(len));
          if (ret >= 0)
          {
            return ret;
          }
          if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
              ret == MBEDTLS_ERR_SSL_WANT_WRITE)
          {
            delay(1);
            continue;
          }
          if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
          {
            return 0;
          }
          log_mbedtls_error("mbedtls_ssl_read", ret);
          return -1;
        }
      }

      int send(const uint8_t *buf, size_t len) override
      {
        size_t sent = 0;
        while (sent < len)
        {
          const int ret =
              mbedtls_ssl_write(&_ssl, buf + sent, static_cast<int>(len - sent));
          if (ret > 0)
          {
            sent += static_cast<size_t>(ret);
            continue;
          }
          if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
              ret == MBEDTLS_ERR_SSL_WANT_WRITE)
          {
            delay(1);
            continue;
          }
          log_mbedtls_error("mbedtls_ssl_write", ret);
          return -1;
        }
        return static_cast<int>(sent);
      }

      void shutdown() override { mbedtls_ssl_close_notify(&_ssl); }

    private:
      Server::TlsContext &_ctx;
      int _fd;
      mbedtls_ssl_context _ssl;
    };
#endif

    class StreamWrapper : public Stream
    {
    public:
      explicit StreamWrapper(Transport &transport) : _transport(transport) {}

      int available() override { return 0; }

      int read() override
      {
        uint8_t byte = 0;
        const int ret = _transport.recv(&byte, 1);
        if (ret <= 0)
        {
          return -1;
        }
        return byte;
      }

      int peek() override { return -1; }

      void flush() override {}

      size_t write(uint8_t b) override { return write(&b, 1); }

      size_t write(const uint8_t *buffer, size_t size) override
      {
        if (!buffer || size == 0)
        {
          return 0;
        }
        size_t total = 0;
        while (total < size)
        {
          const int sent = _transport.send(buffer + total, size - total);
          if (sent < 0)
          {
            return total;
          }
          if (sent == 0)
          {
            return total;
          }
          total += static_cast<size_t>(sent);
        }
        return total;
      }

    private:
      Transport &_transport;
    };

    Server *g_active_server = nullptr;

    class ScopedServerBody
    {
    public:
      explicit ScopedServerBody(Server *srv) : _prev(g_active_server)
      {
        g_active_server = srv;
      }

      ~ScopedServerBody() { g_active_server = _prev; }

    private:
      Server *_prev;
    };

    constexpr int kListenBacklog = QUARKX_MAX_CLIENTS;

    bool set_socket_nonblock(int fd)
    {
      int flags = ::fcntl(fd, F_GETFL, 0);
      if (flags < 0)
      {
        return false;
      }
      if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
      {
        return false;
      }
      return true;
    }

    bool set_socket_blocking(int fd)
    {
      int flags = ::fcntl(fd, F_GETFL, 0);
      if (flags < 0)
      {
        return false;
      }
      flags &= ~O_NONBLOCK;
      if (::fcntl(fd, F_SETFL, flags) < 0)
      {
        return false;
      }
      return true;
    }

    bool set_socket_timeout(int fd, int milliseconds)
    {
      struct timeval tv;
      tv.tv_sec = milliseconds / 1000;
      tv.tv_usec = (milliseconds % 1000) * 1000;
      return ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
             ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
    }

    int close_socket(int fd)
    {
      return ::close(fd);
    }

    static int transport_reader(void *ctx, uint8_t *buf, std::size_t len)
    {
      auto *transport = static_cast<Transport *>(ctx);
      return transport->recv(buf, len);
    }

    int receive_exact(Transport &transport, uint8_t *buffer, size_t len)
    {
      size_t total = 0;
      while (total < len)
      {
        const int r = transport.recv(buffer + total, len - total);
        if (r <= 0)
        {
          return -1;
        }
        total += static_cast<size_t>(r);
      }
      return 0;
    }

  } // namespace detail

  using detail::close_socket;
  using detail::g_active_server;
  using detail::PlainTransport;
  using detail::receive_exact;
  using detail::ScopedServerBody;
  using detail::set_socket_blocking;
  using detail::set_socket_nonblock;
  using detail::set_socket_timeout;
  using detail::StreamWrapper;
  using detail::transport_reader;
#if QUARKX_ENABLE_TLS
  using detail::kTlsPers;
  using detail::log_mbedtls_error;
  using detail::TlsTransport;
#endif
  using detail::kListenBacklog;

  Server::Server(uint16_t port, bool use_tls)
      : _notFound(),
        _port(port),
        _useTls(use_tls),
        _tlsCreds{nullptr, 0, true, nullptr, 0, true},
        _listenFd(-1),
        _listening(false)
#if QUARKX_ENABLE_TLS
        ,
        _tlsCtx(nullptr)
#endif
  {
    _resetBody();
    for (size_t i = 0; i < QUARKX_ROUTE_MAX; ++i)
    {
      _routes[i].path = String();
      _routes[i].handler = nullptr;
    }
    for (size_t i = 0; i < QUARKX_PREFIX_MAX; ++i)
    {
      _prefixes[i].prefix = String();
      _prefixes[i].handler = nullptr;
    }
#if QUARKX_KEEP_ALIVE
    _currentKeepAlive = false;
#endif
  }

  Server::~Server()
  {
#if QUARKX_ENABLE_TLS
    delete _tlsCtx;
    _tlsCtx = nullptr;
#endif
  }

  void Server::setTlsCredentials(const TlsCreds &creds)
  {
    _tlsCreds = creds;
#if QUARKX_ENABLE_TLS
    if (_tlsCtx)
    {
      delete _tlsCtx;
      _tlsCtx = nullptr;
    }
#endif
  }

#if QUARKX_ENABLE_TLS
  bool Server::_ensureTlsContext()
  {
    if (!_useTls)
    {
      return true;
    }
    if (!_tlsCtx)
    {
      _tlsCtx = new TlsContext();
    }
    if (_tlsCtx->ready)
    {
      return true;
    }
    if (!_tlsCreds.cert || !_tlsCreds.key || _tlsCreds.cert_len == 0 ||
        _tlsCreds.key_len == 0)
    {
      QX_LOGE("TLS credentials not provided");
      return false;
    }

    const uint8_t *cert_data = _tlsCreds.cert;
    size_t cert_len = _tlsCreds.cert_len;
    if (_tlsCreds.cert_is_pem)
    {
      if (cert_data[cert_len - 1] != 0)
      {
        _tlsCtx->cert_cache.assign(cert_data, cert_data + cert_len);
        _tlsCtx->cert_cache.push_back(0);
        cert_data = _tlsCtx->cert_cache.data();
        cert_len = _tlsCtx->cert_cache.size();
      }
    }

    const uint8_t *key_data = _tlsCreds.key;
    size_t key_len = _tlsCreds.key_len;
    if (_tlsCreds.key_is_pem)
    {
      if (key_data[key_len - 1] != 0)
      {
        _tlsCtx->key_cache.assign(key_data, key_data + key_len);
        _tlsCtx->key_cache.push_back(0);
        key_data = _tlsCtx->key_cache.data();
        key_len = _tlsCtx->key_cache.size();
      }
    }

    const int seed_ret = mbedtls_ctr_drbg_seed(
        &_tlsCtx->ctr_drbg, mbedtls_entropy_func, &_tlsCtx->entropy,
        reinterpret_cast<const unsigned char *>(kTlsPers),
        sizeof(kTlsPers) - 1);
    if (seed_ret != 0)
    {
      log_mbedtls_error("mbedtls_ctr_drbg_seed", seed_ret);
      return false;
    }

    int cert_ret;
    cert_ret = mbedtls_x509_crt_parse(&_tlsCtx->cert, cert_data, cert_len);
    if (cert_ret != 0)
    {
      log_mbedtls_error("mbedtls_x509_crt_parse", cert_ret);
      return false;
    }

    int key_ret =
        mbedtls_pk_parse_key(&_tlsCtx->key, key_data, key_len, nullptr, 0);
    if (key_ret != 0)
    {
      log_mbedtls_error("mbedtls_pk_parse_key", key_ret);
      return false;
    }

    int cfg_ret = mbedtls_ssl_config_defaults(
        &_tlsCtx->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (cfg_ret != 0)
    {
      log_mbedtls_error("mbedtls_ssl_config_defaults", cfg_ret);
      return false;
    }

    mbedtls_ssl_conf_rng(&_tlsCtx->conf, mbedtls_ctr_drbg_random,
                         &_tlsCtx->ctr_drbg);
    mbedtls_ssl_conf_authmode(&_tlsCtx->conf, MBEDTLS_SSL_VERIFY_NONE);

    cfg_ret =
        mbedtls_ssl_conf_own_cert(&_tlsCtx->conf, &_tlsCtx->cert, &_tlsCtx->key);
    if (cfg_ret != 0)
    {
      log_mbedtls_error("mbedtls_ssl_conf_own_cert", cfg_ret);
      return false;
    }

    _tlsCtx->ready = true;
    return true;
  }
#endif

  void Server::on(const String &path, Handler handler)
  {
    for (size_t i = 0; i < QUARKX_ROUTE_MAX; ++i)
    {
      if (_routes[i].path == path)
      {
        _routes[i].handler = handler;
        return;
      }
      if (_routes[i].path.length() == 0)
      {
        _routes[i].path = path;
        _routes[i].handler = handler;
        return;
      }
    }
    QX_LOGE("Route table full, cannot add '%s'", path.c_str());
  }

  void Server::onPrefix(const String &prefix, Handler handler)
  {
    if (prefix.length() == 0)
    {
      QX_LOGE("Empty prefix not allowed");
      return;
    }
    for (size_t i = 0; i < QUARKX_PREFIX_MAX; ++i)
    {
      if (_prefixes[i].prefix == prefix)
      {
        _prefixes[i].handler = handler;
        return;
      }
    }
    for (size_t i = 0; i < QUARKX_PREFIX_MAX; ++i)
    {
      if (_prefixes[i].prefix.length() == 0)
      {
        _prefixes[i].prefix = prefix;
        _prefixes[i].handler = handler;
        return;
      }
    }
    QX_LOGE("Prefix table full, cannot add '%s'", prefix.c_str());
  }

  void Server::onNotFound(Handler handler) { _notFound = handler; }

  bool Server::begin()
  {
    if (_listening)
    {
      return true;
    }

#if QUARKX_ENABLE_TLS
    if (_useTls && !_ensureTlsContext())
    {
      return false;
    }
#endif

    _listenFd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (_listenFd < 0)
    {
      QX_LOGE("socket() failed: %d", errno);
      return false;
    }

    int opt = 1;
    if (::setsockopt(_listenFd, SOL_SOCKET, SO_REUSEADDR, &opt,
                     sizeof(opt)) != 0)
    {
      QX_LOGE("setsockopt failed: %d", errno);
      close_socket(_listenFd);
      _listenFd = -1;
      return false;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(_port);

    if (::bind(_listenFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) !=
        0)
    {
      QX_LOGE("bind failed: %d", errno);
      close_socket(_listenFd);
      _listenFd = -1;
      return false;
    }

    if (::listen(_listenFd, kListenBacklog) != 0)
    {
      QX_LOGE("listen failed: %d", errno);
      close_socket(_listenFd);
      _listenFd = -1;
      return false;
    }

    if (!set_socket_nonblock(_listenFd))
    {
      QX_LOGE("failed to set listening socket non-blocking");
      close_socket(_listenFd);
      _listenFd = -1;
      return false;
    }

    _listening = true;
    QX_LOGI("Listening on port %u", static_cast<unsigned>(_port));
    return true;
  }

  void Server::poll()
  {
    if (!_listening)
    {
      return;
    }

    sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    const int client_fd =
        ::accept(_listenFd, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
    if (client_fd < 0)
    {
#if defined(EWOULDBLOCK)
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        return;
      }
#else
      if (errno == EAGAIN)
      {
        return;
      }
#endif
      QX_LOGE("accept failed: %d", errno);
      return;
    }

    if (!set_socket_blocking(client_fd))
    {
      QX_LOGE("failed to switch client socket to blocking mode");
    }
    if (!set_socket_timeout(client_fd, QUARKX_RECV_TIMEOUT_MS))
    {
      QX_LOGE("failed to set socket timeout");
    }

    _serveClient(client_fd);
    close_socket(client_fd);
  }

  void Server::end()
  {
    if (_listenFd >= 0)
    {
      close_socket(_listenFd);
      _listenFd = -1;
    }
    _listening = false;
  }

  Handler Server::route(const String &path) const { return _findRoute(path); }

  Handler Server::_findRoute(const String &path) const
  {
    for (size_t i = 0; i < QUARKX_ROUTE_MAX; ++i)
    {
      if (_routes[i].handler && _routes[i].path == path)
      {
        return _routes[i].handler;
      }
    }
    Handler best = nullptr;
    size_t best_len = 0;
    for (size_t i = 0; i < QUARKX_PREFIX_MAX; ++i)
    {
      if (_prefixes[i].handler &&
          path.startsWith(_prefixes[i].prefix))
      {
        const size_t len = static_cast<size_t>(_prefixes[i].prefix.length());
        if (len > best_len)
        {
          best = _prefixes[i].handler;
          best_len = len;
        }
      }
    }
    if (best)
    {
      return best;
    }
    return nullptr;
  }

  bool Server::_readRequestLine(Transport &transport, String &method,
                                String &path)
  {
    char line[QUARKX_HDR_LINE_MAX];
    size_t len = 0;
    bool have_cr = false;

    while (len < sizeof(line) - 1)
    {
      char ch = 0;
      const int r = transport.recv(reinterpret_cast<uint8_t *>(&ch), 1);
      if (r == 0)
      {
        return false;
      }
      if (r < 0)
      {
        return false;
      }

      if (ch == '\r')
      {
        have_cr = true;
        continue;
      }
      if (ch == '\n')
      {
        line[len] = '\0';
        break;
      }
      if (have_cr)
      {
        if (len >= sizeof(line) - 1)
        {
          return false;
        }
        line[len++] = '\r';
        have_cr = false;
      }
      line[len++] = ch;
    }

    if (len == 0 || len >= sizeof(line) - 1)
    {
      return false;
    }

    line[len] = '\0';

    char *method_end = std::strchr(line, ' ');
    if (!method_end)
    {
      return false;
    }
    *method_end = '\0';
    const char *path_begin = method_end + 1;
    char *path_end = std::strchr(path_begin, ' ');
    if (!path_end)
    {
      return false;
    }
    *path_end = '\0';

    method = String(line);
    path = String(path_begin);
    return true;
  }

  void Server::_resetBody()
  {
    _body.length = 0;
    _body.cursor = 0;
    _body.valid = false;
  }

  void Server::_serveClient(int client_fd)
  {
    auto process_request = [&](Transport &transport, detail::StreamWrapper &stream,
                               bool allow_keep) -> bool
    {
      String method;
      String path;
      if (!_readRequestLine(transport, method, path))
      {
        QX_LOGD("Connection closed while waiting for next request");
        return false;
      }

      QX_LOGI("Request %s %s", method.c_str(), path.c_str());

      HeaderTable headers;
      if (!parse_headers(detail::transport_reader, &transport, headers))
      {
        QX_LOGD("Header parse failed");
        return false;
      }

      _resetBody();

      const char *cl = get_header(headers, "content-length");
      if (cl)
      {
        const unsigned long len = std::strtoul(cl, nullptr, 10);
        if (len > 0 && len <= QUARKX_MAX_BODY)
        {
          if (receive_exact(transport, _body.buffer,
                            static_cast<size_t>(len)) == 0)
          {
            _body.length = static_cast<size_t>(len);
            _body.cursor = 0;
            _body.valid = true;
          }
          else
          {
            QX_LOGD("Failed reading body");
          }
        }
        else if (len > QUARKX_MAX_BODY)
        {
          QX_LOGE("Body too large (%lu), dropping", len);
          const size_t to_drain = static_cast<size_t>(len);
          size_t drained = 0;
          uint8_t temp[64];
          while (drained < to_drain)
          {
            const size_t remain = to_drain - drained;
            const size_t chunk = remain < sizeof(temp) ? remain : sizeof(temp);
            const int r = transport.recv(temp, chunk);
            if (r <= 0)
            {
              break;
            }
            drained += static_cast<size_t>(r);
          }
        }
      }

      Handler handler = _findRoute(path);
      if (!handler && _notFound)
      {
        handler = _notFound;
      }

#if QUARKX_KEEP_ALIVE
      bool next_keep = false;
      if (allow_keep)
      {
        const char *conn_hdr = get_header(headers, "connection");
        if (conn_hdr)
        {
          const char target[] = "keep-alive";
          std::size_t i = 0;
          for (; target[i] && conn_hdr[i]; ++i)
          {
            if (std::tolower(static_cast<unsigned char>(conn_hdr[i])) != target[i])
            {
              break;
            }
          }
          if (!target[i] && conn_hdr[i] == '\0')
          {
            next_keep = true;
          }
        }
      }
      _currentKeepAlive = next_keep;
#endif

      if (handler)
      {
        ScopedServerBody guard(this);
        handler(stream, method, path);
      }
      else
      {
        QX_LOGD("No handler for path '%s'", path.c_str());
      }

      QX_LOGD("Finished handling %s %s", method.c_str(), path.c_str());

#if QUARKX_KEEP_ALIVE
      bool keep_loop = _currentKeepAlive;
      _currentKeepAlive = false;
      return keep_loop;
#else
      (void)allow_keep;
      return false;
#endif
    };

#if QUARKX_ENABLE_TLS
    if (_useTls)
    {
      if (!_ensureTlsContext())
      {
        return;
      }
      detail::TlsTransport transport(*_tlsCtx, client_fd);
      if (!transport.handshake())
      {
        return;
      }
      detail::StreamWrapper stream(transport);
#if QUARKX_KEEP_ALIVE
      size_t served = 0;
      bool cont = true;
      while (served < QUARKX_MAX_REQ_PER_CONN && cont)
      {
        const bool allow = (served + 1 < QUARKX_MAX_REQ_PER_CONN);
        cont = process_request(transport, stream, allow);
        ++served;
      }
#else
      process_request(transport, stream, false);
#endif
      transport.shutdown();
      return;
    }
#endif

    detail::PlainTransport transport(client_fd);
    detail::StreamWrapper stream(transport);
#if QUARKX_KEEP_ALIVE
    size_t served = 0;
    bool cont = true;
    while (served < QUARKX_MAX_REQ_PER_CONN && cont)
    {
      const bool allow = (served + 1 < QUARKX_MAX_REQ_PER_CONN);
      cont = process_request(transport, stream, allow);
      ++served;
    }
#else
    process_request(transport, stream, false);
#endif
  }

  size_t Server::_readBody(uint8_t *buf, size_t max)
  {
    if (!_body.valid || !buf || max == 0)
    {
      return 0;
    }
    if (_body.cursor >= _body.length)
    {
      return 0;
    }
    const size_t remaining = _body.length - _body.cursor;
    const size_t to_copy = remaining < max ? remaining : max;
    std::memcpy(buf, _body.buffer + _body.cursor, to_copy);
    _body.cursor += to_copy;
    return to_copy;
  }

  size_t read_body(uint8_t *buf, size_t max)
  {
    if (!g_active_server)
    {
      return 0;
    }
    return g_active_server->_readBody(buf, max);
  }

  void send_basic_response(Stream &out, int code,
                           const __FlashStringHelper *status,
                           const String &body)
  {
    out.print(F("HTTP/1.1 "));
    out.print(code);
    out.print(' ');
    out.print(status);
    out.print(F("\r\nContent-Length: "));
    out.print(static_cast<unsigned>(body.length()));
#if QUARKX_KEEP_ALIVE
    bool keep = g_active_server && g_active_server->_currentKeepAlive;
    out.print(F("\r\nContent-Type: text/plain\r\nConnection: "));
    out.print(keep ? F("keep-alive") : F("close"));
    out.print(F("\r\n"));
    if (keep)
    {
      out.print(F("Keep-Alive: timeout="));
      out.print(static_cast<unsigned>(QUARKX_KEEPALIVE_MS / 1000));
      out.print(F(", max="));
      out.print(static_cast<unsigned>(QUARKX_MAX_REQ_PER_CONN));
      out.print(F("\r\n"));
    }
    out.print(F("\r\n"));
#else
    out.print(F("\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"));
#endif
    out.print(body);
  }

} // namespace quarkx
