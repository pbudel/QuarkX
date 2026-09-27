// Loopback socket helpers shared by the native tests.
#ifndef QUARKX_TEST_NET_H
#define QUARKX_TEST_NET_H

#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace testnet
{

  // Fails the run instead of hanging forever when the code under test blocks.
  inline void arm_watchdog(unsigned seconds)
  {
    std::signal(SIGALRM, [](int)
                {
                  static const char msg[] = "\nWATCHDOG: test blocked, aborting\n";
                  (void)!::write(2, msg, sizeof(msg) - 1);
                  _exit(3);
                });
    ::alarm(seconds);
  }

  inline void disarm_watchdog() { ::alarm(0); }

  inline int connect_loopback(uint16_t port)
  {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
    {
      ::close(fd);
      return -1;
    }
    // Give the kernel time to move the connection to the accept queue so a
    // single non-blocking accept() in poll() is guaranteed to see it.
    ::usleep(20 * 1000);
    return fd;
  }

  inline void send_all(int fd, const std::string &data)
  {
    std::size_t sent = 0;
    while (sent < data.size())
    {
      const ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
      if (n <= 0)
      {
        return;
      }
      sent += static_cast<std::size_t>(n);
    }
  }

  // Reads until the peer closes or `timeout_ms` of silence elapses.
  inline std::string recv_all(int fd, int timeout_ms = 1000)
  {
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::string out;
    char buf[512];
    while (true)
    {
      const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
      if (n <= 0)
      {
        break;
      }
      out.append(buf, static_cast<std::size_t>(n));
    }
    return out;
  }

} // namespace testnet

#endif // QUARKX_TEST_NET_H
