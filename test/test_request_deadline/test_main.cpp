#include <QuarkX.h>
#include <unity.h>

#include <atomic>
#include <csignal>
#include <thread>

#include "test_net.h"

namespace
{
  constexpr uint16_t kPort = 18081;

  quarkx::Server *g_server = nullptr;

  void hello_handler(Stream &out, const String &, const String &)
  {
    quarkx::send_basic_response(out, 200, F("OK"), F("hello"));
  }

  std::string g_last_body;
  bool g_echo_called = false;

  void echo_handler(Stream &out, const String &, const String &)
  {
    g_echo_called = true;
    uint8_t buf[QUARKX_MAX_BODY];
    const size_t n = quarkx::read_body(buf, sizeof(buf));
    g_last_body.assign(reinterpret_cast<const char *>(buf), n);
    quarkx::send_basic_response(out, 200, F("OK"), F("echo"));
  }

  // Sends `data` one byte at a time, each byte well inside the per-read
  // timeout, until everything is sent or the peer goes away.
  class Trickler
  {
  public:
    Trickler(int fd, std::string data, unsigned gap_ms)
        : _thread([fd, data = std::move(data), gap_ms, this]
                  {
                    for (char c : data)
                    {
                      if (_stop || ::send(fd, &c, 1, 0) != 1)
                      {
                        return;
                      }
                      delay(gap_ms);
                    }
                  }) {}

    ~Trickler()
    {
      _stop = true;
      _thread.join();
    }

  private:
    std::atomic<bool> _stop{false};
    std::thread _thread;
  };

  unsigned long timed_poll()
  {
    const unsigned long start = millis();
    g_server->poll();
    return millis() - start;
  }
} // namespace

void setUp()
{
  g_last_body.clear();
  g_echo_called = false;
  g_server = new quarkx::Server(kPort, false);
  g_server->on("/", hello_handler);
  g_server->on("/echo", echo_handler);
  TEST_ASSERT_TRUE(g_server->begin());
  testnet::arm_watchdog(10);
}

void tearDown()
{
  testnet::disarm_watchdog();
  g_server->end();
  delete g_server;
  g_server = nullptr;
}

// Headers trickled byte by byte never trip the per-read timeout, but the
// whole request must still complete within QUARKX_REQUEST_TIMEOUT_MS.
void test_trickled_headers_are_dropped_at_request_deadline()
{
  const int client = testnet::connect_loopback(kPort);
  std::string headers = "GET / HTTP/1.1\r\n";
  for (int i = 0; i < 40; ++i)
  {
    headers += "X-Pad: aaaaaaaaaa\r\n";
  }
  headers += "\r\n";

  unsigned long elapsed;
  std::string resp;
  {
    Trickler trickle(client, headers, QUARKX_RECV_TIMEOUT_MS / 4);
    elapsed = timed_poll();
    ::shutdown(client, SHUT_RDWR);
  }
  ::close(client);

  TEST_ASSERT_LESS_THAN_UINT32(
      QUARKX_REQUEST_TIMEOUT_MS + 2 * QUARKX_RECV_TIMEOUT_MS, elapsed);
}

// Same for a body trickled after complete headers.
void test_trickled_body_is_dropped_at_request_deadline()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client,
                    "POST /echo HTTP/1.1\r\nContent-Length: 400\r\n\r\n");

  unsigned long elapsed;
  {
    Trickler trickle(client, std::string(400, 'b'), QUARKX_RECV_TIMEOUT_MS / 4);
    elapsed = timed_poll();
    ::shutdown(client, SHUT_RDWR);
  }
  ::close(client);

  TEST_ASSERT_LESS_THAN_UINT32(
      QUARKX_REQUEST_TIMEOUT_MS + 2 * QUARKX_RECV_TIMEOUT_MS, elapsed);
  TEST_ASSERT_FALSE(g_echo_called);
}

// An oversized body that keeps trickling in is not drained forever.
void test_trickled_oversized_body_is_dropped_at_request_deadline()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client,
                    "POST /echo HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n");

  unsigned long elapsed;
  {
    Trickler trickle(client, std::string(100000, 'b'), 1);
    elapsed = timed_poll();
    ::shutdown(client, SHUT_RDWR);
  }
  ::close(client);

  TEST_ASSERT_LESS_THAN_UINT32(
      QUARKX_REQUEST_TIMEOUT_MS + 2 * QUARKX_RECV_TIMEOUT_MS, elapsed);
  TEST_ASSERT_FALSE(g_echo_called);
}

// A normal body is still delivered to the handler.
void test_body_is_delivered_to_handler()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client,
                    "POST /echo HTTP/1.1\r\nContent-Length: 11\r\n\r\n"
                    "hello world");
  ::shutdown(client, SHUT_WR);

  g_server->poll();
  const std::string resp = testnet::recv_all(client);
  ::close(client);

  TEST_ASSERT_TRUE(g_echo_called);
  TEST_ASSERT_EQUAL_STRING("hello world", g_last_body.c_str());
  TEST_ASSERT_EQUAL_INT(0, resp.rfind("HTTP/1.1 200 OK\r\n", 0));
}

// An oversized body that arrives promptly is drained and the handler still
// runs, without body, as before.
void test_prompt_oversized_body_still_reaches_handler()
{
  const int client = testnet::connect_loopback(kPort);
  const size_t len = QUARKX_MAX_BODY * 4;
  testnet::send_all(client, "POST /echo HTTP/1.1\r\nContent-Length: " +
                                std::to_string(len) + "\r\n\r\n" +
                                std::string(len, 'b'));
  ::shutdown(client, SHUT_WR);

  g_server->poll();
  testnet::recv_all(client);
  ::close(client);

  TEST_ASSERT_TRUE(g_echo_called);
  TEST_ASSERT_EQUAL_UINT32(0, g_last_body.size());
}

// Between keep-alive requests the server waits QUARKX_KEEPALIVE_MS, not
// QUARKX_RECV_TIMEOUT_MS, for the next request.
void test_keep_alive_idle_wait_uses_keepalive_timeout()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client,
                    "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n");

  const unsigned long elapsed = timed_poll();
  const std::string resp = testnet::recv_all(client, 100);
  ::close(client);

  TEST_ASSERT_NOT_EQUAL(std::string::npos,
                        resp.find("Connection: keep-alive\r\n"));
  TEST_ASSERT_GREATER_OR_EQUAL_UINT32(QUARKX_KEEPALIVE_MS * 9 / 10, elapsed);
  TEST_ASSERT_LESS_THAN_UINT32(QUARKX_KEEPALIVE_MS + QUARKX_RECV_TIMEOUT_MS,
                               elapsed);
}

int main()
{
  std::signal(SIGPIPE, SIG_IGN);
  UNITY_BEGIN();
  RUN_TEST(test_trickled_headers_are_dropped_at_request_deadline);
  RUN_TEST(test_trickled_body_is_dropped_at_request_deadline);
  RUN_TEST(test_trickled_oversized_body_is_dropped_at_request_deadline);
  RUN_TEST(test_body_is_delivered_to_handler);
  RUN_TEST(test_prompt_oversized_body_still_reaches_handler);
  RUN_TEST(test_keep_alive_idle_wait_uses_keepalive_timeout);
  return UNITY_END();
}
