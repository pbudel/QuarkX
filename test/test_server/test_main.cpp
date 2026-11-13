#include <QuarkX.h>
#include <unity.h>

#include <csignal>
#include <string>

#include "test_net.h"

namespace
{
  constexpr uint16_t kPort = 18080;

  quarkx::Server *g_server = nullptr;

  void hello_handler(Stream &out, const String &, const String &)
  {
    quarkx::send_basic_response(out, 200, F("OK"), F("hello"));
  }
} // namespace

void setUp()
{
  g_server = new quarkx::Server(kPort, false);
  g_server->on("/", hello_handler);
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

void test_serves_a_simple_request()
{
  const int client = testnet::connect_loopback(kPort);
  TEST_ASSERT_GREATER_OR_EQUAL(0, client);
  testnet::send_all(client, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
  ::shutdown(client, SHUT_WR);

  g_server->poll();

  const std::string resp = testnet::recv_all(client);
  ::close(client);
  TEST_ASSERT_EQUAL_INT(0, resp.rfind("HTTP/1.1 200 OK\r\n", 0));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, resp.find("\r\n\r\nhello"));
}

// A client that connects and never sends anything must not block poll()
// for longer than the receive timeout.
void test_silent_client_does_not_block_poll()
{
  const int silent = testnet::connect_loopback(kPort);
  TEST_ASSERT_GREATER_OR_EQUAL(0, silent);

  const unsigned long start = millis();
  g_server->poll();
  const unsigned long elapsed = millis() - start;
  ::close(silent);

  TEST_ASSERT_LESS_THAN_UINT32(4 * QUARKX_RECV_TIMEOUT_MS, elapsed);
}

// Same for a client that stops in the middle of the request headers.
void test_client_stalling_mid_headers_does_not_block_poll()
{
  const int stalled = testnet::connect_loopback(kPort);
  TEST_ASSERT_GREATER_OR_EQUAL(0, stalled);
  testnet::send_all(stalled, "GET / HTTP/1.1\r\nHost: x\r\n");

  const unsigned long start = millis();
  g_server->poll();
  const unsigned long elapsed = millis() - start;
  ::close(stalled);

  TEST_ASSERT_LESS_THAN_UINT32(4 * QUARKX_RECV_TIMEOUT_MS, elapsed);
}

// After a silent client times out, the next client is served normally.
void test_next_client_served_after_silent_one()
{
  const int silent = testnet::connect_loopback(kPort);
  const int good = testnet::connect_loopback(kPort);
  testnet::send_all(good, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
  ::shutdown(good, SHUT_WR);

  g_server->poll();
  g_server->poll();

  const std::string resp = testnet::recv_all(good);
  ::close(silent);
  ::close(good);
  TEST_ASSERT_EQUAL_INT(0, resp.rfind("HTTP/1.1 200 OK\r\n", 0));
}

namespace
{
  void flood_handler(Stream &out, const String &, const String &)
  {
    static uint8_t chunk[4096];
    // Far more than the loopback socket buffers can absorb.
    for (int i = 0; i < 4096; ++i)
    {
      if (out.write(chunk, sizeof(chunk)) != sizeof(chunk))
      {
        return;
      }
    }
  }
} // namespace

// A client that requests a large response and never reads it must not block
// poll() forever once the send timeout expires.
void test_client_not_reading_response_does_not_block_poll()
{
  g_server->on("/flood", flood_handler);
  const int lazy = testnet::connect_loopback(kPort);
  TEST_ASSERT_GREATER_OR_EQUAL(0, lazy);
  testnet::send_all(lazy, "GET /flood HTTP/1.1\r\nHost: x\r\n\r\n");

  const unsigned long start = millis();
  g_server->poll();
  const unsigned long elapsed = millis() - start;
  ::close(lazy);

  TEST_ASSERT_LESS_THAN_UINT32(4000, elapsed);
}

namespace
{
  std::string g_seen_origin;
  std::string g_seen_host;
  bool g_origin_was_null = false;

  void echo_headers_handler(Stream &out, const String &, const String &)
  {
    const char *origin = quarkx::request_header("Origin");
    const char *host = quarkx::request_header("HOST");
    g_origin_was_null = (origin == nullptr);
    g_seen_origin = origin ? origin : "";
    g_seen_host = host ? host : "";
    quarkx::send_basic_response(out, 200, F("OK"), F("ok"));
  }

  void serve_once(const char *request)
  {
    const int client = testnet::connect_loopback(kPort);
    TEST_ASSERT_GREATER_OR_EQUAL(0, client);
    testnet::send_all(client, request);
    ::shutdown(client, SHUT_WR);
    g_server->poll();
    testnet::recv_all(client);
    ::close(client);
  }
} // namespace

// Handlers can read request headers by case-insensitive name.
void test_request_header_returns_sent_value()
{
  g_server->on("/h", echo_headers_handler);
  serve_once("POST /h HTTP/1.1\r\nHost: 192.168.1.1\r\n"
             "Origin: https://evil.example\r\nContent-Length: 0\r\n\r\n");
  TEST_ASSERT_FALSE(g_origin_was_null);
  TEST_ASSERT_EQUAL_STRING("https://evil.example", g_seen_origin.c_str());
  TEST_ASSERT_EQUAL_STRING("192.168.1.1", g_seen_host.c_str());
}

void test_request_header_absent_is_null()
{
  g_server->on("/h", echo_headers_handler);
  serve_once("POST /h HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
  TEST_ASSERT_TRUE(g_origin_was_null);
}

void test_request_header_outside_handler_is_null()
{
  TEST_ASSERT_NULL(quarkx::request_header("Host"));
  serve_once("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
  TEST_ASSERT_NULL(quarkx::request_header("Host"));
}

int main()
{
  std::signal(SIGPIPE, SIG_IGN);
  UNITY_BEGIN();
  RUN_TEST(test_serves_a_simple_request);
  RUN_TEST(test_silent_client_does_not_block_poll);
  RUN_TEST(test_client_stalling_mid_headers_does_not_block_poll);
  RUN_TEST(test_next_client_served_after_silent_one);
  RUN_TEST(test_client_not_reading_response_does_not_block_poll);
  RUN_TEST(test_request_header_returns_sent_value);
  RUN_TEST(test_request_header_absent_is_null);
  RUN_TEST(test_request_header_outside_handler_is_null);
  return UNITY_END();
}
