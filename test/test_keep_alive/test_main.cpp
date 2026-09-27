#include <QuarkX.h>
#include <unity.h>

#include <csignal>

#include "test_net.h"

namespace
{
  constexpr uint16_t kPort = 18082;

  quarkx::Server *g_server = nullptr;
  int g_calls = 0;

  void basic_handler(Stream &out, const String &, const String &)
  {
    ++g_calls;
    quarkx::send_basic_response(out, 200, F("OK"), F("hello"));
  }

  // A handler writing its own response, as many applications do.
  void custom_close_handler(Stream &out, const String &, const String &)
  {
    ++g_calls;
    out.print(F("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                "Connection: close\r\n\r\nok"));
  }

  unsigned long timed_poll()
  {
    const unsigned long start = millis();
    g_server->poll();
    return millis() - start;
  }

  size_t count(const std::string &haystack, const char *needle)
  {
    size_t n = 0;
    for (size_t pos = haystack.find(needle); pos != std::string::npos;
         pos = haystack.find(needle, pos + 1))
    {
      ++n;
    }
    return n;
  }
} // namespace

void setUp()
{
  g_calls = 0;
  g_server = new quarkx::Server(kPort, false);
  g_server->on("/", basic_handler);
  g_server->on("/custom", custom_close_handler);
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

// When the handler answers with its own `Connection: close`, the server
// must close right away instead of waiting for another request.
void test_custom_close_response_closes_immediately()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client,
                    "GET /custom HTTP/1.1\r\nConnection: keep-alive\r\n\r\n");

  const unsigned long elapsed = timed_poll();
  const std::string resp = testnet::recv_all(client, 100);
  ::close(client);

  TEST_ASSERT_EQUAL_INT(1, g_calls);
  TEST_ASSERT_NOT_EQUAL(std::string::npos, resp.find("\r\n\r\nok"));
  TEST_ASSERT_LESS_THAN_UINT32(QUARKX_RECV_TIMEOUT_MS / 2, elapsed);
}

// Pipelined requests on a keep-alive connection are all served.
void test_keep_alive_serves_following_requests()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client,
                    "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n"
                    "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n");
  ::shutdown(client, SHUT_WR);

  g_server->poll();
  const std::string resp = testnet::recv_all(client);
  ::close(client);

  TEST_ASSERT_EQUAL_INT(2, g_calls);
  TEST_ASSERT_EQUAL_UINT32(2, count(resp, "HTTP/1.1 200 OK\r\n"));
}

// `Connection` may carry a token list.
void test_keep_alive_token_in_list_is_honoured()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client,
                    "GET / HTTP/1.1\r\nConnection: Upgrade, Keep-Alive\r\n\r\n");
  ::shutdown(client, SHUT_WR);

  g_server->poll();
  const std::string resp = testnet::recv_all(client);
  ::close(client);

  TEST_ASSERT_NOT_EQUAL(std::string::npos,
                        resp.find("Connection: keep-alive\r\n"));
}

// `close` wins over `keep-alive`.
void test_close_token_wins()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client,
                    "GET / HTTP/1.1\r\nConnection: keep-alive, close\r\n\r\n");

  const unsigned long elapsed = timed_poll();
  const std::string resp = testnet::recv_all(client, 100);
  ::close(client);

  TEST_ASSERT_NOT_EQUAL(std::string::npos, resp.find("Connection: close\r\n"));
  TEST_ASSERT_LESS_THAN_UINT32(QUARKX_RECV_TIMEOUT_MS / 2, elapsed);
}

// Without a `Connection` header the server closes after the response.
void test_missing_connection_header_closes()
{
  const int client = testnet::connect_loopback(kPort);
  testnet::send_all(client, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");

  const unsigned long elapsed = timed_poll();
  const std::string resp = testnet::recv_all(client, 100);
  ::close(client);

  TEST_ASSERT_NOT_EQUAL(std::string::npos, resp.find("Connection: close\r\n"));
  TEST_ASSERT_LESS_THAN_UINT32(QUARKX_RECV_TIMEOUT_MS / 2, elapsed);
}

int main()
{
  std::signal(SIGPIPE, SIG_IGN);
  UNITY_BEGIN();
  RUN_TEST(test_custom_close_response_closes_immediately);
  RUN_TEST(test_keep_alive_serves_following_requests);
  RUN_TEST(test_keep_alive_token_in_list_is_honoured);
  RUN_TEST(test_close_token_wins);
  RUN_TEST(test_missing_connection_header_closes);
  return UNITY_END();
}
