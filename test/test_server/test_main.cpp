#include <QuarkX.h>
#include <unity.h>

#include <csignal>

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

int main()
{
  std::signal(SIGPIPE, SIG_IGN);
  UNITY_BEGIN();
  RUN_TEST(test_serves_a_simple_request);
  return UNITY_END();
}
