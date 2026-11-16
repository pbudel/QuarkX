#include <QuarkX_Sni.h>
#include <unity.h>

#include <cstring>

namespace
{
  bool is_hostname(const char *name)
  {
    return quarkx::detail::sni_is_hostname(
        reinterpret_cast<const unsigned char *>(name), std::strlen(name));
  }
} // namespace

void setUp() {}
void tearDown() {}

void test_domain_name_is_hostname()
{
  TEST_ASSERT_TRUE(is_hostname("connectivitycheck.gstatic.com"));
}

void test_uppercase_domain_name_is_hostname()
{
  TEST_ASSERT_TRUE(is_hostname("WWW.Example.COM"));
}

void test_single_character_name_is_hostname()
{
  TEST_ASSERT_TRUE(is_hostname("a"));
}

void test_ipv4_literal_is_not_hostname()
{
  TEST_ASSERT_FALSE(is_hostname("192.168.1.1"));
  TEST_ASSERT_FALSE(is_hostname("0.0.0.0"));
  TEST_ASSERT_FALSE(is_hostname("255.255.255.255"));
}

void test_out_of_range_octet_is_hostname()
{
  TEST_ASSERT_TRUE(is_hostname("256.1.1.1"));
}

void test_three_octets_is_hostname()
{
  TEST_ASSERT_TRUE(is_hostname("1.2.3"));
}

void test_five_octets_is_hostname()
{
  TEST_ASSERT_TRUE(is_hostname("1.2.3.4.5"));
}

void test_empty_octet_is_hostname()
{
  TEST_ASSERT_TRUE(is_hostname("1..2.3"));
  TEST_ASSERT_TRUE(is_hostname("1.2.3."));
}

void test_overlong_octet_is_hostname()
{
  TEST_ASSERT_TRUE(is_hostname("0001.2.3.4"));
}

void test_length_bounds_the_name()
{
  // Only the first `len` bytes count: "10.0.0.1" followed by junk.
  const char name[] = "10.0.0.1.example";
  TEST_ASSERT_FALSE(quarkx::detail::sni_is_hostname(
      reinterpret_cast<const unsigned char *>(name), 8));
}

void test_empty_string_is_not_hostname()
{
  TEST_ASSERT_FALSE(is_hostname(""));
}

void test_null_name_is_not_hostname()
{
  TEST_ASSERT_FALSE(quarkx::detail::sni_is_hostname(nullptr, 0));
  TEST_ASSERT_FALSE(quarkx::detail::sni_is_hostname(nullptr, 5));
}

int main(int, char **)
{
  UNITY_BEGIN();
  RUN_TEST(test_domain_name_is_hostname);
  RUN_TEST(test_uppercase_domain_name_is_hostname);
  RUN_TEST(test_single_character_name_is_hostname);
  RUN_TEST(test_ipv4_literal_is_not_hostname);
  RUN_TEST(test_out_of_range_octet_is_hostname);
  RUN_TEST(test_three_octets_is_hostname);
  RUN_TEST(test_five_octets_is_hostname);
  RUN_TEST(test_empty_octet_is_hostname);
  RUN_TEST(test_overlong_octet_is_hostname);
  RUN_TEST(test_length_bounds_the_name);
  RUN_TEST(test_empty_string_is_not_hostname);
  RUN_TEST(test_null_name_is_not_hostname);
  return UNITY_END();
}
