// Minimal host-side stand-in for the Arduino core, used only by the native
// unit tests. It implements just the subset of the API that QuarkX touches.
#ifndef QUARKX_TEST_ARDUINO_SHIM_H
#define QUARKX_TEST_ARDUINO_SHIM_H

#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

class __FlashStringHelper;
#define F(s) (reinterpret_cast<const __FlashStringHelper *>(s))

inline unsigned long millis()
{
  using namespace std::chrono;
  static const auto start = steady_clock::now();
  return static_cast<unsigned long>(
      duration_cast<milliseconds>(steady_clock::now() - start).count());
}

inline void delay(unsigned long ms)
{
  std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

class String
{
public:
  String() = default;
  String(const char *s) : _s(s ? s : "") {}
  String(const char *s, std::size_t n) : _s(s, n) {}
  String(const __FlashStringHelper *s)
      : _s(reinterpret_cast<const char *>(s)) {}
  String(const std::string &s) : _s(s) {}

  const char *c_str() const { return _s.c_str(); }
  unsigned int length() const { return static_cast<unsigned int>(_s.size()); }
  bool startsWith(const String &p) const { return _s.rfind(p._s, 0) == 0; }
  int indexOf(const char *needle) const
  {
    const auto pos = _s.find(needle);
    return pos == std::string::npos ? -1 : static_cast<int>(pos);
  }

  String &operator+=(const String &o)
  {
    _s += o._s;
    return *this;
  }
  bool operator==(const String &o) const { return _s == o._s; }
  bool operator==(const char *o) const { return _s == o; }
  bool operator!=(const String &o) const { return _s != o._s; }

  const std::string &str() const { return _s; }

private:
  std::string _s;
};

class Print
{
public:
  virtual ~Print() = default;
  virtual std::size_t write(uint8_t b) = 0;
  virtual std::size_t write(const uint8_t *buf, std::size_t n)
  {
    std::size_t total = 0;
    while (n--)
    {
      if (write(*buf++) != 1)
      {
        break;
      }
      ++total;
    }
    return total;
  }

  std::size_t print(const char *s)
  {
    return write(reinterpret_cast<const uint8_t *>(s), std::strlen(s));
  }
  std::size_t print(const __FlashStringHelper *s)
  {
    return print(reinterpret_cast<const char *>(s));
  }
  std::size_t print(const String &s) { return print(s.c_str()); }
  std::size_t print(char c) { return write(static_cast<uint8_t>(c)); }
  std::size_t print(int v) { return print(std::to_string(v).c_str()); }
  std::size_t print(unsigned v) { return print(std::to_string(v).c_str()); }
  std::size_t print(long v) { return print(std::to_string(v).c_str()); }
  std::size_t print(unsigned long v)
  {
    return print(std::to_string(v).c_str());
  }
  template <typename T>
  std::size_t println(const T &v)
  {
    return print(v) + print("\r\n");
  }
  std::size_t printf(const char *fmt, ...)
  {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return n > 0 ? print(buf) : 0;
  }
};

class Stream : public Print
{
public:
  virtual int available() = 0;
  virtual int read() = 0;
  virtual int peek() = 0;
  virtual void flush() = 0;
};

class HostSerial : public Print
{
public:
  std::size_t write(uint8_t b) override
  {
    return std::fputc(b, stderr) == EOF ? 0 : 1;
  }
};

inline HostSerial Serial;

#endif // QUARKX_TEST_ARDUINO_SHIM_H
