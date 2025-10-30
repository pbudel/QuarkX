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

#include "QuarkX_Headers.h"

#include <Arduino.h>

#include <cctype>
#include <cstring>
#include <errno.h>
#include <sys/socket.h>

namespace quarkx {
namespace {

constexpr std::size_t kLineCapacity = QUARKX_HDR_LINE_MAX;

inline bool is_space(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\f' || c == '\v' || c == '\r';
}

void clear_table(HeaderTable &ht) {
  std::memset(&ht, 0, sizeof(ht));
}

bool extract_tokens(const char *line, char *name_out, char *value_out) {
  const char *colon = std::strchr(line, ':');
  if (!colon) {
    return false;
  }

  const char *name_begin = line;
  while (name_begin < colon && is_space(static_cast<unsigned char>(*name_begin))) {
    ++name_begin;
  }

  const char *name_end = colon;
  while (name_end > name_begin &&
         is_space(static_cast<unsigned char>(*(name_end - 1)))) {
    --name_end;
  }

  const std::size_t name_len = static_cast<std::size_t>(name_end - name_begin);
  if (name_len == 0 || name_len >= QUARKX_HDR_NAME_MAX) {
    return false;
  }

  const char *value_begin = colon + 1;
  while (*value_begin && is_space(static_cast<unsigned char>(*value_begin))) {
    ++value_begin;
  }

  const char *value_end = value_begin + std::strlen(value_begin);
  while (value_end > value_begin &&
         is_space(static_cast<unsigned char>(*(value_end - 1)))) {
    --value_end;
  }

  const std::size_t value_len = static_cast<std::size_t>(value_end - value_begin);
  if (value_len >= QUARKX_HDR_VALUE_MAX) {
    return false;
  }

  std::memcpy(name_out, name_begin, name_len);
  name_out[name_len] = '\0';

  for (std::size_t i = 0; i < name_len; ++i) {
    name_out[i] = static_cast<char>(
        std::tolower(static_cast<unsigned char>(name_out[i])));
  }

  if (value_len > 0) {
    std::memcpy(value_out, value_begin, value_len);
  }
  value_out[value_len] = '\0';

  return true;
}

bool add_header(HeaderTable &ht, const char *line) {
  if (!line || line[0] == '\0') {
    return true;
  }

  if (!std::strchr(line, ':')) {
    Serial.print(F("[D] skip header line: "));
    Serial.println(line);
    return true;
  }

  if (ht.count >= QUARKX_HEADER_MAX_COUNT) {
    Serial.println(F("[E] header table full"));
    return false;
  }

  Header &slot = ht.items[ht.count];
  if (!extract_tokens(line, slot.name, slot.value)) {
    Serial.print(F("[E] header token parse failed: "));
    Serial.println(line);
    return false;
  }

  ++ht.count;
  return true;
}

}  // namespace

bool parse_headers(HeaderRecvFn reader, void *ctx, HeaderTable &ht) {
  clear_table(ht);

  char line[kLineCapacity];
  std::size_t line_len = 0;
  bool pending_cr = false;

  while (true) {
    char ch = 0;
    const int r = reader(ctx, reinterpret_cast<uint8_t *>(&ch), 1);
    if (r == 0) {
      return false;
    }
    if (r < 0) {
      return false;
    }

    if (ch == '\r') {
      pending_cr = true;
      continue;
    }

    if (ch == '\n') {
      if (line_len == 0) {
        return true;
      }

      line[line_len] = '\0';

      bool whitespace_only = true;
      for (std::size_t i = 0; i < line_len; ++i) {
        if (!is_space(static_cast<unsigned char>(line[i]))) {
          whitespace_only = false;
          break;
        }
      }
      if (whitespace_only) {
        return true;
      }

      if (!add_header(ht, line)) {
        return false;
      }

      line_len = 0;
      pending_cr = false;
      continue;
    }

    if (pending_cr) {
      if (line_len >= kLineCapacity - 1) {
        return false;
      }
      line[line_len++] = '\r';
      pending_cr = false;
    }

    if (line_len >= kLineCapacity - 1) {
      return false;
    }

    line[line_len++] = ch;
  }
}

}  // namespace quarkx

const char *quarkx::get_header(const HeaderTable &ht, const char *name) {
  if (!name) {
    return nullptr;
  }

  char lookup[QUARKX_HDR_NAME_MAX];
  std::size_t idx = 0;
  while (name[idx] && idx < QUARKX_HDR_NAME_MAX - 1) {
    lookup[idx] = static_cast<char>(std::tolower(static_cast<unsigned char>(name[idx])));
    ++idx;
  }

  if (name[idx] != '\0') {
    return nullptr;
  }

  lookup[idx] = '\0';

  for (std::size_t i = 0; i < ht.count; ++i) {
    if (std::strcmp(ht.items[i].name, lookup) == 0) {
      return ht.items[i].value;
    }
  }

  return nullptr;
}
