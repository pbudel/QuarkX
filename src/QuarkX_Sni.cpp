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

#include "QuarkX_Sni.h"

namespace quarkx
{
  namespace detail
  {
    namespace
    {
      // Strict dotted-quad: four decimal octets of 1-3 digits, each <= 255.
      bool is_ipv4_literal(const unsigned char *name, std::size_t len)
      {
        unsigned octets = 0;
        unsigned digits = 0;
        unsigned value = 0;
        for (std::size_t i = 0; i < len; ++i)
        {
          const unsigned char c = name[i];
          if (c >= '0' && c <= '9')
          {
            if (++digits > 3)
            {
              return false;
            }
            value = value * 10 + static_cast<unsigned>(c - '0');
            if (value > 255)
            {
              return false;
            }
          }
          else if (c == '.')
          {
            if (digits == 0 || ++octets > 3)
            {
              return false;
            }
            digits = 0;
            value = 0;
          }
          else
          {
            return false;
          }
        }
        return octets == 3 && digits > 0;
      }
    } // namespace

    bool sni_is_hostname(const unsigned char *name, std::size_t len)
    {
      if (name == nullptr || len == 0)
      {
        return false;
      }
      return !is_ipv4_literal(name, len);
    }
  } // namespace detail
} // namespace quarkx
