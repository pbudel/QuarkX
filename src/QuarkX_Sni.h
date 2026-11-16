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

#ifndef QUARKX_SNI_H
#define QUARKX_SNI_H

#include <cstddef>

namespace quarkx
{
  namespace detail
  {
    /**
     * @brief Whether a TLS SNI value names a host rather than an address.
     *
     * Clients that reach a server by IP address send no SNI (RFC 6066 forbids
     * IP literals there). A few non-conforming clients still send a dotted
     * IPv4 literal, which is not treated as a hostname.
     *
     * @param name SNI bytes as received (not NUL-terminated).
     * @param len Number of bytes in @p name.
     * @return true for a host name; false for no name or an IPv4 literal.
     */
    bool sni_is_hostname(const unsigned char *name, std::size_t len);
  } // namespace detail
} // namespace quarkx

#endif // QUARKX_SNI_H
