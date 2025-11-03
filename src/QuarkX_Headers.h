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

#ifndef QUARKX_HEADERS_H
#define QUARKX_HEADERS_H

#include <cstddef>
#include <cstdint>

namespace quarkx
{

#ifndef QUARKX_HDR_LINE_MAX
#define QUARKX_HDR_LINE_MAX 512
#endif

#ifndef QUARKX_HDR_TIMEOUT_MS
#define QUARKX_HDR_TIMEOUT_MS 4000
#endif

#ifndef QUARKX_HDR_NAME_MAX
#define QUARKX_HDR_NAME_MAX 48
#endif

#ifndef QUARKX_HDR_VALUE_MAX
#define QUARKX_HDR_VALUE_MAX 210
#endif

#ifndef QUARKX_HEADER_MAX_COUNT
#define QUARKX_HEADER_MAX_COUNT 16
#endif

  struct Header
  {
    char name[QUARKX_HDR_NAME_MAX];
    char value[QUARKX_HDR_VALUE_MAX];
  };

  struct HeaderTable
  {
    Header items[QUARKX_HEADER_MAX_COUNT];
    std::size_t count;
  };

  using HeaderRecvFn = int (*)(void *ctx, uint8_t *buf, std::size_t len);

  /**
   * @brief Parse HTTP header fields using the provided reader callback.
   * @param reader Function used to pull bytes from the underlying transport.
   * @param ctx Opaque context passed to the reader.
   * @param ht Table to populate; any previous contents are cleared.
   * @return true on success, false on overflow or socket failure.
   */
  bool parse_headers(HeaderRecvFn reader, void *ctx, HeaderTable &ht);

  /**
   * @brief Retrieve a header value by case-insensitive name.
   * @param ht Header table to search.
   * @param name Header name (ASCII).
   * @return Pointer to the stored value, or nullptr if not found/too long.
   */
  const char *get_header(const HeaderTable &ht, const char *name);

} // namespace quarkx

#endif // QUARKX_HEADERS_H
