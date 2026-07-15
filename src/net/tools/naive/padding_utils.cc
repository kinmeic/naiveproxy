// Copyright 2020 klzgrad <kizdiv@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/tools/naive/padding_utils.h"

#include <array>

#include "base/check.h"
#include "base/containers/span.h"
#include "net/third_party/quiche/src/quiche/http2/hpack/hpack_constants.h"

namespace net {
namespace {
const std::array<uint8_t, 17>& GetNonindexCodes() {
  static const std::array<uint8_t, 17> codes = [] {
    std::array<uint8_t, 17> result;
    size_t i = 0;
    for (const auto& symbol : spdy::HpackHuffmanCodeVector()) {
      if (symbol.id >= 0x20 && symbol.id <= 0x7f && symbol.length >= 8) {
        if (i >= result.size()) {
          break;
        }
        result[i] = symbol.id;
        ++i;
      }
    }
    CHECK(i == result.size());
    return result;
  }();
  return codes;
}
}  // namespace

void InitializeNonindexCodes() {
  (void)GetNonindexCodes();
}

void FillNonindexHeaderValue(uint64_t unique_bits, base::span<uint8_t> span) {
  const std::array<uint8_t, 17>& nonindex_codes = GetNonindexCodes();
  int first = span.size() < 16 ? span.size() : 16;
  for (int i = 0; i < first; i++) {
    span[i] = nonindex_codes[unique_bits & 0b1111];
    unique_bits >>= 4;
  }
  for (size_t i = first; i < span.size(); ++i) {
    span[i] = nonindex_codes[16];
  }
}
}  // namespace net
