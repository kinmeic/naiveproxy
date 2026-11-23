// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_JSON_JSON_COMMON_H_
#define BASE_JSON_JSON_COMMON_H_

#include <stddef.h>

#include "base/check_op.h"
#include "base/memory/raw_ptr.h"

namespace base::json_internal {

// Chosen to support 99.9% of documents found in the wild late 2016.
// http://crbug.com/673263
// LINT.IfChange
inline constexpr size_t kAbsoluteMaxDepth = 200;
// LINT.ThenChange(//third_party/rust/serde_json_lenient/v0_2/wrapper/visitor.rs)

}  // namespace base::json_internal

namespace base::internal {

inline constexpr size_t kAbsoluteMaxDepth = json_internal::kAbsoluteMaxDepth;

class StackMarker {
 public:
  StackMarker(size_t max_depth, size_t* depth)
      : max_depth_(max_depth), depth_(depth) {
    ++(*depth_);
    DCHECK_LE(*depth_, max_depth_);
  }

  StackMarker(const StackMarker&) = delete;
  StackMarker& operator=(const StackMarker&) = delete;

  ~StackMarker() { --(*depth_); }

  bool IsTooDeep() const { return *depth_ >= max_depth_; }

 private:
  const size_t max_depth_;
  const raw_ptr<size_t> depth_;
};

}  // namespace base::internal

#endif  // BASE_JSON_JSON_COMMON_H_
