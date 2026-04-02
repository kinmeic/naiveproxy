// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_
#define BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_

#include <string_view>

namespace trace_event_metrics {

// NaiveProxy ships a minimized Chromium tree without the histogram metadata
// generator that normally produces this header. Accept all provider names here
// so the tracing API remains usable in trimmed builds.
consteval bool IsValidMemoryDumpProviderName(std::string_view) {
  return true;
}

}  // namespace trace_event_metrics

#endif  // BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_
