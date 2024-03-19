/*
 * Copyright 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tracing_perfetto.h"

#include <cutils/trace.h>

#include "perfetto/public/te_category_macros.h"
#include "trace_categories.h"
#include "tracing_perfetto_internal.h"

namespace tracing_perfetto {

void registerWithPerfetto(bool test) {
  internal::registerWithPerfetto(test);
}

Result traceBegin(uint64_t category, const char* name) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceBegin(*perfettoTeCategory, name);
  } else {
    atrace_begin(category, name);
    return Result::SUCCESS;
  }
}

Result traceEnd(uint64_t category) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceEnd(*perfettoTeCategory);
  } else {
    atrace_end(category);
    return Result::SUCCESS;
  }
}

Result traceAsyncBegin(uint64_t category, const char* name, int32_t cookie) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceAsyncBegin(*perfettoTeCategory, name, cookie);
  } else {
    atrace_async_begin(category, name, cookie);
    return Result::SUCCESS;
  }
}

Result traceAsyncEnd(uint64_t category, const char* name, int32_t cookie) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceAsyncEnd(*perfettoTeCategory, name, cookie);
  } else {
    atrace_async_end(category, name, cookie);
    return Result::SUCCESS;
  }
}

Result traceAsyncBeginForTrack(uint64_t category, const char* name,
                               const char* trackName, int32_t cookie) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceAsyncBeginForTrack(*perfettoTeCategory, name, trackName, cookie);
  } else {
    atrace_async_for_track_begin(category, trackName, name, cookie);
    return Result::SUCCESS;
  }
}

Result traceAsyncEndForTrack(uint64_t category, const char* trackName,
                             int32_t cookie) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceAsyncEndForTrack(*perfettoTeCategory, trackName, cookie);
  } else {
    atrace_async_for_track_end(category, trackName, cookie);
    return Result::SUCCESS;
  }
}

Result traceInstant(uint64_t category, const char* name) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceInstant(*perfettoTeCategory, name);
  } else {
    atrace_instant(category, name);
    return Result::SUCCESS;
  }
}

Result traceInstantForTrack(uint64_t category, const char* trackName,
                            const char* name) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceInstantForTrack(*perfettoTeCategory, trackName, name);
  } else {
    atrace_instant_for_track(category, trackName, name);
    return Result::SUCCESS;
  }
}

Result traceCounter(uint64_t category, const char* name, int64_t value) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return internal::perfettoTraceCounter(*perfettoTeCategory, name, value);
  } else {
    atrace_int64(category, name, value);
    return Result::SUCCESS;
  }
}

bool isTagEnabled(uint64_t category) {
  struct PerfettoTeCategory* perfettoTeCategory =
      internal::toPerfettoCategory(category);
  if (perfettoTeCategory != nullptr) {
    return true;
  } else {
    return (atrace_get_enabled_tags() & category) != 0;
  }
}

}  // namespace tracing_perfetto
