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

#ifndef TRACING_PERFETTO_INTERNAL_H
#define TRACING_PERFETTO_INTERNAL_H

#include <stdint.h>

#include "include/trace_result.h"
#include "perfetto/public/te_category_macros.h"

namespace tracing_perfetto {

namespace internal {

bool isPerfettoSdkTracingEnabled();

struct PerfettoTeCategory* toPerfettoCategory(uint64_t category);

void registerWithPerfetto(bool test = false);

Result perfettoTraceBegin(const struct PerfettoTeCategory& category, const char* name);

Result perfettoTraceEnd(const struct PerfettoTeCategory& category);

Result perfettoTraceAsyncBegin(const struct PerfettoTeCategory& category, const char* name,
                               uint64_t cookie);

Result perfettoTraceAsyncEnd(const struct PerfettoTeCategory& category, const char* name,
                             uint64_t cookie);

Result perfettoTraceAsyncBeginForTrack(const struct PerfettoTeCategory& category, const char* name,
                                       const char* trackName, uint64_t cookie);

Result perfettoTraceAsyncEndForTrack(const struct PerfettoTeCategory& category,
                                     const char* trackName, uint64_t cookie);

Result perfettoTraceInstant(const struct PerfettoTeCategory& category, const char* name);

Result perfettoTraceInstantForTrack(const struct PerfettoTeCategory& category,
                                    const char* trackName, const char* name);

Result perfettoTraceCounter(const struct PerfettoTeCategory& category, const char* name,
                            int64_t value);

uint64_t getDefaultCategories();

}  // namespace internal

}  // namespace tracing_perfetto

#endif  // TRACING_PERFETTO_INTERNAL_H
