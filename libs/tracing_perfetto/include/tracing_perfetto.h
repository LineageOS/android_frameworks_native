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

#ifndef TRACING_PERFETTO_H
#define TRACING_PERFETTO_H

#include <stdint.h>

#include "trace_result.h"

namespace tracing_perfetto {

void registerWithPerfetto(bool test = false);

Result traceBegin(uint64_t category, const char* name);

Result traceEnd(uint64_t category);

Result traceAsyncBegin(uint64_t category, const char* name, int32_t cookie);

Result traceAsyncEnd(uint64_t category, const char* name, int32_t cookie);

Result traceAsyncBeginForTrack(uint64_t category, const char* name,
                               const char* trackName, int32_t cookie);

Result traceAsyncEndForTrack(uint64_t category, const char* trackName,
                             int32_t cookie);

Result traceInstant(uint64_t category, const char* name);

Result traceInstantForTrack(uint64_t category, const char* trackName,
                            const char* name);

Result traceCounter(uint64_t category, const char* name, int64_t value);

uint64_t getEnabledCategories();

}  // namespace tracing_perfetto

#endif  // TRACING_PERFETTO_H
