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

#pragma once

#include <ftl/enum.h>
#include <ftl/flags.h>
#include <perfetto/config/android/android_input_event_config.pbzero.h>
#include <vector>

namespace android::inputdispatcher::trace::impl {

/** Flags representing the configurations that are enabled in the trace. */
enum class TraceFlag : uint32_t {
    // Trace details about input events processed by InputDispatcher.
    TRACE_DISPATCHER_INPUT_EVENTS = 0x1,
    // Trace details about an event being sent to a window by InputDispatcher.
    TRACE_DISPATCHER_WINDOW_DISPATCH = 0x2,

    ftl_last = TRACE_DISPATCHER_WINDOW_DISPATCH,
};

/** Representation of AndroidInputEventConfig::TraceLevel. */
using TraceLevel = perfetto::protos::pbzero::AndroidInputEventConfig::TraceLevel;

/** Representation of AndroidInputEventConfig::TraceRule. */
struct TraceRule {
    TraceLevel level;

    std::vector<std::string> matchAllPackages;
    std::vector<std::string> matchAnyPackages;
    std::optional<bool> matchSecure;
    std::optional<bool> matchImeConnectionActive;
};

/**
 * A complete configuration for a tracing session.
 *
 * The trace rules are applied as documented in the perfetto config:
 *   /external/perfetto/protos/perfetto/config/android/android_input_event_config.proto
 */
struct TraceConfig {
    ftl::Flags<TraceFlag> flags;
    std::vector<TraceRule> rules;
};

} // namespace android::inputdispatcher::trace::impl
