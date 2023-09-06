/*
 * Copyright 2023 The Android Open Source Project
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

#include <utils/Trace.h>
#include <optional>

// A macro for tracing when the given condition is true.
// This macro relies on the fact that only one branch of the ternary operator is evaluated. That
// means if `message` is an expression that evaluates to a std::string value, the value will
// not be computed unless the condition is true.
#define ATRACE_NAME_IF(condition, message)                                            \
    const auto _trace_token = condition                                               \
            ? std::make_optional<android::ScopedTrace>(ATRACE_TAG, (message).c_str()) \
            : std::nullopt
