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

#include "FakeWindows.h"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <perfetto/config/android/android_input_event_config.pbzero.h>
#include <perfetto/trace/trace.pbzero.h>
#include <perfetto/tracing.h>
#include <variant>
#include <vector>

namespace android {

/**
 * Tracing level constants used for adding expectations to the InputTraceSession.
 */
enum class Level {
    NONE,
    REDACTED,
    COMPLETE,
};

template <typename K, typename V>
using ArrayMap = std::vector<std::pair<K, V>>;

/**
 * A scoped representation of a tracing session that is used to make assertions on the trace.
 *
 * When the trace session is created, an "android.input.inputevent" trace will be started
 * synchronously with the given configuration. While the trace is ongoing, the caller must
 * specify the events that are expected to be in the trace using the expect* methods.
 *
 * When the session is destroyed, the trace is stopped synchronously, and all expectations will
 * be verified using the gtest framework. This acts as a strict verifier, where the verification
 * will fail both if an expected event does not show up in the trace and if there is an extra
 * event in the trace that was not expected. Ordering is NOT verified for any events.
 */
class InputTraceSession {
public:
    explicit InputTraceSession(
            std::function<void(
                    protozero::HeapBuffered<perfetto::protos::pbzero::AndroidInputEventConfig>&)>
                    configure);

    ~InputTraceSession();

    void expectMotionTraced(Level level, const MotionEvent& event);

    void expectKeyTraced(Level level, const KeyEvent& event);

    struct WindowDispatchEvent {
        std::variant<KeyEvent, MotionEvent> event;
        sp<FakeWindowHandle> window;
    };
    void expectDispatchTraced(Level level, const WindowDispatchEvent& event);

private:
    std::unique_ptr<perfetto::TracingSession> mPerfettoSession;
    ArrayMap<WindowDispatchEvent, Level> mExpectedWindowDispatches;
    ArrayMap<MotionEvent, Level> mExpectedMotions;
    ArrayMap<KeyEvent, Level> mExpectedKeys;

    void verifyExpectations(const std::string& rawTrace);
};

} // namespace android
