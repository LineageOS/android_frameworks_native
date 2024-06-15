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

#include "InputTracingBackendInterface.h"

#include <perfetto/tracing.h>
#include <mutex>

namespace android::inputdispatcher::trace::impl {

/**
 * The tracing backend that writes events into ongoing Perfetto traces.
 *
 * Example shell command to take an input trace from Perfetto:
 *
 *   adb shell  perfetto \
 *    -c - --txt \
 *    -o /data/misc/perfetto-traces/trace.input-trace \
 *    <<END
 *    buffers: {
 *      size_kb: 5000
 *      fill_policy: RING_BUFFER
 *    }
 *    data_sources: {
 *      config {
 *          name: "android.input.inputevent"
 *      }
 *    }
 *    END
 */
class PerfettoBackend : public InputTracingBackendInterface {
public:
    PerfettoBackend();
    ~PerfettoBackend() override = default;

    void traceKeyEvent(const TracedKeyEvent&) override;
    void traceMotionEvent(const TracedMotionEvent&) override;
    void traceWindowDispatch(const WindowDispatchArgs&) override;

    class InputEventDataSource : public perfetto::DataSource<InputEventDataSource> {
    public:
        void OnSetup(const SetupArgs&) override {}
        void OnStart(const StartArgs&) override;
        void OnStop(const StopArgs&) override;
    };

private:
    static std::once_flag sDataSourceRegistrationFlag;
};

} // namespace android::inputdispatcher::trace::impl
