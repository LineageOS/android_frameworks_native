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

#include "InputTracingPerfettoBackendConfig.h"

#include <android/content/pm/IPackageManagerNative.h>
#include <ftl/flags.h>
#include <perfetto/tracing.h>
#include <mutex>
#include <set>

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
    static bool sUseInProcessBackendForTest;
    static std::function<sp<content::pm::IPackageManagerNative>()> sPackageManagerProvider;

    explicit PerfettoBackend();
    ~PerfettoBackend() override = default;

    void traceKeyEvent(const TracedKeyEvent&, const TracedEventMetadata&) override;
    void traceMotionEvent(const TracedMotionEvent&, const TracedEventMetadata&) override;
    void traceWindowDispatch(const WindowDispatchArgs&, const TracedEventMetadata&) override;

private:
    // Implementation of the perfetto data source.
    // Each instance of the InputEventDataSource represents a different tracing session.
    // Its lifecycle is controlled by perfetto.
    class InputEventDataSource : public perfetto::DataSource<InputEventDataSource> {
    public:
        explicit InputEventDataSource();

        void OnSetup(const SetupArgs&) override;
        void OnStart(const StartArgs&) override;
        void OnStop(const StopArgs&) override;

        void initializeUidMap();
        bool shouldIgnoreTracedInputEvent(const EventType&) const;
        inline ftl::Flags<TraceFlag> getFlags() const { return mConfig.flags; }
        TraceLevel resolveTraceLevel(const TracedEventMetadata&) const;

    private:
        const int32_t mInstanceId;
        TraceConfig mConfig;

        bool ruleMatches(const TraceRule&, const TracedEventMetadata&) const;

        std::optional<std::map<std::string, gui::Uid>> mUidMap;
    };

    static std::once_flag sDataSourceRegistrationFlag;
    static std::atomic<int32_t> sNextInstanceId;
};

} // namespace android::inputdispatcher::trace::impl
