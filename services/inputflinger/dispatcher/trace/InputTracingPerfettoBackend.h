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
    using GetPackageUid = std::function<gui::Uid(std::string)>;

    explicit PerfettoBackend(GetPackageUid);
    ~PerfettoBackend() override = default;

    void traceKeyEvent(const TracedKeyEvent&, const TracedEventArgs&) override;
    void traceMotionEvent(const TracedMotionEvent&, const TracedEventArgs&) override;
    void traceWindowDispatch(const WindowDispatchArgs&, const TracedEventArgs&) override;

private:
    // Implementation of the perfetto data source.
    // Each instance of the InputEventDataSource represents a different tracing session.
    class InputEventDataSource : public perfetto::DataSource<InputEventDataSource> {
    public:
        explicit InputEventDataSource();

        void OnSetup(const SetupArgs&) override;
        void OnStart(const StartArgs&) override;
        void OnStop(const StopArgs&) override;

        void initializeUidMap(GetPackageUid);
        bool shouldIgnoreTracedInputEvent(const EventType&) const;
        inline ftl::Flags<TraceFlag> getFlags() const { return mConfig.flags; }
        TraceLevel resolveTraceLevel(const TracedEventArgs&) const;

    private:
        const int32_t mInstanceId;
        TraceConfig mConfig;

        bool ruleMatches(const TraceRule&, const TracedEventArgs&) const;

        std::optional<std::map<std::string, gui::Uid>> mUidMap;
    };

    // TODO(b/330360505): Query the native package manager directly from the data source,
    //   and remove this.
    GetPackageUid mGetPackageUid;

    static std::once_flag sDataSourceRegistrationFlag;
    static std::atomic<int32_t> sNextInstanceId;
};

} // namespace android::inputdispatcher::trace::impl
