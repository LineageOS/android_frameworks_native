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

#define LOG_TAG "InputTracer"

#include "InputTracingPerfettoBackend.h"

#include "AndroidInputEventProtoConverter.h"

#include <android-base/logging.h>
#include <perfetto/trace/android/android_input_event.pbzero.h>

namespace android::inputdispatcher::trace::impl {

namespace {

constexpr auto INPUT_EVENT_TRACE_DATA_SOURCE_NAME = "android.input.inputevent";

} // namespace

// --- PerfettoBackend::InputEventDataSource ---

void PerfettoBackend::InputEventDataSource::OnStart(const perfetto::DataSourceBase::StartArgs&) {
    LOG(INFO) << "Starting perfetto trace for: " << INPUT_EVENT_TRACE_DATA_SOURCE_NAME;
}

void PerfettoBackend::InputEventDataSource::OnStop(const perfetto::DataSourceBase::StopArgs&) {
    LOG(INFO) << "Stopping perfetto trace for: " << INPUT_EVENT_TRACE_DATA_SOURCE_NAME;
    InputEventDataSource::Trace([&](InputEventDataSource::TraceContext ctx) { ctx.Flush(); });
}

// --- PerfettoBackend ---

std::once_flag PerfettoBackend::sDataSourceRegistrationFlag{};

PerfettoBackend::PerfettoBackend() {
    // Use a once-flag to ensure that the data source is only registered once per boot, since
    // we never unregister the InputEventDataSource.
    std::call_once(sDataSourceRegistrationFlag, []() {
        perfetto::TracingInitArgs args;
        args.backends = perfetto::kSystemBackend;
        perfetto::Tracing::Initialize(args);

        // Register our custom data source for input event tracing.
        perfetto::DataSourceDescriptor dsd;
        dsd.set_name(INPUT_EVENT_TRACE_DATA_SOURCE_NAME);
        InputEventDataSource::Register(dsd);
        LOG(INFO) << "InputTracer initialized for data source: "
                  << INPUT_EVENT_TRACE_DATA_SOURCE_NAME;
    });
}

void PerfettoBackend::traceMotionEvent(const TracedMotionEvent& event) {
    InputEventDataSource::Trace([&](InputEventDataSource::TraceContext ctx) {
        auto tracePacket = ctx.NewTracePacket();
        auto* inputEvent = tracePacket->set_android_input_event();
        auto* dispatchMotion = inputEvent->set_dispatcher_motion_event();
        AndroidInputEventProtoConverter::toProtoMotionEvent(event, *dispatchMotion);
    });
}

void PerfettoBackend::traceKeyEvent(const TracedKeyEvent& event) {
    InputEventDataSource::Trace([&](InputEventDataSource::TraceContext ctx) {
        auto tracePacket = ctx.NewTracePacket();
        auto* inputEvent = tracePacket->set_android_input_event();
        auto* dispatchKey = inputEvent->set_dispatcher_key_event();
        AndroidInputEventProtoConverter::toProtoKeyEvent(event, *dispatchKey);
    });
}

void PerfettoBackend::traceWindowDispatch(const WindowDispatchArgs& dispatchArgs) {
    InputEventDataSource::Trace([&](InputEventDataSource::TraceContext ctx) {
        auto tracePacket = ctx.NewTracePacket();
        auto* inputEventProto = tracePacket->set_android_input_event();
        auto* dispatchEventProto = inputEventProto->set_dispatcher_window_dispatch_event();
        AndroidInputEventProtoConverter::toProtoWindowDispatchEvent(dispatchArgs,
                                                                    *dispatchEventProto);
    });
}

} // namespace android::inputdispatcher::trace::impl
