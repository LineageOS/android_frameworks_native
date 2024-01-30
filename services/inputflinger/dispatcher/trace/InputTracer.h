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

#include "InputTracerInterface.h"

#include <android-base/thread_annotations.h>
#include <gui/WindowInfo.h>

#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

#include "../Entry.h"
#include "InputTracingBackendInterface.h"

namespace android::inputdispatcher::trace::impl {

/**
 * The tracer implementation for InputDispatcher.
 *
 * InputTracer is thread-safe, so it can be called from any thread. Upon construction, InputTracer
 * will start its own thread that it uses for write events into the tracing backend. That is the
 * one and only thread that will interact with the tracing backend, since the Perfetto backend
 * uses thread-local storage.
 *
 * See the documentation in InputTracerInterface for the API surface.
 */
class InputTracer : public InputTracerInterface {
public:
    explicit InputTracer(std::unique_ptr<InputTracingBackendInterface>);
    ~InputTracer() override;
    InputTracer(const InputTracer&) = delete;
    InputTracer& operator=(const InputTracer&) = delete;

    std::unique_ptr<EventTrackerInterface> traceInboundEvent(const EventEntry&) override;
    void dispatchToTargetHint(const EventTrackerInterface&, const InputTarget&) override;
    void eventProcessingComplete(const EventTrackerInterface&) override;
    void traceEventDispatch(const DispatchEntry&, const EventTrackerInterface*) override;

private:
    std::mutex mLock;
    std::thread mTracerThread;
    bool mThreadExit GUARDED_BY(mLock){false};
    std::condition_variable mThreadWakeCondition;
    std::unique_ptr<InputTracingBackendInterface> mBackend;

    // The state of a tracked event.
    struct EventState {
        const TracedEvent event;
        // TODO(b/210460522): Add additional args for tracking event sensitivity and
        //  dispatch target UIDs.
    };
    std::vector<const EventState> mTraceQueue GUARDED_BY(mLock);
    using WindowDispatchArgs = InputTracingBackendInterface::WindowDispatchArgs;
    std::vector<const WindowDispatchArgs> mDispatchTraceQueue GUARDED_BY(mLock);

    // Provides thread-safe access to the state from an event tracker cookie.
    std::optional<EventState>& getState(const EventTrackerInterface&) REQUIRES(mLock);

    // Implementation of the event tracker cookie.
    class EventTrackerImpl : public EventTrackerInterface {
    public:
        explicit EventTrackerImpl(InputTracer&, TracedEvent&& entry);
        virtual ~EventTrackerImpl() override;

    private:
        InputTracer& mTracer;
        // This event tracker cookie will only hold the state as long as it has not been written
        // to the trace. The state is released when the event is written to the trace.
        mutable std::optional<EventState> mLockedState;

        // Only allow InputTracer access to the locked state through getTrackerState() to ensure
        // that the InputTracer lock is held when this is accessed.
        friend std::optional<EventState>& InputTracer::getState(const EventTrackerInterface&);
    };

    void threadLoop();
    void writeEventsToBackend(const std::vector<const EventState>& events,
                              const std::vector<const WindowDispatchArgs>& dispatchEvents);
};

} // namespace android::inputdispatcher::trace::impl
