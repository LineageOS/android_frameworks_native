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

#include <memory>

#include "../Entry.h"
#include "InputTracingBackendInterface.h"

namespace android::inputdispatcher::trace::impl {

/**
 * The tracer implementation for InputDispatcher.
 *
 * InputTracer's responsibility is to keep track of events as they are processed by InputDispatcher,
 * and to write the events to the tracing backend when enough information is collected. InputTracer
 * is not thread-safe.
 *
 * See the documentation in InputTracerInterface for the API surface.
 */
class InputTracer : public InputTracerInterface {
public:
    explicit InputTracer(std::unique_ptr<InputTracingBackendInterface>);
    ~InputTracer() = default;
    InputTracer(const InputTracer&) = delete;
    InputTracer& operator=(const InputTracer&) = delete;

    std::unique_ptr<EventTrackerInterface> traceInboundEvent(const EventEntry&) override;
    std::unique_ptr<EventTrackerInterface> createTrackerForSyntheticEvent() override;
    void dispatchToTargetHint(const EventTrackerInterface&, const InputTarget&) override;
    void eventProcessingComplete(const EventTrackerInterface&) override;
    std::unique_ptr<EventTrackerInterface> traceDerivedEvent(const EventEntry&,
                                                             const EventTrackerInterface&) override;
    void traceEventDispatch(const DispatchEntry&, const EventTrackerInterface&) override;

private:
    std::unique_ptr<InputTracingBackendInterface> mBackend;

    // The state of a tracked event, shared across all events derived from the original event.
    struct EventState {
        explicit inline EventState(InputTracer& tracer) : tracer(tracer){};
        ~EventState();

        void onEventProcessingComplete();

        InputTracer& tracer;
        std::vector<const TracedEvent> events;
        bool isEventProcessingComplete{false};
        // A queue to hold dispatch args from being traced until event processing is complete.
        std::vector<const WindowDispatchArgs> pendingDispatchArgs;
        // True if the event is targeting at least one secure window;
        bool isSecure{false};
        // The list of all possible UIDs that this event could be targeting.
        std::set<gui::Uid> targets;
    };

    // Get the event state associated with a tracking cookie.
    std::shared_ptr<EventState>& getState(const EventTrackerInterface&);
    bool isDerivedCookie(const EventTrackerInterface&);

    // Implementation of the event tracker cookie. The cookie holds the event state directly for
    // convenience to avoid the overhead of tracking the state separately in InputTracer.
    class EventTrackerImpl : public EventTrackerInterface {
    public:
        inline EventTrackerImpl(const std::shared_ptr<EventState>& state, bool isDerivedEvent)
              : mState(state), mIsDerived(isDerivedEvent) {}
        EventTrackerImpl(const EventTrackerImpl&) = default;

    private:
        mutable std::shared_ptr<EventState> mState;
        const bool mIsDerived;

        friend std::shared_ptr<EventState>& InputTracer::getState(const EventTrackerInterface&);
        friend bool InputTracer::isDerivedCookie(const EventTrackerInterface&);
    };
};

} // namespace android::inputdispatcher::trace::impl
