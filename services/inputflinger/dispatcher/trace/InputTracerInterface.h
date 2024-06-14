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

#include "../Entry.h"
#include "../InputTarget.h"
#include "EventTrackerInterface.h"

namespace android::inputdispatcher::trace {

/**
 * InputTracerInterface is the tracing interface for InputDispatcher.
 *
 * The tracer is responsible for tracing information about input events and where they are
 * dispatched. The trace is logged to the backend using the InputTracingBackendInterface.
 *
 * A normal traced event should have the following lifecycle:
 *  - The EventTracker is obtained from traceInboundEvent(), after which point the event
 *    should not change.
 *  - While the event is being processed, dispatchToTargetHint() is called for each target that
 *    the event will be eventually sent to.
 *  - Once all targets have been determined, eventProcessingComplete() is called, at which point
 *    the tracer will have enough information to commit the event to the trace.
 *  - For each event that is dispatched to the client, traceEventDispatch() is called, and the
 *    tracer will record that the event was sent to the client.
 */
class InputTracerInterface {
public:
    InputTracerInterface() = default;
    virtual ~InputTracerInterface() = default;
    InputTracerInterface(const InputTracerInterface&) = delete;
    InputTracerInterface& operator=(const InputTracerInterface&) = delete;

    /**
     * Trace an input event that is being processed by InputDispatcher. The event must not be
     * modified after it is traced to keep the traced event consistent with the event that is
     * eventually dispatched. An EventTracker is returned for each traced event that should be used
     * to track the event's lifecycle inside InputDispatcher.
     */
    virtual std::unique_ptr<EventTrackerInterface> traceInboundEvent(const EventEntry&) = 0;

    /**
     * Create a trace tracker for a synthetic event that does not stem from an inbound input event.
     * This includes things like generating cancellations or down events for various reasons,
     * such as ANR, pilfering, transfer touch, etc. Any key or motion events generated for this
     * synthetic event should be traced as a derived event using {@link #traceDerivedEvent}.
     */
    virtual std::unique_ptr<EventTrackerInterface> createTrackerForSyntheticEvent() = 0;

    /**
     * Notify the tracer that the traced event will be sent to the given InputTarget.
     * The tracer may change how the event is logged depending on the target. For example,
     * events targeting certain UIDs may be logged as sensitive events.
     * This may be called 0 or more times for each tracked event before event processing is
     * completed.
     */
    virtual void dispatchToTargetHint(const EventTrackerInterface&, const InputTarget&) = 0;

    /**
     * Notify the tracer that the event processing is complete. This may be called at most once
     * for each traced event. If a tracked event is dropped before it can be processed, it is
     * possible that this is never called before the EventTracker is destroyed.
     *
     * This is used to commit the event to the trace in a timely manner, rather than always
     * waiting for the event to go out of scope (and thus for the EventTracker to be destroyed)
     * before committing. The point at which the event is destroyed can depend on several factors
     * outside of our control, such as how long apps take to respond, so we don't want to depend on
     * that.
     */
    virtual void eventProcessingComplete(const EventTrackerInterface&,
                                         nsecs_t processingTimestamp) = 0;

    /**
     * Trace an input event that is derived from another event. This is used in cases where an event
     * is modified from the original, such as when a touch is split across multiple windows, or
     * when a HOVER_MOVE event is modified to be a HOVER_EXIT, etc. The original event's tracker
     * must be provided, and a new EventTracker is returned that should be used to track the event's
     * lifecycle.
     *
     * NOTE: The derived tracker cannot be used to change the targets of the original event, meaning
     * it cannot be used with {@link #dispatchToTargetHint} or {@link eventProcessingComplete}.
     */
    virtual std::unique_ptr<EventTrackerInterface> traceDerivedEvent(
            const EventEntry&, const EventTrackerInterface& originalEventTracker) = 0;

    /**
     * Trace an input event being successfully dispatched to a window. The dispatched event may
     * be a previously traced inbound event, or it may be a synthesized event. All dispatched events
     * must have been previously traced, so the trace tracker associated with the event must be
     * provided.
     */
    virtual void traceEventDispatch(const DispatchEntry&, const EventTrackerInterface&) = 0;

    /**
     * Notify that the state of the input method connection changed.
     */
    virtual void setInputMethodConnectionIsActive(bool isActive) = 0;
};

} // namespace android::inputdispatcher::trace
