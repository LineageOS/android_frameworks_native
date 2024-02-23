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

#include "InputTracer.h"

#include <android-base/logging.h>

namespace android::inputdispatcher::trace::impl {

namespace {

// Helper to std::visit with lambdas.
template <typename... V>
struct Visitor : V... {
    using V::operator()...;
};

TracedEvent createTracedEvent(const MotionEntry& e) {
    return TracedMotionEvent{e.id,
                             e.eventTime,
                             e.policyFlags,
                             e.deviceId,
                             e.source,
                             e.displayId,
                             e.action,
                             e.actionButton,
                             e.flags,
                             e.metaState,
                             e.buttonState,
                             e.classification,
                             e.edgeFlags,
                             e.xPrecision,
                             e.yPrecision,
                             e.xCursorPosition,
                             e.yCursorPosition,
                             e.downTime,
                             e.pointerProperties,
                             e.pointerCoords};
}

TracedEvent createTracedEvent(const KeyEntry& e) {
    return TracedKeyEvent{e.id,        e.eventTime, e.policyFlags, e.deviceId, e.source,
                          e.displayId, e.action,    e.keyCode,     e.scanCode, e.metaState,
                          e.downTime,  e.flags,     e.repeatCount};
}

} // namespace

// --- InputTracer ---

InputTracer::InputTracer(std::unique_ptr<InputTracingBackendInterface> backend)
      : mBackend(std::move(backend)) {}

std::unique_ptr<EventTrackerInterface> InputTracer::traceInboundEvent(const EventEntry& entry) {
    TracedEvent traced;

    if (entry.type == EventEntry::Type::MOTION) {
        const auto& motion = static_cast<const MotionEntry&>(entry);
        traced = createTracedEvent(motion);
    } else if (entry.type == EventEntry::Type::KEY) {
        const auto& key = static_cast<const KeyEntry&>(entry);
        traced = createTracedEvent(key);
    } else {
        LOG(FATAL) << "Cannot trace EventEntry of type: " << ftl::enum_string(entry.type);
    }

    return std::make_unique<EventTrackerImpl>(*this, std::move(traced));
}

void InputTracer::dispatchToTargetHint(const EventTrackerInterface& cookie,
                                       const InputTarget& target) {
    auto& cookieState = getState(cookie);
    if (!cookieState) {
        LOG(FATAL) << "dispatchToTargetHint() should not be called after eventProcessingComplete()";
    }
    // TODO(b/210460522): Determine if the event is sensitive based on the target.
}

void InputTracer::eventProcessingComplete(const EventTrackerInterface& cookie) {
    auto& cookieState = getState(cookie);
    if (!cookieState) {
        LOG(FATAL) << "Traced event was already logged. "
                      "eventProcessingComplete() was likely called more than once.";
    }

    std::visit(Visitor{[&](const TracedMotionEvent& e) { mBackend->traceMotionEvent(e); },
                       [&](const TracedKeyEvent& e) { mBackend->traceKeyEvent(e); }},
               cookieState->event);
    cookieState.reset();
}

void InputTracer::traceEventDispatch(const DispatchEntry& dispatchEntry,
                                     const EventTrackerInterface* cookie) {
    const EventEntry& entry = *dispatchEntry.eventEntry;

    TracedEvent traced;
    if (entry.type == EventEntry::Type::MOTION) {
        const auto& motion = static_cast<const MotionEntry&>(entry);
        traced = createTracedEvent(motion);
    } else if (entry.type == EventEntry::Type::KEY) {
        const auto& key = static_cast<const KeyEntry&>(entry);
        traced = createTracedEvent(key);
    } else {
        LOG(FATAL) << "Cannot trace EventEntry of type: " << ftl::enum_string(entry.type);
    }

    if (!cookie) {
        // This event was not tracked as an inbound event, so trace it now.
        std::visit(Visitor{[&](const TracedMotionEvent& e) { mBackend->traceMotionEvent(e); },
                           [&](const TracedKeyEvent& e) { mBackend->traceKeyEvent(e); }},
                   traced);
    }

    // The vsyncId only has meaning if the event is targeting a window.
    const int32_t windowId = dispatchEntry.windowId.value_or(0);
    const int32_t vsyncId = dispatchEntry.windowId.has_value() ? dispatchEntry.vsyncId : 0;

    mBackend->traceWindowDispatch({std::move(traced), dispatchEntry.deliveryTime,
                                   dispatchEntry.resolvedFlags, dispatchEntry.targetUid, vsyncId,
                                   windowId, dispatchEntry.transform, dispatchEntry.rawTransform,
                                   /*hmac=*/{}});
}

std::optional<InputTracer::EventState>& InputTracer::getState(const EventTrackerInterface& cookie) {
    return static_cast<const EventTrackerImpl&>(cookie).mState;
}

// --- InputTracer::EventTrackerImpl ---

InputTracer::EventTrackerImpl::EventTrackerImpl(InputTracer& tracer, TracedEvent&& event)
      : mTracer(tracer), mState(event) {}

InputTracer::EventTrackerImpl::~EventTrackerImpl() {
    if (!mState) {
        // This event has already been written to the trace as expected.
        return;
    }
    // We're still holding on to the state, which means it hasn't yet been written to the trace.
    // Write it to the trace now.
    // TODO(b/210460522): Determine why/where the event is being destroyed before
    //   eventProcessingComplete() is called.
    std::visit(Visitor{[&](const TracedMotionEvent& e) { mTracer.mBackend->traceMotionEvent(e); },
                       [&](const TracedKeyEvent& e) { mTracer.mBackend->traceKeyEvent(e); }},
               mState->event);
    mState.reset();
}

} // namespace android::inputdispatcher::trace::impl
