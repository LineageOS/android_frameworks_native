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
#include <utils/AndroidThreads.h>

namespace android::inputdispatcher::trace::impl {

namespace {

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
      : mTracerThread(&InputTracer::threadLoop, this), mBackend(std::move(backend)) {}

InputTracer::~InputTracer() {
    {
        std::scoped_lock lock(mLock);
        mThreadExit = true;
    }
    mThreadWakeCondition.notify_all();
    mTracerThread.join();
}

std::unique_ptr<EventTrackerInterface> InputTracer::traceInboundEvent(const EventEntry& entry) {
    std::scoped_lock lock(mLock);
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
    std::scoped_lock lock(mLock);
    auto& cookieState = getState(cookie);
    if (!cookieState) {
        LOG(FATAL) << "dispatchToTargetHint() should not be called after eventProcessingComplete()";
    }
    // TODO(b/210460522): Determine if the event is sensitive based on the target.
}

void InputTracer::eventProcessingComplete(const EventTrackerInterface& cookie) {
    {
        std::scoped_lock lock(mLock);
        auto& cookieState = getState(cookie);
        if (!cookieState) {
            LOG(FATAL) << "Traced event was already logged. "
                          "eventProcessingComplete() was likely called more than once.";
        }
        mTraceQueue.emplace_back(std::move(*cookieState));
        cookieState.reset();
    } // release lock

    mThreadWakeCondition.notify_all();
}

void InputTracer::traceEventDispatch(const DispatchEntry& dispatchEntry,
                                     const EventTrackerInterface* cookie) {
    {
        std::scoped_lock lock(mLock);
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
            mTraceQueue.emplace_back(traced);
        }

        // The vsyncId only has meaning if the event is targeting a window.
        const int32_t windowId = dispatchEntry.windowId.value_or(0);
        const int32_t vsyncId = dispatchEntry.windowId.has_value() ? dispatchEntry.vsyncId : 0;

        mDispatchTraceQueue.emplace_back(std::move(traced), dispatchEntry.deliveryTime,
                                         dispatchEntry.resolvedFlags, dispatchEntry.targetUid,
                                         vsyncId, windowId, dispatchEntry.transform,
                                         dispatchEntry.rawTransform);
    } // release lock

    mThreadWakeCondition.notify_all();
}

std::optional<InputTracer::EventState>& InputTracer::getState(const EventTrackerInterface& cookie) {
    return static_cast<const EventTrackerImpl&>(cookie).mLockedState;
}

void InputTracer::threadLoop() {
    androidSetThreadName("InputTracer");

    while (true) {
        std::vector<const EventState> eventsToTrace;
        std::vector<const WindowDispatchArgs> dispatchEventsToTrace;
        {
            std::unique_lock lock(mLock);
            base::ScopedLockAssertion assumeLocked(mLock);
            if (mThreadExit) {
                return;
            }
            if (mTraceQueue.empty() && mDispatchTraceQueue.empty()) {
                // Wait indefinitely until the thread is awoken.
                mThreadWakeCondition.wait(lock);
            }

            mTraceQueue.swap(eventsToTrace);
            mDispatchTraceQueue.swap(dispatchEventsToTrace);
        } // release lock

        // Trace the events into the backend without holding the lock to reduce the amount of
        // work performed in the critical section.
        writeEventsToBackend(eventsToTrace, dispatchEventsToTrace);
        eventsToTrace.clear();
        dispatchEventsToTrace.clear();
    }
}

void InputTracer::writeEventsToBackend(
        const std::vector<const EventState>& events,
        const std::vector<const WindowDispatchArgs>& dispatchEvents) {
    for (const auto& event : events) {
        if (auto* motion = std::get_if<TracedMotionEvent>(&event.event); motion != nullptr) {
            mBackend->traceMotionEvent(*motion);
        } else {
            mBackend->traceKeyEvent(std::get<TracedKeyEvent>(event.event));
        }
    }

    for (const auto& dispatchArgs : dispatchEvents) {
        mBackend->traceWindowDispatch(dispatchArgs);
    }
}

// --- InputTracer::EventTrackerImpl ---

InputTracer::EventTrackerImpl::EventTrackerImpl(InputTracer& tracer, TracedEvent&& event)
      : mTracer(tracer), mLockedState(event) {}

InputTracer::EventTrackerImpl::~EventTrackerImpl() {
    {
        std::scoped_lock lock(mTracer.mLock);
        if (!mLockedState) {
            // This event has already been written to the trace as expected.
            return;
        }
        // We're still holding on to the state, which means it hasn't yet been written to the trace.
        // Write it to the trace now.
        // TODO(b/210460522): Determine why/where the event is being destroyed before
        //   eventProcessingComplete() is called.
        mTracer.mTraceQueue.emplace_back(std::move(*mLockedState));
        mLockedState.reset();
    } // release lock

    mTracer.mThreadWakeCondition.notify_all();
}

} // namespace android::inputdispatcher::trace::impl
