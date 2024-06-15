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
#include <private/android_filesystem_config.h>

namespace android::inputdispatcher::trace::impl {

namespace {

// Helper to std::visit with lambdas.
template <typename... V>
struct Visitor : V... {
    using V::operator()...;
};

TracedEvent createTracedEvent(const MotionEntry& e, EventType type) {
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
                             e.pointerCoords,
                             type};
}

TracedEvent createTracedEvent(const KeyEntry& e, EventType type) {
    return TracedKeyEvent{e.id,        e.eventTime, e.policyFlags, e.deviceId, e.source,
                          e.displayId, e.action,    e.keyCode,     e.scanCode, e.metaState,
                          e.downTime,  e.flags,     e.repeatCount, type};
}

void writeEventToBackend(const TracedEvent& event, const TracedEventMetadata metadata,
                         InputTracingBackendInterface& backend) {
    std::visit(Visitor{[&](const TracedMotionEvent& e) { backend.traceMotionEvent(e, metadata); },
                       [&](const TracedKeyEvent& e) { backend.traceKeyEvent(e, metadata); }},
               event);
}

inline auto getId(const trace::TracedEvent& v) {
    return std::visit([](const auto& event) { return event.id; }, v);
}

// Helper class to extract relevant information from InputTarget.
struct InputTargetInfo {
    gui::Uid uid;
    bool isSecureWindow;
};

InputTargetInfo getTargetInfo(const InputTarget& target) {
    if (target.windowHandle == nullptr) {
        if (!target.connection->monitor) {
            LOG(FATAL) << __func__ << ": Window is not set for non-monitor target";
        }
        // This is a global monitor, assume its target is the system.
        return {.uid = gui::Uid{AID_SYSTEM}, .isSecureWindow = false};
    }
    const auto& info = *target.windowHandle->getInfo();
    const bool isSensitiveTarget =
            info.inputConfig.test(gui::WindowInfo::InputConfig::SENSITIVE_FOR_PRIVACY);
    return {target.windowHandle->getInfo()->ownerUid, isSensitiveTarget};
}

} // namespace

// --- InputTracer ---

InputTracer::InputTracer(std::unique_ptr<InputTracingBackendInterface> backend)
      : mBackend(std::move(backend)) {}

std::unique_ptr<EventTrackerInterface> InputTracer::traceInboundEvent(const EventEntry& entry) {
    // This is a newly traced inbound event. Create a new state to track it and its derived events.
    auto eventState = std::make_shared<EventState>(*this);

    if (entry.type == EventEntry::Type::MOTION) {
        const auto& motion = static_cast<const MotionEntry&>(entry);
        eventState->events.emplace_back(createTracedEvent(motion, EventType::INBOUND));
    } else if (entry.type == EventEntry::Type::KEY) {
        const auto& key = static_cast<const KeyEntry&>(entry);
        eventState->events.emplace_back(createTracedEvent(key, EventType::INBOUND));
    } else {
        LOG(FATAL) << "Cannot trace EventEntry of type: " << ftl::enum_string(entry.type);
    }

    return std::make_unique<EventTrackerImpl>(std::move(eventState), /*isDerived=*/false);
}

std::unique_ptr<EventTrackerInterface> InputTracer::createTrackerForSyntheticEvent() {
    // Create a new EventState to track events derived from this tracker.
    return std::make_unique<EventTrackerImpl>(std::make_shared<EventState>(*this),
                                              /*isDerived=*/false);
}

void InputTracer::dispatchToTargetHint(const EventTrackerInterface& cookie,
                                       const InputTarget& target) {
    auto& eventState = getState(cookie);
    const InputTargetInfo& targetInfo = getTargetInfo(target);
    if (eventState->isEventProcessingComplete) {
        // Disallow adding new targets after eventProcessingComplete() is called.
        if (eventState->metadata.targets.count(targetInfo.uid) == 0) {
            LOG(FATAL) << __func__ << ": Cannot add new target after eventProcessingComplete";
        }
        return;
    }
    if (isDerivedCookie(cookie)) {
        // Disallow adding new targets from a derived cookie.
        if (eventState->metadata.targets.count(targetInfo.uid) == 0) {
            LOG(FATAL) << __func__ << ": Cannot add new target from a derived cookie";
        }
        return;
    }

    eventState->metadata.targets.emplace(targetInfo.uid);
    eventState->metadata.isSecure |= targetInfo.isSecureWindow;
}

void InputTracer::eventProcessingComplete(const EventTrackerInterface& cookie,
                                          nsecs_t processingTimestamp) {
    if (isDerivedCookie(cookie)) {
        LOG(FATAL) << "Event processing cannot be set from a derived cookie.";
    }
    auto& eventState = getState(cookie);
    if (eventState->isEventProcessingComplete) {
        LOG(FATAL) << "Traced event was already logged. "
                      "eventProcessingComplete() was likely called more than once.";
    }
    eventState->onEventProcessingComplete(processingTimestamp);
}

std::unique_ptr<EventTrackerInterface> InputTracer::traceDerivedEvent(
        const EventEntry& entry, const EventTrackerInterface& originalEventCookie) {
    // This is an event derived from an already-established event. Use the same state to track
    // this event too.
    auto eventState = getState(originalEventCookie);

    if (entry.type == EventEntry::Type::MOTION) {
        const auto& motion = static_cast<const MotionEntry&>(entry);
        eventState->events.emplace_back(createTracedEvent(motion, EventType::SYNTHESIZED));
    } else if (entry.type == EventEntry::Type::KEY) {
        const auto& key = static_cast<const KeyEntry&>(entry);
        eventState->events.emplace_back(createTracedEvent(key, EventType::SYNTHESIZED));
    } else {
        LOG(FATAL) << "Cannot trace EventEntry of type: " << ftl::enum_string(entry.type);
    }

    if (eventState->isEventProcessingComplete) {
        // It is possible for a derived event to be dispatched some time after the original event
        // is dispatched, such as in the case of key fallback events. To account for these cases,
        // derived events can be traced after the processing is complete for the original event.
        const auto& event = eventState->events.back();
        writeEventToBackend(event, eventState->metadata, *mBackend);
    }
    return std::make_unique<EventTrackerImpl>(std::move(eventState), /*isDerived=*/true);
}

void InputTracer::traceEventDispatch(const DispatchEntry& dispatchEntry,
                                     const EventTrackerInterface& cookie) {
    auto& eventState = getState(cookie);
    const EventEntry& entry = *dispatchEntry.eventEntry;
    const int32_t eventId = entry.id;
    // TODO(b/328618922): Remove resolved key repeats after making repeatCount non-mutable.
    // The KeyEntry's repeatCount is mutable and can be modified after an event is initially traced,
    // so we need to find the repeatCount at the time of dispatching to trace it accurately.
    int32_t resolvedKeyRepeatCount = 0;
    if (entry.type == EventEntry::Type::KEY) {
        resolvedKeyRepeatCount = static_cast<const KeyEntry&>(entry).repeatCount;
    }

    auto tracedEventIt =
            std::find_if(eventState->events.begin(), eventState->events.end(),
                         [eventId](const auto& event) { return eventId == getId(event); });
    if (tracedEventIt == eventState->events.end()) {
        LOG(FATAL)
                << __func__
                << ": Failed to find a previously traced event that matches the dispatched event";
    }

    if (eventState->metadata.targets.count(dispatchEntry.targetUid) == 0) {
        LOG(FATAL) << __func__ << ": Event is being dispatched to UID that it is not targeting";
    }

    // The vsyncId only has meaning if the event is targeting a window.
    const int32_t windowId = dispatchEntry.windowId.value_or(0);
    const int32_t vsyncId = dispatchEntry.windowId.has_value() ? dispatchEntry.vsyncId : 0;

    // TODO(b/210460522): Pass HMAC into traceEventDispatch.
    const WindowDispatchArgs windowDispatchArgs{*tracedEventIt,
                                                dispatchEntry.deliveryTime,
                                                dispatchEntry.resolvedFlags,
                                                dispatchEntry.targetUid,
                                                vsyncId,
                                                windowId,
                                                dispatchEntry.transform,
                                                dispatchEntry.rawTransform,
                                                /*hmac=*/{},
                                                resolvedKeyRepeatCount};
    if (eventState->isEventProcessingComplete) {
        mBackend->traceWindowDispatch(std::move(windowDispatchArgs), eventState->metadata);
    } else {
        eventState->pendingDispatchArgs.emplace_back(std::move(windowDispatchArgs));
    }
}

std::shared_ptr<InputTracer::EventState>& InputTracer::getState(
        const EventTrackerInterface& cookie) {
    return static_cast<const EventTrackerImpl&>(cookie).mState;
}

bool InputTracer::isDerivedCookie(const EventTrackerInterface& cookie) {
    return static_cast<const EventTrackerImpl&>(cookie).mIsDerived;
}

// --- InputTracer::EventState ---

void InputTracer::EventState::onEventProcessingComplete(nsecs_t processingTimestamp) {
    metadata.processingTimestamp = processingTimestamp;
    metadata.isImeConnectionActive = tracer.mIsImeConnectionActive;

    // Write all of the events known so far to the trace.
    for (const auto& event : events) {
        writeEventToBackend(event, metadata, *tracer.mBackend);
    }
    // Write all pending dispatch args to the trace.
    for (const auto& windowDispatchArgs : pendingDispatchArgs) {
        auto tracedEventIt =
                std::find_if(events.begin(), events.end(),
                             [id = getId(windowDispatchArgs.eventEntry)](const auto& event) {
                                 return id == getId(event);
                             });
        if (tracedEventIt == events.end()) {
            LOG(FATAL) << __func__
                       << ": Failed to find a previously traced event that matches the dispatched "
                          "event";
        }
        tracer.mBackend->traceWindowDispatch(windowDispatchArgs, metadata);
    }
    pendingDispatchArgs.clear();

    isEventProcessingComplete = true;
}

InputTracer::EventState::~EventState() {
    if (isEventProcessingComplete) {
        // This event has already been written to the trace as expected.
        return;
    }
    // The event processing was never marked as complete, so do it now.
    // We should never end up here in normal operation. However, in tests, it's possible that we
    // stop and destroy InputDispatcher without waiting for it to finish processing events, at
    // which point an event (and thus its EventState) may be destroyed before processing finishes.
    onEventProcessingComplete(systemTime(CLOCK_MONOTONIC));
}

} // namespace android::inputdispatcher::trace::impl
