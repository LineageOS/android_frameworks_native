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

#include <gui/PidUid.h>
#include <input/Input.h>
#include <ui/Transform.h>

#include <array>
#include <set>
#include <variant>
#include <vector>

namespace android::inputdispatcher::trace {

/**
 * Describes the type of this event being traced, with respect to InputDispatcher.
 */
enum class EventType {
    // This is an event that was reported through the InputListener interface or was injected.
    INBOUND,
    // This is an event that was synthesized within InputDispatcher; either being derived
    // from an inbound event (e.g. a split motion event), or synthesized completely
    // (e.g. a CANCEL event generated when the inbound stream is not canceled).
    SYNTHESIZED,

    ftl_last = SYNTHESIZED,
};

/**
 * A representation of an Android KeyEvent used by the tracing backend.
 */
struct TracedKeyEvent {
    int32_t id;
    nsecs_t eventTime;
    uint32_t policyFlags;
    int32_t deviceId;
    uint32_t source;
    ui::LogicalDisplayId displayId;
    int32_t action;
    int32_t keyCode;
    int32_t scanCode;
    int32_t metaState;
    nsecs_t downTime;
    int32_t flags;
    int32_t repeatCount;
    EventType eventType;
};

/**
 * A representation of an Android MotionEvent used by the tracing backend.
 */
struct TracedMotionEvent {
    int32_t id;
    nsecs_t eventTime;
    uint32_t policyFlags;
    int32_t deviceId;
    uint32_t source;
    ui::LogicalDisplayId displayId;
    int32_t action;
    int32_t actionButton;
    int32_t flags;
    int32_t metaState;
    int32_t buttonState;
    MotionClassification classification;
    int32_t edgeFlags;
    float xPrecision;
    float yPrecision;
    float xCursorPosition;
    float yCursorPosition;
    nsecs_t downTime;
    std::vector<PointerProperties> pointerProperties;
    std::vector<PointerCoords> pointerCoords;
    EventType eventType;
};

/** A representation of a traced input event. */
using TracedEvent = std::variant<TracedKeyEvent, TracedMotionEvent>;

/** Additional information about an input event being traced. */
struct TracedEventMetadata {
    // True if the event is targeting at least one secure window.
    bool isSecure;
    // The list of possible UIDs that this event could be targeting.
    std::set<gui::Uid> targets;
    // True if the there was an active input method connection while this event was processed.
    bool isImeConnectionActive;
    // The timestamp for when the dispatching decisions were made for the event by the system.
    nsecs_t processingTimestamp;
};

/** Additional information about an input event being dispatched to a window. */
struct WindowDispatchArgs {
    TracedEvent eventEntry;
    nsecs_t deliveryTime;
    int32_t resolvedFlags;
    gui::Uid targetUid;
    int64_t vsyncId;
    int32_t windowId;
    ui::Transform transform;
    ui::Transform rawTransform;
    std::array<uint8_t, 32> hmac;
    int32_t resolvedKeyRepeatCount;
};

/**
 * An interface for the tracing backend, used for setting a custom backend for testing.
 */
class InputTracingBackendInterface {
public:
    virtual ~InputTracingBackendInterface() = default;

    /** Trace a KeyEvent. */
    virtual void traceKeyEvent(const TracedKeyEvent&, const TracedEventMetadata&) = 0;

    /** Trace a MotionEvent. */
    virtual void traceMotionEvent(const TracedMotionEvent&, const TracedEventMetadata&) = 0;

    /** Trace an event being sent to a window. */
    virtual void traceWindowDispatch(const WindowDispatchArgs&, const TracedEventMetadata&) = 0;
};

} // namespace android::inputdispatcher::trace
