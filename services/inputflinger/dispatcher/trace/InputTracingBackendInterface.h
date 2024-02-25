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
#include <variant>
#include <vector>

namespace android::inputdispatcher::trace {

/**
 * A representation of an Android KeyEvent used by the tracing backend.
 */
struct TracedKeyEvent {
    int32_t id;
    nsecs_t eventTime;
    uint32_t policyFlags;
    int32_t deviceId;
    uint32_t source;
    int32_t displayId;
    int32_t action;
    int32_t keyCode;
    int32_t scanCode;
    int32_t metaState;
    nsecs_t downTime;
    int32_t flags;
    int32_t repeatCount;
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
    int32_t displayId;
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
};

/** A representation of a traced input event. */
using TracedEvent = std::variant<TracedKeyEvent, TracedMotionEvent>;

/**
 * An interface for the tracing backend, used for setting a custom backend for testing.
 */
class InputTracingBackendInterface {
public:
    virtual ~InputTracingBackendInterface() = default;

    /** Trace a KeyEvent. */
    virtual void traceKeyEvent(const TracedKeyEvent&) = 0;

    /** Trace a MotionEvent. */
    virtual void traceMotionEvent(const TracedMotionEvent&) = 0;

    /** Trace an event being sent to a window. */
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
    };
    virtual void traceWindowDispatch(const WindowDispatchArgs&) = 0;
};

} // namespace android::inputdispatcher::trace
