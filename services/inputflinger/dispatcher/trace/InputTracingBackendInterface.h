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

namespace android::inputdispatcher::trace {

/**
 * An interface for the tracing backend, used for setting a custom backend for testing.
 */
class InputTracingBackendInterface {
public:
    virtual ~InputTracingBackendInterface() = default;

    /** Trace a KeyEvent. */
    virtual void traceKeyEvent(const KeyEntry&) const = 0;

    /** Trace a MotionEvent. */
    virtual void traceMotionEvent(const MotionEntry&) const = 0;

    /** Trace an event being sent to a window. */
    struct WindowDispatchArgs {
        std::variant<MotionEntry, KeyEntry> eventEntry;
        nsecs_t deliveryTime;
        int32_t resolvedFlags;
        gui::Uid targetUid;
        int64_t vsyncId;
        int32_t windowId;
        ui::Transform transform;
        ui::Transform rawTransform;
        std::array<uint8_t, 32> hmac;
    };
    virtual void traceWindowDispatch(const WindowDispatchArgs&) const = 0;
};

} // namespace android::inputdispatcher::trace
