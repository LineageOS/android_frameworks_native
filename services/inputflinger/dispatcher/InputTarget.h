/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <ftl/flags.h>
#include <gui/WindowInfo.h>
#include <ui/Transform.h>
#include <utils/BitSet.h>
#include <bitset>
#include "Connection.h"
#include "InputTargetFlags.h"

namespace android::inputdispatcher {

/*
 * An input target specifies how an input event is to be dispatched to a particular window
 * including the window's input channel, control flags, a timeout, and an X / Y offset to
 * be added to input event coordinates to compensate for the absolute position of the
 * window area.
 */
class InputTarget {
public:
    using Flags = InputTargetFlags;

    enum class DispatchMode {
        /* This flag indicates that the event should be sent as is.
         * Should always be set unless the event is to be transmuted. */
        AS_IS,
        /* This flag indicates that a MotionEvent with AMOTION_EVENT_ACTION_DOWN falls outside
         * of the area of this target and so should instead be delivered as an
         * AMOTION_EVENT_ACTION_OUTSIDE to this target. */
        OUTSIDE,
        /* This flag indicates that a hover sequence is starting in the given window.
         * The event is transmuted into ACTION_HOVER_ENTER. */
        HOVER_ENTER,
        /* This flag indicates that a hover event happened outside of a window which handled
         * previous hover events, signifying the end of the current hover sequence for that
         * window.
         * The event is transmuted into ACTION_HOVER_ENTER. */
        HOVER_EXIT,
        /* This flag indicates that the event should be canceled.
         * It is used to transmute ACTION_MOVE into ACTION_CANCEL when a touch slips
         * outside of a window. */
        SLIPPERY_EXIT,
        /* This flag indicates that the event should be dispatched as an initial down.
         * It is used to transmute ACTION_MOVE into ACTION_DOWN when a touch slips
         * into a new window. */
        SLIPPERY_ENTER,

        ftl_last = SLIPPERY_ENTER,
    };

    // The input connection to be targeted.
    std::shared_ptr<Connection> connection;

    // Flags for the input target.
    ftl::Flags<Flags> flags;

    // The dispatch mode that should be used for this target.
    DispatchMode dispatchMode = DispatchMode::AS_IS;

    // Scaling factor to apply to MotionEvent as it is delivered.
    // (ignored for KeyEvents)
    float globalScaleFactor = 1.0f;

    // Current display transform. Used for compatibility for raw coordinates.
    ui::Transform displayTransform;

    // Event time for the first motion event (ACTION_DOWN) dispatched to this input target if
    // FLAG_SPLIT is set.
    std::optional<nsecs_t> firstDownTimeInTarget;

    // The window that this input target is being dispatched to. It is possible for this to be
    // null for cases like global monitors.
    sp<gui::WindowInfoHandle> windowHandle;

    InputTarget() = default;
    InputTarget(const std::shared_ptr<Connection>&, ftl::Flags<Flags> = {});

    android::base::Result<void> addPointers(std::bitset<MAX_POINTER_ID + 1> pointerIds,
                                            const ui::Transform& transform);
    void setDefaultPointerTransform(const ui::Transform& transform);

    /**
     * Returns whether the default pointer information should be used. This will be true when the
     * InputTarget doesn't have any bits set in the pointerIds bitset. This can happen for monitors
     * and non splittable windows since we want all pointers for the EventEntry to go to this
     * target.
     */
    bool useDefaultPointerTransform() const;

    /**
     * Returns the default Transform object. This should be used when useDefaultPointerTransform is
     * true.
     */
    const ui::Transform& getDefaultPointerTransform() const;

    const ui::Transform& getTransformForPointer(int32_t pointerId) const;

    std::bitset<MAX_POINTER_ID + 1> getPointerIds() const;

    std::string getPointerInfoString() const;

private:
    template <typename K, typename V>
    using ArrayMap = std::vector<std::pair<K, V>>;
    using PointerIds = std::bitset<MAX_POINTER_ID + 1>;
    // The mapping of pointer IDs to the transform that should be used for that collection of IDs.
    // Each of the pointer IDs are mutually disjoint, and their union makes up pointer IDs to
    // include in the motion events dispatched to this target. We use an ArrayMap to store this to
    // avoid having to define hash or comparison functions for ui::Transform, which would be needed
    // to use std::unordered_map or std::map respectively.
    ArrayMap<ui::Transform, PointerIds> mPointerTransforms;
};

std::ostream& operator<<(std::ostream& out, const InputTarget& target);

} // namespace android::inputdispatcher
