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

#include "CancelationOptions.h"
#include "Entry.h"

#include <utils/Timers.h>
#include <bitset>

namespace android {
namespace inputdispatcher {

static constexpr int32_t INVALID_POINTER_INDEX = -1;

/* Tracks dispatched key and motion event state so that cancellation events can be
 * synthesized when events are dropped. */
class InputState {
public:
    explicit InputState(const IdGenerator& idGenerator);
    ~InputState();

    // Returns true if the specified source is known to have received a hover enter
    // motion event.
    bool isHovering(DeviceId deviceId, uint32_t source, ui::LogicalDisplayId displayId) const;

    // Records tracking information for a key event that has just been published.
    // Returns true if the event should be delivered, false if it is inconsistent
    // and should be skipped.
    bool trackKey(const KeyEntry& entry, int32_t flags);

    // Records tracking information for a motion event that has just been published.
    // Returns true if the event should be delivered, false if it is inconsistent
    // and should be skipped.
    bool trackMotion(const MotionEntry& entry, int32_t flags);

    /**
     * Return the PointerProperties and the PointerCoords for the last event, if found. Return
     * std::nullopt if not found. We should not return std::vector<PointerCoords> in isolation,
     * because the pointers can technically be stored in the vector in any order, so the
     * PointerProperties are needed to specify the order in which the pointer coords are stored.
     */
    std::optional<std::pair<std::vector<PointerProperties>, std::vector<PointerCoords>>>
    getPointersOfLastEvent(const MotionEntry& entry, bool hovering) const;

    // Create cancel events for the previous stream if the current motionEntry requires it.
    std::unique_ptr<EventEntry> cancelConflictingInputStream(const MotionEntry& motionEntry);

    // Synthesizes cancelation events for the current state and resets the tracked state.
    std::vector<std::unique_ptr<EventEntry>> synthesizeCancelationEvents(
            nsecs_t currentTime, const CancelationOptions& options);

    // Synthesizes down events for the current state.
    std::vector<std::unique_ptr<EventEntry>> synthesizePointerDownEvents(nsecs_t currentTime);

    // Clears the current state.
    void clear();

    // Merges pointer-related parts of the input state into another instance.
    void mergePointerStateTo(InputState& other);

    // Gets the fallback key associated with a keycode.
    // Returns std::nullopt if none.
    // Returns AKEYCODE_UNKNOWN if we are only dispatching the unhandled key to the policy.
    std::optional<int32_t> getFallbackKey(int32_t originalKeyCode);

    // Sets the fallback key for a particular keycode.
    void setFallbackKey(int32_t originalKeyCode, int32_t fallbackKeyCode);

    // Removes the fallback key for a particular keycode.
    void removeFallbackKey(int32_t originalKeyCode);

    inline const std::map<int32_t, int32_t>& getFallbackKeys() const { return mFallbackKeys; }

private:
    struct KeyMemento {
        DeviceId deviceId;
        uint32_t source;
        ui::LogicalDisplayId displayId{ui::LogicalDisplayId::INVALID};
        int32_t keyCode;
        int32_t scanCode;
        int32_t metaState;
        int32_t flags;
        nsecs_t downTime;
        uint32_t policyFlags;
    };

    struct MotionMemento {
        DeviceId deviceId;
        uint32_t source;
        ui::LogicalDisplayId displayId{ui::LogicalDisplayId::INVALID};
        int32_t flags;
        float xPrecision;
        float yPrecision;
        float xCursorPosition;
        float yCursorPosition;
        nsecs_t downTime;
        std::vector<PointerProperties> pointerProperties;
        std::vector<PointerCoords> pointerCoords;
        // Track for which pointers the target doesn't know about.
        int32_t firstNewPointerIdx = INVALID_POINTER_INDEX;
        bool hovering;
        uint32_t policyFlags;

        void setPointers(const MotionEntry& entry);
        void mergePointerStateTo(MotionMemento& other) const;
        size_t getPointerCount() const;
    };

    const IdGenerator& mIdGenerator; // InputDispatcher owns it so we won't have dangling reference.

    std::vector<KeyMemento> mKeyMementos;
    std::vector<MotionMemento> mMotionMementos;
    std::map</*originalKeyCode*/int32_t, /*fallbackKeyCode*/int32_t> mFallbackKeys;

    ssize_t findKeyMemento(const KeyEntry& entry) const;
    ssize_t findMotionMemento(const MotionEntry& entry, bool hovering) const;

    void addKeyMemento(const KeyEntry& entry, int32_t flags);
    void addMotionMemento(const MotionEntry& entry, int32_t flags, bool hovering);

    static bool shouldCancelKey(const KeyMemento& memento, const CancelationOptions& options);
    static bool shouldCancelMotion(const MotionMemento& memento, const CancelationOptions& options);
    bool shouldCancelPreviousStream(const MotionEntry& motionEntry) const;
    std::unique_ptr<MotionEntry> createCancelEntryForMemento(const MotionMemento& memento,
                                                             nsecs_t eventTime) const;

    // Synthesizes pointer cancel events for a particular set of pointers.
    std::vector<std::unique_ptr<MotionEntry>> synthesizeCancelationEventsForPointers(
            const MotionMemento& memento, std::bitset<MAX_POINTER_ID + 1> pointerIds,
            nsecs_t currentTime);
    friend std::ostream& operator<<(std::ostream& out, const InputState& state);
};

std::ostream& operator<<(std::ostream& out, const InputState& state);

} // namespace inputdispatcher
} // namespace android
