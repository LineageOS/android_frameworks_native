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

#ifndef _UI_INPUT_INPUTDISPATCHER_ENTRY_H
#define _UI_INPUT_INPUTDISPATCHER_ENTRY_H

#include "InjectionState.h"
#include "InputTarget.h"

#include <input/Input.h>
#include <input/InputApplication.h>
#include <stdint.h>
#include <utils/Timers.h>
#include <functional>
#include <string>

namespace android::inputdispatcher {

template <typename T>
struct Link {
    T* next;
    T* prev;

protected:
    inline Link() : next(nullptr), prev(nullptr) {}
};

struct EventEntry : Link<EventEntry> {
    enum { TYPE_CONFIGURATION_CHANGED, TYPE_DEVICE_RESET, TYPE_KEY, TYPE_MOTION };

    uint32_t sequenceNum;
    mutable int32_t refCount;
    int32_t type;
    nsecs_t eventTime;
    uint32_t policyFlags;
    InjectionState* injectionState;

    bool dispatchInProgress; // initially false, set to true while dispatching

    inline bool isInjected() const { return injectionState != nullptr; }

    void release();

    virtual void appendDescription(std::string& msg) const = 0;

protected:
    EventEntry(uint32_t sequenceNum, int32_t type, nsecs_t eventTime, uint32_t policyFlags);
    virtual ~EventEntry();
    void releaseInjectionState();
};

struct ConfigurationChangedEntry : EventEntry {
    explicit ConfigurationChangedEntry(uint32_t sequenceNum, nsecs_t eventTime);
    virtual void appendDescription(std::string& msg) const;

protected:
    virtual ~ConfigurationChangedEntry();
};

struct DeviceResetEntry : EventEntry {
    int32_t deviceId;

    DeviceResetEntry(uint32_t sequenceNum, nsecs_t eventTime, int32_t deviceId);
    virtual void appendDescription(std::string& msg) const;

protected:
    virtual ~DeviceResetEntry();
};

struct KeyEntry : EventEntry {
    int32_t deviceId;
    uint32_t source;
    int32_t displayId;
    int32_t action;
    int32_t flags;
    int32_t keyCode;
    int32_t scanCode;
    int32_t metaState;
    int32_t repeatCount;
    nsecs_t downTime;

    bool syntheticRepeat; // set to true for synthetic key repeats

    enum InterceptKeyResult {
        INTERCEPT_KEY_RESULT_UNKNOWN,
        INTERCEPT_KEY_RESULT_SKIP,
        INTERCEPT_KEY_RESULT_CONTINUE,
        INTERCEPT_KEY_RESULT_TRY_AGAIN_LATER,
    };
    InterceptKeyResult interceptKeyResult; // set based on the interception result
    nsecs_t interceptKeyWakeupTime;        // used with INTERCEPT_KEY_RESULT_TRY_AGAIN_LATER

    KeyEntry(uint32_t sequenceNum, nsecs_t eventTime, int32_t deviceId, uint32_t source,
             int32_t displayId, uint32_t policyFlags, int32_t action, int32_t flags,
             int32_t keyCode, int32_t scanCode, int32_t metaState, int32_t repeatCount,
             nsecs_t downTime);
    virtual void appendDescription(std::string& msg) const;
    void recycle();

protected:
    virtual ~KeyEntry();
};

struct MotionEntry : EventEntry {
    nsecs_t eventTime;
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
    nsecs_t downTime;
    uint32_t pointerCount;
    PointerProperties pointerProperties[MAX_POINTERS];
    PointerCoords pointerCoords[MAX_POINTERS];

    MotionEntry(uint32_t sequenceNum, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                int32_t displayId, uint32_t policyFlags, int32_t action, int32_t actionButton,
                int32_t flags, int32_t metaState, int32_t buttonState,
                MotionClassification classification, int32_t edgeFlags, float xPrecision,
                float yPrecision, nsecs_t downTime, uint32_t pointerCount,
                const PointerProperties* pointerProperties, const PointerCoords* pointerCoords,
                float xOffset, float yOffset);
    virtual void appendDescription(std::string& msg) const;

protected:
    virtual ~MotionEntry();
};

// Tracks the progress of dispatching a particular event to a particular connection.
struct DispatchEntry : Link<DispatchEntry> {
    const uint32_t seq; // unique sequence number, never 0

    EventEntry* eventEntry; // the event to dispatch
    int32_t targetFlags;
    float xOffset;
    float yOffset;
    float globalScaleFactor;
    float windowXScale = 1.0f;
    float windowYScale = 1.0f;
    nsecs_t deliveryTime; // time when the event was actually delivered

    // Set to the resolved action and flags when the event is enqueued.
    int32_t resolvedAction;
    int32_t resolvedFlags;

    DispatchEntry(EventEntry* eventEntry, int32_t targetFlags, float xOffset, float yOffset,
                  float globalScaleFactor, float windowXScale, float windowYScale);
    ~DispatchEntry();

    inline bool hasForegroundTarget() const { return targetFlags & InputTarget::FLAG_FOREGROUND; }

    inline bool isSplit() const { return targetFlags & InputTarget::FLAG_SPLIT; }

private:
    static volatile int32_t sNextSeqAtomic;

    static uint32_t nextSeq();
};

class InputDispatcher;
// A command entry captures state and behavior for an action to be performed in the
// dispatch loop after the initial processing has taken place.  It is essentially
// a kind of continuation used to postpone sensitive policy interactions to a point
// in the dispatch loop where it is safe to release the lock (generally after finishing
// the critical parts of the dispatch cycle).
//
// The special thing about commands is that they can voluntarily release and reacquire
// the dispatcher lock at will.  Initially when the command starts running, the
// dispatcher lock is held.  However, if the command needs to call into the policy to
// do some work, it can release the lock, do the work, then reacquire the lock again
// before returning.
//
// This mechanism is a bit clunky but it helps to preserve the invariant that the dispatch
// never calls into the policy while holding its lock.
//
// Commands are implicitly 'LockedInterruptible'.
struct CommandEntry;
typedef void (InputDispatcher::*Command)(CommandEntry* commandEntry);

class Connection;
struct CommandEntry : Link<CommandEntry> {
    explicit CommandEntry(Command command);
    ~CommandEntry();

    Command command;

    // parameters for the command (usage varies by command)
    sp<Connection> connection;
    nsecs_t eventTime;
    KeyEntry* keyEntry;
    sp<InputApplicationHandle> inputApplicationHandle;
    std::string reason;
    int32_t userActivityEventType;
    uint32_t seq;
    bool handled;
    sp<InputChannel> inputChannel;
    sp<IBinder> oldToken;
    sp<IBinder> newToken;
};

} // namespace android::inputdispatcher

#endif // _UI_INPUT_INPUTDISPATCHER_ENTRY_H
