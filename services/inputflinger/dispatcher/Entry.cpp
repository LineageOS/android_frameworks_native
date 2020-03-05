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

#include "Entry.h"

#include "Connection.h"

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <cutils/atomic.h>
#include <inttypes.h>

using android::base::GetBoolProperty;
using android::base::StringPrintf;

namespace android::inputdispatcher {

static std::string motionActionToString(int32_t action) {
    // Convert MotionEvent action to string
    switch (action & AMOTION_EVENT_ACTION_MASK) {
        case AMOTION_EVENT_ACTION_DOWN:
            return "DOWN";
        case AMOTION_EVENT_ACTION_MOVE:
            return "MOVE";
        case AMOTION_EVENT_ACTION_UP:
            return "UP";
        case AMOTION_EVENT_ACTION_POINTER_DOWN:
            return "POINTER_DOWN";
        case AMOTION_EVENT_ACTION_POINTER_UP:
            return "POINTER_UP";
    }
    return StringPrintf("%" PRId32, action);
}

static std::string keyActionToString(int32_t action) {
    // Convert KeyEvent action to string
    switch (action) {
        case AKEY_EVENT_ACTION_DOWN:
            return "DOWN";
        case AKEY_EVENT_ACTION_UP:
            return "UP";
        case AKEY_EVENT_ACTION_MULTIPLE:
            return "MULTIPLE";
    }
    return StringPrintf("%" PRId32, action);
}

// --- EventEntry ---

EventEntry::EventEntry(uint32_t sequenceNum, int32_t type, nsecs_t eventTime, uint32_t policyFlags)
      : sequenceNum(sequenceNum),
        refCount(1),
        type(type),
        eventTime(eventTime),
        policyFlags(policyFlags),
        injectionState(nullptr),
        dispatchInProgress(false) {}

EventEntry::~EventEntry() {
    releaseInjectionState();
}

void EventEntry::release() {
    refCount -= 1;
    if (refCount == 0) {
        delete this;
    } else {
        ALOG_ASSERT(refCount > 0);
    }
}

void EventEntry::releaseInjectionState() {
    if (injectionState) {
        injectionState->release();
        injectionState = nullptr;
    }
}

// --- ConfigurationChangedEntry ---

ConfigurationChangedEntry::ConfigurationChangedEntry(uint32_t sequenceNum, nsecs_t eventTime)
      : EventEntry(sequenceNum, TYPE_CONFIGURATION_CHANGED, eventTime, 0) {}

ConfigurationChangedEntry::~ConfigurationChangedEntry() {}

void ConfigurationChangedEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("ConfigurationChangedEvent(), policyFlags=0x%08x", policyFlags);
}

// --- DeviceResetEntry ---

DeviceResetEntry::DeviceResetEntry(uint32_t sequenceNum, nsecs_t eventTime, int32_t deviceId)
      : EventEntry(sequenceNum, TYPE_DEVICE_RESET, eventTime, 0), deviceId(deviceId) {}

DeviceResetEntry::~DeviceResetEntry() {}

void DeviceResetEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("DeviceResetEvent(deviceId=%d), policyFlags=0x%08x", deviceId, policyFlags);
}

// --- KeyEntry ---

KeyEntry::KeyEntry(uint32_t sequenceNum, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                   int32_t displayId, uint32_t policyFlags, int32_t action, int32_t flags,
                   int32_t keyCode, int32_t scanCode, int32_t metaState, int32_t repeatCount,
                   nsecs_t downTime)
      : EventEntry(sequenceNum, TYPE_KEY, eventTime, policyFlags),
        deviceId(deviceId),
        source(source),
        displayId(displayId),
        action(action),
        flags(flags),
        keyCode(keyCode),
        scanCode(scanCode),
        metaState(metaState),
        repeatCount(repeatCount),
        downTime(downTime),
        syntheticRepeat(false),
        interceptKeyResult(KeyEntry::INTERCEPT_KEY_RESULT_UNKNOWN),
        interceptKeyWakeupTime(0) {}

KeyEntry::~KeyEntry() {}

void KeyEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("KeyEvent");
    if (!GetBoolProperty("ro.debuggable", false)) {
        return;
    }
    msg += StringPrintf("(deviceId=%d, source=0x%08x, displayId=%" PRId32 ", action=%s, "
                        "flags=0x%08x, keyCode=%d, scanCode=%d, metaState=0x%08x, "
                        "repeatCount=%d), policyFlags=0x%08x",
                        deviceId, source, displayId, keyActionToString(action).c_str(), flags,
                        keyCode, scanCode, metaState, repeatCount, policyFlags);
}

void KeyEntry::recycle() {
    releaseInjectionState();

    dispatchInProgress = false;
    syntheticRepeat = false;
    interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_UNKNOWN;
    interceptKeyWakeupTime = 0;
}

// --- MotionEntry ---

MotionEntry::MotionEntry(uint32_t sequenceNum, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                         int32_t displayId, uint32_t policyFlags, int32_t action,
                         int32_t actionButton, int32_t flags, int32_t metaState,
                         int32_t buttonState, MotionClassification classification,
                         int32_t edgeFlags, float xPrecision, float yPrecision, nsecs_t downTime,
                         uint32_t pointerCount, const PointerProperties* pointerProperties,
                         const PointerCoords* pointerCoords, float xOffset, float yOffset)
      : EventEntry(sequenceNum, TYPE_MOTION, eventTime, policyFlags),
        eventTime(eventTime),
        deviceId(deviceId),
        source(source),
        displayId(displayId),
        action(action),
        actionButton(actionButton),
        flags(flags),
        metaState(metaState),
        buttonState(buttonState),
        classification(classification),
        edgeFlags(edgeFlags),
        xPrecision(xPrecision),
        yPrecision(yPrecision),
        downTime(downTime),
        pointerCount(pointerCount) {
    for (uint32_t i = 0; i < pointerCount; i++) {
        this->pointerProperties[i].copyFrom(pointerProperties[i]);
        this->pointerCoords[i].copyFrom(pointerCoords[i]);
        if (xOffset || yOffset) {
            this->pointerCoords[i].applyOffset(xOffset, yOffset);
        }
    }
}

MotionEntry::~MotionEntry() {}

void MotionEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("MotionEvent");
    if (!GetBoolProperty("ro.debuggable", false)) {
        return;
    }
    msg += StringPrintf("(deviceId=%d, source=0x%08x, displayId=%" PRId32
                        ", action=%s, actionButton=0x%08x, flags=0x%08x, metaState=0x%08x, "
                        "buttonState=0x%08x, "
                        "classification=%s, edgeFlags=0x%08x, xPrecision=%.1f, yPrecision=%.1f, "
                        "pointers=[",
                        deviceId, source, displayId, motionActionToString(action).c_str(),
                        actionButton, flags, metaState, buttonState,
                        motionClassificationToString(classification), edgeFlags, xPrecision,
                        yPrecision);

    for (uint32_t i = 0; i < pointerCount; i++) {
        if (i) {
            msg += ", ";
        }
        msg += StringPrintf("%d: (%.1f, %.1f)", pointerProperties[i].id, pointerCoords[i].getX(),
                            pointerCoords[i].getY());
    }
    msg += StringPrintf("]), policyFlags=0x%08x", policyFlags);
}

// --- DispatchEntry ---

volatile int32_t DispatchEntry::sNextSeqAtomic;

DispatchEntry::DispatchEntry(EventEntry* eventEntry, int32_t targetFlags, float xOffset,
                             float yOffset, float globalScaleFactor, float windowXScale,
                             float windowYScale)
      : seq(nextSeq()),
        eventEntry(eventEntry),
        targetFlags(targetFlags),
        xOffset(xOffset),
        yOffset(yOffset),
        globalScaleFactor(globalScaleFactor),
        windowXScale(windowXScale),
        windowYScale(windowYScale),
        deliveryTime(0),
        resolvedAction(0),
        resolvedFlags(0) {
    eventEntry->refCount += 1;
}

DispatchEntry::~DispatchEntry() {
    eventEntry->release();
}

uint32_t DispatchEntry::nextSeq() {
    // Sequence number 0 is reserved and will never be returned.
    uint32_t seq;
    do {
        seq = android_atomic_inc(&sNextSeqAtomic);
    } while (!seq);
    return seq;
}

// --- CommandEntry ---

CommandEntry::CommandEntry(Command command)
      : command(command),
        eventTime(0),
        keyEntry(nullptr),
        userActivityEventType(0),
        seq(0),
        handled(false) {}

CommandEntry::~CommandEntry() {}

} // namespace android::inputdispatcher
