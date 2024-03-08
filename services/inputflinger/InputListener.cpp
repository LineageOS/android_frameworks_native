/*
 * Copyright (C) 2011 The Android Open Source Project
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

#define LOG_TAG "InputListener"

#define ATRACE_TAG ATRACE_TAG_INPUT

//#define LOG_NDEBUG 0

#include "InputListener.h"

#include <android-base/stringprintf.h>
#include <android/log.h>
#include <input/TraceTools.h>

using android::base::StringPrintf;

namespace android {

std::list<NotifyArgs>& operator+=(std::list<NotifyArgs>& keep, std::list<NotifyArgs>&& consume) {
    keep.splice(keep.end(), consume);
    return keep;
}

// --- InputListenerInterface ---

// Helper to std::visit with lambdas.
template <typename... V>
struct Visitor : V... { using V::operator()...; };
// explicit deduction guide (not needed as of C++20)
template <typename... V>
Visitor(V...) -> Visitor<V...>;

void InputListenerInterface::notify(const NotifyArgs& generalArgs) {
    Visitor v{
            [&](const NotifyInputDevicesChangedArgs& args) { notifyInputDevicesChanged(args); },
            [&](const NotifyConfigurationChangedArgs& args) { notifyConfigurationChanged(args); },
            [&](const NotifyKeyArgs& args) { notifyKey(args); },
            [&](const NotifyMotionArgs& args) { notifyMotion(args); },
            [&](const NotifySwitchArgs& args) { notifySwitch(args); },
            [&](const NotifySensorArgs& args) { notifySensor(args); },
            [&](const NotifyVibratorStateArgs& args) { notifyVibratorState(args); },
            [&](const NotifyDeviceResetArgs& args) { notifyDeviceReset(args); },
            [&](const NotifyPointerCaptureChangedArgs& args) { notifyPointerCaptureChanged(args); },
    };
    std::visit(v, generalArgs);
}

// --- QueuedInputListener ---

QueuedInputListener::QueuedInputListener(InputListenerInterface& innerListener)
      : mInnerListener(innerListener) {}

void QueuedInputListener::notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::notifyKey(const NotifyKeyArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::notifyMotion(const NotifyMotionArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::notifySwitch(const NotifySwitchArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::notifySensor(const NotifySensorArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::notifyVibratorState(const NotifyVibratorStateArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) {
    mArgsQueue.emplace_back(args);
}

void QueuedInputListener::flush() {
    for (const NotifyArgs& args : mArgsQueue) {
        mInnerListener.notify(args);
    }
    mArgsQueue.clear();
}

// --- TracedInputListener ---

TracedInputListener::TracedInputListener(const char* name, InputListenerInterface& innerListener)
      : mInnerListener(innerListener), mName(name) {}

void TracedInputListener::notifyInputDevicesChanged(const NotifyInputDevicesChangedArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

void TracedInputListener::notifyConfigurationChanged(const NotifyConfigurationChangedArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

void TracedInputListener::notifyKey(const NotifyKeyArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

void TracedInputListener::notifyMotion(const NotifyMotionArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

void TracedInputListener::notifySwitch(const NotifySwitchArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

void TracedInputListener::notifySensor(const NotifySensorArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

void TracedInputListener::notifyVibratorState(const NotifyVibratorStateArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

void TracedInputListener::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

void TracedInputListener::notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs& args) {
    constexpr static auto& fnName = __func__;
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("%s::%s(id=0x%" PRIx32 ")", mName, fnName, args.id));
    mInnerListener.notify(args);
}

} // namespace android
