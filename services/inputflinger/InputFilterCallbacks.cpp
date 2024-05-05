/*
 * Copyright 2023 The Android Open Source Project
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

#define LOG_TAG "InputFilterCallbacks"

#include "InputFilterCallbacks.h"
#include <aidl/com/android/server/inputflinger/BnInputThread.h>
#include <android/binder_auto_utils.h>
#include <utils/Looper.h>
#include <utils/StrongPointer.h>
#include <functional>
#include "InputThread.h"

namespace android {

using AidlKeyEvent = aidl::com::android::server::inputflinger::KeyEvent;

NotifyKeyArgs keyEventToNotifyKeyArgs(const AidlKeyEvent& event) {
    return NotifyKeyArgs(event.id, event.eventTime, event.readTime, event.deviceId,
                         static_cast<uint32_t>(event.source), ui::LogicalDisplayId{event.displayId},
                         event.policyFlags, static_cast<int32_t>(event.action), event.flags,
                         event.keyCode, event.scanCode, event.metaState, event.downTime);
}

namespace {

using namespace aidl::com::android::server::inputflinger;

class InputFilterThread : public BnInputThread {
public:
    InputFilterThread(std::shared_ptr<IInputThreadCallback> callback) : mCallback(callback) {
        mLooper = sp<Looper>::make(/*allowNonCallbacks=*/false);
        mThread = std::make_unique<InputThread>(
                "InputFilter", [this]() { loopOnce(); }, [this]() { mLooper->wake(); });
    }

    ndk::ScopedAStatus finish() override {
        if (mThread && mThread->isCallingThread()) {
            ALOGE("InputFilterThread cannot be stopped on itself!");
            return ndk::ScopedAStatus::fromStatus(INVALID_OPERATION);
        }
        mThread.reset();
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus sleepUntil(nsecs_t when) override {
        nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
        mLooper->pollOnce(toMillisecondTimeoutDelay(now, when));
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus wake() override {
        mLooper->wake();
        return ndk::ScopedAStatus::ok();
    }

private:
    sp<Looper> mLooper;
    std::unique_ptr<InputThread> mThread;
    std::shared_ptr<IInputThreadCallback> mCallback;

    void loopOnce() { LOG_ALWAYS_FATAL_IF(!mCallback->loopOnce().isOk()); }
};

} // namespace

InputFilterCallbacks::InputFilterCallbacks(InputListenerInterface& listener,
                                           InputFilterPolicyInterface& policy)
      : mNextListener(listener), mPolicy(policy) {}

ndk::ScopedAStatus InputFilterCallbacks::sendKeyEvent(const AidlKeyEvent& event) {
    mNextListener.notifyKey(keyEventToNotifyKeyArgs(event));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus InputFilterCallbacks::onModifierStateChanged(int32_t modifierState,
                                                                int32_t lockedModifierState) {
    std::scoped_lock _l(mLock);
    mStickyModifierState.modifierState = modifierState;
    mStickyModifierState.lockedModifierState = lockedModifierState;
    mPolicy.notifyStickyModifierStateChanged(modifierState, lockedModifierState);
    ALOGI("Sticky keys modifier state changed: modifierState=%d, lockedModifierState=%d",
          modifierState, lockedModifierState);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus InputFilterCallbacks::createInputFilterThread(
        const std::shared_ptr<IInputThreadCallback>& callback,
        std::shared_ptr<IInputThread>* aidl_return) {
    *aidl_return = ndk::SharedRefBase::make<InputFilterThread>(callback);
    return ndk::ScopedAStatus::ok();
}

uint32_t InputFilterCallbacks::getModifierState() {
    std::scoped_lock _l(mLock);
    return mStickyModifierState.modifierState;
}

uint32_t InputFilterCallbacks::getLockedModifierState() {
    std::scoped_lock _l(mLock);
    return mStickyModifierState.lockedModifierState;
}

} // namespace android
