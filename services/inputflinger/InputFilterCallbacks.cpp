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
#include <utils/StrongPointer.h>
#include <utils/Thread.h>
#include <functional>

namespace android {

using AidlKeyEvent = aidl::com::android::server::inputflinger::KeyEvent;

NotifyKeyArgs keyEventToNotifyKeyArgs(const AidlKeyEvent& event) {
    return NotifyKeyArgs(event.id, event.eventTime, event.readTime, event.deviceId,
                         static_cast<uint32_t>(event.source), event.displayId, event.policyFlags,
                         static_cast<int32_t>(event.action), event.flags, event.keyCode,
                         event.scanCode, event.metaState, event.downTime);
}

namespace {

using namespace aidl::com::android::server::inputflinger;

class InputFilterThreadImpl : public Thread {
public:
    explicit InputFilterThreadImpl(std::function<void()> loop)
          : Thread(/*canCallJava=*/true), mThreadLoop(loop) {}

    ~InputFilterThreadImpl() {}

private:
    std::function<void()> mThreadLoop;

    bool threadLoop() override {
        mThreadLoop();
        return true;
    }
};

class InputFilterThread : public BnInputThread {
public:
    InputFilterThread(std::shared_ptr<IInputThreadCallback> callback) : mCallback(callback) {
        mThread = sp<InputFilterThreadImpl>::make([this]() { loopOnce(); });
        mThread->run("InputFilterThread", ANDROID_PRIORITY_URGENT_DISPLAY);
    }

    ndk::ScopedAStatus finish() override {
        mThread->requestExit();
        return ndk::ScopedAStatus::ok();
    }

private:
    sp<Thread> mThread;
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
