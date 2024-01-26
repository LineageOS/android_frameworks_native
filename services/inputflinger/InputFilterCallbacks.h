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

#pragma once

#include <aidl/com/android/server/inputflinger/IInputFlingerRust.h>
#include <android/binder_auto_utils.h>
#include <utils/Mutex.h>
#include <memory>
#include <mutex>
#include "InputFilterPolicyInterface.h"
#include "InputListener.h"
#include "NotifyArgs.h"

/**
 * The C++ component of InputFilter designed as a wrapper around the rust callback implementation.
 */
namespace android {

using IInputFilter = aidl::com::android::server::inputflinger::IInputFilter;
using AidlKeyEvent = aidl::com::android::server::inputflinger::KeyEvent;
using aidl::com::android::server::inputflinger::IInputThread;
using IInputThreadCallback =
        aidl::com::android::server::inputflinger::IInputThread::IInputThreadCallback;

class InputFilterCallbacks : public IInputFilter::BnInputFilterCallbacks {
public:
    explicit InputFilterCallbacks(InputListenerInterface& listener,
                                  InputFilterPolicyInterface& policy);
    ~InputFilterCallbacks() override = default;

    uint32_t getModifierState();
    uint32_t getLockedModifierState();

private:
    InputListenerInterface& mNextListener;
    InputFilterPolicyInterface& mPolicy;
    mutable std::mutex mLock;
    struct StickyModifierState {
        uint32_t modifierState;
        uint32_t lockedModifierState;
    } mStickyModifierState GUARDED_BY(mLock);

    ndk::ScopedAStatus sendKeyEvent(const AidlKeyEvent& event) override;
    ndk::ScopedAStatus onModifierStateChanged(int32_t modifierState,
                                              int32_t lockedModifierState) override;
    ndk::ScopedAStatus createInputFilterThread(
            const std::shared_ptr<IInputThreadCallback>& callback,
            std::shared_ptr<IInputThread>* aidl_return) override;
};

} // namespace android