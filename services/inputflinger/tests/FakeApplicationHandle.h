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

#include <android-base/properties.h>
#include <android/os/IInputConstants.h>
#include <gui/InputApplication.h>

namespace android {

namespace inputdispatcher {

class FakeApplicationHandle : public InputApplicationHandle {
public:
    FakeApplicationHandle() {
        static const std::chrono::duration DISPATCHING_TIMEOUT = std::chrono::milliseconds(
                android::os::IInputConstants::UNMULTIPLIED_DEFAULT_DISPATCHING_TIMEOUT_MILLIS *
                android::base::HwTimeoutMultiplier());
        mInfo.name = "Fake Application";
        mInfo.token = sp<BBinder>::make();
        mInfo.dispatchingTimeoutMillis =
                std::chrono::duration_cast<std::chrono::milliseconds>(DISPATCHING_TIMEOUT).count();
    }
    virtual ~FakeApplicationHandle() {}

    bool updateInfo() override { return true; }

    void setDispatchingTimeout(std::chrono::milliseconds timeout) {
        mInfo.dispatchingTimeoutMillis = timeout.count();
    }
};

} // namespace inputdispatcher
} // namespace android
