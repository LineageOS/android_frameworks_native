/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "InputListener.h"

#include <aidl/android/hardware/input/common/Axis.h>
#include <aidl/android/hardware/input/common/MotionEvent.h>
#include <input/Input.h>

namespace android {

/** Convert from framework's NotifyMotionArgs to hidl's common::MotionEvent. */
::aidl::android::hardware::input::common::MotionEvent notifyMotionArgsToHalMotionEvent(
        const NotifyMotionArgs& args);

/** Convert from NotifyMotionArgs to MotionEvent. */
MotionEvent toMotionEvent(const NotifyMotionArgs&, const ui::Transform* transform = nullptr,
                          const ui::Transform* rawTransform = nullptr,
                          const std::array<uint8_t, 32>* hmac = nullptr);

/** Convert from NotifyKeyArgs to KeyEvent. */
KeyEvent toKeyEvent(const NotifyKeyArgs&, int32_t repeatCount = 0,
                    const std::array<uint8_t, 32>* hmac = nullptr);

} // namespace android
