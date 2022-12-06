/*
 * Copyright 2022 The Android Open Source Project
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

#include <memory>

#include "EventHub.h"
#include "InputDevice.h"
#include "InputMapper.h"
#include "NotifyArgs.h"
#include "accumulator/CursorButtonAccumulator.h"
#include "accumulator/MultiTouchMotionAccumulator.h"
#include "accumulator/TouchButtonAccumulator.h"

#include "include/gestures.h"

namespace android {

class TouchpadInputMapper : public InputMapper {
public:
    explicit TouchpadInputMapper(InputDeviceContext& deviceContext);

    uint32_t getSources() const override;
    [[nodiscard]] std::list<NotifyArgs> reset(nsecs_t when) override;
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent* rawEvent) override;

private:
    void sync(nsecs_t when);

    std::unique_ptr<gestures::GestureInterpreter, void (*)(gestures::GestureInterpreter*)>
            mGestureInterpreter;

    CursorButtonAccumulator mCursorButtonAccumulator;
    MultiTouchMotionAccumulator mMotionAccumulator;
    TouchButtonAccumulator mTouchButtonAccumulator;
    int32_t mMscTimestamp = 0;
};

} // namespace android
