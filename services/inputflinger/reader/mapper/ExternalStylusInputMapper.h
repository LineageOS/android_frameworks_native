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

#include "InputMapper.h"

#include "SingleTouchMotionAccumulator.h"
#include "StylusState.h"
#include "TouchButtonAccumulator.h"

namespace android {

class ExternalStylusInputMapper : public InputMapper {
public:
    explicit ExternalStylusInputMapper(InputDeviceContext& deviceContext,
                                       const InputReaderConfiguration& readerConfig);
    virtual ~ExternalStylusInputMapper() = default;

    uint32_t getSources() const override;
    void populateDeviceInfo(InputDeviceInfo& deviceInfo) override;
    void dump(std::string& dump) override;
    [[nodiscard]] std::list<NotifyArgs> reconfigure(nsecs_t when,
                                                    const InputReaderConfiguration& config,
                                                    ConfigurationChanges changes) override;
    [[nodiscard]] std::list<NotifyArgs> reset(nsecs_t when) override;
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent* rawEvent) override;

private:
    SingleTouchMotionAccumulator mSingleTouchMotionAccumulator;
    RawAbsoluteAxisInfo mRawPressureAxis;
    TouchButtonAccumulator mTouchButtonAccumulator;

    StylusState mStylusState;

    [[nodiscard]] std::list<NotifyArgs> sync(nsecs_t when);
};

} // namespace android
