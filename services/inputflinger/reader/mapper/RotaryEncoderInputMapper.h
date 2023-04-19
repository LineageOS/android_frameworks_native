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

#include <ui/Rotation.h>

#include "CursorScrollAccumulator.h"
#include "InputMapper.h"

namespace android {

class RotaryEncoderInputMapper : public InputMapper {
public:
    explicit RotaryEncoderInputMapper(InputDeviceContext& deviceContext,
                                      const InputReaderConfiguration& readerConfig);
    virtual ~RotaryEncoderInputMapper();

    virtual uint32_t getSources() const override;
    virtual void populateDeviceInfo(InputDeviceInfo& deviceInfo) override;
    virtual void dump(std::string& dump) override;
    [[nodiscard]] std::list<NotifyArgs> reconfigure(nsecs_t when,
                                                    const InputReaderConfiguration& config,
                                                    ConfigurationChanges changes) override;
    [[nodiscard]] std::list<NotifyArgs> reset(nsecs_t when) override;
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent* rawEvent) override;

private:
    CursorScrollAccumulator mRotaryEncoderScrollAccumulator;

    int32_t mSource;
    float mScalingFactor;
    ui::Rotation mOrientation;

    [[nodiscard]] std::list<NotifyArgs> sync(nsecs_t when, nsecs_t readTime);
};

} // namespace android
