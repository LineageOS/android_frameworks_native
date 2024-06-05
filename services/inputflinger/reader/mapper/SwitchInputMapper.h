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

namespace android {

class SwitchInputMapper : public InputMapper {
public:
    template <class T, class... Args>
    friend std::unique_ptr<T> createInputMapper(InputDeviceContext& deviceContext,
                                                const InputReaderConfiguration& readerConfig,
                                                Args... args);
    virtual ~SwitchInputMapper();

    virtual uint32_t getSources() const override;
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent& rawEvent) override;

    virtual int32_t getSwitchState(uint32_t sourceMask, int32_t switchCode) override;
    virtual void dump(std::string& dump) override;

private:
    uint32_t mSwitchValues;
    uint32_t mUpdatedSwitchMask;

    explicit SwitchInputMapper(InputDeviceContext& deviceContext,
                               const InputReaderConfiguration& readerConfig);
    void processSwitch(int32_t switchCode, int32_t switchValue);
    [[nodiscard]] std::list<NotifyArgs> sync(nsecs_t when);
};

} // namespace android
