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

class VibratorInputMapper : public InputMapper {
public:
    template <class T, class... Args>
    friend std::unique_ptr<T> createInputMapper(InputDeviceContext& deviceContext,
                                                const InputReaderConfiguration& readerConfig,
                                                Args... args);
    virtual ~VibratorInputMapper();

    virtual uint32_t getSources() const override;
    virtual void populateDeviceInfo(InputDeviceInfo& deviceInfo) override;
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent& rawEvent) override;

    [[nodiscard]] std::list<NotifyArgs> vibrate(const VibrationSequence& sequence, ssize_t repeat,
                                                int32_t token) override;
    [[nodiscard]] std::list<NotifyArgs> cancelVibrate(int32_t token) override;
    virtual bool isVibrating() override;
    virtual std::vector<int32_t> getVibratorIds() override;
    [[nodiscard]] std::list<NotifyArgs> timeoutExpired(nsecs_t when) override;
    virtual void dump(std::string& dump) override;

private:
    bool mVibrating;
    VibrationSequence mSequence;
    ssize_t mRepeat;
    int32_t mToken;
    ssize_t mIndex;
    nsecs_t mNextStepTime;

    explicit VibratorInputMapper(InputDeviceContext& deviceContext,
                                 const InputReaderConfiguration& readerConfig);
    [[nodiscard]] std::list<NotifyArgs> nextStep();
    [[nodiscard]] NotifyVibratorStateArgs stopVibrating();
};

} // namespace android
