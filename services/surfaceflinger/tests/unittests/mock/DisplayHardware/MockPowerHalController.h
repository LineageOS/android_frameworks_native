/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <scheduler/Time.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <powermanager/PowerHalController.h>
#pragma clang diagnostic pop

namespace android {
namespace hardware {
namespace power {
class IPower;
}
} // namespace hardware
} // namespace android

namespace android::Hwc2::mock {

using android::power::HalResult;

class MockPowerHalController : public power::PowerHalController {
public:
    MockPowerHalController();
    ~MockPowerHalController() override;
    MOCK_METHOD(void, init, (), (override));
    MOCK_METHOD(HalResult<void>, setBoost, (aidl::android::hardware::power::Boost, int32_t),
                (override));
    MOCK_METHOD(HalResult<void>, setMode, (aidl::android::hardware::power::Mode, bool), (override));
    MOCK_METHOD(HalResult<std::shared_ptr<android::power::PowerHintSessionWrapper>>,
                createHintSession, (int32_t, int32_t, const std::vector<int32_t>&, int64_t),
                (override));
    MOCK_METHOD(HalResult<std::shared_ptr<android::power::PowerHintSessionWrapper>>,
                createHintSessionWithConfig,
                (int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                 int64_t durationNanos, aidl::android::hardware::power::SessionTag tag,
                 aidl::android::hardware::power::SessionConfig* config),
                (override));
    MOCK_METHOD(HalResult<int64_t>, getHintSessionPreferredRate, (), (override));
    MOCK_METHOD(HalResult<aidl::android::hardware::power::ChannelConfig>, getSessionChannel,
                (int tgid, int uid), (override));
    MOCK_METHOD(HalResult<void>, closeSessionChannel, (int tgid, int uid), (override));
};

} // namespace android::Hwc2::mock