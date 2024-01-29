/*
 * Copyright 2019 The Android Open Source Project
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

#include "TimeStats/TimeStats.h"

namespace android::mock {

class TimeStats : public android::TimeStats {
public:
    TimeStats();
    ~TimeStats() override;

    MOCK_METHOD2(onPullAtom, bool(const int, std::vector<uint8_t>*));
    MOCK_METHOD3(parseArgs, void(bool, const Vector<String16>&, std::string&));
    MOCK_METHOD0(isEnabled, bool());
    MOCK_METHOD0(miniDump, std::string());
    MOCK_METHOD0(incrementTotalFrames, void());
    MOCK_METHOD0(incrementMissedFrames, void());
    MOCK_METHOD0(incrementRefreshRateSwitches, void());
    MOCK_METHOD2(recordFrameDuration, void(nsecs_t, nsecs_t));
    MOCK_METHOD2(recordRenderEngineDuration, void(nsecs_t, nsecs_t));
    MOCK_METHOD2(recordRenderEngineDuration, void(nsecs_t, const std::shared_ptr<FenceTime>&));
    MOCK_METHOD(void, setPostTime,
                (int32_t, uint64_t, const std::string&, uid_t, nsecs_t, GameMode), (override));
    MOCK_METHOD2(incrementLatchSkipped, void(int32_t layerId, LatchSkipReason reason));
    MOCK_METHOD1(incrementBadDesiredPresent, void(int32_t layerId));
    MOCK_METHOD3(setLatchTime, void(int32_t, uint64_t, nsecs_t));
    MOCK_METHOD3(setDesiredTime, void(int32_t, uint64_t, nsecs_t));
    MOCK_METHOD3(setAcquireTime, void(int32_t, uint64_t, nsecs_t));
    MOCK_METHOD3(setAcquireFence, void(int32_t, uint64_t, const std::shared_ptr<FenceTime>&));
    MOCK_METHOD(void, setPresentTime,
                (int32_t, uint64_t, nsecs_t, Fps, std::optional<Fps>, SetFrameRateVote, GameMode),
                (override));
    MOCK_METHOD(void, setPresentFence,
                (int32_t, uint64_t, const std::shared_ptr<FenceTime>&, Fps, std::optional<Fps>,
                 SetFrameRateVote, GameMode),
                (override));
    MOCK_METHOD1(incrementJankyFrames, void(const JankyFramesInfo&));
    MOCK_METHOD1(onDestroy, void(int32_t));
    MOCK_METHOD2(removeTimeRecord, void(int32_t, uint64_t));
    MOCK_METHOD1(setPowerMode,
                 void(hardware::graphics::composer::V2_4::IComposerClient::PowerMode));
    MOCK_METHOD2(recordRefreshRate, void(uint32_t, nsecs_t));
    MOCK_METHOD1(setPresentFenceGlobal, void(const std::shared_ptr<FenceTime>&));
    MOCK_METHOD(void, pushCompositionStrategyState,
                (const android::TimeStats::ClientCompositionRecord&), (override));
};

} // namespace android::mock
