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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include "DisplayTransactionTestHelpers.h"

namespace android {

using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;

class NotifyExpectedPresentTest : public DisplayTransactionTest {
public:
    void SetUp() override {
        mDisplay = PrimaryDisplayVariant::makeFakeExistingDisplayInjector(this).inject();
        FakeHwcDisplayInjector(mDisplay->getPhysicalId(), hal::DisplayType::PHYSICAL, kIsPrimary)
                .setPowerMode(hal::PowerMode::ON)
                .inject(&mFlinger, mComposer);
    }

protected:
    sp<DisplayDevice> mDisplay;
    static constexpr bool kIsPrimary = true;
    static constexpr hal::HWDisplayId HWC_DISPLAY_ID =
            FakeHwcDisplayInjector::DEFAULT_HWC_DISPLAY_ID;
};

TEST_F(NotifyExpectedPresentTest, notifyExpectedPresentTimeout) {
    const auto physicDisplayId = mDisplay->getPhysicalId();
    auto expectedPresentTime = systemTime() + ms2ns(10);
    static constexpr Fps kFps60Hz = 60_Hz;
    static constexpr int32_t kFrameInterval5HzNs = static_cast<Fps>(5_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameInterval60HzNs = kFps60Hz.getPeriodNsecs();
    static constexpr int32_t kFrameInterval120HzNs = static_cast<Fps>(120_Hz).getPeriodNsecs();
    static constexpr Period kVsyncPeriod =
            Period::fromNs(static_cast<Fps>(240_Hz).getPeriodNsecs());
    static constexpr Period kTimeoutNs = Period::fromNs(kFrameInterval5HzNs);
    static constexpr auto kLastExpectedPresentTimestamp = TimePoint::fromNs(0);

    ASSERT_NO_FATAL_FAILURE(mFlinger.setNotifyExpectedPresentData(physicDisplayId,
                                                                  kLastExpectedPresentTimestamp,
                                                                  kFps60Hz));

    {
        // Very first ExpectedPresent after idle, no previous timestamp
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(HWC_DISPLAY_ID, expectedPresentTime,
                                          kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(physicDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
    }
    {
        // Absent timeoutNs
        expectedPresentTime += 2 * kFrameInterval5HzNs;
        EXPECT_CALL(*mComposer, notifyExpectedPresent(HWC_DISPLAY_ID, _, _)).Times(0);
        mFlinger.notifyExpectedPresentIfRequired(physicDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 /*timeoutOpt*/ std::nullopt);
    }
    {
        // Timeout is 0
        expectedPresentTime += kFrameInterval60HzNs;
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(HWC_DISPLAY_ID, expectedPresentTime,
                                          kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(physicDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 Period::fromNs(0));
    }
    {
        // ExpectedPresent is after the timeoutNs
        expectedPresentTime += 2 * kFrameInterval5HzNs;
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(HWC_DISPLAY_ID, expectedPresentTime,
                                          kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(physicDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
    }
    {
        // ExpectedPresent has not changed
        EXPECT_CALL(*mComposer, notifyExpectedPresent(HWC_DISPLAY_ID, _, _)).Times(0);
        mFlinger.notifyExpectedPresentIfRequired(physicDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
    }
    {
        // ExpectedPresent is after the last reported ExpectedPresent.
        expectedPresentTime += kFrameInterval60HzNs;
        EXPECT_CALL(*mComposer, notifyExpectedPresent(HWC_DISPLAY_ID, _, _)).Times(0);
        mFlinger.notifyExpectedPresentIfRequired(physicDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
    }
    {
        // ExpectedPresent is before the last reported ExpectedPresent but after the timeoutNs,
        // representing we changed our decision and want to present earlier than previously
        // reported.
        expectedPresentTime -= kFrameInterval120HzNs;
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(HWC_DISPLAY_ID, expectedPresentTime,
                                          kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(physicDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
    }
}

TEST_F(NotifyExpectedPresentTest, notifyExpectedPresentRenderRateChanged) {
    const auto physicDisplayId = mDisplay->getPhysicalId();
    const auto now = systemTime();
    auto expectedPresentTime = now;
    static constexpr Period kTimeoutNs = Period::fromNs(static_cast<Fps>(1_Hz).getPeriodNsecs());

    ASSERT_NO_FATAL_FAILURE(mFlinger.setNotifyExpectedPresentData(physicDisplayId,
                                                                  TimePoint::fromNs(now),
                                                                  Fps::fromValue(0)));
    static constexpr int32_t kFrameIntervalNs120Hz = static_cast<Fps>(120_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameIntervalNs96Hz = static_cast<Fps>(96_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameIntervalNs80Hz = static_cast<Fps>(80_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameIntervalNs60Hz = static_cast<Fps>(60_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameIntervalNs40Hz = static_cast<Fps>(40_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameIntervalNs30Hz = static_cast<Fps>(30_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameIntervalNs24Hz = static_cast<Fps>(24_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameIntervalNs20Hz = static_cast<Fps>(20_Hz).getPeriodNsecs();
    static constexpr Period kVsyncPeriod =
            Period::fromNs(static_cast<Fps>(240_Hz).getPeriodNsecs());

    struct FrameRateIntervalTestData {
        int32_t frameIntervalNs;
        bool callExpectedPresent;
    };
    const std::vector<FrameRateIntervalTestData> frameIntervals = {
            {kFrameIntervalNs60Hz, true},  {kFrameIntervalNs96Hz, true},
            {kFrameIntervalNs80Hz, true},  {kFrameIntervalNs120Hz, true},
            {kFrameIntervalNs80Hz, true},  {kFrameIntervalNs60Hz, true},
            {kFrameIntervalNs60Hz, false}, {kFrameIntervalNs30Hz, false},
            {kFrameIntervalNs24Hz, true},  {kFrameIntervalNs40Hz, true},
            {kFrameIntervalNs20Hz, false}, {kFrameIntervalNs60Hz, true},
            {kFrameIntervalNs20Hz, false}, {kFrameIntervalNs120Hz, true},
    };

    for (const auto& [frameIntervalNs, callExpectedPresent] : frameIntervals) {
        {
            expectedPresentTime += frameIntervalNs;
            if (callExpectedPresent) {
                EXPECT_CALL(*mComposer,
                            notifyExpectedPresent(HWC_DISPLAY_ID, expectedPresentTime,
                                                  frameIntervalNs))
                        .WillOnce(Return(Error::NONE));
            } else {
                EXPECT_CALL(*mComposer, notifyExpectedPresent(HWC_DISPLAY_ID, _, _)).Times(0);
            }
            mFlinger.notifyExpectedPresentIfRequired(physicDisplayId, kVsyncPeriod,
                                                     TimePoint::fromNs(expectedPresentTime),
                                                     Fps::fromPeriodNsecs(frameIntervalNs),
                                                     kTimeoutNs);
        }
    }
}
} // namespace android