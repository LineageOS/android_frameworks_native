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

#include <ftl/optional.h>
#include <gtest/gtest.h>

#include <common/test/FlagUtils.h>
#include <scheduler/Fps.h>
#include <scheduler/FrameTargeter.h>
#include <scheduler/IVsyncSource.h>

#include <com_android_graphics_surfaceflinger_flags.h>

using namespace std::chrono_literals;

namespace android::scheduler {
namespace {

struct VsyncSource final : IVsyncSource {
    VsyncSource(Period period, Period minFramePeriod, TimePoint deadline)
          : vsyncPeriod(period), framePeriod(minFramePeriod), vsyncDeadline(deadline) {}

    const Period vsyncPeriod;
    const Period framePeriod;
    const TimePoint vsyncDeadline;

    Period period() const override { return vsyncPeriod; }
    TimePoint vsyncDeadlineAfter(TimePoint, ftl::Optional<TimePoint> = {}) const override {
        return vsyncDeadline;
    }
    Period minFramePeriod() const override { return framePeriod; }
};

} // namespace

class FrameTargeterTestBase : public testing::Test {
public:
    FrameTargeterTestBase(FeatureFlags flags) : mTargeter(PhysicalDisplayId::fromPort(13), flags) {}

    const auto& target() const { return mTargeter.target(); }

    bool wouldPresentEarly(Period minFramePeriod) const {
        return target().wouldPresentEarly(minFramePeriod);
    }

    struct Frame {
        Frame(FrameTargeterTestBase* testPtr, VsyncId vsyncId, TimePoint& frameBeginTime,
              Duration frameDuration, Fps refreshRate, Fps peakRefreshRate,
              FrameTargeter::IsFencePendingFuncPtr isFencePendingFuncPtr = Frame::fenceSignaled,
              const ftl::Optional<VsyncSource>& vsyncSourceOpt = std::nullopt)
              : testPtr(testPtr),
                frameBeginTime(frameBeginTime),
                period(refreshRate.getPeriod()),
                minFramePeriod(peakRefreshRate.getPeriod()) {
            const FrameTargeter::BeginFrameArgs args{.frameBeginTime = frameBeginTime,
                                                     .vsyncId = vsyncId,
                                                     .expectedVsyncTime =
                                                             frameBeginTime + frameDuration,
                                                     .sfWorkDuration = 10ms,
                                                     .hwcMinWorkDuration = kHwcMinWorkDuration};

            testPtr->mTargeter.beginFrame(args,
                                          vsyncSourceOpt
                                                  .or_else([&] {
                                                      return std::make_optional(
                                                              VsyncSource(period, period,
                                                                          args.expectedVsyncTime));
                                                  })
                                                  .value(),
                                          isFencePendingFuncPtr);
        }

        FenceTimePtr end(CompositionCoverage coverage = CompositionCoverage::Hwc) {
            if (ended) return nullptr;
            ended = true;

            auto [fence, fenceTime] = testPtr->mFenceMap.makePendingFenceForTest();
            testPtr->mTargeter.setPresentFence(std::move(fence), fenceTime);

            testPtr->mTargeter.endFrame({.compositionCoverage = coverage});
            return fenceTime;
        }

        ~Frame() {
            end();
            frameBeginTime += period;
        }

        static bool fencePending(const FenceTimePtr&, int) { return true; }
        static bool fenceSignaled(const FenceTimePtr&, int) { return false; }

        FrameTargeterTestBase* const testPtr;

        TimePoint& frameBeginTime;
        const Period period;
        const Period minFramePeriod;

        bool ended = false;
    };

    static constexpr Duration kHwcMinWorkDuration = std::chrono::nanoseconds(5ns);

private:
    FenceToFenceTimeMap mFenceMap;

    FrameTargeter mTargeter;
};

class FrameTargeterTest : public FrameTargeterTestBase {
public:
    FrameTargeterTest() : FrameTargeterTestBase(Feature::kBackpressureGpuComposition) {}
};

class FrameTargeterWithExpectedPresentSupportTest : public FrameTargeterTestBase {
public:
    FrameTargeterWithExpectedPresentSupportTest()
          : FrameTargeterTestBase(FeatureFlags(Feature::kBackpressureGpuComposition) |
                                  Feature::kExpectedPresentTime) {}
};

TEST_F(FrameTargeterTest, targetsFrames) {
    VsyncId vsyncId{42};
    {
        TimePoint frameBeginTime(989ms);
        const Frame frame(this, vsyncId++, frameBeginTime, 10ms, 60_Hz, 60_Hz);

        EXPECT_EQ(target().vsyncId(), VsyncId{42});
        EXPECT_EQ(target().frameBeginTime(), TimePoint(989ms));
        EXPECT_EQ(target().expectedPresentTime(), TimePoint(999ms));
        EXPECT_EQ(target().expectedFrameDuration(), 10ms);
    }
    {
        TimePoint frameBeginTime(1100ms);
        const Frame frame(this, vsyncId++, frameBeginTime, 11ms, 60_Hz, 60_Hz);

        EXPECT_EQ(target().vsyncId(), VsyncId{43});
        EXPECT_EQ(target().frameBeginTime(), TimePoint(1100ms));
        EXPECT_EQ(target().expectedPresentTime(), TimePoint(1111ms));
        EXPECT_EQ(target().expectedFrameDuration(), 11ms);
    }
}

TEST_F(FrameTargeterTest, inflatesExpectedPresentTime) {
    // Negative such that `expectedVsyncTime` is in the past.
    constexpr Duration kFrameDuration = -3ms;
    TimePoint frameBeginTime(777ms);

    constexpr Fps kRefreshRate = 120_Hz;
    const VsyncSource vsyncSource(kRefreshRate.getPeriod(), kRefreshRate.getPeriod(),
                                  frameBeginTime + 5ms);
    const Frame frame(this, VsyncId{123}, frameBeginTime, kFrameDuration, kRefreshRate,
                      kRefreshRate, Frame::fenceSignaled, vsyncSource);

    EXPECT_EQ(target().expectedPresentTime(), vsyncSource.vsyncDeadline + vsyncSource.vsyncPeriod);
}

TEST_F(FrameTargeterTest, recallsPastVsync) {
    VsyncId vsyncId{111};
    TimePoint frameBeginTime(1000ms);
    constexpr Fps kRefreshRate = 60_Hz;
    constexpr Period kPeriod = kRefreshRate.getPeriod();
    constexpr Duration kFrameDuration = 13ms;

    for (int n = 5; n-- > 0;) {
        Frame frame(this, vsyncId++, frameBeginTime, kFrameDuration, kRefreshRate, kRefreshRate);
        const auto fence = frame.end();

        EXPECT_EQ(target().pastVsyncTime(kPeriod), frameBeginTime + kFrameDuration - kPeriod);
        EXPECT_EQ(target().presentFenceForPastVsync(kPeriod), fence);
    }
}

TEST_F(FrameTargeterTest, recallsPastVsyncTwoVsyncsAhead) {
    VsyncId vsyncId{222};
    TimePoint frameBeginTime(2000ms);
    constexpr Fps kRefreshRate = 120_Hz;
    constexpr Period kPeriod = kRefreshRate.getPeriod();
    constexpr Duration kFrameDuration = 10ms;

    FenceTimePtr previousFence = FenceTime::NO_FENCE;

    for (int n = 5; n-- > 0;) {
        Frame frame(this, vsyncId++, frameBeginTime, kFrameDuration, kRefreshRate, kRefreshRate);
        const auto fence = frame.end();

        EXPECT_EQ(target().pastVsyncTime(kPeriod), frameBeginTime + kFrameDuration - 2 * kPeriod);
        EXPECT_EQ(target().presentFenceForPastVsync(kPeriod), previousFence);

        previousFence = fence;
    }
}

TEST_F(FrameTargeterTest, recallsPastVsyncTwoVsyncsAheadVrr) {
    SET_FLAG_FOR_TEST(com::android::graphics::surfaceflinger::flags::vrr_config, true);

    VsyncId vsyncId{222};
    TimePoint frameBeginTime(2000ms);
    constexpr Fps kRefreshRate = 120_Hz;
    constexpr Fps kPeakRefreshRate = 240_Hz;
    constexpr Period kPeriod = kRefreshRate.getPeriod();
    constexpr Duration kFrameDuration = 10ms;

    FenceTimePtr previousFence = FenceTime::NO_FENCE;

    for (int n = 5; n-- > 0;) {
        Frame frame(this, vsyncId++, frameBeginTime, kFrameDuration, kRefreshRate,
                    kPeakRefreshRate);
        const auto fence = frame.end();

        EXPECT_EQ(target().pastVsyncTime(kPeriod), frameBeginTime + kFrameDuration - 2 * kPeriod);
        EXPECT_EQ(target().presentFenceForPastVsync(kPeriod), previousFence);

        previousFence = fence;
    }
}

TEST_F(FrameTargeterTest, doesNotDetectEarlyPresentIfNoFence) {
    constexpr Period kPeriod = (60_Hz).getPeriod();
    EXPECT_EQ(target().presentFenceForPastVsync(kPeriod), FenceTime::NO_FENCE);
    EXPECT_FALSE(wouldPresentEarly(kPeriod));
}

TEST_F(FrameTargeterTest, detectsEarlyPresent) {
    VsyncId vsyncId{333};
    TimePoint frameBeginTime(3000ms);
    constexpr Fps kRefreshRate = 60_Hz;
    constexpr Period kPeriod = kRefreshRate.getPeriod();

    // The target is not early while past present fences are pending.
    for (int n = 3; n-- > 0;) {
        const Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
        EXPECT_FALSE(wouldPresentEarly(kPeriod));
        EXPECT_FALSE(target().earliestPresentTime());
    }

    // The target is early if the past present fence was signaled.
    Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
    const auto fence = frame.end();
    fence->signalForTest(frameBeginTime.ns());

    Frame finalFrame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);

    // `finalFrame` would present early, so it has an earliest present time.
    EXPECT_TRUE(wouldPresentEarly(kPeriod));
    ASSERT_NE(std::nullopt, target().earliestPresentTime());
    EXPECT_EQ(*target().earliestPresentTime(),
              target().expectedPresentTime() - kPeriod - kHwcMinWorkDuration);
}

// Same as `detectsEarlyPresent`, above, but verifies that we do not set an earliest present time
// when there is expected present time support.
TEST_F(FrameTargeterWithExpectedPresentSupportTest, detectsEarlyPresent) {
    VsyncId vsyncId{333};
    TimePoint frameBeginTime(3000ms);
    constexpr Fps kRefreshRate = 60_Hz;
    constexpr Period kPeriod = kRefreshRate.getPeriod();

    // The target is not early while past present fences are pending.
    for (int n = 3; n-- > 0;) {
        const Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
        EXPECT_FALSE(wouldPresentEarly(kPeriod));
        EXPECT_FALSE(target().earliestPresentTime());
    }

    // The target is early if the past present fence was signaled.
    Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
    const auto fence = frame.end();
    fence->signalForTest(frameBeginTime.ns());

    Frame finalFrame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);

    // `finalFrame` would present early, but we have expected present time support, so it has no
    // earliest present time.
    EXPECT_TRUE(wouldPresentEarly(kPeriod));
    ASSERT_EQ(std::nullopt, target().earliestPresentTime());
}

TEST_F(FrameTargeterTest, detectsEarlyPresentTwoVsyncsAhead) {
    VsyncId vsyncId{444};
    TimePoint frameBeginTime(4000ms);
    constexpr Fps kRefreshRate = 120_Hz;
    constexpr Period kPeriod = kRefreshRate.getPeriod();

    // The target is not early while past present fences are pending.
    for (int n = 3; n-- > 0;) {
        const Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
        EXPECT_FALSE(wouldPresentEarly(kPeriod));
        EXPECT_FALSE(target().earliestPresentTime());
    }

    Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
    const auto fence = frame.end();
    fence->signalForTest(frameBeginTime.ns());

    // The target is two VSYNCs ahead, so the past present fence is still pending.
    EXPECT_FALSE(wouldPresentEarly(kPeriod));
    EXPECT_FALSE(target().earliestPresentTime());

    { const Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate); }

    Frame finalFrame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);

    // The target is early if the past present fence was signaled.
    EXPECT_TRUE(wouldPresentEarly(kPeriod));
    ASSERT_NE(std::nullopt, target().earliestPresentTime());
    EXPECT_EQ(*target().earliestPresentTime(),
              target().expectedPresentTime() - kPeriod - kHwcMinWorkDuration);
}

TEST_F(FrameTargeterTest, detectsEarlyPresentThreeVsyncsAhead) {
    TimePoint frameBeginTime(5000ms);
    constexpr Fps kRefreshRate = 144_Hz;
    constexpr Period kPeriod = kRefreshRate.getPeriod();

    const Frame frame(this, VsyncId{555}, frameBeginTime, 16ms, kRefreshRate, kRefreshRate);

    // The target is more than two VSYNCs ahead, but present fences are not tracked that far back.
    EXPECT_TRUE(wouldPresentEarly(kPeriod));
    EXPECT_TRUE(target().earliestPresentTime());
    EXPECT_EQ(*target().earliestPresentTime(),
              target().expectedPresentTime() - kPeriod - kHwcMinWorkDuration);
}

TEST_F(FrameTargeterTest, detectsMissedFrames) {
    VsyncId vsyncId{555};
    TimePoint frameBeginTime(5000ms);
    constexpr Fps kRefreshRate = 60_Hz;
    constexpr Period kPeriod = kRefreshRate.getPeriod();

    EXPECT_FALSE(target().isFramePending());
    EXPECT_FALSE(target().didMissFrame());
    EXPECT_FALSE(target().didMissHwcFrame());

    {
        const Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
        EXPECT_FALSE(target().isFramePending());

        // The frame did not miss if the past present fence is invalid.
        EXPECT_FALSE(target().didMissFrame());
        EXPECT_FALSE(target().didMissHwcFrame());
    }
    {
        Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate,
                    Frame::fencePending);
        EXPECT_TRUE(target().isFramePending());

        // The frame missed if the past present fence is pending.
        EXPECT_TRUE(target().didMissFrame());
        EXPECT_TRUE(target().didMissHwcFrame());

        frame.end(CompositionCoverage::Gpu);
    }
    {
        const Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate,
                          Frame::fencePending);
        EXPECT_TRUE(target().isFramePending());

        // The GPU frame missed if the past present fence is pending.
        EXPECT_TRUE(target().didMissFrame());
        EXPECT_FALSE(target().didMissHwcFrame());
    }
    {
        Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
        EXPECT_FALSE(target().isFramePending());

        const auto fence = frame.end();
        const auto expectedPresentTime = target().expectedPresentTime();
        fence->signalForTest(expectedPresentTime.ns() + kPeriod.ns() / 2 + 1);
    }
    {
        Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
        EXPECT_FALSE(target().isFramePending());

        const auto fence = frame.end();
        const auto expectedPresentTime = target().expectedPresentTime();
        fence->signalForTest(expectedPresentTime.ns() + kPeriod.ns() / 2);

        // The frame missed if the past present fence was signaled but not within slop.
        EXPECT_TRUE(target().didMissFrame());
        EXPECT_TRUE(target().didMissHwcFrame());
    }
    {
        Frame frame(this, vsyncId++, frameBeginTime, 10ms, kRefreshRate, kRefreshRate);
        EXPECT_FALSE(target().isFramePending());

        // The frame did not miss if the past present fence was signaled within slop.
        EXPECT_FALSE(target().didMissFrame());
        EXPECT_FALSE(target().didMissHwcFrame());
    }
}

} // namespace android::scheduler
