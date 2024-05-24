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

#include <gui/SurfaceComposerClient.h>
#include "DisplayTransactionTestHelpers.h"

namespace android {

using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;
using android::hardware::graphics::composer::V2_1::Error;

class NotifyExpectedPresentTest : public DisplayTransactionTest {
public:
    void SetUp() override {
        const auto display = PrimaryDisplayVariant::makeFakeExistingDisplayInjector(this).inject();
        mPhysicalDisplayId = display->getPhysicalId();
        FakeHwcDisplayInjector(mPhysicalDisplayId, hal::DisplayType::PHYSICAL, /*isPrimary=*/true)
                .setPowerMode(hal::PowerMode::ON)
                .inject(&mFlinger, mComposer);

        ASSERT_NO_FATAL_FAILURE(mFlinger.setNotifyExpectedPresentData(mPhysicalDisplayId,
                                                                      TimePoint::fromNs(0),
                                                                      kFps60Hz));
        mCompositor = std::make_unique<Compositor>(mPhysicalDisplayId, mFlinger);
    }

protected:
    void setTransactionState() {
        ASSERT_TRUE(mFlinger.getTransactionQueue().isEmpty());
        TransactionInfo transaction;
        mFlinger.setTransactionState(FrameTimelineInfo{}, transaction.states, transaction.displays,
                                     transaction.flags, transaction.applyToken,
                                     transaction.inputWindowCommands,
                                     TimePoint::now().ns() + s2ns(1), transaction.isAutoTimestamp,
                                     transaction.unCachedBuffers,
                                     /*HasListenerCallbacks=*/false, transaction.callbacks,
                                     transaction.id, transaction.mergedTransactionIds);
    }

    struct TransactionInfo {
        Vector<ComposerState> states;
        Vector<DisplayState> displays;
        uint32_t flags = 0;
        sp<IBinder> applyToken = IInterface::asBinder(TransactionCompletedListener::getIInstance());
        InputWindowCommands inputWindowCommands;
        int64_t desiredPresentTime = 0;
        bool isAutoTimestamp = false;
        FrameTimelineInfo frameTimelineInfo{};
        std::vector<client_cache_t> unCachedBuffers;
        uint64_t id = static_cast<uint64_t>(-1);
        std::vector<uint64_t> mergedTransactionIds;
        std::vector<ListenerCallbacks> callbacks;
    };

    struct Compositor final : ICompositor {
        explicit Compositor(PhysicalDisplayId displayId, TestableSurfaceFlinger& surfaceFlinger)
              : displayId(displayId), surfaceFlinger(surfaceFlinger) {}

        void sendNotifyExpectedPresentHint(PhysicalDisplayId id) override {
            surfaceFlinger.sendNotifyExpectedPresentHint(id);
        }

        bool commit(PhysicalDisplayId, const scheduler::FrameTargets&) override {
            return committed;
        }

        CompositeResultsPerDisplay composite(PhysicalDisplayId pacesetterId,
                                             const scheduler::FrameTargeters& targeters) override {
            pacesetterIds.composite = pacesetterId;
            CompositeResultsPerDisplay results;

            for (const auto& [id, targeter] : targeters) {
                vsyncIds.composite.emplace_back(id, targeter->target().vsyncId());
                surfaceFlinger.resetNotifyExpectedPresentHintState(pacesetterId);
                results.try_emplace(id,
                                    CompositeResult{.compositionCoverage =
                                                            CompositionCoverage::Hwc});
            }

            return results;
        }

        void sample() override {}
        void configure() override {}

        struct {
            PhysicalDisplayId commit;
            PhysicalDisplayId composite;
        } pacesetterIds;

        using VsyncIds = std::vector<std::pair<PhysicalDisplayId, VsyncId>>;
        struct {
            VsyncIds commit;
            VsyncIds composite;
        } vsyncIds;

        bool committed = true;
        PhysicalDisplayId displayId;
        TestableSurfaceFlinger& surfaceFlinger;
    };

    PhysicalDisplayId mPhysicalDisplayId;
    std::unique_ptr<Compositor> mCompositor;
    static constexpr hal::HWDisplayId kHwcDisplayId =
            FakeHwcDisplayInjector::DEFAULT_HWC_DISPLAY_ID;
    static constexpr Fps kFps60Hz = 60_Hz;
    static constexpr int32_t kFrameInterval5HzNs = static_cast<Fps>(5_Hz).getPeriodNsecs();
    static constexpr int32_t kFrameInterval60HzNs = kFps60Hz.getPeriodNsecs();
    static constexpr int32_t kFrameInterval120HzNs = static_cast<Fps>(120_Hz).getPeriodNsecs();
    static constexpr Period kVsyncPeriod =
            Period::fromNs(static_cast<Fps>(240_Hz).getPeriodNsecs());
    static constexpr Period kTimeoutNs = Period::fromNs(kFrameInterval5HzNs);
};

TEST_F(NotifyExpectedPresentTest, noNotifyExpectedPresentHintCall_absentTimeout) {
    auto expectedPresentTime = TimePoint::now().ns() + ms2ns(10);
    ASSERT_NO_FATAL_FAILURE(
            mFlinger.setNotifyExpectedPresentData(mPhysicalDisplayId,
                                                  TimePoint::fromNs(expectedPresentTime),
                                                  kFps60Hz));
    EXPECT_CALL(*mComposer, notifyExpectedPresent(kHwcDisplayId, _, _)).Times(0);
    for (int i = 0; i < 5; i++) {
        expectedPresentTime += 2 * kFrameInterval5HzNs;
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 /*timeoutOpt*/ std::nullopt);
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        ASSERT_TRUE(mFlinger.verifyHintStatusIsStart(mPhysicalDisplayId));
    }
}

TEST_F(NotifyExpectedPresentTest, notifyExpectedPresentHint_zeroTimeout) {
    auto expectedPresentTime = TimePoint::now().ns() + ms2ns(10);
    {
        // Very first ExpectedPresent after idle, no previous timestamp.
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(kHwcDisplayId, expectedPresentTime, kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));

        // Present frame
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        // Present happens and NotifyExpectedPresentHintStatus is start.
        ASSERT_TRUE(mFlinger.verifyHintStatusIsStart(mPhysicalDisplayId));
    }
    {
        mCompositor->committed = false;
        expectedPresentTime += kFrameInterval60HzNs;
        EXPECT_CALL(static_cast<mock::VSyncTracker&>(
                            mFlinger.scheduler()->getVsyncSchedule()->getTracker()),
                    nextAnticipatedVSyncTimeFrom(_, _))
                .WillRepeatedly(Return(expectedPresentTime));
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(kHwcDisplayId, expectedPresentTime, kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 Period::fromNs(0));
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        // Hint sent
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
    }
    {
        expectedPresentTime += kFrameInterval60HzNs;
        EXPECT_CALL(static_cast<mock::VSyncTracker&>(
                            mFlinger.scheduler()->getVsyncSchedule()->getTracker()),
                    nextAnticipatedVSyncTimeFrom(_, _))
                .WillRepeatedly(Return(expectedPresentTime));
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(kHwcDisplayId, expectedPresentTime, kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 Period::fromNs(0));
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        // Hint is executed
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
    }
}
TEST_F(NotifyExpectedPresentTest, notifyExpectedPresentTimeout) {
    auto expectedPresentTime = TimePoint::now().ns() + ms2ns(10);
    {
        // Very first ExpectedPresent after idle, no previous timestamp
        mCompositor->committed = false;
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(kHwcDisplayId, expectedPresentTime, kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
    }
    {
        EXPECT_CALL(*mComposer, notifyExpectedPresent(kHwcDisplayId, _, _)).Times(0);
        expectedPresentTime += 2 * kFrameInterval5HzNs;
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        ASSERT_TRUE(mFlinger.verifyHintStatusIsScheduledOnTx(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        ASSERT_TRUE(mFlinger.verifyHintStatusIsScheduledOnTx(mPhysicalDisplayId));
        {
            EXPECT_CALL(*mComposer,
                        notifyExpectedPresent(kHwcDisplayId, expectedPresentTime,
                                              kFrameInterval60HzNs))
                    .WillOnce(Return(Error::NONE));
            // Hint sent with the setTransactionState
            setTransactionState();
            ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
        }
    }
    {
        // ExpectedPresentTime is after the timeoutNs
        mCompositor->committed = true;
        expectedPresentTime += 2 * kFrameInterval5HzNs;
        EXPECT_CALL(*mComposer, notifyExpectedPresent(kHwcDisplayId, _, _)).Times(0);
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        ASSERT_TRUE(mFlinger.verifyHintStatusIsScheduledOnTx(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        // Present happens notifyExpectedPresentHintStatus is Start
        ASSERT_TRUE(mFlinger.verifyHintStatusIsStart(mPhysicalDisplayId));

        // Another expectedPresent after timeout
        expectedPresentTime += 2 * kFrameInterval5HzNs;
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(kHwcDisplayId, expectedPresentTime, kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        ASSERT_TRUE(mFlinger.verifyHintStatusIsStart(mPhysicalDisplayId));
    }
    {
        // ExpectedPresent has not changed
        EXPECT_CALL(*mComposer, notifyExpectedPresent(kHwcDisplayId, _, _)).Times(0);
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        ASSERT_TRUE(mFlinger.verifyHintStatusIsStart(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        ASSERT_TRUE(mFlinger.verifyHintStatusIsStart(mPhysicalDisplayId));
    }
    {
        // ExpectedPresent is after the last reported ExpectedPresent and within timeout.
        expectedPresentTime += kFrameInterval60HzNs;
        EXPECT_CALL(*mComposer, notifyExpectedPresent(kHwcDisplayId, _, _)).Times(0);
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        ASSERT_TRUE(mFlinger.verifyHintStatusIsStart(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        ASSERT_TRUE(mFlinger.verifyHintStatusIsStart(mPhysicalDisplayId));
    }
    {
        // ExpectedPresent is before the last reported ExpectedPresent but after the timeoutNs,
        // representing we changed our decision and want to present earlier than previously
        // reported.
        mCompositor->committed = false;
        expectedPresentTime -= kFrameInterval120HzNs;
        EXPECT_CALL(*mComposer,
                    notifyExpectedPresent(kHwcDisplayId, expectedPresentTime, kFrameInterval60HzNs))
                .WillOnce(Return(Error::NONE));
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime), kFps60Hz,
                                                 kTimeoutNs);
        EXPECT_TRUE(
                mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime));
        ASSERT_TRUE(mFlinger.verifyHintIsScheduledOnPresent(mPhysicalDisplayId));
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        ASSERT_TRUE(mFlinger.verifyHintIsSent(mPhysicalDisplayId));
    }
}

TEST_F(NotifyExpectedPresentTest, notifyExpectedPresentRenderRateChanged) {
    const auto now = TimePoint::now().ns();
    auto expectedPresentTime = now;
    static constexpr Period kTimeoutNs = Period::fromNs(static_cast<Fps>(1_Hz).getPeriodNsecs());

    ASSERT_NO_FATAL_FAILURE(mFlinger.setNotifyExpectedPresentData(mPhysicalDisplayId,
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
        bool callNotifyExpectedPresentHint;
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

    for (size_t i = 0; i < frameIntervals.size(); i++) {
        const auto& [frameIntervalNs, callNotifyExpectedPresentHint] = frameIntervals[i];
        expectedPresentTime += frameIntervalNs;
        mFlinger.notifyExpectedPresentIfRequired(mPhysicalDisplayId, kVsyncPeriod,
                                                 TimePoint::fromNs(expectedPresentTime),
                                                 Fps::fromPeriodNsecs(frameIntervalNs), kTimeoutNs);

        EXPECT_CALL(static_cast<mock::VSyncTracker&>(
                            mFlinger.scheduler()->getVsyncSchedule()->getTracker()),
                    nextAnticipatedVSyncTimeFrom(_, _))
                .WillRepeatedly(Return(expectedPresentTime));
        if (callNotifyExpectedPresentHint) {
            mCompositor->committed = false;
            ASSERT_TRUE(mFlinger.verifyHintIsScheduledOnPresent(mPhysicalDisplayId))
                    << "Hint not scheduled for frameInterval " << frameIntervalNs << " at index "
                    << i;
            EXPECT_CALL(*mComposer,
                        notifyExpectedPresent(kHwcDisplayId, expectedPresentTime, frameIntervalNs))
                    .WillOnce(Return(Error::NONE));
        } else {
            // Only lastExpectedPresentTime is updated
            EXPECT_TRUE(
                    mFlinger.verifyLastExpectedPresentTime(mPhysicalDisplayId, expectedPresentTime))
                    << "LastExpectedPresentTime for frameInterval " << frameIntervalNs
                    << "at index " << i << " did not match for frameInterval " << frameIntervalNs;
            EXPECT_CALL(*mComposer, notifyExpectedPresent(kHwcDisplayId, _, _)).Times(0);
        }
        mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});

        if (callNotifyExpectedPresentHint) {
            // Present resumes the calls to the notifyExpectedPresentHint.
            mCompositor->committed = true;
            mFlinger.scheduler()->doFrameSignal(*mCompositor, VsyncId{42});
        }
    }
}
} // namespace android