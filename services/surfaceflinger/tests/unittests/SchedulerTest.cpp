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

#include <common/test/FlagUtils.h>
#include <ftl/fake_guard.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>

#include <mutex>

#include "Scheduler/EventThread.h"
#include "Scheduler/RefreshRateSelector.h"
#include "Scheduler/VSyncPredictor.h"
#include "TestableScheduler.h"
#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockEventThread.h"
#include "mock/MockLayer.h"
#include "mock/MockSchedulerCallback.h"

#include <FrontEnd/LayerHierarchy.h>

#include <com_android_graphics_surfaceflinger_flags.h>
#include "FpsOps.h"

using namespace com::android::graphics::surfaceflinger;

namespace android::scheduler {

using android::mock::createDisplayMode;
using android::mock::createVrrDisplayMode;

using testing::_;
using testing::Return;

namespace {

using MockEventThread = android::mock::EventThread;
using MockLayer = android::mock::MockLayer;

using LayerHierarchy = surfaceflinger::frontend::LayerHierarchy;
using LayerHierarchyBuilder = surfaceflinger::frontend::LayerHierarchyBuilder;
using RequestedLayerState = surfaceflinger::frontend::RequestedLayerState;

class SchedulerTest : public testing::Test {
protected:
    class MockEventThreadConnection : public android::EventThreadConnection {
    public:
        explicit MockEventThreadConnection(EventThread* eventThread)
              : EventThreadConnection(eventThread, /*callingUid*/ static_cast<uid_t>(0)) {}
        ~MockEventThreadConnection() = default;

        MOCK_METHOD1(stealReceiveChannel, binder::Status(gui::BitTube* outChannel));
        MOCK_METHOD1(setVsyncRate, binder::Status(int count));
        MOCK_METHOD0(requestNextVsync, binder::Status());
    };

    SchedulerTest();

    static constexpr PhysicalDisplayId kDisplayId1 = PhysicalDisplayId::fromPort(255u);
    static inline const ftl::NonNull<DisplayModePtr> kDisplay1Mode60 =
            ftl::as_non_null(createDisplayMode(kDisplayId1, DisplayModeId(0), 60_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kDisplay1Mode120 =
            ftl::as_non_null(createDisplayMode(kDisplayId1, DisplayModeId(1), 120_Hz));
    static inline const DisplayModes kDisplay1Modes = makeModes(kDisplay1Mode60, kDisplay1Mode120);

    static constexpr PhysicalDisplayId kDisplayId2 = PhysicalDisplayId::fromPort(254u);
    static inline const ftl::NonNull<DisplayModePtr> kDisplay2Mode60 =
            ftl::as_non_null(createDisplayMode(kDisplayId2, DisplayModeId(0), 60_Hz));
    static inline const ftl::NonNull<DisplayModePtr> kDisplay2Mode120 =
            ftl::as_non_null(createDisplayMode(kDisplayId2, DisplayModeId(1), 120_Hz));
    static inline const DisplayModes kDisplay2Modes = makeModes(kDisplay2Mode60, kDisplay2Mode120);

    static constexpr PhysicalDisplayId kDisplayId3 = PhysicalDisplayId::fromPort(253u);
    static inline const ftl::NonNull<DisplayModePtr> kDisplay3Mode60 =
            ftl::as_non_null(createDisplayMode(kDisplayId3, DisplayModeId(0), 60_Hz));
    static inline const DisplayModes kDisplay3Modes = makeModes(kDisplay3Mode60);

    std::shared_ptr<RefreshRateSelector> mSelector =
            std::make_shared<RefreshRateSelector>(makeModes(kDisplay1Mode60),
                                                  kDisplay1Mode60->getId());

    mock::SchedulerCallback mSchedulerCallback;
    TestableSurfaceFlinger mFlinger;
    TestableScheduler* mScheduler = new TestableScheduler{mSelector, mFlinger, mSchedulerCallback};
    surfaceflinger::frontend::LayerHierarchyBuilder mLayerHierarchyBuilder;

    MockEventThread* mEventThread;
    sp<MockEventThreadConnection> mEventThreadConnection;
};

SchedulerTest::SchedulerTest() {
    auto eventThread = std::make_unique<MockEventThread>();
    mEventThread = eventThread.get();
    EXPECT_CALL(*mEventThread, registerDisplayEventConnection(_)).WillOnce(Return(0));

    mEventThreadConnection = sp<MockEventThreadConnection>::make(mEventThread);

    // createConnection call to scheduler makes a createEventConnection call to EventThread. Make
    // sure that call gets executed and returns an EventThread::Connection object.
    EXPECT_CALL(*mEventThread, createEventConnection(_, _))
            .WillRepeatedly(Return(mEventThreadConnection));

    mScheduler->setEventThread(Cycle::Render, std::move(eventThread));

    mFlinger.resetScheduler(mScheduler);
}

} // namespace

TEST_F(SchedulerTest, registerDisplay) FTL_FAKE_GUARD(kMainThreadContext) {
    // Hardware VSYNC should not change if the display is already registered.
    EXPECT_CALL(mSchedulerCallback, requestHardwareVsync(kDisplayId1, false)).Times(0);
    mScheduler->registerDisplay(kDisplayId1,
                                std::make_shared<RefreshRateSelector>(kDisplay1Modes,
                                                                      kDisplay1Mode60->getId()));

    // TODO(b/241285191): Restore once VsyncSchedule::getPendingHardwareVsyncState is called by
    // Scheduler::setDisplayPowerMode rather than SF::setPowerModeInternal.
#if 0
    // Hardware VSYNC should be disabled for newly registered displays.
    EXPECT_CALL(mSchedulerCallback, requestHardwareVsync(kDisplayId2, false)).Times(1);
    EXPECT_CALL(mSchedulerCallback, requestHardwareVsync(kDisplayId3, false)).Times(1);
#endif

    mScheduler->registerDisplay(kDisplayId2,
                                std::make_shared<RefreshRateSelector>(kDisplay2Modes,
                                                                      kDisplay2Mode60->getId()));
    mScheduler->registerDisplay(kDisplayId3,
                                std::make_shared<RefreshRateSelector>(kDisplay3Modes,
                                                                      kDisplay3Mode60->getId()));

    EXPECT_FALSE(mScheduler->getVsyncSchedule(kDisplayId1)->getPendingHardwareVsyncState());
    EXPECT_FALSE(mScheduler->getVsyncSchedule(kDisplayId2)->getPendingHardwareVsyncState());
    EXPECT_FALSE(mScheduler->getVsyncSchedule(kDisplayId3)->getPendingHardwareVsyncState());
}

TEST_F(SchedulerTest, chooseRefreshRateForContentIsNoopWhenModeSwitchingIsNotSupported) {
    // The layer is registered at creation time and deregistered at destruction time.
    sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());

    // recordLayerHistory should be a noop
    ASSERT_EQ(0u, mScheduler->getNumActiveLayers());
    mScheduler->recordLayerHistory(layer->getSequence(), layer->getLayerProps(), 0, 0,
                                   LayerHistory::LayerUpdateType::Buffer);
    ASSERT_EQ(0u, mScheduler->getNumActiveLayers());

    constexpr hal::PowerMode kPowerModeOn = hal::PowerMode::ON;
    FTL_FAKE_GUARD(kMainThreadContext, mScheduler->setDisplayPowerMode(kDisplayId1, kPowerModeOn));

    constexpr uint32_t kDisplayArea = 999'999;
    mScheduler->onActiveDisplayAreaChanged(kDisplayArea);

    EXPECT_CALL(mSchedulerCallback, requestDisplayModes(_)).Times(0);
    mScheduler->chooseRefreshRateForContent(/*LayerHierarchy*/ nullptr,
                                            /*updateAttachedChoreographer*/ false);
}

TEST_F(SchedulerTest, updateDisplayModes) {
    ASSERT_EQ(0u, mScheduler->layerHistorySize());
    sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());
    ASSERT_EQ(1u, mScheduler->layerHistorySize());

    // Replace `mSelector` with a new `RefreshRateSelector` that has different display modes.
    mScheduler->registerDisplay(kDisplayId1,
                                std::make_shared<RefreshRateSelector>(kDisplay1Modes,
                                                                      kDisplay1Mode60->getId()));

    ASSERT_EQ(0u, mScheduler->getNumActiveLayers());
    mScheduler->recordLayerHistory(layer->getSequence(), layer->getLayerProps(), 0, 0,
                                   LayerHistory::LayerUpdateType::Buffer);
    ASSERT_EQ(1u, mScheduler->getNumActiveLayers());
}

TEST_F(SchedulerTest, dispatchCachedReportedMode) {
    mScheduler->clearCachedReportedMode();

    EXPECT_CALL(*mEventThread, onModeChanged(_)).Times(0);
    EXPECT_NO_FATAL_FAILURE(mScheduler->dispatchCachedReportedMode());
}

TEST_F(SchedulerTest, calculateMaxAcquiredBufferCount) {
    EXPECT_EQ(1, mFlinger.calculateMaxAcquiredBufferCount(60_Hz, 30ms));
    EXPECT_EQ(2, mFlinger.calculateMaxAcquiredBufferCount(90_Hz, 30ms));
    EXPECT_EQ(3, mFlinger.calculateMaxAcquiredBufferCount(120_Hz, 30ms));

    EXPECT_EQ(2, mFlinger.calculateMaxAcquiredBufferCount(60_Hz, 40ms));

    EXPECT_EQ(1, mFlinger.calculateMaxAcquiredBufferCount(60_Hz, 10ms));

    const auto savedMinAcquiredBuffers = mFlinger.mutableMinAcquiredBuffers();
    mFlinger.mutableMinAcquiredBuffers() = 2;
    EXPECT_EQ(2, mFlinger.calculateMaxAcquiredBufferCount(60_Hz, 10ms));
    mFlinger.mutableMinAcquiredBuffers() = savedMinAcquiredBuffers;
}

MATCHER(Is120Hz, "") {
    return isApproxEqual(arg.front().mode.fps, 120_Hz);
}

TEST_F(SchedulerTest, chooseRefreshRateForContentSelectsMaxRefreshRate) {
    mScheduler->registerDisplay(kDisplayId1,
                                std::make_shared<RefreshRateSelector>(kDisplay1Modes,
                                                                      kDisplay1Mode60->getId()));

    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());
    EXPECT_CALL(*layer, isVisible()).WillOnce(Return(true));

    mScheduler->recordLayerHistory(layer->getSequence(), layer->getLayerProps(), 0, systemTime(),
                                   LayerHistory::LayerUpdateType::Buffer);

    constexpr hal::PowerMode kPowerModeOn = hal::PowerMode::ON;
    FTL_FAKE_GUARD(kMainThreadContext, mScheduler->setDisplayPowerMode(kDisplayId1, kPowerModeOn));

    constexpr uint32_t kDisplayArea = 999'999;
    mScheduler->onActiveDisplayAreaChanged(kDisplayArea);

    EXPECT_CALL(mSchedulerCallback, requestDisplayModes(Is120Hz())).Times(1);
    mScheduler->chooseRefreshRateForContent(/*LayerHierarchy*/ nullptr,
                                            /*updateAttachedChoreographer*/ false);

    // No-op if layer requirements have not changed.
    EXPECT_CALL(mSchedulerCallback, requestDisplayModes(_)).Times(0);
    mScheduler->chooseRefreshRateForContent(/*LayerHierarchy*/ nullptr,
                                            /*updateAttachedChoreographer*/ false);
}

TEST_F(SchedulerTest, chooseDisplayModesSingleDisplay) {
    mScheduler->registerDisplay(kDisplayId1,
                                std::make_shared<RefreshRateSelector>(kDisplay1Modes,
                                                                      kDisplay1Mode60->getId()));

    std::vector<RefreshRateSelector::LayerRequirement> layers =
            std::vector<RefreshRateSelector::LayerRequirement>({{.weight = 1.f}, {.weight = 1.f}});
    mScheduler->setContentRequirements(layers);
    GlobalSignals globalSignals = {.idle = true};
    mScheduler->setTouchStateAndIdleTimerPolicy(globalSignals);

    using DisplayModeChoice = TestableScheduler::DisplayModeChoice;

    auto modeChoices = mScheduler->chooseDisplayModes();
    ASSERT_EQ(1u, modeChoices.size());

    auto choice = modeChoices.get(kDisplayId1);
    ASSERT_TRUE(choice);
    EXPECT_EQ(choice->get(), DisplayModeChoice({60_Hz, kDisplay1Mode60}, globalSignals));

    globalSignals = {.idle = false};
    mScheduler->setTouchStateAndIdleTimerPolicy(globalSignals);

    modeChoices = mScheduler->chooseDisplayModes();
    ASSERT_EQ(1u, modeChoices.size());

    choice = modeChoices.get(kDisplayId1);
    ASSERT_TRUE(choice);
    EXPECT_EQ(choice->get(), DisplayModeChoice({120_Hz, kDisplay1Mode120}, globalSignals));

    globalSignals = {.touch = true};
    mScheduler->replaceTouchTimer(10);
    mScheduler->setTouchStateAndIdleTimerPolicy(globalSignals);

    modeChoices = mScheduler->chooseDisplayModes();
    ASSERT_EQ(1u, modeChoices.size());

    choice = modeChoices.get(kDisplayId1);
    ASSERT_TRUE(choice);
    EXPECT_EQ(choice->get(), DisplayModeChoice({120_Hz, kDisplay1Mode120}, globalSignals));
}

TEST_F(SchedulerTest, chooseDisplayModesSingleDisplayHighHintTouchSignal) {
    mScheduler->registerDisplay(kDisplayId1,
                                std::make_shared<RefreshRateSelector>(kDisplay1Modes,
                                                                      kDisplay1Mode60->getId()));

    using DisplayModeChoice = TestableScheduler::DisplayModeChoice;

    std::vector<RefreshRateSelector::LayerRequirement> layers =
            std::vector<RefreshRateSelector::LayerRequirement>({{.weight = 1.f}, {.weight = 1.f}});
    auto& lr1 = layers[0];
    auto& lr2 = layers[1];

    // Scenario that is similar to game. Expects no touch boost.
    lr1.vote = RefreshRateSelector::LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = RefreshRateSelector::LayerVoteType::ExplicitDefault;
    lr2.desiredRefreshRate = 30_Hz;
    lr2.name = "30Hz ExplicitDefault";
    mScheduler->setContentRequirements(layers);
    auto modeChoices = mScheduler->chooseDisplayModes();
    ASSERT_EQ(1u, modeChoices.size());
    auto choice = modeChoices.get(kDisplayId1);
    ASSERT_TRUE(choice);
    EXPECT_EQ(choice->get(), DisplayModeChoice({60_Hz, kDisplay1Mode60}, {.touch = false}));

    // Scenario that is similar to video playback and interaction. Expects touch boost.
    lr1.vote = RefreshRateSelector::LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = RefreshRateSelector::LayerVoteType::ExplicitExactOrMultiple;
    lr2.desiredRefreshRate = 30_Hz;
    lr2.name = "30Hz ExplicitExactOrMultiple";
    mScheduler->setContentRequirements(layers);
    modeChoices = mScheduler->chooseDisplayModes();
    ASSERT_EQ(1u, modeChoices.size());
    choice = modeChoices.get(kDisplayId1);
    ASSERT_TRUE(choice);
    EXPECT_EQ(choice->get(), DisplayModeChoice({120_Hz, kDisplay1Mode120}, {.touch = true}));

    // Scenario with explicit category and HighHint. Expects touch boost.
    lr1.vote = RefreshRateSelector::LayerVoteType::ExplicitCategory;
    lr1.frameRateCategory = FrameRateCategory::HighHint;
    lr1.name = "ExplicitCategory HighHint";
    lr2.vote = RefreshRateSelector::LayerVoteType::ExplicitCategory;
    lr2.frameRateCategory = FrameRateCategory::Low;
    lr2.name = "ExplicitCategory Low";
    mScheduler->setContentRequirements(layers);
    modeChoices = mScheduler->chooseDisplayModes();
    ASSERT_EQ(1u, modeChoices.size());
    choice = modeChoices.get(kDisplayId1);
    ASSERT_TRUE(choice);
    EXPECT_EQ(choice->get(), DisplayModeChoice({120_Hz, kDisplay1Mode120}, {.touch = true}));
}

TEST_F(SchedulerTest, chooseDisplayModesMultipleDisplays) {
    mScheduler->registerDisplay(kDisplayId1,
                                std::make_shared<RefreshRateSelector>(kDisplay1Modes,
                                                                      kDisplay1Mode60->getId()));
    mScheduler->registerDisplay(kDisplayId2,
                                std::make_shared<RefreshRateSelector>(kDisplay2Modes,
                                                                      kDisplay2Mode60->getId()));

    using DisplayModeChoice = TestableScheduler::DisplayModeChoice;
    TestableScheduler::DisplayModeChoiceMap expectedChoices;

    {
        const GlobalSignals globalSignals = {.idle = true};
        expectedChoices =
                ftl::init::map<const PhysicalDisplayId&,
                               DisplayModeChoice>(kDisplayId1,
                                                  FrameRateMode{60_Hz, kDisplay1Mode60},
                                                  globalSignals)(kDisplayId2,
                                                                 FrameRateMode{60_Hz,
                                                                               kDisplay2Mode60},
                                                                 globalSignals);

        std::vector<RefreshRateSelector::LayerRequirement> layers = {{.weight = 1.f},
                                                                     {.weight = 1.f}};
        mScheduler->setContentRequirements(layers);
        mScheduler->setTouchStateAndIdleTimerPolicy(globalSignals);

        const auto actualChoices = mScheduler->chooseDisplayModes();
        EXPECT_EQ(expectedChoices, actualChoices);
    }
    {
        const GlobalSignals globalSignals = {.idle = false};
        expectedChoices =
                ftl::init::map<const PhysicalDisplayId&,
                               DisplayModeChoice>(kDisplayId1,
                                                  FrameRateMode{120_Hz, kDisplay1Mode120},
                                                  globalSignals)(kDisplayId2,
                                                                 FrameRateMode{120_Hz,
                                                                               kDisplay2Mode120},
                                                                 globalSignals);

        mScheduler->setTouchStateAndIdleTimerPolicy(globalSignals);

        const auto actualChoices = mScheduler->chooseDisplayModes();
        EXPECT_EQ(expectedChoices, actualChoices);
    }
    {
        const GlobalSignals globalSignals = {.touch = true};
        mScheduler->replaceTouchTimer(10);
        mScheduler->setTouchStateAndIdleTimerPolicy(globalSignals);

        expectedChoices =
                ftl::init::map<const PhysicalDisplayId&,
                               DisplayModeChoice>(kDisplayId1,
                                                  FrameRateMode{120_Hz, kDisplay1Mode120},
                                                  globalSignals)(kDisplayId2,
                                                                 FrameRateMode{120_Hz,
                                                                               kDisplay2Mode120},
                                                                 globalSignals);

        const auto actualChoices = mScheduler->chooseDisplayModes();
        EXPECT_EQ(expectedChoices, actualChoices);
    }
    {
        // The kDisplayId3 does not support 120Hz, The pacesetter display rate is chosen to be 120
        // Hz. In this case only the display kDisplayId3 choose 60Hz as it does not support 120Hz.
        mScheduler
                ->registerDisplay(kDisplayId3,
                                  std::make_shared<RefreshRateSelector>(kDisplay3Modes,
                                                                        kDisplay3Mode60->getId()));

        const GlobalSignals globalSignals = {.touch = true};
        mScheduler->replaceTouchTimer(10);
        mScheduler->setTouchStateAndIdleTimerPolicy(globalSignals);

        expectedChoices = ftl::init::map<
                const PhysicalDisplayId&,
                DisplayModeChoice>(kDisplayId1, FrameRateMode{120_Hz, kDisplay1Mode120},
                                   globalSignals)(kDisplayId2,
                                                  FrameRateMode{120_Hz, kDisplay2Mode120},
                                                  globalSignals)(kDisplayId3,
                                                                 FrameRateMode{60_Hz,
                                                                               kDisplay3Mode60},
                                                                 globalSignals);

        const auto actualChoices = mScheduler->chooseDisplayModes();
        EXPECT_EQ(expectedChoices, actualChoices);
    }
    {
        // We should choose 60Hz despite the touch signal as pacesetter only supports 60Hz
        mScheduler->setPacesetterDisplay(kDisplayId3);
        const GlobalSignals globalSignals = {.touch = true};
        mScheduler->replaceTouchTimer(10);
        mScheduler->setTouchStateAndIdleTimerPolicy(globalSignals);

        expectedChoices = ftl::init::map<
                const PhysicalDisplayId&,
                DisplayModeChoice>(kDisplayId1, FrameRateMode{60_Hz, kDisplay1Mode60},
                                   globalSignals)(kDisplayId2,
                                                  FrameRateMode{60_Hz, kDisplay2Mode60},
                                                  globalSignals)(kDisplayId3,
                                                                 FrameRateMode{60_Hz,
                                                                               kDisplay3Mode60},
                                                                 globalSignals);

        const auto actualChoices = mScheduler->chooseDisplayModes();
        EXPECT_EQ(expectedChoices, actualChoices);
    }
}

TEST_F(SchedulerTest, onFrameSignalMultipleDisplays) {
    mScheduler->registerDisplay(kDisplayId1,
                                std::make_shared<RefreshRateSelector>(kDisplay1Modes,
                                                                      kDisplay1Mode60->getId()));
    mScheduler->registerDisplay(kDisplayId2,
                                std::make_shared<RefreshRateSelector>(kDisplay2Modes,
                                                                      kDisplay2Mode60->getId()));

    using VsyncIds = std::vector<std::pair<PhysicalDisplayId, VsyncId>>;

    struct Compositor final : ICompositor {
        explicit Compositor(TestableScheduler& scheduler) : scheduler(scheduler) {}

        TestableScheduler& scheduler;

        struct {
            PhysicalDisplayId commit;
            PhysicalDisplayId composite;
        } pacesetterIds;

        struct {
            VsyncIds commit;
            VsyncIds composite;
        } vsyncIds;

        bool committed = true;
        bool changePacesetter = false;

        void configure() override {}

        bool commit(PhysicalDisplayId pacesetterId,
                    const scheduler::FrameTargets& targets) override {
            pacesetterIds.commit = pacesetterId;

            vsyncIds.commit.clear();
            vsyncIds.composite.clear();

            for (const auto& [id, target] : targets) {
                vsyncIds.commit.emplace_back(id, target->vsyncId());
            }

            if (changePacesetter) {
                scheduler.setPacesetterDisplay(kDisplayId2);
            }

            return committed;
        }

        CompositeResultsPerDisplay composite(PhysicalDisplayId pacesetterId,
                                             const scheduler::FrameTargeters& targeters) override {
            pacesetterIds.composite = pacesetterId;

            CompositeResultsPerDisplay results;

            for (const auto& [id, targeter] : targeters) {
                vsyncIds.composite.emplace_back(id, targeter->target().vsyncId());
                results.try_emplace(id,
                                    CompositeResult{.compositionCoverage =
                                                            CompositionCoverage::Hwc});
            }

            return results;
        }

        void sample() override {}
        void sendNotifyExpectedPresentHint(PhysicalDisplayId) override {}
    } compositor(*mScheduler);

    mScheduler->doFrameSignal(compositor, VsyncId(42));

    const auto makeVsyncIds = [](VsyncId vsyncId, bool swap = false) -> VsyncIds {
        if (swap) {
            return {{kDisplayId2, vsyncId}, {kDisplayId1, vsyncId}};
        } else {
            return {{kDisplayId1, vsyncId}, {kDisplayId2, vsyncId}};
        }
    };

    EXPECT_EQ(kDisplayId1, compositor.pacesetterIds.commit);
    EXPECT_EQ(kDisplayId1, compositor.pacesetterIds.composite);
    EXPECT_EQ(makeVsyncIds(VsyncId(42)), compositor.vsyncIds.commit);
    EXPECT_EQ(makeVsyncIds(VsyncId(42)), compositor.vsyncIds.composite);

    // FrameTargets should be updated despite the skipped commit.
    compositor.committed = false;
    mScheduler->doFrameSignal(compositor, VsyncId(43));

    EXPECT_EQ(kDisplayId1, compositor.pacesetterIds.commit);
    EXPECT_EQ(kDisplayId1, compositor.pacesetterIds.composite);
    EXPECT_EQ(makeVsyncIds(VsyncId(43)), compositor.vsyncIds.commit);
    EXPECT_TRUE(compositor.vsyncIds.composite.empty());

    // The pacesetter may change during commit.
    compositor.committed = true;
    compositor.changePacesetter = true;
    mScheduler->doFrameSignal(compositor, VsyncId(44));

    EXPECT_EQ(kDisplayId1, compositor.pacesetterIds.commit);
    EXPECT_EQ(kDisplayId2, compositor.pacesetterIds.composite);
    EXPECT_EQ(makeVsyncIds(VsyncId(44)), compositor.vsyncIds.commit);
    EXPECT_EQ(makeVsyncIds(VsyncId(44), true), compositor.vsyncIds.composite);
}

TEST_F(SchedulerTest, nextFrameIntervalTest) {
    SET_FLAG_FOR_TEST(flags::vrr_config, true);

    static constexpr size_t kHistorySize = 10;
    static constexpr size_t kMinimumSamplesForPrediction = 6;
    static constexpr size_t kOutlierTolerancePercent = 25;
    const auto refreshRate = Fps::fromPeriodNsecs(500);
    auto frameRate = Fps::fromPeriodNsecs(1000);

    const ftl::NonNull<DisplayModePtr> kMode = ftl::as_non_null(
            createVrrDisplayMode(DisplayModeId(0), refreshRate,
                                 hal::VrrConfig{.minFrameIntervalNs = static_cast<int32_t>(
                                                        frameRate.getPeriodNsecs())}));
    std::shared_ptr<VSyncPredictor> vrrTracker =
            std::make_shared<VSyncPredictor>(kMode, kHistorySize, kMinimumSamplesForPrediction,
                                             kOutlierTolerancePercent);
    std::shared_ptr<RefreshRateSelector> vrrSelectorPtr =
            std::make_shared<RefreshRateSelector>(makeModes(kMode), kMode->getId());
    TestableScheduler scheduler{std::make_unique<android::mock::VsyncController>(),
                                vrrTracker,
                                vrrSelectorPtr,
                                mFlinger.getFactory(),
                                mFlinger.getTimeStats(),
                                mSchedulerCallback};

    scheduler.registerDisplay(kMode->getPhysicalDisplayId(), vrrSelectorPtr, vrrTracker);
    vrrSelectorPtr->setActiveMode(kMode->getId(), frameRate);
    scheduler.setRenderRate(kMode->getPhysicalDisplayId(), frameRate);
    vrrTracker->addVsyncTimestamp(0);

    EXPECT_EQ(Fps::fromPeriodNsecs(1000),
              scheduler.getNextFrameInterval(kMode->getPhysicalDisplayId(),
                                             TimePoint::fromNs(1000)));
    EXPECT_EQ(Fps::fromPeriodNsecs(1000),
              scheduler.getNextFrameInterval(kMode->getPhysicalDisplayId(),
                                             TimePoint::fromNs(2000)));

    // Not crossing the min frame period
    EXPECT_EQ(Fps::fromPeriodNsecs(1500),
              scheduler.getNextFrameInterval(kMode->getPhysicalDisplayId(),
                                             TimePoint::fromNs(2500)));
    // Change render rate
    frameRate = Fps::fromPeriodNsecs(2000);
    vrrSelectorPtr->setActiveMode(kMode->getId(), frameRate);
    scheduler.setRenderRate(kMode->getPhysicalDisplayId(), frameRate);

    EXPECT_EQ(Fps::fromPeriodNsecs(2000),
              scheduler.getNextFrameInterval(kMode->getPhysicalDisplayId(),
                                             TimePoint::fromNs(2000)));
    EXPECT_EQ(Fps::fromPeriodNsecs(2000),
              scheduler.getNextFrameInterval(kMode->getPhysicalDisplayId(),
                                             TimePoint::fromNs(4000)));
}

TEST_F(SchedulerTest, resyncAllToHardwareVsync) FTL_FAKE_GUARD(kMainThreadContext) {
    // resyncAllToHardwareVsync will result in requesting hardware VSYNC on both displays, since
    // they are both on.
    EXPECT_CALL(mScheduler->mockRequestHardwareVsync, Call(kDisplayId1, true)).Times(1);
    EXPECT_CALL(mScheduler->mockRequestHardwareVsync, Call(kDisplayId2, true)).Times(1);

    mScheduler->registerDisplay(kDisplayId2,
                                std::make_shared<RefreshRateSelector>(kDisplay2Modes,
                                                                      kDisplay2Mode60->getId()));
    mScheduler->setDisplayPowerMode(kDisplayId1, hal::PowerMode::ON);
    mScheduler->setDisplayPowerMode(kDisplayId2, hal::PowerMode::ON);

    static constexpr bool kDisallow = true;
    mScheduler->disableHardwareVsync(kDisplayId1, kDisallow);
    mScheduler->disableHardwareVsync(kDisplayId2, kDisallow);

    static constexpr bool kAllowToEnable = true;
    mScheduler->resyncAllToHardwareVsync(kAllowToEnable);
}

TEST_F(SchedulerTest, resyncAllDoNotAllow) FTL_FAKE_GUARD(kMainThreadContext) {
    // Without setting allowToEnable to true, resyncAllToHardwareVsync does not
    // result in requesting hardware VSYNC.
    EXPECT_CALL(mScheduler->mockRequestHardwareVsync, Call(kDisplayId1, _)).Times(0);

    mScheduler->setDisplayPowerMode(kDisplayId1, hal::PowerMode::ON);

    static constexpr bool kDisallow = true;
    mScheduler->disableHardwareVsync(kDisplayId1, kDisallow);

    static constexpr bool kAllowToEnable = false;
    mScheduler->resyncAllToHardwareVsync(kAllowToEnable);
}

TEST_F(SchedulerTest, resyncAllSkipsOffDisplays) FTL_FAKE_GUARD(kMainThreadContext) {
    SET_FLAG_FOR_TEST(flags::multithreaded_present, true);

    // resyncAllToHardwareVsync will result in requesting hardware VSYNC on display 1, which is on,
    // but not on display 2, which is off.
    EXPECT_CALL(mScheduler->mockRequestHardwareVsync, Call(kDisplayId1, true)).Times(1);
    EXPECT_CALL(mScheduler->mockRequestHardwareVsync, Call(kDisplayId2, _)).Times(0);

    mScheduler->setDisplayPowerMode(kDisplayId1, hal::PowerMode::ON);

    mScheduler->registerDisplay(kDisplayId2,
                                std::make_shared<RefreshRateSelector>(kDisplay2Modes,
                                                                      kDisplay2Mode60->getId()));
    ASSERT_EQ(hal::PowerMode::OFF, mScheduler->getDisplayPowerMode(kDisplayId2));

    static constexpr bool kDisallow = true;
    mScheduler->disableHardwareVsync(kDisplayId1, kDisallow);
    mScheduler->disableHardwareVsync(kDisplayId2, kDisallow);

    static constexpr bool kAllowToEnable = true;
    mScheduler->resyncAllToHardwareVsync(kAllowToEnable);
}

TEST_F(SchedulerTest, resyncAllLegacyAppliesToOffDisplays) FTL_FAKE_GUARD(kMainThreadContext) {
    SET_FLAG_FOR_TEST(flags::multithreaded_present, false);

    // In the legacy code, prior to the flag, resync applied to OFF displays.
    EXPECT_CALL(mScheduler->mockRequestHardwareVsync, Call(kDisplayId1, true)).Times(1);
    EXPECT_CALL(mScheduler->mockRequestHardwareVsync, Call(kDisplayId2, true)).Times(1);

    mScheduler->setDisplayPowerMode(kDisplayId1, hal::PowerMode::ON);

    mScheduler->registerDisplay(kDisplayId2,
                                std::make_shared<RefreshRateSelector>(kDisplay2Modes,
                                                                      kDisplay2Mode60->getId()));
    ASSERT_EQ(hal::PowerMode::OFF, mScheduler->getDisplayPowerMode(kDisplayId2));

    static constexpr bool kDisallow = true;
    mScheduler->disableHardwareVsync(kDisplayId1, kDisallow);
    mScheduler->disableHardwareVsync(kDisplayId2, kDisallow);

    static constexpr bool kAllowToEnable = true;
    mScheduler->resyncAllToHardwareVsync(kAllowToEnable);
}

class AttachedChoreographerTest : public SchedulerTest {
protected:
    void frameRateTestScenario(Fps layerFps, int8_t frameRateCompatibility, Fps displayFps,
                               Fps expectedChoreographerFps);
};

TEST_F(AttachedChoreographerTest, registerSingle) {
    EXPECT_TRUE(mScheduler->mutableAttachedChoreographers().empty());

    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);
    const sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, layer->getHandle());

    EXPECT_EQ(1u, mScheduler->mutableAttachedChoreographers().size());
    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(layer->getSequence()));
    EXPECT_EQ(1u,
              mScheduler->mutableAttachedChoreographers()[layer->getSequence()].connections.size());
    EXPECT_FALSE(
            mScheduler->mutableAttachedChoreographers()[layer->getSequence()].frameRate.isValid());
}

TEST_F(AttachedChoreographerTest, registerMultipleOnSameLayer) {
    EXPECT_TRUE(mScheduler->mutableAttachedChoreographers().empty());

    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());
    const auto handle = layer->getHandle();

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached).Times(2);

    EXPECT_CALL(*mEventThread, registerDisplayEventConnection(_))
            .WillOnce(Return(0))
            .WillOnce(Return(0));

    const auto mockConnection1 = sp<MockEventThreadConnection>::make(mEventThread);
    const auto mockConnection2 = sp<MockEventThreadConnection>::make(mEventThread);
    EXPECT_CALL(*mEventThread, createEventConnection(_, _))
            .WillOnce(Return(mockConnection1))
            .WillOnce(Return(mockConnection2));

    const sp<IDisplayEventConnection> connection1 =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, handle);
    const sp<IDisplayEventConnection> connection2 =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, handle);

    EXPECT_EQ(1u, mScheduler->mutableAttachedChoreographers().size());
    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(layer->getSequence()));
    EXPECT_EQ(2u,
              mScheduler->mutableAttachedChoreographers()[layer->getSequence()].connections.size());
    EXPECT_FALSE(
            mScheduler->mutableAttachedChoreographers()[layer->getSequence()].frameRate.isValid());
}

TEST_F(AttachedChoreographerTest, registerMultipleOnDifferentLayers) {
    EXPECT_TRUE(mScheduler->mutableAttachedChoreographers().empty());

    const sp<MockLayer> layer1 = sp<MockLayer>::make(mFlinger.flinger());
    const sp<MockLayer> layer2 = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached).Times(2);
    const sp<IDisplayEventConnection> connection1 =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, layer1->getHandle());
    const sp<IDisplayEventConnection> connection2 =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, layer2->getHandle());

    EXPECT_EQ(2u, mScheduler->mutableAttachedChoreographers().size());

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(layer1->getSequence()));
    EXPECT_EQ(1u,
              mScheduler->mutableAttachedChoreographers()[layer1->getSequence()]
                      .connections.size());
    EXPECT_FALSE(
            mScheduler->mutableAttachedChoreographers()[layer1->getSequence()].frameRate.isValid());

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(layer2->getSequence()));
    EXPECT_EQ(1u,
              mScheduler->mutableAttachedChoreographers()[layer2->getSequence()]
                      .connections.size());
    EXPECT_FALSE(
            mScheduler->mutableAttachedChoreographers()[layer2->getSequence()].frameRate.isValid());
}

TEST_F(AttachedChoreographerTest, removedWhenConnectionIsGone) {
    EXPECT_TRUE(mScheduler->mutableAttachedChoreographers().empty());

    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);

    sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, layer->getHandle());

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(layer->getSequence()));
    EXPECT_EQ(1u,
              mScheduler->mutableAttachedChoreographers()[layer->getSequence()].connections.size());

    // The connection is used all over this test, so it is quite hard to release it from here.
    // Instead, we just do a small shortcut.
    {
        EXPECT_CALL(*mEventThread, registerDisplayEventConnection(_)).WillOnce(Return(0));
        sp<MockEventThreadConnection> mockConnection =
                sp<MockEventThreadConnection>::make(mEventThread);
        mScheduler->mutableAttachedChoreographers()[layer->getSequence()].connections.clear();
        mScheduler->mutableAttachedChoreographers()[layer->getSequence()].connections.emplace(
                mockConnection);
    }

    RequestedLayerState layerState(LayerCreationArgs(layer->getSequence()));
    LayerHierarchy hierarchy(&layerState);
    mScheduler->updateAttachedChoreographers(hierarchy, 60_Hz);
    EXPECT_TRUE(mScheduler->mutableAttachedChoreographers().empty());
}

TEST_F(AttachedChoreographerTest, removedWhenLayerIsGone) {
    EXPECT_TRUE(mScheduler->mutableAttachedChoreographers().empty());

    sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);
    const sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, layer->getHandle());

    layer.clear();
    mFlinger.mutableLayersPendingRemoval().clear();
    EXPECT_TRUE(mScheduler->mutableAttachedChoreographers().empty());
}

void AttachedChoreographerTest::frameRateTestScenario(Fps layerFps, int8_t frameRateCompatibility,
                                                      Fps displayFps,
                                                      Fps expectedChoreographerFps) {
    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);
    sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, layer->getHandle());

    RequestedLayerState layerState(LayerCreationArgs(layer->getSequence()));
    LayerHierarchy hierarchy(&layerState);

    layerState.frameRate = layerFps.getValue();
    layerState.frameRateCompatibility = frameRateCompatibility;

    mScheduler->updateAttachedChoreographers(hierarchy, displayFps);

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(layer->getSequence()));
    EXPECT_EQ(expectedChoreographerFps,
              mScheduler->mutableAttachedChoreographers()[layer->getSequence()].frameRate);
    EXPECT_EQ(expectedChoreographerFps, mEventThreadConnection->frameRate);
}

TEST_F(AttachedChoreographerTest, setsFrameRateDefault) {
    Fps layerFps = 30_Hz;
    int8_t frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;
    Fps displayFps = 60_Hz;
    Fps expectedChoreographerFps = 30_Hz;

    frameRateTestScenario(layerFps, frameRateCompatibility, displayFps, expectedChoreographerFps);

    layerFps = Fps::fromValue(32.7f);
    frameRateTestScenario(layerFps, frameRateCompatibility, displayFps, expectedChoreographerFps);
}

TEST_F(AttachedChoreographerTest, setsFrameRateExact) {
    Fps layerFps = 30_Hz;
    int8_t frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_EXACT;
    Fps displayFps = 60_Hz;
    Fps expectedChoreographerFps = 30_Hz;

    frameRateTestScenario(layerFps, frameRateCompatibility, displayFps, expectedChoreographerFps);

    layerFps = Fps::fromValue(32.7f);
    expectedChoreographerFps = {};
    frameRateTestScenario(layerFps, frameRateCompatibility, displayFps, expectedChoreographerFps);
}

TEST_F(AttachedChoreographerTest, setsFrameRateExactOrMultiple) {
    Fps layerFps = 30_Hz;
    int8_t frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE;
    Fps displayFps = 60_Hz;
    Fps expectedChoreographerFps = 30_Hz;

    frameRateTestScenario(layerFps, frameRateCompatibility, displayFps, expectedChoreographerFps);

    layerFps = Fps::fromValue(32.7f);
    expectedChoreographerFps = {};
    frameRateTestScenario(layerFps, frameRateCompatibility, displayFps, expectedChoreographerFps);
}

TEST_F(AttachedChoreographerTest, setsFrameRateParent) {
    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());
    const sp<MockLayer> parent = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);
    sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, parent->getHandle());

    RequestedLayerState parentState(LayerCreationArgs(parent->getSequence()));
    LayerHierarchy parentHierarchy(&parentState);

    RequestedLayerState layerState(LayerCreationArgs(layer->getSequence()));
    LayerHierarchy hierarchy(&layerState);
    parentHierarchy.mChildren.push_back(
            std::make_pair(&hierarchy, LayerHierarchy::Variant::Attached));

    layerState.frameRate = (30_Hz).getValue();
    layerState.frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;

    mScheduler->updateAttachedChoreographers(parentHierarchy, 120_Hz);

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(parent->getSequence()));

    EXPECT_EQ(30_Hz, mScheduler->mutableAttachedChoreographers()[parent->getSequence()].frameRate);
}

TEST_F(AttachedChoreographerTest, setsFrameRateParent2Children) {
    const sp<MockLayer> layer1 = sp<MockLayer>::make(mFlinger.flinger());
    const sp<MockLayer> layer2 = sp<MockLayer>::make(mFlinger.flinger());
    const sp<MockLayer> parent = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);
    sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, parent->getHandle());

    RequestedLayerState parentState(LayerCreationArgs(parent->getSequence()));
    LayerHierarchy parentHierarchy(&parentState);

    RequestedLayerState layer1State(LayerCreationArgs(layer1->getSequence()));
    LayerHierarchy layer1Hierarchy(&layer1State);
    parentHierarchy.mChildren.push_back(
            std::make_pair(&layer1Hierarchy, LayerHierarchy::Variant::Attached));

    RequestedLayerState layer2State(LayerCreationArgs(layer1->getSequence()));
    LayerHierarchy layer2Hierarchy(&layer2State);
    parentHierarchy.mChildren.push_back(
            std::make_pair(&layer2Hierarchy, LayerHierarchy::Variant::Attached));

    layer1State.frameRate = (30_Hz).getValue();
    layer1State.frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;

    layer2State.frameRate = (20_Hz).getValue();
    layer2State.frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;

    mScheduler->updateAttachedChoreographers(parentHierarchy, 120_Hz);

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(parent->getSequence()));

    EXPECT_EQ(60_Hz, mScheduler->mutableAttachedChoreographers()[parent->getSequence()].frameRate);
}

TEST_F(AttachedChoreographerTest, setsFrameRateParentConflictingChildren) {
    const sp<MockLayer> layer1 = sp<MockLayer>::make(mFlinger.flinger());
    const sp<MockLayer> layer2 = sp<MockLayer>::make(mFlinger.flinger());
    const sp<MockLayer> parent = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);
    sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, parent->getHandle());

    RequestedLayerState parentState(LayerCreationArgs(parent->getSequence()));
    LayerHierarchy parentHierarchy(&parentState);

    RequestedLayerState layer1State(LayerCreationArgs(layer1->getSequence()));
    LayerHierarchy layer1Hierarchy(&layer1State);
    parentHierarchy.mChildren.push_back(
            std::make_pair(&layer1Hierarchy, LayerHierarchy::Variant::Attached));

    RequestedLayerState layer2State(LayerCreationArgs(layer1->getSequence()));
    LayerHierarchy layer2Hierarchy(&layer2State);
    parentHierarchy.mChildren.push_back(
            std::make_pair(&layer2Hierarchy, LayerHierarchy::Variant::Attached));

    layer1State.frameRate = (30_Hz).getValue();
    layer1State.frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;

    layer2State.frameRate = (25_Hz).getValue();
    layer2State.frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;

    mScheduler->updateAttachedChoreographers(parentHierarchy, 120_Hz);

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(parent->getSequence()));

    EXPECT_EQ(Fps(), mScheduler->mutableAttachedChoreographers()[parent->getSequence()].frameRate);
}

TEST_F(AttachedChoreographerTest, setsFrameRateChild) {
    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());
    const sp<MockLayer> parent = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);
    sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, layer->getHandle());

    RequestedLayerState parentState(LayerCreationArgs(parent->getSequence()));
    LayerHierarchy parentHierarchy(&parentState);

    RequestedLayerState layerState(LayerCreationArgs(layer->getSequence()));
    LayerHierarchy hierarchy(&layerState);
    parentHierarchy.mChildren.push_back(
            std::make_pair(&hierarchy, LayerHierarchy::Variant::Attached));

    parentState.frameRate = (30_Hz).getValue();
    parentState.frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;

    mScheduler->updateAttachedChoreographers(parentHierarchy, 120_Hz);

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(layer->getSequence()));

    EXPECT_EQ(30_Hz, mScheduler->mutableAttachedChoreographers()[layer->getSequence()].frameRate);
}

TEST_F(AttachedChoreographerTest, setsFrameRateChildNotOverriddenByParent) {
    const sp<MockLayer> layer = sp<MockLayer>::make(mFlinger.flinger());
    const sp<MockLayer> parent = sp<MockLayer>::make(mFlinger.flinger());

    EXPECT_CALL(mSchedulerCallback, onChoreographerAttached);
    sp<IDisplayEventConnection> connection =
            mScheduler->createDisplayEventConnection(Cycle::Render, {}, layer->getHandle());

    RequestedLayerState parentState(LayerCreationArgs(parent->getSequence()));
    LayerHierarchy parentHierarchy(&parentState);

    RequestedLayerState layerState(LayerCreationArgs(layer->getSequence()));
    LayerHierarchy hierarchy(&layerState);
    parentHierarchy.mChildren.push_back(
            std::make_pair(&hierarchy, LayerHierarchy::Variant::Attached));

    parentState.frameRate = (30_Hz).getValue();
    parentState.frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;

    layerState.frameRate = (60_Hz).getValue();
    layerState.frameRateCompatibility = ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT;

    mScheduler->updateAttachedChoreographers(parentHierarchy, 120_Hz);

    ASSERT_EQ(1u, mScheduler->mutableAttachedChoreographers().count(layer->getSequence()));

    EXPECT_EQ(60_Hz, mScheduler->mutableAttachedChoreographers()[layer->getSequence()].frameRate);
}

} // namespace android::scheduler
