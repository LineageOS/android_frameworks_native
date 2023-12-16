/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <ftl/enum.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <processgroup/sched_policy.h>

#include <scheduler/IVsyncSource.h>
#include <scheduler/PresentLatencyTracker.h>

#include "Scheduler/OneShotTimer.h"
#include "Scheduler/RefreshRateSelector.h"
#include "Scheduler/VSyncDispatchTimerQueue.h"
#include "Scheduler/VSyncPredictor.h"
#include "Scheduler/VSyncReactor.h"

#include "mock/DisplayHardware/MockDisplayMode.h"
#include "mock/MockVSyncDispatch.h"
#include "mock/MockVSyncTracker.h"

#include "surfaceflinger_fuzzers_utils.h"
#include "surfaceflinger_scheduler_fuzzer.h"

namespace android::fuzz {

using hardware::graphics::composer::hal::PowerMode;

constexpr nsecs_t kVsyncPeriods[] = {(30_Hz).getPeriodNsecs(), (60_Hz).getPeriodNsecs(),
                                     (72_Hz).getPeriodNsecs(), (90_Hz).getPeriodNsecs(),
                                     (120_Hz).getPeriodNsecs()};

constexpr auto kLayerVoteTypes = ftl::enum_range<scheduler::RefreshRateSelector::LayerVoteType>();
constexpr auto kCompositionCoverage = ftl::enum_range<CompositionCoverage>();

constexpr PowerMode kPowerModes[] = {PowerMode::ON, PowerMode::DOZE, PowerMode::OFF,
                                     PowerMode::DOZE_SUSPEND, PowerMode::ON_SUSPEND};

constexpr uint16_t kRandomStringLength = 256;
constexpr std::chrono::duration kSyncPeriod(16ms);
constexpr PhysicalDisplayId kDisplayId = PhysicalDisplayId::fromPort(42u);

template <typename T>
void dump(T* component, FuzzedDataProvider* fdp) {
    std::string res = fdp->ConsumeRandomLengthString(kRandomStringLength);
    component->dump(res);
}

inline sp<Fence> makeFakeFence() {
    return sp<Fence>::make(memfd_create("fd", MFD_ALLOW_SEALING));
}

class SchedulerFuzzer {
public:
    SchedulerFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

private:
    void fuzzRefreshRateSelection();
    void fuzzRefreshRateSelector();
    void fuzzPresentLatencyTracker();
    void fuzzFrameTargeter();
    void fuzzVSyncModulator();
    void fuzzVSyncPredictor();
    void fuzzVSyncReactor();
    void fuzzLayerHistory();
    void fuzzCallbackToken(scheduler::VSyncDispatchTimerQueue* dispatch);
    void fuzzVSyncDispatchTimerQueue();
    void fuzzOneShotTimer();
    void fuzzEventThread();
    PhysicalDisplayId getPhysicalDisplayId();

    FuzzedDataProvider mFdp;

    std::shared_ptr<scheduler::VsyncSchedule> mVsyncSchedule;
};

PhysicalDisplayId SchedulerFuzzer::getPhysicalDisplayId() {
    PhysicalDisplayId internalDispId = PhysicalDisplayId::fromPort(111u);
    PhysicalDisplayId externalDispId = PhysicalDisplayId::fromPort(222u);
    PhysicalDisplayId randomDispId = PhysicalDisplayId::fromPort(mFdp.ConsumeIntegral<uint16_t>());
    PhysicalDisplayId dispId64Bit = PhysicalDisplayId::fromEdid(0xffu, 0xffffu, 0xffff'ffffu);
    PhysicalDisplayId displayId = mFdp.PickValueInArray<PhysicalDisplayId>(
            {internalDispId, externalDispId, dispId64Bit, randomDispId});
    return displayId;
}

struct EventThreadCallback : public IEventThreadCallback {
    bool throttleVsync(TimePoint, uid_t) override { return false; }
    Period getVsyncPeriod(uid_t) override { return kSyncPeriod; }
    void resync() override {}
};

void SchedulerFuzzer::fuzzEventThread() {
    mVsyncSchedule = std::shared_ptr<scheduler::VsyncSchedule>(
            new scheduler::VsyncSchedule(getPhysicalDisplayId(),
                                         std::make_shared<mock::VSyncTracker>(),
                                         std::make_shared<mock::VSyncDispatch>(), nullptr));
    EventThreadCallback callback;
    std::unique_ptr<android::impl::EventThread> thread = std::make_unique<
            android::impl::EventThread>("fuzzer", mVsyncSchedule, nullptr, callback,
                                        (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>(),
                                        (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>());

    thread->onHotplugReceived(getPhysicalDisplayId(), mFdp.ConsumeBool());
    sp<EventThreadConnection> connection =
            sp<EventThreadConnection>::make(thread.get(), mFdp.ConsumeIntegral<uint16_t>());
    thread->requestNextVsync(connection);
    thread->setVsyncRate(mFdp.ConsumeIntegral<uint32_t>() /*rate*/, connection);

    thread->setDuration((std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>(),
                        (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>());
    thread->registerDisplayEventConnection(connection);
    thread->enableSyntheticVsync(mFdp.ConsumeBool());
    dump<android::impl::EventThread>(thread.get(), &mFdp);
}

void SchedulerFuzzer::fuzzCallbackToken(scheduler::VSyncDispatchTimerQueue* dispatch) {
    scheduler::VSyncDispatch::CallbackToken tmp = dispatch->registerCallback(
            [&](auto, auto, auto) {
                dispatch->schedule(tmp,
                                   {.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                                    .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                                    .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()});
            },
            "o.o");
    dispatch->schedule(tmp,
                       {.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                        .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                        .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()});
    dispatch->unregisterCallback(tmp);
    dispatch->cancel(tmp);
}

void SchedulerFuzzer::fuzzVSyncDispatchTimerQueue() {
    auto stubTracker = std::make_shared<FuzzImplVSyncTracker>(mFdp.ConsumeIntegral<nsecs_t>());
    scheduler::VSyncDispatchTimerQueue
            mDispatch{std::make_unique<scheduler::ControllableClock>(), stubTracker,
                      mFdp.ConsumeIntegral<nsecs_t>() /*dispatchGroupThreshold*/,
                      mFdp.ConsumeIntegral<nsecs_t>() /*vSyncMoveThreshold*/};

    fuzzCallbackToken(&mDispatch);

    dump<scheduler::VSyncDispatchTimerQueue>(&mDispatch, &mFdp);

    scheduler::VSyncDispatchTimerQueueEntry entry(
            "fuzz", [](auto, auto, auto) {},
            mFdp.ConsumeIntegral<nsecs_t>() /*vSyncMoveThreshold*/);
    entry.update(*stubTracker, 0);
    entry.schedule({.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                    .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                    .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()},
                   *stubTracker, 0);
    entry.disarm();
    entry.ensureNotRunning();
    entry.schedule({.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                    .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                    .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()},
                   *stubTracker, 0);
    auto const wakeup = entry.wakeupTime();
    auto const ready = entry.readyTime();
    entry.callback(entry.executing(), *wakeup, *ready);
    entry.addPendingWorkloadUpdate({.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                                    .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                                    .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()});
    dump<scheduler::VSyncDispatchTimerQueueEntry>(&entry, &mFdp);
}

struct VsyncTrackerCallback : public scheduler::IVsyncTrackerCallback {
    void onVsyncGenerated(TimePoint, ftl::NonNull<DisplayModePtr>, Fps) override {}
};

void SchedulerFuzzer::fuzzVSyncPredictor() {
    uint16_t now = mFdp.ConsumeIntegral<uint16_t>();
    uint16_t historySize = mFdp.ConsumeIntegralInRange<uint16_t>(1, UINT16_MAX);
    uint16_t minimumSamplesForPrediction = mFdp.ConsumeIntegralInRange<uint16_t>(1, UINT16_MAX);
    nsecs_t idealPeriod = mFdp.ConsumeIntegralInRange<nsecs_t>(1, UINT32_MAX);
    VsyncTrackerCallback callback;
    const auto mode = ftl::as_non_null(
            mock::createDisplayMode(DisplayModeId(0), Fps::fromPeriodNsecs(idealPeriod)));
    scheduler::VSyncPredictor tracker{mode, historySize, minimumSamplesForPrediction,
                                      mFdp.ConsumeIntegral<uint32_t>() /*outlierTolerancePercent*/,
                                      callback};
    uint16_t period = mFdp.ConsumeIntegral<uint16_t>();
    tracker.setDisplayModePtr(ftl::as_non_null(
            mock::createDisplayMode(DisplayModeId(0), Fps::fromPeriodNsecs(period))));
    for (uint16_t i = 0; i < minimumSamplesForPrediction; ++i) {
        if (!tracker.needsMoreSamples()) {
            break;
        }
        tracker.addVsyncTimestamp(now += period);
    }
    tracker.nextAnticipatedVSyncTimeFrom(now);
    tracker.resetModel();
}

void SchedulerFuzzer::fuzzOneShotTimer() {
    FakeClock* clock = new FakeClock();
    std::unique_ptr<scheduler::OneShotTimer> idleTimer = std::make_unique<scheduler::OneShotTimer>(
            mFdp.ConsumeRandomLengthString(kRandomStringLength) /*name*/,
            (std::chrono::milliseconds)mFdp.ConsumeIntegral<uint8_t>() /*val*/,
            [] {} /*resetCallback*/, [] {} /*timeoutCallback*/, std::unique_ptr<FakeClock>(clock));
    idleTimer->start();
    idleTimer->reset();
    idleTimer->stop();
}

void SchedulerFuzzer::fuzzLayerHistory() {
    TestableSurfaceFlinger flinger;
    flinger.setupScheduler(std::make_unique<android::mock::VsyncController>(),
                           std::make_unique<android::mock::VSyncTracker>(),
                           std::make_unique<android::mock::EventThread>(),
                           std::make_unique<android::mock::EventThread>());
    flinger.setupTimeStats(std::make_unique<android::mock::TimeStats>());
    std::unique_ptr<android::renderengine::RenderEngine> renderEngine =
            std::make_unique<android::renderengine::mock::RenderEngine>();
    flinger.setupRenderEngine(std::move(renderEngine));
    flinger.setupComposer(std::make_unique<android::Hwc2::mock::Composer>());

    scheduler::TestableScheduler* scheduler = flinger.scheduler();

    scheduler::LayerHistory& historyV1 = scheduler->mutableLayerHistory();
    nsecs_t time1 = systemTime();
    nsecs_t time2 = time1;
    uint8_t historySize = mFdp.ConsumeIntegral<uint8_t>();

    sp<FuzzImplLayer> layer1 = sp<FuzzImplLayer>::make(flinger.flinger());
    sp<FuzzImplLayer> layer2 = sp<FuzzImplLayer>::make(flinger.flinger());

    for (int i = 0; i < historySize; ++i) {
        historyV1.record(layer1->getSequence(), layer1->getLayerProps(), time1, time1,
                         scheduler::LayerHistory::LayerUpdateType::Buffer);
        historyV1.record(layer2->getSequence(), layer2->getLayerProps(), time2, time2,
                         scheduler::LayerHistory::LayerUpdateType::Buffer);
        time1 += mFdp.PickValueInArray(kVsyncPeriods);
        time2 += mFdp.PickValueInArray(kVsyncPeriods);
    }
    historyV1.summarize(*scheduler->refreshRateSelector(), time1);
    historyV1.summarize(*scheduler->refreshRateSelector(), time2);

    scheduler->createConnection(std::make_unique<android::mock::EventThread>());

    scheduler::ConnectionHandle handle;
    scheduler->createDisplayEventConnection(handle);
    scheduler->setDuration(handle, (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>(),
                           (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>());

    std::string result = mFdp.ConsumeRandomLengthString(kRandomStringLength);
    utils::Dumper dumper(result);
    scheduler->dump(dumper);
}

void SchedulerFuzzer::fuzzVSyncReactor() {
    std::shared_ptr<FuzzImplVSyncTracker> vSyncTracker = std::make_shared<FuzzImplVSyncTracker>();
    scheduler::VSyncReactor reactor(kDisplayId,
                                    std::make_unique<ClockWrapper>(
                                            std::make_shared<FuzzImplClock>()),
                                    *vSyncTracker, mFdp.ConsumeIntegral<uint8_t>() /*pendingLimit*/,
                                    false);

    const auto mode = ftl::as_non_null(
            mock::createDisplayMode(DisplayModeId(0),
                                    Fps::fromPeriodNsecs(mFdp.ConsumeIntegral<nsecs_t>())));
    reactor.onDisplayModeChanged(mode, mFdp.ConsumeBool());
    bool periodFlushed = false; // Value does not matter, since this is an out
                                // param from addHwVsyncTimestamp.
    reactor.addHwVsyncTimestamp(0, std::nullopt, &periodFlushed);
    reactor.addHwVsyncTimestamp(mFdp.ConsumeIntegral<nsecs_t>() /*newPeriod*/, std::nullopt,
                                &periodFlushed);

    const auto fence = std::make_shared<FenceTime>(makeFakeFence());
    vSyncTracker->addVsyncTimestamp(mFdp.ConsumeIntegral<nsecs_t>());
    FenceTime::Snapshot snap(mFdp.ConsumeIntegral<nsecs_t>());
    fence->applyTrustedSnapshot(snap);
    reactor.setIgnorePresentFences(mFdp.ConsumeBool());
    reactor.addPresentFence(fence);
    dump<scheduler::VSyncReactor>(&reactor, &mFdp);
}

void SchedulerFuzzer::fuzzVSyncModulator() {
    enum {
        SF_OFFSET_LATE,
        APP_OFFSET_LATE,
        SF_DURATION_LATE,
        APP_DURATION_LATE,
        SF_OFFSET_EARLY,
        APP_OFFSET_EARLY,
        SF_DURATION_EARLY,
        APP_DURATION_EARLY,
        SF_OFFSET_EARLY_GPU,
        APP_OFFSET_EARLY_GPU,
        SF_DURATION_EARLY_GPU,
        APP_DURATION_EARLY_GPU,
        HWC_MIN_WORK_DURATION,
    };
    using Schedule = scheduler::TransactionSchedule;
    using nanos = std::chrono::nanoseconds;
    using FuzzImplVsyncModulator = scheduler::FuzzImplVsyncModulator;
    const scheduler::VsyncConfig early{SF_OFFSET_EARLY, APP_OFFSET_EARLY, nanos(SF_DURATION_LATE),
                                       nanos(APP_DURATION_LATE)};
    const scheduler::VsyncConfig earlyGpu{SF_OFFSET_EARLY_GPU, APP_OFFSET_EARLY_GPU,
                                          nanos(SF_DURATION_EARLY), nanos(APP_DURATION_EARLY)};
    const scheduler::VsyncConfig late{SF_OFFSET_LATE, APP_OFFSET_LATE, nanos(SF_DURATION_EARLY_GPU),
                                      nanos(APP_DURATION_EARLY_GPU)};
    const scheduler::VsyncConfigSet offsets = {early, earlyGpu, late, nanos(HWC_MIN_WORK_DURATION)};
    sp<FuzzImplVsyncModulator> vSyncModulator =
            sp<FuzzImplVsyncModulator>::make(offsets, scheduler::Now);
    (void)vSyncModulator->setVsyncConfigSet(offsets);
    (void)vSyncModulator->setTransactionSchedule(Schedule::Late);
    const auto token = sp<BBinder>::make();
    (void)vSyncModulator->setTransactionSchedule(Schedule::EarlyStart, token);
    vSyncModulator->binderDied(token);
}

void SchedulerFuzzer::fuzzRefreshRateSelection() {
    TestableSurfaceFlinger flinger;
    flinger.setupScheduler(std::make_unique<android::mock::VsyncController>(),
                           std::make_unique<android::mock::VSyncTracker>(),
                           std::make_unique<android::mock::EventThread>(),
                           std::make_unique<android::mock::EventThread>());

    sp<Client> client;
    LayerCreationArgs args(flinger.flinger(), client,
                           mFdp.ConsumeRandomLengthString(kRandomStringLength) /*name*/,
                           mFdp.ConsumeIntegral<uint16_t>() /*layerFlags*/, LayerMetadata());
    sp<Layer> layer = sp<Layer>::make(args);

    layer->setFrameRateSelectionPriority(mFdp.ConsumeIntegral<int16_t>());
}

void SchedulerFuzzer::fuzzRefreshRateSelector() {
    using RefreshRateSelector = scheduler::RefreshRateSelector;
    using LayerRequirement = RefreshRateSelector::LayerRequirement;
    using RefreshRateStats = scheduler::RefreshRateStats;

    const uint16_t minRefreshRate = mFdp.ConsumeIntegralInRange<uint16_t>(1, UINT16_MAX >> 1);
    const uint16_t maxRefreshRate =
            mFdp.ConsumeIntegralInRange<uint16_t>(minRefreshRate + 1, UINT16_MAX);

    const DisplayModeId modeId{mFdp.ConsumeIntegralInRange<uint8_t>(0, 10)};

    DisplayModes displayModes;
    for (uint16_t fps = minRefreshRate; fps < maxRefreshRate; ++fps) {
        displayModes.try_emplace(modeId,
                                 mock::createDisplayMode(modeId,
                                                         Fps::fromValue(static_cast<float>(fps))));
    }

    RefreshRateSelector refreshRateSelector(displayModes, modeId);

    const RefreshRateSelector::GlobalSignals globalSignals = {.touch = false, .idle = false};
    std::vector<LayerRequirement> layers = {{.weight = mFdp.ConsumeFloatingPoint<float>()}};

    refreshRateSelector.getRankedFrameRates(layers, globalSignals);

    layers[0].name = mFdp.ConsumeRandomLengthString(kRandomStringLength);
    layers[0].ownerUid = mFdp.ConsumeIntegral<uint16_t>();
    layers[0].desiredRefreshRate = Fps::fromValue(mFdp.ConsumeFloatingPoint<float>());
    layers[0].vote = mFdp.PickValueInArray(kLayerVoteTypes.values);
    auto frameRateOverrides =
            refreshRateSelector.getFrameRateOverrides(layers,
                                                      Fps::fromValue(
                                                              mFdp.ConsumeFloatingPoint<float>()),
                                                      globalSignals);

    {
        ftl::FakeGuard guard(kMainThreadContext);

        refreshRateSelector.setPolicy(
                RefreshRateSelector::
                        DisplayManagerPolicy{modeId,
                                             {Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()),
                                              Fps::fromValue(mFdp.ConsumeFloatingPoint<float>())}});
        refreshRateSelector.setPolicy(
                RefreshRateSelector::OverridePolicy{modeId,
                                                    {Fps::fromValue(
                                                             mFdp.ConsumeFloatingPoint<float>()),
                                                     Fps::fromValue(
                                                             mFdp.ConsumeFloatingPoint<float>())}});
        refreshRateSelector.setPolicy(RefreshRateSelector::NoOverridePolicy{});

        refreshRateSelector.setActiveMode(modeId,
                                          Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()));
    }

    RefreshRateSelector::isFractionalPairOrMultiple(Fps::fromValue(
                                                            mFdp.ConsumeFloatingPoint<float>()),
                                                    Fps::fromValue(
                                                            mFdp.ConsumeFloatingPoint<float>()));
    RefreshRateSelector::getFrameRateDivisor(Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()),
                                             Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()));

    android::mock::TimeStats timeStats;
    RefreshRateStats refreshRateStats(timeStats, Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()),
                                      PowerMode::OFF);

    const auto fpsOpt = displayModes.get(modeId).transform(
            [](const DisplayModePtr& mode) { return mode->getVsyncRate(); });
    refreshRateStats.setRefreshRate(*fpsOpt);

    refreshRateStats.setPowerMode(mFdp.PickValueInArray(kPowerModes));
}

void SchedulerFuzzer::fuzzPresentLatencyTracker() {
    scheduler::PresentLatencyTracker tracker;

    int i = 5;
    while (i-- > 0) {
        tracker.trackPendingFrame(getFuzzedTimePoint(mFdp),
                                  std::make_shared<FenceTime>(makeFakeFence()));
    }
}

void SchedulerFuzzer::fuzzFrameTargeter() {
    scheduler::FrameTargeter frameTargeter(kDisplayId, mFdp.ConsumeBool());

    const struct VsyncSource final : scheduler::IVsyncSource {
        explicit VsyncSource(FuzzedDataProvider& fuzzer) : fuzzer(fuzzer) {}
        FuzzedDataProvider& fuzzer;

        Period period() const { return getFuzzedDuration(fuzzer); }
        TimePoint vsyncDeadlineAfter(TimePoint) const { return getFuzzedTimePoint(fuzzer); }
        Period minFramePeriod() const { return period(); }
    } vsyncSource{mFdp};

    int i = 10;
    while (i-- > 0) {
        frameTargeter.beginFrame({.frameBeginTime = getFuzzedTimePoint(mFdp),
                                  .vsyncId = getFuzzedVsyncId(mFdp),
                                  .expectedVsyncTime = getFuzzedTimePoint(mFdp),
                                  .sfWorkDuration = getFuzzedDuration(mFdp)},
                                 vsyncSource);

        frameTargeter.setPresentFence(makeFakeFence());

        frameTargeter.endFrame(
                {.compositionCoverage = mFdp.PickValueInArray(kCompositionCoverage.values)});
    }
}

void SchedulerFuzzer::process() {
    fuzzRefreshRateSelection();
    fuzzRefreshRateSelector();
    fuzzPresentLatencyTracker();
    fuzzFrameTargeter();
    fuzzVSyncModulator();
    fuzzVSyncPredictor();
    fuzzVSyncReactor();
    fuzzLayerHistory();
    fuzzEventThread();
    fuzzVSyncDispatchTimerQueue();
    fuzzOneShotTimer();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    SchedulerFuzzer schedulerFuzzer(data, size);
    schedulerFuzzer.process();
    return 0;
}

} // namespace android::fuzz
