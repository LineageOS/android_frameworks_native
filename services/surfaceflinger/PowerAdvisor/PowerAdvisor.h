/*
 * Copyright 2018 The Android Open Source Project
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

#include <atomic>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <android/binder_auto_utils.h>
#include <ui/DisplayId.h>
#include <ui/FenceTime.h>
#include <ui/RingBuffer.h>
#include <utils/Mutex.h>

// FMQ library in IPower does questionable conversions
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <aidl/android/hardware/power/IPower.h>
#include <fmq/AidlMessageQueue.h>
#pragma clang diagnostic pop

#include <common/trace.h>
#include <ftl/flags.h>
#include <scheduler/Time.h>
#include "../Scheduler/OneShotTimer.h"
#include "Workload.h"

#include "SessionManager.h"

using namespace std::chrono_literals;

namespace android {

namespace power {
class PowerHalController;
class PowerHintSessionWrapper;
} // namespace power

namespace adpf {

namespace hal = aidl::android::hardware::power;

class PowerAdvisor {
public:
    virtual ~PowerAdvisor() = default;

    // Initializes resources that cannot be initialized on construction
    virtual void init() = 0;
    // Used to indicate that power hints can now be reported
    virtual void onBootFinished() = 0;
    virtual void setExpensiveRenderingExpected(DisplayId displayId, bool expected) = 0;
    virtual bool isUsingExpensiveRendering() = 0;
    // Checks both if it's supported and if it's enabled; this is thread-safe since its values are
    // set before onBootFinished, which gates all methods that run on threads other than SF main
    virtual bool usePowerHintSession() = 0;
    virtual bool supportsPowerHintSession() = 0;
    virtual bool supportsGpuReporting() = 0;
    virtual void setOptimizeForPerformance(bool enabled) = 0;

    // Sends a power hint that updates to the target work duration for the frame
    virtual void updateTargetWorkDuration(Duration targetDuration) = 0;
    // Sends a power hint for the actual known work duration at the end of the frame
    virtual void reportActualWorkDuration() = 0;
    // Sets whether the power hint session is enabled
    virtual void enablePowerHintSession(bool enabled) = 0;
    // Initializes the power hint session
    virtual bool startPowerHintSession(std::vector<int32_t>&& threadIds) = 0;
    // Provides PowerAdvisor with gpu start time
    virtual void setGpuStartTime(DisplayId displayId, TimePoint startTime) = 0;
    // Provides PowerAdvisor with a copy of the gpu fence so it can determine the gpu end time
    virtual void setGpuFenceTime(DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime) = 0;
    // Reports the start and end times of a hwc validate call this frame for a given display
    virtual void setHwcValidateTiming(DisplayId displayId, TimePoint validateStartTime,
                                      TimePoint validateEndTime) = 0;
    // Reports the start and end times of a hwc present call this frame for a given display
    virtual void setHwcPresentTiming(DisplayId displayId, TimePoint presentStartTime,
                                     TimePoint presentEndTime) = 0;
    // Reports the expected time that the current frame will present to the display
    virtual void setExpectedPresentTime(TimePoint expectedPresentTime) = 0;
    // Reports the most recent present fence time and end time once known
    virtual void setSfPresentTiming(TimePoint presentFenceTime, TimePoint presentEndTime) = 0;
    // Reports whether a display requires RenderEngine to draw
    virtual void setRequiresRenderEngine(DisplayId displayId, bool requiresRenderEngine) = 0;
    // Reports whether a given display skipped validation this frame
    virtual void setSkippedValidate(DisplayId displayId, bool skipped) = 0;
    // Reports when a hwc present is delayed, and the time that it will resume
    virtual void setHwcPresentDelayedTime(DisplayId displayId,
                                          TimePoint earliestFrameStartTime) = 0;
    // Reports the start delay for SurfaceFlinger this frame
    virtual void setFrameDelay(Duration frameDelayDuration) = 0;
    // Reports the SurfaceFlinger commit start time this frame
    virtual void setCommitStart(TimePoint commitStartTime) = 0;
    // Reports the SurfaceFlinger composite end time this frame
    virtual void setCompositeEnd(TimePoint compositeEndTime) = 0;
    // Reports the list of the currently active displays
    virtual void setDisplays(std::vector<DisplayId>& displayIds) = 0;
    // Sets the target duration for the entire pipeline including the gpu
    virtual void setTotalFrameTargetWorkDuration(Duration targetDuration) = 0;
    // Get the session manager, if it exists
    virtual std::shared_ptr<SessionManager> getSessionManager() = 0;
    // Tells the power HAL the current refresh rate so it can switch ADPF profile
    virtual void notifyRefreshRate(int32_t refreshRate) = 0;

    // --- Track per frame workloads to use for load up hint heuristics
    // Track queued workload from transactions as they are queued from the binder thread.
    // The workload is accumulated and reset on frame commit. The queued workload may be
    // relevant for the next frame so can be used as an early load up hint. Note this is
    // only a hint because the transaction can remain in the queue and not be applied on
    // the next frame.
    virtual void setQueuedWorkload(ftl::Flags<Workload> workload) = 0;
    // Track additional workload dur to a screenshot request for load up hint heuristics. This
    // would indicate an immediate increase in GPU workload.
    virtual void setScreenshotWorkload() = 0;
    // Track committed workload from transactions that are applied on the main thread.
    // This workload is determined from the applied transactions. This can provide a high
    // confidence that the CPU and or GPU workload will increase immediately.
    virtual void setCommittedWorkload(ftl::Flags<Workload> workload) = 0;
    // Update committed workload with the actual workload from post composition. This is
    // used to update the baseline workload so we can detect increases in workloads on the
    // next commit. We use composite instead of commit to update the baseline to account
    // for optimizations like caching which may reduce the workload.
    virtual void setCompositedWorkload(ftl::Flags<Workload> workload) = 0;

    // --- The following methods may run on threads besides SF main ---
    // Send a hint about an upcoming increase in the CPU workload
    virtual void notifyCpuLoadUp() = 0;
    // Send a hint about the imminent start of a new CPU workload
    virtual void notifyDisplayUpdateImminentAndCpuReset() = 0;

    // --- The following methods specifically run on binder threads ---
    // Retrieve  a SessionManager for HintManagerService to call
    virtual sp<IBinder> getOrCreateSessionManagerForBinder(uid_t uid) = 0;
};

namespace impl {

// PowerAdvisor is a wrapper around IPower HAL which takes into account the
// full state of the system when sending out power hints to things like the GPU.
class PowerAdvisor final : public adpf::PowerAdvisor {
public:
    PowerAdvisor(std::function<void()>&& function, std::chrono::milliseconds timeout);
    ~PowerAdvisor() override;

    void init() override;
    void onBootFinished() override;
    void setExpensiveRenderingExpected(DisplayId displayId, bool expected) override;
    bool isUsingExpensiveRendering() override { return mNotifiedExpensiveRendering; };
    bool usePowerHintSession() override;
    bool supportsPowerHintSession() override;
    bool supportsGpuReporting() override;
    void setOptimizeForPerformance(bool enabled) override;
    void updateTargetWorkDuration(Duration targetDuration) override;
    void reportActualWorkDuration() override;
    void enablePowerHintSession(bool enabled) override;
    bool startPowerHintSession(std::vector<int32_t>&& threadIds) override;
    void setGpuStartTime(DisplayId displayId, TimePoint startTime) override;
    void setGpuFenceTime(DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime) override;
    void setHwcValidateTiming(DisplayId displayId, TimePoint validateStartTime,
                              TimePoint validateEndTime) override;
    void setHwcPresentTiming(DisplayId displayId, TimePoint presentStartTime,
                             TimePoint presentEndTime) override;
    void setSkippedValidate(DisplayId displayId, bool skipped) override;
    void setRequiresRenderEngine(DisplayId displayId, bool requiresRenderEngine);
    void setExpectedPresentTime(TimePoint expectedPresentTime) override;
    void setSfPresentTiming(TimePoint presentFenceTime, TimePoint presentEndTime) override;
    void setHwcPresentDelayedTime(DisplayId displayId, TimePoint earliestFrameStartTime) override;
    void setFrameDelay(Duration frameDelayDuration) override;
    void setCommitStart(TimePoint commitStartTime) override;
    void setCompositeEnd(TimePoint compositeEndTime) override;
    void setDisplays(std::vector<DisplayId>& displayIds) override;
    void setTotalFrameTargetWorkDuration(Duration targetDuration) override;
    std::shared_ptr<SessionManager> getSessionManager() override;
    void notifyRefreshRate(int32_t refreshRate) override;

    void setQueuedWorkload(ftl::Flags<Workload> workload) override;
    void setScreenshotWorkload() override;
    void setCommittedWorkload(ftl::Flags<Workload> workload) override;
    void setCompositedWorkload(ftl::Flags<Workload> workload) override;

    // --- The following methods may run on threads besides SF main ---
    void notifyCpuLoadUp() override;
    void notifyDisplayUpdateImminentAndCpuReset() override;

    // --- The following methods specifically run on binder threads ---
    sp<IBinder> getOrCreateSessionManagerForBinder(uid_t uid) override;

private:
    friend class PowerAdvisorTest;

    std::unique_ptr<power::PowerHalController> mPowerHal;
    std::atomic_bool mBootFinished = false;
    std::atomic_bool mOptimizeForPerformance = true;

    std::unordered_set<DisplayId> mExpensiveDisplays;
    bool mNotifiedExpensiveRendering = false;

    std::atomic_bool mSendUpdateImminent = true;
    std::atomic<nsecs_t> mLastScreenUpdatedTime = 0;
    std::optional<scheduler::OneShotTimer> mScreenUpdateTimer;

    // Higher-level timing data used for estimation
    struct DisplayTimeline {
        // The start of hwc present, or the start of validate if it happened there instead
        TimePoint hwcPresentStartTime;
        // The end of hwc present or validate, whichever one actually presented
        TimePoint hwcPresentEndTime;
        // How long the actual hwc present was delayed after hwcPresentStartTime
        Duration hwcPresentDelayDuration{0ns};
        // When we think we started waiting for the present fence after calling into hwc present and
        // after potentially waiting for the earliest present time
        TimePoint presentFenceWaitStartTime;
        // How long we ran after we finished waiting for the fence but before hwc present finished
        Duration postPresentFenceHwcPresentDuration{0ns};
        // Are we likely to have waited for the present fence during composition
        bool probablyWaitsForPresentFence = false;
    };

    struct GpuTimeline {
        Duration duration{0ns};
        TimePoint startTime;
    };

    // Power hint session data recorded from the pipeline
    struct DisplayTimingData {
        std::unique_ptr<FenceTime> gpuEndFenceTime;
        std::optional<TimePoint> gpuStartTime;
        std::optional<TimePoint> lastValidGpuEndTime;
        std::optional<TimePoint> lastValidGpuStartTime;
        std::optional<TimePoint> hwcPresentStartTime;
        std::optional<TimePoint> hwcPresentEndTime;
        std::optional<TimePoint> hwcValidateStartTime;
        std::optional<TimePoint> hwcValidateEndTime;
        std::optional<TimePoint> hwcPresentDelayedTime;
        bool requiresRenderEngine = false;
        bool skippedValidate = false;
        // Calculate high-level timing milestones from more granular display timing data
        DisplayTimeline calculateDisplayTimeline(TimePoint fenceTime);
        // Estimate the gpu duration for a given display from previous gpu timing data
        std::optional<GpuTimeline> estimateGpuTiming(std::optional<TimePoint> previousEndTime);
    };

    // Filter and sort the display ids by a given property
    std::vector<DisplayId> getOrderedDisplayIds(
            std::optional<TimePoint> DisplayTimingData::*sortBy);
    // Estimates a frame's total work duration including gpu and gpu time.
    std::optional<aidl::android::hardware::power::WorkDuration> estimateWorkDuration();
    // There are two different targets and actual work durations we care about,
    // this normalizes them together and takes the max of the two
    Duration combineTimingEstimates(Duration totalDuration, Duration flingerDuration);
    // Whether to use the new "createHintSessionWithConfig" method
    bool shouldCreateSessionWithConfig() REQUIRES(mHintSessionMutex);

    bool ensurePowerHintSessionRunning() REQUIRES(mHintSessionMutex);
    void setUpFmq() REQUIRES(mHintSessionMutex);
    std::unordered_map<DisplayId, DisplayTimingData> mDisplayTimingData;
    // Current frame's delay
    Duration mFrameDelayDuration{0ns};
    // Last frame's post-composition duration
    Duration mLastPostcompDuration{0ns};
    // Buffer of recent commit start times
    ui::RingBuffer<TimePoint, 2> mCommitStartTimes;
    // Buffer of recent expected present times
    ui::RingBuffer<TimePoint, 2> mExpectedPresentTimes;
    // Most recent present fence time, provided by SF after composition engine finishes presenting
    TimePoint mLastPresentFenceTime;
    // Most recent composition engine present end time, returned with the present fence from SF
    TimePoint mLastSfPresentEndTime;
    // Target duration for the entire pipeline including gpu
    std::optional<Duration> mTotalFrameTargetDuration;
    // Updated list of display IDs
    std::vector<DisplayId> mDisplayIds;

    // Ensure powerhal connection is initialized
    power::PowerHalController& getPowerHal();

    void refreshRateHintLoop();
    bool applyRefreshRateHint(int32_t refreshRate);
    bool setPowerExtMode(const std::string& mode, bool enabled);

    std::mutex mRefreshRateMutex;
    std::condition_variable mRefreshRateCv;
    std::thread mRefreshRateThread;
    std::optional<int32_t> mPendingRefreshRate;
    int32_t mLastNotifiedRefreshRate = 0;
    bool mRefreshRateStopped = false;

    // Only used on mRefreshRateThread
    ndk::SpAIBinder mPowerExtBinder;

    // These variables are set before mBootFinished and never mutated after, so it's safe to access
    // from threaded methods.
    std::optional<bool> mHintSessionEnabled;
    std::optional<bool> mSupportsHintSession;

    std::mutex mHintSessionMutex;
    std::shared_ptr<power::PowerHintSessionWrapper> mHintSession GUARDED_BY(mHintSessionMutex) =
            nullptr;

    // Initialize to true so we try to call, to check if it's supported
    bool mHasExpensiveRendering = true;
    bool mHasDisplayUpdateImminent = true;
    // Queue of actual durations saved to report
    std::vector<aidl::android::hardware::power::WorkDuration> mHintSessionQueue;
    std::unique_ptr<::android::AidlMessageQueue<
            aidl::android::hardware::power::ChannelMessage,
            ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>>
            mMsgQueue GUARDED_BY(mHintSessionMutex);
    std::unique_ptr<::android::AidlMessageQueue<
            int8_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>>
            mFlagQueue GUARDED_BY(mHintSessionMutex);
    android::hardware::EventFlag* mEventFlag;
    uint32_t mFmqWriteMask;
    // The latest values we have received for target and actual
    Duration mTargetDuration = kDefaultTargetDuration;
    // The list of thread ids, stored so we can restart the session from this class if needed
    std::vector<int32_t> mHintSessionThreadIds;
    Duration mLastTargetDurationSent = kDefaultTargetDuration;

    // Used to manage the execution ordering of reportActualWorkDuration for concurrency testing
    std::promise<bool> mDelayReportActualMutexAcquisitonPromise;
    bool mTimingTestingMode = false;

    // Hint session configuration data
    aidl::android::hardware::power::SessionConfig mSessionConfig;

    // Whether createHintSessionWithConfig is supported, assume true until it fails
    bool mSessionConfigSupported = true;
    bool mFirstConfigSupportCheck = true;

    // Whether we should emit SFTRACE_INT data for hint sessions
    static const bool sTraceHintSessionData;

    // Default target duration for the hint session
    static constexpr const Duration kDefaultTargetDuration{16ms};

    // An adjustable safety margin which pads the "actual" value sent to PowerHAL,
    // encouraging more aggressive boosting to give SurfaceFlinger a larger margin for error
    static const Duration sTargetSafetyMargin;
    static constexpr const Duration kDefaultTargetSafetyMargin{1ms};

    // Whether we should send reportActualWorkDuration calls
    static const bool sUseReportActualDuration;

    // How long we expect hwc to run after the present call until it waits for the fence
    static constexpr const Duration kFenceWaitStartDelayValidated{150us};
    static constexpr const Duration kFenceWaitStartDelaySkippedValidate{250us};

    // Track queued and committed workloads per frame. Queued workload is atomic because it's
    // updated on both binder and the main thread.
    std::atomic<uint32_t> mQueuedWorkload;
    ftl::Flags<Workload> mCommittedWorkload;

    void sendHintSessionHint(aidl::android::hardware::power::SessionHint hint);

    template <aidl::android::hardware::power::ChannelMessage::ChannelMessageContents::Tag T,
              class In>
    bool writeHintSessionMessage(In* elements, size_t count) REQUIRES(mHintSessionMutex);

    std::shared_ptr<SessionManager> mSessionManager;
};

} // namespace impl
} // namespace adpf
} // namespace android
