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
#include <chrono>
#include <unordered_map>
#include <unordered_set>

#include <ui/DisplayId.h>
#include <ui/FenceTime.h>
#include <utils/Mutex.h>

// FMQ library in IPower does questionable conversions
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <aidl/android/hardware/power/IPower.h>
#include <powermanager/PowerHalController.h>
#pragma clang diagnostic pop

#include <compositionengine/impl/OutputCompositionState.h>
#include <scheduler/Time.h>
#include <ui/DisplayIdentification.h>
#include "../Scheduler/OneShotTimer.h"

using namespace std::chrono_literals;

namespace android {

class SurfaceFlinger;

namespace Hwc2 {

class PowerAdvisor {
public:
    virtual ~PowerAdvisor();

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

    // Sends a power hint that updates to the target work duration for the frame
    virtual void updateTargetWorkDuration(Duration targetDuration) = 0;
    // Sends a power hint for the actual known work duration at the end of the frame
    virtual void reportActualWorkDuration() = 0;
    // Sets whether the power hint session is enabled
    virtual void enablePowerHintSession(bool enabled) = 0;
    // Initializes the power hint session
    virtual bool startPowerHintSession(std::vector<int32_t>&& threadIds) = 0;
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
    // Reports whether a display used client composition this frame
    virtual void setRequiresClientComposition(DisplayId displayId,
                                              bool requiresClientComposition) = 0;
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

    // --- The following methods may run on threads besides SF main ---
    // Send a hint about an upcoming increase in the CPU workload
    virtual void notifyCpuLoadUp() = 0;
    // Send a hint about the imminent start of a new CPU workload
    virtual void notifyDisplayUpdateImminentAndCpuReset() = 0;
};

namespace impl {

// PowerAdvisor is a wrapper around IPower HAL which takes into account the
// full state of the system when sending out power hints to things like the GPU.
class PowerAdvisor final : public Hwc2::PowerAdvisor {
public:
    PowerAdvisor(SurfaceFlinger& flinger);
    ~PowerAdvisor() override;

    void init() override;
    void onBootFinished() override;
    void setExpensiveRenderingExpected(DisplayId displayId, bool expected) override;
    bool isUsingExpensiveRendering() override { return mNotifiedExpensiveRendering; };
    bool usePowerHintSession() override;
    bool supportsPowerHintSession() override;
    void updateTargetWorkDuration(Duration targetDuration) override;
    void reportActualWorkDuration() override;
    void enablePowerHintSession(bool enabled) override;
    bool startPowerHintSession(std::vector<int32_t>&& threadIds) override;
    void setGpuFenceTime(DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime) override;
    void setHwcValidateTiming(DisplayId displayId, TimePoint validateStartTime,
                              TimePoint validateEndTime) override;
    void setHwcPresentTiming(DisplayId displayId, TimePoint presentStartTime,
                             TimePoint presentEndTime) override;
    void setSkippedValidate(DisplayId displayId, bool skipped) override;
    void setRequiresClientComposition(DisplayId displayId, bool requiresClientComposition) override;
    void setExpectedPresentTime(TimePoint expectedPresentTime) override;
    void setSfPresentTiming(TimePoint presentFenceTime, TimePoint presentEndTime) override;
    void setHwcPresentDelayedTime(DisplayId displayId, TimePoint earliestFrameStartTime) override;
    void setFrameDelay(Duration frameDelayDuration) override;
    void setCommitStart(TimePoint commitStartTime) override;
    void setCompositeEnd(TimePoint compositeEndTime) override;
    void setDisplays(std::vector<DisplayId>& displayIds) override;
    void setTotalFrameTargetWorkDuration(Duration targetDuration) override;

    // --- The following methods may run on threads besides SF main ---
    void notifyCpuLoadUp() override;
    void notifyDisplayUpdateImminentAndCpuReset() override;

private:
    friend class PowerAdvisorTest;

    std::unique_ptr<power::PowerHalController> mPowerHal;
    std::atomic_bool mBootFinished = false;

    std::unordered_set<DisplayId> mExpensiveDisplays;
    bool mNotifiedExpensiveRendering = false;

    SurfaceFlinger& mFlinger;
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
        bool usedClientComposition = false;
        bool skippedValidate = false;
        // Calculate high-level timing milestones from more granular display timing data
        DisplayTimeline calculateDisplayTimeline(TimePoint fenceTime);
        // Estimate the gpu duration for a given display from previous gpu timing data
        std::optional<GpuTimeline> estimateGpuTiming(std::optional<TimePoint> previousEndTime);
    };

    template <class T, size_t N>
    class RingBuffer {
        std::array<T, N> elements = {};
        size_t mIndex = 0;
        size_t numElements = 0;

    public:
        void append(T item) {
            mIndex = (mIndex + 1) % N;
            numElements = std::min(N, numElements + 1);
            elements[mIndex] = item;
        }
        bool isFull() const { return numElements == N; }
        // Allows access like [0] == current, [-1] = previous, etc..
        T& operator[](int offset) {
            size_t positiveOffset =
                    static_cast<size_t>((offset % static_cast<int>(N)) + static_cast<int>(N));
            return elements[(mIndex + positiveOffset) % N];
        }
    };

    // Filter and sort the display ids by a given property
    std::vector<DisplayId> getOrderedDisplayIds(
            std::optional<TimePoint> DisplayTimingData::*sortBy);
    // Estimates a frame's total work duration including gpu time.
    std::optional<Duration> estimateWorkDuration();
    // There are two different targets and actual work durations we care about,
    // this normalizes them together and takes the max of the two
    Duration combineTimingEstimates(Duration totalDuration, Duration flingerDuration);

    bool ensurePowerHintSessionRunning() REQUIRES(mHintSessionMutex);
    std::unordered_map<DisplayId, DisplayTimingData> mDisplayTimingData;

    // Current frame's delay
    Duration mFrameDelayDuration{0ns};
    // Last frame's post-composition duration
    Duration mLastPostcompDuration{0ns};
    // Buffer of recent commit start times
    RingBuffer<TimePoint, 2> mCommitStartTimes;
    // Buffer of recent expected present times
    RingBuffer<TimePoint, 2> mExpectedPresentTimes;
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

    // These variables are set before mBootFinished and never mutated after, so it's safe to access
    // from threaded methods.
    std::optional<bool> mHintSessionEnabled;
    std::optional<bool> mSupportsHintSession;

    std::mutex mHintSessionMutex;
    std::shared_ptr<aidl::android::hardware::power::IPowerHintSession> mHintSession
            GUARDED_BY(mHintSessionMutex) = nullptr;

    // Initialize to true so we try to call, to check if it's supported
    bool mHasExpensiveRendering = true;
    bool mHasDisplayUpdateImminent = true;
    // Queue of actual durations saved to report
    std::vector<aidl::android::hardware::power::WorkDuration> mHintSessionQueue;
    // The latest values we have received for target and actual
    Duration mTargetDuration = kDefaultTargetDuration;
    std::optional<Duration> mActualDuration;
    // The list of thread ids, stored so we can restart the session from this class if needed
    std::vector<int32_t> mHintSessionThreadIds;
    Duration mLastTargetDurationSent = kDefaultTargetDuration;

    // Used to manage the execution ordering of reportActualWorkDuration for concurrency testing
    std::promise<bool> mDelayReportActualMutexAcquisitonPromise;
    bool mTimingTestingMode = false;

    // Whether we should emit ATRACE_INT data for hint sessions
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
};

} // namespace impl
} // namespace Hwc2
} // namespace android
