/*
 * Copyright 2020 The Android Open Source Project
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

#include <../TimeStats/TimeStats.h>
#include <gui/ISurfaceComposer.h>
#include <gui/JankInfo.h>
#include <perfetto/trace/android/frame_timeline_event.pbzero.h>
#include <perfetto/tracing.h>
#include <ui/FenceTime.h>
#include <utils/RefBase.h>
#include <utils/String16.h>
#include <utils/Timers.h>
#include <utils/Vector.h>

#include <deque>
#include <mutex>

namespace android::frametimeline {

enum JankMetadata {
    // Frame was presented earlier than expected
    EarlyPresent = 0x1,
    // Frame was presented later than expected
    LatePresent = 0x2,
    // App/SF started earlier than expected
    EarlyStart = 0x4,
    // App/SF started later than expected
    LateStart = 0x8,
    // App/SF finished work earlier than the deadline
    EarlyFinish = 0x10,
    // App/SF finished work later than the deadline
    LateFinish = 0x20,
    // SF was in GPU composition
    GpuComposition = 0x40,
};

class FrameTimelineTest;

/*
 * Collection of timestamps that can be used for both predictions and actual times.
 */
struct TimelineItem {
    TimelineItem(const nsecs_t startTime = 0, const nsecs_t endTime = 0,
                 const nsecs_t presentTime = 0)
          : startTime(startTime), endTime(endTime), presentTime(presentTime) {}

    nsecs_t startTime;
    nsecs_t endTime;
    nsecs_t presentTime;

    bool operator==(const TimelineItem& other) const {
        return startTime == other.startTime && endTime == other.endTime &&
                presentTime == other.presentTime;
    }

    bool operator!=(const TimelineItem& other) const { return !(*this == other); }
};

/*
 * TokenManager generates a running number token for a set of predictions made by VsyncPredictor. It
 * saves these predictions for a short period of time and returns the predictions for a given token,
 * if it hasn't expired.
 */
class TokenManager {
public:
    virtual ~TokenManager() = default;

    // Generates a token for the given set of predictions. Stores the predictions for 120ms and
    // destroys it later.
    virtual int64_t generateTokenForPredictions(TimelineItem&& prediction) = 0;
};

enum class PredictionState {
    Valid,   // Predictions obtained successfully from the TokenManager
    Expired, // TokenManager no longer has the predictions
    None,    // Predictions are either not present or didn't come from TokenManager
};

/*
 * Stores a set of predictions and the corresponding actual timestamps pertaining to a single frame
 * from the app
 */
class SurfaceFrame {
public:
    enum class PresentState {
        Presented, // Buffer was latched and presented by SurfaceFlinger
        Dropped,   // Buffer was dropped by SurfaceFlinger
        Unknown,   // Initial state, SurfaceFlinger hasn't seen this buffer yet
    };

    virtual ~SurfaceFrame() = default;

    virtual TimelineItem getPredictions() const = 0;
    virtual TimelineItem getActuals() const = 0;
    virtual nsecs_t getActualQueueTime() const = 0;
    virtual PresentState getPresentState() const = 0;
    virtual PredictionState getPredictionState() const = 0;
    virtual pid_t getOwnerPid() const = 0;

    virtual void setPresentState(PresentState state) = 0;

    // Actual timestamps of the app are set individually at different functions.
    // Start time (if the app provides) and Queue time are accessible after queueing the frame,
    // whereas Acquire Fence time is available only during latch.
    virtual void setActualStartTime(nsecs_t actualStartTime) = 0;
    virtual void setActualQueueTime(nsecs_t actualQueueTime) = 0;
    virtual void setAcquireFenceTime(nsecs_t acquireFenceTime) = 0;
};

/*
 * Maintains a history of SurfaceFrames grouped together by the vsync time in which they were
 * presented
 */
class FrameTimeline {
public:
    virtual ~FrameTimeline() = default;
    virtual TokenManager* getTokenManager() = 0;

    // Initializes the Perfetto DataSource that emits DisplayFrame and SurfaceFrame events. Test
    // classes can avoid double registration by mocking this function.
    virtual void onBootFinished() = 0;

    // Create a new surface frame, set the predictions based on a token and return it to the caller.
    // Sets the PredictionState of SurfaceFrame.
    // Debug name is the human-readable debugging string for dumpsys.
    virtual std::unique_ptr<SurfaceFrame> createSurfaceFrameForToken(
            pid_t ownerPid, uid_t ownerUid, std::string layerName, std::string debugName,
            std::optional<int64_t> token) = 0;

    // Adds a new SurfaceFrame to the current DisplayFrame. Frames from multiple layers can be
    // composited into one display frame.
    virtual void addSurfaceFrame(std::unique_ptr<SurfaceFrame> surfaceFrame,
                                 SurfaceFrame::PresentState state) = 0;

    // The first function called by SF for the current DisplayFrame. Fetches SF predictions based on
    // the token and sets the actualSfWakeTime for the current DisplayFrame.
    virtual void setSfWakeUp(int64_t token, nsecs_t wakeupTime) = 0;

    // Sets the sfPresentTime and finalizes the current DisplayFrame. Tracks the given present fence
    // until it's signaled, and updates the present timestamps of all presented SurfaceFrames in
    // that vsync.
    virtual void setSfPresent(nsecs_t sfPresentTime,
                              const std::shared_ptr<FenceTime>& presentFence) = 0;

    // Args:
    // -jank : Dumps only the Display Frames that are either janky themselves
    //         or contain janky Surface Frames.
    // -all : Dumps the entire list of DisplayFrames and the SurfaceFrames contained within
    virtual void parseArgs(const Vector<String16>& args, std::string& result) = 0;

    // Sets the max number of display frames that can be stored. Called by SF backdoor.
    virtual void setMaxDisplayFrames(uint32_t size);

    // Restores the max number of display frames to default. Called by SF backdoor.
    virtual void reset() = 0;
};

namespace impl {

using namespace std::chrono_literals;

class TokenManager : public android::frametimeline::TokenManager {
public:
    TokenManager() : mCurrentToken(ISurfaceComposer::INVALID_VSYNC_ID + 1) {}
    ~TokenManager() = default;

    int64_t generateTokenForPredictions(TimelineItem&& predictions) override;
    std::optional<TimelineItem> getPredictionsForToken(int64_t token);

private:
    // Friend class for testing
    friend class android::frametimeline::FrameTimelineTest;

    void flushTokens(nsecs_t flushTime) REQUIRES(mMutex);

    std::unordered_map<int64_t, TimelineItem> mPredictions GUARDED_BY(mMutex);
    std::vector<std::pair<int64_t, nsecs_t>> mTokens GUARDED_BY(mMutex);
    int64_t mCurrentToken GUARDED_BY(mMutex);
    std::mutex mMutex;
    static constexpr nsecs_t kMaxRetentionTime =
            std::chrono::duration_cast<std::chrono::nanoseconds>(120ms).count();
};

class SurfaceFrame : public android::frametimeline::SurfaceFrame {
public:
    SurfaceFrame(int64_t token, pid_t ownerPid, uid_t ownerUid, std::string layerName,
                 std::string debugName, PredictionState predictionState,
                 TimelineItem&& predictions);
    ~SurfaceFrame() = default;

    TimelineItem getPredictions() const override { return mPredictions; };
    TimelineItem getActuals() const override;
    nsecs_t getActualQueueTime() const override;
    PresentState getPresentState() const override;
    PredictionState getPredictionState() const override { return mPredictionState; };
    pid_t getOwnerPid() const override { return mOwnerPid; };
    JankType getJankType() const;
    int64_t getToken() const { return mToken; };
    nsecs_t getBaseTime() const;
    uid_t getOwnerUid() const { return mOwnerUid; };
    const std::string& getName() const { return mLayerName; };

    void setActualStartTime(nsecs_t actualStartTime) override;
    void setActualQueueTime(nsecs_t actualQueueTime) override;
    void setAcquireFenceTime(nsecs_t acquireFenceTime) override;
    void setPresentState(PresentState state) override;
    void setActualPresentTime(nsecs_t presentTime);
    void setJankInfo(JankType jankType, int32_t jankMetadata);

    // All the timestamps are dumped relative to the baseTime
    void dump(std::string& result, const std::string& indent, nsecs_t baseTime);

    // Emits a packet for perfetto tracing. The function body will be executed only if tracing is
    // enabled. The displayFrameToken is needed to link the SurfaceFrame to the corresponding
    // DisplayFrame at the trace processor side.
    void traceSurfaceFrame(int64_t displayFrameToken);

private:
    const int64_t mToken;
    const pid_t mOwnerPid;
    const uid_t mOwnerUid;
    const std::string mLayerName;
    const std::string mDebugName;
    PresentState mPresentState GUARDED_BY(mMutex);
    const PredictionState mPredictionState;
    const TimelineItem mPredictions;
    TimelineItem mActuals GUARDED_BY(mMutex);
    nsecs_t mActualQueueTime GUARDED_BY(mMutex);
    mutable std::mutex mMutex;
    JankType mJankType GUARDED_BY(mMutex); // Enum for the type of jank
    int32_t mJankMetadata GUARDED_BY(mMutex); // Additional details about the jank
};

class FrameTimeline : public android::frametimeline::FrameTimeline {
public:
    class FrameTimelineDataSource : public perfetto::DataSource<FrameTimelineDataSource> {
        void OnSetup(const SetupArgs&) override{};
        void OnStart(const StartArgs&) override{};
        void OnStop(const StopArgs&) override{};
    };

    FrameTimeline(std::shared_ptr<TimeStats> timeStats);
    ~FrameTimeline() = default;

    frametimeline::TokenManager* getTokenManager() override { return &mTokenManager; }
    std::unique_ptr<frametimeline::SurfaceFrame> createSurfaceFrameForToken(
            pid_t ownerPid, uid_t ownerUid, std::string layerName, std::string debugName,
            std::optional<int64_t> token) override;
    void addSurfaceFrame(std::unique_ptr<frametimeline::SurfaceFrame> surfaceFrame,
                         SurfaceFrame::PresentState state) override;
    void setSfWakeUp(int64_t token, nsecs_t wakeupTime) override;
    void setSfPresent(nsecs_t sfPresentTime,
                      const std::shared_ptr<FenceTime>& presentFence) override;
    void parseArgs(const Vector<String16>& args, std::string& result) override;
    void setMaxDisplayFrames(uint32_t size) override;
    void reset() override;

    // Sets up the perfetto tracing backend and data source.
    void onBootFinished() override;
    // Registers the data source with the perfetto backend. Called as part of onBootFinished()
    // and should not be called manually outside of tests.
    void registerDataSource();

    static constexpr char kFrameTimelineDataSource[] = "android.surfaceflinger.frametimeline";

private:
    // Friend class for testing
    friend class android::frametimeline::FrameTimelineTest;

    /*
     * DisplayFrame should be used only internally within FrameTimeline.
     */
    struct DisplayFrame {
        DisplayFrame();

        int64_t token = ISurfaceComposer::INVALID_VSYNC_ID;

        /* Usage of TimelineItem w.r.t SurfaceFlinger
         * startTime    Time when SurfaceFlinger wakes up to handle transactions and buffer updates
         * endTime      Time when SurfaceFlinger sends a composited frame to Display
         * presentTime  Time when the composited frame was presented on screen
         */
        TimelineItem surfaceFlingerPredictions;
        TimelineItem surfaceFlingerActuals;

        // Collection of predictions and actual values sent over by Layers
        std::vector<std::unique_ptr<SurfaceFrame>> surfaceFrames;

        PredictionState predictionState = PredictionState::None;
        JankType jankType = JankType::None; // Enum for the type of jank
        int32_t jankMetadata = 0x0; // Additional details about the jank
    };

    void flushPendingPresentFences() REQUIRES(mMutex);
    void finalizeCurrentDisplayFrame() REQUIRES(mMutex);
    // BaseTime is the smallest timestamp in a DisplayFrame.
    // Used for dumping all timestamps relative to the oldest, making it easy to read.
    nsecs_t findBaseTime(const std::shared_ptr<DisplayFrame>&) REQUIRES(mMutex);
    void dumpDisplayFrame(std::string& result, const std::shared_ptr<DisplayFrame>&,
                          nsecs_t baseTime) REQUIRES(mMutex);
    void dumpAll(std::string& result);
    void dumpJank(std::string& result);

    // Emits a packet for perfetto tracing. The function body will be executed only if tracing is
    // enabled.
    void traceDisplayFrame(const DisplayFrame& displayFrame) REQUIRES(mMutex);

    // Sliding window of display frames. TODO(b/168072834): compare perf with fixed size array
    std::deque<std::shared_ptr<DisplayFrame>> mDisplayFrames GUARDED_BY(mMutex);
    std::vector<std::pair<std::shared_ptr<FenceTime>, std::shared_ptr<DisplayFrame>>>
            mPendingPresentFences GUARDED_BY(mMutex);
    std::shared_ptr<DisplayFrame> mCurrentDisplayFrame GUARDED_BY(mMutex);
    TokenManager mTokenManager;
    std::mutex mMutex;
    uint32_t mMaxDisplayFrames;
    std::shared_ptr<TimeStats> mTimeStats;
    static constexpr uint32_t kDefaultMaxDisplayFrames = 64;
    // The initial container size for the vector<SurfaceFrames> inside display frame. Although
    // this number doesn't represent any bounds on the number of surface frames that can go in a
    // display frame, this is a good starting size for the vector so that we can avoid the
    // internal vector resizing that happens with push_back.
    static constexpr uint32_t kNumSurfaceFramesInitial = 10;
    // The various thresholds for App and SF. If the actual timestamp falls within the threshold
    // compared to prediction, we don't treat it as a jank.
    static constexpr nsecs_t kPresentThreshold =
            std::chrono::duration_cast<std::chrono::nanoseconds>(2ms).count();
    static constexpr nsecs_t kDeadlineThreshold =
            std::chrono::duration_cast<std::chrono::nanoseconds>(2ms).count();
    static constexpr nsecs_t kSFStartThreshold =
            std::chrono::duration_cast<std::chrono::nanoseconds>(1ms).count();
};

} // namespace impl
} // namespace android::frametimeline
