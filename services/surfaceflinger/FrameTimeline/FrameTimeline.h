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

#include <deque>
#include <mutex>

#include <ui/FenceTime.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

namespace android::frametimeline {

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
    virtual int64_t generateTokenForPredictions(TimelineItem&& prediction);
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

    virtual TimelineItem getPredictions() = 0;
    virtual TimelineItem getActuals() = 0;
    virtual PresentState getPresentState() = 0;
    virtual PredictionState getPredictionState() = 0;

    virtual void setPresentState(PresentState state) = 0;
    virtual void setActuals(TimelineItem&& actuals) = 0;

    // There is no prediction for Queue time and it is not a part of TimelineItem. Set it
    // separately.
    virtual void setActualQueueTime(nsecs_t actualQueueTime) = 0;
};

/*
 * Maintains a history of SurfaceFrames grouped together by the vsync time in which they were
 * presented
 */
class FrameTimeline {
public:
    virtual ~FrameTimeline() = default;
    virtual TokenManager& getTokenManager() = 0;

    // Create a new surface frame, set the predictions based on a token and return it to the caller.
    // Sets the PredictionState of SurfaceFrame.
    virtual std::unique_ptr<SurfaceFrame> createSurfaceFrameForToken(
            const std::string& layerName, std::optional<int64_t> token) = 0;

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
};

namespace impl {

using namespace std::chrono_literals;

class TokenManager : public android::frametimeline::TokenManager {
public:
    TokenManager() : mCurrentToken(0) {}
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
    SurfaceFrame(const std::string& layerName, PredictionState predictionState,
                 TimelineItem&& predictions);
    ~SurfaceFrame() = default;

    TimelineItem getPredictions() override { return mPredictions; };
    TimelineItem getActuals() override;
    PresentState getPresentState() override;
    PredictionState getPredictionState() override;
    void setActuals(TimelineItem&& actuals) override;
    void setActualQueueTime(nsecs_t actualQueueTime) override {
        mActualQueueTime = actualQueueTime;
    };
    void setPresentState(PresentState state) override;
    void setPresentTime(nsecs_t presentTime);
    void dump(std::string& result);

private:
    const std::string mLayerName;
    PresentState mPresentState GUARDED_BY(mMutex);
    PredictionState mPredictionState GUARDED_BY(mMutex);
    const TimelineItem mPredictions;
    TimelineItem mActuals GUARDED_BY(mMutex);
    nsecs_t mActualQueueTime;
    std::mutex mMutex;
};

class FrameTimeline : public android::frametimeline::FrameTimeline {
public:
    FrameTimeline();
    ~FrameTimeline() = default;

    frametimeline::TokenManager& getTokenManager() override { return mTokenManager; }
    std::unique_ptr<frametimeline::SurfaceFrame> createSurfaceFrameForToken(
            const std::string& layerName, std::optional<int64_t> token) override;
    void addSurfaceFrame(std::unique_ptr<frametimeline::SurfaceFrame> surfaceFrame,
                         SurfaceFrame::PresentState state) override;
    void setSfWakeUp(int64_t token, nsecs_t wakeupTime) override;
    void setSfPresent(nsecs_t sfPresentTime,
                      const std::shared_ptr<FenceTime>& presentFence) override;
    void dump(std::string& result);

private:
    // Friend class for testing
    friend class android::frametimeline::FrameTimelineTest;

    /*
     * DisplayFrame should be used only internally within FrameTimeline.
     */
    struct DisplayFrame {
        DisplayFrame();

        /* Usage of TimelineItem w.r.t SurfaceFlinger
         * startTime    Time when SurfaceFlinger wakes up to handle transactions and buffer updates
         * endTime      Time when SurfaceFlinger sends a composited frame to Display
         * presentTime  Time when the composited frame was presented on screen
         */
        TimelineItem surfaceFlingerPredictions;
        TimelineItem surfaceFlingerActuals;

        // Collection of predictions and actual values sent over by Layers
        std::vector<std::unique_ptr<SurfaceFrame>> surfaceFrames;

        PredictionState predictionState;
    };

    void flushPendingPresentFences() REQUIRES(mMutex);
    void finalizeCurrentDisplayFrame() REQUIRES(mMutex);

    // Sliding window of display frames. TODO(b/168072834): compare perf with fixed size array
    std::deque<std::shared_ptr<DisplayFrame>> mDisplayFrames GUARDED_BY(mMutex);
    std::vector<std::pair<std::shared_ptr<FenceTime>, std::shared_ptr<DisplayFrame>>>
            mPendingPresentFences GUARDED_BY(mMutex);
    std::shared_ptr<DisplayFrame> mCurrentDisplayFrame GUARDED_BY(mMutex);
    TokenManager mTokenManager;
    std::mutex mMutex;
    static constexpr uint32_t kMaxDisplayFrames = 64;
    // The initial container size for the vector<SurfaceFrames> inside display frame. Although this
    // number doesn't represent any bounds on the number of surface frames that can go in a display
    // frame, this is a good starting size for the vector so that we can avoid the internal vector
    // resizing that happens with push_back.
    static constexpr uint32_t kNumSurfaceFramesInitial = 10;
};

} // namespace impl
} // namespace android::frametimeline
