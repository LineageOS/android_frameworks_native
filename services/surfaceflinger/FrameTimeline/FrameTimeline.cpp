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

#undef LOG_TAG
#define LOG_TAG "FrameTimeline"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "FrameTimeline.h"
#include <android-base/stringprintf.h>
#include <utils/Log.h>
#include <utils/Trace.h>
#include <cinttypes>

namespace android::frametimeline::impl {

using base::StringAppendF;

int64_t TokenManager::generateTokenForPredictions(TimelineItem&& predictions) {
    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mMutex);
    const int64_t assignedToken = mCurrentToken++;
    mPredictions[assignedToken] = predictions;
    mTokens.emplace_back(std::make_pair(assignedToken, systemTime()));
    flushTokens(systemTime());
    return assignedToken;
}

std::optional<TimelineItem> TokenManager::getPredictionsForToken(int64_t token) {
    std::lock_guard<std::mutex> lock(mMutex);
    flushTokens(systemTime());
    auto predictionsIterator = mPredictions.find(token);
    if (predictionsIterator != mPredictions.end()) {
        return predictionsIterator->second;
    }
    return {};
}

void TokenManager::flushTokens(nsecs_t flushTime) {
    for (size_t i = 0; i < mTokens.size(); i++) {
        if (flushTime - mTokens[i].second >= kMaxRetentionTime) {
            mPredictions.erase(mTokens[i].first);
            mTokens.erase(mTokens.begin() + static_cast<int>(i));
            --i;
        } else {
            // Tokens are ordered by time. If i'th token is within the retention time, then the
            // i+1'th token will also be within retention time.
            break;
        }
    }
}

SurfaceFrame::SurfaceFrame(const std::string& layerName, PredictionState predictionState,
                           frametimeline::TimelineItem&& predictions)
      : mLayerName(layerName),
        mPresentState(PresentState::Unknown),
        mPredictionState(predictionState),
        mPredictions(predictions),
        mActuals({0, 0, 0}),
        mActualQueueTime(0) {}

void SurfaceFrame::setPresentState(PresentState state) {
    std::lock_guard<std::mutex> lock(mMutex);
    mPresentState = state;
}

PredictionState SurfaceFrame::getPredictionState() {
    std::lock_guard<std::mutex> lock(mMutex);
    return mPredictionState;
}

SurfaceFrame::PresentState SurfaceFrame::getPresentState() {
    std::lock_guard<std::mutex> lock(mMutex);
    return mPresentState;
}

TimelineItem SurfaceFrame::getActuals() {
    std::lock_guard<std::mutex> lock(mMutex);
    return mActuals;
}

nsecs_t SurfaceFrame::getActualQueueTime() {
    std::lock_guard<std::mutex> lock(mMutex);
    return mActualQueueTime;
}

void SurfaceFrame::setActualStartTime(nsecs_t actualStartTime) {
    std::lock_guard<std::mutex> lock(mMutex);
    mActuals.startTime = actualStartTime;
}

void SurfaceFrame::setActualQueueTime(nsecs_t actualQueueTime) {
    std::lock_guard<std::mutex> lock(mMutex);
    mActualQueueTime = actualQueueTime;
}
void SurfaceFrame::setAcquireFenceTime(nsecs_t acquireFenceTime) {
    std::lock_guard<std::mutex> lock(mMutex);
    mActuals.endTime = std::max(acquireFenceTime, mActualQueueTime);
}

void SurfaceFrame::setActualPresentTime(nsecs_t presentTime) {
    std::lock_guard<std::mutex> lock(mMutex);
    mActuals.presentTime = presentTime;
}

void SurfaceFrame::dump(std::string& result) {
    std::lock_guard<std::mutex> lock(mMutex);
    StringAppendF(&result, "Present State : %d\n", static_cast<int>(mPresentState));
    StringAppendF(&result, "Prediction State : %d\n", static_cast<int>(mPredictionState));
    StringAppendF(&result, "Predicted Start Time : %" PRId64 "\n", mPredictions.startTime);
    StringAppendF(&result, "Actual Start Time : %" PRId64 "\n", mActuals.startTime);
    StringAppendF(&result, "Actual Queue Time : %" PRId64 "\n", mActualQueueTime);
    StringAppendF(&result, "Predicted Render Complete Time : %" PRId64 "\n", mPredictions.endTime);
    StringAppendF(&result, "Actual Render Complete Time : %" PRId64 "\n", mActuals.endTime);
    StringAppendF(&result, "Predicted Present Time : %" PRId64 "\n", mPredictions.presentTime);
    StringAppendF(&result, "Actual Present Time : %" PRId64 "\n", mActuals.presentTime);
}

FrameTimeline::FrameTimeline() : mCurrentDisplayFrame(std::make_shared<DisplayFrame>()) {}

FrameTimeline::DisplayFrame::DisplayFrame()
      : surfaceFlingerPredictions(TimelineItem()),
        surfaceFlingerActuals(TimelineItem()),
        predictionState(PredictionState::None) {
    this->surfaceFrames.reserve(kNumSurfaceFramesInitial);
}

std::unique_ptr<android::frametimeline::SurfaceFrame> FrameTimeline::createSurfaceFrameForToken(
        const std::string& layerName, std::optional<int64_t> token) {
    ATRACE_CALL();
    if (!token) {
        return std::make_unique<impl::SurfaceFrame>(layerName, PredictionState::None,
                                                    TimelineItem());
    }
    std::optional<TimelineItem> predictions = mTokenManager.getPredictionsForToken(*token);
    if (predictions) {
        return std::make_unique<impl::SurfaceFrame>(layerName, PredictionState::Valid,
                                                    std::move(*predictions));
    }
    return std::make_unique<impl::SurfaceFrame>(layerName, PredictionState::Expired,
                                                TimelineItem());
}

void FrameTimeline::addSurfaceFrame(
        std::unique_ptr<android::frametimeline::SurfaceFrame> surfaceFrame,
        SurfaceFrame::PresentState state) {
    ATRACE_CALL();
    surfaceFrame->setPresentState(state);
    std::unique_ptr<impl::SurfaceFrame> implSurfaceFrame(
            static_cast<impl::SurfaceFrame*>(surfaceFrame.release()));
    std::lock_guard<std::mutex> lock(mMutex);
    mCurrentDisplayFrame->surfaceFrames.push_back(std::move(implSurfaceFrame));
}

void FrameTimeline::setSfWakeUp(int64_t token, nsecs_t wakeUpTime) {
    ATRACE_CALL();
    const std::optional<TimelineItem> prediction = mTokenManager.getPredictionsForToken(token);
    std::lock_guard<std::mutex> lock(mMutex);
    if (!prediction) {
        mCurrentDisplayFrame->predictionState = PredictionState::Expired;
    } else {
        mCurrentDisplayFrame->surfaceFlingerPredictions = *prediction;
        mCurrentDisplayFrame->predictionState = PredictionState::Valid;
    }
    mCurrentDisplayFrame->surfaceFlingerActuals.startTime = wakeUpTime;
}

void FrameTimeline::setSfPresent(nsecs_t sfPresentTime,
                                 const std::shared_ptr<FenceTime>& presentFence) {
    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mMutex);
    mCurrentDisplayFrame->surfaceFlingerActuals.endTime = sfPresentTime;
    mPendingPresentFences.emplace_back(std::make_pair(presentFence, mCurrentDisplayFrame));
    flushPendingPresentFences();
    finalizeCurrentDisplayFrame();
}

void FrameTimeline::flushPendingPresentFences() {
    for (size_t i = 0; i < mPendingPresentFences.size(); i++) {
        const auto& pendingPresentFence = mPendingPresentFences[i];
        nsecs_t signalTime = Fence::SIGNAL_TIME_INVALID;
        if (pendingPresentFence.first && pendingPresentFence.first->isValid()) {
            signalTime = pendingPresentFence.first->getSignalTime();
            if (signalTime == Fence::SIGNAL_TIME_PENDING) {
                continue;
            }
        }
        if (signalTime != Fence::SIGNAL_TIME_INVALID) {
            auto& displayFrame = pendingPresentFence.second;
            displayFrame->surfaceFlingerActuals.presentTime = signalTime;
            for (auto& surfaceFrame : displayFrame->surfaceFrames) {
                if (surfaceFrame->getPresentState() == SurfaceFrame::PresentState::Presented) {
                    // Only presented SurfaceFrames need to be updated
                    surfaceFrame->setActualPresentTime(signalTime);
                }
            }
        }

        mPendingPresentFences.erase(mPendingPresentFences.begin() + static_cast<int>(i));
        --i;
    }
}

void FrameTimeline::finalizeCurrentDisplayFrame() {
    while (mDisplayFrames.size() >= kMaxDisplayFrames) {
        // We maintain only a fixed number of frames' data. Pop older frames
        mDisplayFrames.pop_front();
    }
    mDisplayFrames.push_back(mCurrentDisplayFrame);
    mCurrentDisplayFrame.reset();
    mCurrentDisplayFrame = std::make_shared<DisplayFrame>();
}

void FrameTimeline::dump(std::string& result) {
    std::lock_guard<std::mutex> lock(mMutex);
    StringAppendF(&result, "Number of display frames : %d\n", (int)mDisplayFrames.size());
    for (const auto& displayFrame : mDisplayFrames) {
        StringAppendF(&result, "---Display Frame---\n");
        StringAppendF(&result, "Prediction State : %d\n",
                      static_cast<int>(displayFrame->predictionState));
        StringAppendF(&result, "Predicted SF wake time : %" PRId64 "\n",
                      displayFrame->surfaceFlingerPredictions.startTime);
        StringAppendF(&result, "Actual SF wake time : %" PRId64 "\n",
                      displayFrame->surfaceFlingerActuals.startTime);
        StringAppendF(&result, "Predicted SF Complete time : %" PRId64 "\n",
                      displayFrame->surfaceFlingerPredictions.endTime);
        StringAppendF(&result, "Actual SF Complete time : %" PRId64 "\n",
                      displayFrame->surfaceFlingerActuals.endTime);
        StringAppendF(&result, "Predicted Present time : %" PRId64 "\n",
                      displayFrame->surfaceFlingerPredictions.presentTime);
        StringAppendF(&result, "Actual Present time : %" PRId64 "\n",
                      displayFrame->surfaceFlingerActuals.presentTime);
        for (size_t i = 0; i < displayFrame->surfaceFrames.size(); i++) {
            StringAppendF(&result, "Surface frame - %" PRId32 "\n", (int)i);
            displayFrame->surfaceFrames[i]->dump(result);
        }
    }
}

} // namespace android::frametimeline::impl
