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
#include <chrono>
#include <cinttypes>
#include <numeric>

namespace android::frametimeline::impl {

using base::StringAppendF;
using FrameTimelineEvent = perfetto::protos::pbzero::FrameTimelineEvent;

void dumpTable(std::string& result, TimelineItem predictions, TimelineItem actuals,
               const std::string& indent, PredictionState predictionState, nsecs_t baseTime) {
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "\t\t");
    StringAppendF(&result, "    Start time\t\t|");
    StringAppendF(&result, "    End time\t\t|");
    StringAppendF(&result, "    Present time\n");
    if (predictionState == PredictionState::Valid) {
        // Dump the Predictions only if they are valid
        StringAppendF(&result, "%s", indent.c_str());
        StringAppendF(&result, "Expected\t|");
        std::chrono::nanoseconds startTime(predictions.startTime - baseTime);
        std::chrono::nanoseconds endTime(predictions.endTime - baseTime);
        std::chrono::nanoseconds presentTime(predictions.presentTime - baseTime);
        StringAppendF(&result, "\t%10.2f\t|\t%10.2f\t|\t%10.2f\n",
                      std::chrono::duration<double, std::milli>(startTime).count(),
                      std::chrono::duration<double, std::milli>(endTime).count(),
                      std::chrono::duration<double, std::milli>(presentTime).count());
    }
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Actual  \t|");

    if (actuals.startTime == 0) {
        StringAppendF(&result, "\t\tN/A\t|");
    } else {
        std::chrono::nanoseconds startTime(std::max<nsecs_t>(0, actuals.startTime - baseTime));
        StringAppendF(&result, "\t%10.2f\t|",
                      std::chrono::duration<double, std::milli>(startTime).count());
    }
    if (actuals.endTime == 0) {
        StringAppendF(&result, "\t\tN/A\t|");
    } else {
        std::chrono::nanoseconds endTime(actuals.endTime - baseTime);
        StringAppendF(&result, "\t%10.2f\t|",
                      std::chrono::duration<double, std::milli>(endTime).count());
    }
    if (actuals.presentTime == 0) {
        StringAppendF(&result, "\t\tN/A\n");
    } else {
        std::chrono::nanoseconds presentTime(std::max<nsecs_t>(0, actuals.presentTime - baseTime));
        StringAppendF(&result, "\t%10.2f\n",
                      std::chrono::duration<double, std::milli>(presentTime).count());
    }

    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "----------------------");
    StringAppendF(&result, "----------------------");
    StringAppendF(&result, "----------------------");
    StringAppendF(&result, "----------------------\n");
}

std::string toString(PredictionState predictionState) {
    switch (predictionState) {
        case PredictionState::Valid:
            return "Valid";
        case PredictionState::Expired:
            return "Expired";
        case PredictionState::None:
        default:
            return "None";
    }
}

std::string toString(JankType jankType) {
    switch (jankType) {
        case JankType::None:
            return "None";
        case JankType::Display:
            return "Composer/Display - outside SF and App";
        case JankType::SurfaceFlingerDeadlineMissed:
            return "SurfaceFlinger Deadline Missed";
        case JankType::AppDeadlineMissed:
            return "App Deadline Missed";
        case JankType::PredictionExpired:
            return "Prediction Expired";
        case JankType::SurfaceFlingerEarlyLatch:
            return "SurfaceFlinger Early Latch";
        default:
            return "Unclassified";
    }
}

std::string jankMetadataBitmaskToString(int32_t jankMetadata) {
    std::vector<std::string> jankInfo;

    if (jankMetadata & EarlyStart) {
        jankInfo.emplace_back("Early Start");
    } else if (jankMetadata & LateStart) {
        jankInfo.emplace_back("Late Start");
    }

    if (jankMetadata & EarlyFinish) {
        jankInfo.emplace_back("Early Finish");
    } else if (jankMetadata & LateFinish) {
        jankInfo.emplace_back("Late Finish");
    }

    if (jankMetadata & EarlyPresent) {
        jankInfo.emplace_back("Early Present");
    } else if (jankMetadata & LatePresent) {
        jankInfo.emplace_back("Late Present");
    }
    // TODO(b/169876734): add GPU composition metadata here

    if (jankInfo.empty()) {
        return "None";
    }
    return std::accumulate(jankInfo.begin(), jankInfo.end(), std::string(),
                           [](const std::string& l, const std::string& r) {
                               return l.empty() ? r : l + ", " + r;
                           });
}

FrameTimelineEvent::PresentType presentTypeToProto(int32_t jankMetadata) {
    if (jankMetadata & EarlyPresent) {
        return FrameTimelineEvent::PRESENT_EARLY;
    }
    if (jankMetadata & LatePresent) {
        return FrameTimelineEvent::PRESENT_LATE;
    }
    return FrameTimelineEvent::PRESENT_ON_TIME;
}

FrameTimelineEvent::JankType JankTypeToProto(JankType jankType) {
    switch (jankType) {
        case JankType::None:
            return FrameTimelineEvent::JANK_NONE;
        case JankType::Display:
            return FrameTimelineEvent::JANK_DISPLAY_HAL;
        case JankType::SurfaceFlingerDeadlineMissed:
            return FrameTimelineEvent::JANK_SF_DEADLINE_MISSED;
        case JankType::AppDeadlineMissed:
        case JankType::PredictionExpired:
            return FrameTimelineEvent::JANK_APP_DEADLINE_MISSED;
        default:
            return FrameTimelineEvent::JANK_UNKNOWN;
    }
}

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

SurfaceFrame::SurfaceFrame(int64_t token, pid_t ownerPid, uid_t ownerUid, std::string layerName,
                           std::string debugName, PredictionState predictionState,
                           frametimeline::TimelineItem&& predictions)
      : mToken(token),
        mOwnerPid(ownerPid),
        mOwnerUid(ownerUid),
        mLayerName(std::move(layerName)),
        mDebugName(std::move(debugName)),
        mPresentState(PresentState::Unknown),
        mPredictionState(predictionState),
        mPredictions(predictions),
        mActuals({0, 0, 0}),
        mActualQueueTime(0),
        mJankType(JankType::None),
        mJankMetadata(0) {}

void SurfaceFrame::setPresentState(PresentState state) {
    std::lock_guard<std::mutex> lock(mMutex);
    mPresentState = state;
}

SurfaceFrame::PresentState SurfaceFrame::getPresentState() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mPresentState;
}

TimelineItem SurfaceFrame::getActuals() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mActuals;
}

nsecs_t SurfaceFrame::getActualQueueTime() const {
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

void SurfaceFrame::setJankInfo(JankType jankType, int32_t jankMetadata) {
    std::lock_guard<std::mutex> lock(mMutex);
    mJankType = jankType;
    mJankMetadata = jankMetadata;
}

JankType SurfaceFrame::getJankType() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mJankType;
}

nsecs_t SurfaceFrame::getBaseTime() const {
    std::lock_guard<std::mutex> lock(mMutex);
    nsecs_t baseTime = std::numeric_limits<nsecs_t>::max();
    if (mPredictionState == PredictionState::Valid) {
        baseTime = std::min(baseTime, mPredictions.startTime);
    }
    if (mActuals.startTime != 0) {
        baseTime = std::min(baseTime, mActuals.startTime);
    }
    baseTime = std::min(baseTime, mActuals.endTime);
    return baseTime;
}

std::string presentStateToString(SurfaceFrame::PresentState presentState) {
    using PresentState = SurfaceFrame::PresentState;
    switch (presentState) {
        case PresentState::Presented:
            return "Presented";
        case PresentState::Dropped:
            return "Dropped";
        case PresentState::Unknown:
        default:
            return "Unknown";
    }
}

void SurfaceFrame::dump(std::string& result, const std::string& indent, nsecs_t baseTime) {
    std::lock_guard<std::mutex> lock(mMutex);
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Layer - %s", mDebugName.c_str());
    if (mJankType != JankType::None) {
        // Easily identify a janky Surface Frame in the dump
        StringAppendF(&result, " [*] ");
    }
    StringAppendF(&result, "\n");
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Owner Pid : %d\n", mOwnerPid);
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Present State : %s\n", presentStateToString(mPresentState).c_str());
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Prediction State : %s\n", toString(mPredictionState).c_str());
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Jank Type : %s\n", toString(mJankType).c_str());
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Jank Metadata: %s\n",
                  jankMetadataBitmaskToString(mJankMetadata).c_str());
    dumpTable(result, mPredictions, mActuals, indent, mPredictionState, baseTime);
}

void SurfaceFrame::traceSurfaceFrame(int64_t displayFrameToken) {
    using FrameTimelineDataSource = FrameTimeline::FrameTimelineDataSource;
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (mToken == ISurfaceComposer::INVALID_VSYNC_ID) {
            ALOGD("Cannot trace SurfaceFrame - %s with invalid token", mLayerName.c_str());
            return;
        } else if (displayFrameToken == ISurfaceComposer::INVALID_VSYNC_ID) {
            ALOGD("Cannot trace SurfaceFrame  - %s with invalid displayFrameToken",
                  mLayerName.c_str());
            return;
        }
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_MONOTONIC);
        packet->set_timestamp(static_cast<uint64_t>(systemTime()));

        auto* event = packet->set_frame_timeline_event();
        auto* surfaceFrameEvent = event->set_surface_frame();

        surfaceFrameEvent->set_token(mToken);
        surfaceFrameEvent->set_display_frame_token(displayFrameToken);

        if (mPresentState == PresentState::Dropped) {
            surfaceFrameEvent->set_present_type(FrameTimelineEvent::PRESENT_DROPPED);
        } else if (mPresentState == PresentState::Unknown) {
            surfaceFrameEvent->set_present_type(FrameTimelineEvent::PRESENT_UNSPECIFIED);
        } else {
            surfaceFrameEvent->set_present_type(presentTypeToProto(mJankMetadata));
        }
        surfaceFrameEvent->set_on_time_finish(!(mJankMetadata & LateFinish));
        surfaceFrameEvent->set_gpu_composition(mJankMetadata & GpuComposition);
        surfaceFrameEvent->set_jank_type(JankTypeToProto(mJankType));

        surfaceFrameEvent->set_expected_start_ns(mPredictions.startTime);
        surfaceFrameEvent->set_expected_end_ns(mPredictions.endTime);

        surfaceFrameEvent->set_actual_start_ns(mActuals.startTime);
        surfaceFrameEvent->set_actual_end_ns(mActuals.endTime);

        surfaceFrameEvent->set_layer_name(mDebugName);
        surfaceFrameEvent->set_pid(mOwnerPid);
    });
}

FrameTimeline::FrameTimeline(std::shared_ptr<TimeStats> timeStats)
      : mCurrentDisplayFrame(std::make_shared<DisplayFrame>()),
        mMaxDisplayFrames(kDefaultMaxDisplayFrames),
        mTimeStats(std::move(timeStats)) {}

void FrameTimeline::onBootFinished() {
    perfetto::TracingInitArgs args;
    args.backends = perfetto::kSystemBackend;
    perfetto::Tracing::Initialize(args);
    registerDataSource();
}

void FrameTimeline::registerDataSource() {
    perfetto::DataSourceDescriptor dsd;
    dsd.set_name(kFrameTimelineDataSource);
    FrameTimelineDataSource::Register(dsd);
}

FrameTimeline::DisplayFrame::DisplayFrame()
      : surfaceFlingerPredictions(TimelineItem()), surfaceFlingerActuals(TimelineItem()) {
    this->surfaceFrames.reserve(kNumSurfaceFramesInitial);
}

std::unique_ptr<android::frametimeline::SurfaceFrame> FrameTimeline::createSurfaceFrameForToken(
        pid_t ownerPid, uid_t ownerUid, std::string layerName, std::string debugName,
        std::optional<int64_t> token) {
    ATRACE_CALL();
    if (!token) {
        return std::make_unique<impl::SurfaceFrame>(ISurfaceComposer::INVALID_VSYNC_ID, ownerPid,
                                                    ownerUid, std::move(layerName),
                                                    std::move(debugName), PredictionState::None,
                                                    TimelineItem());
    }
    std::optional<TimelineItem> predictions = mTokenManager.getPredictionsForToken(*token);
    if (predictions) {
        return std::make_unique<impl::SurfaceFrame>(*token, ownerPid, ownerUid,
                                                    std::move(layerName), std::move(debugName),
                                                    PredictionState::Valid,
                                                    std::move(*predictions));
    }
    return std::make_unique<impl::SurfaceFrame>(*token, ownerPid, ownerUid, std::move(layerName),
                                                std::move(debugName), PredictionState::Expired,
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
    mCurrentDisplayFrame->token = token;
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
            int32_t totalJankReasons = JankType::None;
            auto& displayFrame = pendingPresentFence.second;
            displayFrame->surfaceFlingerActuals.presentTime = signalTime;

            // Jank Analysis for DisplayFrame
            const auto& sfActuals = displayFrame->surfaceFlingerActuals;
            const auto& sfPredictions = displayFrame->surfaceFlingerPredictions;
            if (std::abs(sfActuals.presentTime - sfPredictions.presentTime) > kPresentThreshold) {
                displayFrame->jankMetadata |= sfActuals.presentTime > sfPredictions.presentTime
                        ? LatePresent
                        : EarlyPresent;
            }
            if (std::abs(sfActuals.endTime - sfPredictions.endTime) > kDeadlineThreshold) {
                if (sfActuals.endTime > sfPredictions.endTime) {
                    displayFrame->jankMetadata |= LateFinish;
                } else {
                    displayFrame->jankMetadata |= EarlyFinish;
                }

                if ((displayFrame->jankMetadata & EarlyFinish) &&
                    (displayFrame->jankMetadata & EarlyPresent)) {
                    displayFrame->jankType = JankType::SurfaceFlingerEarlyLatch;
                } else if ((displayFrame->jankMetadata & LateFinish) &&
                           (displayFrame->jankMetadata & LatePresent)) {
                    displayFrame->jankType = JankType::SurfaceFlingerDeadlineMissed;
                } else if (displayFrame->jankMetadata & EarlyPresent ||
                           displayFrame->jankMetadata & LatePresent) {
                    // Cases where SF finished early but frame was presented late and vice versa
                    displayFrame->jankType = JankType::Display;
                }
            }

            if (std::abs(sfActuals.startTime - sfPredictions.startTime) > kSFStartThreshold) {
                displayFrame->jankMetadata |=
                        sfActuals.startTime > sfPredictions.startTime ? LateStart : EarlyStart;
            }

            totalJankReasons |= displayFrame->jankType;
            traceDisplayFrame(*displayFrame);

            for (auto& surfaceFrame : displayFrame->surfaceFrames) {
                if (surfaceFrame->getPresentState() == SurfaceFrame::PresentState::Presented) {
                    // Only presented SurfaceFrames need to be updated
                    surfaceFrame->setActualPresentTime(signalTime);

                    // Jank Analysis for SurfaceFrame
                    const auto& predictionState = surfaceFrame->getPredictionState();
                    if (predictionState == PredictionState::Expired) {
                        // Jank analysis cannot be done on apps that don't use predictions
                        surfaceFrame->setJankInfo(JankType::PredictionExpired, 0);
                    } else if (predictionState == PredictionState::Valid) {
                        const auto& actuals = surfaceFrame->getActuals();
                        const auto& predictions = surfaceFrame->getPredictions();
                        int32_t jankMetadata = 0;
                        JankType jankType = JankType::None;
                        if (std::abs(actuals.endTime - predictions.endTime) > kDeadlineThreshold) {
                            jankMetadata |= actuals.endTime > predictions.endTime ? LateFinish
                                                                                  : EarlyFinish;
                        }
                        if (std::abs(actuals.presentTime - predictions.presentTime) >
                            kPresentThreshold) {
                            jankMetadata |= actuals.presentTime > predictions.presentTime
                                    ? LatePresent
                                    : EarlyPresent;
                        }
                        if (jankMetadata & EarlyPresent) {
                            jankType = JankType::SurfaceFlingerEarlyLatch;
                        } else if (jankMetadata & LatePresent) {
                            if (jankMetadata & EarlyFinish) {
                                // TODO(b/169890654): Classify this properly
                                jankType = JankType::Display;
                            } else {
                                jankType = JankType::AppDeadlineMissed;
                            }
                        }

                        totalJankReasons |= jankType;
                        mTimeStats->incrementJankyFrames(surfaceFrame->getOwnerUid(),
                                                         surfaceFrame->getName(),
                                                         jankType | displayFrame->jankType);
                        surfaceFrame->setJankInfo(jankType, jankMetadata);
                    }
                }
                surfaceFrame->traceSurfaceFrame(displayFrame->token);
            }

            mTimeStats->incrementJankyFrames(totalJankReasons);
        }

        mPendingPresentFences.erase(mPendingPresentFences.begin() + static_cast<int>(i));
        --i;
    }
}

void FrameTimeline::finalizeCurrentDisplayFrame() {
    while (mDisplayFrames.size() >= mMaxDisplayFrames) {
        // We maintain only a fixed number of frames' data. Pop older frames
        mDisplayFrames.pop_front();
    }
    mDisplayFrames.push_back(mCurrentDisplayFrame);
    mCurrentDisplayFrame.reset();
    mCurrentDisplayFrame = std::make_shared<DisplayFrame>();
}

nsecs_t FrameTimeline::findBaseTime(const std::shared_ptr<DisplayFrame>& displayFrame) {
    nsecs_t baseTime = std::numeric_limits<nsecs_t>::max();
    if (displayFrame->predictionState == PredictionState::Valid) {
        baseTime = std::min(baseTime, displayFrame->surfaceFlingerPredictions.startTime);
    }
    baseTime = std::min(baseTime, displayFrame->surfaceFlingerActuals.startTime);
    for (const auto& surfaceFrame : displayFrame->surfaceFrames) {
        nsecs_t surfaceFrameBaseTime = surfaceFrame->getBaseTime();
        if (surfaceFrameBaseTime != 0) {
            baseTime = std::min(baseTime, surfaceFrameBaseTime);
        }
    }
    return baseTime;
}

void FrameTimeline::dumpDisplayFrame(std::string& result,
                                     const std::shared_ptr<DisplayFrame>& displayFrame,
                                     nsecs_t baseTime) {
    if (displayFrame->jankType != JankType::None) {
        // Easily identify a janky Display Frame in the dump
        StringAppendF(&result, " [*] ");
    }
    StringAppendF(&result, "\n");
    StringAppendF(&result, "Prediction State : %s\n",
                  toString(displayFrame->predictionState).c_str());
    StringAppendF(&result, "Jank Type : %s\n", toString(displayFrame->jankType).c_str());
    StringAppendF(&result, "Jank Metadata: %s\n",
                  jankMetadataBitmaskToString(displayFrame->jankMetadata).c_str());
    dumpTable(result, displayFrame->surfaceFlingerPredictions, displayFrame->surfaceFlingerActuals,
              "", displayFrame->predictionState, baseTime);
    StringAppendF(&result, "\n");
    std::string indent = "    "; // 4 spaces
    for (const auto& surfaceFrame : displayFrame->surfaceFrames) {
        surfaceFrame->dump(result, indent, baseTime);
    }
    StringAppendF(&result, "\n");
}
void FrameTimeline::dumpAll(std::string& result) {
    std::lock_guard<std::mutex> lock(mMutex);
    StringAppendF(&result, "Number of display frames : %d\n", (int)mDisplayFrames.size());
    nsecs_t baseTime = (mDisplayFrames.empty()) ? 0 : findBaseTime(mDisplayFrames[0]);
    for (size_t i = 0; i < mDisplayFrames.size(); i++) {
        StringAppendF(&result, "Display Frame %d", static_cast<int>(i));
        dumpDisplayFrame(result, mDisplayFrames[i], baseTime);
    }
}

void FrameTimeline::dumpJank(std::string& result) {
    std::lock_guard<std::mutex> lock(mMutex);
    nsecs_t baseTime = (mDisplayFrames.empty()) ? 0 : findBaseTime(mDisplayFrames[0]);
    for (size_t i = 0; i < mDisplayFrames.size(); i++) {
        const auto& displayFrame = mDisplayFrames[i];
        if (displayFrame->jankType == JankType::None) {
            // Check if any Surface Frame has been janky
            bool isJanky = false;
            for (const auto& surfaceFrame : displayFrame->surfaceFrames) {
                if (surfaceFrame->getJankType() != JankType::None) {
                    isJanky = true;
                    break;
                }
            }
            if (!isJanky) {
                continue;
            }
        }
        StringAppendF(&result, "Display Frame %d", static_cast<int>(i));
        dumpDisplayFrame(result, displayFrame, baseTime);
    }
}
void FrameTimeline::parseArgs(const Vector<String16>& args, std::string& result) {
    ATRACE_CALL();
    std::unordered_map<std::string, bool> argsMap;
    for (size_t i = 0; i < args.size(); i++) {
        argsMap[std::string(String8(args[i]).c_str())] = true;
    }
    if (argsMap.count("-jank")) {
        dumpJank(result);
    }
    if (argsMap.count("-all")) {
        dumpAll(result);
    }
}

void FrameTimeline::setMaxDisplayFrames(uint32_t size) {
    std::lock_guard<std::mutex> lock(mMutex);

    // The size can either increase or decrease, clear everything, to be consistent
    mDisplayFrames.clear();
    mPendingPresentFences.clear();
    mMaxDisplayFrames = size;
}

void FrameTimeline::reset() {
    setMaxDisplayFrames(kDefaultMaxDisplayFrames);
}

void FrameTimeline::traceDisplayFrame(const DisplayFrame& displayFrame) {
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        if (displayFrame.token == ISurfaceComposer::INVALID_VSYNC_ID) {
            ALOGD("Cannot trace DisplayFrame with invalid token");
            return;
        }
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_MONOTONIC);
        packet->set_timestamp(static_cast<uint64_t>(systemTime()));

        auto* event = packet->set_frame_timeline_event();
        auto* displayFrameEvent = event->set_display_frame();

        displayFrameEvent->set_token(displayFrame.token);
        displayFrameEvent->set_present_type(presentTypeToProto(displayFrame.jankMetadata));
        displayFrameEvent->set_on_time_finish(!(displayFrame.jankMetadata & LateFinish));
        displayFrameEvent->set_gpu_composition(displayFrame.jankMetadata & GpuComposition);
        displayFrameEvent->set_jank_type(JankTypeToProto(displayFrame.jankType));

        displayFrameEvent->set_expected_start_ns(displayFrame.surfaceFlingerPredictions.startTime);
        displayFrameEvent->set_expected_end_ns(displayFrame.surfaceFlingerPredictions.endTime);

        displayFrameEvent->set_actual_start_ns(displayFrame.surfaceFlingerActuals.startTime);
        displayFrameEvent->set_actual_end_ns(displayFrame.surfaceFlingerActuals.endTime);
    });
}

} // namespace android::frametimeline::impl
