/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <android-base/thread_annotations.h>
#include <android/gui/ISurfaceComposer.h>
#include <gui/Choreographer.h>
#include <jni.h>
#include <private/android/choreographer.h>
#include <utils/Looper.h>
#include <utils/Timers.h>

#include <cinttypes>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>

#undef LOG_TAG
#define LOG_TAG "AChoreographer"

using namespace android;

static inline Choreographer* AChoreographer_to_Choreographer(AChoreographer* choreographer) {
    return reinterpret_cast<Choreographer*>(choreographer);
}

static inline const Choreographer* AChoreographer_to_Choreographer(
        const AChoreographer* choreographer) {
    return reinterpret_cast<const Choreographer*>(choreographer);
}

static inline const ChoreographerFrameCallbackDataImpl*
AChoreographerFrameCallbackData_to_ChoreographerFrameCallbackDataImpl(
        const AChoreographerFrameCallbackData* data) {
    return reinterpret_cast<const ChoreographerFrameCallbackDataImpl*>(data);
}

// Glue for private C api
namespace android {
void AChoreographer_signalRefreshRateCallbacks(nsecs_t vsyncPeriod) {
    Choreographer::signalRefreshRateCallbacks(vsyncPeriod);
}

void AChoreographer_initJVM(JNIEnv* env) {
    Choreographer::initJVM(env);
}

AChoreographer* AChoreographer_routeGetInstance() {
    return AChoreographer_getInstance();
}
void AChoreographer_routePostFrameCallback(AChoreographer* choreographer,
                                           AChoreographer_frameCallback callback, void* data) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return AChoreographer_postFrameCallback(choreographer, callback, data);
#pragma clang diagnostic pop
}
void AChoreographer_routePostFrameCallbackDelayed(AChoreographer* choreographer,
                                                  AChoreographer_frameCallback callback, void* data,
                                                  long delayMillis) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return AChoreographer_postFrameCallbackDelayed(choreographer, callback, data, delayMillis);
#pragma clang diagnostic pop
}
void AChoreographer_routePostFrameCallback64(AChoreographer* choreographer,
                                             AChoreographer_frameCallback64 callback, void* data) {
    return AChoreographer_postFrameCallback64(choreographer, callback, data);
}
void AChoreographer_routePostFrameCallbackDelayed64(AChoreographer* choreographer,
                                                    AChoreographer_frameCallback64 callback,
                                                    void* data, uint32_t delayMillis) {
    return AChoreographer_postFrameCallbackDelayed64(choreographer, callback, data, delayMillis);
}
void AChoreographer_routePostVsyncCallback(AChoreographer* choreographer,
                                           AChoreographer_vsyncCallback callback, void* data) {
    return AChoreographer_postVsyncCallback(choreographer, callback, data);
}
void AChoreographer_routeRegisterRefreshRateCallback(AChoreographer* choreographer,
                                                     AChoreographer_refreshRateCallback callback,
                                                     void* data) {
    return AChoreographer_registerRefreshRateCallback(choreographer, callback, data);
}
void AChoreographer_routeUnregisterRefreshRateCallback(AChoreographer* choreographer,
                                                       AChoreographer_refreshRateCallback callback,
                                                       void* data) {
    return AChoreographer_unregisterRefreshRateCallback(choreographer, callback, data);
}
int64_t AChoreographerFrameCallbackData_routeGetFrameTimeNanos(
        const AChoreographerFrameCallbackData* data) {
    return AChoreographerFrameCallbackData_getFrameTimeNanos(data);
}
size_t AChoreographerFrameCallbackData_routeGetFrameTimelinesLength(
        const AChoreographerFrameCallbackData* data) {
    return AChoreographerFrameCallbackData_getFrameTimelinesLength(data);
}
size_t AChoreographerFrameCallbackData_routeGetPreferredFrameTimelineIndex(
        const AChoreographerFrameCallbackData* data) {
    return AChoreographerFrameCallbackData_getPreferredFrameTimelineIndex(data);
}
AVsyncId AChoreographerFrameCallbackData_routeGetFrameTimelineVsyncId(
        const AChoreographerFrameCallbackData* data, size_t index) {
    return AChoreographerFrameCallbackData_getFrameTimelineVsyncId(data, index);
}
int64_t AChoreographerFrameCallbackData_routeGetFrameTimelineExpectedPresentationTimeNanos(
        const AChoreographerFrameCallbackData* data, size_t index) {
    return AChoreographerFrameCallbackData_getFrameTimelineExpectedPresentationTimeNanos(data,
                                                                                         index);
}
int64_t AChoreographerFrameCallbackData_routeGetFrameTimelineDeadlineNanos(
        const AChoreographerFrameCallbackData* data, size_t index) {
    return AChoreographerFrameCallbackData_getFrameTimelineDeadlineNanos(data, index);
}

int64_t AChoreographer_getFrameInterval(const AChoreographer* choreographer) {
    return AChoreographer_to_Choreographer(choreographer)->getFrameInterval();
}

int64_t AChoreographer_getStartTimeNanosForVsyncId(AVsyncId vsyncId) {
    return Choreographer::getStartTimeNanosForVsyncId(vsyncId);
}

} // namespace android

/* Glue for the NDK interface */

static inline AChoreographer* Choreographer_to_AChoreographer(Choreographer* choreographer) {
    return reinterpret_cast<AChoreographer*>(choreographer);
}

AChoreographer* AChoreographer_getInstance() {
    return Choreographer_to_AChoreographer(Choreographer::getForThread());
}

void AChoreographer_postFrameCallback(AChoreographer* choreographer,
                                      AChoreographer_frameCallback callback, void* data) {
    AChoreographer_to_Choreographer(choreographer)
            ->postFrameCallbackDelayed(callback, nullptr, nullptr, data, 0, CALLBACK_ANIMATION);
}
void AChoreographer_postFrameCallbackDelayed(AChoreographer* choreographer,
                                             AChoreographer_frameCallback callback, void* data,
                                             long delayMillis) {
    AChoreographer_to_Choreographer(choreographer)
            ->postFrameCallbackDelayed(callback, nullptr, nullptr, data, ms2ns(delayMillis),
                                       CALLBACK_ANIMATION);
}
void AChoreographer_postVsyncCallback(AChoreographer* choreographer,
                                      AChoreographer_vsyncCallback callback, void* data) {
    AChoreographer_to_Choreographer(choreographer)
            ->postFrameCallbackDelayed(nullptr, nullptr, callback, data, 0, CALLBACK_ANIMATION);
}
void AChoreographer_postFrameCallback64(AChoreographer* choreographer,
                                        AChoreographer_frameCallback64 callback, void* data) {
    AChoreographer_to_Choreographer(choreographer)
            ->postFrameCallbackDelayed(nullptr, callback, nullptr, data, 0, CALLBACK_ANIMATION);
}
void AChoreographer_postFrameCallbackDelayed64(AChoreographer* choreographer,
                                               AChoreographer_frameCallback64 callback, void* data,
                                               uint32_t delayMillis) {
    AChoreographer_to_Choreographer(choreographer)
            ->postFrameCallbackDelayed(nullptr, callback, nullptr, data, ms2ns(delayMillis),
                                       CALLBACK_ANIMATION);
}
void AChoreographer_registerRefreshRateCallback(AChoreographer* choreographer,
                                                AChoreographer_refreshRateCallback callback,
                                                void* data) {
    AChoreographer_to_Choreographer(choreographer)->registerRefreshRateCallback(callback, data);
}
void AChoreographer_unregisterRefreshRateCallback(AChoreographer* choreographer,
                                                  AChoreographer_refreshRateCallback callback,
                                                  void* data) {
    AChoreographer_to_Choreographer(choreographer)->unregisterRefreshRateCallback(callback, data);
}

int64_t AChoreographerFrameCallbackData_getFrameTimeNanos(
        const AChoreographerFrameCallbackData* data) {
    const ChoreographerFrameCallbackDataImpl* frameCallbackData =
            AChoreographerFrameCallbackData_to_ChoreographerFrameCallbackDataImpl(data);
    LOG_ALWAYS_FATAL_IF(!frameCallbackData->choreographer->inCallback(),
                        "Data is only valid in callback");
    return frameCallbackData->frameTimeNanos;
}
size_t AChoreographerFrameCallbackData_getFrameTimelinesLength(
        const AChoreographerFrameCallbackData* data) {
    const ChoreographerFrameCallbackDataImpl* frameCallbackData =
            AChoreographerFrameCallbackData_to_ChoreographerFrameCallbackDataImpl(data);
    LOG_ALWAYS_FATAL_IF(!frameCallbackData->choreographer->inCallback(),
                        "Data is only valid in callback");
    return frameCallbackData->vsyncEventData.frameTimelinesLength;
}
size_t AChoreographerFrameCallbackData_getPreferredFrameTimelineIndex(
        const AChoreographerFrameCallbackData* data) {
    const ChoreographerFrameCallbackDataImpl* frameCallbackData =
            AChoreographerFrameCallbackData_to_ChoreographerFrameCallbackDataImpl(data);
    LOG_ALWAYS_FATAL_IF(!frameCallbackData->choreographer->inCallback(),
                        "Data is only valid in callback");
    return frameCallbackData->vsyncEventData.preferredFrameTimelineIndex;
}
AVsyncId AChoreographerFrameCallbackData_getFrameTimelineVsyncId(
        const AChoreographerFrameCallbackData* data, size_t index) {
    const ChoreographerFrameCallbackDataImpl* frameCallbackData =
            AChoreographerFrameCallbackData_to_ChoreographerFrameCallbackDataImpl(data);
    LOG_ALWAYS_FATAL_IF(!frameCallbackData->choreographer->inCallback(),
                        "Data is only valid in callback");
    LOG_ALWAYS_FATAL_IF(index >= VsyncEventData::kFrameTimelinesCapacity, "Index out of bounds");
    return frameCallbackData->vsyncEventData.frameTimelines[index].vsyncId;
}
int64_t AChoreographerFrameCallbackData_getFrameTimelineExpectedPresentationTimeNanos(
        const AChoreographerFrameCallbackData* data, size_t index) {
    const ChoreographerFrameCallbackDataImpl* frameCallbackData =
            AChoreographerFrameCallbackData_to_ChoreographerFrameCallbackDataImpl(data);
    LOG_ALWAYS_FATAL_IF(!frameCallbackData->choreographer->inCallback(),
                        "Data is only valid in callback");
    LOG_ALWAYS_FATAL_IF(index >= VsyncEventData::kFrameTimelinesCapacity, "Index out of bounds");
    return frameCallbackData->vsyncEventData.frameTimelines[index].expectedPresentationTime;
}
int64_t AChoreographerFrameCallbackData_getFrameTimelineDeadlineNanos(
        const AChoreographerFrameCallbackData* data, size_t index) {
    const ChoreographerFrameCallbackDataImpl* frameCallbackData =
            AChoreographerFrameCallbackData_to_ChoreographerFrameCallbackDataImpl(data);
    LOG_ALWAYS_FATAL_IF(!frameCallbackData->choreographer->inCallback(),
                        "Data is only valid in callback");
    LOG_ALWAYS_FATAL_IF(index >= VsyncEventData::kFrameTimelinesCapacity, "Index out of bounds");
    return frameCallbackData->vsyncEventData.frameTimelines[index].deadlineTimestamp;
}

AChoreographer* AChoreographer_create() {
    Choreographer* choreographer = new Choreographer(nullptr);
    status_t result = choreographer->initialize();
    if (result != OK) {
        ALOGW("Failed to initialize");
        return nullptr;
    }
    return Choreographer_to_AChoreographer(choreographer);
}

void AChoreographer_destroy(AChoreographer* choreographer) {
    if (choreographer == nullptr) {
        return;
    }

    delete AChoreographer_to_Choreographer(choreographer);
}

int AChoreographer_getFd(const AChoreographer* choreographer) {
    return AChoreographer_to_Choreographer(choreographer)->getFd();
}

void AChoreographer_handlePendingEvents(AChoreographer* choreographer, void* data) {
    // Pass dummy fd and events args to handleEvent, since the underlying
    // DisplayEventDispatcher doesn't need them outside of validating that a
    // Looper instance didn't break, but these args circumvent those checks.
    Choreographer* impl = AChoreographer_to_Choreographer(choreographer);
    impl->handleEvent(-1, Looper::EVENT_INPUT, data);
}
