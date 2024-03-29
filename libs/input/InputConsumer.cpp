/**
 * Copyright 2024 The Android Open Source Project
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

#include <cstdint>
#define LOG_TAG "InputTransport"
#define ATRACE_TAG ATRACE_TAG_INPUT

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <binder/Parcel.h>
#include <cutils/properties.h>
#include <ftl/enum.h>
#include <log/log.h>
#include <utils/Trace.h>

#include <com_android_input_flags.h>
#include <input/InputConsumer.h>
#include <input/PrintTools.h>
#include <input/TraceTools.h>

namespace input_flags = com::android::input::flags;

namespace android {

namespace {

/**
 * Log debug messages relating to the consumer end of the transport channel.
 * Enable this via "adb shell setprop log.tag.InputTransportConsumer DEBUG" (requires restart)
 */

const bool DEBUG_TRANSPORT_CONSUMER =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Consumer", ANDROID_LOG_INFO);

const bool IS_DEBUGGABLE_BUILD =
#if defined(__ANDROID__)
        android::base::GetBoolProperty("ro.debuggable", false);
#else
        true;
#endif

/**
 * Log debug messages about touch event resampling.
 *
 * Enable this via "adb shell setprop log.tag.InputTransportResampling DEBUG".
 * This requires a restart on non-debuggable (e.g. user) builds, but should take effect immediately
 * on debuggable builds (e.g. userdebug).
 */
bool debugResampling() {
    if (!IS_DEBUGGABLE_BUILD) {
        static const bool DEBUG_TRANSPORT_RESAMPLING =
                __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Resampling",
                                          ANDROID_LOG_INFO);
        return DEBUG_TRANSPORT_RESAMPLING;
    }
    return __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Resampling", ANDROID_LOG_INFO);
}

void initializeKeyEvent(KeyEvent& event, const InputMessage& msg) {
    event.initialize(msg.body.key.eventId, msg.body.key.deviceId, msg.body.key.source,
                     msg.body.key.displayId, msg.body.key.hmac, msg.body.key.action,
                     msg.body.key.flags, msg.body.key.keyCode, msg.body.key.scanCode,
                     msg.body.key.metaState, msg.body.key.repeatCount, msg.body.key.downTime,
                     msg.body.key.eventTime);
}

void initializeFocusEvent(FocusEvent& event, const InputMessage& msg) {
    event.initialize(msg.body.focus.eventId, msg.body.focus.hasFocus);
}

void initializeCaptureEvent(CaptureEvent& event, const InputMessage& msg) {
    event.initialize(msg.body.capture.eventId, msg.body.capture.pointerCaptureEnabled);
}

void initializeDragEvent(DragEvent& event, const InputMessage& msg) {
    event.initialize(msg.body.drag.eventId, msg.body.drag.x, msg.body.drag.y,
                     msg.body.drag.isExiting);
}

void initializeMotionEvent(MotionEvent& event, const InputMessage& msg) {
    uint32_t pointerCount = msg.body.motion.pointerCount;
    PointerProperties pointerProperties[pointerCount];
    PointerCoords pointerCoords[pointerCount];
    for (uint32_t i = 0; i < pointerCount; i++) {
        pointerProperties[i] = msg.body.motion.pointers[i].properties;
        pointerCoords[i] = msg.body.motion.pointers[i].coords;
    }

    ui::Transform transform;
    transform.set({msg.body.motion.dsdx, msg.body.motion.dtdx, msg.body.motion.tx,
                   msg.body.motion.dtdy, msg.body.motion.dsdy, msg.body.motion.ty, 0, 0, 1});
    ui::Transform displayTransform;
    displayTransform.set({msg.body.motion.dsdxRaw, msg.body.motion.dtdxRaw, msg.body.motion.txRaw,
                          msg.body.motion.dtdyRaw, msg.body.motion.dsdyRaw, msg.body.motion.tyRaw,
                          0, 0, 1});
    event.initialize(msg.body.motion.eventId, msg.body.motion.deviceId, msg.body.motion.source,
                     msg.body.motion.displayId, msg.body.motion.hmac, msg.body.motion.action,
                     msg.body.motion.actionButton, msg.body.motion.flags, msg.body.motion.edgeFlags,
                     msg.body.motion.metaState, msg.body.motion.buttonState,
                     msg.body.motion.classification, transform, msg.body.motion.xPrecision,
                     msg.body.motion.yPrecision, msg.body.motion.xCursorPosition,
                     msg.body.motion.yCursorPosition, displayTransform, msg.body.motion.downTime,
                     msg.body.motion.eventTime, pointerCount, pointerProperties, pointerCoords);
}

void addSample(MotionEvent& event, const InputMessage& msg) {
    uint32_t pointerCount = msg.body.motion.pointerCount;
    PointerCoords pointerCoords[pointerCount];
    for (uint32_t i = 0; i < pointerCount; i++) {
        pointerCoords[i] = msg.body.motion.pointers[i].coords;
    }

    event.setMetaState(event.getMetaState() | msg.body.motion.metaState);
    event.addSample(msg.body.motion.eventTime, pointerCoords);
}

void initializeTouchModeEvent(TouchModeEvent& event, const InputMessage& msg) {
    event.initialize(msg.body.touchMode.eventId, msg.body.touchMode.isInTouchMode);
}

// Nanoseconds per milliseconds.
constexpr nsecs_t NANOS_PER_MS = 1000000;

// Latency added during resampling.  A few milliseconds doesn't hurt much but
// reduces the impact of mispredicted touch positions.
const std::chrono::duration RESAMPLE_LATENCY = 5ms;

// Minimum time difference between consecutive samples before attempting to resample.
const nsecs_t RESAMPLE_MIN_DELTA = 2 * NANOS_PER_MS;

// Maximum time difference between consecutive samples before attempting to resample
// by extrapolation.
const nsecs_t RESAMPLE_MAX_DELTA = 20 * NANOS_PER_MS;

// Maximum time to predict forward from the last known state, to avoid predicting too
// far into the future.  This time is further bounded by 50% of the last time delta.
const nsecs_t RESAMPLE_MAX_PREDICTION = 8 * NANOS_PER_MS;

/**
 * System property for enabling / disabling touch resampling.
 * Resampling extrapolates / interpolates the reported touch event coordinates to better
 * align them to the VSYNC signal, thus resulting in smoother scrolling performance.
 * Resampling is not needed (and should be disabled) on hardware that already
 * has touch events triggered by VSYNC.
 * Set to "1" to enable resampling (default).
 * Set to "0" to disable resampling.
 * Resampling is enabled by default.
 */
const char* PROPERTY_RESAMPLING_ENABLED = "ro.input.resampling";

inline float lerp(float a, float b, float alpha) {
    return a + alpha * (b - a);
}

inline bool isPointerEvent(int32_t source) {
    return (source & AINPUT_SOURCE_CLASS_POINTER) == AINPUT_SOURCE_CLASS_POINTER;
}

bool shouldResampleTool(ToolType toolType) {
    return toolType == ToolType::FINGER || toolType == ToolType::UNKNOWN;
}

} // namespace

using android::base::Result;
using android::base::StringPrintf;

// --- InputConsumer ---

InputConsumer::InputConsumer(const std::shared_ptr<InputChannel>& channel)
      : InputConsumer(channel, isTouchResamplingEnabled()) {}

InputConsumer::InputConsumer(const std::shared_ptr<InputChannel>& channel,
                             bool enableTouchResampling)
      : mResampleTouch(enableTouchResampling),
        mChannel(channel),
        mProcessingTraceTag(StringPrintf("InputConsumer processing on %s (%p)",
                                         mChannel->getName().c_str(), this)),
        mLifetimeTraceTag(StringPrintf("InputConsumer lifetime on %s (%p)",
                                       mChannel->getName().c_str(), this)),
        mLifetimeTraceCookie(
                static_cast<int32_t>(reinterpret_cast<std::uintptr_t>(this) & 0xFFFFFFFF)),
        mMsgDeferred(false) {
    ATRACE_ASYNC_BEGIN(mLifetimeTraceTag.c_str(), /*cookie=*/mLifetimeTraceCookie);
}

InputConsumer::~InputConsumer() {
    ATRACE_ASYNC_END(mLifetimeTraceTag.c_str(), /*cookie=*/mLifetimeTraceCookie);
}

bool InputConsumer::isTouchResamplingEnabled() {
    return property_get_bool(PROPERTY_RESAMPLING_ENABLED, true);
}

status_t InputConsumer::consume(InputEventFactoryInterface* factory, bool consumeBatches,
                                nsecs_t frameTime, uint32_t* outSeq, InputEvent** outEvent) {
    ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
             "channel '%s' consumer ~ consume: consumeBatches=%s, frameTime=%" PRId64,
             mChannel->getName().c_str(), toString(consumeBatches), frameTime);

    *outSeq = 0;
    *outEvent = nullptr;

    // Fetch the next input message.
    // Loop until an event can be returned or no additional events are received.
    while (!*outEvent) {
        if (mMsgDeferred) {
            // mMsg contains a valid input message from the previous call to consume
            // that has not yet been processed.
            mMsgDeferred = false;
        } else {
            // Receive a fresh message.
            status_t result = mChannel->receiveMessage(&mMsg);
            if (result == OK) {
                const auto [_, inserted] =
                        mConsumeTimes.emplace(mMsg.header.seq, systemTime(SYSTEM_TIME_MONOTONIC));
                LOG_ALWAYS_FATAL_IF(!inserted, "Already have a consume time for seq=%" PRIu32,
                                    mMsg.header.seq);

                // Trace the event processing timeline - event was just read from the socket
                ATRACE_ASYNC_BEGIN(mProcessingTraceTag.c_str(), /*cookie=*/mMsg.header.seq);
            }
            if (result) {
                // Consume the next batched event unless batches are being held for later.
                if (consumeBatches || result != WOULD_BLOCK) {
                    result = consumeBatch(factory, frameTime, outSeq, outEvent);
                    if (*outEvent) {
                        ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
                                 "channel '%s' consumer ~ consumed batch event, seq=%u",
                                 mChannel->getName().c_str(), *outSeq);
                        break;
                    }
                }
                return result;
            }
        }

        switch (mMsg.header.type) {
            case InputMessage::Type::KEY: {
                KeyEvent* keyEvent = factory->createKeyEvent();
                if (!keyEvent) return NO_MEMORY;

                initializeKeyEvent(*keyEvent, mMsg);
                *outSeq = mMsg.header.seq;
                *outEvent = keyEvent;
                ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
                         "channel '%s' consumer ~ consumed key event, seq=%u",
                         mChannel->getName().c_str(), *outSeq);
                break;
            }

            case InputMessage::Type::MOTION: {
                ssize_t batchIndex = findBatch(mMsg.body.motion.deviceId, mMsg.body.motion.source);
                if (batchIndex >= 0) {
                    Batch& batch = mBatches[batchIndex];
                    if (canAddSample(batch, &mMsg)) {
                        batch.samples.push_back(mMsg);
                        ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
                                 "channel '%s' consumer ~ appended to batch event",
                                 mChannel->getName().c_str());
                        break;
                    } else if (isPointerEvent(mMsg.body.motion.source) &&
                               mMsg.body.motion.action == AMOTION_EVENT_ACTION_CANCEL) {
                        // No need to process events that we are going to cancel anyways
                        const size_t count = batch.samples.size();
                        for (size_t i = 0; i < count; i++) {
                            const InputMessage& msg = batch.samples[i];
                            sendFinishedSignal(msg.header.seq, false);
                        }
                        batch.samples.erase(batch.samples.begin(), batch.samples.begin() + count);
                        mBatches.erase(mBatches.begin() + batchIndex);
                    } else {
                        // We cannot append to the batch in progress, so we need to consume
                        // the previous batch right now and defer the new message until later.
                        mMsgDeferred = true;
                        status_t result = consumeSamples(factory, batch, batch.samples.size(),
                                                         outSeq, outEvent);
                        mBatches.erase(mBatches.begin() + batchIndex);
                        if (result) {
                            return result;
                        }
                        ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
                                 "channel '%s' consumer ~ consumed batch event and "
                                 "deferred current event, seq=%u",
                                 mChannel->getName().c_str(), *outSeq);
                        break;
                    }
                }

                // Start a new batch if needed.
                if (mMsg.body.motion.action == AMOTION_EVENT_ACTION_MOVE ||
                    mMsg.body.motion.action == AMOTION_EVENT_ACTION_HOVER_MOVE) {
                    Batch batch;
                    batch.samples.push_back(mMsg);
                    mBatches.push_back(batch);
                    ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
                             "channel '%s' consumer ~ started batch event",
                             mChannel->getName().c_str());
                    break;
                }

                MotionEvent* motionEvent = factory->createMotionEvent();
                if (!motionEvent) return NO_MEMORY;

                updateTouchState(mMsg);
                initializeMotionEvent(*motionEvent, mMsg);
                *outSeq = mMsg.header.seq;
                *outEvent = motionEvent;

                ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
                         "channel '%s' consumer ~ consumed motion event, seq=%u",
                         mChannel->getName().c_str(), *outSeq);
                break;
            }

            case InputMessage::Type::FINISHED:
            case InputMessage::Type::TIMELINE: {
                LOG(FATAL) << "Consumed a " << ftl::enum_string(mMsg.header.type)
                           << " message, which should never be seen by "
                              "InputConsumer on "
                           << mChannel->getName();
                break;
            }

            case InputMessage::Type::FOCUS: {
                FocusEvent* focusEvent = factory->createFocusEvent();
                if (!focusEvent) return NO_MEMORY;

                initializeFocusEvent(*focusEvent, mMsg);
                *outSeq = mMsg.header.seq;
                *outEvent = focusEvent;
                break;
            }

            case InputMessage::Type::CAPTURE: {
                CaptureEvent* captureEvent = factory->createCaptureEvent();
                if (!captureEvent) return NO_MEMORY;

                initializeCaptureEvent(*captureEvent, mMsg);
                *outSeq = mMsg.header.seq;
                *outEvent = captureEvent;
                break;
            }

            case InputMessage::Type::DRAG: {
                DragEvent* dragEvent = factory->createDragEvent();
                if (!dragEvent) return NO_MEMORY;

                initializeDragEvent(*dragEvent, mMsg);
                *outSeq = mMsg.header.seq;
                *outEvent = dragEvent;
                break;
            }

            case InputMessage::Type::TOUCH_MODE: {
                TouchModeEvent* touchModeEvent = factory->createTouchModeEvent();
                if (!touchModeEvent) return NO_MEMORY;

                initializeTouchModeEvent(*touchModeEvent, mMsg);
                *outSeq = mMsg.header.seq;
                *outEvent = touchModeEvent;
                break;
            }
        }
    }
    return OK;
}

status_t InputConsumer::consumeBatch(InputEventFactoryInterface* factory, nsecs_t frameTime,
                                     uint32_t* outSeq, InputEvent** outEvent) {
    status_t result;
    for (size_t i = mBatches.size(); i > 0;) {
        i--;
        Batch& batch = mBatches[i];
        if (frameTime < 0) {
            result = consumeSamples(factory, batch, batch.samples.size(), outSeq, outEvent);
            mBatches.erase(mBatches.begin() + i);
            return result;
        }

        nsecs_t sampleTime = frameTime;
        if (mResampleTouch) {
            sampleTime -= std::chrono::nanoseconds(RESAMPLE_LATENCY).count();
        }
        ssize_t split = findSampleNoLaterThan(batch, sampleTime);
        if (split < 0) {
            continue;
        }

        result = consumeSamples(factory, batch, split + 1, outSeq, outEvent);
        const InputMessage* next;
        if (batch.samples.empty()) {
            mBatches.erase(mBatches.begin() + i);
            next = nullptr;
        } else {
            next = &batch.samples[0];
        }
        if (!result && mResampleTouch) {
            resampleTouchState(sampleTime, static_cast<MotionEvent*>(*outEvent), next);
        }
        return result;
    }

    return WOULD_BLOCK;
}

status_t InputConsumer::consumeSamples(InputEventFactoryInterface* factory, Batch& batch,
                                       size_t count, uint32_t* outSeq, InputEvent** outEvent) {
    MotionEvent* motionEvent = factory->createMotionEvent();
    if (!motionEvent) return NO_MEMORY;

    uint32_t chain = 0;
    for (size_t i = 0; i < count; i++) {
        InputMessage& msg = batch.samples[i];
        updateTouchState(msg);
        if (i) {
            SeqChain seqChain;
            seqChain.seq = msg.header.seq;
            seqChain.chain = chain;
            mSeqChains.push_back(seqChain);
            addSample(*motionEvent, msg);
        } else {
            initializeMotionEvent(*motionEvent, msg);
        }
        chain = msg.header.seq;
    }
    batch.samples.erase(batch.samples.begin(), batch.samples.begin() + count);

    *outSeq = chain;
    *outEvent = motionEvent;
    return OK;
}

void InputConsumer::updateTouchState(InputMessage& msg) {
    if (!mResampleTouch || !isPointerEvent(msg.body.motion.source)) {
        return;
    }

    int32_t deviceId = msg.body.motion.deviceId;
    int32_t source = msg.body.motion.source;

    // Update the touch state history to incorporate the new input message.
    // If the message is in the past relative to the most recently produced resampled
    // touch, then use the resampled time and coordinates instead.
    switch (msg.body.motion.action & AMOTION_EVENT_ACTION_MASK) {
        case AMOTION_EVENT_ACTION_DOWN: {
            ssize_t index = findTouchState(deviceId, source);
            if (index < 0) {
                mTouchStates.push_back({});
                index = mTouchStates.size() - 1;
            }
            TouchState& touchState = mTouchStates[index];
            touchState.initialize(deviceId, source);
            touchState.addHistory(msg);
            break;
        }

        case AMOTION_EVENT_ACTION_MOVE: {
            ssize_t index = findTouchState(deviceId, source);
            if (index >= 0) {
                TouchState& touchState = mTouchStates[index];
                touchState.addHistory(msg);
                rewriteMessage(touchState, msg);
            }
            break;
        }

        case AMOTION_EVENT_ACTION_POINTER_DOWN: {
            ssize_t index = findTouchState(deviceId, source);
            if (index >= 0) {
                TouchState& touchState = mTouchStates[index];
                touchState.lastResample.idBits.clearBit(msg.body.motion.getActionId());
                rewriteMessage(touchState, msg);
            }
            break;
        }

        case AMOTION_EVENT_ACTION_POINTER_UP: {
            ssize_t index = findTouchState(deviceId, source);
            if (index >= 0) {
                TouchState& touchState = mTouchStates[index];
                rewriteMessage(touchState, msg);
                touchState.lastResample.idBits.clearBit(msg.body.motion.getActionId());
            }
            break;
        }

        case AMOTION_EVENT_ACTION_SCROLL: {
            ssize_t index = findTouchState(deviceId, source);
            if (index >= 0) {
                TouchState& touchState = mTouchStates[index];
                rewriteMessage(touchState, msg);
            }
            break;
        }

        case AMOTION_EVENT_ACTION_UP:
        case AMOTION_EVENT_ACTION_CANCEL: {
            ssize_t index = findTouchState(deviceId, source);
            if (index >= 0) {
                TouchState& touchState = mTouchStates[index];
                rewriteMessage(touchState, msg);
                mTouchStates.erase(mTouchStates.begin() + index);
            }
            break;
        }
    }
}

/**
 * Replace the coordinates in msg with the coordinates in lastResample, if necessary.
 *
 * If lastResample is no longer valid for a specific pointer (i.e. the lastResample time
 * is in the past relative to msg and the past two events do not contain identical coordinates),
 * then invalidate the lastResample data for that pointer.
 * If the two past events have identical coordinates, then lastResample data for that pointer will
 * remain valid, and will be used to replace these coordinates. Thus, if a certain coordinate x0 is
 * resampled to the new value x1, then x1 will always be used to replace x0 until some new value
 * not equal to x0 is received.
 */
void InputConsumer::rewriteMessage(TouchState& state, InputMessage& msg) {
    nsecs_t eventTime = msg.body.motion.eventTime;
    for (uint32_t i = 0; i < msg.body.motion.pointerCount; i++) {
        uint32_t id = msg.body.motion.pointers[i].properties.id;
        if (state.lastResample.idBits.hasBit(id)) {
            if (eventTime < state.lastResample.eventTime ||
                state.recentCoordinatesAreIdentical(id)) {
                PointerCoords& msgCoords = msg.body.motion.pointers[i].coords;
                const PointerCoords& resampleCoords = state.lastResample.getPointerById(id);
                ALOGD_IF(debugResampling(), "[%d] - rewrite (%0.3f, %0.3f), old (%0.3f, %0.3f)", id,
                         resampleCoords.getX(), resampleCoords.getY(), msgCoords.getX(),
                         msgCoords.getY());
                msgCoords.setAxisValue(AMOTION_EVENT_AXIS_X, resampleCoords.getX());
                msgCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, resampleCoords.getY());
                msgCoords.isResampled = true;
            } else {
                state.lastResample.idBits.clearBit(id);
            }
        }
    }
}

void InputConsumer::resampleTouchState(nsecs_t sampleTime, MotionEvent* event,
                                       const InputMessage* next) {
    if (!mResampleTouch || !(isPointerEvent(event->getSource())) ||
        event->getAction() != AMOTION_EVENT_ACTION_MOVE) {
        return;
    }

    ssize_t index = findTouchState(event->getDeviceId(), event->getSource());
    if (index < 0) {
        ALOGD_IF(debugResampling(), "Not resampled, no touch state for device.");
        return;
    }

    TouchState& touchState = mTouchStates[index];
    if (touchState.historySize < 1) {
        ALOGD_IF(debugResampling(), "Not resampled, no history for device.");
        return;
    }

    // Ensure that the current sample has all of the pointers that need to be reported.
    const History* current = touchState.getHistory(0);
    size_t pointerCount = event->getPointerCount();
    for (size_t i = 0; i < pointerCount; i++) {
        uint32_t id = event->getPointerId(i);
        if (!current->idBits.hasBit(id)) {
            ALOGD_IF(debugResampling(), "Not resampled, missing id %d", id);
            return;
        }
    }

    // Find the data to use for resampling.
    const History* other;
    History future;
    float alpha;
    if (next) {
        // Interpolate between current sample and future sample.
        // So current->eventTime <= sampleTime <= future.eventTime.
        future.initializeFrom(*next);
        other = &future;
        nsecs_t delta = future.eventTime - current->eventTime;
        if (delta < RESAMPLE_MIN_DELTA) {
            ALOGD_IF(debugResampling(), "Not resampled, delta time is too small: %" PRId64 " ns.",
                     delta);
            return;
        }
        alpha = float(sampleTime - current->eventTime) / delta;
    } else if (touchState.historySize >= 2) {
        // Extrapolate future sample using current sample and past sample.
        // So other->eventTime <= current->eventTime <= sampleTime.
        other = touchState.getHistory(1);
        nsecs_t delta = current->eventTime - other->eventTime;
        if (delta < RESAMPLE_MIN_DELTA) {
            ALOGD_IF(debugResampling(), "Not resampled, delta time is too small: %" PRId64 " ns.",
                     delta);
            return;
        } else if (delta > RESAMPLE_MAX_DELTA) {
            ALOGD_IF(debugResampling(), "Not resampled, delta time is too large: %" PRId64 " ns.",
                     delta);
            return;
        }
        nsecs_t maxPredict = current->eventTime + std::min(delta / 2, RESAMPLE_MAX_PREDICTION);
        if (sampleTime > maxPredict) {
            ALOGD_IF(debugResampling(),
                     "Sample time is too far in the future, adjusting prediction "
                     "from %" PRId64 " to %" PRId64 " ns.",
                     sampleTime - current->eventTime, maxPredict - current->eventTime);
            sampleTime = maxPredict;
        }
        alpha = float(current->eventTime - sampleTime) / delta;
    } else {
        ALOGD_IF(debugResampling(), "Not resampled, insufficient data.");
        return;
    }

    if (current->eventTime == sampleTime) {
        // Prevents having 2 events with identical times and coordinates.
        return;
    }

    // Resample touch coordinates.
    History oldLastResample;
    oldLastResample.initializeFrom(touchState.lastResample);
    touchState.lastResample.eventTime = sampleTime;
    touchState.lastResample.idBits.clear();
    for (size_t i = 0; i < pointerCount; i++) {
        uint32_t id = event->getPointerId(i);
        touchState.lastResample.idToIndex[id] = i;
        touchState.lastResample.idBits.markBit(id);
        if (oldLastResample.hasPointerId(id) && touchState.recentCoordinatesAreIdentical(id)) {
            // We maintain the previously resampled value for this pointer (stored in
            // oldLastResample) when the coordinates for this pointer haven't changed since then.
            // This way we don't introduce artificial jitter when pointers haven't actually moved.
            // The isResampled flag isn't cleared as the values don't reflect what the device is
            // actually reporting.

            // We know here that the coordinates for the pointer haven't changed because we
            // would've cleared the resampled bit in rewriteMessage if they had. We can't modify
            // lastResample in place because the mapping from pointer ID to index may have changed.
            touchState.lastResample.pointers[i] = oldLastResample.getPointerById(id);
            continue;
        }

        PointerCoords& resampledCoords = touchState.lastResample.pointers[i];
        const PointerCoords& currentCoords = current->getPointerById(id);
        resampledCoords = currentCoords;
        resampledCoords.isResampled = true;
        if (other->idBits.hasBit(id) && shouldResampleTool(event->getToolType(i))) {
            const PointerCoords& otherCoords = other->getPointerById(id);
            resampledCoords.setAxisValue(AMOTION_EVENT_AXIS_X,
                                         lerp(currentCoords.getX(), otherCoords.getX(), alpha));
            resampledCoords.setAxisValue(AMOTION_EVENT_AXIS_Y,
                                         lerp(currentCoords.getY(), otherCoords.getY(), alpha));
            ALOGD_IF(debugResampling(),
                     "[%d] - out (%0.3f, %0.3f), cur (%0.3f, %0.3f), "
                     "other (%0.3f, %0.3f), alpha %0.3f",
                     id, resampledCoords.getX(), resampledCoords.getY(), currentCoords.getX(),
                     currentCoords.getY(), otherCoords.getX(), otherCoords.getY(), alpha);
        } else {
            ALOGD_IF(debugResampling(), "[%d] - out (%0.3f, %0.3f), cur (%0.3f, %0.3f)", id,
                     resampledCoords.getX(), resampledCoords.getY(), currentCoords.getX(),
                     currentCoords.getY());
        }
    }

    event->addSample(sampleTime, touchState.lastResample.pointers);
}

status_t InputConsumer::sendFinishedSignal(uint32_t seq, bool handled) {
    ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
             "channel '%s' consumer ~ sendFinishedSignal: seq=%u, handled=%s",
             mChannel->getName().c_str(), seq, toString(handled));

    if (!seq) {
        ALOGE("Attempted to send a finished signal with sequence number 0.");
        return BAD_VALUE;
    }

    // Send finished signals for the batch sequence chain first.
    size_t seqChainCount = mSeqChains.size();
    if (seqChainCount) {
        uint32_t currentSeq = seq;
        uint32_t chainSeqs[seqChainCount];
        size_t chainIndex = 0;
        for (size_t i = seqChainCount; i > 0;) {
            i--;
            const SeqChain& seqChain = mSeqChains[i];
            if (seqChain.seq == currentSeq) {
                currentSeq = seqChain.chain;
                chainSeqs[chainIndex++] = currentSeq;
                mSeqChains.erase(mSeqChains.begin() + i);
            }
        }
        status_t status = OK;
        while (!status && chainIndex > 0) {
            chainIndex--;
            status = sendUnchainedFinishedSignal(chainSeqs[chainIndex], handled);
        }
        if (status) {
            // An error occurred so at least one signal was not sent, reconstruct the chain.
            for (;;) {
                SeqChain seqChain;
                seqChain.seq = chainIndex != 0 ? chainSeqs[chainIndex - 1] : seq;
                seqChain.chain = chainSeqs[chainIndex];
                mSeqChains.push_back(seqChain);
                if (!chainIndex) break;
                chainIndex--;
            }
            return status;
        }
    }

    // Send finished signal for the last message in the batch.
    return sendUnchainedFinishedSignal(seq, handled);
}

status_t InputConsumer::sendTimeline(int32_t inputEventId,
                                     std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline) {
    ALOGD_IF(DEBUG_TRANSPORT_CONSUMER,
             "channel '%s' consumer ~ sendTimeline: inputEventId=%" PRId32
             ", gpuCompletedTime=%" PRId64 ", presentTime=%" PRId64,
             mChannel->getName().c_str(), inputEventId,
             graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME],
             graphicsTimeline[GraphicsTimeline::PRESENT_TIME]);

    InputMessage msg;
    msg.header.type = InputMessage::Type::TIMELINE;
    msg.header.seq = 0;
    msg.body.timeline.eventId = inputEventId;
    msg.body.timeline.graphicsTimeline = std::move(graphicsTimeline);
    return mChannel->sendMessage(&msg);
}

nsecs_t InputConsumer::getConsumeTime(uint32_t seq) const {
    auto it = mConsumeTimes.find(seq);
    // Consume time will be missing if either 'finishInputEvent' is called twice, or if it was
    // called for the wrong (synthetic?) input event. Either way, it is a bug that should be fixed.
    LOG_ALWAYS_FATAL_IF(it == mConsumeTimes.end(), "Could not find consume time for seq=%" PRIu32,
                        seq);
    return it->second;
}

void InputConsumer::popConsumeTime(uint32_t seq) {
    mConsumeTimes.erase(seq);
}

status_t InputConsumer::sendUnchainedFinishedSignal(uint32_t seq, bool handled) {
    InputMessage msg;
    msg.header.type = InputMessage::Type::FINISHED;
    msg.header.seq = seq;
    msg.body.finished.handled = handled;
    msg.body.finished.consumeTime = getConsumeTime(seq);
    status_t result = mChannel->sendMessage(&msg);
    if (result == OK) {
        // Remove the consume time if the socket write succeeded. We will not need to ack this
        // message anymore. If the socket write did not succeed, we will try again and will still
        // need consume time.
        popConsumeTime(seq);

        // Trace the event processing timeline - event was just finished
        ATRACE_ASYNC_END(mProcessingTraceTag.c_str(), /*cookie=*/seq);
    }
    return result;
}

bool InputConsumer::hasPendingBatch() const {
    return !mBatches.empty();
}

int32_t InputConsumer::getPendingBatchSource() const {
    if (mBatches.empty()) {
        return AINPUT_SOURCE_CLASS_NONE;
    }

    const Batch& batch = mBatches[0];
    const InputMessage& head = batch.samples[0];
    return head.body.motion.source;
}

bool InputConsumer::probablyHasInput() const {
    return hasPendingBatch() || mChannel->probablyHasInput();
}

ssize_t InputConsumer::findBatch(int32_t deviceId, int32_t source) const {
    for (size_t i = 0; i < mBatches.size(); i++) {
        const Batch& batch = mBatches[i];
        const InputMessage& head = batch.samples[0];
        if (head.body.motion.deviceId == deviceId && head.body.motion.source == source) {
            return i;
        }
    }
    return -1;
}

ssize_t InputConsumer::findTouchState(int32_t deviceId, int32_t source) const {
    for (size_t i = 0; i < mTouchStates.size(); i++) {
        const TouchState& touchState = mTouchStates[i];
        if (touchState.deviceId == deviceId && touchState.source == source) {
            return i;
        }
    }
    return -1;
}

bool InputConsumer::canAddSample(const Batch& batch, const InputMessage* msg) {
    const InputMessage& head = batch.samples[0];
    uint32_t pointerCount = msg->body.motion.pointerCount;
    if (head.body.motion.pointerCount != pointerCount ||
        head.body.motion.action != msg->body.motion.action) {
        return false;
    }
    for (size_t i = 0; i < pointerCount; i++) {
        if (head.body.motion.pointers[i].properties != msg->body.motion.pointers[i].properties) {
            return false;
        }
    }
    return true;
}

ssize_t InputConsumer::findSampleNoLaterThan(const Batch& batch, nsecs_t time) {
    size_t numSamples = batch.samples.size();
    size_t index = 0;
    while (index < numSamples && batch.samples[index].body.motion.eventTime <= time) {
        index += 1;
    }
    return ssize_t(index) - 1;
}

std::string InputConsumer::dump() const {
    std::string out;
    out = out + "mResampleTouch = " + toString(mResampleTouch) + "\n";
    out = out + "mChannel = " + mChannel->getName() + "\n";
    out = out + "mMsgDeferred: " + toString(mMsgDeferred) + "\n";
    if (mMsgDeferred) {
        out = out + "mMsg : " + ftl::enum_string(mMsg.header.type) + "\n";
    }
    out += "Batches:\n";
    for (const Batch& batch : mBatches) {
        out += "    Batch:\n";
        for (const InputMessage& msg : batch.samples) {
            out += android::base::StringPrintf("        Message %" PRIu32 ": %s ", msg.header.seq,
                                               ftl::enum_string(msg.header.type).c_str());
            switch (msg.header.type) {
                case InputMessage::Type::KEY: {
                    out += android::base::StringPrintf("action=%s keycode=%" PRId32,
                                                       KeyEvent::actionToString(
                                                               msg.body.key.action),
                                                       msg.body.key.keyCode);
                    break;
                }
                case InputMessage::Type::MOTION: {
                    out = out + "action=" + MotionEvent::actionToString(msg.body.motion.action);
                    for (uint32_t i = 0; i < msg.body.motion.pointerCount; i++) {
                        const float x = msg.body.motion.pointers[i].coords.getX();
                        const float y = msg.body.motion.pointers[i].coords.getY();
                        out += android::base::StringPrintf("\n            Pointer %" PRIu32
                                                           " : x=%.1f y=%.1f",
                                                           i, x, y);
                    }
                    break;
                }
                case InputMessage::Type::FINISHED: {
                    out += android::base::StringPrintf("handled=%s, consumeTime=%" PRId64,
                                                       toString(msg.body.finished.handled),
                                                       msg.body.finished.consumeTime);
                    break;
                }
                case InputMessage::Type::FOCUS: {
                    out += android::base::StringPrintf("hasFocus=%s",
                                                       toString(msg.body.focus.hasFocus));
                    break;
                }
                case InputMessage::Type::CAPTURE: {
                    out += android::base::StringPrintf("hasCapture=%s",
                                                       toString(msg.body.capture
                                                                        .pointerCaptureEnabled));
                    break;
                }
                case InputMessage::Type::DRAG: {
                    out += android::base::StringPrintf("x=%.1f y=%.1f, isExiting=%s",
                                                       msg.body.drag.x, msg.body.drag.y,
                                                       toString(msg.body.drag.isExiting));
                    break;
                }
                case InputMessage::Type::TIMELINE: {
                    const nsecs_t gpuCompletedTime =
                            msg.body.timeline
                                    .graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME];
                    const nsecs_t presentTime =
                            msg.body.timeline.graphicsTimeline[GraphicsTimeline::PRESENT_TIME];
                    out += android::base::StringPrintf("inputEventId=%" PRId32
                                                       ", gpuCompletedTime=%" PRId64
                                                       ", presentTime=%" PRId64,
                                                       msg.body.timeline.eventId, gpuCompletedTime,
                                                       presentTime);
                    break;
                }
                case InputMessage::Type::TOUCH_MODE: {
                    out += android::base::StringPrintf("isInTouchMode=%s",
                                                       toString(msg.body.touchMode.isInTouchMode));
                    break;
                }
            }
            out += "\n";
        }
    }
    if (mBatches.empty()) {
        out += "    <empty>\n";
    }
    out += "mSeqChains:\n";
    for (const SeqChain& chain : mSeqChains) {
        out += android::base::StringPrintf("    chain: seq = %" PRIu32 " chain=%" PRIu32, chain.seq,
                                           chain.chain);
    }
    if (mSeqChains.empty()) {
        out += "    <empty>\n";
    }
    out += "mConsumeTimes:\n";
    for (const auto& [seq, consumeTime] : mConsumeTimes) {
        out += android::base::StringPrintf("    seq = %" PRIu32 " consumeTime = %" PRId64, seq,
                                           consumeTime);
    }
    if (mConsumeTimes.empty()) {
        out += "    <empty>\n";
    }
    return out;
}

} // namespace android
