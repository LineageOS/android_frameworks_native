/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "InputVerifier"

#include <android-base/logging.h>
#include <input/InputVerifier.h>

namespace android {

/**
 * Log all of the movements that are sent to this verifier. Helps to identify the streams that lead
 * to inconsistent events.
 * Enable this via "adb shell setprop log.tag.InputVerifierLogEvents DEBUG"
 */
static bool logEvents() {
    return __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "LogEvents", ANDROID_LOG_INFO);
}

// --- InputVerifier ---

InputVerifier::InputVerifier(const std::string& name) : mName(name){};

void InputVerifier::processMovement(int32_t deviceId, int32_t action, uint32_t pointerCount,
                                    const PointerProperties* pointerProperties,
                                    const PointerCoords* pointerCoords, int32_t flags) {
    if (logEvents()) {
        LOG(ERROR) << "Processing " << MotionEvent::actionToString(action) << " for device "
                   << deviceId << " (" << pointerCount << " pointer"
                   << (pointerCount == 1 ? "" : "s") << ") on " << mName;
    }

    switch (MotionEvent::getActionMasked(action)) {
        case AMOTION_EVENT_ACTION_DOWN: {
            auto [it, inserted] = mTouchingPointerIdsByDevice.insert({deviceId, {}});
            if (!inserted) {
                LOG(FATAL) << "Got ACTION_DOWN, but already have touching pointers " << it->second
                           << " for device " << deviceId << " on " << mName;
            }
            it->second.set(pointerProperties[0].id);
            break;
        }
        case AMOTION_EVENT_ACTION_POINTER_DOWN: {
            auto it = mTouchingPointerIdsByDevice.find(deviceId);
            if (it == mTouchingPointerIdsByDevice.end()) {
                LOG(FATAL) << "Got POINTER_DOWN, but no touching pointers for device " << deviceId
                           << " on " << mName;
            }
            it->second.set(pointerProperties[MotionEvent::getActionIndex(action)].id);
            break;
        }
        case AMOTION_EVENT_ACTION_MOVE: {
            ensureTouchingPointersMatch(deviceId, pointerCount, pointerProperties, "MOVE");
            break;
        }
        case AMOTION_EVENT_ACTION_POINTER_UP: {
            auto it = mTouchingPointerIdsByDevice.find(deviceId);
            if (it == mTouchingPointerIdsByDevice.end()) {
                LOG(FATAL) << "Got POINTER_UP, but no touching pointers for device " << deviceId
                           << " on " << mName;
            }
            it->second.reset(pointerProperties[MotionEvent::getActionIndex(action)].id);
            break;
        }
        case AMOTION_EVENT_ACTION_UP: {
            auto it = mTouchingPointerIdsByDevice.find(deviceId);
            if (it == mTouchingPointerIdsByDevice.end()) {
                LOG(FATAL) << "Got ACTION_UP, but no record for deviceId " << deviceId << " on "
                           << mName;
            }
            const auto& [_, touchingPointerIds] = *it;
            if (touchingPointerIds.count() != 1) {
                LOG(FATAL) << "Got ACTION_UP, but we have pointers: " << touchingPointerIds
                           << " for deviceId " << deviceId << " on " << mName;
            }
            const int32_t pointerId = pointerProperties[0].id;
            if (!touchingPointerIds.test(pointerId)) {
                LOG(FATAL) << "Got ACTION_UP, but pointerId " << pointerId
                           << " is not touching. Touching pointers: " << touchingPointerIds
                           << " for deviceId " << deviceId << " on " << mName;
            }
            mTouchingPointerIdsByDevice.erase(it);
            break;
        }
        case AMOTION_EVENT_ACTION_CANCEL: {
            if ((flags & AMOTION_EVENT_FLAG_CANCELED) != AMOTION_EVENT_FLAG_CANCELED) {
                LOG(FATAL) << "For ACTION_CANCEL, must set FLAG_CANCELED";
            }
            ensureTouchingPointersMatch(deviceId, pointerCount, pointerProperties, "CANCEL");
            mTouchingPointerIdsByDevice.erase(deviceId);
            break;
        }
    }
}

void InputVerifier::ensureTouchingPointersMatch(int32_t deviceId, uint32_t pointerCount,
                                                const PointerProperties* pointerProperties,
                                                const char* action) const {
    auto it = mTouchingPointerIdsByDevice.find(deviceId);
    if (it == mTouchingPointerIdsByDevice.end()) {
        LOG(FATAL) << "Got " << action << ", but no touching pointers for device " << deviceId
                   << " on " << mName;
    }
    const auto& [_, touchingPointerIds] = *it;
    for (size_t i = 0; i < pointerCount; i++) {
        const int32_t pointerId = pointerProperties[i].id;
        if (!touchingPointerIds.test(pointerId)) {
            LOG(FATAL) << "Got " << action << " for pointerId " << pointerId
                       << " but the touching pointers are " << touchingPointerIds << " on "
                       << mName;
        }
    }
};

} // namespace android
