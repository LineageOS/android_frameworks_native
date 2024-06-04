/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "../Macros.h"

#include "VibratorInputMapper.h"

namespace android {

VibratorInputMapper::VibratorInputMapper(InputDeviceContext& deviceContext,
                                         const InputReaderConfiguration& readerConfig)
      : InputMapper(deviceContext, readerConfig), mVibrating(false), mSequence(0) {}

VibratorInputMapper::~VibratorInputMapper() {}

uint32_t VibratorInputMapper::getSources() const {
    return 0;
}

void VibratorInputMapper::populateDeviceInfo(InputDeviceInfo& info) {
    InputMapper::populateDeviceInfo(info);

    info.setVibrator(true);
}

std::list<NotifyArgs> VibratorInputMapper::process(const RawEvent& rawEvent) {
    // TODO: Handle FF_STATUS, although it does not seem to be widely supported.
    return {};
}

std::list<NotifyArgs> VibratorInputMapper::vibrate(const VibrationSequence& sequence,
                                                   ssize_t repeat, int32_t token) {
    if (DEBUG_VIBRATOR) {
        ALOGD("vibrate: deviceId=%d, pattern=[%s], repeat=%zd, token=%d", getDeviceId(),
              sequence.toString().c_str(), repeat, token);
    }
    std::list<NotifyArgs> out;

    mVibrating = true;
    mSequence = sequence;
    mRepeat = repeat;
    mToken = token;
    mIndex = -1;

    // Request InputReader to notify InputManagerService for vibration started.
    out.push_back(
            NotifyVibratorStateArgs(getContext()->getNextId(), systemTime(), getDeviceId(), true));
    out += nextStep();
    return out;
}

std::list<NotifyArgs> VibratorInputMapper::cancelVibrate(int32_t token) {
    if (DEBUG_VIBRATOR) {
        ALOGD("cancelVibrate: deviceId=%d, token=%d", getDeviceId(), token);
    }
    std::list<NotifyArgs> out;

    if (mVibrating && mToken == token) {
        out.push_back(stopVibrating());
    }
    return out;
}

bool VibratorInputMapper::isVibrating() {
    return mVibrating;
}

std::vector<int32_t> VibratorInputMapper::getVibratorIds() {
    return getDeviceContext().getVibratorIds();
}

std::list<NotifyArgs> VibratorInputMapper::timeoutExpired(nsecs_t when) {
    std::list<NotifyArgs> out;
    if (mVibrating) {
        if (when >= mNextStepTime) {
            out += nextStep();
        } else {
            getContext()->requestTimeoutAtTime(mNextStepTime);
        }
    }
    return out;
}

std::list<NotifyArgs> VibratorInputMapper::nextStep() {
    if (DEBUG_VIBRATOR) {
        ALOGD("nextStep: index=%d, vibrate deviceId=%d", (int)mIndex, getDeviceId());
    }
    std::list<NotifyArgs> out;
    mIndex += 1;
    if (size_t(mIndex) >= mSequence.pattern.size()) {
        if (mRepeat < 0) {
            // We are done.
            out.push_back(stopVibrating());
            return out;
        }
        mIndex = mRepeat;
    }

    const VibrationElement& element = mSequence.pattern[mIndex];
    if (element.isOn()) {
        if (DEBUG_VIBRATOR) {
            std::string description = element.toString();
            ALOGD("nextStep: sending vibrate deviceId=%d, element=%s", getDeviceId(),
                  description.c_str());
        }
        getDeviceContext().vibrate(element);
    } else {
        if (DEBUG_VIBRATOR) {
            ALOGD("nextStep: sending cancel vibrate deviceId=%d", getDeviceId());
        }
        getDeviceContext().cancelVibrate();
    }
    nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
    std::chrono::nanoseconds duration =
            std::chrono::duration_cast<std::chrono::nanoseconds>(element.duration);
    mNextStepTime = now + duration.count();
    getContext()->requestTimeoutAtTime(mNextStepTime);
    if (DEBUG_VIBRATOR) {
        ALOGD("nextStep: scheduled timeout in %lldms", element.duration.count());
    }
    return out;
}

NotifyVibratorStateArgs VibratorInputMapper::stopVibrating() {
    mVibrating = false;
    if (DEBUG_VIBRATOR) {
        ALOGD("stopVibrating: sending cancel vibrate deviceId=%d", getDeviceId());
    }
    getDeviceContext().cancelVibrate();

    // Request InputReader to notify InputManagerService for vibration complete.
    return NotifyVibratorStateArgs(getContext()->getNextId(), systemTime(), getDeviceId(), false);
}

void VibratorInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Vibrator Input Mapper:\n";
    dump += StringPrintf(INDENT3 "Vibrating: %s\n", toString(mVibrating));
    if (mVibrating) {
        dump += INDENT3 "Pattern: ";
        dump += mSequence.toString();
        dump += "\n";
        dump += StringPrintf(INDENT3 "Repeat Index: %zd\n", mRepeat);
    }
}

} // namespace android
