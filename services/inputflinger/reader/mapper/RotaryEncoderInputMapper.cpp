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

#include "Macros.h"

#include "RotaryEncoderInputMapper.h"

#include "CursorScrollAccumulator.h"

namespace android {

RotaryEncoderInputMapper::RotaryEncoderInputMapper(InputDevice* device)
      : InputMapper(device), mOrientation(DISPLAY_ORIENTATION_0) {
    mSource = AINPUT_SOURCE_ROTARY_ENCODER;
}

RotaryEncoderInputMapper::~RotaryEncoderInputMapper() {}

uint32_t RotaryEncoderInputMapper::getSources() {
    return mSource;
}

void RotaryEncoderInputMapper::populateDeviceInfo(InputDeviceInfo* info) {
    InputMapper::populateDeviceInfo(info);

    if (mRotaryEncoderScrollAccumulator.haveRelativeVWheel()) {
        float res = 0.0f;
        if (!mDevice->getConfiguration().tryGetProperty(String8("device.res"), res)) {
            ALOGW("Rotary Encoder device configuration file didn't specify resolution!\n");
        }
        if (!mDevice->getConfiguration().tryGetProperty(String8("device.scalingFactor"),
                                                        mScalingFactor)) {
            ALOGW("Rotary Encoder device configuration file didn't specify scaling factor,"
                  "default to 1.0!\n");
            mScalingFactor = 1.0f;
        }
        info->addMotionRange(AMOTION_EVENT_AXIS_SCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f,
                             res * mScalingFactor);
    }
}

void RotaryEncoderInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Rotary Encoder Input Mapper:\n";
    dump += StringPrintf(INDENT3 "HaveWheel: %s\n",
                         toString(mRotaryEncoderScrollAccumulator.haveRelativeVWheel()));
}

void RotaryEncoderInputMapper::configure(nsecs_t when, const InputReaderConfiguration* config,
                                         uint32_t changes) {
    InputMapper::configure(when, config, changes);
    if (!changes) {
        mRotaryEncoderScrollAccumulator.configure(getDevice());
    }
    if (!changes || (changes & InputReaderConfiguration::CHANGE_DISPLAY_INFO)) {
        std::optional<DisplayViewport> internalViewport =
                config->getDisplayViewportByType(ViewportType::VIEWPORT_INTERNAL);
        if (internalViewport) {
            mOrientation = internalViewport->orientation;
        } else {
            mOrientation = DISPLAY_ORIENTATION_0;
        }
    }
}

void RotaryEncoderInputMapper::reset(nsecs_t when) {
    mRotaryEncoderScrollAccumulator.reset(getDevice());

    InputMapper::reset(when);
}

void RotaryEncoderInputMapper::process(const RawEvent* rawEvent) {
    mRotaryEncoderScrollAccumulator.process(rawEvent);

    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        sync(rawEvent->when);
    }
}

void RotaryEncoderInputMapper::sync(nsecs_t when) {
    PointerCoords pointerCoords;
    pointerCoords.clear();

    PointerProperties pointerProperties;
    pointerProperties.clear();
    pointerProperties.id = 0;
    pointerProperties.toolType = AMOTION_EVENT_TOOL_TYPE_UNKNOWN;

    float scroll = mRotaryEncoderScrollAccumulator.getRelativeVWheel();
    bool scrolled = scroll != 0;

    // This is not a pointer, so it's not associated with a display.
    int32_t displayId = ADISPLAY_ID_NONE;

    // Moving the rotary encoder should wake the device (if specified).
    uint32_t policyFlags = 0;
    if (scrolled && getDevice()->isExternal()) {
        policyFlags |= POLICY_FLAG_WAKE;
    }

    if (mOrientation == DISPLAY_ORIENTATION_180) {
        scroll = -scroll;
    }

    // Send motion event.
    if (scrolled) {
        int32_t metaState = mContext->getGlobalMetaState();
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_SCROLL, scroll * mScalingFactor);

        NotifyMotionArgs scrollArgs(mContext->getNextSequenceNum(), when, getDeviceId(), mSource,
                                    displayId, policyFlags, AMOTION_EVENT_ACTION_SCROLL, 0, 0,
                                    metaState, /* buttonState */ 0, MotionClassification::NONE,
                                    AMOTION_EVENT_EDGE_FLAG_NONE,
                                    /* deviceTimestamp */ 0, 1, &pointerProperties, &pointerCoords,
                                    0, 0, 0, /* videoFrames */ {});
        getListener()->notifyMotion(&scrollArgs);
    }

    mRotaryEncoderScrollAccumulator.finishSync();
}

} // namespace android
