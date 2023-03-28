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

// clang-format off
#include "../Macros.h"
// clang-format on

#include "RotaryEncoderInputMapper.h"

#include <optional>

#include "CursorScrollAccumulator.h"

namespace android {

RotaryEncoderInputMapper::RotaryEncoderInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext), mOrientation(ui::ROTATION_0) {
    mSource = AINPUT_SOURCE_ROTARY_ENCODER;
}

RotaryEncoderInputMapper::~RotaryEncoderInputMapper() {}

uint32_t RotaryEncoderInputMapper::getSources() const {
    return mSource;
}

void RotaryEncoderInputMapper::populateDeviceInfo(InputDeviceInfo& info) {
    InputMapper::populateDeviceInfo(info);

    if (mRotaryEncoderScrollAccumulator.haveRelativeVWheel()) {
        const PropertyMap& config = getDeviceContext().getConfiguration();
        std::optional<float> res = config.getFloat("device.res");
        if (!res.has_value()) {
            ALOGW("Rotary Encoder device configuration file didn't specify resolution!\n");
        }
        std::optional<float> scalingFactor = config.getFloat("device.scalingFactor");
        if (!scalingFactor.has_value()) {
            ALOGW("Rotary Encoder device configuration file didn't specify scaling factor,"
                  "default to 1.0!\n");
        }
        mScalingFactor = scalingFactor.value_or(1.0f);
        info.addMotionRange(AMOTION_EVENT_AXIS_SCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f,
                            res.value_or(0.0f) * mScalingFactor);
    }
}

void RotaryEncoderInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Rotary Encoder Input Mapper:\n";
    dump += StringPrintf(INDENT3 "HaveWheel: %s\n",
                         toString(mRotaryEncoderScrollAccumulator.haveRelativeVWheel()));
}

std::list<NotifyArgs> RotaryEncoderInputMapper::configure(nsecs_t when,
                                                          const InputReaderConfiguration* config,
                                                          uint32_t changes) {
    std::list<NotifyArgs> out = InputMapper::configure(when, config, changes);
    if (!changes) {
        mRotaryEncoderScrollAccumulator.configure(getDeviceContext());
    }
    if (!changes || (changes & InputReaderConfiguration::CHANGE_DISPLAY_INFO)) {
        std::optional<DisplayViewport> internalViewport =
                config->getDisplayViewportByType(ViewportType::INTERNAL);
        if (internalViewport) {
            mOrientation = internalViewport->orientation;
        } else {
            mOrientation = ui::ROTATION_0;
        }
    }
    return out;
}

std::list<NotifyArgs> RotaryEncoderInputMapper::reset(nsecs_t when) {
    mRotaryEncoderScrollAccumulator.reset(getDeviceContext());

    return InputMapper::reset(when);
}

std::list<NotifyArgs> RotaryEncoderInputMapper::process(const RawEvent* rawEvent) {
    std::list<NotifyArgs> out;
    mRotaryEncoderScrollAccumulator.process(rawEvent);

    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        out += sync(rawEvent->when, rawEvent->readTime);
    }
    return out;
}

std::list<NotifyArgs> RotaryEncoderInputMapper::sync(nsecs_t when, nsecs_t readTime) {
    std::list<NotifyArgs> out;

    float scroll = mRotaryEncoderScrollAccumulator.getRelativeVWheel();
    bool scrolled = scroll != 0;

    // Send motion event.
    if (scrolled) {
        int32_t metaState = getContext()->getGlobalMetaState();
        // This is not a pointer, so it's not associated with a display.
        int32_t displayId = ADISPLAY_ID_NONE;

        if (mOrientation == ui::ROTATION_180) {
            scroll = -scroll;
        }

        PointerCoords pointerCoords;
        pointerCoords.clear();
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_SCROLL, scroll * mScalingFactor);

        PointerProperties pointerProperties;
        pointerProperties.clear();
        pointerProperties.id = 0;
        pointerProperties.toolType = ToolType::UNKNOWN;

        uint32_t policyFlags = 0;
        if (getDeviceContext().isExternal()) {
            policyFlags |= POLICY_FLAG_WAKE;
        }

        out.push_back(
                NotifyMotionArgs(getContext()->getNextId(), when, readTime, getDeviceId(), mSource,
                                 displayId, policyFlags, AMOTION_EVENT_ACTION_SCROLL, 0, 0,
                                 metaState, /* buttonState */ 0, MotionClassification::NONE,
                                 AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                 &pointerCoords, 0, 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                                 AMOTION_EVENT_INVALID_CURSOR_POSITION, 0, /* videoFrames */ {}));
    }

    mRotaryEncoderScrollAccumulator.finishSync();
    return out;
}

} // namespace android
