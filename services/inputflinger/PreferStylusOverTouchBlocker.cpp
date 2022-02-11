/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "PreferStylusOverTouchBlocker.h"

#include <android-base/stringprintf.h>

using android::base::StringPrintf;

static const char* toString(bool value) {
    return value ? "true" : "false";
}

namespace android {

ftl::StaticVector<NotifyMotionArgs, 2> PreferStylusOverTouchBlocker::processMotion(
        const NotifyMotionArgs& args) {
    const bool isStylusEvent = isFromSource(args.source, AINPUT_SOURCE_STYLUS);
    if (isStylusEvent) {
        for (size_t i = 0; i < args.pointerCount; i++) {
            // Make sure we are canceling stylus pointers
            const int32_t toolType = args.pointerProperties[i].toolType;
            LOG_ALWAYS_FATAL_IF(toolType != AMOTION_EVENT_TOOL_TYPE_STYLUS &&
                                        toolType != AMOTION_EVENT_TOOL_TYPE_ERASER,
                                "The pointer %zu has toolType=%i, but the source is STYLUS. If "
                                "simultaneous touch and stylus is supported, "
                                "'PreferStylusOverTouchBlocker' should be disabled.",
                                i, toolType);
        }
    }
    const bool isDown = args.action == AMOTION_EVENT_ACTION_DOWN;
    const bool isUpOrCancel =
            args.action == AMOTION_EVENT_ACTION_UP || args.action == AMOTION_EVENT_ACTION_CANCEL;
    if (isStylusEvent) {
        if (isDown) {
            // Reject all touch while stylus is down
            mIsStylusDown = true;
            if (mIsTouchDown && !mCurrentTouchIsCanceled) {
                // Cancel touch!
                mCurrentTouchIsCanceled = true;
                mLastTouchEvent.action = AMOTION_EVENT_ACTION_CANCEL;
                mLastTouchEvent.flags |= AMOTION_EVENT_FLAG_CANCELED;
                mLastTouchEvent.eventTime = systemTime(SYSTEM_TIME_MONOTONIC);
                return {mLastTouchEvent, args};
            }
        }
        if (isUpOrCancel) {
            mIsStylusDown = false;
        }
        // Never drop stylus events
        return {args};
    }

    const bool isTouchEvent =
            isFromSource(args.source, AINPUT_SOURCE_TOUCHSCREEN) && !isStylusEvent;
    if (isTouchEvent) {
        if (mIsStylusDown) {
            mCurrentTouchIsCanceled = true;
        }
        // If we already canceled the current gesture, then continue to drop events from it, even if
        // the stylus has been lifted.
        if (mCurrentTouchIsCanceled) {
            if (isUpOrCancel) {
                mCurrentTouchIsCanceled = false;
            }
            return {};
        }

        // Update state
        mLastTouchEvent = args;
        if (isDown) {
            mIsTouchDown = true;
        }
        if (isUpOrCancel) {
            mIsTouchDown = false;
            mCurrentTouchIsCanceled = false;
        }
        return {args};
    }

    // Not a touch or stylus event
    return {args};
}

std::string PreferStylusOverTouchBlocker::dump() {
    std::string out;
    out += StringPrintf("mIsTouchDown: %s\n", toString(mIsTouchDown));
    out += StringPrintf("mIsStylusDown: %s\n", toString(mIsStylusDown));
    out += StringPrintf("mLastTouchEvent: %s\n", mLastTouchEvent.dump().c_str());
    out += StringPrintf("mCurrentTouchIsCanceled: %s\n", toString(mCurrentTouchIsCanceled));
    return out;
}

} // namespace android
