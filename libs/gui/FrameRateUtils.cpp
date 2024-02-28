/*
 * Copyright 2023 The Android Open Source Project
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

#include <gui/FrameRateUtils.h>
#include <system/window.h>
#include <utils/Log.h>

#include <cmath>

#include <com_android_graphics_libgui_flags.h>

namespace android {
using namespace com::android::graphics::libgui;
// Returns true if the frameRate is valid.
//
// @param frameRate the frame rate in Hz
// @param compatibility a ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_*
// @param changeFrameRateStrategy a ANATIVEWINDOW_CHANGE_FRAME_RATE_*
// @param functionName calling function or nullptr. Used for logging
// @param privileged whether caller has unscoped surfaceflinger access
bool ValidateFrameRate(float frameRate, int8_t compatibility, int8_t changeFrameRateStrategy,
                       const char* inFunctionName, bool privileged) {
    const char* functionName = inFunctionName != nullptr ? inFunctionName : "call";
    int floatClassification = std::fpclassify(frameRate);
    if (frameRate < 0 || floatClassification == FP_INFINITE || floatClassification == FP_NAN) {
        ALOGE("%s failed - invalid frame rate %f", functionName, frameRate);
        return false;
    }

    if (compatibility != ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT &&
        compatibility != ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE &&
        compatibility != ANATIVEWINDOW_FRAME_RATE_GTE &&
        (!privileged ||
         (compatibility != ANATIVEWINDOW_FRAME_RATE_EXACT &&
          compatibility != ANATIVEWINDOW_FRAME_RATE_NO_VOTE))) {
        ALOGE("%s failed - invalid compatibility value %d privileged: %s", functionName,
              compatibility, privileged ? "yes" : "no");
        return false;
    }

    if (__builtin_available(android 31, *)) {
        if (changeFrameRateStrategy != ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS &&
            changeFrameRateStrategy != ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS) {
            ALOGE("%s failed - invalid change frame rate strategy value %d", functionName,
                  changeFrameRateStrategy);
            if (flags::bq_setframerate()) {
                return false;
            }
        }
    }

    return true;
}

} // namespace android
