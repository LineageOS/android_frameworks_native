/*
 * Copyright 2022 The Android Open Source Project
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

#define LOG_TAG "CompositorTiming"

#include <cutils/compiler.h>
#include <gui/CompositorTiming.h>
#include <log/log.h>

namespace android::gui {

CompositorTiming::CompositorTiming(nsecs_t vsyncDeadline, nsecs_t vsyncPeriod, nsecs_t vsyncPhase,
                                   nsecs_t presentLatency) {
    if (CC_UNLIKELY(vsyncPeriod <= 0)) {
        ALOGE("Invalid VSYNC period");
        return;
    }

    const nsecs_t idealLatency = [=] {
        // Modulo rounds toward 0 not INT64_MIN, so treat signs separately.
        if (vsyncPhase < 0) return -vsyncPhase % vsyncPeriod;

        const nsecs_t latency = (vsyncPeriod - vsyncPhase) % vsyncPeriod;
        return latency > 0 ? latency : vsyncPeriod;
    }();

    // Snap the latency to a value that removes scheduling jitter from the composite and present
    // times, which often have >1ms of jitter. Reducing jitter is important if an app attempts to
    // extrapolate something like user input to an accurate present time. Snapping also allows an
    // app to precisely calculate vsyncPhase with (presentLatency % interval).
    const nsecs_t bias = vsyncPeriod / 2;
    const nsecs_t extraVsyncs = (presentLatency - idealLatency + bias) / vsyncPeriod;
    const nsecs_t snappedLatency =
            extraVsyncs > 0 ? idealLatency + extraVsyncs * vsyncPeriod : idealLatency;

    this->deadline = vsyncDeadline - idealLatency;
    this->interval = vsyncPeriod;
    this->presentLatency = snappedLatency;
}

} // namespace android::gui
