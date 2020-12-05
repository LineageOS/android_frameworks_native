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

#pragma once

namespace android {

// Jank information tracked by SurfaceFlinger for the purpose of funneling to telemetry.
enum JankType {
    // No Jank
    None = 0x0,
    // Jank not related to SurfaceFlinger or the App
    Display = 0x1,
    // SF took too long on the CPU
    SurfaceFlingerDeadlineMissed = 0x2,
    // SF took too long on the GPU
    SurfaceFlingerGpuDeadlineMissed = 0x4,
    // Either App or GPU took too long on the frame
    AppDeadlineMissed = 0x8,
    // Predictions live for 120ms, if prediction is expired for a frame, there is definitely a
    // jank
    // associated with the App if this is for a SurfaceFrame, and SF for a DisplayFrame.
    PredictionExpired = 0x10,
    // Latching a buffer early might cause an early present of the frame
    SurfaceFlingerEarlyLatch = 0x20,
};

} // namespace android
