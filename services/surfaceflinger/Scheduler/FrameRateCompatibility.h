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

#pragma once

namespace android::scheduler {
// FrameRateCompatibility specifies how we should interpret the frame rate associated with
// the layer.
enum class FrameRateCompatibility {
    Default, // Layer didn't specify any specific handling strategy

    Min, // Layer needs the minimum frame rate.

    Exact, // Layer needs the exact frame rate.

    ExactOrMultiple, // Layer needs the exact frame rate (or a multiple of it) to present the
                     // content properly. Any other value will result in a pull down.

    Gte, // Layer needs greater than or equal to the frame rate.

    NoVote, // Layer doesn't have any requirements for the refresh rate and
            // should not be considered when the display refresh rate is determined.

    ftl_last = NoVote
};

} // namespace android::scheduler
