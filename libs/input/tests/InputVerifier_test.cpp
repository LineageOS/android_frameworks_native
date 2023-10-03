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

#include <gtest/gtest.h>
#include <input/InputVerifier.h>
#include <string>

namespace android {

using android::base::Result;

TEST(InputVerifierTest, CreationWithInvalidUtfStringDoesNotCrash) {
    constexpr char bytes[] = {static_cast<char>(0xC0), static_cast<char>(0x80)};
    const std::string name(bytes, sizeof(bytes));
    InputVerifier verifier(name);
}

TEST(InputVerifierTest, ProcessSourceClassPointer) {
    InputVerifier verifier("Verify testOnTouchEventScroll");

    std::vector<PointerProperties> properties;
    properties.push_back({});
    properties.back().clear();
    properties.back().id = 0;
    properties.back().toolType = ToolType::UNKNOWN;

    std::vector<PointerCoords> coords;
    coords.push_back({});
    coords.back().clear();
    coords.back().setAxisValue(AMOTION_EVENT_AXIS_X, 75);
    coords.back().setAxisValue(AMOTION_EVENT_AXIS_Y, 300);

    const Result<void> result =
            verifier.processMovement(/*deviceId=*/0, AINPUT_SOURCE_CLASS_POINTER,
                                     AMOTION_EVENT_ACTION_DOWN,
                                     /*pointerCount=*/properties.size(), properties.data(),
                                     coords.data(), /*flags=*/0);
    ASSERT_TRUE(result.ok());
}

} // namespace android
