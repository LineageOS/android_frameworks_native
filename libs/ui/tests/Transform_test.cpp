/*
 * Copyright 2021 The Android Open Source Project
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

#include <ui/Transform.h>

#include <gtest/gtest.h>

namespace android::ui {

TEST(TransformTest, inverseRotation_hasCorrectType) {
    const auto testRotationFlagsForInverse = [](Transform::RotationFlags rotation,
                                                Transform::RotationFlags expectedInverse,
                                                bool isRotation) {
        const Transform t(rotation, 0, 0);
        EXPECT_EQ(t.getOrientation(), rotation);
        const Transform inverse = t.inverse();
        EXPECT_EQ(inverse.getOrientation(), expectedInverse);

        if (isRotation) {
            EXPECT_TRUE(t.getType() & Transform::ROTATE);
            EXPECT_TRUE(inverse.getType() & Transform::ROTATE);
        } else {
            EXPECT_FALSE(t.getType() & Transform::ROTATE);
            EXPECT_FALSE(inverse.getType() & Transform::ROTATE);
        }
    };

    testRotationFlagsForInverse(Transform::ROT_0, Transform::ROT_0, false);
    testRotationFlagsForInverse(Transform::ROT_90, Transform::ROT_270, true);
    testRotationFlagsForInverse(Transform::ROT_180, Transform::ROT_180, true);
    testRotationFlagsForInverse(Transform::ROT_270, Transform::ROT_90, true);
    testRotationFlagsForInverse(Transform::FLIP_H, Transform::FLIP_H, false);
    testRotationFlagsForInverse(Transform::FLIP_V, Transform::FLIP_V, false);
}

} // namespace android::ui
