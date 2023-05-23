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

#include "../reader/mapper/SlopController.h"

#include <gtest/gtest.h>

namespace android {

// --- SlopControllerTest ---

TEST(SlopControllerTest, PositiveValues) {
    SlopController controller = SlopController(/*slopThreshold=*/5, /*slopDurationNanos=*/100);

    ASSERT_EQ(0, controller.consumeEvent(1000, 1));
    ASSERT_EQ(0, controller.consumeEvent(1003, 3));
    ASSERT_EQ(2, controller.consumeEvent(1005, 3));
    ASSERT_EQ(4, controller.consumeEvent(1009, 4));

    SlopController controller2 = SlopController(/*slopThreshold=*/5, /*slopDurationNanos=*/100);

    ASSERT_EQ(0, controller2.consumeEvent(1000, 5));
    ASSERT_EQ(3, controller2.consumeEvent(1003, 3));
    ASSERT_EQ(4, controller2.consumeEvent(1005, 4));
}

TEST(SlopControllerTest, NegativeValues) {
    SlopController controller = SlopController(/*slopThreshold=*/5, /*slopDurationNanos=*/100);

    ASSERT_EQ(0, controller.consumeEvent(1000, -1));
    ASSERT_EQ(0, controller.consumeEvent(1003, -3));
    ASSERT_EQ(-2, controller.consumeEvent(1005, -3));
    ASSERT_EQ(-4, controller.consumeEvent(1009, -4));

    SlopController controller2 = SlopController(/*slopThreshold=*/5, /*slopDurationNanos=*/100);

    ASSERT_EQ(0, controller2.consumeEvent(1000, -5));
    ASSERT_EQ(-3, controller2.consumeEvent(1003, -3));
    ASSERT_EQ(-4, controller2.consumeEvent(1005, -4));
}

TEST(SlopControllerTest, ZeroDoesNotResetSlop) {
    SlopController controller = SlopController(/*slopThreshold=*/5, /*slopDurationNanos=*/100);

    ASSERT_EQ(1, controller.consumeEvent(1005, 6));
    ASSERT_EQ(0, controller.consumeEvent(1006, 0));
    ASSERT_EQ(2, controller.consumeEvent(1008, 2));
}

TEST(SlopControllerTest, SignChange_ResetsSlop) {
    SlopController controller = SlopController(/*slopThreshold=*/5, /*slopDurationNanos=*/100);

    ASSERT_EQ(0, controller.consumeEvent(1000, 2));
    ASSERT_EQ(0, controller.consumeEvent(1001, -4));
    ASSERT_EQ(0, controller.consumeEvent(1002, 3));
    ASSERT_EQ(0, controller.consumeEvent(1003, -2));

    ASSERT_EQ(1, controller.consumeEvent(1005, 6));
    ASSERT_EQ(0, controller.consumeEvent(1006, 0));
    ASSERT_EQ(2, controller.consumeEvent(1008, 2));

    ASSERT_EQ(0, controller.consumeEvent(1010, -4));
    ASSERT_EQ(-1, controller.consumeEvent(1011, -2));

    ASSERT_EQ(0, controller.consumeEvent(1015, 5));
    ASSERT_EQ(2, controller.consumeEvent(1016, 2));

    ASSERT_EQ(0, controller.consumeEvent(1017, -5));
    ASSERT_EQ(-2, controller.consumeEvent(1018, -2));
}

TEST(SlopControllerTest, OldAge_ResetsSlop) {
    SlopController controller = SlopController(/*slopThreshold=*/5, /*slopDurationNanos=*/100);

    ASSERT_EQ(1, controller.consumeEvent(1005, 6));
    ASSERT_EQ(0, controller.consumeEvent(1108, 2)); // age exceeds slop duration

    ASSERT_EQ(1, controller.consumeEvent(1110, 4));
    ASSERT_EQ(0, controller.consumeEvent(1210, 2)); // age equals slop duration

    ASSERT_EQ(0, controller.consumeEvent(1215, -3));
    ASSERT_EQ(-2, controller.consumeEvent(1216, -4));
    ASSERT_EQ(-5, controller.consumeEvent(1315, -5));
}

} // namespace android
