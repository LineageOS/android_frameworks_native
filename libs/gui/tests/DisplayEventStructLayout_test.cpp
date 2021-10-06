/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include <gui/DisplayEventReceiver.h>

namespace android::test {

#define CHECK_OFFSET(type, member, expected_offset) \
    static_assert((offsetof(type, member) == (expected_offset)), "")

TEST(DisplayEventStructLayoutTest, TestEventAlignment) {
    CHECK_OFFSET(DisplayEventReceiver::Event, vsync, 24);
    CHECK_OFFSET(DisplayEventReceiver::Event, hotplug, 24);
    CHECK_OFFSET(DisplayEventReceiver::Event, modeChange, 24);

    CHECK_OFFSET(DisplayEventReceiver::Event::Header, type, 0);
    CHECK_OFFSET(DisplayEventReceiver::Event::Header, displayId, 8);
    CHECK_OFFSET(DisplayEventReceiver::Event::Header, timestamp, 16);

    CHECK_OFFSET(DisplayEventReceiver::Event::VSync, count, 0);
    CHECK_OFFSET(DisplayEventReceiver::Event::VSync, expectedVSyncTimestamp, 8);
    CHECK_OFFSET(DisplayEventReceiver::Event::VSync, deadlineTimestamp, 16);
    CHECK_OFFSET(DisplayEventReceiver::Event::VSync, frameInterval, 24);
    CHECK_OFFSET(DisplayEventReceiver::Event::VSync, vsyncId, 32);

    CHECK_OFFSET(DisplayEventReceiver::Event::Hotplug, connected, 0);

    CHECK_OFFSET(DisplayEventReceiver::Event::ModeChange, modeId, 0);
    CHECK_OFFSET(DisplayEventReceiver::Event::ModeChange, vsyncPeriod, 8);

    CHECK_OFFSET(DisplayEventReceiver::Event::FrameRateOverride, uid, 0);
    CHECK_OFFSET(DisplayEventReceiver::Event::FrameRateOverride, frameRateHz, 8);
}

} // namespace android::test
