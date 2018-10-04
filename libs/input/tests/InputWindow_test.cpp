/*
 * Copyright 2018 The Android Open Source Project
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

#include <binder/Parcel.h>

#include <input/InputWindow.h>
#include <input/InputTransport.h>

namespace android {
namespace test {

TEST(InputWindowInfo, ParcellingWithoutChannel) {
    InputWindowInfo i;
    i.inputChannel = nullptr;

    Parcel p;
    ASSERT_EQ(OK, i.write(p));
    p.setDataPosition(0);
    InputWindowInfo i2 = InputWindowInfo::read(p);
    ASSERT_TRUE(i2.inputChannel == nullptr);
}

TEST(InputWindowInfo, Parcelling) {
    sp<InputChannel> channel, junkChannel;
    status_t result = InputChannel::openInputChannelPair("name", channel, junkChannel);
    ASSERT_EQ(OK, result) << "openInputChannelPair should have returned valid channels";

    InputWindowInfo i;
    i.inputChannel = channel;
    i.name = "Foobar";
    i.layoutParamsFlags = 7;
    i.layoutParamsType = 39;
    i.dispatchingTimeout = 12;
    i.frameLeft = 93;
    i.frameTop = 34;
    i.frameRight = 16;
    i.frameBottom = 19;
    i.scaleFactor = 0.3;
    i.visible = false;
    i.canReceiveKeys = false;
    i.hasFocus = false;
    i.hasWallpaper = false;
    i.paused = false;
    i.layer = 7;
    i.ownerPid = 19;
    i.ownerUid = 24;
    i.inputFeatures = 29;
    i.displayId = 34;

    Parcel p;
    i.write(p);

    p.setDataPosition(0);
    InputWindowInfo i2 = InputWindowInfo::read(p);
    ASSERT_EQ(i.inputChannel->getName(), i2.inputChannel->getName());
    ASSERT_EQ(i.name, i2.name);
    ASSERT_EQ(i.layoutParamsFlags, i2.layoutParamsFlags);
    ASSERT_EQ(i.layoutParamsType, i2.layoutParamsType);
    ASSERT_EQ(i.dispatchingTimeout, i2.dispatchingTimeout);
    ASSERT_EQ(i.frameLeft, i2.frameLeft);
    ASSERT_EQ(i.frameTop, i2.frameTop);
    ASSERT_EQ(i.frameRight, i2.frameRight);
    ASSERT_EQ(i.frameBottom, i2.frameBottom);
    ASSERT_EQ(i.scaleFactor, i2.scaleFactor);
    ASSERT_EQ(i.visible, i2.visible);
    ASSERT_EQ(i.canReceiveKeys, i2.canReceiveKeys);
    ASSERT_EQ(i.hasFocus, i2.hasFocus);
    ASSERT_EQ(i.hasWallpaper, i2.hasWallpaper);
    ASSERT_EQ(i.paused, i2.paused);
    ASSERT_EQ(i.layer, i2.layer);
    ASSERT_EQ(i.ownerPid, i2.ownerPid);
    ASSERT_EQ(i.ownerUid, i2.ownerUid);
    ASSERT_EQ(i.inputFeatures, i2.inputFeatures);
    ASSERT_EQ(i.displayId, i2.displayId);
}

} // namespace test
} // namespace android
