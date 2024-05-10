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

#include <binder/Binder.h>
#include <binder/Parcel.h>

#include <gui/WindowInfo.h>

using std::chrono_literals::operator""s;

namespace android {

using gui::InputApplicationInfo;
using gui::TouchOcclusionMode;
using gui::WindowInfo;
using ui::Size;

namespace test {

TEST(WindowInfo, ParcellingWithoutToken) {
    WindowInfo i, i2;
    i.token = nullptr;

    Parcel p;
    ASSERT_EQ(OK, i.writeToParcel(&p));
    p.setDataPosition(0);
    i2.readFromParcel(&p);
    ASSERT_TRUE(i2.token == nullptr);
}

TEST(WindowInfo, Parcelling) {
    sp<IBinder> touchableRegionCropHandle = new BBinder();
    WindowInfo i;
    i.token = new BBinder();
    i.windowToken = new BBinder();
    i.id = 1;
    i.name = "Foobar";
    i.layoutParamsFlags = WindowInfo::Flag::SLIPPERY;
    i.layoutParamsType = WindowInfo::Type::INPUT_METHOD;
    i.dispatchingTimeout = 12s;
    i.frame = Rect(93, 34, 16, 19);
    i.contentSize = Size(10, 40);
    i.surfaceInset = 17;
    i.globalScaleFactor = 0.3;
    i.alpha = 0.7;
    i.transform.set({0.4, -1, 100, 0.5, 0, 40, 0, 0, 1});
    i.touchOcclusionMode = TouchOcclusionMode::ALLOW;
    i.ownerPid = gui::Pid{19};
    i.ownerUid = gui::Uid{24};
    i.packageName = "com.example.package";
    i.inputConfig = WindowInfo::InputConfig::NOT_FOCUSABLE;
    i.displayId = ui::LogicalDisplayId{34};
    i.replaceTouchableRegionWithCrop = true;
    i.touchableRegionCropHandle = touchableRegionCropHandle;
    i.applicationInfo.name = "ApplicationFooBar";
    i.applicationInfo.token = new BBinder();
    i.applicationInfo.dispatchingTimeoutMillis = 0x12345678ABCD;
    i.focusTransferTarget = new BBinder();

    Parcel p;
    i.writeToParcel(&p);
    p.setDataPosition(0);
    WindowInfo i2;
    i2.readFromParcel(&p);
    ASSERT_EQ(i.token, i2.token);
    ASSERT_EQ(i.windowToken, i2.windowToken);
    ASSERT_EQ(i.id, i2.id);
    ASSERT_EQ(i.name, i2.name);
    ASSERT_EQ(i.layoutParamsFlags, i2.layoutParamsFlags);
    ASSERT_EQ(i.layoutParamsType, i2.layoutParamsType);
    ASSERT_EQ(i.dispatchingTimeout, i2.dispatchingTimeout);
    ASSERT_EQ(i.frame, i2.frame);
    ASSERT_EQ(i.contentSize, i2.contentSize);
    ASSERT_EQ(i.surfaceInset, i2.surfaceInset);
    ASSERT_EQ(i.globalScaleFactor, i2.globalScaleFactor);
    ASSERT_EQ(i.alpha, i2.alpha);
    ASSERT_EQ(i.transform, i2.transform);
    ASSERT_EQ(i.touchOcclusionMode, i2.touchOcclusionMode);
    ASSERT_EQ(i.ownerPid, i2.ownerPid);
    ASSERT_EQ(i.ownerUid, i2.ownerUid);
    ASSERT_EQ(i.packageName, i2.packageName);
    ASSERT_EQ(i.inputConfig, i2.inputConfig);
    ASSERT_EQ(i.displayId, i2.displayId);
    ASSERT_EQ(i.replaceTouchableRegionWithCrop, i2.replaceTouchableRegionWithCrop);
    ASSERT_EQ(i.touchableRegionCropHandle, i2.touchableRegionCropHandle);
    ASSERT_EQ(i.applicationInfo, i2.applicationInfo);
    ASSERT_EQ(i.focusTransferTarget, i2.focusTransferTarget);
}

TEST(InputApplicationInfo, Parcelling) {
    InputApplicationInfo i;
    i.token = new BBinder();
    i.name = "ApplicationFooBar";
    i.dispatchingTimeoutMillis = 0x12345678ABCD;

    Parcel p;
    ASSERT_EQ(i.writeToParcel(&p), OK);
    p.setDataPosition(0);
    InputApplicationInfo i2;
    ASSERT_EQ(i2.readFromParcel(&p), OK);
    ASSERT_EQ(i, i2);
}

} // namespace test
} // namespace android
