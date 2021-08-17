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

#include <input/InputWindow.h>
#include <input/InputTransport.h>

using std::chrono_literals::operator""s;

namespace android {
namespace test {

TEST(InputWindowInfo, ParcellingWithoutToken) {
    InputWindowInfo i, i2;
    i.token = nullptr;

    Parcel p;
    ASSERT_EQ(OK, i.writeToParcel(&p));
    p.setDataPosition(0);
    i2.readFromParcel(&p);
    ASSERT_TRUE(i2.token == nullptr);
}

TEST(InputWindowInfo, Parcelling) {
    sp<IBinder> touchableRegionCropHandle = new BBinder();
    InputWindowInfo i;
    i.token = new BBinder();
    i.id = 1;
    i.name = "Foobar";
    i.flags = InputWindowInfo::Flag::SLIPPERY;
    i.type = InputWindowInfo::Type::INPUT_METHOD;
    i.dispatchingTimeout = 12s;
    i.frameLeft = 93;
    i.frameTop = 34;
    i.frameRight = 16;
    i.frameBottom = 19;
    i.surfaceInset = 17;
    i.globalScaleFactor = 0.3;
    i.alpha = 0.7;
    i.transform.set({0.4, -1, 100, 0.5, 0, 40, 0, 0, 1});
    i.displayWidth = 1000;
    i.displayHeight = 2000;
    i.visible = false;
    i.focusable = false;
    i.hasWallpaper = false;
    i.paused = false;
    i.touchOcclusionMode = TouchOcclusionMode::ALLOW;
    i.ownerPid = 19;
    i.ownerUid = 24;
    i.packageName = "com.example.package";
    i.inputFeatures = InputWindowInfo::Feature::DISABLE_USER_ACTIVITY;
    i.displayId = 34;
    i.portalToDisplayId = 2;
    i.replaceTouchableRegionWithCrop = true;
    i.touchableRegionCropHandle = touchableRegionCropHandle;
    i.applicationInfo.name = "ApplicationFooBar";
    i.applicationInfo.token = new BBinder();
    i.applicationInfo.dispatchingTimeoutMillis = 0x12345678ABCD;

    Parcel p;
    i.writeToParcel(&p);
    p.setDataPosition(0);
    InputWindowInfo i2;
    i2.readFromParcel(&p);
    ASSERT_EQ(i.token, i2.token);
    ASSERT_EQ(i.id, i2.id);
    ASSERT_EQ(i.name, i2.name);
    ASSERT_EQ(i.flags, i2.flags);
    ASSERT_EQ(i.type, i2.type);
    ASSERT_EQ(i.dispatchingTimeout, i2.dispatchingTimeout);
    ASSERT_EQ(i.frameLeft, i2.frameLeft);
    ASSERT_EQ(i.frameTop, i2.frameTop);
    ASSERT_EQ(i.frameRight, i2.frameRight);
    ASSERT_EQ(i.frameBottom, i2.frameBottom);
    ASSERT_EQ(i.surfaceInset, i2.surfaceInset);
    ASSERT_EQ(i.globalScaleFactor, i2.globalScaleFactor);
    ASSERT_EQ(i.alpha, i2.alpha);
    ASSERT_EQ(i.transform, i2.transform);
    ASSERT_EQ(i.displayWidth, i2.displayWidth);
    ASSERT_EQ(i.displayHeight, i2.displayHeight);
    ASSERT_EQ(i.visible, i2.visible);
    ASSERT_EQ(i.focusable, i2.focusable);
    ASSERT_EQ(i.hasWallpaper, i2.hasWallpaper);
    ASSERT_EQ(i.paused, i2.paused);
    ASSERT_EQ(i.touchOcclusionMode, i2.touchOcclusionMode);
    ASSERT_EQ(i.ownerPid, i2.ownerPid);
    ASSERT_EQ(i.ownerUid, i2.ownerUid);
    ASSERT_EQ(i.packageName, i2.packageName);
    ASSERT_EQ(i.inputFeatures, i2.inputFeatures);
    ASSERT_EQ(i.displayId, i2.displayId);
    ASSERT_EQ(i.portalToDisplayId, i2.portalToDisplayId);
    ASSERT_EQ(i.replaceTouchableRegionWithCrop, i2.replaceTouchableRegionWithCrop);
    ASSERT_EQ(i.touchableRegionCropHandle, i2.touchableRegionCropHandle);
    ASSERT_EQ(i.applicationInfo, i2.applicationInfo);
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
