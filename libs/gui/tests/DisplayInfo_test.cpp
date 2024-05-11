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

#include <gtest/gtest.h>

#include <binder/Parcel.h>

#include <gui/DisplayInfo.h>

namespace android {

using gui::DisplayInfo;

namespace test {

TEST(DisplayInfo, Parcelling) {
    DisplayInfo info;
    info.displayId = ui::LogicalDisplayId{42};
    info.logicalWidth = 99;
    info.logicalHeight = 78;
    info.transform.set({0.4, -1, 100, 0.5, 0, 40, 0, 0, 1});

    Parcel p;
    info.writeToParcel(&p);
    p.setDataPosition(0);

    DisplayInfo info2;
    info2.readFromParcel(&p);
    ASSERT_EQ(info.displayId, info2.displayId);
    ASSERT_EQ(info.logicalWidth, info2.logicalWidth);
    ASSERT_EQ(info.logicalHeight, info2.logicalHeight);
    ASSERT_EQ(info.transform, info2.transform);
}

} // namespace test
} // namespace android
