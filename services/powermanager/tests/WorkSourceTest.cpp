/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <optional>
#define LOG_TAG "PowerHalLoaderTest"

#include <android-base/logging.h>
#include <android/WorkSource.h>
#include <binder/Parcel.h>
#include <gtest/gtest.h>

#include <future>

using namespace android;
using namespace testing;

TEST(WorkSourceTest, Parcel) {
    std::vector<int32_t> uids = {1, 2};
    using Names = std::vector<std::optional<String16>>;
    std::optional<Names> names = std::make_optional<Names>({std::make_optional(String16("name"))});
    os::WorkSource ws{uids, names};

    Parcel p;
    ws.writeToParcel(&p);
    p.setDataPosition(0);

    os::WorkSource otherWs;
    otherWs.readFromParcel(&p);

    EXPECT_EQ(ws, otherWs);
    EXPECT_EQ(uids, otherWs.getUids());
    EXPECT_EQ(names, otherWs.getNames());
}
