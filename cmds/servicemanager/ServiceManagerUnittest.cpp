/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "NameUtil.h"

namespace android {

TEST(ServiceManager, NativeName) {
    NativeName nname;
    EXPECT_TRUE(NativeName::fill("mapper/default", &nname));
    EXPECT_EQ("mapper", nname.package);
    EXPECT_EQ("default", nname.instance);
}

TEST(ServiceManager, NativeName_Malformed) {
    NativeName nname;
    EXPECT_FALSE(NativeName::fill("mapper", &nname));
    EXPECT_FALSE(NativeName::fill("mapper/", &nname));
    EXPECT_FALSE(NativeName::fill("/default", &nname));
    EXPECT_FALSE(NativeName::fill("mapper/default/0", &nname));
    EXPECT_FALSE(NativeName::fill("aidl.like.IType/default", &nname));
}

} // namespace android
