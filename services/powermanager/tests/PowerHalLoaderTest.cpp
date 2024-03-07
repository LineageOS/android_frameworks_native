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

#define LOG_TAG "PowerHalLoaderTest"

#include <aidl/android/hardware/power/IPower.h>
#include <android/hardware/power/1.1/IPower.h>
#include <gtest/gtest.h>
#include <powermanager/PowerHalLoader.h>

#include <future>

using IPowerV1_0 = android::hardware::power::V1_0::IPower;
using IPowerV1_1 = android::hardware::power::V1_1::IPower;
using IPowerV1_2 = android::hardware::power::V1_2::IPower;
using IPowerV1_3 = android::hardware::power::V1_3::IPower;
using IPowerAidl = aidl::android::hardware::power::IPower;

using namespace android;
using namespace android::power;
using namespace testing;

// -------------------------------------------------------------------------------------------------

template <typename T>
T loadHal();

template <>
std::shared_ptr<IPowerAidl> loadHal<std::shared_ptr<IPowerAidl>>() {
    return PowerHalLoader::loadAidl();
}

template <>
sp<IPowerV1_0> loadHal<sp<IPowerV1_0>>() {
    return PowerHalLoader::loadHidlV1_0();
}

template <>
sp<IPowerV1_1> loadHal<sp<IPowerV1_1>>() {
    return PowerHalLoader::loadHidlV1_1();
}

template <>
sp<IPowerV1_2> loadHal<sp<IPowerV1_2>>() {
    return PowerHalLoader::loadHidlV1_2();
}

template <>
sp<IPowerV1_3> loadHal<sp<IPowerV1_3>>() {
    return PowerHalLoader::loadHidlV1_3();
}

// -------------------------------------------------------------------------------------------------

template <typename T>
class PowerHalLoaderTest : public Test {
public:
    T load() { return ::loadHal<T>(); }
    void unload() { PowerHalLoader::unloadAll(); }
};

// -------------------------------------------------------------------------------------------------
typedef ::testing::Types<std::shared_ptr<IPowerAidl>, sp<IPowerV1_0>, sp<IPowerV1_1>,
                         sp<IPowerV1_2>, sp<IPowerV1_3>>
        PowerHalTypes;
TYPED_TEST_SUITE(PowerHalLoaderTest, PowerHalTypes);

TYPED_TEST(PowerHalLoaderTest, TestLoadsOnlyOnce) {
    TypeParam firstHal = this->load();
    if (firstHal == nullptr) {
        ALOGE("Power HAL not available. Skipping test.");
        return;
    }
    TypeParam secondHal = this->load();
    ASSERT_EQ(firstHal, secondHal);
}

TYPED_TEST(PowerHalLoaderTest, TestUnload) {
    TypeParam firstHal = this->load();
    if (firstHal == nullptr) {
        ALOGE("Power HAL not available. Skipping test.");
        return;
    }
    this->unload();
    TypeParam secondHal = this->load();
    ASSERT_NE(secondHal, nullptr);
    ASSERT_NE(firstHal, secondHal);
}

TYPED_TEST(PowerHalLoaderTest, TestLoadMultiThreadLoadsOnlyOnce) {
    std::vector<std::future<TypeParam>> futures;
    for (int i = 0; i < 10; i++) {
        futures.push_back(
                std::async(std::launch::async, &PowerHalLoaderTest<TypeParam>::load, this));
    }

    futures[0].wait();
    TypeParam firstHal = futures[0].get();
    if (firstHal == nullptr) {
        ALOGE("Power HAL not available. Skipping test.");
        return;
    }

    for (int i = 1; i < 10; i++) {
        futures[i].wait();
        TypeParam currentHal = futures[i].get();
        ASSERT_EQ(firstHal, currentHal);
    }
}
