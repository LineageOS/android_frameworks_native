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

#include <android/binder_manager.h>
#include <binder/IServiceManager.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <utils/String16.h>
#include <utils/String8.h>
#include <utils/StrongPointer.h>

#include <optional>

#include "fakeservicemanager/FakeServiceManager.h"

using android::FakeServiceManager;
using android::setDefaultServiceManager;
using android::sp;
using android::String16;
using android::String8;
using testing::_;
using testing::Eq;
using testing::Mock;
using testing::NiceMock;
using testing::Optional;
using testing::Return;

struct MockServiceManager : FakeServiceManager {
    MOCK_METHOD1(updatableViaApex, std::optional<String16>(const String16&));
};

struct AServiceManager : testing::Test {
    static sp<MockServiceManager> mockSM;

    static void InitMock() {
        mockSM = new NiceMock<MockServiceManager>;
        setDefaultServiceManager(mockSM);
    }

    void TearDown() override { Mock::VerifyAndClear(mockSM.get()); }

    void ExpectUpdatableViaApexReturns(std::optional<String16> apexName) {
        EXPECT_CALL(*mockSM, updatableViaApex(_)).WillRepeatedly(Return(apexName));
    }
};

sp<MockServiceManager> AServiceManager::mockSM;

TEST_F(AServiceManager, isUpdatableViaApex) {
    auto apexFoo = String16("com.android.hardware.foo");
    ExpectUpdatableViaApexReturns(apexFoo);

    bool isUpdatable = AServiceManager_isUpdatableViaApex("android.hardware.foo.IFoo/default");
    EXPECT_EQ(isUpdatable, true);
}

TEST_F(AServiceManager, isUpdatableViaApex_Not) {
    ExpectUpdatableViaApexReturns(std::nullopt);

    bool isUpdatable = AServiceManager_isUpdatableViaApex("android.hardware.foo.IFoo/default");
    EXPECT_EQ(isUpdatable, false);
}

void getUpdatableApexNameCallback(const char* apexName, void* context) {
    *(static_cast<std::optional<std::string>*>(context)) = apexName;
}

TEST_F(AServiceManager, getUpdatableApexName) {
    auto apexFoo = String16("com.android.hardware.foo");
    ExpectUpdatableViaApexReturns(apexFoo);

    std::optional<std::string> result;
    AServiceManager_getUpdatableApexName("android.hardware.foo.IFoo/default", &result,
                                         getUpdatableApexNameCallback);
    EXPECT_THAT(result, Optional(std::string(String8(apexFoo))));
}

TEST_F(AServiceManager, getUpdatableApexName_Null) {
    ExpectUpdatableViaApexReturns(std::nullopt);

    std::optional<std::string> result;
    AServiceManager_getUpdatableApexName("android.hardware.foo.IFoo/default", &result,
                                         getUpdatableApexNameCallback);
    EXPECT_THAT(result, Eq(std::nullopt));
}

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    AServiceManager::InitMock();
    return RUN_ALL_TESTS();
}
