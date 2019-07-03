/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <binder/ProcessState.h>
#include <cutils/android_filesystem_config.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "Access.h"
#include "ServiceManager.h"

using android::sp;
using android::Access;
using android::IBinder;
using android::ServiceManager;
using android::os::IServiceManager;
using testing::_;
using testing::ElementsAre;
using testing::NiceMock;
using testing::Return;

static sp<IBinder> getBinder() {
    // It doesn't matter what remote binder it is, we just need one so that linkToDeath will work.
    // The context manager (servicemanager) is easy to get and is in another process.
    return android::ProcessState::self()->getContextObject(nullptr);
}

class MockAccess : public Access {
public:
    MOCK_METHOD1(getCallingContext, CallingContext(const std::string& name));
    MOCK_METHOD1(canAdd, bool(const CallingContext&));
    MOCK_METHOD1(canFind, bool(const CallingContext&));
    MOCK_METHOD1(canList, bool(const CallingContext&));
};

static sp<ServiceManager> getPermissiveServiceManager() {
    std::unique_ptr<MockAccess> access = std::make_unique<NiceMock<MockAccess>>();

    ON_CALL(*access, getCallingContext(_)).WillByDefault(Return(Access::CallingContext{}));
    ON_CALL(*access, canAdd(_)).WillByDefault(Return(true));
    ON_CALL(*access, canFind(_)).WillByDefault(Return(true));
    ON_CALL(*access, canList(_)).WillByDefault(Return(true));

    sp<ServiceManager> sm = new ServiceManager(std::move(access));
    return sm;
}

TEST(AddService, HappyHappy) {
    auto sm = getPermissiveServiceManager();
    EXPECT_TRUE(sm->addService("foo", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
}

TEST(AddService, EmptyNameDisallowed) {
    auto sm = getPermissiveServiceManager();
    EXPECT_FALSE(sm->addService("", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
}

TEST(AddService, JustShortEnoughServiceNameHappy) {
    auto sm = getPermissiveServiceManager();
    EXPECT_TRUE(sm->addService(std::string(127, 'a'), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
}

TEST(AddService, TooLongNameDisallowed) {
    auto sm = getPermissiveServiceManager();
    EXPECT_FALSE(sm->addService(std::string(128, 'a'), getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
}

TEST(AddService, AddNullServiceDisallowed) {
    auto sm = getPermissiveServiceManager();
    EXPECT_FALSE(sm->addService("foo", nullptr, false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
}

TEST(AddService, AddDisallowedFromApp) {
    for (uid_t uid : { AID_APP_START, AID_APP_START + 1, AID_APP_END }) {
        std::unique_ptr<MockAccess> access = std::make_unique<NiceMock<MockAccess>>();
        EXPECT_CALL(*access, getCallingContext(_)).WillOnce(Return(Access::CallingContext{
            .debugPid = 1337,
            .uid = uid,
        }));
        EXPECT_CALL(*access, canAdd(_)).Times(0);
        sp<ServiceManager> sm = new ServiceManager(std::move(access));

        EXPECT_FALSE(sm->addService("foo", getBinder(), false /*allowIsolated*/,
            IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
    }

}

TEST(AddService, HappyOverExistingService) {
    auto sm = getPermissiveServiceManager();
    EXPECT_TRUE(sm->addService("foo", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
    EXPECT_TRUE(sm->addService("foo", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
}

TEST(AddService, NoPermissions) {
    std::unique_ptr<MockAccess> access = std::make_unique<NiceMock<MockAccess>>();

    EXPECT_CALL(*access, getCallingContext(_)).WillOnce(Return(Access::CallingContext{}));
    EXPECT_CALL(*access, canAdd(_)).WillOnce(Return(false));

    sp<ServiceManager> sm = new ServiceManager(std::move(access));

    EXPECT_FALSE(sm->addService("foo", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
}

TEST(GetService, HappyHappy) {
    auto sm = getPermissiveServiceManager();
    EXPECT_TRUE(sm->addService("foo", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());

    sp<IBinder> out;
    EXPECT_TRUE(sm->getService("foo", &out).isOk());
    EXPECT_EQ(getBinder(), out);
}

TEST(GetService, NonExistant) {
    auto sm = getPermissiveServiceManager();

    sp<IBinder> out;
    EXPECT_TRUE(sm->getService("foo", &out).isOk());
    EXPECT_EQ(nullptr, out.get());
}

TEST(GetService, NoPermissionsForGettingService) {
    std::unique_ptr<MockAccess> access = std::make_unique<NiceMock<MockAccess>>();

    EXPECT_CALL(*access, getCallingContext(_)).WillRepeatedly(Return(Access::CallingContext{}));
    EXPECT_CALL(*access, canAdd(_)).WillOnce(Return(true));
    EXPECT_CALL(*access, canFind(_)).WillOnce(Return(false));

    sp<ServiceManager> sm = new ServiceManager(std::move(access));

    EXPECT_TRUE(sm->addService("foo", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());

    sp<IBinder> out;
    // returns nullptr but has OK status for legacy compatibility
    EXPECT_TRUE(sm->getService("foo", &out).isOk());
    EXPECT_EQ(nullptr, out.get());
}

TEST(GetService, AllowedFromIsolated) {
    std::unique_ptr<MockAccess> access = std::make_unique<NiceMock<MockAccess>>();

    EXPECT_CALL(*access, getCallingContext(_))
        // something adds it
        .WillOnce(Return(Access::CallingContext{}))
        // next call is from isolated app
        .WillOnce(Return(Access::CallingContext{
            .uid = AID_ISOLATED_START,
        }));
    EXPECT_CALL(*access, canAdd(_)).WillOnce(Return(true));
    EXPECT_CALL(*access, canFind(_)).WillOnce(Return(true));

    sp<ServiceManager> sm = new ServiceManager(std::move(access));

    EXPECT_TRUE(sm->addService("foo", getBinder(), true /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());

    sp<IBinder> out;
    EXPECT_TRUE(sm->getService("foo", &out).isOk());
    EXPECT_EQ(getBinder(), out.get());
}

TEST(GetService, NotAllowedFromIsolated) {
    std::unique_ptr<MockAccess> access = std::make_unique<NiceMock<MockAccess>>();

    EXPECT_CALL(*access, getCallingContext(_))
        // something adds it
        .WillOnce(Return(Access::CallingContext{}))
        // next call is from isolated app
        .WillOnce(Return(Access::CallingContext{
            .uid = AID_ISOLATED_START,
        }));
    EXPECT_CALL(*access, canAdd(_)).WillOnce(Return(true));

    // TODO(b/136023468): when security check is first, this should be called first
    // EXPECT_CALL(*access, canFind(_)).WillOnce(Return(true));

    sp<ServiceManager> sm = new ServiceManager(std::move(access));

    EXPECT_TRUE(sm->addService("foo", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());

    sp<IBinder> out;
    // returns nullptr but has OK status for legacy compatibility
    EXPECT_TRUE(sm->getService("foo", &out).isOk());
    EXPECT_EQ(nullptr, out.get());
}

TEST(ListServices, NoPermissions) {
    std::unique_ptr<MockAccess> access = std::make_unique<NiceMock<MockAccess>>();

    EXPECT_CALL(*access, getCallingContext(_)).WillOnce(Return(Access::CallingContext{}));
    EXPECT_CALL(*access, canList(_)).WillOnce(Return(false));

    sp<ServiceManager> sm = new ServiceManager(std::move(access));

    std::vector<std::string> out;
    EXPECT_FALSE(sm->listServices(IServiceManager::DUMP_FLAG_PRIORITY_ALL, &out).isOk());
    EXPECT_TRUE(out.empty());
}

TEST(ListServices, AllServices) {
    auto sm = getPermissiveServiceManager();

    EXPECT_TRUE(sm->addService("sd", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
    EXPECT_TRUE(sm->addService("sc", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_NORMAL).isOk());
    EXPECT_TRUE(sm->addService("sb", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_HIGH).isOk());
    EXPECT_TRUE(sm->addService("sa", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_CRITICAL).isOk());

    std::vector<std::string> out;
    EXPECT_TRUE(sm->listServices(IServiceManager::DUMP_FLAG_PRIORITY_ALL, &out).isOk());

    // all there and in the right order
    EXPECT_THAT(out, ElementsAre("sa", "sb", "sc", "sd"));
}

TEST(ListServices, CriticalServices) {
    auto sm = getPermissiveServiceManager();

    EXPECT_TRUE(sm->addService("sd", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT).isOk());
    EXPECT_TRUE(sm->addService("sc", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_NORMAL).isOk());
    EXPECT_TRUE(sm->addService("sb", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_HIGH).isOk());
    EXPECT_TRUE(sm->addService("sa", getBinder(), false /*allowIsolated*/,
        IServiceManager::DUMP_FLAG_PRIORITY_CRITICAL).isOk());

    std::vector<std::string> out;
    EXPECT_TRUE(sm->listServices(IServiceManager::DUMP_FLAG_PRIORITY_CRITICAL, &out).isOk());

    // all there and in the right order
    EXPECT_THAT(out, ElementsAre("sa"));
}
