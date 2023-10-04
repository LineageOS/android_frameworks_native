/*
 * Copyright 2023 The Android Open Source Project
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

#include <errno.h>
#include <sched.h>

#include <android/gui/ISurfaceComposer.h>
#include <android/gui/ISurfaceComposerClient.h>
#include <binder/IBinder.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>
#include <gui/ISurfaceComposer.h>

#include <com_android_graphics_surfaceflinger_flags.h>

namespace android::test {
using namespace com::android::graphics::surfaceflinger;

class BinderTest : public ::testing::Test {
protected:
    BinderTest();

    void SetUp() override;

    void getSchedulingPolicy(gui::SchedulingPolicy* outPolicy);
    void getNonAidlSchedulingPolicy(gui::SchedulingPolicy* outPolicy);
    void getClientSchedulingPolicy(gui::SchedulingPolicy* outPolicy);
    void getDisplayEventConnectionSchedulingPolicy(gui::SchedulingPolicy* outPolicy);

private:
    sp<gui::ISurfaceComposer> mISurfaceComposerAidl;
    sp<ISurfaceComposer> mISurfaceComposer;
    sp<gui::ISurfaceComposerClient> mISurfaceComposerClient;
    sp<gui::IDisplayEventConnection> mConnection;
};

BinderTest::BinderTest() {
    const String16 name("SurfaceFlingerAIDL");
    mISurfaceComposerAidl = waitForService<gui::ISurfaceComposer>(String16("SurfaceFlingerAIDL"));
    mISurfaceComposer = waitForService<ISurfaceComposer>(String16("SurfaceFlinger"));
    mISurfaceComposerAidl->createConnection(&mISurfaceComposerClient);
    mISurfaceComposerAidl
            ->createDisplayEventConnection(gui::ISurfaceComposer::VsyncSource::eVsyncSourceApp,
                                           gui::ISurfaceComposer::EventRegistration(0), {},
                                           &mConnection);
}

void BinderTest::SetUp() {
    ASSERT_TRUE(mISurfaceComposerAidl);
    ASSERT_TRUE(mISurfaceComposer);
    ASSERT_TRUE(mISurfaceComposerClient);
    ASSERT_TRUE(mConnection);
}

void BinderTest::getSchedulingPolicy(gui::SchedulingPolicy* outPolicy) {
    const auto status = mISurfaceComposerAidl->getSchedulingPolicy(outPolicy);
    ASSERT_TRUE(status.isOk());
}

void BinderTest::getNonAidlSchedulingPolicy(gui::SchedulingPolicy* outPolicy) {
    Parcel data, reply;
    const status_t status =
            IInterface::asBinder(mISurfaceComposer)
                    ->transact(BnSurfaceComposer::GET_SCHEDULING_POLICY, data, &reply);
    ASSERT_EQ(OK, status);

    outPolicy->policy = reply.readInt32();
    outPolicy->priority = reply.readInt32();
}

void BinderTest::getClientSchedulingPolicy(gui::SchedulingPolicy* outPolicy) {
    const auto status = mISurfaceComposerClient->getSchedulingPolicy(outPolicy);
    ASSERT_TRUE(status.isOk());
}

void BinderTest::getDisplayEventConnectionSchedulingPolicy(gui::SchedulingPolicy* outPolicy) {
    const auto status = mConnection->getSchedulingPolicy(outPolicy);
    ASSERT_TRUE(status.isOk());
}

TEST_F(BinderTest, SchedulingPolicy) {
    if (!flags::misc1()) GTEST_SKIP();

    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    gui::SchedulingPolicy sfPolicy;
    ASSERT_NO_FATAL_FAILURE(getSchedulingPolicy(&sfPolicy));

    ASSERT_EQ(policy, sfPolicy.policy & (~SCHED_RESET_ON_FORK));
    ASSERT_EQ(priority, sfPolicy.priority);
}

TEST_F(BinderTest, NonAidlSchedulingPolicy) {
    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    gui::SchedulingPolicy sfPolicy;
    ASSERT_NO_FATAL_FAILURE(getNonAidlSchedulingPolicy(&sfPolicy));

    ASSERT_EQ(policy, sfPolicy.policy & (~SCHED_RESET_ON_FORK));
    ASSERT_EQ(priority, sfPolicy.priority);
}

TEST_F(BinderTest, ClientSchedulingPolicy) {
    if (!flags::misc1()) GTEST_SKIP();

    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    gui::SchedulingPolicy sfPolicy;
    ASSERT_NO_FATAL_FAILURE(getClientSchedulingPolicy(&sfPolicy));

    ASSERT_EQ(policy, sfPolicy.policy & (~SCHED_RESET_ON_FORK));
    ASSERT_EQ(priority, sfPolicy.priority);
}

TEST_F(BinderTest, DisplayEventConnectionSchedulingPolicy) {
    if (!flags::misc1()) GTEST_SKIP();

    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    gui::SchedulingPolicy sfPolicy;
    ASSERT_NO_FATAL_FAILURE(getDisplayEventConnectionSchedulingPolicy(&sfPolicy));

    ASSERT_EQ(policy, sfPolicy.policy & (~SCHED_RESET_ON_FORK));
    ASSERT_EQ(priority, sfPolicy.priority);
}

class BinderTestRtCaller : public BinderTest {
protected:
    void SetUp() override;
    void TearDown() override;

private:
    int mOrigPolicy;
    int mOrigPriority;
};

void BinderTestRtCaller::SetUp() {
    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    mOrigPolicy = sched_getscheduler(0);
    struct sched_param origSchedParam;
    ASSERT_GE(0, sched_getparam(0, &origSchedParam)) << "errno: " << strerror(errno);
    mOrigPriority = origSchedParam.sched_priority;

    struct sched_param param;
    param.sched_priority = priority;
    ASSERT_GE(0, sched_setscheduler(0, policy, &param)) << "errno: " << strerror(errno);
}

void BinderTestRtCaller::TearDown() {
    struct sched_param origSchedParam;
    origSchedParam.sched_priority = mOrigPriority;
    ASSERT_GE(0, sched_setscheduler(0, mOrigPolicy, &origSchedParam))
            << "errno: " << strerror(errno);
}

TEST_F(BinderTestRtCaller, SchedulingPolicy) {
    if (!flags::misc1()) GTEST_SKIP();

    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    gui::SchedulingPolicy sfPolicy;
    ASSERT_NO_FATAL_FAILURE(getSchedulingPolicy(&sfPolicy));

    ASSERT_EQ(policy, sfPolicy.policy & (~SCHED_RESET_ON_FORK));
    ASSERT_EQ(priority, sfPolicy.priority);
}

TEST_F(BinderTestRtCaller, NonAidlSchedulingPolicy) {
    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    gui::SchedulingPolicy sfPolicy;
    ASSERT_NO_FATAL_FAILURE(getNonAidlSchedulingPolicy(&sfPolicy));

    ASSERT_EQ(policy, sfPolicy.policy & (~SCHED_RESET_ON_FORK));
    ASSERT_EQ(priority, sfPolicy.priority);
}

TEST_F(BinderTestRtCaller, ClientSchedulingPolicy) {
    if (!flags::misc1()) GTEST_SKIP();

    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    gui::SchedulingPolicy sfPolicy;
    ASSERT_NO_FATAL_FAILURE(getClientSchedulingPolicy(&sfPolicy));

    ASSERT_EQ(policy, sfPolicy.policy & (~SCHED_RESET_ON_FORK));
    ASSERT_EQ(priority, sfPolicy.priority);
}

TEST_F(BinderTestRtCaller, DisplayEventConnectionSchedulingPolicy) {
    if (!flags::misc1()) GTEST_SKIP();

    const int policy = SCHED_FIFO;
    const int priority = sched_get_priority_min(policy);

    gui::SchedulingPolicy sfPolicy;
    ASSERT_NO_FATAL_FAILURE(getDisplayEventConnectionSchedulingPolicy(&sfPolicy));

    ASSERT_EQ(policy, sfPolicy.policy & (~SCHED_RESET_ON_FORK));
    ASSERT_EQ(priority, sfPolicy.priority);
}

} // namespace android::test
