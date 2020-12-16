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

#include <binder/Binder.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/IPCThreadState.h>
#include <binderdebug/BinderDebug.h>
#include <gtest/gtest.h>
#include <semaphore.h>
#include <thread>

#include <android/binderdebug/test/BnControl.h>
#include <android/binderdebug/test/IControl.h>

namespace android {
namespace binderdebug {
namespace test {

class Control : public BnControl {
public:
    Control() {sem_init(&s, 1, 0);};
    ::android::binder::Status Continue() override;
    sem_t s;
};

::android::binder::Status Control::Continue() {
    IPCThreadState::self()->flushCommands();
    sem_post(&s);
    return binder::Status::ok();
}

TEST(BinderDebugTests, BinderPid) {
    BinderPidInfo pidInfo;
    const auto& status = getBinderPidInfo(BinderDebugContext::BINDER, getpid(), &pidInfo);
    ASSERT_EQ(status, OK);
    // There should be one referenced PID for servicemanager
    EXPECT_TRUE(!pidInfo.refPids.empty());
}

TEST(BinderDebugTests, BinderThreads) {
    BinderPidInfo pidInfo;
    const auto& status = getBinderPidInfo(BinderDebugContext::BINDER, getpid(), &pidInfo);
    ASSERT_EQ(status, OK);
    EXPECT_TRUE(pidInfo.threadUsage <= pidInfo.threadCount);
    // The second looper thread can sometimes take longer to spawn.
    EXPECT_GE(pidInfo.threadCount, 1);
}

extern "C" {
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Create a child/client process to call into the main process so we can ensure
    // looper thread has been registered before attempting to get the BinderPidInfo
    pid_t pid = fork();
    if (pid == 0) {
        sp<IBinder> binder = android::defaultServiceManager()->getService(String16("binderdebug"));
        sp<IControl> service;
        if (binder != nullptr) {
            service = android::interface_cast<IControl>(binder);
        }
        service->Continue();
        exit(0);
    }
    sp<Control> iface = new Control;
    android::defaultServiceManager()->addService(String16("binderdebug"), iface);
    android::ProcessState::self()->setThreadPoolMaxThreadCount(8);
    ProcessState::self()->startThreadPool();
    sem_wait(&iface->s);

    return RUN_ALL_TESTS();
}
} // extern "C"
} // namespace  test
} // namespace  binderdebug
} // namespace  android
