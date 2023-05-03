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

#include <BnBinderRecordReplayTest.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/RecordedTransaction.h>
#include <gtest/gtest.h>

#include <sys/prctl.h>

using namespace android;
using android::binder::Status;
using android::binder::debug::RecordedTransaction;

const String16 kServerName = String16("binderRecordReplay");

class MyRecordReplay : public BnBinderRecordReplayTest {
public:
    Status setInt(int input) {
        mInt = input;
        return Status::ok();
    }
    Status getInt(int* output) {
        *output = mInt;
        return Status::ok();
    }

private:
    int mInt = 0;
};

class BinderClearBuf : public ::testing::Test {
public:
    void SetUp() override {
        // get the remote service
        mBinder = defaultServiceManager()->getService(kServerName);
        ASSERT_NE(nullptr, mBinder);
        mInterface = interface_cast<IBinderRecordReplayTest>(mBinder);
        mBpBinder = mBinder->remoteBinder();
        ASSERT_NE(nullptr, mBpBinder);
    }

    template <typename T>
    void DoTest(Status (IBinderRecordReplayTest::*set)(T), T recordedValue,
                Status (IBinderRecordReplayTest::*get)(T*), T changedValue) {
        base::unique_fd fd(open("/data/local/tmp/binderRecordReplayTest.rec",
                                O_RDWR | O_CREAT | O_CLOEXEC, 0666));
        ASSERT_TRUE(fd.ok());

        // record a transaction
        mBpBinder->startRecordingBinder(fd);
        auto status = (*mInterface.*set)(recordedValue);
        EXPECT_TRUE(status.isOk());
        mBpBinder->stopRecordingBinder();

        // test transaction does the thing we expect it to do
        T output;
        status = (*mInterface.*get)(&output);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(output, recordedValue);

        // write over the existing state
        status = (*mInterface.*set)(changedValue);
        EXPECT_TRUE(status.isOk());

        status = (*mInterface.*get)(&output);
        EXPECT_TRUE(status.isOk());

        EXPECT_EQ(output, changedValue);

        // replay transaction
        ASSERT_EQ(0, lseek(fd.get(), 0, SEEK_SET));
        std::optional<RecordedTransaction> transaction = RecordedTransaction::fromFile(fd);
        ASSERT_NE(transaction, std::nullopt);

        // TODO: move logic to replay RecordedTransaction into RecordedTransaction
        Parcel data;
        data.setData(transaction->getDataParcel().data(), transaction->getDataParcel().dataSize());
        auto result = mBinder->remoteBinder()->transact(transaction->getCode(), data, nullptr,
                                                        transaction->getFlags());

        // make sure recording does the thing we expect it to do
        EXPECT_EQ(OK, result);

        status = (*mInterface.*get)(&output);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(output, recordedValue);
    }

private:
    sp<IBinder> mBinder;
    sp<BpBinder> mBpBinder;
    sp<IBinderRecordReplayTest> mInterface;
};

TEST_F(BinderClearBuf, RecordReplayRepeatInt) {
    DoTest(&IBinderRecordReplayTest::setInt, 3, &IBinderRecordReplayTest::getInt, 5);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        auto server = sp<MyRecordReplay>::make();
        android::defaultServiceManager()->addService(kServerName, server.get());

        IPCThreadState::self()->joinThreadPool(true);
        exit(1); // should not reach
    }

    // not racey, but getService sleeps for 1s
    usleep(100000);

    return RUN_ALL_TESTS();
}
