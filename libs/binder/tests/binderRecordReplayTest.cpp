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

TEST(BinderClearBuf, RecordReplayRepeatInt) {
    // get the remote service
    sp<IBinder> binder = defaultServiceManager()->getService(kServerName);
    ASSERT_NE(nullptr, binder);
    sp<IBinderRecordReplayTest> iface = interface_cast<IBinderRecordReplayTest>(binder);
    sp<BpBinder> bpBinder = binder->remoteBinder();
    ASSERT_NE(nullptr, bpBinder);

    base::unique_fd fd(
            open("/data/local/tmp/binderRecordReplayTest.rec", O_RDWR | O_CREAT | O_CLOEXEC, 0666));
    ASSERT_TRUE(fd.ok());

    // record a transaction
    bpBinder->startRecordingBinder(fd);
    EXPECT_TRUE(iface->setInt(3).isOk());
    bpBinder->stopRecordingBinder();

    // test transaction does the thing we expect it to do
    int output;
    EXPECT_TRUE(iface->getInt(&output).isOk());
    EXPECT_EQ(output, 3);

    // write over the existing state
    EXPECT_TRUE(iface->setInt(5).isOk());
    EXPECT_TRUE(iface->getInt(&output).isOk());
    EXPECT_EQ(output, 5);

    // replay transaction
    ASSERT_EQ(0, lseek(fd.get(), 0, SEEK_SET));
    std::optional<RecordedTransaction> transaction = RecordedTransaction::fromFile(fd);
    ASSERT_NE(transaction, std::nullopt);

    // TODO: move logic to replay RecordedTransaction into RecordedTransaction
    Parcel data;
    data.setData(transaction->getDataParcel().data(), transaction->getDataParcel().dataSize());
    status_t status = binder->remoteBinder()->transact(transaction->getCode(), data, nullptr,
                                                       transaction->getFlags());

    // make sure recording does the thing we expect it to do
    EXPECT_EQ(OK, status);
    EXPECT_TRUE(iface->getInt(&output).isOk());
    EXPECT_EQ(output, 3);

    // TODO: we should also make sure we can convert the recording to a fuzzer
    // corpus entry, and we will be able to replay it in the same way
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
