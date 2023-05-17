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

#include "parcelables/SingleDataParcelable.h"

using namespace android;
using android::binder::Status;
using android::binder::debug::RecordedTransaction;
using parcelables::SingleDataParcelable;

const String16 kServerName = String16("binderRecordReplay");

#define GENERATE_GETTER_SETTER_PRIMITIVE(name, T) \
    Status set##name(T input) {                   \
        m##name = input;                          \
        return Status::ok();                      \
    }                                             \
                                                  \
    Status get##name(T* output) {                 \
        *output = m##name;                        \
        return Status::ok();                      \
    }                                             \
    T m##name

#define GENERATE_GETTER_SETTER(name, T) \
    Status set##name(const T& input) {  \
        m##name = input;                \
        return Status::ok();            \
    }                                   \
                                        \
    Status get##name(T* output) {       \
        *output = m##name;              \
        return Status::ok();            \
    }                                   \
    T m##name

class MyRecordReplay : public BnBinderRecordReplayTest {
public:
    GENERATE_GETTER_SETTER_PRIMITIVE(Boolean, bool);
    GENERATE_GETTER_SETTER_PRIMITIVE(Byte, int8_t);
    GENERATE_GETTER_SETTER_PRIMITIVE(Int, int);
    GENERATE_GETTER_SETTER_PRIMITIVE(Char, char16_t);
    GENERATE_GETTER_SETTER_PRIMITIVE(Long, int64_t);
    GENERATE_GETTER_SETTER_PRIMITIVE(Float, float);
    GENERATE_GETTER_SETTER_PRIMITIVE(Double, double);

    GENERATE_GETTER_SETTER(String, String16);
    GENERATE_GETTER_SETTER(SingleDataParcelable, SingleDataParcelable);

    GENERATE_GETTER_SETTER(BooleanArray, std::vector<bool>);
    GENERATE_GETTER_SETTER(ByteArray, std::vector<uint8_t>);
    GENERATE_GETTER_SETTER(IntArray, std::vector<int>);
    GENERATE_GETTER_SETTER(CharArray, std::vector<char16_t>);
    GENERATE_GETTER_SETTER(LongArray, std::vector<int64_t>);
    GENERATE_GETTER_SETTER(FloatArray, std::vector<float>);
    GENERATE_GETTER_SETTER(DoubleArray, std::vector<double>);
    GENERATE_GETTER_SETTER(StringArray, std::vector<::android::String16>);
    GENERATE_GETTER_SETTER(SingleDataParcelableArray, std::vector<SingleDataParcelable>);
};

class BinderRecordReplayTest : public ::testing::Test {
public:
    void SetUp() override {
        // get the remote service
        auto binder = defaultServiceManager()->getService(kServerName);
        ASSERT_NE(nullptr, binder);
        mInterface = interface_cast<IBinderRecordReplayTest>(binder);
        mBpBinder = binder->remoteBinder();
        ASSERT_NE(nullptr, mBpBinder);
    }

    template <typename T, typename U>
    void recordReplay(Status (IBinderRecordReplayTest::*set)(T), U recordedValue,
                      Status (IBinderRecordReplayTest::*get)(U*), U changedValue) {
        base::unique_fd fd(open("/data/local/tmp/binderRecordReplayTest.rec",
                                O_RDWR | O_CREAT | O_CLOEXEC, 0666));
        ASSERT_TRUE(fd.ok());

        // record a transaction
        mBpBinder->startRecordingBinder(fd);
        auto status = (*mInterface.*set)(recordedValue);
        EXPECT_TRUE(status.isOk());
        mBpBinder->stopRecordingBinder();

        // test transaction does the thing we expect it to do
        U output;
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
        auto result =
                mBpBinder->transact(transaction->getCode(), data, nullptr, transaction->getFlags());

        // make sure recording does the thing we expect it to do
        EXPECT_EQ(OK, result);

        status = (*mInterface.*get)(&output);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(output, recordedValue);
    }

private:
    sp<BpBinder> mBpBinder;
    sp<IBinderRecordReplayTest> mInterface;
};

TEST_F(BinderRecordReplayTest, ReplayByte) {
    recordReplay(&IBinderRecordReplayTest::setByte, int8_t{122}, &IBinderRecordReplayTest::getByte,
                 int8_t{90});
}

TEST_F(BinderRecordReplayTest, ReplayBoolean) {
    recordReplay(&IBinderRecordReplayTest::setBoolean, true, &IBinderRecordReplayTest::getBoolean,
                 false);
}

TEST_F(BinderRecordReplayTest, ReplayChar) {
    recordReplay(&IBinderRecordReplayTest::setChar, char16_t{'G'},
                 &IBinderRecordReplayTest::getChar, char16_t{'K'});
}

TEST_F(BinderRecordReplayTest, ReplayInt) {
    recordReplay(&IBinderRecordReplayTest::setInt, 3, &IBinderRecordReplayTest::getInt, 5);
}

TEST_F(BinderRecordReplayTest, ReplayFloat) {
    recordReplay(&IBinderRecordReplayTest::setFloat, 1.1f, &IBinderRecordReplayTest::getFloat,
                 22.0f);
}

TEST_F(BinderRecordReplayTest, ReplayLong) {
    recordReplay(&IBinderRecordReplayTest::setLong, int64_t{1LL << 55},
                 &IBinderRecordReplayTest::getLong, int64_t{1LL << 12});
}

TEST_F(BinderRecordReplayTest, ReplayDouble) {
    recordReplay(&IBinderRecordReplayTest::setDouble, 0.00, &IBinderRecordReplayTest::getDouble,
                 1.11);
}

TEST_F(BinderRecordReplayTest, ReplayString) {
    const ::android::String16& input1 = String16("This is saved string");
    const ::android::String16& input2 = String16("This is changed string");
    recordReplay(&IBinderRecordReplayTest::setString, input1, &IBinderRecordReplayTest::getString,
                 input2);
}

TEST_F(BinderRecordReplayTest, ReplaySingleDataParcelable) {
    SingleDataParcelable saved, changed;
    saved.data = 3;
    changed.data = 5;
    recordReplay(&IBinderRecordReplayTest::setSingleDataParcelable, saved,
                 &IBinderRecordReplayTest::getSingleDataParcelable, changed);
}

TEST_F(BinderRecordReplayTest, ReplayByteArray) {
    std::vector<uint8_t> savedArray = {uint8_t{255}, uint8_t{0}, uint8_t{127}};
    std::vector<uint8_t> changedArray = {uint8_t{2}, uint8_t{7}, uint8_t{117}};
    recordReplay(&IBinderRecordReplayTest::setByteArray, savedArray,
                 &IBinderRecordReplayTest::getByteArray, changedArray);
}

TEST_F(BinderRecordReplayTest, ReplayBooleanArray) {
    std::vector<bool> savedArray = {true, false, true};
    std::vector<bool> changedArray = {false, true, false};
    recordReplay(&IBinderRecordReplayTest::setBooleanArray, savedArray,
                 &IBinderRecordReplayTest::getBooleanArray, changedArray);
}

TEST_F(BinderRecordReplayTest, ReplayCharArray) {
    std::vector<char16_t> savedArray = {char16_t{'G'}, char16_t{'L'}, char16_t{'K'}, char16_t{'T'}};
    std::vector<char16_t> changedArray = {char16_t{'X'}, char16_t{'Y'}, char16_t{'Z'}};
    recordReplay(&IBinderRecordReplayTest::setCharArray, savedArray,
                 &IBinderRecordReplayTest::getCharArray, changedArray);
}

TEST_F(BinderRecordReplayTest, ReplayIntArray) {
    std::vector<int> savedArray = {12, 45, 178};
    std::vector<int> changedArray = {32, 14, 78, 1899};
    recordReplay(&IBinderRecordReplayTest::setIntArray, savedArray,
                 &IBinderRecordReplayTest::getIntArray, changedArray);
}

TEST_F(BinderRecordReplayTest, ReplayFloatArray) {
    std::vector<float> savedArray = {12.14f, 45.56f, 123.178f};
    std::vector<float> changedArray = {0.00f, 14.0f, 718.1f, 1899.122f, 3268.123f};
    recordReplay(&IBinderRecordReplayTest::setFloatArray, savedArray,
                 &IBinderRecordReplayTest::getFloatArray, changedArray);
}

TEST_F(BinderRecordReplayTest, ReplayLongArray) {
    std::vector<int64_t> savedArray = {int64_t{1LL << 11}, int64_t{1LL << 55}, int64_t{1LL << 45}};
    std::vector<int64_t> changedArray = {int64_t{1LL << 1}, int64_t{1LL << 21}, int64_t{1LL << 33},
                                         int64_t{1LL << 62}};
    recordReplay(&IBinderRecordReplayTest::setLongArray, savedArray,
                 &IBinderRecordReplayTest::getLongArray, changedArray);
}

TEST_F(BinderRecordReplayTest, ReplayDoubleArray) {
    std::vector<double> savedArray = {12.1412313, 45.561232, 123.1781111};
    std::vector<double> changedArray = {0.00111, 14.32130, 712312318.19, 1899212.122,
                                        322168.122123};
    recordReplay(&IBinderRecordReplayTest::setDoubleArray, savedArray,
                 &IBinderRecordReplayTest::getDoubleArray, changedArray);
}

TEST_F(BinderRecordReplayTest, ReplayStringArray) {
    std::vector<String16> savedArray = {String16("This is saved value"), String16(),
                                        String16("\0\0", 2), String16("\xF3\x01\xAC\xAD\x21\xAF")};

    std::vector<String16> changedArray = {String16("This is changed value"),
                                          String16("\xF0\x90\x90\xB7\xE2\x82\xAC")};
    recordReplay(&IBinderRecordReplayTest::setStringArray, savedArray,
                 &IBinderRecordReplayTest::getStringArray, changedArray);
}

TEST_F(BinderRecordReplayTest, ReplaySingleDataParcelableArray) {
    SingleDataParcelable s1, s2, s3, s4, s5;
    s1.data = 5213;
    s2.data = 1512;
    s3.data = 4233;
    s4.data = 123124;
    s5.data = 0;
    std::vector<SingleDataParcelable> saved = {s1, s2, s3};
    std::vector<SingleDataParcelable> changed = {s4, s5};

    recordReplay(&IBinderRecordReplayTest::setSingleDataParcelableArray, saved,
                 &IBinderRecordReplayTest::getSingleDataParcelableArray, changed);
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
