/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "ANativeWindow_test"
//#define LOG_NDEBUG 0

#include <gtest/gtest.h>
#include <gui/BufferItemConsumer.h>
#include <gui/BufferQueue.h>
#include <gui/Surface.h>
#include <log/log.h>
#include <sync/sync.h>
// We need to use the private system apis since not everything is visible to
// apexes yet.
#include <system/window.h>

using namespace android;

class ANativeWindowTest : public ::testing::Test {
protected:
    void SetUp() override {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGV("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        BufferQueue::createBufferQueue(&mProducer, &mConsumer);
        mItemConsumer = new BufferItemConsumer(mConsumer, GRALLOC_USAGE_SW_READ_OFTEN);
        mWindow = new Surface(mProducer);
        const int success = native_window_api_connect(mWindow.get(), NATIVE_WINDOW_API_CPU);
        EXPECT_EQ(0, success);
    }

    void TearDown() override {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGV("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
        const int success = native_window_api_disconnect(mWindow.get(), NATIVE_WINDOW_API_CPU);
        EXPECT_EQ(0, success);
    }
    sp<IGraphicBufferProducer> mProducer;
    sp<IGraphicBufferConsumer> mConsumer;
    sp<BufferItemConsumer> mItemConsumer;
    sp<ANativeWindow> mWindow;
};

TEST_F(ANativeWindowTest, getLastDequeueDuration_noDequeue_returnsZero) {
    int result = ANativeWindow_getLastDequeueDuration(mWindow.get());
    EXPECT_EQ(0, result);
}

TEST_F(ANativeWindowTest, getLastDequeueDuration_withDequeue_returnsTime) {
    ANativeWindowBuffer* buffer;
    int fd;
    int result = ANativeWindow_dequeueBuffer(mWindow.get(), &buffer, &fd);
    close(fd);
    EXPECT_EQ(0, result);

    result = ANativeWindow_getLastDequeueDuration(mWindow.get());
    EXPECT_GT(result, 0);
}
