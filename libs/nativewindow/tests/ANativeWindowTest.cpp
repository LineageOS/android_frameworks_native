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

class TestableSurface final : public Surface {
public:
    explicit TestableSurface(const sp<IGraphicBufferProducer>& bufferProducer)
          : Surface(bufferProducer) {}

    // Exposes the internal last dequeue duration that's stored on the Surface.
    nsecs_t getLastDequeueDuration() const { return mLastDequeueDuration; }

    // Exposes the internal last queue duration that's stored on the Surface.
    nsecs_t getLastQueueDuration() const { return mLastQueueDuration; }

    // Exposes the internal last dequeue start time that's stored on the Surface.
    nsecs_t getLastDequeueStartTime() const { return mLastDequeueStartTime; }
};

class ANativeWindowTest : public ::testing::Test {
protected:
    void SetUp() override {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGV("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());
        BufferQueue::createBufferQueue(&mProducer, &mConsumer);
        mItemConsumer = new BufferItemConsumer(mConsumer, GRALLOC_USAGE_SW_READ_OFTEN);
        mWindow = new TestableSurface(mProducer);
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

    sp<TestableSurface> mWindow;
};

TEST_F(ANativeWindowTest, getLastDequeueDuration_noDequeue_returnsZero) {
    int result = ANativeWindow_getLastDequeueDuration(mWindow.get());
    EXPECT_EQ(0, result);
    EXPECT_EQ(0, mWindow->getLastDequeueDuration());
}

TEST_F(ANativeWindowTest, getLastDequeueDuration_withDequeue_returnsTime) {
    ANativeWindowBuffer* buffer;
    int fd;
    int result = ANativeWindow_dequeueBuffer(mWindow.get(), &buffer, &fd);
    close(fd);
    EXPECT_EQ(0, result);

    result = ANativeWindow_getLastDequeueDuration(mWindow.get());
    EXPECT_GT(result, 0);
    EXPECT_EQ(result, mWindow->getLastDequeueDuration());
}

TEST_F(ANativeWindowTest, getLastQueueDuration_noDequeue_returnsZero) {
    int result = ANativeWindow_getLastQueueDuration(mWindow.get());
    EXPECT_EQ(0, result);
    EXPECT_EQ(0, mWindow->getLastQueueDuration());
}

TEST_F(ANativeWindowTest, getLastQueueDuration_noQueue_returnsZero) {
    ANativeWindowBuffer* buffer;
    int fd;
    int result = ANativeWindow_dequeueBuffer(mWindow.get(), &buffer, &fd);
    close(fd);
    EXPECT_EQ(0, result);

    result = ANativeWindow_getLastQueueDuration(mWindow.get());
    EXPECT_EQ(result, 0);
    EXPECT_EQ(result, mWindow->getLastQueueDuration());
}

TEST_F(ANativeWindowTest, getLastQueueDuration_withQueue_returnsTime) {
    ANativeWindowBuffer* buffer;
    int fd;
    int result = ANativeWindow_dequeueBuffer(mWindow.get(), &buffer, &fd);
    close(fd);
    EXPECT_EQ(0, result);

    result = ANativeWindow_queueBuffer(mWindow.get(), buffer, 0);

    result = ANativeWindow_getLastQueueDuration(mWindow.get());
    EXPECT_GT(result, 0);
    EXPECT_EQ(result, mWindow->getLastQueueDuration());
}

TEST_F(ANativeWindowTest, getLastDequeueStartTime_noDequeue_returnsZero) {
    int64_t result = ANativeWindow_getLastDequeueStartTime(mWindow.get());
    EXPECT_EQ(0, result);
    EXPECT_EQ(0, mWindow->getLastQueueDuration());
}

TEST_F(ANativeWindowTest, getLastDequeueStartTime_withDequeue_returnsTime) {
    ANativeWindowBuffer* buffer;
    int fd;
    int dequeueResult = ANativeWindow_dequeueBuffer(mWindow.get(), &buffer, &fd);
    close(fd);
    EXPECT_EQ(0, dequeueResult);

    int64_t result = ANativeWindow_getLastDequeueStartTime(mWindow.get());
    EXPECT_GT(result, 0);
    EXPECT_EQ(result, mWindow->getLastDequeueStartTime());
}

TEST_F(ANativeWindowTest, setDequeueTimeout_causesDequeueTimeout) {
    nsecs_t timeout = milliseconds_to_nanoseconds(100);
    int result = ANativeWindow_setDequeueTimeout(mWindow.get(), timeout);
    EXPECT_EQ(0, result);

    // The two dequeues should not timeout...
    ANativeWindowBuffer* buffer;
    int fd;
    int dequeueResult = ANativeWindow_dequeueBuffer(mWindow.get(), &buffer, &fd);
    close(fd);
    EXPECT_EQ(0, dequeueResult);
    int queueResult = ANativeWindow_queueBuffer(mWindow.get(), buffer, -1);
    EXPECT_EQ(0, queueResult);
    dequeueResult = ANativeWindow_dequeueBuffer(mWindow.get(), &buffer, &fd);
    close(fd);
    EXPECT_EQ(0, dequeueResult);
    queueResult = ANativeWindow_queueBuffer(mWindow.get(), buffer, -1);
    EXPECT_EQ(0, queueResult);

    // ...but the third one should since the queue depth is too deep.
    nsecs_t start = systemTime(SYSTEM_TIME_MONOTONIC);
    dequeueResult = ANativeWindow_dequeueBuffer(mWindow.get(), &buffer, &fd);
    nsecs_t end = systemTime(SYSTEM_TIME_MONOTONIC);
    close(fd);
    EXPECT_EQ(TIMED_OUT, dequeueResult);
    EXPECT_GE(end - start, timeout);
}
