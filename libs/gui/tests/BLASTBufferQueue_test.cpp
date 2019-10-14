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

#define LOG_TAG "BLASTBufferQueue_test"

#include <gui/BLASTBufferQueue.h>

#include <gui/SurfaceComposerClient.h>
#include <ui/GraphicBuffer.h>

#include <gtest/gtest.h>

using namespace std::chrono_literals;

namespace android {

const int DEFAULT_WIDTH = 100;
const int DEFAULT_HEIGHT = 100;

using Transaction = SurfaceComposerClient::Transaction;

class BLASTBufferQueueHelper {
public:
    BLASTBufferQueueHelper(const sp<SurfaceControl>& sc, int width, int height) {
        mBlastBufferQueueAdapter = new BLASTBufferQueue(sc, width, height);
    }

    void update(const sp<SurfaceControl>& sc, int width, int height) {
        mBlastBufferQueueAdapter->update(sc, width, height);
    }

    void setNextTransaction(Transaction* next) {
        mBlastBufferQueueAdapter->setNextTransaction(next);
    }

    int getWidth() { return mBlastBufferQueueAdapter->mWidth; }
    int getHeight() { return mBlastBufferQueueAdapter->mHeight; }
    Transaction* getNextTransaction() { return mBlastBufferQueueAdapter->mNextTransaction; }
    const sp<SurfaceControl> getSurfaceControl() {
        return mBlastBufferQueueAdapter->mSurfaceControl;
    }

private:
    sp<BLASTBufferQueue> mBlastBufferQueueAdapter;
};

class BLASTBufferQueueTest : public ::testing::Test {
public:
protected:
    BLASTBufferQueueTest() {
        const ::testing::TestInfo* const testInfo =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGV("Begin test: %s.%s", testInfo->test_case_name(), testInfo->name());
    }

    ~BLASTBufferQueueTest() {
        const ::testing::TestInfo* const testInfo =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGV("End test:   %s.%s", testInfo->test_case_name(), testInfo->name());
    }

    void SetUp() {
        mClient = new SurfaceComposerClient();
        mSurfaceControl = mClient->createSurface(String8("TestSurface"), DEFAULT_WIDTH,
                                                 DEFAULT_HEIGHT, PIXEL_FORMAT_RGBA_8888);
    }

    sp<SurfaceComposerClient> mClient;
    sp<SurfaceControl> mSurfaceControl;
};

TEST_F(BLASTBufferQueueTest, CreateBLASTBufferQueue) {
    // create BLASTBufferQueue adapter associated with this surface
    BLASTBufferQueueHelper adapter(mSurfaceControl, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    ASSERT_EQ(mSurfaceControl, adapter.getSurfaceControl());
    ASSERT_EQ(DEFAULT_WIDTH, adapter.getWidth());
    ASSERT_EQ(DEFAULT_HEIGHT, adapter.getHeight());
    ASSERT_EQ(nullptr, adapter.getNextTransaction());
}

TEST_F(BLASTBufferQueueTest, Update) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    sp<SurfaceControl> updateSurface =
            mClient->createSurface(String8("UpdateTest"), DEFAULT_WIDTH / 2, DEFAULT_HEIGHT / 2,
                                   PIXEL_FORMAT_RGB_888);
    adapter.update(updateSurface, DEFAULT_WIDTH / 2, DEFAULT_HEIGHT / 2);
    ASSERT_EQ(updateSurface, adapter.getSurfaceControl());
    ASSERT_EQ(DEFAULT_WIDTH / 2, adapter.getWidth());
    ASSERT_EQ(DEFAULT_HEIGHT / 2, adapter.getHeight());
}

TEST_F(BLASTBufferQueueTest, SetNextTransaction) {
    BLASTBufferQueueHelper adapter(mSurfaceControl, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    Transaction next;
    adapter.setNextTransaction(&next);
    ASSERT_EQ(&next, adapter.getNextTransaction());
}
} // namespace android
