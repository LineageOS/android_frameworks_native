/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "LayerTransactionTest.h"
#include "utils/CallbackUtils.h"

using namespace std::chrono_literals;

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

// b/181132765 - disabled until cuttlefish failures are investigated
class ReleaseBufferCallbackHelper {
public:
    static void function(void* callbackContext, uint64_t graphicsBufferId,
                         const sp<Fence>& releaseFence) {
        if (!callbackContext) {
            FAIL() << "failed to get callback context";
        }
        ReleaseBufferCallbackHelper* helper =
                static_cast<ReleaseBufferCallbackHelper*>(callbackContext);
        std::lock_guard lock(helper->mMutex);
        helper->mCallbackDataQueue.emplace(graphicsBufferId, releaseFence);
        helper->mConditionVariable.notify_all();
    }

    void getCallbackData(uint64_t* bufferId) {
        std::unique_lock lock(mMutex);
        if (mCallbackDataQueue.empty()) {
            if (!mConditionVariable.wait_for(lock, std::chrono::seconds(3),
                                             [&] { return !mCallbackDataQueue.empty(); })) {
                FAIL() << "failed to get releaseBuffer callback";
            }
        }

        auto callbackData = mCallbackDataQueue.front();
        mCallbackDataQueue.pop();
        *bufferId = callbackData.first;
    }

    void verifyNoCallbacks() {
        // Wait to see if there are extra callbacks
        std::this_thread::sleep_for(300ms);

        std::lock_guard lock(mMutex);
        EXPECT_EQ(mCallbackDataQueue.size(), 0) << "extra callbacks received";
        mCallbackDataQueue = {};
    }

    android::ReleaseBufferCallback getCallback() {
        return std::bind(function, static_cast<void*>(this) /* callbackContext */,
                         std::placeholders::_1, std::placeholders::_2);
    }

    std::mutex mMutex;
    std::condition_variable mConditionVariable;
    std::queue<std::pair<uint64_t, sp<Fence>>> mCallbackDataQueue;
};

class ReleaseBufferCallbackTest : public LayerTransactionTest {
public:
    virtual sp<SurfaceControl> createBufferStateLayer() {
        return createLayer(mClient, "test", 0, 0, ISurfaceComposerClient::eFXSurfaceBufferState);
    }

    static void submitBuffer(const sp<SurfaceControl>& layer, sp<GraphicBuffer> buffer,
                             sp<Fence> fence, CallbackHelper& callback,
                             ReleaseBufferCallbackHelper& releaseCallback) {
        Transaction t;
        t.setBuffer(layer, buffer, releaseCallback.getCallback());
        t.setAcquireFence(layer, fence);
        t.addTransactionCompletedCallback(callback.function, callback.getContext());
        t.apply();
    }

    static void waitForCallback(CallbackHelper& helper, const ExpectedResult& expectedResult) {
        CallbackData callbackData;
        helper.getCallbackData(&callbackData);
        expectedResult.verifyCallbackData(callbackData);
    }

    static void waitForReleaseBufferCallback(ReleaseBufferCallbackHelper& releaseCallback,
                                             uint64_t expectedReleaseBufferId) {
        uint64_t actualReleaseBufferId;
        releaseCallback.getCallbackData(&actualReleaseBufferId);
        EXPECT_EQ(expectedReleaseBufferId, actualReleaseBufferId);
        releaseCallback.verifyNoCallbacks();
    }
    static ReleaseBufferCallbackHelper* getReleaseBufferCallbackHelper() {
        static std::vector<ReleaseBufferCallbackHelper*> sCallbacks;
        sCallbacks.emplace_back(new ReleaseBufferCallbackHelper());
        return sCallbacks.back();
    }

    static sp<GraphicBuffer> getBuffer() {
        return new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1,
                                 BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                         BufferUsage::COMPOSER_OVERLAY,
                                 "test");
    }
};

TEST_F(ReleaseBufferCallbackTest, DISABLED_PresentBuffer) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    CallbackHelper transactionCallback;
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // If a buffer is being presented, we should not emit a release callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, transactionCallback, *releaseCallback);
    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    EXPECT_NO_FATAL_FAILURE(releaseCallback->verifyNoCallbacks());

    // if state doesn't change, no release callbacks are expected
    Transaction t;
    t.addTransactionCompletedCallback(transactionCallback.function,
                                      transactionCallback.getContext());
    t.apply();
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, ExpectedResult()));
    EXPECT_NO_FATAL_FAILURE(releaseCallback->verifyNoCallbacks());

    // If a presented buffer is replaced, we should emit a release callback for the
    // previously presented buffer.
    sp<GraphicBuffer> secondBuffer = getBuffer();
    submitBuffer(layer, secondBuffer, Fence::NO_FENCE, transactionCallback, *releaseCallback);
    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBuffer->getId()));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_OffScreenLayer) {
    sp<SurfaceControl> layer = createBufferStateLayer();

    CallbackHelper transactionCallback;
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // If a buffer is being presented, we should not emit a release callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, transactionCallback, *releaseCallback);
    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    releaseCallback->verifyNoCallbacks();

    // If a layer is parented offscreen then it should not emit a callback since sf still owns
    // the buffer and can render it again.
    Transaction t;
    t.reparent(layer, nullptr);
    t.addTransactionCompletedCallback(transactionCallback.function,
                                      transactionCallback.getContext());
    t.apply();
    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::NOT_PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::NOT_RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(releaseCallback->verifyNoCallbacks());

    // If a presented buffer is replaced, we should emit a release callback for the
    // previously presented buffer.
    sp<GraphicBuffer> secondBuffer = getBuffer();
    submitBuffer(layer, secondBuffer, Fence::NO_FENCE, transactionCallback, *releaseCallback);
    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::NOT_RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBuffer->getId()));

    // If continue to submit buffer we continue to get release callbacks
    sp<GraphicBuffer> thirdBuffer = getBuffer();
    submitBuffer(layer, thirdBuffer, Fence::NO_FENCE, transactionCallback, *releaseCallback);
    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::NOT_RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, secondBuffer->getId()));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_LayerLifecycle_layerdestroy) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    CallbackHelper* transactionCallback = new CallbackHelper();
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // If a buffer is being presented, we should not emit a release callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, *transactionCallback, *releaseCallback);
    {
        ExpectedResult expected;
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::NOT_ACQUIRED);
        ASSERT_NO_FATAL_FAILURE(waitForCallback(*transactionCallback, expected));
        ASSERT_NO_FATAL_FAILURE(releaseCallback->verifyNoCallbacks());
    }

    // Destroying a currently presenting layer emits a callback.
    Transaction t;
    t.reparent(layer, nullptr);
    t.apply();
    layer = nullptr;

    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBuffer->getId()));
}

// Destroying a never presented layer emits a callback.
TEST_F(ReleaseBufferCallbackTest, DISABLED_LayerLifecycle_OffScreenLayerDestroy) {
    sp<SurfaceControl> layer = createBufferStateLayer();

    // make layer offscreen
    Transaction t;
    t.reparent(layer, nullptr);
    t.apply();

    CallbackHelper* transactionCallback = new CallbackHelper();
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // Submitting a buffer does not emit a callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, *transactionCallback, *releaseCallback);
    {
        ExpectedResult expected;
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::NOT_ACQUIRED);
        ASSERT_NO_FATAL_FAILURE(waitForCallback(*transactionCallback, expected));
        ASSERT_NO_FATAL_FAILURE(releaseCallback->verifyNoCallbacks());
    }

    // Submitting a second buffer will replace the drawing state buffer and emit a callback.
    sp<GraphicBuffer> secondBuffer = getBuffer();
    submitBuffer(layer, secondBuffer, Fence::NO_FENCE, *transactionCallback, *releaseCallback);
    {
        ExpectedResult expected;
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::NOT_ACQUIRED);
        ASSERT_NO_FATAL_FAILURE(waitForCallback(*transactionCallback, expected));
        ASSERT_NO_FATAL_FAILURE(
                waitForReleaseBufferCallback(*releaseCallback, firstBuffer->getId()));
    }

    // Destroying the offscreen layer emits a callback.
    layer = nullptr;
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, secondBuffer->getId()));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_FrameDropping) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    CallbackHelper transactionCallback;
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // If a buffer is being presented, we should not emit a release callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();

    // Try to present 100ms in the future
    nsecs_t time = systemTime() + std::chrono::nanoseconds(100ms).count();

    Transaction t;
    t.setBuffer(layer, firstBuffer, releaseCallback->getCallback());
    t.setAcquireFence(layer, Fence::NO_FENCE);
    t.addTransactionCompletedCallback(transactionCallback.function,
                                      transactionCallback.getContext());
    t.setDesiredPresentTime(time);
    t.apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    EXPECT_NO_FATAL_FAILURE(releaseCallback->verifyNoCallbacks());

    // Dropping frames in transaction queue emits a callback
    sp<GraphicBuffer> secondBuffer = getBuffer();
    t.setBuffer(layer, secondBuffer, releaseCallback->getCallback());
    t.setAcquireFence(layer, Fence::NO_FENCE);
    t.addTransactionCompletedCallback(transactionCallback.function,
                                      transactionCallback.getContext());
    t.setDesiredPresentTime(time);
    t.apply();

    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBuffer->getId()));
}

} // namespace android
