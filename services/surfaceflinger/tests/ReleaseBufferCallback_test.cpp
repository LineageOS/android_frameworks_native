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

#include <gui/test/CallbackUtils.h>
#include "LayerTransactionTest.h"

using namespace std::chrono_literals;

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

// b/181132765 - disabled until cuttlefish failures are investigated
class ReleaseBufferCallbackHelper {
public:
    static void function(void* callbackContext, ReleaseCallbackId callbackId,
                         const sp<Fence>& releaseFence,
                         std::optional<uint32_t> /*currentMaxAcquiredBufferCount*/) {
        if (!callbackContext) {
            FAIL() << "failed to get callback context";
        }
        ReleaseBufferCallbackHelper* helper =
                static_cast<ReleaseBufferCallbackHelper*>(callbackContext);
        std::lock_guard lock(helper->mMutex);
        helper->mCallbackDataQueue.emplace(callbackId, releaseFence);
        helper->mConditionVariable.notify_all();
    }

    void getCallbackData(ReleaseCallbackId* callbackId) {
        std::unique_lock lock(mMutex);
        if (mCallbackDataQueue.empty()) {
            if (!mConditionVariable.wait_for(lock, std::chrono::seconds(3),
                                             [&] { return !mCallbackDataQueue.empty(); })) {
                FAIL() << "failed to get releaseBuffer callback";
            }
        }

        auto callbackData = mCallbackDataQueue.front();
        mCallbackDataQueue.pop();
        *callbackId = callbackData.first;
    }

    void verifyNoCallbacks() {
        // Wait to see if there are extra callbacks
        std::this_thread::sleep_for(300ms);

        std::lock_guard lock(mMutex);
        EXPECT_EQ(mCallbackDataQueue.size(), 0U) << "extra callbacks received";
        mCallbackDataQueue = {};
    }

    android::ReleaseBufferCallback getCallback() {
        return std::bind(function, static_cast<void*>(this) /* callbackContext */,
                         std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    }

    std::mutex mMutex;
    std::condition_variable mConditionVariable;
    std::queue<std::pair<ReleaseCallbackId, sp<Fence>>> mCallbackDataQueue;
};

class ReleaseBufferCallbackTest : public LayerTransactionTest {
public:
    virtual sp<SurfaceControl> createBufferStateLayer() {
        return createLayer(mClient, "test", 0, 0, ISurfaceComposerClient::eFXSurfaceBufferState);
    }

    static void submitBuffer(const sp<SurfaceControl>& layer, sp<GraphicBuffer> buffer,
                             sp<Fence> fence, CallbackHelper& callback, const ReleaseCallbackId& id,
                             ReleaseBufferCallbackHelper& releaseCallback) {
        Transaction t;
        t.setBuffer(layer, buffer, fence, id.framenumber, 0 /* producerId */,
                    releaseCallback.getCallback());
        t.addTransactionCompletedCallback(callback.function, callback.getContext());
        t.apply();
    }

    static void waitForCallback(CallbackHelper& helper, const ExpectedResult& expectedResult) {
        CallbackData callbackData;
        helper.getCallbackData(&callbackData);
        expectedResult.verifyCallbackData(callbackData);
    }

    static void waitForReleaseBufferCallback(ReleaseBufferCallbackHelper& releaseCallback,
                                             const ReleaseCallbackId& expectedReleaseBufferId) {
        ReleaseCallbackId actualReleaseBufferId;
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
        return sp<GraphicBuffer>::make(32u, 32u, PIXEL_FORMAT_RGBA_8888, 1u,
                                       BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                               BufferUsage::COMPOSER_OVERLAY,
                                       "test");
    }
    static uint64_t generateFrameNumber() {
        static uint64_t sFrameNumber = 0;
        return ++sFrameNumber;
    }
};

TEST_F(ReleaseBufferCallbackTest, DISABLED_PresentBuffer) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    CallbackHelper transactionCallback;
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // If a buffer is being presented, we should not emit a release callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, transactionCallback, firstBufferCallbackId,
                 *releaseCallback);
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
    ReleaseCallbackId secondBufferCallbackId(secondBuffer->getId(), generateFrameNumber());
    submitBuffer(layer, secondBuffer, Fence::NO_FENCE, transactionCallback, secondBufferCallbackId,
                 *releaseCallback);
    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_OffScreenLayer) {
    sp<SurfaceControl> layer = createBufferStateLayer();

    CallbackHelper transactionCallback;
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // If a buffer is being presented, we should not emit a release callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, transactionCallback, firstBufferCallbackId,
                 *releaseCallback);
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
    ReleaseCallbackId secondBufferCallbackId(secondBuffer->getId(), generateFrameNumber());
    submitBuffer(layer, secondBuffer, Fence::NO_FENCE, transactionCallback, secondBufferCallbackId,
                 *releaseCallback);
    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::NOT_RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));

    // If continue to submit buffer we continue to get release callbacks
    sp<GraphicBuffer> thirdBuffer = getBuffer();
    ReleaseCallbackId thirdBufferCallbackId(secondBuffer->getId(), generateFrameNumber());
    submitBuffer(layer, thirdBuffer, Fence::NO_FENCE, transactionCallback, thirdBufferCallbackId,
                 *releaseCallback);
    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::NOT_RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, secondBufferCallbackId));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_LayerLifecycle_layerdestroy) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    CallbackHelper* transactionCallback = new CallbackHelper();
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // If a buffer is being presented, we should not emit a release callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, *transactionCallback, firstBufferCallbackId,
                 *releaseCallback);
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

    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
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
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, *transactionCallback, firstBufferCallbackId,
                 *releaseCallback);
    {
        ExpectedResult expected;
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::NOT_ACQUIRED);
        ASSERT_NO_FATAL_FAILURE(waitForCallback(*transactionCallback, expected));
        ASSERT_NO_FATAL_FAILURE(releaseCallback->verifyNoCallbacks());
    }

    // Submitting a second buffer will replace the drawing state buffer and emit a callback.
    sp<GraphicBuffer> secondBuffer = getBuffer();
    ReleaseCallbackId secondBufferCallbackId(secondBuffer->getId(), generateFrameNumber());
    submitBuffer(layer, secondBuffer, Fence::NO_FENCE, *transactionCallback, secondBufferCallbackId,
                 *releaseCallback);
    {
        ExpectedResult expected;
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::NOT_ACQUIRED);
        ASSERT_NO_FATAL_FAILURE(waitForCallback(*transactionCallback, expected));
        ASSERT_NO_FATAL_FAILURE(
                waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
    }

    // Destroying the offscreen layer emits a callback.
    layer = nullptr;
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, secondBufferCallbackId));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_FrameDropping) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    CallbackHelper transactionCallback;
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    // If a buffer is being presented, we should not emit a release callback.
    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());

    // Try to present 100ms in the future
    nsecs_t time = systemTime() + std::chrono::nanoseconds(100ms).count();

    Transaction t;
    t.setBuffer(layer, firstBuffer, std::nullopt, firstBufferCallbackId.framenumber,
                0 /* producerId */, releaseCallback->getCallback());
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
    ReleaseCallbackId secondBufferCallbackId(secondBuffer->getId(), generateFrameNumber());
    t.setBuffer(layer, secondBuffer, std::nullopt, secondBufferCallbackId.framenumber,
                0 /* producerId */, releaseCallback->getCallback());
    t.addTransactionCompletedCallback(transactionCallback.function,
                                      transactionCallback.getContext());
    t.setDesiredPresentTime(time);
    t.apply();

    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(transactionCallback, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_Merge_Different_Processes) {
    sp<TransactionCompletedListener> firstCompletedListener =
            sp<TransactionCompletedListener>::make();
    sp<TransactionCompletedListener> secondCompletedListener =
            sp<TransactionCompletedListener>::make();

    CallbackHelper callback1, callback2;

    TransactionCompletedListener::setInstance(firstCompletedListener);

    sp<SurfaceControl> layer = createBufferStateLayer();
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());

    // Send initial buffer for the layer
    submitBuffer(layer, firstBuffer, Fence::NO_FENCE, callback1, firstBufferCallbackId,
                 *releaseCallback);

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(callback1, expected));

    // Sent a second buffer to allow the first buffer to get released.
    sp<GraphicBuffer> secondBuffer = getBuffer();
    ReleaseCallbackId secondBufferCallbackId(secondBuffer->getId(), generateFrameNumber());

    Transaction transaction1;
    transaction1.setBuffer(layer, secondBuffer, std::nullopt, secondBufferCallbackId.framenumber,
                           0 /* producerId */, releaseCallback->getCallback());
    transaction1.addTransactionCompletedCallback(callback1.function, callback1.getContext());

    // Set a different TransactionCompletedListener to mimic a second process
    TransactionCompletedListener::setInstance(secondCompletedListener);

    // Make sure the second "process" has a callback set up.
    Transaction transaction2;
    transaction2.addTransactionCompletedCallback(callback2.function, callback2.getContext());

    // This merging order, merge transaction1 first then transaction2, seems to ensure the listener
    // for transaction2 is ordered first. This makes sure the wrong process is added first to the
    // layer's vector of listeners. With the bug, only the secondCompletedListener will get the
    // release callback id, since it's ordered first. Then firstCompletedListener would fail to get
    // the release callback id and not invoke the release callback.
    Transaction().merge(std::move(transaction1)).merge(std::move(transaction2)).apply();

    expected = ExpectedResult();
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED,
                        ExpectedResult::PreviousBuffer::RELEASED);
    ASSERT_NO_FATAL_FAILURE(waitForCallback(callback1, expected));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_SetBuffer_OverwriteBuffers) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());

    // Create transaction with a buffer.
    Transaction transaction;
    transaction.setBuffer(layer, firstBuffer, std::nullopt, firstBufferCallbackId.framenumber,
                          0 /* producerId */, releaseCallback->getCallback());

    sp<GraphicBuffer> secondBuffer = getBuffer();
    ReleaseCallbackId secondBufferCallbackId(secondBuffer->getId(), generateFrameNumber());

    // Call setBuffer on the same transaction with a different buffer.
    transaction.setBuffer(layer, secondBuffer, std::nullopt, secondBufferCallbackId.framenumber,
                          0 /* producerId */, releaseCallback->getCallback());

    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_Merge_Transactions_OverwriteBuffers) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());

    // Create transaction with a buffer.
    Transaction transaction1;
    transaction1.setBuffer(layer, firstBuffer, std::nullopt, firstBufferCallbackId.framenumber,
                           0 /* producerId */, releaseCallback->getCallback());

    sp<GraphicBuffer> secondBuffer = getBuffer();
    ReleaseCallbackId secondBufferCallbackId(secondBuffer->getId(), generateFrameNumber());

    // Create a second transaction with a new buffer for the same layer.
    Transaction transaction2;
    transaction2.setBuffer(layer, secondBuffer, std::nullopt, secondBufferCallbackId.framenumber,
                           0 /* producerId */, releaseCallback->getCallback());

    // merge transaction1 into transaction2 so ensure we get a proper buffer release callback.
    transaction1.merge(std::move(transaction2));
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
}

TEST_F(ReleaseBufferCallbackTest, DISABLED_MergeBuffers_Different_Processes) {
    sp<TransactionCompletedListener> firstCompletedListener =
            sp<TransactionCompletedListener>::make();
    sp<TransactionCompletedListener> secondCompletedListener =
            sp<TransactionCompletedListener>::make();

    TransactionCompletedListener::setInstance(firstCompletedListener);

    sp<SurfaceControl> layer = createBufferStateLayer();
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());

    Transaction transaction1;
    transaction1.setBuffer(layer, firstBuffer, std::nullopt, firstBufferCallbackId.framenumber,
                           0 /* producerId */, releaseCallback->getCallback());

    // Sent a second buffer to allow the first buffer to get released.
    sp<GraphicBuffer> secondBuffer = getBuffer();
    ReleaseCallbackId secondBufferCallbackId(secondBuffer->getId(), generateFrameNumber());

    Transaction transaction2;
    transaction2.setBuffer(layer, secondBuffer, std::nullopt, secondBufferCallbackId.framenumber,
                           0 /* producerId */, releaseCallback->getCallback());

    // Set a different TransactionCompletedListener to mimic a second process
    TransactionCompletedListener::setInstance(secondCompletedListener);
    Transaction().merge(std::move(transaction1)).merge(std::move(transaction2)).apply();

    // Make sure we can still get the release callback even though the merge happened in a different
    // process.
    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
}

TEST_F(ReleaseBufferCallbackTest, SetBuffer_OverwriteBuffersWithNull) {
    sp<SurfaceControl> layer = createBufferStateLayer();
    ReleaseBufferCallbackHelper* releaseCallback = getReleaseBufferCallbackHelper();

    sp<GraphicBuffer> firstBuffer = getBuffer();
    ReleaseCallbackId firstBufferCallbackId(firstBuffer->getId(), generateFrameNumber());

    // Create transaction with a buffer.
    Transaction transaction;
    transaction.setBuffer(layer, firstBuffer, std::nullopt, firstBufferCallbackId.framenumber,
                          0 /* producerId */, releaseCallback->getCallback());

    // Call setBuffer on the same transaction with a null buffer.
    transaction.setBuffer(layer, nullptr, std::nullopt, 0, 0 /* producerId */,
                          releaseCallback->getCallback());

    ASSERT_NO_FATAL_FAILURE(waitForReleaseBufferCallback(*releaseCallback, firstBufferCallbackId));
}

} // namespace android
