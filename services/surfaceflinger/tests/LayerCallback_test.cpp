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

#include <sys/epoll.h>

#include <gui/DisplayEventReceiver.h>

#include "LayerTransactionTest.h"
#include "utils/CallbackUtils.h"

using namespace std::chrono_literals;

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

::testing::Environment* const binderEnv =
        ::testing::AddGlobalTestEnvironment(new BinderEnvironment());

class LayerCallbackTest : public LayerTransactionTest {
public:
    void SetUp() override {
        LayerTransactionTest::SetUp();

        EXPECT_EQ(NO_ERROR, mDisplayEventReceiver.initCheck());

        mEpollFd = epoll_create1(EPOLL_CLOEXEC);
        EXPECT_GT(mEpollFd, 1);

        epoll_event event;
        event.events = EPOLLIN;
        EXPECT_EQ(0, epoll_ctl(mEpollFd, EPOLL_CTL_ADD, mDisplayEventReceiver.getFd(), &event));
    }

    void TearDown() override {
        close(mEpollFd);
        LayerTransactionTest::TearDown();
    }

    virtual sp<SurfaceControl> createBufferStateLayer() {
        return createLayer(mClient, "test", 0, 0, ISurfaceComposerClient::eFXSurfaceBufferState);
    }

    static int fillTransaction(Transaction& transaction, CallbackHelper* callbackHelper,
                               const sp<SurfaceControl>& layer = nullptr, bool setBuffer = true,
                               bool setBackgroundColor = false) {
        if (layer) {
            sp<GraphicBuffer> buffer;
            sp<Fence> fence;
            if (setBuffer) {
                int err = getBuffer(&buffer, &fence);
                if (err != NO_ERROR) {
                    return err;
                }

                transaction.setBuffer(layer, buffer);
                transaction.setAcquireFence(layer, fence);
            }

            if (setBackgroundColor) {
                transaction.setBackgroundColor(layer, /*color*/ half3(1.0f, 0, 0), /*alpha*/ 1.0f,
                                               ui::Dataspace::UNKNOWN);
            }
        }

        transaction.addTransactionCompletedCallback(callbackHelper->function,
                                                    callbackHelper->getContext());
        return NO_ERROR;
    }

    static void waitForCallback(CallbackHelper& helper, const ExpectedResult& expectedResult,
                                bool finalState = false) {
        CallbackData callbackData;
        ASSERT_NO_FATAL_FAILURE(helper.getCallbackData(&callbackData));
        EXPECT_NO_FATAL_FAILURE(expectedResult.verifyCallbackData(callbackData));

        if (finalState) {
            ASSERT_NO_FATAL_FAILURE(helper.verifyFinalState());
        }
    }

    static void waitForCallbacks(CallbackHelper& helper,
                                 const std::vector<ExpectedResult>& expectedResults,
                                 bool finalState = false) {
        for (const auto& expectedResult : expectedResults) {
            waitForCallback(helper, expectedResult);
        }
        if (finalState) {
            ASSERT_NO_FATAL_FAILURE(helper.verifyFinalState());
        }
    }

    DisplayEventReceiver mDisplayEventReceiver;
    int mEpollFd;

    struct Vsync {
        int64_t vsyncId = FrameTimelineInfo::INVALID_VSYNC_ID;
        nsecs_t expectedPresentTime = std::numeric_limits<nsecs_t>::max();
    };

    Vsync waitForNextVsync() {
        mDisplayEventReceiver.requestNextVsync();
        epoll_event epollEvent;
        Vsync vsync;
        EXPECT_EQ(1, epoll_wait(mEpollFd, &epollEvent, 1, 1000))
                << "Timeout waiting for vsync event";
        DisplayEventReceiver::Event event;
        while (mDisplayEventReceiver.getEvents(&event, 1) > 0) {
            if (event.header.type != DisplayEventReceiver::DISPLAY_EVENT_VSYNC) {
                continue;
            }

            vsync = {event.vsync.vsyncId, event.vsync.expectedVSyncTimestamp};
        }

        EXPECT_GE(vsync.vsyncId, 1);
        EXPECT_GT(event.vsync.expectedVSyncTimestamp, systemTime());

        return vsync;
    }
};

TEST_F(LayerCallbackTest, BufferColor) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer, true, true);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction.apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, NoBufferNoColor) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer, false, false);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction.setFrame(layer, Rect(0, 0, 32, 32)).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::NOT_PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, BufferNoColor) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer, true, false);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction.setFrame(layer, Rect(0, 0, 32, 32)).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, NoBufferColor) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer, false, true);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction.setFrame(layer, Rect(0, 0, 32, 32)).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                        ExpectedResult::Buffer::NOT_ACQUIRED);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, NoStateChange) {
    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction.apply();

    ExpectedResult expected;
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, OffScreen) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction.setFrame(layer, Rect(-100, -100, 100, 100)).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, MergeBufferNoColor) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    int err = fillTransaction(transaction1, &callback1, layer1);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2, layer2);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction1.setFrame(layer1, Rect(0, 0, 32, 32));
    transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, MergeNoBufferColor) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    int err = fillTransaction(transaction1, &callback1, layer1, false, true);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2, layer2, false, true);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction1.setFrame(layer1, Rect(0, 0, 32, 32));
    transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2},
                         ExpectedResult::Buffer::NOT_ACQUIRED);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, MergeOneBufferOneColor) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    int err = fillTransaction(transaction1, &callback1, layer1);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2, layer2, false, true);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction1.setFrame(layer1, Rect(0, 0, 32, 32));
    transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer1);
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer2,
                        ExpectedResult::Buffer::NOT_ACQUIRED);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}
TEST_F(LayerCallbackTest, Merge_SameCallback) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback;
    int err = fillTransaction(transaction1, &callback, layer1);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback, layer2);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction2.merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, Merge_SameLayer) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    int err = fillTransaction(transaction1, &callback1, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction2.merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, Merge_DifferentClients) {
    sp<SurfaceComposerClient> client1(new SurfaceComposerClient),
            client2(new SurfaceComposerClient);

    ASSERT_EQ(NO_ERROR, client1->initCheck()) << "failed to create SurfaceComposerClient";
    ASSERT_EQ(NO_ERROR, client2->initCheck()) << "failed to create SurfaceComposerClient";

    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer(client1, "test", 0, 0,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer(client2, "test", 0, 0,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    int err = fillTransaction(transaction1, &callback1, layer1);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2, layer2);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction1.setFrame(layer1, Rect(0, 0, 32, 32));
    transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    for (size_t i = 0; i < 10; i++) {
        int err = fillTransaction(transaction, &callback, layer);
        if (err) {
            GTEST_SUCCEED() << "test not supported";
            return;
        }

        transaction.apply();

        ExpectedResult expected;
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::ACQUIRED,
                            (i == 0) ? ExpectedResult::PreviousBuffer::NOT_RELEASED
                                     : ExpectedResult::PreviousBuffer::RELEASED);
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected));
    }
    ASSERT_NO_FATAL_FAILURE(callback.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_NoStateChange) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    for (size_t i = 0; i < 10; i++) {
        ExpectedResult expected;

        if (i == 0) {
            int err = fillTransaction(transaction, &callback, layer);
            if (err) {
                GTEST_SUCCEED() << "test not supported";
                return;
            }
            expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
        } else {
            int err = fillTransaction(transaction, &callback);
            if (err) {
                GTEST_SUCCEED() << "test not supported";
                return;
            }
        }

        transaction.apply();

        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected));
    }
    ASSERT_NO_FATAL_FAILURE(callback.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_SameStateChange) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    for (size_t i = 0; i < 10; i++) {
        if (i == 0) {
            int err = fillTransaction(transaction, &callback, layer);
            if (err) {
                GTEST_SUCCEED() << "test not supported";
                return;
            }
        } else {
            int err = fillTransaction(transaction, &callback);
            if (err) {
                GTEST_SUCCEED() << "test not supported";
                return;
            }
        }

        transaction.setFrame(layer, Rect(0, 0, 32, 32)).apply();

        ExpectedResult expected;
        expected.addSurface((i == 0) ? ExpectedResult::Transaction::PRESENTED
                                     : ExpectedResult::Transaction::NOT_PRESENTED,
                            layer,
                            (i == 0) ? ExpectedResult::Buffer::ACQUIRED
                                     : ExpectedResult::Buffer::NOT_ACQUIRED);
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, i == 0));
    }
    ASSERT_NO_FATAL_FAILURE(callback.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_Merge) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    for (size_t i = 0; i < 10; i++) {
        int err = fillTransaction(transaction1, &callback1, layer1);
        if (err) {
            GTEST_SUCCEED() << "test not supported";
            return;
        }
        err = fillTransaction(transaction2, &callback2, layer2);
        if (err) {
            GTEST_SUCCEED() << "test not supported";
            return;
        }

        transaction1.setFrame(layer1, Rect(0, 0, 32, 32));
        transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

        ExpectedResult expected;
        expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2},
                             ExpectedResult::Buffer::ACQUIRED,
                             (i == 0) ? ExpectedResult::PreviousBuffer::NOT_RELEASED
                                      : ExpectedResult::PreviousBuffer::RELEASED);
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected));
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected));
    }
    ASSERT_NO_FATAL_FAILURE(callback1.verifyFinalState());
    ASSERT_NO_FATAL_FAILURE(callback2.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_Merge_DifferentClients) {
    sp<SurfaceComposerClient> client1(new SurfaceComposerClient),
            client2(new SurfaceComposerClient);
    ASSERT_EQ(NO_ERROR, client1->initCheck()) << "failed to create SurfaceComposerClient";
    ASSERT_EQ(NO_ERROR, client2->initCheck()) << "failed to create SurfaceComposerClient";

    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer(client1, "test", 0, 0,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer(client2, "test", 0, 0,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    for (size_t i = 0; i < 10; i++) {
        int err = fillTransaction(transaction1, &callback1, layer1);
        if (err) {
            GTEST_SUCCEED() << "test not supported";
            return;
        }
        err = fillTransaction(transaction2, &callback2, layer2);
        if (err) {
            GTEST_SUCCEED() << "test not supported";
            return;
        }

        transaction1.setFrame(layer1, Rect(0, 0, 32, 32));
        transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

        ExpectedResult expected;
        expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2},
                             ExpectedResult::Buffer::ACQUIRED,
                             (i == 0) ? ExpectedResult::PreviousBuffer::NOT_RELEASED
                                      : ExpectedResult::PreviousBuffer::RELEASED);
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected));
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected));
    }
    ASSERT_NO_FATAL_FAILURE(callback1.verifyFinalState());
    ASSERT_NO_FATAL_FAILURE(callback2.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_Merge_DifferentClients_NoStateChange) {
    sp<SurfaceComposerClient> client1(new SurfaceComposerClient),
            client2(new SurfaceComposerClient);
    ASSERT_EQ(NO_ERROR, client1->initCheck()) << "failed to create SurfaceComposerClient";
    ASSERT_EQ(NO_ERROR, client2->initCheck()) << "failed to create SurfaceComposerClient";

    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer(client1, "test", 0, 0,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer(client2, "test", 0, 0,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;

    // Normal call to set up test
    int err = fillTransaction(transaction1, &callback1, layer1);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2, layer2);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction1.setFrame(layer1, Rect(0, 0, 32, 32));
    transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
    expected.reset();

    // Test
    err = fillTransaction(transaction1, &callback1);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction2.merge(std::move(transaction1)).apply();

    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions_Merge_DifferentClients_SameStateChange) {
    sp<SurfaceComposerClient> client1(new SurfaceComposerClient),
            client2(new SurfaceComposerClient);

    ASSERT_EQ(NO_ERROR, client1->initCheck()) << "failed to create SurfaceComposerClient";
    ASSERT_EQ(NO_ERROR, client2->initCheck()) << "failed to create SurfaceComposerClient";

    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer(client1, "test", 0, 0,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer(client2, "test", 0, 0,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;

    // Normal call to set up test
    int err = fillTransaction(transaction1, &callback1, layer1);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2, layer2);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction1.setFrame(layer1, Rect(0, 0, 32, 32));
    transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
    expected.reset();

    // Test
    err = fillTransaction(transaction1, &callback1);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }
    err = fillTransaction(transaction2, &callback2);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction2.setFrame(layer2, Rect(32, 32, 64, 64)).merge(std::move(transaction1)).apply();

    expected.addSurface(ExpectedResult::Transaction::NOT_PRESENTED, layer2,
                        ExpectedResult::Buffer::NOT_ACQUIRED);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions_SingleFrame) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    std::vector<ExpectedResult> expectedResults(50);
    for (auto& expected : expectedResults) {
        expected.reset();
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::ACQUIRED,
                            ExpectedResult::PreviousBuffer::UNKNOWN);

        int err = fillTransaction(transaction, &callback, layer);
        if (err) {
            GTEST_SUCCEED() << "test not supported";
            return;
        }

        transaction.apply();
    }
    EXPECT_NO_FATAL_FAILURE(waitForCallbacks(callback, expectedResults, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions_SingleFrame_NoStateChange) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    // Normal call to set up test
    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction.apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));

    // Test
    std::vector<ExpectedResult> expectedResults(50);
    for (auto& expected : expectedResults) {
        expected.reset();

        err = fillTransaction(transaction, &callback);
        if (err) {
            GTEST_SUCCEED() << "test not supported";
            return;
        }

        transaction.apply();
    }
    EXPECT_NO_FATAL_FAILURE(waitForCallbacks(callback, expectedResults, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions_SingleFrame_SameStateChange) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    // Normal call to set up test
    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    transaction.setFrame(layer, Rect(0, 0, 32, 32)).apply();

    ExpectedResult expectedResult;
    expectedResult.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expectedResult, true));

    // Test
    std::vector<ExpectedResult> expectedResults(50);
    for (auto& expected : expectedResults) {
        expected.reset();
        expected.addSurface(ExpectedResult::Transaction::NOT_PRESENTED, layer,
                            ExpectedResult::Buffer::NOT_ACQUIRED);

        err = fillTransaction(transaction, &callback);
        if (err) {
            GTEST_SUCCEED() << "test not supported";
            return;
        }

        transaction.setFrame(layer, Rect(0, 0, 32, 32)).apply();
    }
    EXPECT_NO_FATAL_FAILURE(waitForCallbacks(callback, expectedResults, true));
}

TEST_F(LayerCallbackTest, DesiredPresentTime) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    // Try to present 100ms in the future
    nsecs_t time = systemTime() + std::chrono::nanoseconds(100ms).count();

    transaction.setDesiredPresentTime(time);
    transaction.apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    expected.addExpectedPresentTime(time);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, DesiredPresentTime_Multiple) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback1;
    int err = fillTransaction(transaction, &callback1, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    // Try to present 100ms in the future
    nsecs_t time = systemTime() + std::chrono::nanoseconds(100ms).count();

    transaction.setDesiredPresentTime(time);
    transaction.apply();

    ExpectedResult expected1;
    expected1.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    expected1.addExpectedPresentTime(time);

    CallbackHelper callback2;
    err = fillTransaction(transaction, &callback2, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    // Try to present 33ms after the first frame
    time += std::chrono::nanoseconds(33ms).count();

    transaction.setDesiredPresentTime(time);
    transaction.apply();

    ExpectedResult expected2;
    expected2.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                         ExpectedResult::Buffer::ACQUIRED,
                         ExpectedResult::PreviousBuffer::RELEASED);
    expected2.addExpectedPresentTime(time);

    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected1, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected2, true));
}

TEST_F(LayerCallbackTest, DesiredPresentTime_OutOfOrder) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback1;
    int err = fillTransaction(transaction, &callback1, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    // Try to present 100ms in the future
    nsecs_t time = systemTime() + std::chrono::nanoseconds(100ms).count();

    transaction.setDesiredPresentTime(time);
    transaction.apply();

    ExpectedResult expected1;
    expected1.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    expected1.addExpectedPresentTime(time);

    CallbackHelper callback2;
    err = fillTransaction(transaction, &callback2, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    // Try to present 33ms before the previous frame
    time -= std::chrono::nanoseconds(33ms).count();

    transaction.setDesiredPresentTime(time);
    transaction.apply();

    ExpectedResult expected2;
    expected2.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                         ExpectedResult::Buffer::ACQUIRED,
                         ExpectedResult::PreviousBuffer::RELEASED);

    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected1, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected2, true));
}

TEST_F(LayerCallbackTest, DesiredPresentTime_Past) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    // Try to present 100ms in the past
    nsecs_t time = systemTime() - std::chrono::nanoseconds(100ms).count();

    transaction.setDesiredPresentTime(time);
    transaction.apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    expected.addExpectedPresentTime(systemTime());
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, ExpectedPresentTime) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    int err = fillTransaction(transaction, &callback, layer);
    if (err) {
        GTEST_SUCCEED() << "test not supported";
        return;
    }

    const Vsync vsync = waitForNextVsync();
    transaction.setFrameTimelineInfo({vsync.vsyncId, 0});
    transaction.apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    expected.addExpectedPresentTimeForVsyncId(vsync.expectedPresentTime);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

} // namespace android
