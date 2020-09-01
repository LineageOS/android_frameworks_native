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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "CompositionTest"

#include <compositionengine/Display.h>
#include <compositionengine/mock/DisplaySurface.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/SurfaceComposerClient.h>
#include <log/log.h>
#include <utils/String8.h>

#include "TestableScheduler.h"
#include "TestableSurfaceFlinger.h"
#include "mock/MockDispSync.h"
#include "mock/MockEventControlThread.h"
#include "mock/MockEventThread.h"
#include "mock/MockMessageQueue.h"

namespace android {

using testing::_;
using testing::Return;

using FakeHwcDisplayInjector = TestableSurfaceFlinger::FakeHwcDisplayInjector;

class TransactionApplicationTest : public testing::Test {
public:
    TransactionApplicationTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

        mFlinger.mutableEventQueue().reset(mMessageQueue);
        setupScheduler();
    }

    ~TransactionApplicationTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    void setupScheduler() {
        auto eventThread = std::make_unique<mock::EventThread>();
        auto sfEventThread = std::make_unique<mock::EventThread>();

        EXPECT_CALL(*eventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*eventThread, createEventConnection(_, _))
                .WillOnce(Return(
                        new EventThreadConnection(eventThread.get(), ResyncCallback(),
                                                  ISurfaceComposer::eConfigChangedSuppress)));

        EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
                .WillOnce(Return(
                        new EventThreadConnection(sfEventThread.get(), ResyncCallback(),
                                                  ISurfaceComposer::eConfigChangedSuppress)));

        EXPECT_CALL(*mPrimaryDispSync, computeNextRefresh(0, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(*mPrimaryDispSync, getPeriod())
                .WillRepeatedly(Return(FakeHwcDisplayInjector::DEFAULT_REFRESH_RATE));

        mFlinger.setupScheduler(std::unique_ptr<mock::DispSync>(mPrimaryDispSync),
                                std::make_unique<mock::EventControlThread>(),
                                std::move(eventThread), std::move(sfEventThread));
    }

    TestableScheduler* mScheduler;
    TestableSurfaceFlinger mFlinger;

    std::unique_ptr<mock::EventThread> mEventThread = std::make_unique<mock::EventThread>();
    mock::EventControlThread* mEventControlThread = new mock::EventControlThread();

    mock::MessageQueue* mMessageQueue = new mock::MessageQueue();
    mock::DispSync* mPrimaryDispSync = new mock::DispSync();

    struct TransactionInfo {
        Vector<ComposerState> states;
        Vector<DisplayState> displays;
        uint32_t flags = 0;
        sp<IBinder> applyToken = IInterface::asBinder(TransactionCompletedListener::getIInstance());
        InputWindowCommands inputWindowCommands;
        int64_t desiredPresentTime = -1;
        client_cache_t uncacheBuffer;
    };

    void checkEqual(TransactionInfo info, SurfaceFlinger::TransactionState state) {
        EXPECT_EQ(0, info.states.size());
        EXPECT_EQ(0, state.states.size());

        EXPECT_EQ(0, info.displays.size());
        EXPECT_EQ(0, state.displays.size());
        EXPECT_EQ(info.flags, state.flags);
        EXPECT_EQ(info.desiredPresentTime, state.desiredPresentTime);
    }

    void setupSingle(TransactionInfo& transaction, uint32_t flags, bool syncInputWindows,
                     int64_t desiredPresentTime) {
        mTransactionNumber++;
        transaction.flags |= flags; // ISurfaceComposer::eSynchronous;
        transaction.inputWindowCommands.syncInputWindows = syncInputWindows;
        transaction.desiredPresentTime = desiredPresentTime;
    }

    void NotPlacedOnTransactionQueue(uint32_t flags, bool syncInputWindows) {
        ASSERT_EQ(0, mFlinger.getTransactionQueue().size());
        // called in SurfaceFlinger::signalTransaction
        EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);
        EXPECT_CALL(*mPrimaryDispSync, expectedPresentTime(_)).WillOnce(Return(systemTime()));
        TransactionInfo transaction;
        setupSingle(transaction, flags, syncInputWindows,
                    /*desiredPresentTime*/ -1);
        nsecs_t applicationTime = systemTime();
        mFlinger.setTransactionState(transaction.states, transaction.displays, transaction.flags,
                                     transaction.applyToken, transaction.inputWindowCommands,
                                     transaction.desiredPresentTime, transaction.uncacheBuffer,
                                     mHasListenerCallbacks, mCallbacks);

        // This transaction should not have been placed on the transaction queue.
        // If transaction is synchronous or syncs input windows, SF
        // applyTransactionState should time out (5s) wating for SF to commit
        // the transaction or to receive a signal that syncInputWindows has
        // completed.  If this is animation, it should not time out waiting.
        nsecs_t returnedTime = systemTime();
        if (flags & ISurfaceComposer::eSynchronous || syncInputWindows) {
            EXPECT_GE(returnedTime, applicationTime + s2ns(5));
        } else {
            EXPECT_LE(returnedTime, applicationTime + s2ns(5));
        }
        auto transactionQueue = mFlinger.getTransactionQueue();
        EXPECT_EQ(0, transactionQueue.size());
    }

    void PlaceOnTransactionQueue(uint32_t flags, bool syncInputWindows) {
        ASSERT_EQ(0, mFlinger.getTransactionQueue().size());
        // called in SurfaceFlinger::signalTransaction
        EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

        // first check will see desired present time has not passed,
        // but afterwards it will look like the desired present time has passed
        nsecs_t time = systemTime();
        EXPECT_CALL(*mPrimaryDispSync, expectedPresentTime(_))
                .WillOnce(Return(time + nsecs_t(5 * 1e8)));
        TransactionInfo transaction;
        setupSingle(transaction, flags, syncInputWindows,
                    /*desiredPresentTime*/ time + s2ns(1));
        nsecs_t applicationSentTime = systemTime();
        mFlinger.setTransactionState(transaction.states, transaction.displays, transaction.flags,
                                     transaction.applyToken, transaction.inputWindowCommands,
                                     transaction.desiredPresentTime, transaction.uncacheBuffer,
                                     mHasListenerCallbacks, mCallbacks);

        nsecs_t returnedTime = systemTime();
        EXPECT_LE(returnedTime, applicationSentTime + s2ns(5));
        // This transaction should have been placed on the transaction queue
        auto transactionQueue = mFlinger.getTransactionQueue();
        EXPECT_EQ(1, transactionQueue.size());
    }

    void BlockedByPriorTransaction(uint32_t flags, bool syncInputWindows) {
        ASSERT_EQ(0, mFlinger.getTransactionQueue().size());
        // called in SurfaceFlinger::signalTransaction
        nsecs_t time = systemTime();
        EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);
        EXPECT_CALL(*mPrimaryDispSync, expectedPresentTime(_))
                .WillOnce(Return(time + nsecs_t(5 * 1e8)));
        // transaction that should go on the pending thread
        TransactionInfo transactionA;
        setupSingle(transactionA, /*flags*/ 0, /*syncInputWindows*/ false,
                    /*desiredPresentTime*/ time + s2ns(1));

        // transaction that would not have gone on the pending thread if not
        // blocked
        TransactionInfo transactionB;
        setupSingle(transactionB, flags, syncInputWindows,
                    /*desiredPresentTime*/ -1);

        nsecs_t applicationSentTime = systemTime();
        mFlinger.setTransactionState(transactionA.states, transactionA.displays, transactionA.flags,
                                     transactionA.applyToken, transactionA.inputWindowCommands,
                                     transactionA.desiredPresentTime, transactionA.uncacheBuffer,
                                     mHasListenerCallbacks, mCallbacks);

        // This thread should not have been blocked by the above transaction
        // (5s is the timeout period that applyTransactionState waits for SF to
        // commit the transaction)
        EXPECT_LE(systemTime(), applicationSentTime + s2ns(5));

        applicationSentTime = systemTime();
        mFlinger.setTransactionState(transactionB.states, transactionB.displays, transactionB.flags,
                                     transactionB.applyToken, transactionB.inputWindowCommands,
                                     transactionB.desiredPresentTime, transactionB.uncacheBuffer,
                                     mHasListenerCallbacks, mCallbacks);

        // this thread should have been blocked by the above transaction
        // if this is an animation, this thread should be blocked for 5s
        // in setTransactionState waiting for transactionA to flush.  Otherwise,
        // the transaction should be placed on the pending queue
        if (flags & ISurfaceComposer::eAnimation) {
            EXPECT_GE(systemTime(), applicationSentTime + s2ns(5));
        } else {
            EXPECT_LE(systemTime(), applicationSentTime + s2ns(5));
        }

        // check that there is one binder on the pending queue.
        auto transactionQueue = mFlinger.getTransactionQueue();
        EXPECT_EQ(1, transactionQueue.size());

        auto& [applyToken, transactionStates] = *(transactionQueue.begin());
        EXPECT_EQ(2, transactionStates.size());

        auto& transactionStateA = transactionStates.front();
        transactionStates.pop();
        checkEqual(transactionA, transactionStateA);
        auto& transactionStateB = transactionStates.front();
        checkEqual(transactionB, transactionStateB);
    }

    bool mHasListenerCallbacks = false;
    std::vector<ListenerCallbacks> mCallbacks;
    int mTransactionNumber = 0;
};

TEST_F(TransactionApplicationTest, Flush_RemovesFromQueue) {
    ASSERT_EQ(0, mFlinger.getTransactionQueue().size());
    // called in SurfaceFlinger::signalTransaction
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

    // nsecs_t time = systemTime();
    EXPECT_CALL(*mPrimaryDispSync, expectedPresentTime(_))
            .WillOnce(Return(nsecs_t(5 * 1e8)))
            .WillOnce(Return(s2ns(2)));
    TransactionInfo transactionA; // transaction to go on pending queue
    setupSingle(transactionA, /*flags*/ 0, /*syncInputWindows*/ false,
                /*desiredPresentTime*/ s2ns(1));
    mFlinger.setTransactionState(transactionA.states, transactionA.displays, transactionA.flags,
                                 transactionA.applyToken, transactionA.inputWindowCommands,
                                 transactionA.desiredPresentTime, transactionA.uncacheBuffer,
                                 mHasListenerCallbacks, mCallbacks);

    auto& transactionQueue = mFlinger.getTransactionQueue();
    ASSERT_EQ(1, transactionQueue.size());

    auto& [applyToken, transactionStates] = *(transactionQueue.begin());
    ASSERT_EQ(1, transactionStates.size());

    auto& transactionState = transactionStates.front();
    checkEqual(transactionA, transactionState);

    // because flushing uses the cached expected present time, we send an empty
    // transaction here (sending a null applyToken to fake it as from a
    // different process) to re-query and reset the cached expected present time
    TransactionInfo empty;
    empty.applyToken = sp<IBinder>();
    mFlinger.setTransactionState(empty.states, empty.displays, empty.flags, empty.applyToken,
                                 empty.inputWindowCommands, empty.desiredPresentTime,
                                 empty.uncacheBuffer, mHasListenerCallbacks, mCallbacks);

    // flush transaction queue should flush as desiredPresentTime has
    // passed
    mFlinger.flushTransactionQueues();

    EXPECT_EQ(0, transactionQueue.size());
}

TEST_F(TransactionApplicationTest, NotPlacedOnTransactionQueue_Synchronous) {
    NotPlacedOnTransactionQueue(ISurfaceComposer::eSynchronous, /*syncInputWindows*/ false);
}

TEST_F(TransactionApplicationTest, NotPlacedOnTransactionQueue_Animation) {
    NotPlacedOnTransactionQueue(ISurfaceComposer::eAnimation, /*syncInputWindows*/ false);
}

TEST_F(TransactionApplicationTest, NotPlacedOnTransactionQueue_SyncInputWindows) {
    NotPlacedOnTransactionQueue(/*flags*/ 0, /*syncInputWindows*/ true);
}

TEST_F(TransactionApplicationTest, PlaceOnTransactionQueue_Synchronous) {
    PlaceOnTransactionQueue(ISurfaceComposer::eSynchronous, /*syncInputWindows*/ false);
}

TEST_F(TransactionApplicationTest, PlaceOnTransactionQueue_Animation) {
    PlaceOnTransactionQueue(ISurfaceComposer::eAnimation, /*syncInputWindows*/ false);
}

TEST_F(TransactionApplicationTest, PlaceOnTransactionQueue_SyncInputWindows) {
    PlaceOnTransactionQueue(/*flags*/ 0, /*syncInputWindows*/ true);
}

TEST_F(TransactionApplicationTest, BlockWithPriorTransaction_Synchronous) {
    BlockedByPriorTransaction(ISurfaceComposer::eSynchronous, /*syncInputWindows*/ false);
}

TEST_F(TransactionApplicationTest, BlockWithPriorTransaction_Animation) {
    BlockedByPriorTransaction(ISurfaceComposer::eSynchronous, /*syncInputWindows*/ false);
}

TEST_F(TransactionApplicationTest, BlockWithPriorTransaction_SyncInputWindows) {
    BlockedByPriorTransaction(/*flags*/ 0, /*syncInputWindows*/ true);
}

TEST_F(TransactionApplicationTest, FromHandle) {
    sp<IBinder> badHandle;
    auto ret = mFlinger.fromHandle(badHandle);
    EXPECT_EQ(nullptr, ret.promote().get());
}
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
