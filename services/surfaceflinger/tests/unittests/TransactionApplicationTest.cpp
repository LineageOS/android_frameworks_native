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
#include "mock/MockEventThread.h"
#include "mock/MockMessageQueue.h"
#include "mock/MockVsyncController.h"

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
                .WillOnce(Return(new EventThreadConnection(eventThread.get(), /*callingUid=*/0,
                                                           ResyncCallback())));

        EXPECT_CALL(*sfEventThread, registerDisplayEventConnection(_));
        EXPECT_CALL(*sfEventThread, createEventConnection(_, _))
                .WillOnce(Return(new EventThreadConnection(sfEventThread.get(), /*callingUid=*/0,
                                                           ResyncCallback())));

        EXPECT_CALL(*mVSyncTracker, nextAnticipatedVSyncTimeFrom(_)).WillRepeatedly(Return(0));
        EXPECT_CALL(*mVSyncTracker, currentPeriod())
                .WillRepeatedly(Return(FakeHwcDisplayInjector::DEFAULT_VSYNC_PERIOD));

        mFlinger.setupScheduler(std::unique_ptr<mock::VsyncController>(mVsyncController),
                                std::unique_ptr<mock::VSyncTracker>(mVSyncTracker),
                                std::move(eventThread), std::move(sfEventThread));
    }

    TestableScheduler* mScheduler;
    TestableSurfaceFlinger mFlinger;

    std::unique_ptr<mock::EventThread> mEventThread = std::make_unique<mock::EventThread>();

    mock::MessageQueue* mMessageQueue = new mock::MessageQueue();
    mock::VsyncController* mVsyncController = new mock::VsyncController();
    mock::VSyncTracker* mVSyncTracker = new mock::VSyncTracker();

    struct TransactionInfo {
        Vector<ComposerState> states;
        Vector<DisplayState> displays;
        uint32_t flags = 0;
        sp<IBinder> applyToken = IInterface::asBinder(TransactionCompletedListener::getIInstance());
        InputWindowCommands inputWindowCommands;
        int64_t desiredPresentTime = 0;
        bool isAutoTimestamp = true;
        FrameTimelineInfo frameTimelineInfo;
        client_cache_t uncacheBuffer;
        uint64_t id = static_cast<uint64_t>(-1);
        static_assert(0xffffffffffffffff == static_cast<uint64_t>(-1));
    };

    void checkEqual(TransactionInfo info, SurfaceFlinger::TransactionState state) {
        EXPECT_EQ(0u, info.states.size());
        EXPECT_EQ(0u, state.states.size());

        EXPECT_EQ(0u, info.displays.size());
        EXPECT_EQ(0u, state.displays.size());
        EXPECT_EQ(info.flags, state.flags);
        EXPECT_EQ(info.desiredPresentTime, state.desiredPresentTime);
    }

    void setupSingle(TransactionInfo& transaction, uint32_t flags, bool syncInputWindows,
                     int64_t desiredPresentTime, bool isAutoTimestamp,
                     const FrameTimelineInfo& frameTimelineInfo) {
        mTransactionNumber++;
        transaction.flags |= flags; // ISurfaceComposer::eSynchronous;
        transaction.inputWindowCommands.syncInputWindows = syncInputWindows;
        transaction.desiredPresentTime = desiredPresentTime;
        transaction.isAutoTimestamp = isAutoTimestamp;
        transaction.frameTimelineInfo = frameTimelineInfo;
    }

    void NotPlacedOnTransactionQueue(uint32_t flags, bool syncInputWindows) {
        ASSERT_EQ(0u, mFlinger.getTransactionQueue().size());
        // called in SurfaceFlinger::signalTransaction
        EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);
        TransactionInfo transaction;
        setupSingle(transaction, flags, syncInputWindows,
                    /*desiredPresentTime*/ systemTime(), /*isAutoTimestamp*/ true,
                    FrameTimelineInfo{});
        nsecs_t applicationTime = systemTime();
        mFlinger.setTransactionState(transaction.frameTimelineInfo, transaction.states,
                                     transaction.displays, transaction.flags,
                                     transaction.applyToken, transaction.inputWindowCommands,
                                     transaction.desiredPresentTime, transaction.isAutoTimestamp,
                                     transaction.uncacheBuffer, mHasListenerCallbacks, mCallbacks,
                                     transaction.id);

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
        // Each transaction should have been placed on the transaction queue
        auto transactionQueue = mFlinger.getTransactionQueue();
        EXPECT_EQ(1u, transactionQueue.size());
    }

    void PlaceOnTransactionQueue(uint32_t flags, bool syncInputWindows) {
        ASSERT_EQ(0u, mFlinger.getTransactionQueue().size());
        // called in SurfaceFlinger::signalTransaction
        EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

        // first check will see desired present time has not passed,
        // but afterwards it will look like the desired present time has passed
        nsecs_t time = systemTime();
        TransactionInfo transaction;
        setupSingle(transaction, flags, syncInputWindows,
                    /*desiredPresentTime*/ time + s2ns(1), false, FrameTimelineInfo{});
        nsecs_t applicationSentTime = systemTime();
        mFlinger.setTransactionState(transaction.frameTimelineInfo, transaction.states,
                                     transaction.displays, transaction.flags,
                                     transaction.applyToken, transaction.inputWindowCommands,
                                     transaction.desiredPresentTime, transaction.isAutoTimestamp,
                                     transaction.uncacheBuffer, mHasListenerCallbacks, mCallbacks,
                                     transaction.id);

        nsecs_t returnedTime = systemTime();
        if ((flags & ISurfaceComposer::eSynchronous) || syncInputWindows) {
            EXPECT_GE(systemTime(), applicationSentTime + s2ns(5));
        } else {
            EXPECT_LE(returnedTime, applicationSentTime + s2ns(5));
        }
        // This transaction should have been placed on the transaction queue
        auto transactionQueue = mFlinger.getTransactionQueue();
        EXPECT_EQ(1u, transactionQueue.size());
    }

    void BlockedByPriorTransaction(uint32_t flags, bool syncInputWindows) {
        ASSERT_EQ(0u, mFlinger.getTransactionQueue().size());
        // called in SurfaceFlinger::signalTransaction
        nsecs_t time = systemTime();
        if (!syncInputWindows) {
            EXPECT_CALL(*mMessageQueue, invalidate()).Times(2);
        } else {
            EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);
        }
        // transaction that should go on the pending thread
        TransactionInfo transactionA;
        setupSingle(transactionA, /*flags*/ 0, /*syncInputWindows*/ false,
                    /*desiredPresentTime*/ time + s2ns(1), false, FrameTimelineInfo{});

        // transaction that would not have gone on the pending thread if not
        // blocked
        TransactionInfo transactionB;
        setupSingle(transactionB, flags, syncInputWindows,
                    /*desiredPresentTime*/ systemTime(), /*isAutoTimestamp*/ true,
                    FrameTimelineInfo{});

        nsecs_t applicationSentTime = systemTime();
        mFlinger.setTransactionState(transactionA.frameTimelineInfo, transactionA.states,
                                     transactionA.displays, transactionA.flags,
                                     transactionA.applyToken, transactionA.inputWindowCommands,
                                     transactionA.desiredPresentTime, transactionA.isAutoTimestamp,
                                     transactionA.uncacheBuffer, mHasListenerCallbacks, mCallbacks,
                                     transactionA.id);

        // This thread should not have been blocked by the above transaction
        // (5s is the timeout period that applyTransactionState waits for SF to
        // commit the transaction)
        EXPECT_LE(systemTime(), applicationSentTime + s2ns(5));
        // transaction that would goes to pending transaciton queue.
        mFlinger.flushTransactionQueues();

        applicationSentTime = systemTime();
        mFlinger.setTransactionState(transactionB.frameTimelineInfo, transactionB.states,
                                     transactionB.displays, transactionB.flags,
                                     transactionB.applyToken, transactionB.inputWindowCommands,
                                     transactionB.desiredPresentTime, transactionB.isAutoTimestamp,
                                     transactionB.uncacheBuffer, mHasListenerCallbacks, mCallbacks,
                                     transactionB.id);

        // this thread should have been blocked by the above transaction
        // if this is an animation, this thread should be blocked for 5s
        // in setTransactionState waiting for transactionA to flush.  Otherwise,
        // the transaction should be placed on the pending queue
        if (flags & (ISurfaceComposer::eAnimation | ISurfaceComposer::eSynchronous) ||
            syncInputWindows) {
            EXPECT_GE(systemTime(), applicationSentTime + s2ns(5));
        } else {
            EXPECT_LE(systemTime(), applicationSentTime + s2ns(5));
        }

        // transaction that would goes to pending transaciton queue.
        mFlinger.flushTransactionQueues();

        // check that the transaction was applied.
        auto transactionQueue = mFlinger.getPendingTransactionQueue();
        EXPECT_EQ(0u, transactionQueue.size());
    }

    bool mHasListenerCallbacks = false;
    std::vector<ListenerCallbacks> mCallbacks;
    int mTransactionNumber = 0;
};

TEST_F(TransactionApplicationTest, Flush_RemovesFromQueue) {
    ASSERT_EQ(0u, mFlinger.getTransactionQueue().size());
    // called in SurfaceFlinger::signalTransaction
    EXPECT_CALL(*mMessageQueue, invalidate()).Times(1);

    TransactionInfo transactionA; // transaction to go on pending queue
    setupSingle(transactionA, /*flags*/ 0, /*syncInputWindows*/ false,
                /*desiredPresentTime*/ s2ns(1), false, FrameTimelineInfo{});
    mFlinger.setTransactionState(transactionA.frameTimelineInfo, transactionA.states,
                                 transactionA.displays, transactionA.flags, transactionA.applyToken,
                                 transactionA.inputWindowCommands, transactionA.desiredPresentTime,
                                 transactionA.isAutoTimestamp, transactionA.uncacheBuffer,
                                 mHasListenerCallbacks, mCallbacks, transactionA.id);

    auto& transactionQueue = mFlinger.getTransactionQueue();
    ASSERT_EQ(1u, transactionQueue.size());

    auto& transactionState = transactionQueue.front();
    checkEqual(transactionA, transactionState);

    // because flushing uses the cached expected present time, we send an empty
    // transaction here (sending a null applyToken to fake it as from a
    // different process) to re-query and reset the cached expected present time
    TransactionInfo empty;
    empty.applyToken = sp<IBinder>();
    mFlinger.setTransactionState(empty.frameTimelineInfo, empty.states, empty.displays, empty.flags,
                                 empty.applyToken, empty.inputWindowCommands,
                                 empty.desiredPresentTime, empty.isAutoTimestamp,
                                 empty.uncacheBuffer, mHasListenerCallbacks, mCallbacks, empty.id);

    // flush transaction queue should flush as desiredPresentTime has
    // passed
    mFlinger.flushTransactionQueues();

    EXPECT_EQ(0u, transactionQueue.size());
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
