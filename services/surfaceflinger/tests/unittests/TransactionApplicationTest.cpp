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
#include <ui/MockFence.h>
#include <utils/String8.h>

#include "TestableSurfaceFlinger.h"
#include "mock/MockEventThread.h"
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

        mFlinger.setupComposer(std::make_unique<Hwc2::mock::Composer>());
        mFlinger.setupScheduler(std::unique_ptr<mock::VsyncController>(mVsyncController),
                                std::unique_ptr<mock::VSyncTracker>(mVSyncTracker),
                                std::move(eventThread), std::move(sfEventThread));
    }

    TestableSurfaceFlinger mFlinger;

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

    void checkEqual(TransactionInfo info, TransactionState state) {
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
        EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);
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
            EXPECT_GE(returnedTime, applicationTime + mFlinger.getAnimationTransactionTimeout());
        } else {
            EXPECT_LE(returnedTime, applicationTime + mFlinger.getAnimationTransactionTimeout());
        }
        // Each transaction should have been placed on the transaction queue
        auto transactionQueue = mFlinger.getTransactionQueue();
        EXPECT_EQ(1u, transactionQueue.size());
    }

    void PlaceOnTransactionQueue(uint32_t flags, bool syncInputWindows) {
        ASSERT_EQ(0u, mFlinger.getTransactionQueue().size());
        EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

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
            EXPECT_GE(systemTime(),
                      applicationSentTime + mFlinger.getAnimationTransactionTimeout());
        } else {
            EXPECT_LE(returnedTime,
                      applicationSentTime + mFlinger.getAnimationTransactionTimeout());
        }
        // This transaction should have been placed on the transaction queue
        auto transactionQueue = mFlinger.getTransactionQueue();
        EXPECT_EQ(1u, transactionQueue.size());
    }

    void BlockedByPriorTransaction(uint32_t flags, bool syncInputWindows) {
        ASSERT_EQ(0u, mFlinger.getTransactionQueue().size());
        nsecs_t time = systemTime();
        if (!syncInputWindows) {
            EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(2);
        } else {
            EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);
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
        EXPECT_LE(systemTime(), applicationSentTime + mFlinger.getAnimationTransactionTimeout());
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
        if (flags & (ISurfaceComposer::eSynchronous) ||
            syncInputWindows) {
            EXPECT_GE(systemTime(),
                      applicationSentTime + mFlinger.getAnimationTransactionTimeout());
        } else {
            EXPECT_LE(systemTime(),
                      applicationSentTime + mFlinger.getAnimationTransactionTimeout());
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
    EXPECT_CALL(*mFlinger.scheduler(), scheduleFrame()).Times(1);

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

TEST_F(TransactionApplicationTest, NotPlacedOnTransactionQueue_SyncInputWindows) {
    NotPlacedOnTransactionQueue(/*flags*/ 0, /*syncInputWindows*/ true);
}

TEST_F(TransactionApplicationTest, PlaceOnTransactionQueue_Synchronous) {
    PlaceOnTransactionQueue(ISurfaceComposer::eSynchronous, /*syncInputWindows*/ false);
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

class LatchUnsignaledTest : public TransactionApplicationTest {
public:
    void TearDown() override {
        // Clear all transaction queues to release all transactions we sent
        // in the tests. Otherwise, gmock complains about memory leaks.
        mFlinger.getTransactionQueue().clear();
        mFlinger.getPendingTransactionQueue().clear();
        mFlinger.getTransactionCommittedSignals().clear();
        mFlinger.commitTransactionsLocked(eTransactionMask);
        mFlinger.mutableCurrentState().layersSortedByZ.clear();
        mFlinger.mutableDrawingState().layersSortedByZ.clear();
    }

    static sp<Fence> fence(Fence::Status status) {
        const auto fence = sp<mock::MockFence>::make();
        EXPECT_CALL(*fence, getStatus()).WillRepeatedly(Return(status));
        return fence;
    }

    ComposerState createComposerState(int layerId, sp<Fence> fence, uint64_t what) {
        ComposerState state;
        state.state.bufferData = std::make_shared<BufferData>();
        state.state.bufferData->acquireFence = std::move(fence);
        state.state.layerId = layerId;
        state.state.surface =
                sp<BufferStateLayer>::make(
                        LayerCreationArgs(mFlinger.flinger(), nullptr, "TestLayer", 0, {}))
                        ->getHandle();
        state.state.bufferData->flags = BufferData::BufferDataChange::fenceChanged;

        state.state.what = what;
        if (what & layer_state_t::eCropChanged) {
            state.state.crop = Rect(1, 2, 3, 4);
        }
        return state;
    }

    TransactionInfo createTransactionInfo(const sp<IBinder>& applyToken,
                                          const std::vector<ComposerState>& states) {
        TransactionInfo transaction;
        const uint32_t kFlags = ISurfaceComposer::eSynchronous;
        const bool kSyncInputWindows = false;
        const nsecs_t kDesiredPresentTime = systemTime();
        const bool kIsAutoTimestamp = true;
        const auto kFrameTimelineInfo = FrameTimelineInfo{};

        setupSingle(transaction, kFlags, kSyncInputWindows, kDesiredPresentTime, kIsAutoTimestamp,
                    kFrameTimelineInfo);
        transaction.applyToken = applyToken;
        for (const auto& state : states) {
            transaction.states.push_back(state);
        }

        return transaction;
    }

    void setTransactionStates(const std::vector<TransactionInfo>& transactions,
                              size_t expectedTransactionsApplied,
                              size_t expectedTransactionsPending) {
        EXPECT_EQ(0u, mFlinger.getTransactionQueue().size());
        EXPECT_EQ(0u, mFlinger.getPendingTransactionQueue().size());

        for (const auto& transaction : transactions) {
            mFlinger.setTransactionState(transaction.frameTimelineInfo, transaction.states,
                                         transaction.displays, transaction.flags,
                                         transaction.applyToken, transaction.inputWindowCommands,
                                         transaction.desiredPresentTime,
                                         transaction.isAutoTimestamp, transaction.uncacheBuffer,
                                         mHasListenerCallbacks, mCallbacks, transaction.id);
        }
        mFlinger.flushTransactionQueues();
        EXPECT_EQ(0u, mFlinger.getTransactionQueue().size());
        EXPECT_EQ(expectedTransactionsPending, mFlinger.getPendingTransactionQueue().size());
        EXPECT_EQ(expectedTransactionsApplied, mFlinger.getTransactionCommittedSignals().size());
    }
};

class LatchUnsignaledAutoSingleLayerTest : public LatchUnsignaledTest {
public:
    void SetUp() override {
        LatchUnsignaledTest::SetUp();
        SurfaceFlinger::enableLatchUnsignaledConfig = LatchUnsignaledConfig::AutoSingleLayer;
    }
};

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_RemovesSingleSignaledFromTheQueue) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 0u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {createComposerState(kLayerId, fence(Fence::Status::Signaled),
                                                       layer_state_t::eBufferChanged)});
    setTransactionStates({signaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_RemovesSingleUnSignaledFromTheQueue) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 0u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_KeepsUnSignaledInTheQueue_NonBufferCropChange) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eCropChanged),
                                  });
    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_KeepsUnSignaledInTheQueue_NonBufferChangeClubed) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eCropChanged |
                                                                      layer_state_t::
                                                                              eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_KeepsInTheQueueSameApplyTokenMultiState) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto mixedTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({mixedTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_KeepsInTheQueue_MultipleStateTransaction) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto mixedTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({mixedTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_RemovesSignaledFromTheQueue) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 2u;
    const auto kExpectedTransactionsPending = 0u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto signaledTransaction2 =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({signaledTransaction, signaledTransaction2}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest,
       UnsignaledNotAppliedWhenThereAreSignaled_UnsignaledFirst) {
    const sp<IBinder> kApplyToken1 =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const sp<IBinder> kApplyToken2 = sp<BBinder>::make();
    const sp<IBinder> kApplyToken3 = sp<BBinder>::make();
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 2u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken1,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken2,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto signaledTransaction2 =
            createTransactionInfo(kApplyToken3,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });

    setTransactionStates({unsignaledTransaction, signaledTransaction, signaledTransaction2},
                         kExpectedTransactionsApplied, kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, UnsignaledNotAppliedWhenThereAreSignaled_SignaledFirst) {
    const sp<IBinder> kApplyToken1 =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const sp<IBinder> kApplyToken2 = sp<BBinder>::make();
    const sp<IBinder> kApplyToken3 = sp<BBinder>::make();
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 2u;
    const auto kExpectedTransactionsPending = 1u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken1,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto signaledTransaction2 =
            createTransactionInfo(kApplyToken2,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken3,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });

    setTransactionStates({signaledTransaction, signaledTransaction2, unsignaledTransaction},
                         kExpectedTransactionsApplied, kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_KeepsTransactionInTheQueueSameApplyToken) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction, signaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, Flush_KeepsTransactionInTheQueue) {
    const sp<IBinder> kApplyToken1 =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const sp<IBinder> kApplyToken2 = sp<BBinder>::make();
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken1,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto unsignaledTransaction2 =
            createTransactionInfo(kApplyToken2,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction, unsignaledTransaction2},
                         kExpectedTransactionsApplied, kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAutoSingleLayerTest, DontLatchUnsignaledWhenEarlyOffset) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });

    // Get VsyncModulator out of the default config
    static_cast<void>(mFlinger.mutableVsyncModulator()->onRefreshRateChangeInitiated());

    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

class LatchUnsignaledDisabledTest : public LatchUnsignaledTest {
public:
    void SetUp() override {
        LatchUnsignaledTest::SetUp();
        SurfaceFlinger::enableLatchUnsignaledConfig = LatchUnsignaledConfig::Disabled;
    }
};

TEST_F(LatchUnsignaledDisabledTest, Flush_RemovesSignaledFromTheQueue) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 0u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {createComposerState(kLayerId, fence(Fence::Status::Signaled),
                                                       layer_state_t::eBufferChanged)});
    setTransactionStates({signaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledDisabledTest, Flush_KeepsInTheQueue) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledDisabledTest, Flush_KeepsInTheQueueSameLayerId) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledDisabledTest, Flush_KeepsInTheQueueDifferentLayerId) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledDisabledTest, Flush_RemovesSignaledFromTheQueue_MultipleLayers) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 2u;
    const auto kExpectedTransactionsPending = 0u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto signaledTransaction2 =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({signaledTransaction, signaledTransaction2}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledDisabledTest, Flush_KeepInTheQueueDifferentApplyToken) {
    const sp<IBinder> kApplyToken1 =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const sp<IBinder> kApplyToken2 = sp<BBinder>::make();
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken1,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto signaledTransaction =
            createTransactionInfo(kApplyToken2,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction, signaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledDisabledTest, Flush_KeepInTheQueueSameApplyToken) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 1u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({signaledTransaction, unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledDisabledTest, Flush_KeepInTheUnsignaledTheQueue) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 0u;
    const auto kExpectedTransactionsPending = 1u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto unsignaledTransaction2 =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction, unsignaledTransaction2},
                         kExpectedTransactionsApplied, kExpectedTransactionsPending);
}

class LatchUnsignaledAlwaysTest : public LatchUnsignaledTest {
public:
    void SetUp() override {
        LatchUnsignaledTest::SetUp();
        SurfaceFlinger::enableLatchUnsignaledConfig = LatchUnsignaledConfig::Always;
    }
};

TEST_F(LatchUnsignaledAlwaysTest, Flush_RemovesSignaledFromTheQueue) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 0u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {createComposerState(kLayerId, fence(Fence::Status::Signaled),
                                                       layer_state_t::eBufferChanged)});
    setTransactionStates({signaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAlwaysTest, Flush_RemovesFromTheQueue) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 0u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {createComposerState(kLayerId, fence(Fence::Status::Unsignaled),
                                                       layer_state_t::eBufferChanged)});
    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAlwaysTest, Flush_RemovesFromTheQueueSameLayerId) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 0u;

    const auto mixedTransaction =
            createTransactionInfo(kApplyToken,
                                  {createComposerState(kLayerId, fence(Fence::Status::Unsignaled),
                                                       layer_state_t::eBufferChanged),
                                   createComposerState(kLayerId, fence(Fence::Status::Signaled),
                                                       layer_state_t::eBufferChanged)});
    setTransactionStates({mixedTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAlwaysTest, Flush_RemovesFromTheQueueDifferentLayerId) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 0u;

    const auto mixedTransaction =
            createTransactionInfo(kApplyToken,
                                  {createComposerState(kLayerId1, fence(Fence::Status::Unsignaled),
                                                       layer_state_t::eBufferChanged),
                                   createComposerState(kLayerId2, fence(Fence::Status::Signaled),
                                                       layer_state_t::eBufferChanged)});
    setTransactionStates({mixedTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAlwaysTest, Flush_RemovesSignaledFromTheQueue_MultipleLayers) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 2u;
    const auto kExpectedTransactionsPending = 0u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto signaledTransaction2 =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({signaledTransaction, signaledTransaction2}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAlwaysTest, Flush_RemovesFromTheQueueDifferentApplyToken) {
    const sp<IBinder> kApplyToken1 =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const sp<IBinder> kApplyToken2 = sp<BBinder>::make();
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 2u;
    const auto kExpectedTransactionsPending = 0u;

    const auto signaledTransaction =
            createTransactionInfo(kApplyToken1,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken2,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({signaledTransaction, unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAlwaysTest, Flush_RemovesUnsignaledFromTheQueueSameApplyToken) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 2u;
    const auto kExpectedTransactionsPending = 0u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto signaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Signaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction, signaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAlwaysTest, Flush_RemovesUnsignaledFromTheQueue) {
    const sp<IBinder> kApplyToken1 =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const sp<IBinder> kApplyToken2 = sp<BBinder>::make();
    const auto kLayerId1 = 1;
    const auto kLayerId2 = 2;
    const auto kExpectedTransactionsApplied = 2u;
    const auto kExpectedTransactionsPending = 0u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken1,
                                  {
                                          createComposerState(kLayerId1,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    const auto unsignaledTransaction2 =
            createTransactionInfo(kApplyToken2,
                                  {
                                          createComposerState(kLayerId2,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });
    setTransactionStates({unsignaledTransaction, unsignaledTransaction2},
                         kExpectedTransactionsApplied, kExpectedTransactionsPending);
}

TEST_F(LatchUnsignaledAlwaysTest, LatchUnsignaledWhenEarlyOffset) {
    const sp<IBinder> kApplyToken =
            IInterface::asBinder(TransactionCompletedListener::getIInstance());
    const auto kLayerId = 1;
    const auto kExpectedTransactionsApplied = 1u;
    const auto kExpectedTransactionsPending = 0u;

    const auto unsignaledTransaction =
            createTransactionInfo(kApplyToken,
                                  {
                                          createComposerState(kLayerId,
                                                              fence(Fence::Status::Unsignaled),
                                                              layer_state_t::eBufferChanged),
                                  });

    // Get VsyncModulator out of the default config
    static_cast<void>(mFlinger.mutableVsyncModulator()->onRefreshRateChangeInitiated());

    setTransactionStates({unsignaledTransaction}, kExpectedTransactionsApplied,
                         kExpectedTransactionsPending);
}

} // namespace android
