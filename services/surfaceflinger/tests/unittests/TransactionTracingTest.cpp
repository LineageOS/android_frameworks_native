/*
 * Copyright 2021 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <gui/SurfaceComposerClient.h>
#include <cstdint>
#include "Client.h"

#include <layerproto/LayerProtoHeader.h>
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/Update.h"
#include "Tracing/LayerTracing.h"
#include "Tracing/RingBuffer.h"
#include "Tracing/TransactionTracing.h"

using namespace android::surfaceflinger;

namespace android {

class TransactionTracingTest : public testing::Test {
protected:
    static constexpr size_t SMALL_BUFFER_SIZE = 1024;
    TransactionTracing mTracing;

    void flush(int64_t vsyncId) { mTracing.flush(vsyncId); }
    proto::TransactionTraceFile writeToProto() { return mTracing.writeToProto(); }

    proto::TransactionTraceEntry bufferFront() {
        std::scoped_lock<std::mutex> lock(mTracing.mTraceLock);
        proto::TransactionTraceEntry entry;
        entry.ParseFromString(mTracing.mBuffer.front());
        return entry;
    }

    void queueAndCommitTransaction(int64_t vsyncId) {
        frontend::Update update;
        TransactionState transaction;
        transaction.id = static_cast<uint64_t>(vsyncId * 3);
        transaction.originUid = 1;
        transaction.originPid = 2;
        mTracing.addQueuedTransaction(transaction);
        std::vector<TransactionState> transactions;
        update.transactions.emplace_back(transaction);
        mTracing.addCommittedTransactions(vsyncId, 0, update, {}, false);
        flush(vsyncId);
    }

    void verifyEntry(const proto::TransactionTraceEntry& actualProto,
                     const std::vector<TransactionState>& expectedTransactions,
                     int64_t expectedVsyncId) {
        EXPECT_EQ(actualProto.vsync_id(), expectedVsyncId);
        ASSERT_EQ(actualProto.transactions().size(),
                  static_cast<int32_t>(expectedTransactions.size()));
        for (uint32_t i = 0; i < expectedTransactions.size(); i++) {
            const auto expectedTransaction = expectedTransactions[i];
            const auto protoTransaction = actualProto.transactions(static_cast<int32_t>(i));
            EXPECT_EQ(protoTransaction.transaction_id(), expectedTransaction.id);
            EXPECT_EQ(protoTransaction.pid(), expectedTransaction.originPid);
            for (uint32_t i = 0; i < expectedTransaction.mergedTransactionIds.size(); i++) {
                EXPECT_EQ(protoTransaction.merged_transaction_ids(static_cast<int32_t>(i)),
                          expectedTransaction.mergedTransactionIds[i]);
            }
        }
    }

    LayerCreationArgs getLayerCreationArgs(uint32_t layerId, uint32_t parentId,
                                           uint32_t layerIdToMirror, uint32_t flags,
                                           bool addToRoot) {
        LayerCreationArgs args;
        args.sequence = layerId;
        args.parentId = parentId;
        args.layerIdToMirror = layerIdToMirror;
        args.flags = flags;
        args.addToRoot = addToRoot;
        return args;
    }
};

TEST_F(TransactionTracingTest, addTransactions) {
    std::vector<TransactionState> transactions;
    transactions.reserve(100);
    for (uint64_t i = 0; i < 100; i++) {
        TransactionState transaction;
        transaction.id = i;
        transaction.originPid = static_cast<int32_t>(i);
        transaction.mergedTransactionIds = std::vector<uint64_t>{i + 100, i + 102};
        transactions.emplace_back(transaction);
        mTracing.addQueuedTransaction(transaction);
    }

    // Split incoming transactions into two and commit them in reverse order to test out of order
    // commits.
    int64_t firstTransactionSetVsyncId = 42;
    frontend::Update firstUpdate;
    firstUpdate.transactions =
            std::vector<TransactionState>(transactions.begin() + 50, transactions.end());
    mTracing.addCommittedTransactions(firstTransactionSetVsyncId, 0, firstUpdate, {}, false);

    int64_t secondTransactionSetVsyncId = 43;
    frontend::Update secondUpdate;
    secondUpdate.transactions =
            std::vector<TransactionState>(transactions.begin(), transactions.begin() + 50);
    mTracing.addCommittedTransactions(secondTransactionSetVsyncId, 0, secondUpdate, {}, false);
    flush(secondTransactionSetVsyncId);

    proto::TransactionTraceFile proto = writeToProto();
    ASSERT_EQ(proto.entry().size(), 2);
    verifyEntry(proto.entry(0), firstUpdate.transactions, firstTransactionSetVsyncId);
    verifyEntry(proto.entry(1), secondUpdate.transactions, secondTransactionSetVsyncId);
}

class TransactionTracingLayerHandlingTest : public TransactionTracingTest {
protected:
    void SetUp() override {
        mTracing.setBufferSize(SMALL_BUFFER_SIZE);

        // add layers and add some layer transaction
        {
            frontend::Update update;
            update.layerCreationArgs.emplace_back(std::move(
                    getLayerCreationArgs(mParentLayerId, /*parentId=*/UNASSIGNED_LAYER_ID,
                                         /*layerIdToMirror=*/UNASSIGNED_LAYER_ID, /*flags=*/123,
                                         /*addToRoot=*/true)));
            update.layerCreationArgs.emplace_back(std::move(
                    getLayerCreationArgs(mChildLayerId, mParentLayerId,
                                         /*layerIdToMirror=*/UNASSIGNED_LAYER_ID, /*flags=*/456,
                                         /*addToRoot=*/true)));
            TransactionState transaction;
            transaction.id = 50;
            ResolvedComposerState layerState;
            layerState.layerId = mParentLayerId;
            layerState.state.what = layer_state_t::eLayerChanged;
            layerState.state.z = 42;
            transaction.states.emplace_back(layerState);
            ResolvedComposerState childState;
            childState.layerId = mChildLayerId;
            childState.state.what = layer_state_t::eLayerChanged;
            childState.state.z = 43;
            transaction.states.emplace_back(childState);
            mTracing.addQueuedTransaction(transaction);

            update.transactions.emplace_back(transaction);
            VSYNC_ID_FIRST_LAYER_CHANGE = ++mVsyncId;
            mTracing.addCommittedTransactions(VSYNC_ID_FIRST_LAYER_CHANGE, 0, update, {}, false);

            flush(VSYNC_ID_FIRST_LAYER_CHANGE);
        }

        // add transactions that modify the layer state further so we can test that layer state
        // gets merged
        {
            TransactionState transaction;
            transaction.id = 51;
            ResolvedComposerState layerState;
            layerState.layerId = mParentLayerId;
            layerState.state.what = layer_state_t::eLayerChanged | layer_state_t::ePositionChanged;
            layerState.state.z = 41;
            layerState.state.x = 22;
            transaction.states.emplace_back(layerState);
            mTracing.addQueuedTransaction(transaction);

            frontend::Update update;
            update.transactions.emplace_back(transaction);
            VSYNC_ID_SECOND_LAYER_CHANGE = ++mVsyncId;
            mTracing.addCommittedTransactions(VSYNC_ID_SECOND_LAYER_CHANGE, 0, update, {}, false);
            flush(VSYNC_ID_SECOND_LAYER_CHANGE);
        }

        // remove child layer
        mTracing.onLayerRemoved(2);
        VSYNC_ID_CHILD_LAYER_REMOVED = ++mVsyncId;
        queueAndCommitTransaction(VSYNC_ID_CHILD_LAYER_REMOVED);

        // remove layer
        mTracing.onLayerRemoved(1);
        queueAndCommitTransaction(++mVsyncId);
    }

    uint32_t mParentLayerId = 1;
    uint32_t mChildLayerId = 2;
    int64_t mVsyncId = 0;
    int64_t VSYNC_ID_FIRST_LAYER_CHANGE;
    int64_t VSYNC_ID_SECOND_LAYER_CHANGE;
    int64_t VSYNC_ID_CHILD_LAYER_REMOVED;
};

TEST_F(TransactionTracingLayerHandlingTest, addStartingState) {
    // add transactions until we drop the transaction with the first layer change
    while (bufferFront().vsync_id() <= VSYNC_ID_FIRST_LAYER_CHANGE) {
        queueAndCommitTransaction(++mVsyncId);
    }
    proto::TransactionTraceFile proto = writeToProto();
    // verify we can still retrieve the layer change from the first entry containing starting
    // states.
    EXPECT_GT(proto.entry().size(), 0);
    EXPECT_EQ(proto.entry(0).transactions().size(), 1);
    EXPECT_EQ(proto.entry(0).added_layers().size(), 2);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes().size(), 2);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes(0).layer_id(), mParentLayerId);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes(0).z(), 42);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes(1).layer_id(), mChildLayerId);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes(1).z(), 43);
}

TEST_F(TransactionTracingLayerHandlingTest, updateStartingState) {
    // add transactions until we drop the transaction with the second layer change
    while (bufferFront().vsync_id() <= VSYNC_ID_SECOND_LAYER_CHANGE) {
        queueAndCommitTransaction(++mVsyncId);
    }
    proto::TransactionTraceFile proto = writeToProto();
    // verify starting states are updated correctly
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes(0).z(), 41);
}

TEST_F(TransactionTracingLayerHandlingTest, removeStartingState) {
    // add transactions until we drop the transaction which removes the child layer
    while (bufferFront().vsync_id() <= VSYNC_ID_CHILD_LAYER_REMOVED) {
        queueAndCommitTransaction(++mVsyncId);
    }
    proto::TransactionTraceFile proto = writeToProto();
    // verify the child layer has been removed from the trace
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes().size(), 1);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes(0).layer_id(), mParentLayerId);
}

TEST_F(TransactionTracingLayerHandlingTest, startingStateSurvivesBufferFlush) {
    // add transactions until we drop the transaction with the second layer change
    while (bufferFront().vsync_id() <= VSYNC_ID_SECOND_LAYER_CHANGE) {
        queueAndCommitTransaction(++mVsyncId);
    }
    proto::TransactionTraceFile proto = writeToProto();
    // verify we have two starting states
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes().size(), 2);

    // Continue adding transactions until child layer is removed
    while (bufferFront().vsync_id() <= VSYNC_ID_CHILD_LAYER_REMOVED) {
        queueAndCommitTransaction(++mVsyncId);
    }
    proto = writeToProto();
    // verify we still have the parent layer state
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes().size(), 1);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes(0).layer_id(), mParentLayerId);
}

class TransactionTracingMirrorLayerTest : public TransactionTracingTest {
protected:
    void SetUp() override {
        mTracing.setBufferSize(SMALL_BUFFER_SIZE);

        // add layers and some layer transaction
        {
            frontend::Update update;
            update.layerCreationArgs.emplace_back(
                    getLayerCreationArgs(mLayerId, /*parentId=*/UNASSIGNED_LAYER_ID,
                                         /*layerIdToMirror=*/UNASSIGNED_LAYER_ID, /*flags=*/123,
                                         /*addToRoot=*/true));
            update.layerCreationArgs.emplace_back(
                    getLayerCreationArgs(mMirrorLayerId, UNASSIGNED_LAYER_ID,
                                         /*layerIdToMirror=*/mLayerId, /*flags=*/0,
                                         /*addToRoot=*/false));

            TransactionState transaction;
            transaction.id = 50;
            ResolvedComposerState layerState;
            layerState.layerId = mLayerId;
            layerState.state.what = layer_state_t::eLayerChanged;
            layerState.state.z = 42;
            transaction.states.emplace_back(layerState);
            ResolvedComposerState mirrorState;
            mirrorState.layerId = mMirrorLayerId;
            mirrorState.state.what = layer_state_t::eLayerChanged;
            mirrorState.state.z = 43;
            transaction.states.emplace_back(mirrorState);
            mTracing.addQueuedTransaction(transaction);

            update.transactions.emplace_back(transaction);
            mTracing.addCommittedTransactions(mVsyncId, 0, update, {}, false);
            flush(mVsyncId);
        }
    }

    uint32_t mLayerId = 5;
    uint32_t mMirrorLayerId = 55;
    int64_t mVsyncId = 0;
    int64_t VSYNC_ID_FIRST_LAYER_CHANGE;
    int64_t VSYNC_ID_SECOND_LAYER_CHANGE;
    int64_t VSYNC_ID_CHILD_LAYER_REMOVED;
};

TEST_F(TransactionTracingMirrorLayerTest, canAddMirrorLayers) {
    proto::TransactionTraceFile proto = writeToProto();
    // We don't have any starting states since no layer was removed from.
    EXPECT_EQ(proto.entry().size(), 1);

    // Verify the mirror layer was added
    EXPECT_EQ(proto.entry(0).transactions().size(), 1);
    EXPECT_EQ(proto.entry(0).added_layers().size(), 2);
    EXPECT_EQ(proto.entry(0).added_layers(1).layer_id(), mMirrorLayerId);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes().size(), 2);
    EXPECT_EQ(proto.entry(0).transactions(0).layer_changes(1).z(), 43);
}

// Verify we can write the layers traces by entry to reduce mem pressure
// on the system when generating large traces.
TEST(LayerTraceTest, canStreamLayersTrace) {
    LayersTraceFileProto inProto = LayerTracing::createTraceFileProto();
    inProto.add_entry();
    inProto.add_entry();

    std::string output;
    inProto.SerializeToString(&output);
    LayersTraceFileProto inProto2 = LayerTracing::createTraceFileProto();
    inProto2.add_entry();
    std::string output2;
    inProto2.SerializeToString(&output2);

    LayersTraceFileProto outProto;
    outProto.ParseFromString(output + output2);
    // magic?
    EXPECT_EQ(outProto.entry().size(), 3);
}
} // namespace android
