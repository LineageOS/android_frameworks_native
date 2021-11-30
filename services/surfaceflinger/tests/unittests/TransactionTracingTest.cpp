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

#include "Tracing/RingBuffer.h"
#include "Tracing/TransactionTracing.h"

using namespace android::surfaceflinger;

namespace android {

class TransactionTracingTest : public testing::Test {
protected:
    std::unique_ptr<android::TransactionTracing> mTracing;

    void SetUp() override { mTracing = std::make_unique<android::TransactionTracing>(); }

    void TearDown() override { mTracing.reset(); }

    auto getCommittedTransactions() {
        std::scoped_lock<std::mutex> lock(mTracing->mMainThreadLock);
        return mTracing->mCommittedTransactions;
    }

    auto getQueuedTransactions() {
        std::scoped_lock<std::mutex> lock(mTracing->mTraceLock);
        return mTracing->mQueuedTransactions;
    }

    auto getUsedBufferSize() {
        std::scoped_lock<std::mutex> lock(mTracing->mTraceLock);
        return mTracing->mBuffer->used();
    }

    auto flush() { return mTracing->flush(); }

    auto bufferFront() {
        std::scoped_lock<std::mutex> lock(mTracing->mTraceLock);
        return mTracing->mBuffer->front();
    }

    bool threadIsJoinable() {
        std::scoped_lock lock(mTracing->mMainThreadLock);
        return mTracing->mThread.joinable();
    }

    std::string writeToString() {
        std::scoped_lock<std::mutex> lock(mTracing->mTraceLock);
        std::string output;
        proto::TransactionTraceFile fileProto = mTracing->createTraceFileProto();
        mTracing->mBuffer->writeToString(fileProto, &output);
        return output;
    }

    // Test that we clean up the tracing thread and free any memory allocated.
    void verifyDisabledTracingState() {
        EXPECT_FALSE(mTracing->isEnabled());
        EXPECT_FALSE(threadIsJoinable());
        EXPECT_EQ(getCommittedTransactions().size(), 0u);
        EXPECT_EQ(getQueuedTransactions().size(), 0u);
        EXPECT_EQ(getUsedBufferSize(), 0u);
    }

    void verifyEntry(const proto::TransactionTraceEntry& actualProto,
                     const std::vector<TransactionState> expectedTransactions,
                     int64_t expectedVsyncId) {
        EXPECT_EQ(actualProto.vsync_id(), expectedVsyncId);
        EXPECT_EQ(actualProto.transactions().size(),
                  static_cast<int32_t>(expectedTransactions.size()));
        for (uint32_t i = 0; i < expectedTransactions.size(); i++) {
            EXPECT_EQ(actualProto.transactions(static_cast<int32_t>(i)).pid(),
                      expectedTransactions[i].originPid);
        }
    }
};

TEST_F(TransactionTracingTest, enable) {
    EXPECT_FALSE(mTracing->isEnabled());
    mTracing->enable();
    EXPECT_TRUE(mTracing->isEnabled());
    mTracing->disable();
    verifyDisabledTracingState();
}

TEST_F(TransactionTracingTest, addTransactions) {
    mTracing->enable();
    std::vector<TransactionState> transactions;
    transactions.reserve(100);
    for (uint64_t i = 0; i < 100; i++) {
        TransactionState transaction;
        transaction.id = i;
        transaction.originPid = static_cast<int32_t>(i);
        transactions.emplace_back(transaction);
        mTracing->addQueuedTransaction(transaction);
    }

    // Split incoming transactions into two and commit them in reverse order to test out of order
    // commits.
    std::vector<TransactionState> firstTransactionSet =
            std::vector<TransactionState>(transactions.begin() + 50, transactions.end());
    int64_t firstTransactionSetVsyncId = 42;
    mTracing->addCommittedTransactions(firstTransactionSet, firstTransactionSetVsyncId);

    int64_t secondTransactionSetVsyncId = 43;
    std::vector<TransactionState> secondTransactionSet =
            std::vector<TransactionState>(transactions.begin(), transactions.begin() + 50);
    mTracing->addCommittedTransactions(secondTransactionSet, secondTransactionSetVsyncId);
    flush();

    std::string protoString = writeToString();
    proto::TransactionTraceFile proto;
    proto.ParseFromString(protoString);
    EXPECT_EQ(proto.entry().size(), 2);
    verifyEntry(proto.entry(0), firstTransactionSet, firstTransactionSetVsyncId);
    verifyEntry(proto.entry(1), secondTransactionSet, secondTransactionSetVsyncId);

    mTracing->disable();
    verifyDisabledTracingState();
}

} // namespace android
