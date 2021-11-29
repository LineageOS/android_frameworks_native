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

#undef LOG_TAG
#define LOG_TAG "TransactionTracing"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <android-base/stringprintf.h>
#include <log/log.h>
#include <utils/SystemClock.h>
#include <utils/Trace.h>

#include "RingBuffer.h"
#include "TransactionTracing.h"

namespace android {

TransactionTracing::TransactionTracing() {
    mBuffer = std::make_unique<
            RingBuffer<proto::TransactionTraceFile, proto::TransactionTraceEntry>>();
}

TransactionTracing::~TransactionTracing() = default;

bool TransactionTracing::enable() {
    std::scoped_lock lock(mTraceLock);
    if (mEnabled) {
        return false;
    }
    mBuffer->setSize(mBufferSizeInBytes);
    mEnabled = true;
    {
        std::scoped_lock lock(mMainThreadLock);
        mDone = false;
        mThread = std::thread(&TransactionTracing::loop, this);
    }
    return true;
}

bool TransactionTracing::disable() {
    std::thread thread;
    {
        std::scoped_lock lock(mMainThreadLock);
        mDone = true;
        mTransactionsAvailableCv.notify_all();
        thread = std::move(mThread);
    }
    if (thread.joinable()) {
        thread.join();
    }

    std::scoped_lock lock(mTraceLock);
    if (!mEnabled) {
        return false;
    }
    mEnabled = false;

    proto::TransactionTraceFile fileProto = createTraceFileProto();
    mBuffer->writeToFile(fileProto, FILE_NAME);
    mQueuedTransactions.clear();
    return true;
}

bool TransactionTracing::isEnabled() const {
    std::scoped_lock lock(mTraceLock);
    return mEnabled;
}

status_t TransactionTracing::writeToFile() {
    std::scoped_lock lock(mTraceLock);
    if (!mEnabled) {
        return STATUS_OK;
    }
    proto::TransactionTraceFile fileProto = createTraceFileProto();
    return mBuffer->writeToFile(fileProto, FILE_NAME);
}

void TransactionTracing::setBufferSize(size_t bufferSizeInBytes) {
    std::scoped_lock lock(mTraceLock);
    mBufferSizeInBytes = bufferSizeInBytes;
    mBuffer->setSize(mBufferSizeInBytes);
}

proto::TransactionTraceFile TransactionTracing::createTraceFileProto() const {
    proto::TransactionTraceFile proto;
    proto.set_magic_number(uint64_t(proto::TransactionTraceFile_MagicNumber_MAGIC_NUMBER_H) << 32 |
                           proto::TransactionTraceFile_MagicNumber_MAGIC_NUMBER_L);
    return proto;
}

void TransactionTracing::dump(std::string& result) const {
    std::scoped_lock lock(mTraceLock);
    base::StringAppendF(&result, "Transaction tracing state: %s\n",
                        mEnabled ? "enabled" : "disabled");
    base::StringAppendF(&result, "  queued transactions: %d\n",
                        static_cast<uint32_t>(mQueuedTransactions.size()));
    mBuffer->dump(result);
}

void TransactionTracing::addQueuedTransaction(const TransactionState& transaction) {
    std::scoped_lock lock(mTraceLock);
    ATRACE_CALL();
    if (!mEnabled) {
        return;
    }
    mQueuedTransactions[transaction.id] =
            TransactionProtoParser::toProto(transaction, nullptr, nullptr);
}

void TransactionTracing::addCommittedTransactions(std::vector<TransactionState>& transactions,
                                                  int64_t vsyncId) {
    CommittedTransactions committedTransactions;
    committedTransactions.vsyncId = vsyncId;
    committedTransactions.timestamp = systemTime();
    committedTransactions.transactionIds.reserve(transactions.size());
    for (const auto& transaction : transactions) {
        committedTransactions.transactionIds.emplace_back(transaction.id);
    }

    // Try to acquire the lock from main thread, but don't block if we cannot acquire the lock. Add
    // it to pending transactions that we can collect later.
    if (mMainThreadLock.try_lock()) {
        // We got the lock! Collect any pending transactions and continue.
        mCommittedTransactions.insert(mCommittedTransactions.end(),
                                      std::make_move_iterator(mPendingTransactions.begin()),
                                      std::make_move_iterator(mPendingTransactions.end()));
        mPendingTransactions.clear();
        mCommittedTransactions.emplace_back(committedTransactions);
        mTransactionsAvailableCv.notify_one();
        mMainThreadLock.unlock();
    } else {
        mPendingTransactions.emplace_back(committedTransactions);
    }
}

void TransactionTracing::loop() {
    while (true) {
        std::vector<CommittedTransactions> committedTransactions;
        {
            std::unique_lock<std::mutex> lock(mMainThreadLock);
            base::ScopedLockAssertion assumeLocked(mMainThreadLock);
            mTransactionsAvailableCv.wait(lock, [&]() REQUIRES(mMainThreadLock) {
                return mDone || !mCommittedTransactions.empty();
            });
            if (mDone) {
                mCommittedTransactions.clear();
                break;
            }
            committedTransactions = std::move(mCommittedTransactions);
            mCommittedTransactions.clear();
        } // unlock mMainThreadLock

        addEntry(committedTransactions);

        mTransactionsAddedToBufferCv.notify_one();
    }
}

void TransactionTracing::addEntry(const std::vector<CommittedTransactions>& committedTransactions) {
    ATRACE_CALL();
    std::scoped_lock lock(mTraceLock);
    std::vector<proto::TransactionTraceEntry> removedEntries;
    for (const CommittedTransactions& entry : committedTransactions) {
        proto::TransactionTraceEntry entryProto;
        entryProto.set_elapsed_realtime_nanos(entry.timestamp);
        entryProto.set_vsync_id(entry.vsyncId);
        entryProto.mutable_transactions()->Reserve(
                static_cast<int32_t>(entry.transactionIds.size()));
        for (const uint64_t& id : entry.transactionIds) {
            auto it = mQueuedTransactions.find(id);
            if (it != mQueuedTransactions.end()) {
                entryProto.mutable_transactions()->Add(std::move(it->second));
                mQueuedTransactions.erase(it);
            } else {
                ALOGE("Could not find transaction id %" PRIu64, id);
            }
        }
        mBuffer->emplace(std::move(entryProto));
    }
}

void TransactionTracing::flush() {
    std::unique_lock<std::mutex> lock(mMainThreadLock);
    base::ScopedLockAssertion assumeLocked(mMainThreadLock);
    mTransactionsAddedToBufferCv.wait(lock, [&]() REQUIRES(mMainThreadLock) {
        return mCommittedTransactions.empty();
    });
}

} // namespace android
