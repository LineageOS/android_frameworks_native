/*
 * Copyright 2022 The Android Open Source Project
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

#pragma once

#include <semaphore.h>
#include <cstdint>
#include <vector>

#include <LocklessQueue.h>
#include <TransactionState.h>
#include <android-base/thread_annotations.h>
#include <ftl/small_map.h>
#include <ftl/small_vector.h>

namespace android {

class TestableSurfaceFlinger;
using gui::IListenerHash;
namespace surfaceflinger::frontend {

class TransactionHandler {
public:
    struct TransactionFlushState {
        const TransactionState* transaction;
        bool firstTransaction = true;
        nsecs_t queueProcessTime = 0;
        // Layer handles that have transactions with buffers that are ready to be applied.
        ftl::SmallMap<IBinder* /* binder address */, uint64_t /* framenumber */, 15>
                bufferLayersReadyToPresent = {};
        ftl::SmallVector<IBinder* /* queueToken */, 15> queuesWithUnsignaledBuffers;
    };
    enum class TransactionReadiness {
        NotReady,
        NotReadyBarrier,
        Ready,
        ReadyUnsignaled,
        ReadyUnsignaledSingle,
    };
    using TransactionFilter = std::function<TransactionReadiness(const TransactionFlushState&)>;

    bool hasPendingTransactions();
    std::vector<TransactionState> flushTransactions();
    void addTransactionReadyFilter(TransactionFilter&&);
    void queueTransaction(TransactionState&&);
    void onTransactionQueueStalled(uint64_t transactionId, sp<ITransactionCompletedListener>&,
                                   const std::string& reason);
    void removeFromStalledTransactions(uint64_t transactionId);

private:
    // For unit tests
    friend class ::android::TestableSurfaceFlinger;

    int flushPendingTransactionQueues(std::vector<TransactionState>&, TransactionFlushState&);
    TransactionReadiness applyFilters(TransactionFlushState&);
    std::unordered_map<sp<IBinder>, std::queue<TransactionState>, IListenerHash>
            mPendingTransactionQueues;
    LocklessQueue<TransactionState> mLocklessTransactionQueue;
    std::atomic<size_t> mPendingTransactionCount = 0;
    ftl::SmallVector<TransactionFilter, 2> mTransactionReadyFilters;
    std::vector<uint64_t> mStalledTransactions;
};
} // namespace surfaceflinger::frontend
} // namespace android
