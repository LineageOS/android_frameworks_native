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
#include <optional>
#include <vector>

#include <LocklessQueue.h>
#include <TransactionState.h>
#include <android-base/thread_annotations.h>
#include <ftl/small_map.h>
#include <ftl/small_vector.h>

namespace android {

class TestableSurfaceFlinger;
namespace surfaceflinger::frontend {

class TransactionHandler {
public:
    struct TransactionFlushState {
        TransactionState* transaction;
        bool firstTransaction = true;
        nsecs_t queueProcessTime = 0;
        // Layer handles that have transactions with buffers that are ready to be applied.
        ftl::SmallMap<IBinder* /* binder address */, uint64_t /* framenumber */, 15>
                bufferLayersReadyToPresent = {};
        // Tracks the queue with an unsignaled buffer. This is used to handle
        // LatchUnsignaledConfig::AutoSingleLayer to ensure we only apply an unsignaled buffer
        // if it's the only transaction that is ready to be applied.
        sp<IBinder> queueWithUnsignaledBuffer = nullptr;
    };
    enum class TransactionReadiness {
        // Transaction is ready to be applied
        Ready,
        // Transaction has unmet conditions (fence, present time, etc) and cannot be applied.
        NotReady,
        // Transaction is waiting on a barrier (another buffer to be latched first)
        NotReadyBarrier,
        // Transaction has an unsignaled fence but can be applied if it's the only transaction
        NotReadyUnsignaled,
    };
    using TransactionFilter = std::function<TransactionReadiness(const TransactionFlushState&)>;

    bool hasPendingTransactions();
    // Moves transactions from the lockless queue.
    void collectTransactions();
    std::vector<TransactionState> flushTransactions();
    void addTransactionReadyFilter(TransactionFilter&&);
    void queueTransaction(TransactionState&&);

    struct StalledTransactionInfo {
        pid_t pid;
        uint32_t layerId;
        std::string layerName;
        uint64_t bufferId;
        uint64_t frameNumber;
    };
    void onTransactionQueueStalled(uint64_t transactionId, StalledTransactionInfo);
    void removeFromStalledTransactions(uint64_t transactionId);
    std::optional<StalledTransactionInfo> getStalledTransactionInfo(pid_t pid);
    void onLayerDestroyed(uint32_t layerId);

private:
    // For unit tests
    friend class ::android::TestableSurfaceFlinger;

    int flushPendingTransactionQueues(std::vector<TransactionState>&, TransactionFlushState&);
    void applyUnsignaledBufferTransaction(std::vector<TransactionState>&, TransactionFlushState&);
    void popTransactionFromPending(std::vector<TransactionState>&, TransactionFlushState&,
                                   std::queue<TransactionState>&);
    TransactionReadiness applyFilters(TransactionFlushState&);
    std::unordered_map<sp<IBinder>, std::queue<TransactionState>, IListenerHash>
            mPendingTransactionQueues;
    LocklessQueue<TransactionState> mLocklessTransactionQueue;
    std::atomic<size_t> mPendingTransactionCount = 0;
    ftl::SmallVector<TransactionFilter, 2> mTransactionReadyFilters;

    std::mutex mStalledMutex;
    std::unordered_map<uint64_t /* transactionId */, StalledTransactionInfo> mStalledTransactions
            GUARDED_BY(mStalledMutex);
};
} // namespace surfaceflinger::frontend
} // namespace android
