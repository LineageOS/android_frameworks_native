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

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "SurfaceFlinger"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <cutils/trace.h>
#include <utils/Log.h>
#include <utils/Trace.h>
#include "FrontEnd/LayerLog.h"

#include "TransactionHandler.h"

namespace android::surfaceflinger::frontend {

void TransactionHandler::queueTransaction(TransactionState&& state) {
    mLocklessTransactionQueue.push(std::move(state));
    mPendingTransactionCount.fetch_add(1);
    ATRACE_INT("TransactionQueue", static_cast<int>(mPendingTransactionCount.load()));
}

void TransactionHandler::collectTransactions() {
    while (!mLocklessTransactionQueue.isEmpty()) {
        auto maybeTransaction = mLocklessTransactionQueue.pop();
        if (!maybeTransaction.has_value()) {
            break;
        }
        auto transaction = maybeTransaction.value();
        mPendingTransactionQueues[transaction.applyToken].emplace(std::move(transaction));
    }
}

std::vector<TransactionState> TransactionHandler::flushTransactions() {
    // Collect transaction that are ready to be applied.
    std::vector<TransactionState> transactions;
    TransactionFlushState flushState;
    flushState.queueProcessTime = systemTime();
    // Transactions with a buffer pending on a barrier may be on a different applyToken
    // than the transaction which satisfies our barrier. In fact this is the exact use case
    // that the primitive is designed for. This means we may first process
    // the barrier dependent transaction, determine it ineligible to complete
    // and then satisfy in a later inner iteration of flushPendingTransactionQueues.
    // The barrier dependent transaction was eligible to be presented in this frame
    // but we would have prevented it without case. To fix this we continually
    // loop through flushPendingTransactionQueues until we perform an iteration
    // where the number of transactionsPendingBarrier doesn't change. This way
    // we can continue to resolve dependency chains of barriers as far as possible.
    int lastTransactionsPendingBarrier = 0;
    int transactionsPendingBarrier = 0;
    do {
        lastTransactionsPendingBarrier = transactionsPendingBarrier;
        // Collect transactions that are ready to be applied.
        transactionsPendingBarrier = flushPendingTransactionQueues(transactions, flushState);
    } while (lastTransactionsPendingBarrier != transactionsPendingBarrier);

    applyUnsignaledBufferTransaction(transactions, flushState);

    mPendingTransactionCount.fetch_sub(transactions.size());
    ATRACE_INT("TransactionQueue", static_cast<int>(mPendingTransactionCount.load()));
    return transactions;
}

void TransactionHandler::applyUnsignaledBufferTransaction(
        std::vector<TransactionState>& transactions, TransactionFlushState& flushState) {
    if (!flushState.queueWithUnsignaledBuffer) {
        return;
    }

    // only apply an unsignaled buffer transaction if it's the first one
    if (!transactions.empty()) {
        ATRACE_NAME("fence unsignaled");
        return;
    }

    auto it = mPendingTransactionQueues.find(flushState.queueWithUnsignaledBuffer);
    LLOG_ALWAYS_FATAL_WITH_TRACE_IF(it == mPendingTransactionQueues.end(),
                                    "Could not find queue with unsignaled buffer!");

    auto& queue = it->second;
    popTransactionFromPending(transactions, flushState, queue);
    if (queue.empty()) {
        it = mPendingTransactionQueues.erase(it);
    }
}

void TransactionHandler::popTransactionFromPending(std::vector<TransactionState>& transactions,
                                                   TransactionFlushState& flushState,
                                                   std::queue<TransactionState>& queue) {
    auto& transaction = queue.front();
    // Transaction is ready move it from the pending queue.
    flushState.firstTransaction = false;
    removeFromStalledTransactions(transaction.id);
    transactions.emplace_back(std::move(transaction));
    queue.pop();

    auto& readyToApplyTransaction = transactions.back();
    readyToApplyTransaction.traverseStatesWithBuffers([&](const layer_state_t& state) {
        const bool frameNumberChanged =
                state.bufferData->flags.test(BufferData::BufferDataChange::frameNumberChanged);
        if (frameNumberChanged) {
            flushState.bufferLayersReadyToPresent.emplace_or_replace(state.surface.get(),
                                                                     state.bufferData->frameNumber);
        } else {
            // Barrier function only used for BBQ which always includes a frame number.
            // This value only used for barrier logic.
            flushState.bufferLayersReadyToPresent
                    .emplace_or_replace(state.surface.get(), std::numeric_limits<uint64_t>::max());
        }
    });
}

TransactionHandler::TransactionReadiness TransactionHandler::applyFilters(
        TransactionFlushState& flushState) {
    auto ready = TransactionReadiness::Ready;
    for (auto& filter : mTransactionReadyFilters) {
        auto perFilterReady = filter(flushState);
        switch (perFilterReady) {
            case TransactionReadiness::NotReady:
            case TransactionReadiness::NotReadyBarrier:
                return perFilterReady;

            case TransactionReadiness::NotReadyUnsignaled:
                // If one of the filters allows latching an unsignaled buffer, latch this ready
                // state.
                ready = perFilterReady;
                break;
            case TransactionReadiness::Ready:
                continue;
        }
    }
    return ready;
}

int TransactionHandler::flushPendingTransactionQueues(std::vector<TransactionState>& transactions,
                                                      TransactionFlushState& flushState) {
    int transactionsPendingBarrier = 0;
    auto it = mPendingTransactionQueues.begin();
    while (it != mPendingTransactionQueues.end()) {
        auto& [applyToken, queue] = *it;
        while (!queue.empty()) {
            auto& transaction = queue.front();
            flushState.transaction = &transaction;
            auto ready = applyFilters(flushState);
            if (ready == TransactionReadiness::NotReadyBarrier) {
                transactionsPendingBarrier++;
                break;
            } else if (ready == TransactionReadiness::NotReady) {
                break;
            } else if (ready == TransactionReadiness::NotReadyUnsignaled) {
                // We maybe able to latch this transaction if it's the only transaction
                // ready to be applied.
                flushState.queueWithUnsignaledBuffer = applyToken;
                break;
            }
            // ready == TransactionReadiness::Ready
            popTransactionFromPending(transactions, flushState, queue);
        }

        if (queue.empty()) {
            it = mPendingTransactionQueues.erase(it);
        } else {
            it = std::next(it, 1);
        }
    }
    return transactionsPendingBarrier;
}

void TransactionHandler::addTransactionReadyFilter(TransactionFilter&& filter) {
    mTransactionReadyFilters.emplace_back(std::move(filter));
}

bool TransactionHandler::hasPendingTransactions() {
    return !mPendingTransactionQueues.empty() || !mLocklessTransactionQueue.isEmpty();
}

void TransactionHandler::onTransactionQueueStalled(uint64_t transactionId,
                                                   StalledTransactionInfo stalledTransactionInfo) {
    std::lock_guard lock{mStalledMutex};
    mStalledTransactions.emplace(transactionId, std::move(stalledTransactionInfo));
}

void TransactionHandler::removeFromStalledTransactions(uint64_t transactionId) {
    std::lock_guard lock{mStalledMutex};
    mStalledTransactions.erase(transactionId);
}

std::optional<TransactionHandler::StalledTransactionInfo>
TransactionHandler::getStalledTransactionInfo(pid_t pid) {
    std::lock_guard lock{mStalledMutex};
    for (auto [_, stalledTransactionInfo] : mStalledTransactions) {
        if (pid == stalledTransactionInfo.pid) {
            return stalledTransactionInfo;
        }
    }
    return std::nullopt;
}

void TransactionHandler::onLayerDestroyed(uint32_t layerId) {
    std::lock_guard lock{mStalledMutex};
    for (auto it = mStalledTransactions.begin(); it != mStalledTransactions.end();) {
        if (it->second.layerId == layerId) {
            it = mStalledTransactions.erase(it);
        } else {
            it++;
        }
    }
}

} // namespace android::surfaceflinger::frontend
