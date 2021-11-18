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
    mStartingTimestamp = systemTime();
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

    writeToFileLocked();
    mBuffer->reset();
    mQueuedTransactions.clear();
    mStartingStates.clear();
    mLayerHandles.clear();
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
    return writeToFileLocked();
}

status_t TransactionTracing::writeToFileLocked() {
    proto::TransactionTraceFile fileProto = createTraceFileProto();
    addStartingStateToProtoLocked(fileProto);
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
    base::StringAppendF(&result,
                        "  queued transactions=%zu created layers=%zu handles=%zu states=%zu\n",
                        mQueuedTransactions.size(), mCreatedLayers.size(), mLayerHandles.size(),
                        mStartingStates.size());
    mBuffer->dump(result);
}

void TransactionTracing::addQueuedTransaction(const TransactionState& transaction) {
    std::scoped_lock lock(mTraceLock);
    ATRACE_CALL();
    if (!mEnabled) {
        return;
    }
    mQueuedTransactions[transaction.id] =
            TransactionProtoParser::toProto(transaction,
                                            std::bind(&TransactionTracing::getLayerIdLocked, this,
                                                      std::placeholders::_1),
                                            nullptr);
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

    mPendingTransactions.emplace_back(committedTransactions);
    tryPushToTracingThread();
}

void TransactionTracing::loop() {
    while (true) {
        std::vector<CommittedTransactions> committedTransactions;
        std::vector<int32_t> removedLayers;
        {
            std::unique_lock<std::mutex> lock(mMainThreadLock);
            base::ScopedLockAssertion assumeLocked(mMainThreadLock);
            mTransactionsAvailableCv.wait(lock, [&]() REQUIRES(mMainThreadLock) {
                return mDone || !mCommittedTransactions.empty();
            });
            if (mDone) {
                mCommittedTransactions.clear();
                mRemovedLayers.clear();
                break;
            }

            removedLayers = std::move(mRemovedLayers);
            mRemovedLayers.clear();
            committedTransactions = std::move(mCommittedTransactions);
            mCommittedTransactions.clear();
        } // unlock mMainThreadLock

        addEntry(committedTransactions, removedLayers);
    }
}

void TransactionTracing::addEntry(const std::vector<CommittedTransactions>& committedTransactions,
                                  const std::vector<int32_t>& removedLayers) {
    ATRACE_CALL();
    std::scoped_lock lock(mTraceLock);
    std::vector<proto::TransactionTraceEntry> removedEntries;
    for (const CommittedTransactions& entry : committedTransactions) {
        proto::TransactionTraceEntry entryProto;
        entryProto.set_elapsed_realtime_nanos(entry.timestamp);
        entryProto.set_vsync_id(entry.vsyncId);
        entryProto.mutable_added_layers()->Reserve(static_cast<int32_t>(mCreatedLayers.size()));
        for (auto& newLayer : mCreatedLayers) {
            entryProto.mutable_added_layers()->Add(std::move(newLayer));
        }
        entryProto.mutable_removed_layers()->Reserve(static_cast<int32_t>(removedLayers.size()));
        for (auto& removedLayer : removedLayers) {
            entryProto.mutable_removed_layers()->Add(removedLayer);
        }
        mCreatedLayers.clear();
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
        std::vector<proto::TransactionTraceEntry> entries = mBuffer->emplace(std::move(entryProto));
        removedEntries.insert(removedEntries.end(), std::make_move_iterator(entries.begin()),
                              std::make_move_iterator(entries.end()));
    }

    for (const proto::TransactionTraceEntry& removedEntry : removedEntries) {
        updateStartingStateLocked(removedEntry);
    }
    mTransactionsAddedToBufferCv.notify_one();
}

void TransactionTracing::flush(int64_t vsyncId) {
    while (!mPendingTransactions.empty() || !mPendingRemovedLayers.empty()) {
        tryPushToTracingThread();
    }
    std::unique_lock<std::mutex> lock(mTraceLock);
    base::ScopedLockAssertion assumeLocked(mTraceLock);
    mTransactionsAddedToBufferCv.wait(lock, [&]() REQUIRES(mTraceLock) {
        return mBuffer->used() > 0 && mBuffer->back().vsync_id() >= vsyncId;
    });
}

void TransactionTracing::onLayerAdded(BBinder* layerHandle, int layerId, const std::string& name,
                                      uint32_t flags, int parentId) {
    std::scoped_lock lock(mTraceLock);
    TracingLayerCreationArgs args{layerId, name, flags, parentId};
    mLayerHandles[layerHandle] = layerId;
    mCreatedLayers.emplace_back(TransactionProtoParser::toProto(args));
}

void TransactionTracing::onLayerRemoved(int32_t layerId) {
    mPendingRemovedLayers.emplace_back(layerId);
    tryPushToTracingThread();
}

void TransactionTracing::tryPushToTracingThread() {
    // Try to acquire the lock from main thread.
    if (mMainThreadLock.try_lock()) {
        // We got the lock! Collect any pending transactions and continue.
        mCommittedTransactions.insert(mCommittedTransactions.end(),
                                      std::make_move_iterator(mPendingTransactions.begin()),
                                      std::make_move_iterator(mPendingTransactions.end()));
        mPendingTransactions.clear();
        mRemovedLayers.insert(mRemovedLayers.end(), mPendingRemovedLayers.begin(),
                              mPendingRemovedLayers.end());
        mPendingRemovedLayers.clear();
        mTransactionsAvailableCv.notify_one();
        mMainThreadLock.unlock();
    } else {
        ALOGV("Couldn't get lock");
    }
}

int32_t TransactionTracing::getLayerIdLocked(const sp<IBinder>& layerHandle) {
    if (layerHandle == nullptr) {
        return -1;
    }
    auto it = mLayerHandles.find(layerHandle->localBinder());
    return it == mLayerHandles.end() ? -1 : it->second;
}

void TransactionTracing::updateStartingStateLocked(
        const proto::TransactionTraceEntry& removedEntry) {
    // Keep track of layer starting state so we can reconstruct the layer state as we purge
    // transactions from the buffer.
    for (const proto::LayerCreationArgs& addedLayer : removedEntry.added_layers()) {
        TracingLayerState& startingState = mStartingStates[addedLayer.layer_id()];
        startingState.layerId = addedLayer.layer_id();
        startingState.name = addedLayer.name();
        startingState.layerCreationFlags = addedLayer.flags();
        startingState.parentId = addedLayer.parent_id();
    }

    // Merge layer states to starting transaction state.
    for (const proto::TransactionState& transaction : removedEntry.transactions()) {
        for (const proto::LayerState& layerState : transaction.layer_changes()) {
            auto it = mStartingStates.find(layerState.layer_id());
            if (it == mStartingStates.end()) {
                ALOGE("Could not find layer id %d", layerState.layer_id());
                continue;
            }
            TransactionProtoParser::fromProto(layerState, nullptr, it->second);
        }
    }

    // Clean up stale starting states since the layer has been removed and the buffer does not
    // contain any references to the layer.
    for (const int32_t removedLayerId : removedEntry.removed_layers()) {
        auto it = std::find_if(mLayerHandles.begin(), mLayerHandles.end(),
                               [removedLayerId](auto& layer) {
                                   return layer.second == removedLayerId;
                               });
        if (it != mLayerHandles.end()) {
            mLayerHandles.erase(it);
        }
        mStartingStates.erase(removedLayerId);
    }
}

void TransactionTracing::addStartingStateToProtoLocked(proto::TransactionTraceFile& proto) {
    proto::TransactionTraceEntry* entryProto = proto.add_entry();
    entryProto->set_elapsed_realtime_nanos(mStartingTimestamp);
    entryProto->set_vsync_id(0);
    entryProto->mutable_added_layers()->Reserve(static_cast<int32_t>(mStartingStates.size()));
    for (auto& [layerId, state] : mStartingStates) {
        TracingLayerCreationArgs args{layerId, state.name, state.layerCreationFlags,
                                      state.parentId};
        entryProto->mutable_added_layers()->Add(TransactionProtoParser::toProto(args));
    }

    proto::TransactionState transactionProto = TransactionProtoParser::toProto(mStartingStates);
    transactionProto.set_vsync_id(0);
    transactionProto.set_post_time(mStartingTimestamp);
    entryProto->mutable_transactions()->Add(std::move(transactionProto));
}

proto::TransactionTraceFile TransactionTracing::writeToProto() {
    std::scoped_lock<std::mutex> lock(mTraceLock);
    proto::TransactionTraceFile proto = createTraceFileProto();
    addStartingStateToProtoLocked(proto);
    mBuffer->writeToProto(proto);
    return proto;
}

} // namespace android
