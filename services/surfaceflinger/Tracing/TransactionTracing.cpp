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

#include <android-base/stringprintf.h>
#include <log/log.h>
#include <utils/SystemClock.h>

#include "Client.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "TransactionDataSource.h"
#include "TransactionTracing.h"

namespace android {
ANDROID_SINGLETON_STATIC_INSTANCE(android::TransactionTraceWriter)

TransactionTracing::TransactionTracing()
      : mProtoParser(std::make_unique<TransactionProtoParser::FlingerDataMapper>()) {
    std::scoped_lock lock(mTraceLock);

    mBuffer.setSize(CONTINUOUS_TRACING_BUFFER_SIZE);

    mStartingTimestamp = systemTime();

    {
        std::scoped_lock lock(mMainThreadLock);
        mThread = std::thread(&TransactionTracing::loop, this);
    }

    TransactionDataSource::Initialize(*this);
}

TransactionTracing::~TransactionTracing() {
    TransactionDataSource::UnregisterTransactionTracing();
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
}

void TransactionTracing::onStart(TransactionTracing::Mode mode) {
    // In "active" mode write the ring buffer (starting state + following sequence of transactions)
    // to perfetto when tracing starts (only once).
    if (mode != Mode::MODE_ACTIVE) {
        return;
    }

    writeRingBufferToPerfetto(TransactionTracing::Mode::MODE_ACTIVE);

    ALOGD("Started active mode tracing (wrote initial transactions ring buffer to perfetto)");
}

void TransactionTracing::onFlush(TransactionTracing::Mode mode) {
    // In "continuous" mode write the ring buffer (starting state + following sequence of
    // transactions) to perfetto when a "flush" event is received (bugreport is taken or tracing is
    // stopped).
    if (mode != Mode::MODE_CONTINUOUS) {
        return;
    }

    writeRingBufferToPerfetto(TransactionTracing::Mode::MODE_CONTINUOUS);

    ALOGD("Flushed continuous mode tracing (wrote transactions ring buffer to perfetto");
}

void TransactionTracing::writeRingBufferToPerfetto(TransactionTracing::Mode mode) {
    // Write the ring buffer (starting state + following sequence of transactions) to perfetto
    // tracing sessions with the specified mode.
    const auto fileProto = writeToProto();

    TransactionDataSource::Trace([&](TransactionDataSource::TraceContext context) {
        // Write packets only to tracing sessions with specified mode
        if (context.GetCustomTlsState()->mMode != mode) {
            return;
        }
        for (const auto& entryProto : fileProto.entry()) {
            const auto entryBytes = entryProto.SerializeAsString();

            auto packet = context.NewTracePacket();
            packet->set_timestamp(static_cast<uint64_t>(entryProto.elapsed_realtime_nanos()));
            packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_MONOTONIC);

            auto* transactionsProto = packet->set_surfaceflinger_transactions();
            transactionsProto->AppendRawProtoBytes(entryBytes.data(), entryBytes.size());
        }
        {
            // TODO (b/162206162): remove empty packet when perfetto bug is fixed.
            //  It is currently needed in order not to lose the last trace entry.
            context.NewTracePacket();
        }
    });
}

status_t TransactionTracing::writeToFile(const std::string& filename) {
    auto fileProto = writeToProto();

    std::string output;
    if (!fileProto.SerializeToString(&output)) {
        ALOGE("Could not serialize proto.");
        return UNKNOWN_ERROR;
    }

    // -rw-r--r--
    const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (!android::base::WriteStringToFile(output, filename, mode, getuid(), getgid(), true)) {
        ALOGE("Could not save the proto file %s", filename.c_str());
        return PERMISSION_DENIED;
    }

    return NO_ERROR;
}

perfetto::protos::TransactionTraceFile TransactionTracing::writeToProto() {
    std::scoped_lock<std::mutex> lock(mTraceLock);
    perfetto::protos::TransactionTraceFile fileProto = createTraceFileProto();
    const auto startingStateProto = createStartingStateProtoLocked();
    if (startingStateProto) {
        *fileProto.add_entry() = std::move(*startingStateProto);
    }
    mBuffer.writeToProto(fileProto);
    return fileProto;
}

void TransactionTracing::setBufferSize(size_t bufferSizeInBytes) {
    std::scoped_lock lock(mTraceLock);
    mBuffer.setSize(bufferSizeInBytes);
}

perfetto::protos::TransactionTraceFile TransactionTracing::createTraceFileProto() const {
    perfetto::protos::TransactionTraceFile proto;
    proto.set_magic_number(
            uint64_t(perfetto::protos::TransactionTraceFile_MagicNumber_MAGIC_NUMBER_H) << 32 |
            perfetto::protos::TransactionTraceFile_MagicNumber_MAGIC_NUMBER_L);
    auto timeOffsetNs = static_cast<uint64_t>(systemTime(SYSTEM_TIME_REALTIME) -
                                              systemTime(SYSTEM_TIME_MONOTONIC));
    proto.set_real_to_elapsed_time_offset_nanos(timeOffsetNs);
    proto.set_version(TRACING_VERSION);
    return proto;
}

void TransactionTracing::dump(std::string& result) const {
    std::scoped_lock lock(mTraceLock);
    base::StringAppendF(&result, "  queued transactions=%zu created layers=%zu states=%zu\n",
                        mQueuedTransactions.size(), mCreatedLayers.size(), mStartingStates.size());
    mBuffer.dump(result);
}

void TransactionTracing::addQueuedTransaction(const TransactionState& transaction) {
    perfetto::protos::TransactionState* state =
            new perfetto::protos::TransactionState(mProtoParser.toProto(transaction));
    mTransactionQueue.push(state);
}

void TransactionTracing::addCommittedTransactions(int64_t vsyncId, nsecs_t commitTime,
                                                  frontend::Update& newUpdate,
                                                  const frontend::DisplayInfos& displayInfos,
                                                  bool displayInfoChanged) {
    CommittedUpdates update;
    update.vsyncId = vsyncId;
    update.timestamp = commitTime;
    update.transactionIds.reserve(newUpdate.transactions.size());
    for (const auto& transaction : newUpdate.transactions) {
        update.transactionIds.emplace_back(transaction.id);
    }
    update.displayInfoChanged = displayInfoChanged;
    if (displayInfoChanged) {
        update.displayInfos = displayInfos;
    }
    update.createdLayers = std::move(newUpdate.layerCreationArgs);
    newUpdate.layerCreationArgs.clear();
    update.destroyedLayerHandles.reserve(newUpdate.destroyedHandles.size());
    for (auto& [handle, _] : newUpdate.destroyedHandles) {
        update.destroyedLayerHandles.push_back(handle);
    }
    mPendingUpdates.emplace_back(update);
    tryPushToTracingThread();
    mLastUpdatedVsyncId = vsyncId;
}

void TransactionTracing::loop() {
    while (true) {
        std::vector<CommittedUpdates> committedUpdates;
        std::vector<uint32_t> destroyedLayers;
        {
            std::unique_lock<std::mutex> lock(mMainThreadLock);
            base::ScopedLockAssertion assumeLocked(mMainThreadLock);
            mTransactionsAvailableCv.wait(lock, [&]() REQUIRES(mMainThreadLock) {
                return mDone || !mUpdates.empty();
            });
            if (mDone) {
                mUpdates.clear();
                mDestroyedLayers.clear();
                break;
            }

            destroyedLayers = std::move(mDestroyedLayers);
            mDestroyedLayers.clear();
            committedUpdates = std::move(mUpdates);
            mUpdates.clear();
        } // unlock mMainThreadLock

        if (!committedUpdates.empty() || !destroyedLayers.empty()) {
            addEntry(committedUpdates, destroyedLayers);
        }
    }
}

void TransactionTracing::addEntry(const std::vector<CommittedUpdates>& committedUpdates,
                                  const std::vector<uint32_t>& destroyedLayers) {
    std::scoped_lock lock(mTraceLock);
    std::vector<std::string> removedEntries;
    perfetto::protos::TransactionTraceEntry entryProto;

    while (auto incomingTransaction = mTransactionQueue.pop()) {
        auto transaction = *incomingTransaction;
        mQueuedTransactions[incomingTransaction->transaction_id()] = transaction;
        delete incomingTransaction;
    }
    for (const CommittedUpdates& update : committedUpdates) {
        entryProto.set_elapsed_realtime_nanos(update.timestamp);
        entryProto.set_vsync_id(update.vsyncId);
        entryProto.mutable_added_layers()->Reserve(
                static_cast<int32_t>(update.createdLayers.size()));

        for (const auto& args : update.createdLayers) {
            entryProto.mutable_added_layers()->Add(std::move(mProtoParser.toProto(args)));
        }

        entryProto.mutable_destroyed_layers()->Reserve(
                static_cast<int32_t>(destroyedLayers.size()));
        for (auto& destroyedLayer : destroyedLayers) {
            entryProto.mutable_destroyed_layers()->Add(destroyedLayer);
        }
        entryProto.mutable_transactions()->Reserve(
                static_cast<int32_t>(update.transactionIds.size()));
        for (const uint64_t& id : update.transactionIds) {
            auto it = mQueuedTransactions.find(id);
            if (it != mQueuedTransactions.end()) {
                entryProto.mutable_transactions()->Add(std::move(it->second));
                mQueuedTransactions.erase(it);
            } else {
                ALOGW("Could not find transaction id %" PRIu64, id);
            }
        }

        entryProto.mutable_destroyed_layer_handles()->Reserve(
                static_cast<int32_t>(update.destroyedLayerHandles.size()));
        for (auto layerId : update.destroyedLayerHandles) {
            entryProto.mutable_destroyed_layer_handles()->Add(layerId);
        }

        entryProto.set_displays_changed(update.displayInfoChanged);
        if (update.displayInfoChanged) {
            entryProto.mutable_displays()->Reserve(
                    static_cast<int32_t>(update.displayInfos.size()));
            for (auto& [layerStack, displayInfo] : update.displayInfos) {
                entryProto.mutable_displays()->Add(
                        std::move(mProtoParser.toProto(displayInfo, layerStack.id)));
            }
        }

        std::string serializedProto;
        entryProto.SerializeToString(&serializedProto);

        TransactionDataSource::Trace([&](TransactionDataSource::TraceContext context) {
            // In "active" mode write each committed transaction to perfetto.
            // Note: the starting state is written (once) when the perfetto "start" event is
            // received.
            if (context.GetCustomTlsState()->mMode != Mode::MODE_ACTIVE) {
                return;
            }
            {
                auto packet = context.NewTracePacket();
                packet->set_timestamp(static_cast<uint64_t>(entryProto.elapsed_realtime_nanos()));
                packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_MONOTONIC);
                auto* transactions = packet->set_surfaceflinger_transactions();
                transactions->AppendRawProtoBytes(serializedProto.data(), serializedProto.size());
            }
            {
                // TODO (b/162206162): remove empty packet when perfetto bug is fixed.
                //  It is currently needed in order not to lose the last trace entry.
                context.NewTracePacket();
            }
        });

        std::vector<std::string> entries = mBuffer.emplace(std::move(serializedProto));
        removedEntries.reserve(removedEntries.size() + entries.size());
        removedEntries.insert(removedEntries.end(), std::make_move_iterator(entries.begin()),
                              std::make_move_iterator(entries.end()));

        entryProto.Clear();
    }

    perfetto::protos::TransactionTraceEntry removedEntryProto;
    for (const std::string& removedEntry : removedEntries) {
        removedEntryProto.ParseFromString(removedEntry);
        updateStartingStateLocked(removedEntryProto);
        removedEntryProto.Clear();
    }
    mTransactionsAddedToBufferCv.notify_one();
}

void TransactionTracing::flush() {
    {
        std::scoped_lock lock(mMainThreadLock);
        // Collect any pending transactions and wait for transactions to be added to
        mUpdates.insert(mUpdates.end(), std::make_move_iterator(mPendingUpdates.begin()),
                        std::make_move_iterator(mPendingUpdates.end()));
        mPendingUpdates.clear();
        mDestroyedLayers.insert(mDestroyedLayers.end(), mPendingDestroyedLayers.begin(),
                                mPendingDestroyedLayers.end());
        mPendingDestroyedLayers.clear();
        mTransactionsAvailableCv.notify_one();
    }
    std::unique_lock<std::mutex> lock(mTraceLock);
    base::ScopedLockAssertion assumeLocked(mTraceLock);
    mTransactionsAddedToBufferCv.wait_for(lock, std::chrono::milliseconds(100),
                                          [&]() REQUIRES(mTraceLock) {
                                              perfetto::protos::TransactionTraceEntry entry;
                                              if (mBuffer.used() > 0) {
                                                  entry.ParseFromString(mBuffer.back());
                                              }
                                              return mBuffer.used() > 0 &&
                                                      entry.vsync_id() >= mLastUpdatedVsyncId;
                                          });
}

void TransactionTracing::onLayerRemoved(int32_t layerId) {
    mPendingDestroyedLayers.emplace_back(layerId);
    tryPushToTracingThread();
}

void TransactionTracing::tryPushToTracingThread() {
    // Try to acquire the lock from main thread.
    if (mMainThreadLock.try_lock()) {
        // We got the lock! Collect any pending transactions and continue.
        mUpdates.insert(mUpdates.end(), std::make_move_iterator(mPendingUpdates.begin()),
                        std::make_move_iterator(mPendingUpdates.end()));
        mPendingUpdates.clear();
        mDestroyedLayers.insert(mDestroyedLayers.end(), mPendingDestroyedLayers.begin(),
                                mPendingDestroyedLayers.end());
        mPendingDestroyedLayers.clear();
        mTransactionsAvailableCv.notify_one();
        mMainThreadLock.unlock();
    } else {
        ALOGV("Couldn't get lock");
    }
}

void TransactionTracing::updateStartingStateLocked(
        const perfetto::protos::TransactionTraceEntry& removedEntry) {
    mStartingTimestamp = removedEntry.elapsed_realtime_nanos();
    // Keep track of layer starting state so we can reconstruct the layer state as we purge
    // transactions from the buffer.
    for (const perfetto::protos::LayerCreationArgs& addedLayer : removedEntry.added_layers()) {
        TracingLayerState& startingState = mStartingStates[addedLayer.layer_id()];
        startingState.layerId = addedLayer.layer_id();
        mProtoParser.fromProto(addedLayer, startingState.args);
    }

    // Merge layer states to starting transaction state.
    for (const perfetto::protos::TransactionState& transaction : removedEntry.transactions()) {
        for (const perfetto::protos::LayerState& layerState : transaction.layer_changes()) {
            auto it = mStartingStates.find(layerState.layer_id());
            if (it == mStartingStates.end()) {
                // TODO(b/238781169) make this log fatal when we switch over to using new fe
                ALOGW("Could not find layer id %d", layerState.layer_id());
                continue;
            }
            mProtoParser.mergeFromProto(layerState, it->second);
        }
    }

    for (const uint32_t destroyedLayerHandleId : removedEntry.destroyed_layer_handles()) {
        mRemovedLayerHandlesAtStart.insert(destroyedLayerHandleId);
    }

    // Clean up stale starting states since the layer has been removed and the buffer does not
    // contain any references to the layer.
    for (const uint32_t destroyedLayerId : removedEntry.destroyed_layers()) {
        mStartingStates.erase(destroyedLayerId);
        mRemovedLayerHandlesAtStart.erase(destroyedLayerId);
    }

    if (removedEntry.displays_changed()) {
        mProtoParser.fromProto(removedEntry.displays(), mStartingDisplayInfos);
    }
}

std::optional<perfetto::protos::TransactionTraceEntry>
TransactionTracing::createStartingStateProtoLocked() {
    if (mStartingStates.empty()) {
        return std::nullopt;
    }

    perfetto::protos::TransactionTraceEntry entryProto;
    entryProto.set_elapsed_realtime_nanos(mStartingTimestamp);
    entryProto.set_vsync_id(0);

    entryProto.mutable_added_layers()->Reserve(static_cast<int32_t>(mStartingStates.size()));
    for (auto& [layerId, state] : mStartingStates) {
        entryProto.mutable_added_layers()->Add(mProtoParser.toProto(state.args));
    }

    perfetto::protos::TransactionState transactionProto = mProtoParser.toProto(mStartingStates);
    transactionProto.set_vsync_id(0);
    transactionProto.set_post_time(mStartingTimestamp);
    entryProto.mutable_transactions()->Add(std::move(transactionProto));

    entryProto.mutable_destroyed_layer_handles()->Reserve(
            static_cast<int32_t>(mRemovedLayerHandlesAtStart.size()));
    for (const uint32_t destroyedLayerHandleId : mRemovedLayerHandlesAtStart) {
        entryProto.mutable_destroyed_layer_handles()->Add(destroyedLayerHandleId);
    }

    entryProto.mutable_displays()->Reserve(static_cast<int32_t>(mStartingDisplayInfos.size()));
    for (auto& [layerStack, displayInfo] : mStartingDisplayInfos) {
        entryProto.mutable_displays()->Add(mProtoParser.toProto(displayInfo, layerStack.id));
    }
    entryProto.set_displays_changed(true);

    return entryProto;
}

} // namespace android
