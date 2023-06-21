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

#pragma once

#include <android-base/thread_annotations.h>
#include <layerproto/TransactionProto.h>
#include <utils/Errors.h>
#include <utils/Singleton.h>
#include <utils/Timers.h>

#include <memory>
#include <mutex>
#include <thread>

#include "FrontEnd/DisplayInfo.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/Update.h"
#include "LocklessStack.h"
#include "RingBuffer.h"
#include "TransactionProtoParser.h"

using namespace android::surfaceflinger;

namespace android {

class SurfaceFlinger;
class TransactionTracingTest;

/*
 * Records all committed transactions into a ring bufffer.
 *
 * Transactions come in via the binder thread. They are serialized to proto
 * and stored in a map using the transaction id as key. Main thread will
 * pass the list of transaction ids that are committed every vsync and notify
 * the tracing thread. The tracing thread will then wake up and add the
 * committed transactions to the ring buffer.
 *
 * When generating SF dump state, we will flush the buffer to a file which
 * will then be included in the bugreport.
 *
 */
class TransactionTracing {
public:
    TransactionTracing();
    ~TransactionTracing();

    void addQueuedTransaction(const TransactionState&);
    void addCommittedTransactions(int64_t vsyncId, nsecs_t commitTime, frontend::Update& update,
                                  const frontend::DisplayInfos&, bool displayInfoChanged);
    status_t writeToFile(const std::string& filename = FILE_PATH);
    void setBufferSize(size_t bufferSizeInBytes);
    void onLayerRemoved(int layerId);
    void dump(std::string&) const;
    // Wait until all the committed transactions for the specified vsync id are added to the buffer.
    void flush() EXCLUDES(mMainThreadLock);
    static constexpr auto CONTINUOUS_TRACING_BUFFER_SIZE = 512 * 1024;
    static constexpr auto ACTIVE_TRACING_BUFFER_SIZE = 100 * 1024 * 1024;
    // version 1 - switching to support new frontend
    static constexpr auto TRACING_VERSION = 1;

private:
    friend class TransactionTracingTest;
    friend class SurfaceFlinger;

    static constexpr auto DIR_NAME = "/data/misc/wmtrace/";
    static constexpr auto FILE_NAME = "/transactions_trace.winscope";
    static constexpr auto FILE_PATH = "/data/misc/wmtrace/transactions_trace.winscope";

    mutable std::mutex mTraceLock;
    RingBuffer<proto::TransactionTraceFile, proto::TransactionTraceEntry> mBuffer
            GUARDED_BY(mTraceLock);
    size_t mBufferSizeInBytes GUARDED_BY(mTraceLock) = CONTINUOUS_TRACING_BUFFER_SIZE;
    std::unordered_map<uint64_t, proto::TransactionState> mQueuedTransactions
            GUARDED_BY(mTraceLock);
    LocklessStack<proto::TransactionState> mTransactionQueue;
    nsecs_t mStartingTimestamp GUARDED_BY(mTraceLock);
    std::unordered_map<int, proto::LayerCreationArgs> mCreatedLayers GUARDED_BY(mTraceLock);
    std::map<uint32_t /* layerId */, TracingLayerState> mStartingStates GUARDED_BY(mTraceLock);
    frontend::DisplayInfos mStartingDisplayInfos GUARDED_BY(mTraceLock);

    std::set<uint32_t /* layerId */> mRemovedLayerHandlesAtStart GUARDED_BY(mTraceLock);
    TransactionProtoParser mProtoParser;

    // We do not want main thread to block so main thread will try to acquire mMainThreadLock,
    // otherwise will push data to temporary container.
    std::mutex mMainThreadLock;
    std::thread mThread GUARDED_BY(mMainThreadLock);
    bool mDone GUARDED_BY(mMainThreadLock) = false;
    std::condition_variable mTransactionsAvailableCv;
    std::condition_variable mTransactionsAddedToBufferCv;
    struct CommittedUpdates {
        std::vector<uint64_t> transactionIds;
        std::vector<LayerCreationArgs> createdLayers;
        std::vector<uint32_t> destroyedLayerHandles;
        bool displayInfoChanged;
        frontend::DisplayInfos displayInfos;
        int64_t vsyncId;
        int64_t timestamp;
    };
    std::vector<CommittedUpdates> mUpdates GUARDED_BY(mMainThreadLock);
    std::vector<CommittedUpdates> mPendingUpdates; // only accessed by main thread

    std::vector<uint32_t /* layerId */> mDestroyedLayers GUARDED_BY(mMainThreadLock);
    std::vector<uint32_t /* layerId */> mPendingDestroyedLayers; // only accessed by main thread
    int64_t mLastUpdatedVsyncId = -1;

    proto::TransactionTraceFile createTraceFileProto() const;
    void loop();
    void addEntry(const std::vector<CommittedUpdates>& committedTransactions,
                  const std::vector<uint32_t>& removedLayers) EXCLUDES(mTraceLock);
    int32_t getLayerIdLocked(const sp<IBinder>& layerHandle) REQUIRES(mTraceLock);
    void tryPushToTracingThread() EXCLUDES(mMainThreadLock);
    void addStartingStateToProtoLocked(proto::TransactionTraceFile& proto) REQUIRES(mTraceLock);
    void updateStartingStateLocked(const proto::TransactionTraceEntry& entry) REQUIRES(mTraceLock);
    // TEST
    // Return buffer contents as trace file proto
    proto::TransactionTraceFile writeToProto() EXCLUDES(mMainThreadLock);
};

class TransactionTraceWriter : public Singleton<TransactionTraceWriter> {
    friend class Singleton<TransactionTracing>;
    std::function<void(const std::string& prefix, bool overwrite)> mWriterFunction =
            [](const std::string&, bool) {};

public:
    void setWriterFunction(
            std::function<void(const std::string& prefix, bool overwrite)> function) {
        mWriterFunction = std::move(function);
    }
    void invoke(const std::string& prefix, bool overwrite) { mWriterFunction(prefix, overwrite); }
};

} // namespace android
