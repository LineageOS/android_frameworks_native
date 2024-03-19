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

#include <mutex>
#include <optional>
#include <set>
#include <thread>

#include "FrontEnd/DisplayInfo.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/Update.h"
#include "LocklessStack.h"
#include "TransactionProtoParser.h"
#include "TransactionRingBuffer.h"

using namespace android::surfaceflinger;

namespace android {

class SurfaceFlinger;
class TransactionTracingTest;

/*
 * Records all committed transactions into a ring buffer.
 *
 * Transactions come in via the binder thread. They are serialized to proto
 * and stored in a map using the transaction id as key. Main thread will
 * pass the list of transaction ids that are committed every vsync and notify
 * the tracing thread. The tracing thread will then wake up and add the
 * committed transactions to the ring buffer.
 *
 * The traced data can then be collected via:
 * - Perfetto (preferred).
 * - File system, after triggering the disk write through SF backdoor. This is legacy and is going
 *   to be phased out.
 *
 * The Perfetto custom data source TransactionDataSource is registered with perfetto and is used
 * to listen to perfetto events (setup, start, stop, flush) and to write trace packets to perfetto.
 *
 * The user can configure/start/stop tracing via /system/bin/perfetto.
 *
 * Tracing can operate in the following modes.
 *
 * ACTIVE mode:
 * The transactions ring buffer (starting state + following committed transactions) is written
 * (only once) to perfetto when the 'start' event is received.
 * Transactions are then written to perfetto each time they are committed.
 * On the receiver side, the data source is to be configured to periodically
 * flush data to disk providing virtually infinite storage.
 *
 * CONTINUOUS mode:
 * Listens to the perfetto 'flush' event (e.g. when a bugreport is taken).
 * When a 'flush' event is received, the ring buffer of transactions (starting state + following
 * committed transactions) is written to perfetto. On the receiver side, the data source is to be
 * configured with a dedicated buffer large enough to store all the flushed data.
 *
 *
 * E.g. start active mode tracing:
 *
   adb shell perfetto \
     -c - --txt \
     -o /data/misc/perfetto-traces/trace \
   <<EOF
   unique_session_name: "surfaceflinger_transactions_active"
   buffers: {
       size_kb: 1024
       fill_policy: RING_BUFFER
   }
   data_sources: {
       config {
           name: "android.surfaceflinger.transactions"
           surfaceflinger_transactions_config: {
               mode: MODE_ACTIVE
           }
       }
   }
   write_into_file: true
   file_write_period_ms: 100
   EOF
 *
 *
 * E.g. start continuous mode tracing:
 *
   adb shell perfetto \
     -c - --txt \
     -o /data/misc/perfetto-traces/trace \
   <<EOF
   unique_session_name: "surfaceflinger_transactions_continuous"
   buffers: {
       size_kb: 1024
       fill_policy: RING_BUFFER
   }
   data_sources: {
       config {
           name: "android.surfaceflinger.transactions"
           surfaceflinger_transactions_config: {
               mode: MODE_CONTINUOUS
           }
       }
   }
   EOF
 *
 */
class TransactionTracing {
public:
    using Mode = perfetto::protos::pbzero::SurfaceFlingerTransactionsConfig::Mode;

    TransactionTracing();
    ~TransactionTracing();

    // Start event from perfetto data source
    void onStart(Mode mode);
    // Flush event from perfetto data source
    void onFlush(Mode mode);

    void addQueuedTransaction(const TransactionState&);
    void addCommittedTransactions(int64_t vsyncId, nsecs_t commitTime, frontend::Update& update,
                                  const frontend::DisplayInfos&, bool displayInfoChanged);
    status_t writeToFile(const std::string& filename = FILE_PATH);
    // Return buffer contents as trace file proto
    perfetto::protos::TransactionTraceFile writeToProto() EXCLUDES(mMainThreadLock);
    void setBufferSize(size_t bufferSizeInBytes);
    void onLayerRemoved(int layerId);
    void dump(std::string&) const;
    // Wait until all the committed transactions for the specified vsync id are added to the buffer.
    void flush() EXCLUDES(mMainThreadLock);

    static constexpr auto CONTINUOUS_TRACING_BUFFER_SIZE = 512 * 1024;
    static constexpr auto LEGACY_ACTIVE_TRACING_BUFFER_SIZE = 100 * 1024 * 1024;
    // version 1 - switching to support new frontend
    static constexpr auto TRACING_VERSION = 1;

private:
    friend class TransactionTraceWriter;
    friend class TransactionTracingTest;
    friend class SurfaceFlinger;

    static constexpr auto DIR_NAME = "/data/misc/wmtrace/";
    static constexpr auto FILE_NAME = "transactions_trace.winscope";
    static constexpr auto FILE_PATH = "/data/misc/wmtrace/transactions_trace.winscope";
    static std::string getFilePath(const std::string& prefix) {
        return DIR_NAME + prefix + FILE_NAME;
    }

    mutable std::mutex mTraceLock;
    TransactionRingBuffer<perfetto::protos::TransactionTraceFile,
                          perfetto::protos::TransactionTraceEntry>
            mBuffer GUARDED_BY(mTraceLock);
    std::unordered_map<uint64_t, perfetto::protos::TransactionState> mQueuedTransactions
            GUARDED_BY(mTraceLock);
    LocklessStack<perfetto::protos::TransactionState> mTransactionQueue;
    nsecs_t mStartingTimestamp GUARDED_BY(mTraceLock);
    std::unordered_map<int, perfetto::protos::LayerCreationArgs> mCreatedLayers
            GUARDED_BY(mTraceLock);
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

    void writeRingBufferToPerfetto(TransactionTracing::Mode mode);
    perfetto::protos::TransactionTraceFile createTraceFileProto() const;
    void loop();
    void addEntry(const std::vector<CommittedUpdates>& committedTransactions,
                  const std::vector<uint32_t>& removedLayers) EXCLUDES(mTraceLock);
    int32_t getLayerIdLocked(const sp<IBinder>& layerHandle) REQUIRES(mTraceLock);
    void tryPushToTracingThread() EXCLUDES(mMainThreadLock);
    std::optional<perfetto::protos::TransactionTraceEntry> createStartingStateProtoLocked()
            REQUIRES(mTraceLock);
    void updateStartingStateLocked(const perfetto::protos::TransactionTraceEntry& entry)
            REQUIRES(mTraceLock);
};

class TransactionTraceWriter : public Singleton<TransactionTraceWriter> {
    friend class Singleton<TransactionTracing>;
    std::function<void(const std::string& prefix, bool overwrite)> mWriterFunction =
            [](const std::string&, bool) {};
    std::atomic<bool> mEnabled{true};

    void doInvoke(const std::string& filename, bool overwrite) {
        if (mEnabled) {
            mWriterFunction(filename, overwrite);
        }
    };

public:
    void setWriterFunction(
            std::function<void(const std::string& filename, bool overwrite)> function) {
        mWriterFunction = std::move(function);
    }
    void invoke(const std::string& prefix, bool overwrite) {
        doInvoke(TransactionTracing::getFilePath(prefix), overwrite);
    }
    /* pass in a complete file path for testing */
    void invokeForTest(const std::string& filename, bool overwrite) {
        doInvoke(filename, overwrite);
    }
    /* hacky way to avoid generating traces when converting transaction trace to layers trace. */
    void disable() { mEnabled.store(false); }
    void enable() { mEnabled.store(true); }
};

} // namespace android
