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

#include <layerproto/LayerProtoHeader.h>

#include <atomic>
#include <functional>
#include <optional>
#include <ostream>

namespace android {

class TransactionTracing;

/*
 * LayerTracing records layer states during surface flinging. Manages tracing state and
 * configuration.
 *
 * The traced data can then be collected with Perfetto.
 *
 * The Perfetto custom data source LayerDataSource is registered with perfetto. The data source
 * is used to listen to perfetto events (setup, start, stop, flush) and to write trace packets
 * to perfetto.
 *
 * The user can configure/start/stop tracing via /system/bin/perfetto.
 *
 * Tracing can operate in the following modes.
 *
 * ACTIVE mode:
 * A layers snapshot is taken and written to perfetto for each vsyncid commit.
 *
 * GENERATED mode:
 * Listens to the perfetto 'flush' event (e.g. when a bugreport is taken).
 * When a 'flush' event is received, the ring buffer of transactions (hold by TransactionTracing)
 * is processed by LayerTraceGenerator, a sequence of layers snapshots is generated
 * and written to perfetto.
 *
 * DUMP mode:
 * When the 'start' event is received a single layers snapshot is taken
 * and written to perfetto.
 *
 *
 * E.g. start active mode tracing
 * (replace mode value with MODE_DUMP, MODE_GENERATED or MODE_GENERATED_BUGREPORT_ONLY to enable
 * different tracing modes):
 *
   adb shell -t perfetto \
     -c - --txt \
     -o /data/misc/perfetto-traces/trace \
   <<EOF
   unique_session_name: "surfaceflinger_layers_active"
   buffers: {
       size_kb: 63488
       fill_policy: RING_BUFFER
   }
   data_sources: {
       config {
           name: "android.surfaceflinger.layers"
           surfaceflinger_layers_config: {
               mode: MODE_ACTIVE
               trace_flags: TRACE_FLAG_INPUT
               trace_flags: TRACE_FLAG_COMPOSITION
               trace_flags: TRACE_FLAG_HWC
               trace_flags: TRACE_FLAG_BUFFERS
               trace_flags: TRACE_FLAG_VIRTUAL_DISPLAYS
           }
       }
   }
EOF
 *
 */
class LayerTracing {
public:
    using Mode = perfetto::protos::pbzero::SurfaceFlingerLayersConfig::Mode;

    enum Flag : uint32_t {
        TRACE_INPUT = 1 << 1,
        TRACE_COMPOSITION = 1 << 2,
        TRACE_EXTRA = 1 << 3,
        TRACE_HWC = 1 << 4,
        TRACE_BUFFERS = 1 << 5,
        TRACE_VIRTUAL_DISPLAYS = 1 << 6,
        TRACE_ALL = TRACE_INPUT | TRACE_COMPOSITION | TRACE_EXTRA,
    };

    LayerTracing();
    LayerTracing(std::ostream&);
    ~LayerTracing();
    void setTakeLayersSnapshotProtoFunction(
            const std::function<perfetto::protos::LayersSnapshotProto(uint32_t)>&);
    void setTransactionTracing(TransactionTracing&);

    // Start event from perfetto data source
    void onStart(Mode mode, uint32_t flags);
    // Flush event from perfetto data source
    void onFlush(Mode mode, uint32_t flags, bool isBugreport);
    // Stop event from perfetto data source
    void onStop(Mode mode);

    void addProtoSnapshotToOstream(perfetto::protos::LayersSnapshotProto&& snapshot, Mode mode);
    bool isActiveTracingStarted() const;
    uint32_t getActiveTracingFlags() const;
    bool isActiveTracingFlagSet(Flag flag) const;
    static perfetto::protos::LayersTraceFileProto createTraceFileProto();

private:
    void writeSnapshotToStream(perfetto::protos::LayersSnapshotProto&& snapshot) const;
    void writeSnapshotToPerfetto(const perfetto::protos::LayersSnapshotProto& snapshot, Mode mode);
    bool checkAndUpdateLastVsyncIdWrittenToPerfetto(Mode mode, std::int64_t vsyncId);

    std::function<perfetto::protos::LayersSnapshotProto(uint32_t)> mTakeLayersSnapshotProto;
    TransactionTracing* mTransactionTracing;

    std::atomic<bool> mIsActiveTracingStarted{false};
    std::atomic<uint32_t> mActiveTracingFlags{0};
    std::atomic<std::int64_t> mLastVsyncIdWrittenToPerfetto{-1};
    std::optional<std::reference_wrapper<std::ostream>> mOutStream;
};

} // namespace android
