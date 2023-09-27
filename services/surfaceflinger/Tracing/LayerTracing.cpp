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
#define LOG_TAG "LayerTracing"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "LayerTracing.h"

#include "LayerDataSource.h"
#include "Tracing/tools/LayerTraceGenerator.h"
#include "TransactionTracing.h"

#include <log/log.h>
#include <perfetto/tracing.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

namespace android {

LayerTracing::LayerTracing() {
    mTakeLayersSnapshotProto = [](uint32_t) { return perfetto::protos::LayersSnapshotProto{}; };
    LayerDataSource::Initialize(*this);
}

LayerTracing::LayerTracing(std::ostream& outStream) : LayerTracing() {
    mOutStream = std::ref(outStream);
}

LayerTracing::~LayerTracing() {
    LayerDataSource::UnregisterLayerTracing();
}

void LayerTracing::setTakeLayersSnapshotProtoFunction(
        const std::function<perfetto::protos::LayersSnapshotProto(uint32_t)>& callback) {
    mTakeLayersSnapshotProto = callback;
}

void LayerTracing::setTransactionTracing(TransactionTracing& transactionTracing) {
    mTransactionTracing = &transactionTracing;
}

void LayerTracing::onStart(Mode mode, uint32_t flags) {
    switch (mode) {
        case Mode::MODE_ACTIVE: {
            mActiveTracingFlags.store(flags);
            mIsActiveTracingStarted.store(true);
            ALOGV("Starting active tracing (waiting for initial snapshot)");
            // It might take a while before a layers change occurs and a "spontaneous" snapshot is
            // taken. Let's manually take a snapshot, so that the trace's first entry will contain
            // the current layers state.
            addProtoSnapshotToOstream(mTakeLayersSnapshotProto(flags), Mode::MODE_ACTIVE);
            ALOGD("Started active tracing (traced initial snapshot)");
            break;
        }
        case Mode::MODE_GENERATED: {
            ALOGD("Started generated tracing (waiting for OnFlush event to generated layers)");
            break;
        }
        case Mode::MODE_DUMP: {
            auto snapshot = mTakeLayersSnapshotProto(flags);
            addProtoSnapshotToOstream(std::move(snapshot), Mode::MODE_DUMP);
            ALOGD("Started dump tracing (dumped single snapshot)");
            break;
        }
        default: {
            ALOGE("Started unknown tracing mode (0x%02x)", mode);
        }
    }
}

void LayerTracing::onFlush(Mode mode, uint32_t flags) {
    // In "generated" mode process the buffer of transactions (owned by TransactionTracing),
    // generate a sequence of layers snapshots and write them to perfetto.
    if (mode != Mode::MODE_GENERATED) {
        return;
    }

    if (!mTransactionTracing) {
        ALOGD("Skipping layers trace generation (transactions tracing disabled)");
        return;
    }

    auto transactionTrace = mTransactionTracing->writeToProto();
    LayerTraceGenerator{}.generate(transactionTrace, flags, *this);
    ALOGD("Flushed generated tracing");
}

void LayerTracing::onStop(Mode mode) {
    if (mode == Mode::MODE_ACTIVE) {
        mIsActiveTracingStarted.store(false);
        ALOGD("Stopped active tracing");
    }
}

void LayerTracing::addProtoSnapshotToOstream(perfetto::protos::LayersSnapshotProto&& snapshot,
                                             Mode mode) {
    ATRACE_CALL();
    if (mOutStream) {
        writeSnapshotToStream(std::move(snapshot));
    } else {
        writeSnapshotToPerfetto(snapshot, mode);
    }
}

bool LayerTracing::isActiveTracingStarted() const {
    return mIsActiveTracingStarted.load();
}

uint32_t LayerTracing::getActiveTracingFlags() const {
    return mActiveTracingFlags.load();
}

bool LayerTracing::isActiveTracingFlagSet(Flag flag) const {
    return (mActiveTracingFlags.load() & flag) != 0;
}

perfetto::protos::LayersTraceFileProto LayerTracing::createTraceFileProto() {
    perfetto::protos::LayersTraceFileProto fileProto;
    fileProto.set_magic_number(
            static_cast<uint64_t>(perfetto::protos::LayersTraceFileProto_MagicNumber_MAGIC_NUMBER_H)
                    << 32 |
            perfetto::protos::LayersTraceFileProto_MagicNumber_MAGIC_NUMBER_L);
    auto timeOffsetNs = static_cast<uint64_t>(systemTime(SYSTEM_TIME_REALTIME) -
                                              systemTime(SYSTEM_TIME_MONOTONIC));
    fileProto.set_real_to_elapsed_time_offset_nanos(timeOffsetNs);
    return fileProto;
}

void LayerTracing::writeSnapshotToStream(perfetto::protos::LayersSnapshotProto&& snapshot) const {
    auto fileProto = createTraceFileProto();
    *fileProto.add_entry() = std::move(snapshot);
    mOutStream->get() << fileProto.SerializeAsString();
}

void LayerTracing::writeSnapshotToPerfetto(const perfetto::protos::LayersSnapshotProto& snapshot,
                                           Mode mode) {
    const auto snapshotBytes = snapshot.SerializeAsString();

    LayerDataSource::Trace([&](LayerDataSource::TraceContext context) {
        if (mode != context.GetCustomTlsState()->mMode) {
            return;
        }
        if (!checkAndUpdateLastVsyncIdWrittenToPerfetto(mode, snapshot.vsync_id())) {
            return;
        }
        {
            auto packet = context.NewTracePacket();
            packet->set_timestamp(static_cast<uint64_t>(snapshot.elapsed_realtime_nanos()));
            packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_MONOTONIC);
            auto* snapshotProto = packet->set_surfaceflinger_layers_snapshot();
            snapshotProto->AppendRawProtoBytes(snapshotBytes.data(), snapshotBytes.size());
        }
        {
            // TODO (b/162206162): remove empty packet when perfetto bug is fixed.
            //  It is currently needed in order not to lose the last trace entry.
            context.NewTracePacket();
        }
    });
}

bool LayerTracing::checkAndUpdateLastVsyncIdWrittenToPerfetto(Mode mode, std::int64_t vsyncId) {
    // In some situations (e.g. two bugreports taken shortly one after the other) the generated
    // sequence of layers snapshots might overlap. Here we check the snapshot's vsyncid to make
    // sure that in generated tracing mode a given snapshot is written only once to perfetto.
    if (mode != Mode::MODE_GENERATED) {
        return true;
    }

    auto lastVsyncId = mLastVsyncIdWrittenToPerfetto.load();
    while (lastVsyncId < vsyncId) {
        if (mLastVsyncIdWrittenToPerfetto.compare_exchange_strong(lastVsyncId, vsyncId)) {
            return true;
        }
    }

    return false;
}

} // namespace android
