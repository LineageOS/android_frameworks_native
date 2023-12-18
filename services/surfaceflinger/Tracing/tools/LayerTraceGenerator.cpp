/*
 * Copyright (C) 2022 The Android Open Source Project
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
#define LOG_TAG "LayerTraceGenerator"
//#define LOG_NDEBUG 0

#include <Tracing/TransactionProtoParser.h>
#include <gui/LayerState.h>
#include <log/log.h>
#include <renderengine/ExternalTexture.h>
#include <utils/String16.h>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <vector>
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/RequestedLayerState.h"
#include "LayerProtoHelper.h"
#include "Tracing/LayerTracing.h"
#include "TransactionState.h"
#include "cutils/properties.h"

#include "LayerTraceGenerator.h"

namespace android {
using namespace ftl::flag_operators;

namespace {
class ScopedTraceDisabler {
public:
    ScopedTraceDisabler() { TransactionTraceWriter::getInstance().disable(); }
    ~ScopedTraceDisabler() { TransactionTraceWriter::getInstance().enable(); }
};
} // namespace

bool LayerTraceGenerator::generate(const perfetto::protos::TransactionTraceFile& traceFile,
                                   std::uint32_t traceFlags, LayerTracing& layerTracing,
                                   bool onlyLastEntry) {
    // We are generating the layers trace by replaying back a set of transactions. If the
    // transactions have unexpected states, we may generate a transaction trace to debug
    // the unexpected state. This is silly. So we disable it by poking the
    // TransactionTraceWriter. This is really a hack since we should manage our depenecies a
    // little better.
    ScopedTraceDisabler fatalErrorTraceDisabler;

    if (traceFile.entry_size() == 0) {
        ALOGD("Trace file is empty");
        return false;
    }

    TransactionProtoParser parser(std::make_unique<TransactionProtoParser::FlingerDataMapper>());

    // frontend
    frontend::LayerLifecycleManager lifecycleManager;
    frontend::LayerHierarchyBuilder hierarchyBuilder;
    frontend::LayerSnapshotBuilder snapshotBuilder;
    ui::DisplayMap<ui::LayerStack, frontend::DisplayInfo> displayInfos;

    ShadowSettings globalShadowSettings{.ambientColor = {1, 1, 1, 1}};
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.surface_flinger.supports_background_blur", value, "0");
    bool supportsBlur = atoi(value);

    ALOGD("Generating %d transactions...", traceFile.entry_size());
    for (int i = 0; i < traceFile.entry_size(); i++) {
        // parse proto
        perfetto::protos::TransactionTraceEntry entry = traceFile.entry(i);
        ALOGV("    Entry %04d/%04d for time=%" PRId64 " vsyncid=%" PRId64
              " layers +%d -%d handles -%d transactions=%d",
              i, traceFile.entry_size(), entry.elapsed_realtime_nanos(), entry.vsync_id(),
              entry.added_layers_size(), entry.destroyed_layers_size(),
              entry.destroyed_layer_handles_size(), entry.transactions_size());

        std::vector<std::unique_ptr<frontend::RequestedLayerState>> addedLayers;
        addedLayers.reserve((size_t)entry.added_layers_size());
        for (int j = 0; j < entry.added_layers_size(); j++) {
            LayerCreationArgs args;
            parser.fromProto(entry.added_layers(j), args);
            ALOGV("       %s", args.getDebugString().c_str());
            addedLayers.emplace_back(std::make_unique<frontend::RequestedLayerState>(args));
        }

        std::vector<TransactionState> transactions;
        transactions.reserve((size_t)entry.transactions_size());
        for (int j = 0; j < entry.transactions_size(); j++) {
            // apply transactions
            TransactionState transaction = parser.fromProto(entry.transactions(j));
            for (auto& resolvedComposerState : transaction.states) {
                if (resolvedComposerState.state.what & layer_state_t::eInputInfoChanged) {
                    if (!resolvedComposerState.state.windowInfoHandle->getInfo()->inputConfig.test(
                                gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL)) {
                        // create a fake token since the FE expects a valid token
                        resolvedComposerState.state.windowInfoHandle->editInfo()->token =
                                sp<BBinder>::make();
                    }
                }
            }
            transactions.emplace_back(std::move(transaction));
        }

        for (int j = 0; j < entry.destroyed_layers_size(); j++) {
            ALOGV("       destroyedHandles=%d", entry.destroyed_layers(j));
        }

        std::vector<std::pair<uint32_t, std::string>> destroyedHandles;
        destroyedHandles.reserve((size_t)entry.destroyed_layer_handles_size());
        for (int j = 0; j < entry.destroyed_layer_handles_size(); j++) {
            ALOGV("       destroyedHandles=%d", entry.destroyed_layer_handles(j));
            destroyedHandles.push_back({entry.destroyed_layer_handles(j), ""});
        }

        bool displayChanged = entry.displays_changed();
        if (displayChanged) {
            parser.fromProto(entry.displays(), displayInfos);
        }

        // apply updates
        lifecycleManager.addLayers(std::move(addedLayers));
        lifecycleManager.applyTransactions(transactions, /*ignoreUnknownHandles=*/true);
        lifecycleManager.onHandlesDestroyed(destroyedHandles, /*ignoreUnknownHandles=*/true);

        // update hierarchy
        hierarchyBuilder.update(lifecycleManager);

        // update snapshots
        frontend::LayerSnapshotBuilder::Args args{.root = hierarchyBuilder.getHierarchy(),
                                                  .layerLifecycleManager = lifecycleManager,
                                                  .displays = displayInfos,
                                                  .displayChanges = displayChanged,
                                                  .globalShadowSettings = globalShadowSettings,
                                                  .supportsBlur = supportsBlur,
                                                  .forceFullDamage = false,
                                                  .supportedLayerGenericMetadata = {},
                                                  .genericLayerMetadataKeyMap = {}};
        snapshotBuilder.update(args);

        bool visibleRegionsDirty = lifecycleManager.getGlobalChanges().any(
                frontend::RequestedLayerState::Changes::VisibleRegion |
                frontend::RequestedLayerState::Changes::Hierarchy |
                frontend::RequestedLayerState::Changes::Visibility);

        ALOGV("    layers:%04zu snapshots:%04zu changes:%s", lifecycleManager.getLayers().size(),
              snapshotBuilder.getSnapshots().size(),
              lifecycleManager.getGlobalChanges().string().c_str());

        lifecycleManager.commitChanges();

        auto layersProto =
                LayerProtoFromSnapshotGenerator(snapshotBuilder, displayInfos, {}, traceFlags)
                        .generate(hierarchyBuilder.getHierarchy());
        auto displayProtos = LayerProtoHelper::writeDisplayInfoToProto(displayInfos);
        if (!onlyLastEntry || (i == traceFile.entry_size() - 1)) {
            perfetto::protos::LayersSnapshotProto snapshotProto{};
            snapshotProto.set_vsync_id(entry.vsync_id());
            snapshotProto.set_elapsed_realtime_nanos(entry.elapsed_realtime_nanos());
            snapshotProto.set_where(visibleRegionsDirty ? "visibleRegionsDirty" : "bufferLatched");
            *snapshotProto.mutable_layers() = std::move(layersProto);
            if ((traceFlags & LayerTracing::TRACE_COMPOSITION) == 0) {
                snapshotProto.set_excludes_composition_state(true);
            }
            *snapshotProto.mutable_displays() = std::move(displayProtos);

            layerTracing.addProtoSnapshotToOstream(std::move(snapshotProto),
                                                   LayerTracing::Mode::MODE_GENERATED);
        }
    }
    ALOGD("End of generating trace file");
    return true;
}

} // namespace android
