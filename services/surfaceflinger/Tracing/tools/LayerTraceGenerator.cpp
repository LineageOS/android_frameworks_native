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

bool LayerTraceGenerator::generate(const proto::TransactionTraceFile& traceFile,
                                   const char* outputLayersTracePath, bool onlyLastEntry) {
    if (traceFile.entry_size() == 0) {
        ALOGD("Trace file is empty");
        return false;
    }

    TransactionProtoParser parser(std::make_unique<TransactionProtoParser::FlingerDataMapper>());

    // frontend
    frontend::LayerLifecycleManager lifecycleManager;
    frontend::LayerHierarchyBuilder hierarchyBuilder{{}};
    frontend::LayerSnapshotBuilder snapshotBuilder;
    ui::DisplayMap<ui::LayerStack, frontend::DisplayInfo> displayInfos;

    renderengine::ShadowSettings globalShadowSettings{.ambientColor = {1, 1, 1, 1}};
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.surface_flinger.supports_background_blur", value, "0");
    bool supportsBlur = atoi(value);

    LayerTracing layerTracing;
    layerTracing.setTraceFlags(LayerTracing::TRACE_INPUT | LayerTracing::TRACE_BUFFERS);
    // 10MB buffer size (large enough to hold a single entry)
    layerTracing.setBufferSize(10 * 1024 * 1024);
    layerTracing.enable();
    layerTracing.writeToFile(outputLayersTracePath);
    std::ofstream out(outputLayersTracePath, std::ios::binary | std::ios::app);

    ALOGD("Generating %d transactions...", traceFile.entry_size());
    for (int i = 0; i < traceFile.entry_size(); i++) {
        // parse proto
        proto::TransactionTraceEntry entry = traceFile.entry(i);
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

        std::vector<uint32_t> destroyedHandles;
        destroyedHandles.reserve((size_t)entry.destroyed_layer_handles_size());
        for (int j = 0; j < entry.destroyed_layer_handles_size(); j++) {
            ALOGV("       destroyedHandles=%d", entry.destroyed_layer_handles(j));
            destroyedHandles.push_back(entry.destroyed_layer_handles(j));
        }

        bool displayChanged = entry.displays_changed();
        if (displayChanged) {
            parser.fromProto(entry.displays(), displayInfos);
        }

        // apply updates
        lifecycleManager.addLayers(std::move(addedLayers));
        lifecycleManager.applyTransactions(transactions, /*ignoreUnknownHandles=*/true);
        lifecycleManager.onHandlesDestroyed(destroyedHandles, /*ignoreUnknownHandles=*/true);

        if (lifecycleManager.getGlobalChanges().test(
                    frontend::RequestedLayerState::Changes::Hierarchy)) {
            hierarchyBuilder.update(lifecycleManager.getLayers(),
                                    lifecycleManager.getDestroyedLayers());
        }

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

        LayersProto layersProto = LayerProtoFromSnapshotGenerator(snapshotBuilder, displayInfos, {},
                                                                  layerTracing.getFlags())
                                          .generate(hierarchyBuilder.getHierarchy());
        auto displayProtos = LayerProtoHelper::writeDisplayInfoToProto(displayInfos);
        if (!onlyLastEntry || (i == traceFile.entry_size() - 1)) {
            layerTracing.notify(visibleRegionsDirty, entry.elapsed_realtime_nanos(),
                                entry.vsync_id(), &layersProto, {}, &displayProtos);
            layerTracing.appendToStream(out);
        }
    }
    layerTracing.disable("", /*writeToFile=*/false);
    out.close();
    ALOGD("End of generating trace file. File written to %s", outputLayersTracePath);
    return true;
}

} // namespace android
