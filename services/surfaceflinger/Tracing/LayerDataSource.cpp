/*
 * Copyright 2023 The Android Open Source Project
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

#include "LayerDataSource.h"

#include <log/log.h>
#include <perfetto/config/android/surfaceflinger_layers_config.pbzero.h>

namespace android {

void LayerDataSource::Initialize(LayerTracing& layerTracing) {
    mLayerTracing.store(&layerTracing);

    auto args = perfetto::TracingInitArgs{};
    args.backends = perfetto::kSystemBackend;
    // We are tracing ~50kb/entry and the default shmem buffer size (256kb) could be overrun.
    // A shmem buffer overrun typically just stalls layer tracing, however when the stall
    // lasts for too long perfetto assumes there is a deadlock and aborts surfaceflinger.
    args.shmem_size_hint_kb = 1024;
    perfetto::Tracing::Initialize(args);

    perfetto::DataSourceDescriptor descriptor;
    descriptor.set_name(android::LayerDataSource::kName);
    LayerDataSource::Register(descriptor);
}

void LayerDataSource::UnregisterLayerTracing() {
    mLayerTracing.store(nullptr);
}

void LayerDataSource::OnSetup(const LayerDataSource::SetupArgs& args) {
    const auto configRaw = args.config->surfaceflinger_layers_config_raw();
    const auto config = perfetto::protos::pbzero::SurfaceFlingerLayersConfig::Decoder{configRaw};

    if (config.has_mode() && config.mode() != LayerTracing::Mode::MODE_UNSPECIFIED) {
        mMode = static_cast<LayerTracing::Mode>(config.mode());
    } else {
        mMode = LayerTracing::Mode::MODE_GENERATED_BUGREPORT_ONLY;
        ALOGD("Received config with unspecified 'mode'."
              " Using 'MODE_GENERATED_BUGREPORT_ONLY' as default");
    }

    mFlags = 0;
    for (auto it = config.trace_flags(); it; ++it) {
        mFlags |= static_cast<uint32_t>(*it);
    }
}

void LayerDataSource::OnStart(const LayerDataSource::StartArgs&) {
    ALOGD("Received OnStart event (mode = 0x%02x, flags = 0x%02x)", mMode, mFlags);
    if (auto* p = mLayerTracing.load()) {
        p->onStart(mMode, mFlags);
    }
}

void LayerDataSource::OnFlush(const LayerDataSource::FlushArgs& args) {
    ALOGD("Received OnFlush event"
          " (mode = 0x%02x, flags = 0x%02x, reason = 0x%" PRIx64 ", clone_target = 0x%0" PRIx64 ")",
          mMode, mFlags, args.flush_flags.reason(), args.flush_flags.clone_target());

    bool isBugreport = args.flush_flags.reason() == perfetto::FlushFlags::Reason::kTraceClone &&
            args.flush_flags.clone_target() == perfetto::FlushFlags::CloneTarget::kBugreport;

    if (auto* p = mLayerTracing.load()) {
        p->onFlush(mMode, mFlags, isBugreport);
    }
}

void LayerDataSource::OnStop(const LayerDataSource::StopArgs&) {
    ALOGD("Received OnStop event (mode = 0x%02x, flags = 0x%02x)", mMode, mFlags);
    if (auto* p = mLayerTracing.load()) {
        p->onStop(mMode);
    }
}

LayerTracing::Mode LayerDataSource::GetMode() const {
    return mMode;
}

std::atomic<LayerTracing*> LayerDataSource::mLayerTracing = nullptr;

} // namespace android

PERFETTO_DEFINE_DATA_SOURCE_STATIC_MEMBERS(android::LayerDataSource);
