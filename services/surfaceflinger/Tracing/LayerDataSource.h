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

#pragma once

#include "LayerTracing.h"

#include <perfetto/tracing.h>

#include <atomic>

namespace android {

/*
 * Thread local storage used for fast (lock free) read of data source's properties.
 *
 */
struct LayerDataSourceTlsState {
    template <typename TraceContext>
    explicit LayerDataSourceTlsState(const TraceContext& trace_context) {
        auto dataSource = trace_context.GetDataSourceLocked();
        mMode = dataSource.valid()
                ? dataSource->GetMode()
                : perfetto::protos::pbzero::SurfaceFlingerLayersConfig::Mode::MODE_GENERATED;
    }

    LayerTracing::Mode mMode;
};

struct LayerDataSourceTraits : public perfetto::DefaultDataSourceTraits {
    using TlsStateType = LayerDataSourceTlsState;
};

/*
 * Defines the Perfetto custom data source 'android.surfaceflinger.layers'.
 *
 * Registers the data source with Perfetto, listens to Perfetto events (setup/start/flush/stop)
 * and writes trace packets to Perfetto.
 *
 */
class LayerDataSource : public perfetto::DataSource<LayerDataSource, LayerDataSourceTraits> {
public:
    static void Initialize(LayerTracing&);
    static void UnregisterLayerTracing();
    void OnSetup(const SetupArgs&) override;
    void OnStart(const StartArgs&) override;
    void OnFlush(const FlushArgs&) override;
    void OnStop(const StopArgs&) override;
    LayerTracing::Mode GetMode() const;

    static constexpr auto* kName = "android.surfaceflinger.layers";
    static constexpr perfetto::BufferExhaustedPolicy kBufferExhaustedPolicy =
            perfetto::BufferExhaustedPolicy::kStall;
    static constexpr bool kRequiresCallbacksUnderLock = false;

private:
    static std::atomic<LayerTracing*> mLayerTracing;
    LayerTracing::Mode mMode;
    std::uint32_t mFlags;
};

} // namespace android

PERFETTO_DECLARE_DATA_SOURCE_STATIC_MEMBERS(android::LayerDataSource);
