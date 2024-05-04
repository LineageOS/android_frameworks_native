/*
 * Copyright 2019 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <compositionengine/impl/CompositionEngine.h>
#include <cutils/properties.h>
#include <ui/GraphicBuffer.h>

#include "DisplayDevice.h"
#include "FrameTracer/FrameTracer.h"
#include "Layer.h"
#include "NativeWindowSurface.h"
#include "SurfaceFlingerDefaultFactory.h"
#include "SurfaceFlingerProperties.h"

#include "DisplayHardware/ComposerHal.h"
#include "FrameTimeline/FrameTimeline.h"
#include "Scheduler/Scheduler.h"
#include "Scheduler/VsyncConfiguration.h"
#include "Scheduler/VsyncController.h"

namespace android::surfaceflinger {

DefaultFactory::~DefaultFactory() = default;

std::unique_ptr<HWComposer> DefaultFactory::createHWComposer(const std::string& serviceName) {
    return std::make_unique<android::impl::HWComposer>(serviceName);
}

std::unique_ptr<scheduler::VsyncConfiguration> DefaultFactory::createVsyncConfiguration(
        Fps currentRefreshRate) {
    if (property_get_bool("debug.sf.use_phase_offsets_as_durations", false)) {
        return std::make_unique<scheduler::impl::WorkDuration>(currentRefreshRate);
    } else {
        return std::make_unique<scheduler::impl::PhaseOffsets>(currentRefreshRate);
    }
}

sp<DisplayDevice> DefaultFactory::createDisplayDevice(DisplayDeviceCreationArgs& creationArgs) {
    return sp<DisplayDevice>::make(creationArgs);
}

sp<GraphicBuffer> DefaultFactory::createGraphicBuffer(uint32_t width, uint32_t height,
                                                      PixelFormat format, uint32_t layerCount,
                                                      uint64_t usage, std::string requestorName) {
    return sp<GraphicBuffer>::make(width, height, format, layerCount, usage, requestorName);
}

void DefaultFactory::createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
                                       sp<IGraphicBufferConsumer>* outConsumer,
                                       bool consumerIsSurfaceFlinger) {
    BufferQueue::createBufferQueue(outProducer, outConsumer, consumerIsSurfaceFlinger);
}

std::unique_ptr<surfaceflinger::NativeWindowSurface> DefaultFactory::createNativeWindowSurface(
        const sp<IGraphicBufferProducer>& producer) {
    return surfaceflinger::impl::createNativeWindowSurface(producer);
}

std::unique_ptr<compositionengine::CompositionEngine> DefaultFactory::createCompositionEngine() {
    return compositionengine::impl::createCompositionEngine();
}

sp<Layer> DefaultFactory::createBufferStateLayer(const LayerCreationArgs& args) {
    return sp<Layer>::make(args);
}

sp<Layer> DefaultFactory::createEffectLayer(const LayerCreationArgs& args) {
    return sp<Layer>::make(args);
}

sp<LayerFE> DefaultFactory::createLayerFE(const std::string& layerName, const Layer* /* owner */) {
    return sp<LayerFE>::make(layerName);
}

std::unique_ptr<FrameTracer> DefaultFactory::createFrameTracer() {
    return std::make_unique<FrameTracer>();
}

std::unique_ptr<frametimeline::FrameTimeline> DefaultFactory::createFrameTimeline(
        std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid) {
    return std::make_unique<frametimeline::impl::FrameTimeline>(timeStats, surfaceFlingerPid);
}

} // namespace android::surfaceflinger

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
