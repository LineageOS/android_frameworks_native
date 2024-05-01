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

#pragma once

#include "SurfaceFlingerFactory.h"

namespace android::surfaceflinger {

// A default implementation of the factory which creates the standard
// implementation types for each interface.
class DefaultFactory : public surfaceflinger::Factory {
public:
    virtual ~DefaultFactory();

    std::unique_ptr<HWComposer> createHWComposer(const std::string& serviceName) override;
    std::unique_ptr<scheduler::VsyncConfiguration> createVsyncConfiguration(
            Fps currentRefreshRate) override;
    sp<DisplayDevice> createDisplayDevice(DisplayDeviceCreationArgs&) override;
    sp<GraphicBuffer> createGraphicBuffer(uint32_t width, uint32_t height, PixelFormat format,
                                          uint32_t layerCount, uint64_t usage,
                                          std::string requestorName) override;
    void createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
                           sp<IGraphicBufferConsumer>* outConsumer,
                           bool consumerIsSurfaceFlinger) override;
    std::unique_ptr<surfaceflinger::NativeWindowSurface> createNativeWindowSurface(
            const sp<IGraphicBufferProducer>&) override;
    std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine() override;
    sp<Layer> createBufferStateLayer(const LayerCreationArgs& args) override;
    sp<Layer> createEffectLayer(const LayerCreationArgs& args) override;
    sp<LayerFE> createLayerFE(const std::string& layerName, const Layer* owner) override;
    std::unique_ptr<FrameTracer> createFrameTracer() override;
    std::unique_ptr<frametimeline::FrameTimeline> createFrameTimeline(
            std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid) override;
};

} // namespace android::surfaceflinger
