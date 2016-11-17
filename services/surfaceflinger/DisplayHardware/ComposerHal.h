/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_SF_COMPOSER_HAL_H
#define ANDROID_SF_COMPOSER_HAL_H

#include <string>
#include <vector>

#include <android/hardware/graphics/composer/2.1/IComposer.h>
#include <utils/StrongPointer.h>

namespace android {

namespace Hwc2 {

using android::hardware::graphics::common::V1_0::ColorMode;
using android::hardware::graphics::common::V1_0::ColorTransform;
using android::hardware::graphics::common::V1_0::Dataspace;
using android::hardware::graphics::common::V1_0::Hdr;
using android::hardware::graphics::common::V1_0::PixelFormat;
using android::hardware::graphics::common::V1_0::Transform;

using android::hardware::graphics::composer::V2_1::IComposer;
using android::hardware::graphics::composer::V2_1::IComposerCallback;
using android::hardware::graphics::composer::V2_1::Error;
using android::hardware::graphics::composer::V2_1::Display;
using android::hardware::graphics::composer::V2_1::Layer;
using android::hardware::graphics::composer::V2_1::Config;

// Composer is a wrapper to IComposer, a proxy to server-side composer.
class Composer {
public:
    Composer();

    std::vector<IComposer::Capability> getCapabilities() const;
    std::string dumpDebugInfo() const;

    void registerCallback(const sp<IComposerCallback>& callback) const;

    uint32_t getMaxVirtualDisplayCount() const;
    Error createVirtualDisplay(uint32_t width, uint32_t height,
            PixelFormat& format, Display& display) const;
    Error destroyVirtualDisplay(Display display) const;

    Error acceptDisplayChanges(Display display) const;

    Error createLayer(Display display, Layer& layer) const;
    Error destroyLayer(Display display, Layer layer) const;

    Error getActiveConfig(Display display, Config& config) const;
    Error getChangedCompositionTypes(Display display,
            std::vector<Layer>& layers,
            std::vector<IComposer::Composition>& types) const;
    Error getColorModes(Display display, std::vector<ColorMode>& modes) const;
    Error getDisplayAttribute(Display display, Config config,
            IComposer::Attribute attribute, int32_t& value) const;
    Error getDisplayConfigs(Display display,
            std::vector<Config>& configs) const;
    Error getDisplayName(Display display, std::string& name) const;

    Error getDisplayRequests(Display display, uint32_t& displayRequestMask,
            std::vector<Layer>& layers,
            std::vector<uint32_t>& layerRequestMasks) const;

    Error getDisplayType(Display display, IComposer::DisplayType& type) const;
    Error getDozeSupport(Display display, bool& support) const;
    Error getHdrCapabilities(Display display, std::vector<Hdr>& types,
            float& maxLuminance, float& maxAverageLuminance,
            float& minLuminance) const;

    Error getReleaseFences(Display display, std::vector<Layer>& layers,
            std::vector<int>& releaseFences) const;

    Error presentDisplay(Display display, int& presentFence) const;

    Error setActiveConfig(Display display, Config config) const;
    Error setClientTarget(Display display, const native_handle_t* target,
            int acquireFence, Dataspace dataspace,
            const std::vector<IComposer::Rect>& damage) const;
    Error setColorMode(Display display, ColorMode mode) const;
    Error setColorTransform(Display display, const float* matrix,
            ColorTransform hint) const;
    Error setOutputBuffer(Display display, const native_handle_t* buffer,
            int releaseFence) const;
    Error setPowerMode(Display display, IComposer::PowerMode mode) const;
    Error setVsyncEnabled(Display display, IComposer::Vsync enabled) const;

    Error validateDisplay(Display display, uint32_t& numTypes,
            uint32_t& numRequests) const;

    Error setCursorPosition(Display display, Layer layer,
            int32_t x, int32_t y) const;
    Error setLayerBuffer(Display display, Layer layer,
            const native_handle_t* buffer, int acquireFence) const;
    Error setLayerSurfaceDamage(Display display, Layer layer,
            const std::vector<IComposer::Rect>& damage) const;
    Error setLayerBlendMode(Display display, Layer layer,
            IComposer::BlendMode mode) const;
    Error setLayerColor(Display display, Layer layer,
            const IComposer::Color& color) const;
    Error setLayerCompositionType(Display display, Layer layer,
            IComposer::Composition type) const;
    Error setLayerDataspace(Display display, Layer layer,
            Dataspace dataspace) const;
    Error setLayerDisplayFrame(Display display, Layer layer,
            const IComposer::Rect& frame) const;
    Error setLayerPlaneAlpha(Display display, Layer layer,
            float alpha) const;
    Error setLayerSidebandStream(Display display, Layer layer,
            const native_handle_t* stream) const;
    Error setLayerSourceCrop(Display display, Layer layer,
            const IComposer::FRect& crop) const;
    Error setLayerTransform(Display display, Layer layer,
            Transform transform) const;
    Error setLayerVisibleRegion(Display display, Layer layer,
            const std::vector<IComposer::Rect>& visible) const;
    Error setLayerZOrder(Display display, Layer layer, uint32_t z) const;

private:
    sp<IComposer> mService;
};

} // namespace Hwc2

} // namespace android

#endif // ANDROID_SF_COMPOSER_HAL_H
