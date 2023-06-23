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

#include <cstdlib>

#include <ui/ConfigStoreTypes.h>
#include <ui/GraphicTypes.h>

namespace android::surfaceflinger {

class Factory;

struct Config final {
    Factory* factory = nullptr;

    std::string hwcServiceName;
    pid_t pid;

    float emulatedDisplayDensity = 0;
    float internalDisplayDensity = 0;

    // If fences from sync Framework are supported.
    bool hasSyncFramework = true;

    // The offset in nanoseconds to use when VsyncController timestamps present
    // fence signaling time.
    int64_t dispSyncPresentTimeOffset = 0;

    // Some hardware can do RGB->YUV conversion more efficiently in hardware
    // controlled by HWC than in hardware controlled by the video encoder. This
    // instruct VirtualDisplaySurface to use HWC for such conversion on GL
    // composition.
    bool useHwcForRgbToYuv = false;

    // Controls the number of buffers SurfaceFlinger will allocate for use in
    // FramebufferSurface
    int64_t maxFrameBufferAcquiredBuffers = 2;

    // Controls the minimum acquired buffers SurfaceFlinger will suggest via
    // ISurfaceComposer.getMaxAcquiredBufferCount().
    int64_t minAcquiredBuffers = 1;

    // Controls the maximum width and height in pixels that the graphics
    // pipeline can support for GPU fallback composition. For example, 8k
    // devices with 4k GPUs, or 4k devices with 2k GPUs.
    uint32_t maxGraphicsWidth = 0;
    uint32_t maxGraphicsHeight = 0;

    // Whether to enable wide color gamut (e.g. Display P3) for internal
    // displays that support it. If false, wide color modes are filtered out
    // for all internal displays.
    bool mSupportsWideColor = false;
    bool supportsWideColor = false;

    // The data space and pixel format that SurfaceFlinger expects hardware
    // composer to composite efficiently. Meaning under most scenarios,
    // hardware composer will accept layers with the data space and pixel
    // format.
    ui::Dataspace defaultCompositionDataspace = ui::Dataspace::V0_SRGB;
    ui::PixelFormat defaultCompositionPixelFormat = ui::PixelFormat::RGBA_8888;

    // The data space and pixel format that SurfaceFlinger expects hardware
    // composer to composite efficiently for wide color gamut surfaces. Meaning
    // under most scenarios, hardware composer will accept layers with the data
    // space and pixel format.
    ui::Dataspace wideColorGamutCompositionDataspace = ui::Dataspace::V0_SRGB;
    ui::PixelFormat wideColorGamutCompositionPixelFormat = ui::PixelFormat::RGBA_8888;

    ui::Dataspace colorSpaceAgnosticDataspace = ui::Dataspace::UNKNOWN;

    ui::DisplayPrimaries internalDisplayPrimaries{};

    bool layerCachingEnabled = false;
    bool useContextPriority = true;
    bool isUserBuild = true;
    bool backpressureGpuComposition = true;

    // If blurs should be enabled on this device.
    bool supportsBlur = false;
    bool lumaSampling = true;

    // If set, disables reusing client composition buffers. This can be set by
    // debug.sf.disable_client_composition_cache
    bool disableClientCompositionCache = false;

    // If set, composition engine tries to predict the composition strategy
    // provided by HWC based on the previous frame. If the strategy can be
    // predicted, gpu composition will run parallel to the hwc validateDisplay
    // call and re-run if the predition is incorrect.
    bool predictCompositionStrategy = true;

    // If true, then any layer with a SMPTE 170M transfer function is decoded
    // using the sRGB transfer instead. This is mainly to preserve legacy
    // behavior, where implementations treated SMPTE 170M as sRGB prior to
    // color management being implemented, and now implementations rely on this
    // behavior to increase contrast for some media sources.
    bool treat170mAsSrgb = false;

    // Allows to ignore physical orientation provided through hwc API in favour
    // of 'ro.surface_flinger.primary_display_orientation'.
    // TODO(b/246793311): Clean up a temporary property
    bool ignoreHwcPhysicalDisplayOrientation = false;

    bool trebleTestingOverride = false;

    struct {
        // Show spinner with refresh rate overlay
        bool showSpinner = false;

        // Show render rate with refresh rate overlay
        bool showRenderRate = false;

        // Show render rate overlay offseted to the middle of the screen (e.g.
        // for circular displays)
        bool showInMiddle = false;
    } refreshRateOverlay;

    bool ignoreHdrCameraLayers = false;
    bool enableTransactionTracing = true;
    bool layerLifecycleManagerEnabled = false;
    bool legacyFrontEndEnabled = true;

    static Config makeDefault(Factory* factory);
    static Config makeProduction(Factory* factory);

private:
    Config();
};

} // namespace android::surfaceflinger
