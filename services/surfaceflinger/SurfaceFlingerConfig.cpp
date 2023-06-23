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

#include <cstdlib>

#include <SurfaceFlingerProperties.h>
#include <SurfaceFlingerProperties.sysprop.h>
#include <android-base/properties.h>
#include <android/configuration.h>

#include "SurfaceFlingerConfig.h"

namespace android::surfaceflinger {

using namespace std::string_literals;

namespace {

// TODO(b/141333600): Consolidate with DisplayMode::Builder::getDefaultDensity.
constexpr float FALLBACK_DENSITY = ACONFIGURATION_DENSITY_TV;

float getDensityFromProperty(const std::string& key, bool required) {
    std::string value = base::GetProperty(key, ""s);
    const float density = static_cast<float>(std::atof(value.c_str()));
    if (density == 0.f && required) {
        ALOGE("%s must be defined as a build property", key.c_str());
        return FALLBACK_DENSITY;
    }
    return density;
}

} // namespace

Config::Config() = default;

Config Config::makeDefault(Factory* factory) {
    Config cfg{};

    // Note: The values set here will affect tests.
    // To keep tests hermetic, do not set values here based on runtime values.

    cfg.factory = factory;
    cfg.hwcServiceName = "default"s;
    cfg.pid = getpid(); // Exception to the hermetic rules. Allow the pid to be cached.

    return cfg;
}

Config Config::makeProduction(Factory* factory) {
    Config cfg = makeDefault(factory);

    cfg.hwcServiceName = base::GetProperty("debug.sf.hwc_service_name"s, "default"s);

    cfg.emulatedDisplayDensity = getDensityFromProperty("qemu.sf.lcd_density"s, false),
    cfg.internalDisplayDensity =
            getDensityFromProperty("ro.sf.lcd_density"s, cfg.emulatedDisplayDensity == 0.f),

    cfg.hasSyncFramework = sysprop::running_without_sync_framework(cfg.hasSyncFramework);
    cfg.dispSyncPresentTimeOffset =
            sysprop::present_time_offset_from_vsync_ns(cfg.dispSyncPresentTimeOffset);
    cfg.useHwcForRgbToYuv = sysprop::force_hwc_copy_for_virtual_displays(cfg.useHwcForRgbToYuv);
    cfg.maxFrameBufferAcquiredBuffers =
            sysprop::max_frame_buffer_acquired_buffers(cfg.maxFrameBufferAcquiredBuffers);
    cfg.minAcquiredBuffers = sysprop::SurfaceFlingerProperties::min_acquired_buffers().value_or(
            cfg.minAcquiredBuffers);

    cfg.maxGraphicsWidth = std::max(static_cast<uint32_t>(sysprop::max_graphics_width(
                                            static_cast<int32_t>(cfg.maxGraphicsWidth))),
                                    0u);
    cfg.maxGraphicsHeight = std::max(static_cast<uint32_t>(sysprop::max_graphics_height(
                                             static_cast<int32_t>(cfg.maxGraphicsHeight))),
                                     0u);

    cfg.supportsWideColor = sysprop::has_wide_color_display(cfg.supportsWideColor);

    cfg.defaultCompositionDataspace = static_cast<ui::Dataspace>(
            sysprop::default_composition_dataspace(cfg.defaultCompositionDataspace));
    cfg.defaultCompositionPixelFormat = static_cast<ui::PixelFormat>(
            sysprop::default_composition_pixel_format(cfg.defaultCompositionPixelFormat));

    cfg.wideColorGamutCompositionDataspace =
            static_cast<ui::Dataspace>(sysprop::wcg_composition_dataspace(
                    cfg.supportsWideColor ? ui::Dataspace::DISPLAY_P3 : ui::Dataspace::V0_SRGB));
    cfg.wideColorGamutCompositionPixelFormat = static_cast<ui::PixelFormat>(
            sysprop::wcg_composition_pixel_format(cfg.wideColorGamutCompositionPixelFormat));

    cfg.colorSpaceAgnosticDataspace = static_cast<ui::Dataspace>(
            sysprop::color_space_agnostic_dataspace(cfg.colorSpaceAgnosticDataspace));

    cfg.internalDisplayPrimaries = sysprop::getDisplayNativePrimaries();

    cfg.layerCachingEnabled =
            base::GetBoolProperty("debug.sf.enable_layer_caching"s,
                                  android::sysprop::SurfaceFlingerProperties::enable_layer_caching()
                                          .value_or(cfg.layerCachingEnabled));
    cfg.useContextPriority = sysprop::use_context_priority(cfg.useContextPriority);

    cfg.isUserBuild = "user"s == base::GetProperty("ro.build.type"s, "user"s);

    cfg.backpressureGpuComposition = base::GetBoolProperty("debug.sf.enable_gl_backpressure"s,
                                                           cfg.backpressureGpuComposition);
    cfg.supportsBlur =
            base::GetBoolProperty("ro.surface_flinger.supports_background_blur"s, cfg.supportsBlur);

    cfg.lumaSampling = base::GetBoolProperty("debug.sf.luma_sampling"s, cfg.lumaSampling);

    cfg.disableClientCompositionCache =
            base::GetBoolProperty("debug.sf.disable_client_composition_cache"s,
                                  cfg.disableClientCompositionCache);

    cfg.predictCompositionStrategy =
            base::GetBoolProperty("debug.sf.predict_hwc_composition_strategy"s,
                                  cfg.predictCompositionStrategy);

    cfg.treat170mAsSrgb =
            base::GetBoolProperty("debug.sf.treat_170m_as_sRGB"s, cfg.treat170mAsSrgb);

    cfg.ignoreHwcPhysicalDisplayOrientation =
            base::GetBoolProperty("debug.sf.ignore_hwc_physical_display_orientation"s,
                                  cfg.ignoreHwcPhysicalDisplayOrientation);

    cfg.trebleTestingOverride =
            base::GetBoolProperty("debug.sf.treble_testing_override"s, cfg.trebleTestingOverride);

    // TODO (b/270966065) Update the HWC based refresh rate overlay to support spinner
    cfg.refreshRateOverlay.showSpinner =
            base::GetBoolProperty("debug.sf.show_refresh_rate_overlay_spinner"s,
                                  cfg.refreshRateOverlay.showSpinner);
    cfg.refreshRateOverlay.showRenderRate =
            base::GetBoolProperty("debug.sf.show_refresh_rate_overlay_render_rate"s,
                                  cfg.refreshRateOverlay.showRenderRate);
    cfg.refreshRateOverlay.showInMiddle =
            base::GetBoolProperty("debug.sf.show_refresh_rate_overlay_in_middle"s,
                                  cfg.refreshRateOverlay.showInMiddle);

    cfg.ignoreHdrCameraLayers = sysprop::ignore_hdr_camera_layers(cfg.ignoreHdrCameraLayers);

    cfg.enableTransactionTracing = base::GetBoolProperty("debug.sf.enable_transaction_tracing"s,
                                                         cfg.enableTransactionTracing);
    cfg.layerLifecycleManagerEnabled =
            base::GetBoolProperty("persist.debug.sf.enable_layer_lifecycle_manager"s,
                                  cfg.layerLifecycleManagerEnabled);
    cfg.legacyFrontEndEnabled = !cfg.layerLifecycleManagerEnabled ||
            base::GetBoolProperty("persist.debug.sf.enable_legacy_frontend"s, false);

    return cfg;
}

} // namespace android::surfaceflinger