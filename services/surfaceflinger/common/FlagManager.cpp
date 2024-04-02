/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <common/FlagManager.h>

#include <SurfaceFlingerProperties.sysprop.h>
#include <android-base/parsebool.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <renderengine/RenderEngine.h>
#include <server_configurable_flags/get_flags.h>
#include <cinttypes>

#include <android_os.h>
#include <com_android_graphics_surfaceflinger_flags.h>
#include <com_android_server_display_feature_flags.h>

namespace android {
using namespace com::android::graphics::surfaceflinger;

static constexpr const char* kExperimentNamespace = "surface_flinger_native_boot";

std::unique_ptr<FlagManager> FlagManager::mInstance;
std::once_flag FlagManager::mOnce;

FlagManager::FlagManager(ConstructorTag) {}
FlagManager::~FlagManager() = default;

namespace {
std::optional<bool> parseBool(const char* str) {
    base::ParseBoolResult parseResult = base::ParseBool(str);
    switch (parseResult) {
        case base::ParseBoolResult::kTrue:
            return std::make_optional(true);
        case base::ParseBoolResult::kFalse:
            return std::make_optional(false);
        case base::ParseBoolResult::kError:
            return std::nullopt;
    }
}

bool getFlagValue(std::function<bool()> getter, std::optional<bool> overrideValue) {
    if (overrideValue.has_value()) {
        return *overrideValue;
    }

    return getter();
}

} // namespace

const FlagManager& FlagManager::getInstance() {
    return getMutableInstance();
}

FlagManager& FlagManager::getMutableInstance() {
    std::call_once(mOnce, [&] {
        LOG_ALWAYS_FATAL_IF(mInstance, "Instance already created");
        mInstance = std::make_unique<FlagManager>(ConstructorTag{});
    });

    return *mInstance;
}

void FlagManager::markBootCompleted() {
    mBootCompleted = true;
}

void FlagManager::setUnitTestMode() {
    mUnitTestMode = true;

    // Also set boot completed as we don't really care about it in unit testing
    mBootCompleted = true;
}

void FlagManager::dumpFlag(std::string& result, bool readonly, const char* name,
                           std::function<bool()> getter) const {
    if (readonly || mBootCompleted) {
        base::StringAppendF(&result, "%s: %s\n", name, getter() ? "true" : "false");
    } else {
        base::StringAppendF(&result, "%s: in progress (still booting)\n", name);
    }
}

void FlagManager::dump(std::string& result) const {
#define DUMP_FLAG_INTERVAL(name, readonly) \
    dumpFlag(result, (readonly), #name, std::bind(&FlagManager::name, this))
#define DUMP_SERVER_FLAG(name) DUMP_FLAG_INTERVAL(name, false)
#define DUMP_READ_ONLY_FLAG(name) DUMP_FLAG_INTERVAL(name, true)

    base::StringAppendF(&result, "FlagManager values: \n");

    /// Legacy server flags ///
    DUMP_SERVER_FLAG(use_adpf_cpu_hint);
    DUMP_SERVER_FLAG(use_skia_tracing);

    /// Trunk stable server flags ///
    DUMP_SERVER_FLAG(refresh_rate_overlay_on_external_display);
    DUMP_SERVER_FLAG(adpf_gpu_sf);
    DUMP_SERVER_FLAG(adpf_use_fmq_channel);

    /// Trunk stable readonly flags ///
    DUMP_READ_ONLY_FLAG(connected_display);
    DUMP_READ_ONLY_FLAG(enable_small_area_detection);
    DUMP_READ_ONLY_FLAG(frame_rate_category_mrr);
    DUMP_READ_ONLY_FLAG(misc1);
    DUMP_READ_ONLY_FLAG(vrr_config);
    DUMP_READ_ONLY_FLAG(hotplug2);
    DUMP_READ_ONLY_FLAG(hdcp_level_hal);
    DUMP_READ_ONLY_FLAG(multithreaded_present);
    DUMP_READ_ONLY_FLAG(add_sf_skipped_frames_to_trace);
    DUMP_READ_ONLY_FLAG(use_known_refresh_rate_for_fps_consistency);
    DUMP_READ_ONLY_FLAG(cache_when_source_crop_layer_only_moved);
    DUMP_READ_ONLY_FLAG(enable_fro_dependent_features);
    DUMP_READ_ONLY_FLAG(display_protected);
    DUMP_READ_ONLY_FLAG(fp16_client_target);
    DUMP_READ_ONLY_FLAG(game_default_frame_rate);
    DUMP_READ_ONLY_FLAG(enable_layer_command_batching);
    DUMP_READ_ONLY_FLAG(screenshot_fence_preservation);
    DUMP_READ_ONLY_FLAG(vulkan_renderengine);
    DUMP_READ_ONLY_FLAG(renderable_buffer_usage);
    DUMP_READ_ONLY_FLAG(restore_blur_step);
    DUMP_READ_ONLY_FLAG(dont_skip_on_early_ro);
    DUMP_READ_ONLY_FLAG(protected_if_client);
    DUMP_READ_ONLY_FLAG(ce_fence_promise);
    DUMP_READ_ONLY_FLAG(idle_screen_refresh_rate_timeout);
    DUMP_READ_ONLY_FLAG(graphite_renderengine);
    DUMP_READ_ONLY_FLAG(latch_unsignaled_with_auto_refresh_changed);
    DUMP_READ_ONLY_FLAG(deprecate_vsync_sf);
    DUMP_READ_ONLY_FLAG(allow_n_vsyncs_in_targeter);
    DUMP_READ_ONLY_FLAG(detached_mirror);

#undef DUMP_READ_ONLY_FLAG
#undef DUMP_SERVER_FLAG
#undef DUMP_FLAG_INTERVAL
}

std::optional<bool> FlagManager::getBoolProperty(const char* property) const {
    return parseBool(base::GetProperty(property, "").c_str());
}

bool FlagManager::getServerConfigurableFlag(const char* experimentFlagName) const {
    const auto value = server_configurable_flags::GetServerConfigurableFlag(kExperimentNamespace,
                                                                            experimentFlagName, "");
    const auto res = parseBool(value.c_str());
    return res.has_value() && res.value();
}

#define FLAG_MANAGER_LEGACY_SERVER_FLAG(name, syspropOverride, serverFlagName)              \
    bool FlagManager::name() const {                                                        \
        LOG_ALWAYS_FATAL_IF(!mBootCompleted,                                                \
                            "Can't read %s before boot completed as it is server writable", \
                            __func__);                                                      \
        const auto debugOverride = getBoolProperty(syspropOverride);                        \
        if (debugOverride.has_value()) return debugOverride.value();                        \
        return getServerConfigurableFlag(serverFlagName);                                   \
    }

#define FLAG_MANAGER_FLAG_INTERNAL(name, syspropOverride, checkForBootCompleted, owner)         \
    bool FlagManager::name() const {                                                            \
        if (checkForBootCompleted) {                                                            \
            LOG_ALWAYS_FATAL_IF(!mBootCompleted,                                                \
                                "Can't read %s before boot completed as it is server writable", \
                                __func__);                                                      \
        }                                                                                       \
        static const std::optional<bool> debugOverride = getBoolProperty(syspropOverride);      \
        static const bool value = getFlagValue([] { return owner ::name(); }, debugOverride);   \
        if (mUnitTestMode) {                                                                    \
            /*                                                                                  \
             * When testing, we don't want to rely on the cached `value` or the debugOverride.  \
             */                                                                                 \
            return owner ::name();                                                              \
        }                                                                                       \
        return value;                                                                           \
    }

#define FLAG_MANAGER_SERVER_FLAG(name, syspropOverride) \
    FLAG_MANAGER_FLAG_INTERNAL(name, syspropOverride, true, flags)

#define FLAG_MANAGER_READ_ONLY_FLAG(name, syspropOverride) \
    FLAG_MANAGER_FLAG_INTERNAL(name, syspropOverride, false, flags)

#define FLAG_MANAGER_SERVER_FLAG_IMPORTED(name, syspropOverride, owner) \
    FLAG_MANAGER_FLAG_INTERNAL(name, syspropOverride, true, owner)

#define FLAG_MANAGER_READ_ONLY_FLAG_IMPORTED(name, syspropOverride, owner) \
    FLAG_MANAGER_FLAG_INTERNAL(name, syspropOverride, false, owner)

/// Legacy server flags ///
FLAG_MANAGER_LEGACY_SERVER_FLAG(test_flag, "", "")
FLAG_MANAGER_LEGACY_SERVER_FLAG(use_adpf_cpu_hint, "debug.sf.enable_adpf_cpu_hint",
                                "AdpfFeature__adpf_cpu_hint")
FLAG_MANAGER_LEGACY_SERVER_FLAG(use_skia_tracing, PROPERTY_SKIA_ATRACE_ENABLED,
                                "SkiaTracingFeature__use_skia_tracing")

/// Trunk stable readonly flags ///
FLAG_MANAGER_READ_ONLY_FLAG(connected_display, "")
FLAG_MANAGER_READ_ONLY_FLAG(enable_small_area_detection, "")
FLAG_MANAGER_READ_ONLY_FLAG(frame_rate_category_mrr, "debug.sf.frame_rate_category_mrr")
FLAG_MANAGER_READ_ONLY_FLAG(misc1, "")
FLAG_MANAGER_READ_ONLY_FLAG(vrr_config, "debug.sf.enable_vrr_config")
FLAG_MANAGER_READ_ONLY_FLAG(hotplug2, "")
FLAG_MANAGER_READ_ONLY_FLAG(hdcp_level_hal, "")
FLAG_MANAGER_READ_ONLY_FLAG(multithreaded_present, "debug.sf.multithreaded_present")
FLAG_MANAGER_READ_ONLY_FLAG(add_sf_skipped_frames_to_trace, "")
FLAG_MANAGER_READ_ONLY_FLAG(use_known_refresh_rate_for_fps_consistency, "")
FLAG_MANAGER_READ_ONLY_FLAG(cache_when_source_crop_layer_only_moved,
                            "debug.sf.cache_source_crop_only_moved")
FLAG_MANAGER_READ_ONLY_FLAG(enable_fro_dependent_features, "")
FLAG_MANAGER_READ_ONLY_FLAG(display_protected, "")
FLAG_MANAGER_READ_ONLY_FLAG(fp16_client_target, "debug.sf.fp16_client_target")
FLAG_MANAGER_READ_ONLY_FLAG(game_default_frame_rate, "")
FLAG_MANAGER_READ_ONLY_FLAG(enable_layer_command_batching, "debug.sf.enable_layer_command_batching")
FLAG_MANAGER_READ_ONLY_FLAG(screenshot_fence_preservation, "debug.sf.screenshot_fence_preservation")
FLAG_MANAGER_READ_ONLY_FLAG(vulkan_renderengine, "debug.renderengine.vulkan")
FLAG_MANAGER_READ_ONLY_FLAG(renderable_buffer_usage, "")
FLAG_MANAGER_READ_ONLY_FLAG(restore_blur_step, "debug.renderengine.restore_blur_step")
FLAG_MANAGER_READ_ONLY_FLAG(dont_skip_on_early_ro, "")
FLAG_MANAGER_READ_ONLY_FLAG(protected_if_client, "")
FLAG_MANAGER_READ_ONLY_FLAG(ce_fence_promise, "");
FLAG_MANAGER_READ_ONLY_FLAG(graphite_renderengine, "debug.renderengine.graphite")
FLAG_MANAGER_READ_ONLY_FLAG(latch_unsignaled_with_auto_refresh_changed, "");
FLAG_MANAGER_READ_ONLY_FLAG(deprecate_vsync_sf, "");
FLAG_MANAGER_READ_ONLY_FLAG(allow_n_vsyncs_in_targeter, "");
FLAG_MANAGER_READ_ONLY_FLAG(detached_mirror, "");

/// Trunk stable server flags ///
FLAG_MANAGER_SERVER_FLAG(refresh_rate_overlay_on_external_display, "")
FLAG_MANAGER_SERVER_FLAG(adpf_gpu_sf, "")

/// Trunk stable server flags from outside SurfaceFlinger ///
FLAG_MANAGER_SERVER_FLAG_IMPORTED(adpf_use_fmq_channel, "", android::os)

/// Trunk stable readonly flags from outside SurfaceFlinger ///
FLAG_MANAGER_READ_ONLY_FLAG_IMPORTED(idle_screen_refresh_rate_timeout, "",
                                     com::android::server::display::feature::flags)
FLAG_MANAGER_READ_ONLY_FLAG_IMPORTED(adpf_use_fmq_channel_fixed, "", android::os)

} // namespace android
