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

#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

namespace android {
// Manages flags for SurfaceFlinger, including default values, system properties, and Mendel
// experiment configuration values. Can be called from any thread.
class FlagManager {
private:
    // Effectively making the constructor private, while allowing std::make_unique to work
    struct ConstructorTag {};

public:
    static const FlagManager& getInstance();
    static FlagManager& getMutableInstance();

    FlagManager(ConstructorTag);
    virtual ~FlagManager();

    void markBootCompleted();
    void dump(std::string& result) const;

    void setUnitTestMode();

    /// Legacy server flags ///
    bool test_flag() const;
    bool use_adpf_cpu_hint() const;
    bool use_skia_tracing() const;

    /// Trunk stable server flags ///
    bool refresh_rate_overlay_on_external_display() const;

    /// Trunk stable readonly flags ///
    bool connected_display() const;
    bool enable_small_area_detection() const;
    bool misc1() const;
    bool vrr_config() const;
    bool hotplug2() const;
    bool hdcp_level_hal() const;
    bool multithreaded_present() const;
    bool add_sf_skipped_frames_to_trace() const;
    bool use_known_refresh_rate_for_fps_consistency() const;
    bool cache_when_source_crop_layer_only_moved() const;
    bool enable_fro_dependent_features() const;
    bool display_protected() const;
    bool fp16_client_target() const;
    bool game_default_frame_rate() const;
    bool enable_layer_command_batching() const;
    bool screenshot_fence_preservation() const;
    bool vulkan_renderengine() const;
    bool renderable_buffer_usage() const;
    bool restore_blur_step() const;
    bool dont_skip_on_early_ro() const;
    bool protected_if_client() const;

protected:
    // overridden for unit tests
    virtual std::optional<bool> getBoolProperty(const char*) const;
    virtual bool getServerConfigurableFlag(const char*) const;

private:
    friend class TestableFlagManager;

    FlagManager(const FlagManager&) = delete;

    void dumpFlag(std::string& result, bool readonly, const char* name,
                  std::function<bool()> getter) const;

    std::atomic_bool mBootCompleted = false;
    std::atomic_bool mUnitTestMode = false;

    static std::unique_ptr<FlagManager> mInstance;
    static std::once_flag mOnce;
};
} // namespace android
