
#ifndef SURFACEFLINGERPROPERTIES_H_
#define SURFACEFLINGERPROPERTIES_H_

#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.2/ISurfaceFlingerConfigs.h>
#include <sysprop/SurfaceFlingerProperties.sysprop.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace android {
namespace sysprop {

int64_t vsync_event_phase_offset_ns(int64_t defaultValue);

int64_t vsync_sf_event_phase_offset_ns(int64_t defaultValue);

bool use_context_priority(bool defaultValue);

int64_t max_frame_buffer_acquired_buffers(int64_t defaultValue);

bool has_wide_color_display(bool defaultValue);

bool running_without_sync_framework(bool defaultValue);

bool has_HDR_display(bool defaultValue);

int64_t present_time_offset_from_vsync_ns(int64_t defaultValue);

bool force_hwc_copy_for_virtual_displays(bool defaultValue);

int64_t max_virtual_display_dimension(int64_t defaultValue);

bool use_vr_flinger(bool defaultValue);

bool start_graphics_allocator_service(bool defaultValue);

SurfaceFlingerProperties::primary_display_orientation_values primary_display_orientation(
        SurfaceFlingerProperties::primary_display_orientation_values defaultValue);

bool use_color_management(bool defaultValue);

int64_t default_composition_dataspace(
        android::hardware::graphics::common::V1_2::Dataspace defaultValue);

int32_t default_composition_pixel_format(
        android::hardware::graphics::common::V1_2::PixelFormat defaultValue);

int64_t wcg_composition_dataspace(
        android::hardware::graphics::common::V1_2::Dataspace defaultValue);

int32_t wcg_composition_pixel_format(
        android::hardware::graphics::common::V1_2::PixelFormat defaultValue);

android::hardware::configstore::V1_2::DisplayPrimaries getDisplayNativePrimaries();
} // namespace sysprop
} // namespace android
#endif // SURFACEFLINGERPROPERTIES_H_
