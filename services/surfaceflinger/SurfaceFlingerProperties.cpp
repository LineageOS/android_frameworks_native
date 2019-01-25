
#include <sysprop/SurfaceFlingerProperties.sysprop.h>

#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/types.h>
#include <android/hardware/configstore/1.2/ISurfaceFlingerConfigs.h>
#include <configstore/Utils.h>

#include <tuple>

#include "SurfaceFlingerProperties.h"

namespace android {
namespace sysprop {
using namespace android::hardware::configstore;
using namespace android::hardware::configstore::V1_0;
using ::android::hardware::graphics::common::V1_2::Dataspace;
using ::android::hardware::graphics::common::V1_2::PixelFormat;

int64_t vsync_event_phase_offset_ns(int64_t defaultValue) {
    auto temp = SurfaceFlingerProperties::vsync_event_phase_offset_ns();
    if (temp.has_value()) {
        return *temp;
    }
    return getInt64<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::vsyncEventPhaseOffsetNs>(
            defaultValue);
}

int64_t vsync_sf_event_phase_offset_ns(int64_t defaultValue) {
    auto temp = SurfaceFlingerProperties::vsync_sf_event_phase_offset_ns();
    if (temp.has_value()) {
        return *temp;
    }
    return getInt64<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::vsyncSfEventPhaseOffsetNs>(
            defaultValue);
}

bool use_context_priority(bool defaultValue) {
    auto temp = SurfaceFlingerProperties::use_context_priority();
    if (temp.has_value()) {
        return *temp;
    }
    return getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::useContextPriority>(
            defaultValue);
}

int64_t max_frame_buffer_acquired_buffers(int64_t defaultValue) {
    auto temp = SurfaceFlingerProperties::max_frame_buffer_acquired_buffers();
    if (temp.has_value()) {
        return *temp;
    }
    return getInt64<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::maxFrameBufferAcquiredBuffers>(
            defaultValue);
}

bool has_wide_color_display(bool defaultValue) {
    auto temp = SurfaceFlingerProperties::has_wide_color_display();
    if (temp.has_value()) {
        return *temp;
    }
    return getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::hasWideColorDisplay>(
            defaultValue);
}

bool running_without_sync_framework(bool defaultValue) {
    auto temp = SurfaceFlingerProperties::running_without_sync_framework();
    if (temp.has_value()) {
        return !(*temp);
    }
    return getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::hasSyncFramework>(defaultValue);
}

bool has_HDR_display(bool defaultValue) {
    auto temp = SurfaceFlingerProperties::has_HDR_display();
    if (temp.has_value()) {
        return *temp;
    }
    return getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::hasHDRDisplay>(defaultValue);
}

int64_t present_time_offset_from_vsync_ns(int64_t defaultValue) {
    auto temp = SurfaceFlingerProperties::present_time_offset_from_vsync_ns();
    if (temp.has_value()) {
        return *temp;
    }
    return getInt64<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::presentTimeOffsetFromVSyncNs>(
            defaultValue);
}

bool force_hwc_copy_for_virtual_displays(bool defaultValue) {
    auto temp = SurfaceFlingerProperties::force_hwc_copy_for_virtual_displays();
    if (temp.has_value()) {
        return *temp;
    }
    return getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::useHwcForRGBtoYUV>(
            defaultValue);
}

int64_t max_virtual_display_dimension(int64_t defaultValue) {
    auto temp = SurfaceFlingerProperties::max_virtual_display_dimension();
    if (temp.has_value()) {
        return *temp;
    }
    return getUInt64<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::maxVirtualDisplaySize>(
            defaultValue);
}

bool use_vr_flinger(bool defaultValue) {
    auto temp = SurfaceFlingerProperties::use_vr_flinger();
    if (temp.has_value()) {
        return *temp;
    }
    return getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::useVrFlinger>(defaultValue);
}

bool start_graphics_allocator_service(bool defaultValue) {
    auto temp = SurfaceFlingerProperties::start_graphics_allocator_service();
    if (temp.has_value()) {
        return *temp;
    }
    return getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::startGraphicsAllocatorService>(
            defaultValue);
}

SurfaceFlingerProperties::primary_display_orientation_values primary_display_orientation(
        SurfaceFlingerProperties::primary_display_orientation_values defaultValue) {
    auto temp = SurfaceFlingerProperties::primary_display_orientation();
    if (temp.has_value()) {
        return *temp;
    }
    auto configDefault = DisplayOrientation::ORIENTATION_0;
    switch (defaultValue) {
        case SurfaceFlingerProperties::primary_display_orientation_values::ORIENTATION_90:
            configDefault = DisplayOrientation::ORIENTATION_90;
            break;
        case SurfaceFlingerProperties::primary_display_orientation_values::ORIENTATION_180:
            configDefault = DisplayOrientation::ORIENTATION_180;
            break;
        case SurfaceFlingerProperties::primary_display_orientation_values::ORIENTATION_270:
            configDefault = DisplayOrientation::ORIENTATION_270;
            break;
        default:
            configDefault = DisplayOrientation::ORIENTATION_0;
            break;
    }
    DisplayOrientation result =
            getDisplayOrientation<V1_1::ISurfaceFlingerConfigs,
                                  &V1_1::ISurfaceFlingerConfigs::primaryDisplayOrientation>(
                    configDefault);
    switch (result) {
        case DisplayOrientation::ORIENTATION_90:
            return SurfaceFlingerProperties::primary_display_orientation_values::ORIENTATION_90;
        case DisplayOrientation::ORIENTATION_180:
            return SurfaceFlingerProperties::primary_display_orientation_values::ORIENTATION_180;
        case DisplayOrientation::ORIENTATION_270:
            return SurfaceFlingerProperties::primary_display_orientation_values::ORIENTATION_270;
        default:
            break;
    }
    return SurfaceFlingerProperties::primary_display_orientation_values::ORIENTATION_0;
}

bool use_color_management(bool defaultValue) {
    auto tmpuseColorManagement = SurfaceFlingerProperties::use_color_management();
    auto tmpHasHDRDisplay = SurfaceFlingerProperties::has_HDR_display();
    auto tmpHasWideColorDisplay = SurfaceFlingerProperties::has_wide_color_display();
    if (tmpuseColorManagement.has_value() && tmpHasHDRDisplay.has_value() &&
        tmpHasWideColorDisplay.has_value()) {
        return *tmpuseColorManagement || *tmpHasHDRDisplay || *tmpHasWideColorDisplay;
    }
    auto surfaceFlingerConfigsServiceV1_2 = ISurfaceFlingerConfigs::getService();
    if (surfaceFlingerConfigsServiceV1_2) {
        return getBool<V1_2::ISurfaceFlingerConfigs,
                       &V1_2::ISurfaceFlingerConfigs::useColorManagement>(defaultValue);
    }
    return defaultValue;
}

auto getCompositionPreference(sp<V1_2::ISurfaceFlingerConfigs> configsServiceV1_2) {
    Dataspace defaultCompositionDataspace = Dataspace::V0_SRGB;
    PixelFormat defaultCompositionPixelFormat = PixelFormat::RGBA_8888;
    Dataspace wideColorGamutCompositionDataspace = Dataspace::V0_SRGB;
    PixelFormat wideColorGamutCompositionPixelFormat = PixelFormat::RGBA_8888;
    configsServiceV1_2->getCompositionPreference(
            [&](auto tmpDefaultDataspace, auto tmpDefaultPixelFormat,
                auto tmpWideColorGamutDataspace, auto tmpWideColorGamutPixelFormat) {
                defaultCompositionDataspace = tmpDefaultDataspace;
                defaultCompositionPixelFormat = tmpDefaultPixelFormat;
                wideColorGamutCompositionDataspace = tmpWideColorGamutDataspace;
                wideColorGamutCompositionPixelFormat = tmpWideColorGamutPixelFormat;
            });
    return std::tuple(defaultCompositionDataspace, defaultCompositionPixelFormat,
                      wideColorGamutCompositionDataspace, wideColorGamutCompositionPixelFormat);
}

int64_t default_composition_dataspace(Dataspace defaultValue) {
    auto temp = SurfaceFlingerProperties::default_composition_dataspace();
    if (temp.has_value()) {
        return *temp;
    }
    auto configsServiceV1_2 = V1_2::ISurfaceFlingerConfigs::getService();
    if (configsServiceV1_2) {
        return static_cast<int64_t>(get<0>(getCompositionPreference(configsServiceV1_2)));
    }
    return static_cast<int64_t>(defaultValue);
}

int32_t default_composition_pixel_format(PixelFormat defaultValue) {
    auto temp = SurfaceFlingerProperties::default_composition_pixel_format();
    if (temp.has_value()) {
        return *temp;
    }
    auto configsServiceV1_2 = V1_2::ISurfaceFlingerConfigs::getService();
    if (configsServiceV1_2) {
        return static_cast<int32_t>(get<1>(getCompositionPreference(configsServiceV1_2)));
    }
    return static_cast<int32_t>(defaultValue);
}

int64_t wcg_composition_dataspace(Dataspace defaultValue) {
    auto temp = SurfaceFlingerProperties::wcg_composition_dataspace();
    if (temp.has_value()) {
        return *temp;
    }
    auto configsServiceV1_2 = V1_2::ISurfaceFlingerConfigs::getService();
    if (configsServiceV1_2) {
        return static_cast<int64_t>(get<2>(getCompositionPreference(configsServiceV1_2)));
    }
    return static_cast<int64_t>(defaultValue);
}

int32_t wcg_composition_pixel_format(PixelFormat defaultValue) {
    auto temp = SurfaceFlingerProperties::wcg_composition_pixel_format();
    if (temp.has_value()) {
        return *temp;
    }
    auto configsServiceV1_2 = V1_2::ISurfaceFlingerConfigs::getService();
    if (configsServiceV1_2) {
        return static_cast<int32_t>(get<3>(getCompositionPreference(configsServiceV1_2)));
    }
    return static_cast<int32_t>(defaultValue);
}

} // namespace sysprop
} // namespace android
