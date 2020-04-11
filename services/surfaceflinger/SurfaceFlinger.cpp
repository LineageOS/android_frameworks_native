/*
 * Copyright (C) 2007 The Android Open Source Project
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
#pragma clang diagnostic ignored "-Wextra"

//#define LOG_NDEBUG 0
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "SurfaceFlinger.h"

#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android/configuration.h>
#include <android/gui/IDisplayEventConnection.h>
#include <android/gui/StaticDisplayInfo.h>
#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/types.h>
#include <android/hardware/power/Boost.h>
#include <android/native_window.h>
#include <android/os/IInputFlinger.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/CompositionRefreshArgs.h>
#include <compositionengine/Display.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/DisplayColorProfileCreationArgs.h>
#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/impl/DisplayColorProfile.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <configstore/Utils.h>
#include <cutils/compiler.h>
#include <cutils/properties.h>
#include <ftl/algorithm.h>
#include <ftl/concat.h>
#include <ftl/fake_guard.h>
#include <ftl/future.h>
#include <ftl/unit.h>
#include <gui/AidlStatusUtil.h>
#include <gui/BufferQueue.h>
#include <gui/DebugEGLImageTracker.h>
#include <gui/IProducerListener.h>
#include <gui/LayerDebugInfo.h>
#include <gui/LayerMetadata.h>
#include <gui/LayerState.h>
#include <gui/Surface.h>
#include <gui/TraceUtils.h>
#include <hidl/ServiceManagement.h>
#include <layerproto/LayerProtoParser.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <private/gui/SyncFeatures.h>
#include <processgroup/processgroup.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/impl/ExternalTexture.h>
#include <scheduler/FrameTargeter.h>
#include <sys/types.h>
#include <ui/ColorSpace.h>
#include <ui/DebugUtils.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMode.h>
#include <ui/DisplayStatInfo.h>
#include <ui/DisplayState.h>
#include <ui/DynamicDisplayInfo.h>
#include <ui/GraphicBufferAllocator.h>
#include <ui/HdrRenderTypeUtils.h>
#include <ui/LayerStack.h>
#include <ui/PixelFormat.h>
#include <ui/StaticDisplayInfo.h>
#include <utils/StopWatch.h>
#include <utils/String16.h>
#include <utils/String8.h>
#include <utils/Timers.h>
#include <utils/misc.h>

#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <gui/LayerStatePermissions.h>
#include <ui/DisplayIdentification.h>
#include "BackgroundExecutor.h"
#include "Client.h"
#include "ClientCache.h"
#include "Colorizer.h"
#include "DisplayDevice.h"
#include "DisplayHardware/ComposerHal.h"
#include "DisplayHardware/FramebufferSurface.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/Hal.h"
#include "DisplayHardware/PowerAdvisor.h"
#include "DisplayHardware/VirtualDisplaySurface.h"
#include "DisplayRenderArea.h"
#include "Effects/Daltonizer.h"
#include "FlagManager.h"
#include "FpsReporter.h"
#include "FrameTimeline/FrameTimeline.h"
#include "FrameTracer/FrameTracer.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/LayerHandle.h"
#include "FrontEnd/LayerLifecycleManager.h"
#include "FrontEnd/LayerSnapshot.h"
#include "HdrLayerInfoReporter.h"
#include "Layer.h"
#include "LayerProtoHelper.h"
#include "LayerRenderArea.h"
#include "LayerVector.h"
#include "MutexUtils.h"
#include "NativeWindowSurface.h"
#include "RegionSamplingThread.h"
#include "Scheduler/EventThread.h"
#include "Scheduler/LayerHistory.h"
#include "Scheduler/Scheduler.h"
#include "Scheduler/VsyncConfiguration.h"
#include "Scheduler/VsyncModulator.h"
#include "ScreenCaptureOutput.h"
#include "StartPropertySetThread.h"
#include "SurfaceFlingerProperties.h"
#include "TimeStats/TimeStats.h"
#include "TunnelModeEnabledReporter.h"
#include "Utils/Dumper.h"
#include "WindowInfosListenerInvoker.h"

#if __has_include("QtiGralloc.h")
#include "QtiGralloc.h"
#else
#include "gralloc_priv.h"
#endif

#include <aidl/android/hardware/graphics/common/DisplayDecorationSupport.h>
#include <aidl/android/hardware/graphics/composer3/DisplayCapability.h>
#include <aidl/android/hardware/graphics/composer3/RenderIntent.h>

#undef NO_THREAD_SAFETY_ANALYSIS
#define NO_THREAD_SAFETY_ANALYSIS \
    _Pragma("GCC error \"Prefer <ftl/fake_guard.h> or MutexUtils.h helpers.\"")

// To enable layer borders in the system, change the below flag to true.
#undef DOES_CONTAIN_BORDER
#define DOES_CONTAIN_BORDER false

namespace android {

using namespace std::chrono_literals;
using namespace std::string_literals;
using namespace std::string_view_literals;

using namespace hardware::configstore;
using namespace hardware::configstore::V1_0;
using namespace sysprop;
using ftl::Flags;
using namespace ftl::flag_operators;

using aidl::android::hardware::graphics::common::DisplayDecorationSupport;
using aidl::android::hardware::graphics::composer3::Capability;
using aidl::android::hardware::graphics::composer3::DisplayCapability;
using CompositionStrategyPredictionState = android::compositionengine::impl::
        OutputCompositionState::CompositionStrategyPredictionState;

using base::StringAppendF;
using display::PhysicalDisplay;
using display::PhysicalDisplays;
using frontend::TransactionHandler;
using gui::DisplayInfo;
using gui::GameMode;
using gui::IDisplayEventConnection;
using gui::IWindowInfosListener;
using gui::LayerMetadata;
using gui::WindowInfo;
using gui::aidl_utils::binderStatusFromStatusT;
using scheduler::VsyncModulator;
using ui::Dataspace;
using ui::DisplayPrimaries;
using ui::RenderIntent;

using KernelIdleTimerController = scheduler::RefreshRateSelector::KernelIdleTimerController;

namespace hal = android::hardware::graphics::composer::hal;

namespace {

static constexpr int FOUR_K_WIDTH = 3840;
static constexpr int FOUR_K_HEIGHT = 2160;

// TODO(b/141333600): Consolidate with DisplayMode::Builder::getDefaultDensity.
constexpr float FALLBACK_DENSITY = ACONFIGURATION_DENSITY_TV;

float getDensityFromProperty(const char* property, bool required) {
    char value[PROPERTY_VALUE_MAX];
    const float density = property_get(property, value, nullptr) > 0 ? std::atof(value) : 0.f;
    if (!density && required) {
        ALOGE("%s must be defined as a build property", property);
        return FALLBACK_DENSITY;
    }
    return density;
}

// Currently we only support V0_SRGB and DISPLAY_P3 as composition preference.
bool validateCompositionDataspace(Dataspace dataspace) {
    return dataspace == Dataspace::V0_SRGB || dataspace == Dataspace::DISPLAY_P3;
}

std::chrono::milliseconds getIdleTimerTimeout(DisplayId displayId) {
    const auto displayIdleTimerMsKey = [displayId] {
        std::stringstream ss;
        ss << "debug.sf.set_idle_timer_ms_" << displayId.value;
        return ss.str();
    }();

    const int32_t displayIdleTimerMs = base::GetIntProperty(displayIdleTimerMsKey, 0);
    if (displayIdleTimerMs > 0) {
        return std::chrono::milliseconds(displayIdleTimerMs);
    }

    const int32_t setIdleTimerMs = base::GetIntProperty("debug.sf.set_idle_timer_ms", 0);
    const int32_t millis = setIdleTimerMs ? setIdleTimerMs : sysprop::set_idle_timer_ms(0);
    return std::chrono::milliseconds(millis);
}

bool getKernelIdleTimerSyspropConfig(DisplayId displayId) {
    const auto displaySupportKernelIdleTimerKey = [displayId] {
        std::stringstream ss;
        ss << "debug.sf.support_kernel_idle_timer_" << displayId.value;
        return ss.str();
    }();

    const auto displaySupportKernelIdleTimer =
            base::GetBoolProperty(displaySupportKernelIdleTimerKey, false);
    return displaySupportKernelIdleTimer || sysprop::support_kernel_idle_timer(false);
}

bool isAbove4k30(const ui::DisplayMode& outMode) {
    using fps_approx_ops::operator>;
    Fps refreshRate = Fps::fromValue(outMode.refreshRate);
    return outMode.resolution.getWidth() >= FOUR_K_WIDTH &&
            outMode.resolution.getHeight() >= FOUR_K_HEIGHT && refreshRate > 30_Hz;
}

void excludeDolbyVisionIf4k30Present(const std::vector<ui::Hdr>& displayHdrTypes,
                                     ui::DisplayMode& outMode) {
    if (isAbove4k30(outMode) &&
        std::any_of(displayHdrTypes.begin(), displayHdrTypes.end(),
                    [](ui::Hdr type) { return type == ui::Hdr::DOLBY_VISION_4K30; })) {
        for (ui::Hdr type : displayHdrTypes) {
            if (type != ui::Hdr::DOLBY_VISION_4K30 && type != ui::Hdr::DOLBY_VISION) {
                outMode.supportedHdrTypes.push_back(type);
            }
        }
    } else {
        for (ui::Hdr type : displayHdrTypes) {
            if (type != ui::Hdr::DOLBY_VISION_4K30) {
                outMode.supportedHdrTypes.push_back(type);
            }
        }
    }
}

HdrCapabilities filterOut4k30(const HdrCapabilities& displayHdrCapabilities) {
    std::vector<ui::Hdr> hdrTypes;
    for (ui::Hdr type : displayHdrCapabilities.getSupportedHdrTypes()) {
        if (type != ui::Hdr::DOLBY_VISION_4K30) {
            hdrTypes.push_back(type);
        }
    }
    return {hdrTypes, displayHdrCapabilities.getDesiredMaxLuminance(),
            displayHdrCapabilities.getDesiredMaxAverageLuminance(),
            displayHdrCapabilities.getDesiredMinLuminance()};
}

uint32_t getLayerIdFromSurfaceControl(sp<SurfaceControl> surfaceControl) {
    if (!surfaceControl) {
        return UNASSIGNED_LAYER_ID;
    }
    return LayerHandle::getLayerId(surfaceControl->getHandle());
}

}  // namespace anonymous

// ---------------------------------------------------------------------------

const String16 sHardwareTest("android.permission.HARDWARE_TEST");
const String16 sAccessSurfaceFlinger("android.permission.ACCESS_SURFACE_FLINGER");
const String16 sRotateSurfaceFlinger("android.permission.ROTATE_SURFACE_FLINGER");
const String16 sReadFramebuffer("android.permission.READ_FRAME_BUFFER");
const String16 sControlDisplayBrightness("android.permission.CONTROL_DISPLAY_BRIGHTNESS");
const String16 sDump("android.permission.DUMP");
const String16 sCaptureBlackoutContent("android.permission.CAPTURE_BLACKOUT_CONTENT");
const String16 sInternalSystemWindow("android.permission.INTERNAL_SYSTEM_WINDOW");
const String16 sWakeupSurfaceFlinger("android.permission.WAKEUP_SURFACE_FLINGER");

const char* KERNEL_IDLE_TIMER_PROP = "graphics.display.kernel_idle_timer.enabled";

static const int MAX_TRACING_MEMORY = 1024 * 1024 * 1024; // 1GB

// ---------------------------------------------------------------------------
int64_t SurfaceFlinger::dispSyncPresentTimeOffset;
bool SurfaceFlinger::useHwcForRgbToYuv;
bool SurfaceFlinger::hasSyncFramework;
int64_t SurfaceFlinger::maxFrameBufferAcquiredBuffers;
uint32_t SurfaceFlinger::maxGraphicsWidth;
uint32_t SurfaceFlinger::maxGraphicsHeight;
bool SurfaceFlinger::useContextPriority;
Dataspace SurfaceFlinger::defaultCompositionDataspace = Dataspace::V0_SRGB;
ui::PixelFormat SurfaceFlinger::defaultCompositionPixelFormat = ui::PixelFormat::RGBA_8888;
Dataspace SurfaceFlinger::wideColorGamutCompositionDataspace = Dataspace::V0_SRGB;
ui::PixelFormat SurfaceFlinger::wideColorGamutCompositionPixelFormat = ui::PixelFormat::RGBA_8888;
LatchUnsignaledConfig SurfaceFlinger::enableLatchUnsignaledConfig;

std::string decodeDisplayColorSetting(DisplayColorSetting displayColorSetting) {
    switch(displayColorSetting) {
        case DisplayColorSetting::kManaged:
            return std::string("Managed");
        case DisplayColorSetting::kUnmanaged:
            return std::string("Unmanaged");
        case DisplayColorSetting::kEnhanced:
            return std::string("Enhanced");
        default:
            return std::string("Unknown ") +
                std::to_string(static_cast<int>(displayColorSetting));
    }
}

bool callingThreadHasPermission(const String16& permission) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    return uid == AID_GRAPHICS || uid == AID_SYSTEM ||
            PermissionCache::checkPermission(permission, pid, uid);
}

ui::Transform::RotationFlags SurfaceFlinger::sActiveDisplayRotationFlags = ui::Transform::ROT_0;

SurfaceFlinger::SurfaceFlinger(Factory& factory, SkipInitializationTag)
      : mFactory(factory),
        mPid(getpid()),
        mTimeStats(std::make_shared<impl::TimeStats>()),
        mFrameTracer(mFactory.createFrameTracer()),
        mFrameTimeline(mFactory.createFrameTimeline(mTimeStats, mPid)),
        mCompositionEngine(mFactory.createCompositionEngine()),
        mHwcServiceName(base::GetProperty("debug.sf.hwc_service_name"s, "default"s)),
        mTunnelModeEnabledReporter(sp<TunnelModeEnabledReporter>::make()),
        mEmulatedDisplayDensity(getDensityFromProperty("qemu.sf.lcd_density", false)),
        mInternalDisplayDensity(
                getDensityFromProperty("ro.sf.lcd_density", !mEmulatedDisplayDensity)),
        mPowerAdvisor(std::make_unique<Hwc2::impl::PowerAdvisor>(*this)),
        mWindowInfosListenerInvoker(sp<WindowInfosListenerInvoker>::make()) {
    ALOGI("Using HWComposer service: %s", mHwcServiceName.c_str());
}

SurfaceFlinger::SurfaceFlinger(Factory& factory) : SurfaceFlinger(factory, SkipInitialization) {
    ALOGI("SurfaceFlinger is starting");

    hasSyncFramework = running_without_sync_framework(true);

    dispSyncPresentTimeOffset = present_time_offset_from_vsync_ns(0);

    useHwcForRgbToYuv = force_hwc_copy_for_virtual_displays(false);

    maxFrameBufferAcquiredBuffers = max_frame_buffer_acquired_buffers(2);

    maxGraphicsWidth = std::max(max_graphics_width(0), 0);
    maxGraphicsHeight = std::max(max_graphics_height(0), 0);

    mSupportsWideColor = has_wide_color_display(false);
    mDefaultCompositionDataspace =
            static_cast<ui::Dataspace>(default_composition_dataspace(Dataspace::V0_SRGB));
    mWideColorGamutCompositionDataspace = static_cast<ui::Dataspace>(wcg_composition_dataspace(
            mSupportsWideColor ? Dataspace::DISPLAY_P3 : Dataspace::V0_SRGB));
    defaultCompositionDataspace = mDefaultCompositionDataspace;
    wideColorGamutCompositionDataspace = mWideColorGamutCompositionDataspace;
    defaultCompositionPixelFormat = static_cast<ui::PixelFormat>(
            default_composition_pixel_format(ui::PixelFormat::RGBA_8888));
    wideColorGamutCompositionPixelFormat =
            static_cast<ui::PixelFormat>(wcg_composition_pixel_format(ui::PixelFormat::RGBA_8888));

    mColorSpaceAgnosticDataspace =
            static_cast<ui::Dataspace>(color_space_agnostic_dataspace(Dataspace::UNKNOWN));

    mLayerCachingEnabled = [] {
        const bool enable =
                android::sysprop::SurfaceFlingerProperties::enable_layer_caching().value_or(false);
        return base::GetBoolProperty(std::string("debug.sf.enable_layer_caching"), enable);
    }();

    useContextPriority = use_context_priority(true);

    mInternalDisplayPrimaries = sysprop::getDisplayNativePrimaries();

    // debugging stuff...
    char value[PROPERTY_VALUE_MAX];

    property_get("ro.build.type", value, "user");
    mIsUserBuild = strcmp(value, "user") == 0;

    mDebugFlashDelay = base::GetUintProperty("debug.sf.showupdates"s, 0u);

    mBackpressureGpuComposition = base::GetBoolProperty("debug.sf.enable_gl_backpressure"s, true);
    ALOGI_IF(mBackpressureGpuComposition, "Enabling backpressure for GPU composition");

    property_get("ro.surface_flinger.supports_background_blur", value, "0");
    bool supportsBlurs = atoi(value);
    mSupportsBlur = supportsBlurs;
    ALOGI_IF(!mSupportsBlur, "Disabling blur effects, they are not supported.");

    const size_t defaultListSize = MAX_LAYERS;
    auto listSize = property_get_int32("debug.sf.max_igbp_list_size", int32_t(defaultListSize));
    mMaxGraphicBufferProducerListSize = (listSize > 0) ? size_t(listSize) : defaultListSize;
    mGraphicBufferProducerListSizeLogThreshold =
            std::max(static_cast<int>(0.95 *
                                      static_cast<double>(mMaxGraphicBufferProducerListSize)),
                     1);

    property_get("debug.sf.luma_sampling", value, "1");
    mLumaSampling = atoi(value);

    property_get("debug.sf.disable_client_composition_cache", value, "0");
    mDisableClientCompositionCache = atoi(value);

    property_get("debug.sf.predict_hwc_composition_strategy", value, "1");
    mPredictCompositionStrategy = atoi(value);

    property_get("debug.sf.treat_170m_as_sRGB", value, "0");
    mTreat170mAsSrgb = atoi(value);

    property_get("debug.sf.dim_in_gamma_in_enhanced_screenshots", value, 0);
    mDimInGammaSpaceForEnhancedScreenshots = atoi(value);

    mIgnoreHwcPhysicalDisplayOrientation =
            base::GetBoolProperty("debug.sf.ignore_hwc_physical_display_orientation"s, false);

    // We should be reading 'persist.sys.sf.color_saturation' here
    // but since /data may be encrypted, we need to wait until after vold
    // comes online to attempt to read the property. The property is
    // instead read after the boot animation

    if (base::GetBoolProperty("debug.sf.treble_testing_override"s, false)) {
        // Without the override SurfaceFlinger cannot connect to HIDL
        // services that are not listed in the manifests.  Considered
        // deriving the setting from the set service name, but it
        // would be brittle if the name that's not 'default' is used
        // for production purposes later on.
        ALOGI("Enabling Treble testing override");
        android::hardware::details::setTrebleTestingOverride(true);
    }

    // TODO (b/270966065) Update the HWC based refresh rate overlay to support spinner
    mRefreshRateOverlaySpinner = property_get_bool("debug.sf.show_refresh_rate_overlay_spinner", 0);
    mRefreshRateOverlayRenderRate =
            property_get_bool("debug.sf.show_refresh_rate_overlay_render_rate", 0);
    mRefreshRateOverlayShowInMiddle =
            property_get_bool("debug.sf.show_refresh_rate_overlay_in_middle", 0);

    if (!mIsUserBuild && base::GetBoolProperty("debug.sf.enable_transaction_tracing"s, true)) {
        mTransactionTracing.emplace();
    }

    mIgnoreHdrCameraLayers = ignore_hdr_camera_layers(false);

    mLayerLifecycleManagerEnabled =
            base::GetBoolProperty("persist.debug.sf.enable_layer_lifecycle_manager"s, false);
    mLegacyFrontEndEnabled = !mLayerLifecycleManagerEnabled ||
            base::GetBoolProperty("persist.debug.sf.enable_legacy_frontend"s, false);
}

LatchUnsignaledConfig SurfaceFlinger::getLatchUnsignaledConfig() {
    if (base::GetBoolProperty("debug.sf.auto_latch_unsignaled"s, true)) {
        return LatchUnsignaledConfig::AutoSingleLayer;
    }

    if (base::GetBoolProperty("debug.sf.latch_unsignaled"s, false)) {
        return LatchUnsignaledConfig::Always;
    }

    return LatchUnsignaledConfig::Disabled;
}

SurfaceFlinger::~SurfaceFlinger() = default;

void SurfaceFlinger::binderDied(const wp<IBinder>&) {
    // the window manager died on us. prepare its eulogy.
    mBootFinished = false;

    static_cast<void>(mScheduler->schedule([this]() FTL_FAKE_GUARD(kMainThreadContext) {
        // Sever the link to inputflinger since it's gone as well.
        mInputFlinger.clear();

        initializeDisplays();
    }));

    startBootAnim();
}

void SurfaceFlinger::run() {
    mScheduler->run();
}

sp<IBinder> SurfaceFlinger::createDisplay(const String8& displayName, bool secure,
                                          float requestedRefreshRate) {
    // onTransact already checks for some permissions, but adding an additional check here.
    // This is to ensure that only system and graphics can request to create a secure
    // display. Secure displays can show secure content so we add an additional restriction on it.
    const int uid = IPCThreadState::self()->getCallingUid();
    if (secure && uid != AID_GRAPHICS && uid != AID_SYSTEM) {
        ALOGE("Only privileged processes can create a secure display");
        return nullptr;
    }

    class DisplayToken : public BBinder {
        sp<SurfaceFlinger> flinger;
        virtual ~DisplayToken() {
             // no more references, this display must be terminated
             Mutex::Autolock _l(flinger->mStateLock);
             flinger->mCurrentState.displays.removeItem(wp<IBinder>::fromExisting(this));
             flinger->setTransactionFlags(eDisplayTransactionNeeded);
         }
     public:
        explicit DisplayToken(const sp<SurfaceFlinger>& flinger)
            : flinger(flinger) {
        }
    };

    sp<BBinder> token = sp<DisplayToken>::make(sp<SurfaceFlinger>::fromExisting(this));

    Mutex::Autolock _l(mStateLock);
    // Display ID is assigned when virtual display is allocated by HWC.
    DisplayDeviceState state;
    state.isSecure = secure;
    state.displayName = displayName;
    state.requestedRefreshRate = Fps::fromValue(requestedRefreshRate);
    mCurrentState.displays.add(token, state);
    return token;
}

void SurfaceFlinger::destroyDisplay(const sp<IBinder>& displayToken) {
    Mutex::Autolock lock(mStateLock);

    const ssize_t index = mCurrentState.displays.indexOfKey(displayToken);
    if (index < 0) {
        ALOGE("%s: Invalid display token %p", __func__, displayToken.get());
        return;
    }

    const DisplayDeviceState& state = mCurrentState.displays.valueAt(index);
    if (state.physical) {
        ALOGE("%s: Invalid operation on physical display", __func__);
        return;
    }
    mCurrentState.displays.removeItemsAt(index);
    setTransactionFlags(eDisplayTransactionNeeded);
}

void SurfaceFlinger::enableHalVirtualDisplays(bool enable) {
    auto& generator = mVirtualDisplayIdGenerators.hal;
    if (!generator && enable) {
        ALOGI("Enabling HAL virtual displays");
        generator.emplace(getHwComposer().getMaxVirtualDisplayCount());
    } else if (generator && !enable) {
        ALOGW_IF(generator->inUse(), "Disabling HAL virtual displays while in use");
        generator.reset();
    }
}

VirtualDisplayId SurfaceFlinger::acquireVirtualDisplay(ui::Size resolution,
                                                       ui::PixelFormat format) {
    if (auto& generator = mVirtualDisplayIdGenerators.hal) {
        if (const auto id = generator->generateId()) {
            if (getHwComposer().allocateVirtualDisplay(*id, resolution, &format)) {
                return *id;
            }

            generator->releaseId(*id);
        } else {
            ALOGW("%s: Exhausted HAL virtual displays", __func__);
        }

        ALOGW("%s: Falling back to GPU virtual display", __func__);
    }

    const auto id = mVirtualDisplayIdGenerators.gpu.generateId();
    LOG_ALWAYS_FATAL_IF(!id, "Failed to generate ID for GPU virtual display");
    return *id;
}

void SurfaceFlinger::releaseVirtualDisplay(VirtualDisplayId displayId) {
    if (const auto id = HalVirtualDisplayId::tryCast(displayId)) {
        if (auto& generator = mVirtualDisplayIdGenerators.hal) {
            generator->releaseId(*id);
        }
        return;
    }

    const auto id = GpuVirtualDisplayId::tryCast(displayId);
    LOG_ALWAYS_FATAL_IF(!id);
    mVirtualDisplayIdGenerators.gpu.releaseId(*id);
}

std::vector<PhysicalDisplayId> SurfaceFlinger::getPhysicalDisplayIdsLocked() const {
    std::vector<PhysicalDisplayId> displayIds;
    displayIds.reserve(mPhysicalDisplays.size());

    const auto defaultDisplayId = getDefaultDisplayDeviceLocked()->getPhysicalId();
    displayIds.push_back(defaultDisplayId);

    for (const auto& [id, display] : mPhysicalDisplays) {
        if (id != defaultDisplayId) {
            displayIds.push_back(id);
        }
    }

    return displayIds;
}

std::optional<PhysicalDisplayId> SurfaceFlinger::getPhysicalDisplayIdLocked(
        const sp<display::DisplayToken>& displayToken) const {
    return ftl::find_if(mPhysicalDisplays, PhysicalDisplay::hasToken(displayToken))
            .transform(&ftl::to_key<PhysicalDisplays>);
}

sp<IBinder> SurfaceFlinger::getPhysicalDisplayToken(PhysicalDisplayId displayId) const {
    Mutex::Autolock lock(mStateLock);
    return getPhysicalDisplayTokenLocked(displayId);
}

status_t SurfaceFlinger::getColorManagement(bool* outGetColorManagement) const {
    if (!outGetColorManagement) {
        return BAD_VALUE;
    }
    *outGetColorManagement = useColorManagement;
    return NO_ERROR;
}

HWComposer& SurfaceFlinger::getHwComposer() const {
    return mCompositionEngine->getHwComposer();
}

renderengine::RenderEngine& SurfaceFlinger::getRenderEngine() const {
    return *mRenderEngine;
}

compositionengine::CompositionEngine& SurfaceFlinger::getCompositionEngine() const {
    return *mCompositionEngine.get();
}

void SurfaceFlinger::bootFinished() {
    if (mBootFinished == true) {
        ALOGE("Extra call to bootFinished");
        return;
    }
    mBootFinished = true;
    if (mStartPropertySetThread->join() != NO_ERROR) {
        ALOGE("Join StartPropertySetThread failed!");
    }

    if (mRenderEnginePrimeCacheFuture.valid()) {
        mRenderEnginePrimeCacheFuture.get();
    }
    const nsecs_t now = systemTime();
    const nsecs_t duration = now - mBootTime;
    ALOGI("Boot is finished (%ld ms)", long(ns2ms(duration)) );

    mFrameTracer->initialize();
    mFrameTimeline->onBootFinished();
    getRenderEngine().setEnableTracing(mFlagManager.use_skia_tracing());

    // wait patiently for the window manager death
    const String16 name("window");
    mWindowManager = defaultServiceManager()->getService(name);
    if (mWindowManager != 0) {
        mWindowManager->linkToDeath(sp<IBinder::DeathRecipient>::fromExisting(this));
    }

    // stop boot animation
    // formerly we would just kill the process, but we now ask it to exit so it
    // can choose where to stop the animation.
    property_set("service.bootanim.exit", "1");

    const int LOGTAG_SF_STOP_BOOTANIM = 60110;
    LOG_EVENT_LONG(LOGTAG_SF_STOP_BOOTANIM,
                   ns2ms(systemTime(SYSTEM_TIME_MONOTONIC)));

    sp<IBinder> input(defaultServiceManager()->getService(String16("inputflinger")));

    static_cast<void>(mScheduler->schedule([=]() FTL_FAKE_GUARD(kMainThreadContext) {
        if (input == nullptr) {
            ALOGE("Failed to link to input service");
        } else {
            mInputFlinger = interface_cast<os::IInputFlinger>(input);
        }

        readPersistentProperties();
        mPowerAdvisor->onBootFinished();
        const bool hintSessionEnabled = mFlagManager.use_adpf_cpu_hint();
        mPowerAdvisor->enablePowerHintSession(hintSessionEnabled);
        const bool hintSessionUsed = mPowerAdvisor->usePowerHintSession();
        ALOGD("Power hint is %s",
              hintSessionUsed ? "supported" : (hintSessionEnabled ? "unsupported" : "disabled"));
        if (hintSessionUsed) {
            std::optional<pid_t> renderEngineTid = getRenderEngine().getRenderEngineTid();
            std::vector<int32_t> tidList;
            tidList.emplace_back(gettid());
            if (renderEngineTid.has_value()) {
                tidList.emplace_back(*renderEngineTid);
            }
            if (!mPowerAdvisor->startPowerHintSession(tidList)) {
                ALOGW("Cannot start power hint session");
            }
        }

        mBootStage = BootStage::FINISHED;

        if (base::GetBoolProperty("sf.debug.show_refresh_rate_overlay"s, false)) {
            ftl::FakeGuard guard(mStateLock);
            enableRefreshRateOverlay(true);
        }
    }));
}

uint32_t SurfaceFlinger::getNewTexture() {
    {
        std::lock_guard lock(mTexturePoolMutex);
        if (!mTexturePool.empty()) {
            uint32_t name = mTexturePool.back();
            mTexturePool.pop_back();
            ATRACE_INT("TexturePoolSize", mTexturePool.size());
            return name;
        }

        // The pool was too small, so increase it for the future
        ++mTexturePoolSize;
    }

    // The pool was empty, so we need to get a new texture name directly using a
    // blocking call to the main thread
    auto genTextures = [this] {
               uint32_t name = 0;
               getRenderEngine().genTextures(1, &name);
               return name;
    };
    if (std::this_thread::get_id() == mMainThreadId) {
        return genTextures();
    } else {
        return mScheduler->schedule(genTextures).get();
    }
}

void SurfaceFlinger::deleteTextureAsync(uint32_t texture) {
    std::lock_guard lock(mTexturePoolMutex);
    // We don't change the pool size, so the fix-up logic in postComposition will decide whether
    // to actually delete this or not based on mTexturePoolSize
    mTexturePool.push_back(texture);
    ATRACE_INT("TexturePoolSize", mTexturePool.size());
}

static std::optional<renderengine::RenderEngine::RenderEngineType>
chooseRenderEngineTypeViaSysProp() {
    char prop[PROPERTY_VALUE_MAX];
    property_get(PROPERTY_DEBUG_RENDERENGINE_BACKEND, prop, "");

    if (strcmp(prop, "gles") == 0) {
        return renderengine::RenderEngine::RenderEngineType::GLES;
    } else if (strcmp(prop, "threaded") == 0) {
        return renderengine::RenderEngine::RenderEngineType::THREADED;
    } else if (strcmp(prop, "skiagl") == 0) {
        return renderengine::RenderEngine::RenderEngineType::SKIA_GL;
    } else if (strcmp(prop, "skiaglthreaded") == 0) {
        return renderengine::RenderEngine::RenderEngineType::SKIA_GL_THREADED;
    } else if (strcmp(prop, "skiavk") == 0) {
        return renderengine::RenderEngine::RenderEngineType::SKIA_VK;
    } else if (strcmp(prop, "skiavkthreaded") == 0) {
        return renderengine::RenderEngine::RenderEngineType::SKIA_VK_THREADED;
    } else {
        ALOGE("Unrecognized RenderEngineType %s; ignoring!", prop);
        return {};
    }
}

// Do not call property_set on main thread which will be blocked by init
// Use StartPropertySetThread instead.
void SurfaceFlinger::init() FTL_FAKE_GUARD(kMainThreadContext) {
    ALOGI(  "SurfaceFlinger's main thread ready to run. "
            "Initializing graphics H/W...");
    addTransactionReadyFilters();
    Mutex::Autolock lock(mStateLock);

    // Get a RenderEngine for the given display / config (can't fail)
    // TODO(b/77156734): We need to stop casting and use HAL types when possible.
    // Sending maxFrameBufferAcquiredBuffers as the cache size is tightly tuned to single-display.
    auto builder = renderengine::RenderEngineCreationArgs::Builder()
                           .setPixelFormat(static_cast<int32_t>(defaultCompositionPixelFormat))
                           .setImageCacheSize(maxFrameBufferAcquiredBuffers)
                           .setUseColorManagerment(useColorManagement)
                           .setEnableProtectedContext(enable_protected_contents(false))
                           .setPrecacheToneMapperShaderOnly(false)
                           .setSupportsBackgroundBlur(mSupportsBlur)
                           .setContextPriority(
                                   useContextPriority
                                           ? renderengine::RenderEngine::ContextPriority::REALTIME
                                           : renderengine::RenderEngine::ContextPriority::MEDIUM);
    if (auto type = chooseRenderEngineTypeViaSysProp()) {
        builder.setRenderEngineType(type.value());
    }
    mRenderEngine = renderengine::RenderEngine::create(builder.build());
    mCompositionEngine->setRenderEngine(mRenderEngine.get());
    mMaxRenderTargetSize =
            std::min(getRenderEngine().getMaxTextureSize(), getRenderEngine().getMaxViewportDims());

    // Set SF main policy after initializing RenderEngine which has its own policy.
    if (!SetTaskProfiles(0, {"SFMainPolicy"})) {
        ALOGW("Failed to set main task profile");
    }

    mCompositionEngine->setTimeStats(mTimeStats);
    mCompositionEngine->setHwComposer(getFactory().createHWComposer(mHwcServiceName));
    mCompositionEngine->getHwComposer().setCallback(*this);
    ClientCache::getInstance().setRenderEngine(&getRenderEngine());

    enableLatchUnsignaledConfig = getLatchUnsignaledConfig();

    if (base::GetBoolProperty("debug.sf.enable_hwc_vds"s, false)) {
        enableHalVirtualDisplays(true);
    }

    // Process hotplug for displays connected at boot.
    LOG_ALWAYS_FATAL_IF(!configureLocked(),
                        "Initial display configuration failed: HWC did not hotplug");

    // Commit primary display.
    sp<const DisplayDevice> display;
    if (const auto indexOpt = mCurrentState.getDisplayIndex(getPrimaryDisplayIdLocked())) {
        const auto& displays = mCurrentState.displays;

        const auto& token = displays.keyAt(*indexOpt);
        const auto& state = displays.valueAt(*indexOpt);

        processDisplayAdded(token, state);
        mDrawingState.displays.add(token, state);

        display = getDefaultDisplayDeviceLocked();
    }

    LOG_ALWAYS_FATAL_IF(!display, "Failed to configure the primary display");
    LOG_ALWAYS_FATAL_IF(!getHwComposer().isConnected(display->getPhysicalId()),
                        "Primary display is disconnected");

    // TODO(b/241285876): The Scheduler needlessly depends on creating the CompositionEngine part of
    // the DisplayDevice, hence the above commit of the primary display. Remove that special case by
    // initializing the Scheduler after configureLocked, once decoupled from DisplayDevice.
    initScheduler(display);
    dispatchDisplayHotplugEvent(display->getPhysicalId(), true);

    // Commit secondary display(s).
    processDisplayChangesLocked();

    // initialize our drawing state
    mDrawingState = mCurrentState;

    onActiveDisplayChangedLocked(nullptr, *display);

    static_cast<void>(mScheduler->schedule(
            [this]() FTL_FAKE_GUARD(kMainThreadContext) { initializeDisplays(); }));

    mPowerAdvisor->init();

    char primeShaderCache[PROPERTY_VALUE_MAX];
    property_get("service.sf.prime_shader_cache", primeShaderCache, "1");
    if (atoi(primeShaderCache)) {
        if (setSchedFifo(false) != NO_ERROR) {
            ALOGW("Can't set SCHED_OTHER for primeCache");
        }

        mRenderEnginePrimeCacheFuture = getRenderEngine().primeCache();

        if (setSchedFifo(true) != NO_ERROR) {
            ALOGW("Can't set SCHED_OTHER for primeCache");
        }
    }

    // Inform native graphics APIs whether the present timestamp is supported:

    const bool presentFenceReliable =
            !getHwComposer().hasCapability(Capability::PRESENT_FENCE_IS_NOT_RELIABLE);
    mStartPropertySetThread = getFactory().createStartPropertySetThread(presentFenceReliable);

    if (mStartPropertySetThread->Start() != NO_ERROR) {
        ALOGE("Run StartPropertySetThread failed!");
    }

    if (mTransactionTracing) {
        TransactionTraceWriter::getInstance().setWriterFunction([&](const std::string& prefix,
                                                                    bool overwrite) {
            auto writeFn = [&]() {
                const std::string filename =
                        TransactionTracing::DIR_NAME + prefix + TransactionTracing::FILE_NAME;
                if (overwrite && access(filename.c_str(), F_OK) == 0) {
                    ALOGD("TransactionTraceWriter: file=%s already exists", filename.c_str());
                    return;
                }
                mTransactionTracing->flush();
                mTransactionTracing->writeToFile(filename);
            };
            if (std::this_thread::get_id() == mMainThreadId) {
                writeFn();
            } else {
                mScheduler->schedule(writeFn).get();
            }
        });
    }

    ALOGV("Done initializing");
}

void SurfaceFlinger::readPersistentProperties() {
    Mutex::Autolock _l(mStateLock);

    char value[PROPERTY_VALUE_MAX];

    property_get("persist.sys.sf.color_saturation", value, "1.0");
    mGlobalSaturationFactor = atof(value);
    updateColorMatrixLocked();
    ALOGV("Saturation is set to %.2f", mGlobalSaturationFactor);

    property_get("persist.sys.sf.native_mode", value, "0");
    mDisplayColorSetting = static_cast<DisplayColorSetting>(atoi(value));

    mForceColorMode =
            static_cast<ui::ColorMode>(base::GetIntProperty("persist.sys.sf.color_mode"s, 0));
}

void SurfaceFlinger::startBootAnim() {
    // Start boot animation service by setting a property mailbox
    // if property setting thread is already running, Start() will be just a NOP
    mStartPropertySetThread->Start();
    // Wait until property was set
    if (mStartPropertySetThread->join() != NO_ERROR) {
        ALOGE("Join StartPropertySetThread failed!");
    }
}

// ----------------------------------------------------------------------------

status_t SurfaceFlinger::getSupportedFrameTimestamps(
        std::vector<FrameEvent>* outSupported) const {
    *outSupported = {
        FrameEvent::REQUESTED_PRESENT,
        FrameEvent::ACQUIRE,
        FrameEvent::LATCH,
        FrameEvent::FIRST_REFRESH_START,
        FrameEvent::LAST_REFRESH_START,
        FrameEvent::GPU_COMPOSITION_DONE,
        FrameEvent::DEQUEUE_READY,
        FrameEvent::RELEASE,
    };

    ConditionalLock lock(mStateLock, std::this_thread::get_id() != mMainThreadId);

    if (!getHwComposer().hasCapability(Capability::PRESENT_FENCE_IS_NOT_RELIABLE)) {
        outSupported->push_back(FrameEvent::DISPLAY_PRESENT);
    }
    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayState(const sp<IBinder>& displayToken, ui::DisplayState* state) {
    if (!displayToken || !state) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    state->layerStack = display->getLayerStack();
    state->orientation = display->getOrientation();

    const Rect layerStackRect = display->getLayerStackSpaceRect();
    state->layerStackSpaceRect =
            layerStackRect.isValid() ? layerStackRect.getSize() : display->getSize();

    return NO_ERROR;
}

status_t SurfaceFlinger::getStaticDisplayInfo(int64_t displayId, ui::StaticDisplayInfo* info) {
    if (!info) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);
    const auto id = DisplayId::fromValue<PhysicalDisplayId>(static_cast<uint64_t>(displayId));
    const auto displayOpt = mPhysicalDisplays.get(*id).and_then(getDisplayDeviceAndSnapshot());

    if (!displayOpt) {
        return NAME_NOT_FOUND;
    }

    const auto& [display, snapshotRef] = *displayOpt;
    const auto& snapshot = snapshotRef.get();

    info->connectionType = snapshot.connectionType();
    info->deviceProductInfo = snapshot.deviceProductInfo();

    if (mEmulatedDisplayDensity) {
        info->density = mEmulatedDisplayDensity;
    } else {
        info->density = info->connectionType == ui::DisplayConnectionType::Internal
                ? mInternalDisplayDensity
                : FALLBACK_DENSITY;
    }
    info->density /= ACONFIGURATION_DENSITY_MEDIUM;

    info->secure = display->isSecure();
    info->installOrientation = display->getPhysicalOrientation();

    return NO_ERROR;
}

void SurfaceFlinger::getDynamicDisplayInfoInternal(ui::DynamicDisplayInfo*& info,
                                                   const sp<DisplayDevice>& display,
                                                   const display::DisplaySnapshot& snapshot) {
    const auto& displayModes = snapshot.displayModes();
    info->supportedDisplayModes.clear();
    info->supportedDisplayModes.reserve(displayModes.size());

    for (const auto& [id, mode] : displayModes) {
        ui::DisplayMode outMode;
        outMode.id = static_cast<int32_t>(id.value());

        auto [width, height] = mode->getResolution();
        auto [xDpi, yDpi] = mode->getDpi();

        if (const auto physicalOrientation = display->getPhysicalOrientation();
            physicalOrientation == ui::ROTATION_90 || physicalOrientation == ui::ROTATION_270) {
            std::swap(width, height);
            std::swap(xDpi, yDpi);
        }

        outMode.resolution = ui::Size(width, height);

        outMode.xDpi = xDpi;
        outMode.yDpi = yDpi;

        const nsecs_t period = mode->getVsyncPeriod();
        outMode.refreshRate = Fps::fromPeriodNsecs(period).getValue();

        const auto vsyncConfigSet =
                mVsyncConfiguration->getConfigsForRefreshRate(Fps::fromValue(outMode.refreshRate));
        outMode.appVsyncOffset = vsyncConfigSet.late.appOffset;
        outMode.sfVsyncOffset = vsyncConfigSet.late.sfOffset;
        outMode.group = mode->getGroup();

        // This is how far in advance a buffer must be queued for
        // presentation at a given time.  If you want a buffer to appear
        // on the screen at time N, you must submit the buffer before
        // (N - presentationDeadline).
        //
        // Normally it's one full refresh period (to give SF a chance to
        // latch the buffer), but this can be reduced by configuring a
        // VsyncController offset.  Any additional delays introduced by the hardware
        // composer or panel must be accounted for here.
        //
        // We add an additional 1ms to allow for processing time and
        // differences between the ideal and actual refresh rate.
        outMode.presentationDeadline = period - outMode.sfVsyncOffset + 1000000;
        excludeDolbyVisionIf4k30Present(display->getHdrCapabilities().getSupportedHdrTypes(),
                                        outMode);
        info->supportedDisplayModes.push_back(outMode);
    }

    info->supportedColorModes = snapshot.filterColorModes(mSupportsWideColor);

    const PhysicalDisplayId displayId = snapshot.displayId();

    const auto mode = display->refreshRateSelector().getActiveMode();
    info->activeDisplayModeId = mode.modePtr->getId().value();
    info->renderFrameRate = mode.fps.getValue();
    info->activeColorMode = display->getCompositionDisplay()->getState().colorMode;
    info->hdrCapabilities = filterOut4k30(display->getHdrCapabilities());

    info->autoLowLatencyModeSupported =
            getHwComposer().hasDisplayCapability(displayId,
                                                 DisplayCapability::AUTO_LOW_LATENCY_MODE);
    info->gameContentTypeSupported =
            getHwComposer().supportsContentType(displayId, hal::ContentType::GAME);

    info->preferredBootDisplayMode = static_cast<ui::DisplayModeId>(-1);

    if (getHwComposer().hasCapability(Capability::BOOT_DISPLAY_CONFIG)) {
        if (const auto hwcId = getHwComposer().getPreferredBootDisplayMode(displayId)) {
            if (const auto modeId = snapshot.translateModeId(*hwcId)) {
                info->preferredBootDisplayMode = modeId->value();
            }
        }
    }
}

status_t SurfaceFlinger::getDynamicDisplayInfoFromId(int64_t physicalDisplayId,
                                                     ui::DynamicDisplayInfo* info) {
    if (!info) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto id_ =
            DisplayId::fromValue<PhysicalDisplayId>(static_cast<uint64_t>(physicalDisplayId));
    const auto displayOpt = mPhysicalDisplays.get(*id_).and_then(getDisplayDeviceAndSnapshot());

    if (!displayOpt) {
        return NAME_NOT_FOUND;
    }

    const auto& [display, snapshotRef] = *displayOpt;
    getDynamicDisplayInfoInternal(info, display, snapshotRef.get());
    return NO_ERROR;
}

status_t SurfaceFlinger::getDynamicDisplayInfoFromToken(const sp<IBinder>& displayToken,
                                                        ui::DynamicDisplayInfo* info) {
    if (!displayToken || !info) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto displayOpt = ftl::find_if(mPhysicalDisplays, PhysicalDisplay::hasToken(displayToken))
                                    .transform(&ftl::to_mapped_ref<PhysicalDisplays>)
                                    .and_then(getDisplayDeviceAndSnapshot());

    if (!displayOpt) {
        return NAME_NOT_FOUND;
    }

    const auto& [display, snapshotRef] = *displayOpt;
    getDynamicDisplayInfoInternal(info, display, snapshotRef.get());
    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayStats(const sp<IBinder>& displayToken,
                                         DisplayStatInfo* outStats) {
    if (!outStats) {
        return BAD_VALUE;
    }

    std::optional<PhysicalDisplayId> displayIdOpt;
    {
        Mutex::Autolock lock(mStateLock);
        if (displayToken) {
            displayIdOpt = getPhysicalDisplayIdLocked(displayToken);
            if (!displayIdOpt) {
                ALOGW("%s: Invalid physical display token %p", __func__, displayToken.get());
                return NAME_NOT_FOUND;
            }
        } else {
            // TODO (b/277364366): Clients should be updated to pass in the display they
            // want, rather than us picking an arbitrary one (the active display, in this
            // case).
            displayIdOpt = mActiveDisplayId;
        }
    }

    const auto schedule = mScheduler->getVsyncSchedule(displayIdOpt);
    if (!schedule) {
        ALOGE("%s: Missing VSYNC schedule for display %s!", __func__,
              to_string(*displayIdOpt).c_str());
        return NAME_NOT_FOUND;
    }
    outStats->vsyncTime = schedule->vsyncDeadlineAfter(TimePoint::now()).ns();
    outStats->vsyncPeriod = schedule->period().ns();
    return NO_ERROR;
}

void SurfaceFlinger::setDesiredActiveMode(display::DisplayModeRequest&& request, bool force) {
    const auto displayId = request.mode.modePtr->getPhysicalDisplayId();
    ATRACE_NAME(ftl::Concat(__func__, ' ', displayId.value).c_str());

    const auto display = getDisplayDeviceLocked(displayId);
    if (!display) {
        ALOGW("%s: display is no longer valid", __func__);
        return;
    }

    const auto mode = request.mode;
    const bool emitEvent = request.emitEvent;

    switch (display->setDesiredActiveMode(DisplayDevice::ActiveModeInfo(std::move(request)),
                                          force)) {
        case DisplayDevice::DesiredActiveModeAction::InitiateDisplayModeSwitch:
            // Set the render rate as setDesiredActiveMode updated it.
            mScheduler->setRenderRate(displayId,
                                      display->refreshRateSelector().getActiveMode().fps);

            // Schedule a new frame to initiate the display mode switch.
            scheduleComposite(FrameHint::kNone);

            // Start receiving vsync samples now, so that we can detect a period
            // switch.
            mScheduler->resyncToHardwareVsync(displayId, true /* allowToEnable */,
                                              mode.modePtr->getFps());

            // As we called to set period, we will call to onRefreshRateChangeCompleted once
            // VsyncController model is locked.
            mScheduler->modulateVsync(displayId, &VsyncModulator::onRefreshRateChangeInitiated);

            if (displayId == mActiveDisplayId) {
                updatePhaseConfiguration(mode.fps);
            }

            mScheduler->setModeChangePending(true);
            break;
        case DisplayDevice::DesiredActiveModeAction::InitiateRenderRateSwitch:
            mScheduler->setRenderRate(displayId, mode.fps);

            if (displayId == mActiveDisplayId) {
                updatePhaseConfiguration(mode.fps);
                mRefreshRateStats->setRefreshRate(mode.fps);
            }

            if (emitEvent) {
                dispatchDisplayModeChangeEvent(displayId, mode);
            }
            break;
        case DisplayDevice::DesiredActiveModeAction::None:
            break;
    }
}

status_t SurfaceFlinger::setActiveModeFromBackdoor(const sp<display::DisplayToken>& displayToken,
                                                   DisplayModeId modeId) {
    ATRACE_CALL();

    if (!displayToken) {
        return BAD_VALUE;
    }

    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(kMainThreadContext) -> status_t {
        const auto displayOpt =
                FTL_FAKE_GUARD(mStateLock,
                               ftl::find_if(mPhysicalDisplays,
                                            PhysicalDisplay::hasToken(displayToken))
                                       .transform(&ftl::to_mapped_ref<PhysicalDisplays>)
                                       .and_then(getDisplayDeviceAndSnapshot()));
        if (!displayOpt) {
            ALOGE("%s: Invalid physical display token %p", whence, displayToken.get());
            return NAME_NOT_FOUND;
        }

        const auto& [display, snapshotRef] = *displayOpt;
        const auto& snapshot = snapshotRef.get();

        const auto fpsOpt = snapshot.displayModes().get(modeId).transform(
                [](const DisplayModePtr& mode) { return mode->getFps(); });

        if (!fpsOpt) {
            ALOGE("%s: Invalid mode %d for display %s", whence, modeId.value(),
                  to_string(snapshot.displayId()).c_str());
            return BAD_VALUE;
        }

        const Fps fps = *fpsOpt;

        // Keep the old switching type.
        const bool allowGroupSwitching =
                display->refreshRateSelector().getCurrentPolicy().allowGroupSwitching;

        const scheduler::RefreshRateSelector::DisplayManagerPolicy policy{modeId,
                                                                          {fps, fps},
                                                                          allowGroupSwitching};

        return setDesiredDisplayModeSpecsInternal(display, policy);
    });

    return future.get();
}

void SurfaceFlinger::finalizeDisplayModeChange(DisplayDevice& display) {
    const auto displayId = display.getPhysicalId();
    ATRACE_NAME(ftl::Concat(__func__, ' ', displayId.value).c_str());

    const auto upcomingModeInfo = display.getUpcomingActiveMode();
    if (!upcomingModeInfo.modeOpt) {
        // There is no pending mode change. This can happen if the active
        // display changed and the mode change happened on a different display.
        return;
    }

    if (display.getActiveMode().modePtr->getResolution() !=
        upcomingModeInfo.modeOpt->modePtr->getResolution()) {
        auto& state = mCurrentState.displays.editValueFor(display.getDisplayToken());
        // We need to generate new sequenceId in order to recreate the display (and this
        // way the framebuffer).
        state.sequenceId = DisplayDeviceState{}.sequenceId;
        state.physical->activeMode = upcomingModeInfo.modeOpt->modePtr.get();
        processDisplayChangesLocked();

        // processDisplayChangesLocked will update all necessary components so we're done here.
        return;
    }

    const auto& activeMode = *upcomingModeInfo.modeOpt;
    display.finalizeModeChange(activeMode.modePtr->getId(), activeMode.modePtr->getFps(),
                               activeMode.fps);

    if (displayId == mActiveDisplayId) {
        mRefreshRateStats->setRefreshRate(activeMode.fps);
        updatePhaseConfiguration(activeMode.fps);
    }

    if (upcomingModeInfo.event != scheduler::DisplayModeEvent::None) {
        dispatchDisplayModeChangeEvent(displayId, activeMode);
    }
}

void SurfaceFlinger::clearDesiredActiveModeState(const sp<DisplayDevice>& display) {
    display->clearDesiredActiveModeState();
    if (display->getPhysicalId() == mActiveDisplayId) {
        // TODO(b/255635711): Check for pending mode changes on other displays.
        mScheduler->setModeChangePending(false);
    }
}

void SurfaceFlinger::desiredActiveModeChangeDone(const sp<DisplayDevice>& display) {
    const auto desiredActiveMode = display->getDesiredActiveMode();
    const auto& modeOpt = desiredActiveMode->modeOpt;
    const auto displayId = modeOpt->modePtr->getPhysicalDisplayId();
    const auto displayFps = modeOpt->modePtr->getFps();
    const auto renderFps = modeOpt->fps;
    clearDesiredActiveModeState(display);
    mScheduler->resyncToHardwareVsync(displayId, true /* allowToEnable */, displayFps);
    mScheduler->setRenderRate(displayId, renderFps);

    if (displayId == mActiveDisplayId) {
        updatePhaseConfiguration(renderFps);
    }
}

void SurfaceFlinger::initiateDisplayModeChanges() {
    ATRACE_CALL();

    std::optional<PhysicalDisplayId> displayToUpdateImmediately;

    for (const auto& [id, physical] : mPhysicalDisplays) {
        const auto display = getDisplayDeviceLocked(id);
        if (!display) continue;

        // Store the local variable to release the lock.
        const auto desiredActiveMode = display->getDesiredActiveMode();
        if (!desiredActiveMode) {
            // No desired active mode pending to be applied.
            continue;
        }

        if (!shouldApplyRefreshRateSelectorPolicy(*display)) {
            clearDesiredActiveModeState(display);
            continue;
        }

        const auto desiredModeId = desiredActiveMode->modeOpt->modePtr->getId();
        const auto displayModePtrOpt = physical.snapshot().displayModes().get(desiredModeId);

        if (!displayModePtrOpt) {
            ALOGW("Desired display mode is no longer supported. Mode ID = %d",
                  desiredModeId.value());
            clearDesiredActiveModeState(display);
            continue;
        }

        ALOGV("%s changing active mode to %d(%s) for display %s", __func__, desiredModeId.value(),
              to_string(displayModePtrOpt->get()->getFps()).c_str(),
              to_string(display->getId()).c_str());

        if (display->getActiveMode() == desiredActiveMode->modeOpt) {
            // we are already in the requested mode, there is nothing left to do
            desiredActiveModeChangeDone(display);
            continue;
        }

        // Desired active mode was set, it is different than the mode currently in use, however
        // allowed modes might have changed by the time we process the refresh.
        // Make sure the desired mode is still allowed
        const auto displayModeAllowed =
                display->refreshRateSelector().isModeAllowed(*desiredActiveMode->modeOpt);
        if (!displayModeAllowed) {
            clearDesiredActiveModeState(display);
            continue;
        }

        // TODO(b/142753666) use constrains
        hal::VsyncPeriodChangeConstraints constraints;
        constraints.desiredTimeNanos = systemTime();
        constraints.seamlessRequired = false;
        hal::VsyncPeriodChangeTimeline outTimeline;

        const auto status =
                display->initiateModeChange(*desiredActiveMode, constraints, &outTimeline);

        if (status != NO_ERROR) {
            // initiateModeChange may fail if a hotplug event is just about
            // to be sent. We just log the error in this case.
            ALOGW("initiateModeChange failed: %d", status);
            continue;
        }

        display->refreshRateSelector().onModeChangeInitiated();
        mScheduler->onNewVsyncPeriodChangeTimeline(outTimeline);

        if (outTimeline.refreshRequired) {
            scheduleComposite(FrameHint::kNone);
        } else {
            // TODO(b/255635711): Remove `displayToUpdateImmediately` to `finalizeDisplayModeChange`
            // for all displays. This was only needed when the loop iterated over `mDisplays` rather
            // than `mPhysicalDisplays`.
            displayToUpdateImmediately = display->getPhysicalId();
        }
    }

    if (displayToUpdateImmediately) {
        const auto display = getDisplayDeviceLocked(*displayToUpdateImmediately);
        finalizeDisplayModeChange(*display);

        const auto desiredActiveMode = display->getDesiredActiveMode();
        if (desiredActiveMode && display->getActiveMode() == desiredActiveMode->modeOpt) {
            desiredActiveModeChangeDone(display);
        }
    }
}

void SurfaceFlinger::disableExpensiveRendering() {
    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
        ATRACE_NAME(whence);
        if (mPowerAdvisor->isUsingExpensiveRendering()) {
            for (const auto& [_, display] : mDisplays) {
                constexpr bool kDisable = false;
                mPowerAdvisor->setExpensiveRenderingExpected(display->getId(), kDisable);
            }
        }
    });

    future.wait();
}

status_t SurfaceFlinger::getDisplayNativePrimaries(const sp<IBinder>& displayToken,
                                                   ui::DisplayPrimaries& primaries) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = ftl::find_if(mPhysicalDisplays, PhysicalDisplay::hasToken(displayToken))
                                 .transform(&ftl::to_mapped_ref<PhysicalDisplays>);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    if (!display.transform(&PhysicalDisplay::isInternal).value()) {
        return INVALID_OPERATION;
    }

    // TODO(b/229846990): For now, assume that all internal displays have the same primaries.
    primaries = mInternalDisplayPrimaries;
    return NO_ERROR;
}

status_t SurfaceFlinger::setActiveColorMode(const sp<IBinder>& displayToken, ui::ColorMode mode) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) -> status_t {
        const auto displayOpt =
                ftl::find_if(mPhysicalDisplays, PhysicalDisplay::hasToken(displayToken))
                        .transform(&ftl::to_mapped_ref<PhysicalDisplays>)
                        .and_then(getDisplayDeviceAndSnapshot());

        if (!displayOpt) {
            ALOGE("%s: Invalid physical display token %p", whence, displayToken.get());
            return NAME_NOT_FOUND;
        }

        const auto& [display, snapshotRef] = *displayOpt;
        const auto& snapshot = snapshotRef.get();

        const auto modes = snapshot.filterColorModes(mSupportsWideColor);
        const bool exists = std::find(modes.begin(), modes.end(), mode) != modes.end();

        if (mode < ui::ColorMode::NATIVE || !exists) {
            ALOGE("%s: Invalid color mode %s (%d) for display %s", whence,
                  decodeColorMode(mode).c_str(), mode, to_string(snapshot.displayId()).c_str());
            return BAD_VALUE;
        }

        display->getCompositionDisplay()->setColorProfile(
                {mode, Dataspace::UNKNOWN, RenderIntent::COLORIMETRIC, Dataspace::UNKNOWN});

        return NO_ERROR;
    });

    // TODO(b/195698395): Propagate error.
    future.wait();
    return NO_ERROR;
}

status_t SurfaceFlinger::getBootDisplayModeSupport(bool* outSupport) const {
    auto future = mScheduler->schedule(
            [this] { return getHwComposer().hasCapability(Capability::BOOT_DISPLAY_CONFIG); });

    *outSupport = future.get();
    return NO_ERROR;
}

status_t SurfaceFlinger::getOverlaySupport(gui::OverlayProperties* outProperties) const {
    const auto& aidlProperties = getHwComposer().getOverlaySupport();
    // convert aidl OverlayProperties to gui::OverlayProperties
    outProperties->combinations.reserve(aidlProperties.combinations.size());
    for (const auto& combination : aidlProperties.combinations) {
        std::vector<int32_t> pixelFormats;
        pixelFormats.reserve(combination.pixelFormats.size());
        std::transform(combination.pixelFormats.cbegin(), combination.pixelFormats.cend(),
                       std::back_inserter(pixelFormats),
                       [](const auto& val) { return static_cast<int32_t>(val); });
        std::vector<int32_t> standards;
        standards.reserve(combination.standards.size());
        std::transform(combination.standards.cbegin(), combination.standards.cend(),
                       std::back_inserter(standards),
                       [](const auto& val) { return static_cast<int32_t>(val); });
        std::vector<int32_t> transfers;
        transfers.reserve(combination.transfers.size());
        std::transform(combination.transfers.cbegin(), combination.transfers.cend(),
                       std::back_inserter(transfers),
                       [](const auto& val) { return static_cast<int32_t>(val); });
        std::vector<int32_t> ranges;
        ranges.reserve(combination.ranges.size());
        std::transform(combination.ranges.cbegin(), combination.ranges.cend(),
                       std::back_inserter(ranges),
                       [](const auto& val) { return static_cast<int32_t>(val); });
        gui::OverlayProperties::SupportedBufferCombinations outCombination;
        outCombination.pixelFormats = std::move(pixelFormats);
        outCombination.standards = std::move(standards);
        outCombination.transfers = std::move(transfers);
        outCombination.ranges = std::move(ranges);
        outProperties->combinations.emplace_back(outCombination);
    }
    outProperties->supportMixedColorSpaces = aidlProperties.supportMixedColorSpaces;
    return NO_ERROR;
}

status_t SurfaceFlinger::setBootDisplayMode(const sp<display::DisplayToken>& displayToken,
                                            DisplayModeId modeId) {
    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) -> status_t {
        const auto snapshotOpt =
                ftl::find_if(mPhysicalDisplays, PhysicalDisplay::hasToken(displayToken))
                        .transform(&ftl::to_mapped_ref<PhysicalDisplays>)
                        .transform(&PhysicalDisplay::snapshotRef);

        if (!snapshotOpt) {
            ALOGE("%s: Invalid physical display token %p", whence, displayToken.get());
            return NAME_NOT_FOUND;
        }

        const auto& snapshot = snapshotOpt->get();
        const auto hwcIdOpt = snapshot.displayModes().get(modeId).transform(
                [](const DisplayModePtr& mode) { return mode->getHwcId(); });

        if (!hwcIdOpt) {
            ALOGE("%s: Invalid mode %d for display %s", whence, modeId.value(),
                  to_string(snapshot.displayId()).c_str());
            return BAD_VALUE;
        }

        return getHwComposer().setBootDisplayMode(snapshot.displayId(), *hwcIdOpt);
    });
    return future.get();
}

status_t SurfaceFlinger::clearBootDisplayMode(const sp<IBinder>& displayToken) {
    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) -> status_t {
        if (const auto displayId = getPhysicalDisplayIdLocked(displayToken)) {
            return getHwComposer().clearBootDisplayMode(*displayId);
        } else {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
            return BAD_VALUE;
        }
    });
    return future.get();
}

status_t SurfaceFlinger::getHdrConversionCapabilities(
        std::vector<gui::HdrConversionCapability>* hdrConversionCapabilities) const {
    bool hdrOutputConversionSupport;
    getHdrOutputConversionSupport(&hdrOutputConversionSupport);
    if (hdrOutputConversionSupport == false) {
        ALOGE("hdrOutputConversion is not supported by this device.");
        return INVALID_OPERATION;
    }
    const auto aidlConversionCapability = getHwComposer().getHdrConversionCapabilities();
    for (auto capability : aidlConversionCapability) {
        gui::HdrConversionCapability tempCapability;
        tempCapability.sourceType = static_cast<int>(capability.sourceType);
        tempCapability.outputType = static_cast<int>(capability.outputType);
        tempCapability.addsLatency = capability.addsLatency;
        hdrConversionCapabilities->push_back(tempCapability);
    }
    return NO_ERROR;
}

status_t SurfaceFlinger::setHdrConversionStrategy(
        const gui::HdrConversionStrategy& hdrConversionStrategy,
        int32_t* outPreferredHdrOutputType) {
    bool hdrOutputConversionSupport;
    getHdrOutputConversionSupport(&hdrOutputConversionSupport);
    if (hdrOutputConversionSupport == false) {
        ALOGE("hdrOutputConversion is not supported by this device.");
        return INVALID_OPERATION;
    }
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) mutable -> status_t {
        using AidlHdrConversionStrategy =
                aidl::android::hardware::graphics::common::HdrConversionStrategy;
        using GuiHdrConversionStrategyTag = gui::HdrConversionStrategy::Tag;
        AidlHdrConversionStrategy aidlConversionStrategy;
        status_t status;
        aidl::android::hardware::graphics::common::Hdr aidlPreferredHdrOutputType;
        switch (hdrConversionStrategy.getTag()) {
            case GuiHdrConversionStrategyTag::passthrough: {
                aidlConversionStrategy.set<AidlHdrConversionStrategy::Tag::passthrough>(
                        hdrConversionStrategy.get<GuiHdrConversionStrategyTag::passthrough>());
                status = getHwComposer().setHdrConversionStrategy(aidlConversionStrategy,
                                                                  &aidlPreferredHdrOutputType);
                *outPreferredHdrOutputType = static_cast<int32_t>(aidlPreferredHdrOutputType);
                return status;
            }
            case GuiHdrConversionStrategyTag::autoAllowedHdrTypes: {
                auto autoHdrTypes =
                        hdrConversionStrategy
                                .get<GuiHdrConversionStrategyTag::autoAllowedHdrTypes>();
                std::vector<aidl::android::hardware::graphics::common::Hdr> aidlAutoHdrTypes;
                for (auto type : autoHdrTypes) {
                    aidlAutoHdrTypes.push_back(
                            static_cast<aidl::android::hardware::graphics::common::Hdr>(type));
                }
                aidlConversionStrategy.set<AidlHdrConversionStrategy::Tag::autoAllowedHdrTypes>(
                        aidlAutoHdrTypes);
                status = getHwComposer().setHdrConversionStrategy(aidlConversionStrategy,
                                                                  &aidlPreferredHdrOutputType);
                *outPreferredHdrOutputType = static_cast<int32_t>(aidlPreferredHdrOutputType);
                return status;
            }
            case GuiHdrConversionStrategyTag::forceHdrConversion: {
                auto forceHdrConversion =
                        hdrConversionStrategy
                                .get<GuiHdrConversionStrategyTag::forceHdrConversion>();
                aidlConversionStrategy.set<AidlHdrConversionStrategy::Tag::forceHdrConversion>(
                        static_cast<aidl::android::hardware::graphics::common::Hdr>(
                                forceHdrConversion));
                status = getHwComposer().setHdrConversionStrategy(aidlConversionStrategy,
                                                                  &aidlPreferredHdrOutputType);
                *outPreferredHdrOutputType = static_cast<int32_t>(aidlPreferredHdrOutputType);
                return status;
            }
        }
    });
    return future.get();
}

status_t SurfaceFlinger::getHdrOutputConversionSupport(bool* outSupport) const {
    auto future = mScheduler->schedule([this] {
        return getHwComposer().hasCapability(Capability::HDR_OUTPUT_CONVERSION_CONFIG);
    });

    *outSupport = future.get();
    return NO_ERROR;
}

void SurfaceFlinger::setAutoLowLatencyMode(const sp<IBinder>& displayToken, bool on) {
    const char* const whence = __func__;
    static_cast<void>(mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
        if (const auto displayId = getPhysicalDisplayIdLocked(displayToken)) {
            getHwComposer().setAutoLowLatencyMode(*displayId, on);
        } else {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
        }
    }));
}

void SurfaceFlinger::setGameContentType(const sp<IBinder>& displayToken, bool on) {
    const char* const whence = __func__;
    static_cast<void>(mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
        if (const auto displayId = getPhysicalDisplayIdLocked(displayToken)) {
            const auto type = on ? hal::ContentType::GAME : hal::ContentType::NONE;
            getHwComposer().setContentType(*displayId, type);
        } else {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
        }
    }));
}

status_t SurfaceFlinger::overrideHdrTypes(const sp<IBinder>& displayToken,
                                          const std::vector<ui::Hdr>& hdrTypes) {
    Mutex::Autolock lock(mStateLock);

    auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        ALOGE("%s: Invalid display token %p", __func__, displayToken.get());
        return NAME_NOT_FOUND;
    }

    display->overrideHdrTypes(hdrTypes);
    dispatchDisplayHotplugEvent(display->getPhysicalId(), true /* connected */);
    return NO_ERROR;
}

status_t SurfaceFlinger::onPullAtom(const int32_t atomId, std::vector<uint8_t>* pulledData,
                                    bool* success) {
    *success = mTimeStats->onPullAtom(atomId, pulledData);
    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayedContentSamplingAttributes(const sp<IBinder>& displayToken,
                                                               ui::PixelFormat* outFormat,
                                                               ui::Dataspace* outDataspace,
                                                               uint8_t* outComponentMask) const {
    if (!outFormat || !outDataspace || !outComponentMask) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto displayId = getPhysicalDisplayIdLocked(displayToken);
    if (!displayId) {
        return NAME_NOT_FOUND;
    }

    return getHwComposer().getDisplayedContentSamplingAttributes(*displayId, outFormat,
                                                                 outDataspace, outComponentMask);
}

status_t SurfaceFlinger::setDisplayContentSamplingEnabled(const sp<IBinder>& displayToken,
                                                          bool enable, uint8_t componentMask,
                                                          uint64_t maxFrames) {
    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) -> status_t {
        if (const auto displayId = getPhysicalDisplayIdLocked(displayToken)) {
            return getHwComposer().setDisplayContentSamplingEnabled(*displayId, enable,
                                                                    componentMask, maxFrames);
        } else {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
            return NAME_NOT_FOUND;
        }
    });

    return future.get();
}

status_t SurfaceFlinger::getDisplayedContentSample(const sp<IBinder>& displayToken,
                                                   uint64_t maxFrames, uint64_t timestamp,
                                                   DisplayedFrameStats* outStats) const {
    Mutex::Autolock lock(mStateLock);

    const auto displayId = getPhysicalDisplayIdLocked(displayToken);
    if (!displayId) {
        return NAME_NOT_FOUND;
    }

    return getHwComposer().getDisplayedContentSample(*displayId, maxFrames, timestamp, outStats);
}

status_t SurfaceFlinger::getProtectedContentSupport(bool* outSupported) const {
    if (!outSupported) {
        return BAD_VALUE;
    }
    *outSupported = getRenderEngine().supportsProtectedContent();
    return NO_ERROR;
}

status_t SurfaceFlinger::isWideColorDisplay(const sp<IBinder>& displayToken,
                                            bool* outIsWideColorDisplay) const {
    if (!displayToken || !outIsWideColorDisplay) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);
    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    *outIsWideColorDisplay =
            display->isPrimary() ? mSupportsWideColor : display->hasWideColorGamut();
    return NO_ERROR;
}

status_t SurfaceFlinger::getLayerDebugInfo(std::vector<gui::LayerDebugInfo>* outLayers) {
    outLayers->clear();
    auto future = mScheduler->schedule([=] {
        const auto display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());
        mDrawingState.traverseInZOrder([&](Layer* layer) {
            outLayers->push_back(layer->getLayerDebugInfo(display.get()));
        });
    });

    future.wait();
    return NO_ERROR;
}

status_t SurfaceFlinger::getCompositionPreference(
        Dataspace* outDataspace, ui::PixelFormat* outPixelFormat,
        Dataspace* outWideColorGamutDataspace,
        ui::PixelFormat* outWideColorGamutPixelFormat) const {
    *outDataspace = mDefaultCompositionDataspace;
    *outPixelFormat = defaultCompositionPixelFormat;
    *outWideColorGamutDataspace = mWideColorGamutCompositionDataspace;
    *outWideColorGamutPixelFormat = wideColorGamutCompositionPixelFormat;
    return NO_ERROR;
}

status_t SurfaceFlinger::addRegionSamplingListener(const Rect& samplingArea,
                                                   const sp<IBinder>& stopLayerHandle,
                                                   const sp<IRegionSamplingListener>& listener) {
    if (!listener || samplingArea == Rect::INVALID_RECT || samplingArea.isEmpty()) {
        return BAD_VALUE;
    }

    // LayerHandle::getLayer promotes the layer object in a binder thread but we will not destroy
    // the layer here since the caller has a strong ref to the layer's handle.
    const sp<Layer> stopLayer = LayerHandle::getLayer(stopLayerHandle);
    mRegionSamplingThread->addListener(samplingArea,
                                       stopLayer ? stopLayer->getSequence() : UNASSIGNED_LAYER_ID,
                                       listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::removeRegionSamplingListener(const sp<IRegionSamplingListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }
    mRegionSamplingThread->removeListener(listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::addFpsListener(int32_t taskId, const sp<gui::IFpsListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }

    mFpsReporter->addListener(listener, taskId);
    return NO_ERROR;
}

status_t SurfaceFlinger::removeFpsListener(const sp<gui::IFpsListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }
    mFpsReporter->removeListener(listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::addTunnelModeEnabledListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }

    mTunnelModeEnabledReporter->addListener(listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::removeTunnelModeEnabledListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }

    mTunnelModeEnabledReporter->removeListener(listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayBrightnessSupport(const sp<IBinder>& displayToken,
                                                     bool* outSupport) const {
    if (!displayToken || !outSupport) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto displayId = getPhysicalDisplayIdLocked(displayToken);
    if (!displayId) {
        return NAME_NOT_FOUND;
    }
    *outSupport = getHwComposer().hasDisplayCapability(*displayId, DisplayCapability::BRIGHTNESS);
    return NO_ERROR;
}

status_t SurfaceFlinger::setDisplayBrightness(const sp<IBinder>& displayToken,
                                              const gui::DisplayBrightness& brightness) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    const char* const whence = __func__;
    return ftl::Future(mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
               if (const auto display = getDisplayDeviceLocked(displayToken)) {
                   const bool supportsDisplayBrightnessCommand =
                           getHwComposer().getComposer()->isSupported(
                                   Hwc2::Composer::OptionalFeature::DisplayBrightnessCommand);
                   // If we support applying display brightness as a command, then we also support
                   // dimming SDR layers.
                   if (supportsDisplayBrightnessCommand) {
                       auto compositionDisplay = display->getCompositionDisplay();
                       float currentDimmingRatio =
                               compositionDisplay->editState().sdrWhitePointNits /
                               compositionDisplay->editState().displayBrightnessNits;
                       compositionDisplay->setDisplayBrightness(brightness.sdrWhitePointNits,
                                                                brightness.displayBrightnessNits);
                       FTL_FAKE_GUARD(kMainThreadContext,
                                      display->stageBrightness(brightness.displayBrightness));

                       if (brightness.sdrWhitePointNits / brightness.displayBrightnessNits !=
                           currentDimmingRatio) {
                           scheduleComposite(FrameHint::kNone);
                       } else {
                           scheduleCommit(FrameHint::kNone);
                       }
                       return ftl::yield<status_t>(OK);
                   } else {
                       return getHwComposer()
                               .setDisplayBrightness(display->getPhysicalId(),
                                                     brightness.displayBrightness,
                                                     brightness.displayBrightnessNits,
                                                     Hwc2::Composer::DisplayBrightnessOptions{
                                                             .applyImmediately = true});
                   }

               } else {
                   ALOGE("%s: Invalid display token %p", whence, displayToken.get());
                   return ftl::yield<status_t>(NAME_NOT_FOUND);
               }
           }))
            .then([](ftl::Future<status_t> task) { return task; })
            .get();
}

status_t SurfaceFlinger::addHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                                 const sp<gui::IHdrLayerInfoListener>& listener) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }
    const auto displayId = display->getId();
    sp<HdrLayerInfoReporter>& hdrInfoReporter = mHdrLayerInfoListeners[displayId];
    if (!hdrInfoReporter) {
        hdrInfoReporter = sp<HdrLayerInfoReporter>::make();
    }
    hdrInfoReporter->addListener(listener);


    mAddingHDRLayerInfoListener = true;
    return OK;
}

status_t SurfaceFlinger::removeHdrLayerInfoListener(
        const sp<IBinder>& displayToken, const sp<gui::IHdrLayerInfoListener>& listener) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }
    const auto displayId = display->getId();
    sp<HdrLayerInfoReporter>& hdrInfoReporter = mHdrLayerInfoListeners[displayId];
    if (hdrInfoReporter) {
        hdrInfoReporter->removeListener(listener);
    }
    return OK;
}

status_t SurfaceFlinger::notifyPowerBoost(int32_t boostId) {
    using hardware::power::Boost;
    Boost powerBoost = static_cast<Boost>(boostId);

    if (powerBoost == Boost::INTERACTION) {
        mScheduler->onTouchHint();
    }

    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayDecorationSupport(
        const sp<IBinder>& displayToken,
        std::optional<DisplayDecorationSupport>* outSupport) const {
    if (!displayToken || !outSupport) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto displayId = getPhysicalDisplayIdLocked(displayToken);
    if (!displayId) {
        return NAME_NOT_FOUND;
    }
    getHwComposer().getDisplayDecorationSupport(*displayId, outSupport);
    return NO_ERROR;
}

// ----------------------------------------------------------------------------

sp<IDisplayEventConnection> SurfaceFlinger::createDisplayEventConnection(
        gui::ISurfaceComposer::VsyncSource vsyncSource, EventRegistrationFlags eventRegistration,
        const sp<IBinder>& layerHandle) {
    const auto& handle =
            vsyncSource == gui::ISurfaceComposer::VsyncSource::eVsyncSourceSurfaceFlinger
            ? mSfConnectionHandle
            : mAppConnectionHandle;

    return mScheduler->createDisplayEventConnection(handle, eventRegistration, layerHandle);
}

void SurfaceFlinger::scheduleCommit(FrameHint hint) {
    if (hint == FrameHint::kActive) {
        mScheduler->resetIdleTimer();
    }
    mPowerAdvisor->notifyDisplayUpdateImminentAndCpuReset();
    mScheduler->scheduleFrame();
}

void SurfaceFlinger::scheduleComposite(FrameHint hint) {
    mMustComposite = true;
    scheduleCommit(hint);
}

void SurfaceFlinger::scheduleRepaint() {
    mGeometryDirty = true;
    scheduleComposite(FrameHint::kActive);
}

void SurfaceFlinger::scheduleSample() {
    static_cast<void>(mScheduler->schedule([this] { sample(); }));
}

nsecs_t SurfaceFlinger::getVsyncPeriodFromHWC() const {
    if (const auto display = getDefaultDisplayDeviceLocked()) {
        return display->getVsyncPeriodFromHWC();
    }

    return 0;
}

void SurfaceFlinger::onComposerHalVsync(hal::HWDisplayId hwcDisplayId, int64_t timestamp,
                                        std::optional<hal::VsyncPeriodNanos> vsyncPeriod) {
    ATRACE_NAME(vsyncPeriod
                        ? ftl::Concat(__func__, ' ', hwcDisplayId, ' ', *vsyncPeriod, "ns").c_str()
                        : ftl::Concat(__func__, ' ', hwcDisplayId).c_str());

    Mutex::Autolock lock(mStateLock);
    if (const auto displayIdOpt = getHwComposer().onVsync(hwcDisplayId, timestamp)) {
        if (mScheduler->addResyncSample(*displayIdOpt, timestamp, vsyncPeriod)) {
            // period flushed
            mScheduler->modulateVsync(displayIdOpt, &VsyncModulator::onRefreshRateChangeCompleted);
        }
    }
}

void SurfaceFlinger::onComposerHalHotplug(hal::HWDisplayId hwcDisplayId,
                                          hal::Connection connection) {
    {
        std::lock_guard<std::mutex> lock(mHotplugMutex);
        mPendingHotplugEvents.push_back(HotplugEvent{hwcDisplayId, connection});
    }

    if (mScheduler) {
        mScheduler->scheduleConfigure();
    }
}

void SurfaceFlinger::onComposerHalVsyncPeriodTimingChanged(
        hal::HWDisplayId, const hal::VsyncPeriodChangeTimeline& timeline) {
    Mutex::Autolock lock(mStateLock);
    mScheduler->onNewVsyncPeriodChangeTimeline(timeline);

    if (timeline.refreshRequired) {
        scheduleComposite(FrameHint::kNone);
    }
}

void SurfaceFlinger::onComposerHalSeamlessPossible(hal::HWDisplayId) {
    // TODO(b/142753666): use constraints when calling to setActiveModeWithConstraints and
    // use this callback to know when to retry in case of SEAMLESS_NOT_POSSIBLE.
}

void SurfaceFlinger::onComposerHalRefresh(hal::HWDisplayId) {
    Mutex::Autolock lock(mStateLock);
    scheduleComposite(FrameHint::kNone);
}

void SurfaceFlinger::onComposerHalVsyncIdle(hal::HWDisplayId) {
    ATRACE_CALL();
    mScheduler->forceNextResync();
}

void SurfaceFlinger::onRefreshRateChangedDebug(const RefreshRateChangedDebugData& data) {
    ATRACE_CALL();
    if (const auto displayId = getHwComposer().toPhysicalDisplayId(data.display); displayId) {
        const Fps fps = Fps::fromPeriodNsecs(data.vsyncPeriodNanos);
        ATRACE_FORMAT("%s Fps %d", __func__, fps.getIntValue());
        static_cast<void>(mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
            {
                {
                    const auto display = getDisplayDeviceLocked(*displayId);
                    FTL_FAKE_GUARD(kMainThreadContext,
                                   display->updateRefreshRateOverlayRate(fps,
                                                                         display->getActiveMode()
                                                                                 .fps,
                                                                         /* setByHwc */ true));
                }
            }
        }));
    }
}

void SurfaceFlinger::configure() {
    Mutex::Autolock lock(mStateLock);
    if (configureLocked()) {
        setTransactionFlags(eDisplayTransactionNeeded);
    }
}

bool SurfaceFlinger::updateLayerSnapshotsLegacy(VsyncId vsyncId, frontend::Update& update,
                                                bool transactionsFlushed,
                                                bool& outTransactionsAreEmpty) {
    ATRACE_CALL();
    bool needsTraversal = false;
    if (transactionsFlushed) {
        needsTraversal |= commitMirrorDisplays(vsyncId);
        needsTraversal |= commitCreatedLayers(vsyncId, update.layerCreatedStates);
        needsTraversal |= applyTransactions(update.transactions, vsyncId);
    }
    outTransactionsAreEmpty = !needsTraversal;
    const bool shouldCommit = (getTransactionFlags() & ~eTransactionFlushNeeded) || needsTraversal;
    if (shouldCommit) {
        commitTransactions();
    }

    bool mustComposite = latchBuffers() || shouldCommit;
    updateLayerGeometry();
    return mustComposite;
}

void SurfaceFlinger::updateLayerHistory(const frontend::LayerSnapshot& snapshot) {
    using Changes = frontend::RequestedLayerState::Changes;
    if (snapshot.path.isClone() ||
        !snapshot.changes.any(Changes::FrameRate | Changes::Buffer | Changes::Animation)) {
        return;
    }

    const auto layerProps = scheduler::LayerProps{
            .visible = snapshot.isVisible,
            .bounds = snapshot.geomLayerBounds,
            .transform = snapshot.geomLayerTransform,
            .setFrameRateVote = snapshot.frameRate,
            .frameRateSelectionPriority = snapshot.frameRateSelectionPriority,
    };

    auto it = mLegacyLayers.find(snapshot.sequence);
    LOG_ALWAYS_FATAL_IF(it == mLegacyLayers.end(), "Couldnt find layer object for %s",
                        snapshot.getDebugString().c_str());

    if (snapshot.changes.test(Changes::Animation)) {
        it->second->recordLayerHistoryAnimationTx(layerProps);
    }

    if (snapshot.changes.test(Changes::FrameRate)) {
        it->second->setFrameRateForLayerTree(snapshot.frameRate, layerProps);
    }

    if (snapshot.changes.test(Changes::Buffer)) {
        it->second->recordLayerHistoryBufferUpdate(layerProps);
    }
}

bool SurfaceFlinger::updateLayerSnapshots(VsyncId vsyncId, frontend::Update& update,
                                          bool transactionsFlushed, bool& outTransactionsAreEmpty) {
    using Changes = frontend::RequestedLayerState::Changes;
    ATRACE_CALL();
    {
        mLayerLifecycleManager.addLayers(std::move(update.newLayers));
        mLayerLifecycleManager.applyTransactions(update.transactions);
        mLayerLifecycleManager.onHandlesDestroyed(update.destroyedHandles);
        for (auto& legacyLayer : update.layerCreatedStates) {
            sp<Layer> layer = legacyLayer.layer.promote();
            if (layer) {
                mLegacyLayers[layer->sequence] = layer;
            }
        }
    }
    if (mLayerLifecycleManager.getGlobalChanges().test(Changes::Hierarchy)) {
        ATRACE_NAME("LayerHierarchyBuilder:update");
        mLayerHierarchyBuilder.update(mLayerLifecycleManager.getLayers(),
                                      mLayerLifecycleManager.getDestroyedLayers());
    }

    bool mustComposite = false;
    mustComposite |= applyAndCommitDisplayTransactionStates(update.transactions);

    {
        ATRACE_NAME("LayerSnapshotBuilder:update");
        frontend::LayerSnapshotBuilder::Args
                args{.root = mLayerHierarchyBuilder.getHierarchy(),
                     .layerLifecycleManager = mLayerLifecycleManager,
                     .displays = mFrontEndDisplayInfos,
                     .displayChanges = mFrontEndDisplayInfosChanged,
                     .globalShadowSettings = mDrawingState.globalShadowSettings,
                     .supportsBlur = mSupportsBlur,
                     .forceFullDamage = mForceFullDamage,
                     .supportedLayerGenericMetadata =
                             getHwComposer().getSupportedLayerGenericMetadata(),
                     .genericLayerMetadataKeyMap = getGenericLayerMetadataKeyMap()};
        mLayerSnapshotBuilder.update(args);
    }

    if (mLayerLifecycleManager.getGlobalChanges().any(Changes::Geometry | Changes::Input |
                                                      Changes::Hierarchy | Changes::Visibility)) {
        mUpdateInputInfo = true;
    }
    if (mLayerLifecycleManager.getGlobalChanges().any(Changes::VisibleRegion | Changes::Hierarchy |
                                                      Changes::Visibility)) {
        mVisibleRegionsDirty = true;
    }
    outTransactionsAreEmpty = mLayerLifecycleManager.getGlobalChanges().get() == 0;
    mustComposite |= mLayerLifecycleManager.getGlobalChanges().get() != 0;

    bool newDataLatched = false;
    if (!mLegacyFrontEndEnabled) {
        ATRACE_NAME("DisplayCallbackAndStatsUpdates");
        applyTransactions(update.transactions, vsyncId);
        const nsecs_t latchTime = systemTime();
        bool unused = false;

        for (auto& layer : mLayerLifecycleManager.getLayers()) {
            if (layer->changes.test(frontend::RequestedLayerState::Changes::Created) &&
                layer->bgColorLayer) {
                sp<Layer> bgColorLayer = getFactory().createEffectLayer(
                        LayerCreationArgs(this, nullptr, layer->name,
                                          ISurfaceComposerClient::eFXSurfaceEffect, LayerMetadata(),
                                          std::make_optional(layer->id), true));
                mLegacyLayers[bgColorLayer->sequence] = bgColorLayer;
            }
            const bool willReleaseBufferOnLatch = layer->willReleaseBufferOnLatch();
            if (!layer->hasReadyFrame() && !willReleaseBufferOnLatch) continue;

            auto it = mLegacyLayers.find(layer->id);
            LOG_ALWAYS_FATAL_IF(it == mLegacyLayers.end(), "Couldnt find layer object for %s",
                                layer->getDebugString().c_str());
            const bool bgColorOnly =
                    !layer->externalTexture && (layer->bgColorLayerId != UNASSIGNED_LAYER_ID);
            if (willReleaseBufferOnLatch) {
                mLayersWithBuffersRemoved.emplace(it->second);
            }
            it->second->latchBufferImpl(unused, latchTime, bgColorOnly);
            mLayersWithQueuedFrames.emplace(it->second);
        }

        for (auto& snapshot : mLayerSnapshotBuilder.getSnapshots()) {
            updateLayerHistory(*snapshot);
            if (!snapshot->hasReadyFrame) continue;
            newDataLatched = true;
            if (!snapshot->isVisible) break;

            Region visibleReg;
            visibleReg.set(snapshot->transformedBoundsWithoutTransparentRegion);
            invalidateLayerStack(snapshot->outputFilter, visibleReg);
        }

        for (auto& destroyedLayer : mLayerLifecycleManager.getDestroyedLayers()) {
            mLegacyLayers.erase(destroyedLayer->id);
        }

        {
            ATRACE_NAME("LLM:commitChanges");
            mLayerLifecycleManager.commitChanges();
        }

        commitTransactions();

        // enter boot animation on first buffer latch
        if (CC_UNLIKELY(mBootStage == BootStage::BOOTLOADER && newDataLatched)) {
            ALOGI("Enter boot animation");
            mBootStage = BootStage::BOOTANIMATION;
        }
    }
    mustComposite |= (getTransactionFlags() & ~eTransactionFlushNeeded) || newDataLatched;
    return mustComposite;
}

bool SurfaceFlinger::commit(PhysicalDisplayId pacesetterId,
                            const scheduler::FrameTargets& frameTargets) {
    const scheduler::FrameTarget& pacesetterFrameTarget = *frameTargets.get(pacesetterId)->get();

    const VsyncId vsyncId = pacesetterFrameTarget.vsyncId();
    ATRACE_NAME(ftl::Concat(__func__, ' ', ftl::to_underlying(vsyncId)).c_str());

    if (pacesetterFrameTarget.didMissFrame()) {
        mTimeStats->incrementMissedFrames();
    }

    if (mTracingEnabledChanged) {
        mLayerTracingEnabled = mLayerTracing.isEnabled();
        mTracingEnabledChanged = false;
    }

    // If a mode set is pending and the fence hasn't fired yet, wait for the next commit.
    if (std::any_of(frameTargets.begin(), frameTargets.end(),
                    [this](const auto& pair) FTL_FAKE_GUARD(mStateLock)
                            FTL_FAKE_GUARD(kMainThreadContext) {
                                if (!pair.second->isFramePending()) return false;

                                if (const auto display = getDisplayDeviceLocked(pair.first)) {
                                    return display->isModeSetPending();
                                }

                                return false;
                            })) {
        mScheduler->scheduleFrame();
        return false;
    }

    {
        Mutex::Autolock lock(mStateLock);

        for (const auto [id, target] : frameTargets) {
            // TODO(b/241285876): This is `nullptr` when the DisplayDevice is about to be removed in
            // this commit, since the PhysicalDisplay has already been removed. Rather than checking
            // for `nullptr` below, change Scheduler::onFrameSignal to filter out the FrameTarget of
            // the removed display.
            const auto display = getDisplayDeviceLocked(id);

            if (display && display->isModeSetPending()) {
                finalizeDisplayModeChange(*display);
            }
        }
    }

    if (pacesetterFrameTarget.isFramePending()) {
        if (mBackpressureGpuComposition || pacesetterFrameTarget.didMissHwcFrame()) {
            scheduleCommit(FrameHint::kNone);
            return false;
        }
    }

    const Period vsyncPeriod = mScheduler->getVsyncSchedule()->period();

    // Save this once per commit + composite to ensure consistency
    // TODO (b/240619471): consider removing active display check once AOD is fixed
    const auto activeDisplay = FTL_FAKE_GUARD(mStateLock, getDisplayDeviceLocked(mActiveDisplayId));
    mPowerHintSessionEnabled = mPowerAdvisor->usePowerHintSession() && activeDisplay &&
            activeDisplay->getPowerMode() == hal::PowerMode::ON;
    if (mPowerHintSessionEnabled) {
        mPowerAdvisor->setCommitStart(pacesetterFrameTarget.frameBeginTime());
        mPowerAdvisor->setExpectedPresentTime(pacesetterFrameTarget.expectedPresentTime());

        // Frame delay is how long we should have minus how long we actually have.
        const Duration idealSfWorkDuration =
                mScheduler->vsyncModulator().getVsyncConfig().sfWorkDuration;
        const Duration frameDelay =
                idealSfWorkDuration - pacesetterFrameTarget.expectedFrameDuration();

        mPowerAdvisor->setFrameDelay(frameDelay);
        mPowerAdvisor->setTotalFrameTargetWorkDuration(idealSfWorkDuration);

        const auto& display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked()).get();
        const Period idealVsyncPeriod = display->getActiveMode().fps.getPeriod();
        mPowerAdvisor->updateTargetWorkDuration(idealVsyncPeriod);
    }

    if (mRefreshRateOverlaySpinner) {
        Mutex::Autolock lock(mStateLock);
        if (const auto display = getDefaultDisplayDeviceLocked()) {
            display->animateRefreshRateOverlay();
        }
    }

    // Composite if transactions were committed, or if requested by HWC.
    bool mustComposite = mMustComposite.exchange(false);
    {
        mFrameTimeline->setSfWakeUp(ftl::to_underlying(vsyncId),
                                    pacesetterFrameTarget.frameBeginTime().ns(),
                                    Fps::fromPeriodNsecs(vsyncPeriod.ns()));

        const bool flushTransactions = clearTransactionFlags(eTransactionFlushNeeded);
        frontend::Update updates;
        if (flushTransactions) {
            updates = flushLifecycleUpdates();
            if (mTransactionTracing) {
                mTransactionTracing
                        ->addCommittedTransactions(ftl::to_underlying(vsyncId),
                                                   pacesetterFrameTarget.frameBeginTime().ns(),
                                                   updates, mFrontEndDisplayInfos,
                                                   mFrontEndDisplayInfosChanged);
            }
        }
        bool transactionsAreEmpty;
        if (mLegacyFrontEndEnabled) {
            mustComposite |= updateLayerSnapshotsLegacy(vsyncId, updates, flushTransactions,
                                                        transactionsAreEmpty);
        }
        if (mLayerLifecycleManagerEnabled) {
            mustComposite |=
                    updateLayerSnapshots(vsyncId, updates, flushTransactions, transactionsAreEmpty);
        }

        if (transactionFlushNeeded()) {
            setTransactionFlags(eTransactionFlushNeeded);
        }

        // This has to be called after latchBuffers because we want to include the layers that have
        // been latched in the commit callback
        if (transactionsAreEmpty) {
            // Invoke empty transaction callbacks early.
            mTransactionCallbackInvoker.sendCallbacks(false /* onCommitOnly */);
        } else {
            // Invoke OnCommit callbacks.
            mTransactionCallbackInvoker.sendCallbacks(true /* onCommitOnly */);
        }
    }

    // Layers need to get updated (in the previous line) before we can use them for
    // choosing the refresh rate.
    // Hold mStateLock as chooseRefreshRateForContent promotes wp<Layer> to sp<Layer>
    // and may eventually call to ~Layer() if it holds the last reference
    {
        Mutex::Autolock lock(mStateLock);
        mScheduler->chooseRefreshRateForContent();
        initiateDisplayModeChanges();
    }

    updateCursorAsync();
    updateInputFlinger(vsyncId, pacesetterFrameTarget.frameBeginTime());

    if (mLayerTracingEnabled && !mLayerTracing.flagIsSet(LayerTracing::TRACE_COMPOSITION)) {
        // This will block and tracing should only be enabled for debugging.
        addToLayerTracing(mVisibleRegionsDirty, pacesetterFrameTarget.frameBeginTime(), vsyncId);
    }
    mLastCommittedVsyncId = vsyncId;

    persistDisplayBrightness(mustComposite);

    return mustComposite && CC_LIKELY(mBootStage != BootStage::BOOTLOADER);
}

CompositeResultsPerDisplay SurfaceFlinger::composite(
        PhysicalDisplayId pacesetterId, const scheduler::FrameTargeters& frameTargeters) {
    const scheduler::FrameTarget& pacesetterTarget =
            frameTargeters.get(pacesetterId)->get()->target();

    const VsyncId vsyncId = pacesetterTarget.vsyncId();
    ATRACE_NAME(ftl::Concat(__func__, ' ', ftl::to_underlying(vsyncId)).c_str());

    compositionengine::CompositionRefreshArgs refreshArgs;
    refreshArgs.powerCallback = this;
    const auto& displays = FTL_FAKE_GUARD(mStateLock, mDisplays);
    refreshArgs.outputs.reserve(displays.size());

    // Add outputs for physical displays.
    for (const auto& [id, targeter] : frameTargeters) {
        ftl::FakeGuard guard(mStateLock);

        if (const auto display = getCompositionDisplayLocked(id)) {
            refreshArgs.outputs.push_back(display);
        }
    }

    std::vector<DisplayId> displayIds;
    for (const auto& [_, display] : displays) {
        displayIds.push_back(display->getId());
        display->tracePowerMode();

        // Add outputs for virtual displays.
        if (display->isVirtual()) {
            const Fps refreshRate = display->getAdjustedRefreshRate();

            if (!refreshRate.isValid() ||
                mScheduler->isVsyncInPhase(pacesetterTarget.frameBeginTime(), refreshRate)) {
                refreshArgs.outputs.push_back(display->getCompositionDisplay());
            }
        }
    }
    mPowerAdvisor->setDisplays(displayIds);

    const bool updateTaskMetadata = mCompositionEngine->getFeatureFlags().test(
            compositionengine::Feature::kSnapshotLayerMetadata);
    if (updateTaskMetadata && (mVisibleRegionsDirty || mLayerMetadataSnapshotNeeded)) {
        updateLayerMetadataSnapshot();
        mLayerMetadataSnapshotNeeded = false;
    }

    if (DOES_CONTAIN_BORDER) {
        refreshArgs.borderInfoList.clear();
        mDrawingState.traverse([&refreshArgs](Layer* layer) {
            if (layer->isBorderEnabled()) {
                compositionengine::BorderRenderInfo info;
                info.width = layer->getBorderWidth();
                info.color = layer->getBorderColor();
                layer->traverse(LayerVector::StateSet::Drawing, [&info](Layer* ilayer) {
                    info.layerIds.push_back(ilayer->getSequence());
                });
                refreshArgs.borderInfoList.emplace_back(std::move(info));
            }
        });
    }

    refreshArgs.bufferIdsToUncache = std::move(mBufferIdsToUncache);

    refreshArgs.layersWithQueuedFrames.reserve(mLayersWithQueuedFrames.size());
    for (auto layer : mLayersWithQueuedFrames) {
        if (auto layerFE = layer->getCompositionEngineLayerFE())
            refreshArgs.layersWithQueuedFrames.push_back(layerFE);
    }

    refreshArgs.outputColorSetting = useColorManagement
            ? mDisplayColorSetting
            : compositionengine::OutputColorSetting::kUnmanaged;
    refreshArgs.colorSpaceAgnosticDataspace = mColorSpaceAgnosticDataspace;
    refreshArgs.forceOutputColorMode = mForceColorMode;

    refreshArgs.updatingOutputGeometryThisFrame = mVisibleRegionsDirty;
    refreshArgs.updatingGeometryThisFrame = mGeometryDirty.exchange(false) || mVisibleRegionsDirty;
    refreshArgs.internalDisplayRotationFlags = getActiveDisplayRotationFlags();

    if (CC_UNLIKELY(mDrawingState.colorMatrixChanged)) {
        refreshArgs.colorTransformMatrix = mDrawingState.colorMatrix;
        mDrawingState.colorMatrixChanged = false;
    }

    refreshArgs.devOptForceClientComposition = mDebugDisableHWC;

    if (mDebugFlashDelay != 0) {
        refreshArgs.devOptForceClientComposition = true;
        refreshArgs.devOptFlashDirtyRegionsDelay = std::chrono::milliseconds(mDebugFlashDelay);
    }

    const Period vsyncPeriod = mScheduler->getVsyncSchedule()->period();

    if (!getHwComposer().getComposer()->isSupported(
                Hwc2::Composer::OptionalFeature::ExpectedPresentTime) &&
        pacesetterTarget.wouldPresentEarly(vsyncPeriod)) {
        const auto hwcMinWorkDuration = mVsyncConfiguration->getCurrentConfigs().hwcMinWorkDuration;

        // TODO(b/255601557): Calculate and pass per-display values for each FrameTarget.
        refreshArgs.earliestPresentTime =
                pacesetterTarget.previousFrameVsyncTime(vsyncPeriod) - hwcMinWorkDuration;
    }

    refreshArgs.scheduledFrameTime = mScheduler->getScheduledFrameTime();
    refreshArgs.expectedPresentTime = pacesetterTarget.expectedPresentTime().ns();
    refreshArgs.hasTrustedPresentationListener = mNumTrustedPresentationListeners > 0;

    // Store the present time just before calling to the composition engine so we could notify
    // the scheduler.
    const auto presentTime = systemTime();

    constexpr bool kCursorOnly = false;
    const auto layers = moveSnapshotsToCompositionArgs(refreshArgs, kCursorOnly);

    mCompositionEngine->present(refreshArgs);
    moveSnapshotsFromCompositionArgs(refreshArgs, layers);

    for (auto [layer, layerFE] : layers) {
        CompositionResult compositionResult{layerFE->stealCompositionResult()};
        layer->onPreComposition(compositionResult.refreshStartTime);
        for (auto& [releaseFence, layerStack] : compositionResult.releaseFences) {
            Layer* clonedFrom = layer->getClonedFrom().get();
            auto owningLayer = clonedFrom ? clonedFrom : layer;
            owningLayer->onLayerDisplayed(std::move(releaseFence), layerStack);
        }
        if (compositionResult.lastClientCompositionFence) {
            layer->setWasClientComposed(compositionResult.lastClientCompositionFence);
        }
    }

    mTimeStats->recordFrameDuration(pacesetterTarget.frameBeginTime().ns(), systemTime());

    // Send a power hint after presentation is finished.
    if (mPowerHintSessionEnabled) {
        // Now that the current frame has been presented above, PowerAdvisor needs the present time
        // of the previous frame (whose fence is signaled by now) to determine how long the HWC had
        // waited on that fence to retire before presenting.
        const auto& previousPresentFence = pacesetterTarget.presentFenceForPreviousFrame();

        mPowerAdvisor->setSfPresentTiming(TimePoint::fromNs(previousPresentFence->getSignalTime()),
                                          TimePoint::now());
        mPowerAdvisor->reportActualWorkDuration();
    }

    if (mScheduler->onPostComposition(presentTime)) {
        scheduleComposite(FrameHint::kNone);
    }

    postComposition(pacesetterId, frameTargeters, presentTime);

    const bool hadGpuComposited =
            multiDisplayUnion(mCompositionCoverage).test(CompositionCoverage::Gpu);
    mCompositionCoverage.clear();

    TimeStats::ClientCompositionRecord clientCompositionRecord;

    for (const auto& [_, display] : displays) {
        const auto& state = display->getCompositionDisplay()->getState();
        CompositionCoverageFlags& flags =
                mCompositionCoverage.try_emplace(display->getId()).first->second;

        if (state.usesDeviceComposition) {
            flags |= CompositionCoverage::Hwc;
        }

        if (state.reusedClientComposition) {
            flags |= CompositionCoverage::GpuReuse;
        } else if (state.usesClientComposition) {
            flags |= CompositionCoverage::Gpu;
        }

        clientCompositionRecord.predicted |=
                (state.strategyPrediction != CompositionStrategyPredictionState::DISABLED);
        clientCompositionRecord.predictionSucceeded |=
                (state.strategyPrediction == CompositionStrategyPredictionState::SUCCESS);
    }

    const auto coverage = multiDisplayUnion(mCompositionCoverage);
    const bool hasGpuComposited = coverage.test(CompositionCoverage::Gpu);

    clientCompositionRecord.hadClientComposition = hasGpuComposited;
    clientCompositionRecord.reused = coverage.test(CompositionCoverage::GpuReuse);
    clientCompositionRecord.changed = hadGpuComposited != hasGpuComposited;

    mTimeStats->pushCompositionStrategyState(clientCompositionRecord);

    using namespace ftl::flag_operators;

    // TODO(b/160583065): Enable skip validation when SF caches all client composition layers.
    const bool hasGpuUseOrReuse =
            coverage.any(CompositionCoverage::Gpu | CompositionCoverage::GpuReuse);
    mScheduler->modulateVsync({}, &VsyncModulator::onDisplayRefresh, hasGpuUseOrReuse);

    mLayersWithQueuedFrames.clear();
    if (mLayerTracingEnabled && mLayerTracing.flagIsSet(LayerTracing::TRACE_COMPOSITION)) {
        // This will block and should only be used for debugging.
        addToLayerTracing(mVisibleRegionsDirty, pacesetterTarget.frameBeginTime(), vsyncId);
    }

    if (mVisibleRegionsDirty) mHdrLayerInfoChanged = true;
    mVisibleRegionsDirty = false;

    if (mCompositionEngine->needsAnotherUpdate()) {
        scheduleCommit(FrameHint::kNone);
    }

    if (mPowerHintSessionEnabled) {
        mPowerAdvisor->setCompositeEnd(TimePoint::now());
    }

    CompositeResultsPerDisplay resultsPerDisplay;

    // Filter out virtual displays.
    for (const auto& [id, coverage] : mCompositionCoverage) {
        if (const auto idOpt = PhysicalDisplayId::tryCast(id)) {
            resultsPerDisplay.try_emplace(*idOpt, CompositeResult{coverage});
        }
    }

    return resultsPerDisplay;
}

void SurfaceFlinger::updateLayerGeometry() {
    ATRACE_CALL();

    if (mVisibleRegionsDirty) {
        computeLayerBounds();
    }

    for (auto& layer : mLayersPendingRefresh) {
        Region visibleReg;
        visibleReg.set(layer->getScreenBounds());
        invalidateLayerStack(layer->getOutputFilter(), visibleReg);
    }
    mLayersPendingRefresh.clear();
}

bool SurfaceFlinger::isHdrLayer(const frontend::LayerSnapshot& snapshot) const {
    // Even though the camera layer may be using an HDR transfer function or otherwise be "HDR"
    // the device may need to avoid boosting the brightness as a result of these layers to
    // reduce power consumption during camera recording
    if (mIgnoreHdrCameraLayers) {
        if (snapshot.externalTexture &&
            (snapshot.externalTexture->getUsage() & GRALLOC_USAGE_HW_CAMERA_WRITE) != 0) {
            return false;
        }
    }
    // RANGE_EXTENDED layer may identify themselves as being "HDR"
    // via a desired hdr/sdr ratio
    auto pixelFormat = snapshot.buffer
            ? std::make_optional(static_cast<ui::PixelFormat>(snapshot.buffer->getPixelFormat()))
            : std::nullopt;

    if (getHdrRenderType(snapshot.dataspace, pixelFormat, snapshot.desiredHdrSdrRatio) !=
        HdrRenderType::SDR) {
        return true;
    }
    // If the layer is not allowed to be dimmed, treat it as HDR. WindowManager may disable
    // dimming in order to keep animations invoking SDR screenshots of HDR layers seamless.
    // Treat such tagged layers as HDR so that DisplayManagerService does not try to change
    // the screen brightness
    if (!snapshot.dimmingEnabled) {
        return true;
    }
    return false;
}

ui::Rotation SurfaceFlinger::getPhysicalDisplayOrientation(DisplayId displayId,
                                                           bool isPrimary) const {
    const auto id = PhysicalDisplayId::tryCast(displayId);
    if (!id) {
        return ui::ROTATION_0;
    }
    if (!mIgnoreHwcPhysicalDisplayOrientation &&
        getHwComposer().getComposer()->isSupported(
                Hwc2::Composer::OptionalFeature::PhysicalDisplayOrientation)) {
        switch (getHwComposer().getPhysicalDisplayOrientation(*id)) {
            case Hwc2::AidlTransform::ROT_90:
                return ui::ROTATION_90;
            case Hwc2::AidlTransform::ROT_180:
                return ui::ROTATION_180;
            case Hwc2::AidlTransform::ROT_270:
                return ui::ROTATION_270;
            default:
                return ui::ROTATION_0;
        }
    }

    if (isPrimary) {
        using Values = SurfaceFlingerProperties::primary_display_orientation_values;
        switch (primary_display_orientation(Values::ORIENTATION_0)) {
            case Values::ORIENTATION_90:
                return ui::ROTATION_90;
            case Values::ORIENTATION_180:
                return ui::ROTATION_180;
            case Values::ORIENTATION_270:
                return ui::ROTATION_270;
            default:
                break;
        }
    }
    return ui::ROTATION_0;
}

void SurfaceFlinger::postComposition(PhysicalDisplayId pacesetterId,
                                     const scheduler::FrameTargeters& frameTargeters,
                                     nsecs_t presentStartTime) {
    ATRACE_CALL();
    ALOGV(__func__);

    ui::PhysicalDisplayMap<PhysicalDisplayId, std::shared_ptr<FenceTime>> presentFences;
    ui::PhysicalDisplayMap<PhysicalDisplayId, const sp<Fence>> gpuCompositionDoneFences;

    for (const auto& [id, targeter] : frameTargeters) {
        auto presentFence = getHwComposer().getPresentFence(id);

        if (id == pacesetterId) {
            mTransactionCallbackInvoker.addPresentFence(presentFence);
        }

        if (auto fenceTime = targeter->setPresentFence(std::move(presentFence));
            fenceTime->isValid()) {
            presentFences.try_emplace(id, std::move(fenceTime));
        }

        ftl::FakeGuard guard(mStateLock);
        if (const auto display = getCompositionDisplayLocked(id);
            display && display->getState().usesClientComposition) {
            gpuCompositionDoneFences
                    .try_emplace(id, display->getRenderSurface()->getClientTargetAcquireFence());
        }
    }

    const auto pacesetterDisplay = FTL_FAKE_GUARD(mStateLock, getDisplayDeviceLocked(pacesetterId));

    std::shared_ptr<FenceTime> pacesetterPresentFenceTime =
            presentFences.get(pacesetterId)
                    .transform([](const FenceTimePtr& ptr) { return ptr; })
                    .value_or(FenceTime::NO_FENCE);

    std::shared_ptr<FenceTime> pacesetterGpuCompositionDoneFenceTime =
            gpuCompositionDoneFences.get(pacesetterId)
                    .transform([](sp<Fence> fence) {
                        return std::make_shared<FenceTime>(std::move(fence));
                    })
                    .value_or(FenceTime::NO_FENCE);

    const TimePoint presentTime = TimePoint::now();

    // Set presentation information before calling Layer::releasePendingBuffer, such that jank
    // information from previous' frame classification is already available when sending jank info
    // to clients, so they get jank classification as early as possible.
    mFrameTimeline->setSfPresent(presentTime.ns(), pacesetterPresentFenceTime,
                                 pacesetterGpuCompositionDoneFenceTime);

    // We use the CompositionEngine::getLastFrameRefreshTimestamp() which might
    // be sampled a little later than when we started doing work for this frame,
    // but that should be okay since CompositorTiming has snapping logic.
    const TimePoint compositeTime =
            TimePoint::fromNs(mCompositionEngine->getLastFrameRefreshTimestamp());
    const Duration presentLatency =
            getHwComposer().hasCapability(Capability::PRESENT_FENCE_IS_NOT_RELIABLE)
            ? Duration::zero()
            : mPresentLatencyTracker.trackPendingFrame(compositeTime, pacesetterPresentFenceTime);

    const auto schedule = mScheduler->getVsyncSchedule();
    const TimePoint vsyncDeadline = schedule->vsyncDeadlineAfter(presentTime);
    const Period vsyncPeriod = schedule->period();
    const nsecs_t vsyncPhase = mVsyncConfiguration->getCurrentConfigs().late.sfOffset;

    const CompositorTiming compositorTiming(vsyncDeadline.ns(), vsyncPeriod.ns(), vsyncPhase,
                                            presentLatency.ns());

    ui::DisplayMap<ui::LayerStack, const DisplayDevice*> layerStackToDisplay;
    {
        if (!mLayersWithBuffersRemoved.empty() || mNumTrustedPresentationListeners > 0) {
            Mutex::Autolock lock(mStateLock);
            for (const auto& [token, display] : mDisplays) {
                layerStackToDisplay.emplace_or_replace(display->getLayerStack(), display.get());
            }
        }
    }

    for (auto layer : mLayersWithBuffersRemoved) {
        std::vector<ui::LayerStack> previouslyPresentedLayerStacks =
                std::move(layer->mPreviouslyPresentedLayerStacks);
        layer->mPreviouslyPresentedLayerStacks.clear();
        for (auto layerStack : previouslyPresentedLayerStacks) {
            auto optDisplay = layerStackToDisplay.get(layerStack);
            if (optDisplay && !optDisplay->get()->isVirtual()) {
                auto fence = getHwComposer().getPresentFence(optDisplay->get()->getPhysicalId());
                layer->onLayerDisplayed(ftl::yield<FenceResult>(fence).share(),
                                        ui::INVALID_LAYER_STACK);
            }
        }
        layer->releasePendingBuffer(presentTime.ns());
    }
    mLayersWithBuffersRemoved.clear();

    for (const auto& layer: mLayersWithQueuedFrames) {
        layer->onPostComposition(pacesetterDisplay.get(), pacesetterGpuCompositionDoneFenceTime,
                                 pacesetterPresentFenceTime, compositorTiming);
        layer->releasePendingBuffer(presentTime.ns());
    }

    std::vector<std::pair<std::shared_ptr<compositionengine::Display>, sp<HdrLayerInfoReporter>>>
            hdrInfoListeners;
    bool haveNewListeners = false;
    {
        Mutex::Autolock lock(mStateLock);
        if (mFpsReporter) {
            mFpsReporter->dispatchLayerFps();
        }

        if (mTunnelModeEnabledReporter) {
            mTunnelModeEnabledReporter->updateTunnelModeStatus();
        }
        hdrInfoListeners.reserve(mHdrLayerInfoListeners.size());
        for (const auto& [displayId, reporter] : mHdrLayerInfoListeners) {
            if (reporter && reporter->hasListeners()) {
                if (const auto display = getDisplayDeviceLocked(displayId)) {
                    hdrInfoListeners.emplace_back(display->getCompositionDisplay(), reporter);
                }
            }
        }
        haveNewListeners = mAddingHDRLayerInfoListener; // grab this with state lock
        mAddingHDRLayerInfoListener = false;
    }

    if (haveNewListeners || mHdrLayerInfoChanged) {
        for (auto& [compositionDisplay, listener] : hdrInfoListeners) {
            HdrLayerInfoReporter::HdrLayerInfo info;
            int32_t maxArea = 0;
            mDrawingState.traverse([&, compositionDisplay = compositionDisplay](Layer* layer) {
                const auto layerFe = layer->getCompositionEngineLayerFE();
                const frontend::LayerSnapshot& snapshot = *layer->getLayerSnapshot();
                if (snapshot.isVisible &&
                    compositionDisplay->includesLayer(snapshot.outputFilter)) {
                    if (isHdrLayer(snapshot)) {
                        const auto* outputLayer =
                            compositionDisplay->getOutputLayerForLayer(layerFe);
                        if (outputLayer) {
                            const float desiredHdrSdrRatio = snapshot.desiredHdrSdrRatio <= 1.f
                                    ? std::numeric_limits<float>::infinity()
                                    : snapshot.desiredHdrSdrRatio;
                            info.mergeDesiredRatio(desiredHdrSdrRatio);
                            info.numberOfHdrLayers++;
                            const auto displayFrame = outputLayer->getState().displayFrame;
                            const int32_t area = displayFrame.width() * displayFrame.height();
                            if (area > maxArea) {
                                maxArea = area;
                                info.maxW = displayFrame.width();
                                info.maxH = displayFrame.height();
                            }
                        }
                    }
                }
            });
            listener->dispatchHdrLayerInfo(info);
        }
    }

    mHdrLayerInfoChanged = false;

    mTransactionCallbackInvoker.sendCallbacks(false /* onCommitOnly */);
    mTransactionCallbackInvoker.clearCompletedTransactions();

    mTimeStats->incrementTotalFrames();
    mTimeStats->setPresentFenceGlobal(pacesetterPresentFenceTime);

    for (auto&& [id, presentFence] : presentFences) {
        ftl::FakeGuard guard(mStateLock);
        const bool isInternalDisplay =
                mPhysicalDisplays.get(id).transform(&PhysicalDisplay::isInternal).value_or(false);

        if (isInternalDisplay) {
            mScheduler->addPresentFence(id, std::move(presentFence));
        }
    }

    const bool hasPacesetterDisplay =
            pacesetterDisplay && getHwComposer().isConnected(pacesetterId);

    if (!hasSyncFramework) {
        if (hasPacesetterDisplay && pacesetterDisplay->isPoweredOn()) {
            mScheduler->enableHardwareVsync(pacesetterId);
        }
    }

    const size_t sfConnections = mScheduler->getEventThreadConnectionCount(mSfConnectionHandle);
    const size_t appConnections = mScheduler->getEventThreadConnectionCount(mAppConnectionHandle);
    mTimeStats->recordDisplayEventConnectionCount(sfConnections + appConnections);

    if (hasPacesetterDisplay && !pacesetterDisplay->isPoweredOn()) {
        getRenderEngine().cleanupPostRender();
        return;
    }

    // Cleanup any outstanding resources due to rendering a prior frame.
    getRenderEngine().cleanupPostRender();

    {
        std::lock_guard lock(mTexturePoolMutex);
        if (mTexturePool.size() < mTexturePoolSize) {
            const size_t refillCount = mTexturePoolSize - mTexturePool.size();
            const size_t offset = mTexturePool.size();
            mTexturePool.resize(mTexturePoolSize);
            getRenderEngine().genTextures(refillCount, mTexturePool.data() + offset);
            ATRACE_INT("TexturePoolSize", mTexturePool.size());
        } else if (mTexturePool.size() > mTexturePoolSize) {
            const size_t deleteCount = mTexturePool.size() - mTexturePoolSize;
            const size_t offset = mTexturePoolSize;
            getRenderEngine().deleteTextures(deleteCount, mTexturePool.data() + offset);
            mTexturePool.resize(mTexturePoolSize);
            ATRACE_INT("TexturePoolSize", mTexturePool.size());
        }
    }

    if (mNumTrustedPresentationListeners > 0) {
        // We avoid any reverse traversal upwards so this shouldn't be too expensive
        traverseLegacyLayers([&](Layer* layer) {
            if (!layer->hasTrustedPresentationListener()) {
                return;
            }
            const frontend::LayerSnapshot* snapshot = mLayerLifecycleManagerEnabled
                    ? mLayerSnapshotBuilder.getSnapshot(layer->sequence)
                    : layer->getLayerSnapshot();
            std::optional<const DisplayDevice*> displayOpt = std::nullopt;
            if (snapshot) {
                displayOpt = layerStackToDisplay.get(snapshot->outputFilter.layerStack);
            }
            const DisplayDevice* display = displayOpt.value_or(nullptr);
            layer->updateTrustedPresentationState(display, snapshot,
                                                  nanoseconds_to_milliseconds(presentStartTime),
                                                  false);
        });
    }

    // Even though ATRACE_INT64 already checks if tracing is enabled, it doesn't prevent the
    // side-effect of getTotalSize(), so we check that again here
    if (ATRACE_ENABLED()) {
        // getTotalSize returns the total number of buffers that were allocated by SurfaceFlinger
        ATRACE_INT64("Total Buffer Size", GraphicBufferAllocator::get().getTotalSize());
    }

    logFrameStats(presentTime);
}

FloatRect SurfaceFlinger::getMaxDisplayBounds() {
    const ui::Size maxSize = [this] {
        ftl::FakeGuard guard(mStateLock);

        // The LayerTraceGenerator tool runs without displays.
        if (mDisplays.empty()) return ui::Size{5000, 5000};

        return std::accumulate(mDisplays.begin(), mDisplays.end(), ui::kEmptySize,
                               [](ui::Size size, const auto& pair) -> ui::Size {
                                   const auto& display = pair.second;
                                   return {std::max(size.getWidth(), display->getWidth()),
                                           std::max(size.getHeight(), display->getHeight())};
                               });
    }();

    // Ignore display bounds for now since they will be computed later. Use a large Rect bound
    // to ensure it's bigger than an actual display will be.
    const float xMax = maxSize.getWidth() * 10.f;
    const float yMax = maxSize.getHeight() * 10.f;

    return {-xMax, -yMax, xMax, yMax};
}

void SurfaceFlinger::computeLayerBounds() {
    const FloatRect maxBounds = getMaxDisplayBounds();
    for (const auto& layer : mDrawingState.layersSortedByZ) {
        layer->computeBounds(maxBounds, ui::Transform(), 0.f /* shadowRadius */);
    }
}

void SurfaceFlinger::commitTransactions() {
    ATRACE_CALL();

    // Keep a copy of the drawing state (that is going to be overwritten
    // by commitTransactionsLocked) outside of mStateLock so that the side
    // effects of the State assignment don't happen with mStateLock held,
    // which can cause deadlocks.
    State drawingState(mDrawingState);

    Mutex::Autolock lock(mStateLock);
    mDebugInTransaction = systemTime();

    // Here we're guaranteed that some transaction flags are set
    // so we can call commitTransactionsLocked unconditionally.
    // We clear the flags with mStateLock held to guarantee that
    // mCurrentState won't change until the transaction is committed.
    mScheduler->modulateVsync({}, &VsyncModulator::onTransactionCommit);
    commitTransactionsLocked(clearTransactionFlags(eTransactionMask));

    mDebugInTransaction = 0;
}

std::pair<DisplayModes, DisplayModePtr> SurfaceFlinger::loadDisplayModes(
        PhysicalDisplayId displayId) const {
    std::vector<HWComposer::HWCDisplayMode> hwcModes;
    std::optional<hal::HWDisplayId> activeModeHwcId;

    int attempt = 0;
    constexpr int kMaxAttempts = 3;
    do {
        hwcModes = getHwComposer().getModes(displayId);
        activeModeHwcId = getHwComposer().getActiveMode(displayId);

        const auto isActiveMode = [activeModeHwcId](const HWComposer::HWCDisplayMode& mode) {
            return mode.hwcId == activeModeHwcId;
        };

        if (std::any_of(hwcModes.begin(), hwcModes.end(), isActiveMode)) {
            break;
        }
    } while (++attempt < kMaxAttempts);

    if (attempt == kMaxAttempts) {
        const std::string activeMode =
                activeModeHwcId ? std::to_string(*activeModeHwcId) : "unknown"s;
        ALOGE("HWC failed to report an active mode that is supported: activeModeHwcId=%s, "
              "hwcModes={%s}",
              activeMode.c_str(), base::Join(hwcModes, ", ").c_str());
        return {};
    }

    const DisplayModes oldModes = mPhysicalDisplays.get(displayId)
                                          .transform([](const PhysicalDisplay& display) {
                                              return display.snapshot().displayModes();
                                          })
                                          .value_or(DisplayModes{});

    ui::DisplayModeId nextModeId = 1 +
            std::accumulate(oldModes.begin(), oldModes.end(), static_cast<ui::DisplayModeId>(-1),
                            [](ui::DisplayModeId max, const auto& pair) {
                                return std::max(max, pair.first.value());
                            });

    DisplayModes newModes;
    for (const auto& hwcMode : hwcModes) {
        const DisplayModeId id{nextModeId++};
        newModes.try_emplace(id,
                             DisplayMode::Builder(hwcMode.hwcId)
                                     .setId(id)
                                     .setPhysicalDisplayId(displayId)
                                     .setResolution({hwcMode.width, hwcMode.height})
                                     .setVsyncPeriod(hwcMode.vsyncPeriod)
                                     .setDpiX(hwcMode.dpiX)
                                     .setDpiY(hwcMode.dpiY)
                                     .setGroup(hwcMode.configGroup)
                                     .build());
    }

    const bool sameModes =
            std::equal(newModes.begin(), newModes.end(), oldModes.begin(), oldModes.end(),
                       [](const auto& lhs, const auto& rhs) {
                           return equalsExceptDisplayModeId(*lhs.second, *rhs.second);
                       });

    // Keep IDs if modes have not changed.
    const auto& modes = sameModes ? oldModes : newModes;
    const DisplayModePtr activeMode =
            std::find_if(modes.begin(), modes.end(), [activeModeHwcId](const auto& pair) {
                return pair.second->getHwcId() == activeModeHwcId;
            })->second;

    return {modes, activeMode};
}

bool SurfaceFlinger::configureLocked() {
    std::vector<HotplugEvent> events;
    {
        std::lock_guard<std::mutex> lock(mHotplugMutex);
        events = std::move(mPendingHotplugEvents);
    }

    for (const auto [hwcDisplayId, connection] : events) {
        if (auto info = getHwComposer().onHotplug(hwcDisplayId, connection)) {
            const auto displayId = info->id;
            const bool connected = connection == hal::Connection::CONNECTED;

            if (const char* const log =
                        processHotplug(displayId, hwcDisplayId, connected, std::move(*info))) {
                ALOGI("%s display %s (HAL ID %" PRIu64 ")", log, to_string(displayId).c_str(),
                      hwcDisplayId);
            }
        }
    }

    return !events.empty();
}

const char* SurfaceFlinger::processHotplug(PhysicalDisplayId displayId,
                                           hal::HWDisplayId hwcDisplayId, bool connected,
                                           DisplayIdentificationInfo&& info) {
    const auto displayOpt = mPhysicalDisplays.get(displayId);
    if (!connected) {
        LOG_ALWAYS_FATAL_IF(!displayOpt);
        const auto& display = displayOpt->get();

        if (const ssize_t index = mCurrentState.displays.indexOfKey(display.token()); index >= 0) {
            mCurrentState.displays.removeItemsAt(index);
        }

        mPhysicalDisplays.erase(displayId);
        return "Disconnecting";
    }

    auto [displayModes, activeMode] = loadDisplayModes(displayId);
    if (!activeMode) {
        // TODO(b/241286153): Report hotplug failure to the framework.
        ALOGE("Failed to hotplug display %s", to_string(displayId).c_str());
        getHwComposer().disconnectDisplay(displayId);
        return nullptr;
    }

    ui::ColorModes colorModes = getHwComposer().getColorModes(displayId);

    if (displayOpt) {
        const auto& display = displayOpt->get();
        const auto& snapshot = display.snapshot();

        std::optional<DeviceProductInfo> deviceProductInfo;
        if (getHwComposer().updatesDeviceProductInfoOnHotplugReconnect()) {
            deviceProductInfo = std::move(info.deviceProductInfo);
        } else {
            deviceProductInfo = snapshot.deviceProductInfo();
        }

        const auto it =
                mPhysicalDisplays.try_replace(displayId, display.token(), displayId,
                                              snapshot.connectionType(), std::move(displayModes),
                                              std::move(colorModes), std::move(deviceProductInfo));

        auto& state = mCurrentState.displays.editValueFor(it->second.token());
        state.sequenceId = DisplayDeviceState{}.sequenceId; // Generate new sequenceId.
        state.physical->activeMode = std::move(activeMode);
        return "Reconnecting";
    }

    const sp<IBinder> token = sp<BBinder>::make();

    mPhysicalDisplays.try_emplace(displayId, token, displayId,
                                  getHwComposer().getDisplayConnectionType(displayId),
                                  std::move(displayModes), std::move(colorModes),
                                  std::move(info.deviceProductInfo));

    DisplayDeviceState state;
    state.physical = {.id = displayId,
                      .hwcDisplayId = hwcDisplayId,
                      .activeMode = std::move(activeMode)};
    state.isSecure = true; // All physical displays are currently considered secure.
    state.displayName = std::move(info.name);

    mCurrentState.displays.add(token, state);
    return "Connecting";
}

void SurfaceFlinger::dispatchDisplayHotplugEvent(PhysicalDisplayId displayId, bool connected) {
    mScheduler->onHotplugReceived(mAppConnectionHandle, displayId, connected);
    mScheduler->onHotplugReceived(mSfConnectionHandle, displayId, connected);
}

void SurfaceFlinger::dispatchDisplayModeChangeEvent(PhysicalDisplayId displayId,
                                                    const scheduler::FrameRateMode& mode) {
    // TODO(b/255635821): Merge code paths and move to Scheduler.
    const auto onDisplayModeChanged = displayId == mActiveDisplayId
            ? &scheduler::Scheduler::onPrimaryDisplayModeChanged
            : &scheduler::Scheduler::onNonPrimaryDisplayModeChanged;

    ((*mScheduler).*onDisplayModeChanged)(mAppConnectionHandle, mode);
}

sp<DisplayDevice> SurfaceFlinger::setupNewDisplayDeviceInternal(
        const wp<IBinder>& displayToken,
        std::shared_ptr<compositionengine::Display> compositionDisplay,
        const DisplayDeviceState& state,
        const sp<compositionengine::DisplaySurface>& displaySurface,
        const sp<IGraphicBufferProducer>& producer) {
    DisplayDeviceCreationArgs creationArgs(sp<SurfaceFlinger>::fromExisting(this), getHwComposer(),
                                           displayToken, compositionDisplay);
    creationArgs.sequenceId = state.sequenceId;
    creationArgs.isSecure = state.isSecure;
    creationArgs.displaySurface = displaySurface;
    creationArgs.hasWideColorGamut = false;
    creationArgs.supportedPerFrameMetadata = 0;

    if (const auto& physical = state.physical) {
        creationArgs.activeModeId = physical->activeMode->getId();
        const auto [kernelIdleTimerController, idleTimerTimeoutMs] =
                getKernelIdleTimerProperties(compositionDisplay->getId());

        using Config = scheduler::RefreshRateSelector::Config;
        const auto enableFrameRateOverride = sysprop::enable_frame_rate_override(true)
                ? Config::FrameRateOverride::Enabled
                : Config::FrameRateOverride::Disabled;
        Config config =
                {.enableFrameRateOverride = enableFrameRateOverride,
                 .frameRateMultipleThreshold =
                         base::GetIntProperty("debug.sf.frame_rate_multiple_threshold", 0),
                 .idleTimerTimeout = idleTimerTimeoutMs,
                 .kernelIdleTimerController = kernelIdleTimerController};

        creationArgs.refreshRateSelector =
                mPhysicalDisplays.get(physical->id)
                        .transform(&PhysicalDisplay::snapshotRef)
                        .transform([&](const display::DisplaySnapshot& snapshot) {
                            return std::make_shared<
                                    scheduler::RefreshRateSelector>(snapshot.displayModes(),
                                                                    creationArgs.activeModeId,
                                                                    config);
                        })
                        .value_or(nullptr);

        creationArgs.isPrimary = physical->id == getPrimaryDisplayIdLocked();

        if (useColorManagement) {
            mPhysicalDisplays.get(physical->id)
                    .transform(&PhysicalDisplay::snapshotRef)
                    .transform(ftl::unit_fn([&](const display::DisplaySnapshot& snapshot) {
                        for (const auto mode : snapshot.colorModes()) {
                            creationArgs.hasWideColorGamut |= ui::isWideColorMode(mode);
                            creationArgs.hwcColorModes
                                    .emplace(mode,
                                             getHwComposer().getRenderIntents(physical->id, mode));
                        }
                    }));
        }
    }

    if (const auto id = HalDisplayId::tryCast(compositionDisplay->getId())) {
        getHwComposer().getHdrCapabilities(*id, &creationArgs.hdrCapabilities);
        creationArgs.supportedPerFrameMetadata = getHwComposer().getSupportedPerFrameMetadata(*id);
    }

    auto nativeWindowSurface = getFactory().createNativeWindowSurface(producer);
    auto nativeWindow = nativeWindowSurface->getNativeWindow();
    creationArgs.nativeWindow = nativeWindow;

    // Make sure that composition can never be stalled by a virtual display
    // consumer that isn't processing buffers fast enough. We have to do this
    // here, in case the display is composed entirely by HWC.
    if (state.isVirtual()) {
        nativeWindow->setSwapInterval(nativeWindow.get(), 0);
    }

    creationArgs.physicalOrientation =
            getPhysicalDisplayOrientation(compositionDisplay->getId(), creationArgs.isPrimary);
    ALOGV("Display Orientation: %s", toCString(creationArgs.physicalOrientation));

    // virtual displays are always considered enabled
    creationArgs.initialPowerMode =
            state.isVirtual() ? std::make_optional(hal::PowerMode::ON) : std::nullopt;

    creationArgs.requestedRefreshRate = state.requestedRefreshRate;

    sp<DisplayDevice> display = getFactory().createDisplayDevice(creationArgs);

    nativeWindowSurface->preallocateBuffers();

    ui::ColorMode defaultColorMode = ui::ColorMode::NATIVE;
    Dataspace defaultDataSpace = Dataspace::UNKNOWN;
    if (display->hasWideColorGamut()) {
        defaultColorMode = ui::ColorMode::SRGB;
        defaultDataSpace = Dataspace::V0_SRGB;
    }
    display->getCompositionDisplay()->setColorProfile(
            compositionengine::Output::ColorProfile{defaultColorMode, defaultDataSpace,
                                                    RenderIntent::COLORIMETRIC,
                                                    Dataspace::UNKNOWN});

    if (const auto& physical = state.physical) {
        const auto& mode = *physical->activeMode;
        display->setActiveMode(mode.getId(), mode.getFps(), mode.getFps());
    }

    display->setLayerFilter(makeLayerFilterForDisplay(display->getId(), state.layerStack));
    display->setProjection(state.orientation, state.layerStackSpaceRect,
                           state.orientedDisplaySpaceRect);
    display->setDisplayName(state.displayName);
    display->setFlags(state.flags);

    return display;
}

void SurfaceFlinger::processDisplayAdded(const wp<IBinder>& displayToken,
                                         const DisplayDeviceState& state) {
    bool canAllocateHwcForVDS = false;
    ui::Size resolution(0, 0);
    ui::PixelFormat pixelFormat = static_cast<ui::PixelFormat>(PIXEL_FORMAT_UNKNOWN);
    if (state.physical) {
        resolution = state.physical->activeMode->getResolution();
        pixelFormat = static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888);
    } else if (state.surface != nullptr) {
        int status = state.surface->query(NATIVE_WINDOW_WIDTH, &resolution.width);
        ALOGE_IF(status != NO_ERROR, "Unable to query width (%d)", status);
        status = state.surface->query(NATIVE_WINDOW_HEIGHT, &resolution.height);
        ALOGE_IF(status != NO_ERROR, "Unable to query height (%d)", status);
        int format;
        status = state.surface->query(NATIVE_WINDOW_FORMAT, &format);
        ALOGE_IF(status != NO_ERROR, "Unable to query format (%d)", status);
        pixelFormat = static_cast<ui::PixelFormat>(format);
        if (mUseHwcVirtualDisplays || getHwComposer().isUsingVrComposer()) {
            if (maxVirtualDisplaySize == 0 ||
                ((uint64_t)width <= maxVirtualDisplaySize &&
                (uint64_t)height <= maxVirtualDisplaySize)) {
                uint64_t usage = 0;
                // Replace with native_window_get_consumer_usage ?
                status = state .surface->getConsumerUsage(&usage);
                ALOGW_IF(status != NO_ERROR, "Unable to query usage (%d)", status);
                if ((status == NO_ERROR) && canAllocateHwcDisplayIdForVDS(usage)) {
                   canAllocateHwcForVDS = true;
               }
            }
        }

    } else {
        // Virtual displays without a surface are dormant:
        // they have external state (layer stack, projection,
        // etc.) but no internal state (i.e. a DisplayDevice).
        return;
    }

    compositionengine::DisplayCreationArgsBuilder builder;
    if (const auto& physical = state.physical) {
        builder.setId(physical->id);
    } else {
        builder.setId(acquireVirtualDisplay(resolution, pixelFormat));
    }

    builder.setPixels(resolution);
    builder.setIsSecure(state.isSecure);
    builder.setPowerAdvisor(mPowerAdvisor.get());
    builder.setName(state.displayName);
    auto compositionDisplay = getCompositionEngine().createDisplay(builder.build());
    compositionDisplay->setLayerCachingEnabled(mLayerCachingEnabled);

    sp<compositionengine::DisplaySurface> displaySurface;
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferProducer> bqProducer;
    sp<IGraphicBufferConsumer> bqConsumer;
    getFactory().createBufferQueue(&bqProducer, &bqConsumer, /*consumerIsSurfaceFlinger =*/false);

    if (state.isVirtual()) {
        const auto displayId = VirtualDisplayId::tryCast(compositionDisplay->getId());
        LOG_FATAL_IF(!displayId);
        auto surface = sp<VirtualDisplaySurface>::make(getHwComposer(), *displayId, state.surface,
                                                       bqProducer, bqConsumer, state.displayName,
                                                       state.isSecure);
        displaySurface = surface;
        producer = std::move(surface);
    } else {
        ALOGE_IF(state.surface != nullptr,
                 "adding a supported display, but rendering "
                 "surface is provided (%p), ignoring it",
                 state.surface.get());
        const auto displayId = PhysicalDisplayId::tryCast(compositionDisplay->getId());
        LOG_FATAL_IF(!displayId);
        displaySurface =
                sp<FramebufferSurface>::make(getHwComposer(), *displayId, bqConsumer,
                                             state.physical->activeMode->getResolution(),
                                             ui::Size(maxGraphicsWidth, maxGraphicsHeight));
        producer = bqProducer;
    }

    LOG_FATAL_IF(!displaySurface);
    auto display = setupNewDisplayDeviceInternal(displayToken, std::move(compositionDisplay), state,
                                                 displaySurface, producer);

    if (mScheduler && !display->isVirtual()) {
        const auto displayId = display->getPhysicalId();
        {
            // TODO(b/241285876): Annotate `processDisplayAdded` instead.
            ftl::FakeGuard guard(kMainThreadContext);

            // For hotplug reconnect, renew the registration since display modes have been reloaded.
            mScheduler->registerDisplay(displayId, display->holdRefreshRateSelector());
        }

        dispatchDisplayHotplugEvent(displayId, true);
    }

    if (display->isVirtual()) {
        display->adjustRefreshRate(mScheduler->getPacesetterRefreshRate());
    }

    mDisplays.try_emplace(displayToken, std::move(display));
}

void SurfaceFlinger::processDisplayRemoved(const wp<IBinder>& displayToken) {
    auto display = getDisplayDeviceLocked(displayToken);
    if (display) {
        display->disconnect();

        if (display->isVirtual()) {
            releaseVirtualDisplay(display->getVirtualId());
        } else {
            dispatchDisplayHotplugEvent(display->getPhysicalId(), false);
            mScheduler->unregisterDisplay(display->getPhysicalId());
        }
    }

    mDisplays.erase(displayToken);

    if (display && display->isVirtual()) {
        static_cast<void>(mScheduler->schedule([display = std::move(display)] {
            // Destroy the display without holding the mStateLock.
            // This is a temporary solution until we can manage transaction queues without
            // holding the mStateLock.
            // With blast, the IGBP that is passed to the VirtualDisplaySurface is owned by the
            // client. When the IGBP is disconnected, its buffer cache in SF will be cleared
            // via SurfaceComposerClient::doUncacheBufferTransaction. This call from the client
            // ends up running on the main thread causing a deadlock since setTransactionstate
            // will try to acquire the mStateLock. Instead we extend the lifetime of
            // DisplayDevice and destroy it in the main thread without holding the mStateLock.
            // The display will be disconnected and removed from the mDisplays list so it will
            // not be accessible.
        }));
    }
}

void SurfaceFlinger::processDisplayChanged(const wp<IBinder>& displayToken,
                                           const DisplayDeviceState& currentState,
                                           const DisplayDeviceState& drawingState) {
    const sp<IBinder> currentBinder = IInterface::asBinder(currentState.surface);
    const sp<IBinder> drawingBinder = IInterface::asBinder(drawingState.surface);

    // Recreate the DisplayDevice if the surface or sequence ID changed.
    if (currentBinder != drawingBinder || currentState.sequenceId != drawingState.sequenceId) {
        getRenderEngine().cleanFramebufferCache();

        if (const auto display = getDisplayDeviceLocked(displayToken)) {
            display->disconnect();
            if (display->isVirtual()) {
                releaseVirtualDisplay(display->getVirtualId());
            }
        }

        mDisplays.erase(displayToken);

        if (const auto& physical = currentState.physical) {
            getHwComposer().allocatePhysicalDisplay(physical->hwcDisplayId, physical->id);
        }

        processDisplayAdded(displayToken, currentState);

        if (currentState.physical) {
            const auto display = getDisplayDeviceLocked(displayToken);
            setPowerModeInternal(display, hal::PowerMode::ON);

            // TODO(b/175678251) Call a listener instead.
            if (currentState.physical->hwcDisplayId == getHwComposer().getPrimaryHwcDisplayId()) {
                resetPhaseConfiguration(display->getActiveMode().fps);
            }
        }
        return;
    }

    if (const auto display = getDisplayDeviceLocked(displayToken)) {
        if (currentState.layerStack != drawingState.layerStack) {
            display->setLayerFilter(
                    makeLayerFilterForDisplay(display->getId(), currentState.layerStack));
        }
        if (currentState.flags != drawingState.flags) {
            display->setFlags(currentState.flags);
        }
        if ((currentState.orientation != drawingState.orientation) ||
            (currentState.layerStackSpaceRect != drawingState.layerStackSpaceRect) ||
            (currentState.orientedDisplaySpaceRect != drawingState.orientedDisplaySpaceRect)) {
            display->setProjection(currentState.orientation, currentState.layerStackSpaceRect,
                                   currentState.orientedDisplaySpaceRect);
            if (display->getId() == mActiveDisplayId) {
                mActiveDisplayTransformHint = display->getTransformHint();
                sActiveDisplayRotationFlags =
                        ui::Transform::toRotationFlags(display->getOrientation());
            }
        }
        if (currentState.width != drawingState.width ||
            currentState.height != drawingState.height) {
            display->setDisplaySize(currentState.width, currentState.height);

            if (display->getId() == mActiveDisplayId) {
                onActiveDisplaySizeChanged(*display);
            }
        }
    }
}

void SurfaceFlinger::resetPhaseConfiguration(Fps refreshRate) {
    // Cancel the pending refresh rate change, if any, before updating the phase configuration.
    mScheduler->vsyncModulator().cancelRefreshRateChange();

    mVsyncConfiguration->reset();
    updatePhaseConfiguration(refreshRate);
    mRefreshRateStats->setRefreshRate(refreshRate);
}

void SurfaceFlinger::processDisplayChangesLocked() {
    // here we take advantage of Vector's copy-on-write semantics to
    // improve performance by skipping the transaction entirely when
    // know that the lists are identical
    const KeyedVector<wp<IBinder>, DisplayDeviceState>& curr(mCurrentState.displays);
    const KeyedVector<wp<IBinder>, DisplayDeviceState>& draw(mDrawingState.displays);
    if (!curr.isIdenticalTo(draw)) {
        mVisibleRegionsDirty = true;
        mUpdateInputInfo = true;

        // find the displays that were removed
        // (ie: in drawing state but not in current state)
        // also handle displays that changed
        // (ie: displays that are in both lists)
        for (size_t i = 0; i < draw.size(); i++) {
            const wp<IBinder>& displayToken = draw.keyAt(i);
            const ssize_t j = curr.indexOfKey(displayToken);
            if (j < 0) {
                // in drawing state but not in current state
                processDisplayRemoved(displayToken);
            } else {
                // this display is in both lists. see if something changed.
                const DisplayDeviceState& currentState = curr[j];
                const DisplayDeviceState& drawingState = draw[i];
                processDisplayChanged(displayToken, currentState, drawingState);
            }
        }

        // find displays that were added
        // (ie: in current state but not in drawing state)
        for (size_t i = 0; i < curr.size(); i++) {
            const wp<IBinder>& displayToken = curr.keyAt(i);
            if (draw.indexOfKey(displayToken) < 0) {
                processDisplayAdded(displayToken, curr[i]);
            }
        }
    }

    mDrawingState.displays = mCurrentState.displays;
}

void SurfaceFlinger::commitTransactionsLocked(uint32_t transactionFlags) {
    // Commit display transactions.
    const bool displayTransactionNeeded = transactionFlags & eDisplayTransactionNeeded;
    mFrontEndDisplayInfosChanged = displayTransactionNeeded;
    if (displayTransactionNeeded && !mLayerLifecycleManagerEnabled) {
        processDisplayChangesLocked();
        mFrontEndDisplayInfos.clear();
        for (const auto& [_, display] : mDisplays) {
            mFrontEndDisplayInfos.try_emplace(display->getLayerStack(), display->getFrontEndInfo());
        }
    }
    mForceTransactionDisplayChange = displayTransactionNeeded;

    if (mSomeChildrenChanged) {
        mVisibleRegionsDirty = true;
        mSomeChildrenChanged = false;
        mUpdateInputInfo = true;
    }

    // Update transform hint.
    if (transactionFlags & (eTransformHintUpdateNeeded | eDisplayTransactionNeeded)) {
        // Layers and/or displays have changed, so update the transform hint for each layer.
        //
        // NOTE: we do this here, rather than when presenting the display so that
        // the hint is set before we acquire a buffer from the surface texture.
        //
        // NOTE: layer transactions have taken place already, so we use their
        // drawing state. However, SurfaceFlinger's own transaction has not
        // happened yet, so we must use the current state layer list
        // (soon to become the drawing state list).
        //
        sp<const DisplayDevice> hintDisplay;
        ui::LayerStack layerStack;

        mCurrentState.traverse([&](Layer* layer) REQUIRES(mStateLock) {
            // NOTE: we rely on the fact that layers are sorted by
            // layerStack first (so we don't have to traverse the list
            // of displays for every layer).
            if (const auto filter = layer->getOutputFilter(); layerStack != filter.layerStack) {
                layerStack = filter.layerStack;
                hintDisplay = nullptr;

                // Find the display that includes the layer.
                for (const auto& [token, display] : mDisplays) {
                    if (!display->getCompositionDisplay()->includesLayer(filter)) {
                        continue;
                    }

                    // Pick the primary display if another display mirrors the layer.
                    if (hintDisplay) {
                        hintDisplay = nullptr;
                        break;
                    }

                    hintDisplay = display;
                }
            }

            if (!hintDisplay) {
                // NOTE: TEMPORARY FIX ONLY. Real fix should cause layers to
                // redraw after transform hint changes. See bug 8508397.
                // could be null when this layer is using a layerStack
                // that is not visible on any display. Also can occur at
                // screen off/on times.
                // U Update: Don't provide stale hints to the clients. For
                // special cases where we want the app to draw its
                // first frame before the display is available, we rely
                // on WMS and DMS to provide the right information
                // so the client can calculate the hint.
                ALOGV("Skipping reporting transform hint update for %s", layer->getDebugName());
                layer->skipReportingTransformHint();
            } else {
                layer->updateTransformHint(hintDisplay->getTransformHint());
            }
        });
    }

    if (mLayersAdded) {
        mLayersAdded = false;
        // Layers have been added.
        mVisibleRegionsDirty = true;
        mUpdateInputInfo = true;
    }

    // some layers might have been removed, so
    // we need to update the regions they're exposing.
    if (mLayersRemoved) {
        mLayersRemoved = false;
        mVisibleRegionsDirty = true;
        mUpdateInputInfo = true;
        mDrawingState.traverseInZOrder([&](Layer* layer) {
            if (mLayersPendingRemoval.indexOf(sp<Layer>::fromExisting(layer)) >= 0) {
                // this layer is not visible anymore
                Region visibleReg;
                visibleReg.set(layer->getScreenBounds());
                invalidateLayerStack(layer->getOutputFilter(), visibleReg);
            }
        });
    }

    if (transactionFlags & eInputInfoUpdateNeeded) {
        mUpdateInputInfo = true;
    }

    doCommitTransactions();
}

void SurfaceFlinger::updateInputFlinger(VsyncId vsyncId, TimePoint frameTime) {
    if (!mInputFlinger || (!mUpdateInputInfo && mInputWindowCommands.empty())) {
        return;
    }
    ATRACE_CALL();

    std::vector<WindowInfo> windowInfos;
    std::vector<DisplayInfo> displayInfos;
    bool updateWindowInfo = false;
    if (mUpdateInputInfo) {
        mUpdateInputInfo = false;
        updateWindowInfo = true;
        buildWindowInfos(windowInfos, displayInfos);
    }

    std::unordered_set<int32_t> visibleWindowIds;
    for (WindowInfo& windowInfo : windowInfos) {
        if (!windowInfo.inputConfig.test(WindowInfo::InputConfig::NOT_VISIBLE)) {
            visibleWindowIds.insert(windowInfo.id);
        }
    }
    bool visibleWindowsChanged = false;
    if (visibleWindowIds != mVisibleWindowIds) {
        visibleWindowsChanged = true;
        mVisibleWindowIds = std::move(visibleWindowIds);
    }

    BackgroundExecutor::getInstance().sendCallbacks({[updateWindowInfo,
                                                      windowInfos = std::move(windowInfos),
                                                      displayInfos = std::move(displayInfos),
                                                      inputWindowCommands =
                                                              std::move(mInputWindowCommands),
                                                      inputFlinger = mInputFlinger, this,
                                                      visibleWindowsChanged, vsyncId, frameTime]() {
        ATRACE_NAME("BackgroundExecutor::updateInputFlinger");
        if (updateWindowInfo) {
            mWindowInfosListenerInvoker
                    ->windowInfosChanged(gui::WindowInfosUpdate{std::move(windowInfos),
                                                                std::move(displayInfos),
                                                                ftl::to_underlying(vsyncId),
                                                                frameTime.ns()},
                                         std::move(
                                                 inputWindowCommands.windowInfosReportedListeners),
                                         /* forceImmediateCall= */ visibleWindowsChanged ||
                                                 !inputWindowCommands.focusRequests.empty());
        } else {
            // If there are listeners but no changes to input windows, call the listeners
            // immediately.
            for (const auto& listener : inputWindowCommands.windowInfosReportedListeners) {
                if (IInterface::asBinder(listener)->isBinderAlive()) {
                    listener->onWindowInfosReported();
                }
            }
        }
        for (const auto& focusRequest : inputWindowCommands.focusRequests) {
            inputFlinger->setFocusedWindow(focusRequest);
        }
    }});

    mInputWindowCommands.clear();
}

void SurfaceFlinger::persistDisplayBrightness(bool needsComposite) {
    const bool supportsDisplayBrightnessCommand = getHwComposer().getComposer()->isSupported(
            Hwc2::Composer::OptionalFeature::DisplayBrightnessCommand);
    if (!supportsDisplayBrightnessCommand) {
        return;
    }

    for (const auto& [_, display] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        if (const auto brightness = display->getStagedBrightness(); brightness) {
            if (!needsComposite) {
                const status_t error =
                        getHwComposer()
                                .setDisplayBrightness(display->getPhysicalId(), *brightness,
                                                      display->getCompositionDisplay()
                                                              ->getState()
                                                              .displayBrightnessNits,
                                                      Hwc2::Composer::DisplayBrightnessOptions{
                                                              .applyImmediately = true})
                                .get();

                ALOGE_IF(error != NO_ERROR,
                         "Error setting display brightness for display %s: %d (%s)",
                         to_string(display->getId()).c_str(), error, strerror(error));
            }
            display->persistBrightness(needsComposite);
        }
    }
}

void SurfaceFlinger::buildWindowInfos(std::vector<WindowInfo>& outWindowInfos,
                                      std::vector<DisplayInfo>& outDisplayInfos) {
    static size_t sNumWindowInfos = 0;
    outWindowInfos.reserve(sNumWindowInfos);
    sNumWindowInfos = 0;

    if (mLayerLifecycleManagerEnabled) {
        mLayerSnapshotBuilder.forEachInputSnapshot(
                [&outWindowInfos](const frontend::LayerSnapshot& snapshot) {
                    outWindowInfos.push_back(snapshot.inputInfo);
                });
    } else {
        mDrawingState.traverseInReverseZOrder([&](Layer* layer) {
            if (!layer->needsInputInfo()) return;
            const auto opt =
                    mFrontEndDisplayInfos.get(layer->getLayerStack())
                            .transform([](const frontend::DisplayInfo& info) {
                                return Layer::InputDisplayArgs{&info.transform, info.isSecure};
                            });

            outWindowInfos.push_back(layer->fillInputInfo(opt.value_or(Layer::InputDisplayArgs{})));
        });
    }

    sNumWindowInfos = outWindowInfos.size();

    outDisplayInfos.reserve(mFrontEndDisplayInfos.size());
    for (const auto& [_, info] : mFrontEndDisplayInfos) {
        outDisplayInfos.push_back(info.info);
    }
}

void SurfaceFlinger::updateCursorAsync() {
    compositionengine::CompositionRefreshArgs refreshArgs;
    for (const auto& [_, display] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        if (HalDisplayId::tryCast(display->getId())) {
            refreshArgs.outputs.push_back(display->getCompositionDisplay());
        }
    }

    constexpr bool kCursorOnly = true;
    const auto layers = moveSnapshotsToCompositionArgs(refreshArgs, kCursorOnly);
    mCompositionEngine->updateCursorAsync(refreshArgs);
    moveSnapshotsFromCompositionArgs(refreshArgs, layers);
}

void SurfaceFlinger::requestHardwareVsync(PhysicalDisplayId displayId, bool enable) {
    getHwComposer().setVsyncEnabled(displayId, enable ? hal::Vsync::ENABLE : hal::Vsync::DISABLE);
}

void SurfaceFlinger::requestDisplayModes(std::vector<display::DisplayModeRequest> modeRequests) {
    if (mBootStage != BootStage::FINISHED) {
        ALOGV("Currently in the boot stage, skipping display mode changes");
        return;
    }

    ATRACE_CALL();

    // If this is called from the main thread mStateLock must be locked before
    // Currently the only way to call this function from the main thread is from
    // Scheduler::chooseRefreshRateForContent

    ConditionalLock lock(mStateLock, std::this_thread::get_id() != mMainThreadId);

    for (auto& request : modeRequests) {
        const auto& modePtr = request.mode.modePtr;

        const auto displayId = modePtr->getPhysicalDisplayId();
        const auto display = getDisplayDeviceLocked(displayId);

        if (!display) continue;

        if (ftl::FakeGuard guard(kMainThreadContext);
            !shouldApplyRefreshRateSelectorPolicy(*display)) {
            ALOGV("%s(%s): Skipped applying policy", __func__, to_string(displayId).c_str());
            continue;
        }

        if (display->refreshRateSelector().isModeAllowed(request.mode)) {
            setDesiredActiveMode(std::move(request));
        } else {
            ALOGV("%s: Mode %d is disallowed for display %s", __func__, modePtr->getId().value(),
                  to_string(displayId).c_str());
        }
    }
}

void SurfaceFlinger::triggerOnFrameRateOverridesChanged() {
    PhysicalDisplayId displayId = [&]() {
        ConditionalLock lock(mStateLock, std::this_thread::get_id() != mMainThreadId);
        return getDefaultDisplayDeviceLocked()->getPhysicalId();
    }();

    mScheduler->onFrameRateOverridesChanged(mAppConnectionHandle, displayId);
}

void SurfaceFlinger::notifyCpuLoadUp() {
    mPowerAdvisor->notifyCpuLoadUp();
}

void SurfaceFlinger::initScheduler(const sp<const DisplayDevice>& display) {
    using namespace scheduler;

    LOG_ALWAYS_FATAL_IF(mScheduler);

    const auto activeMode = display->refreshRateSelector().getActiveMode();
    const Fps activeRefreshRate = activeMode.fps;
    mRefreshRateStats =
            std::make_unique<RefreshRateStats>(*mTimeStats, activeRefreshRate, hal::PowerMode::OFF);

    mVsyncConfiguration = getFactory().createVsyncConfiguration(activeRefreshRate);

    FeatureFlags features;

    if (sysprop::use_content_detection_for_refresh_rate(false)) {
        features |= Feature::kContentDetection;
        if (base::GetBoolProperty("debug.sf.enable_small_dirty_detection"s, false)) {
            features |= Feature::kSmallDirtyContentDetection;
        }
    }
    if (base::GetBoolProperty("debug.sf.show_predicted_vsync"s, false)) {
        features |= Feature::kTracePredictedVsync;
    }
    if (!base::GetBoolProperty("debug.sf.vsync_reactor_ignore_present_fences"s, false) &&
        !getHwComposer().hasCapability(Capability::PRESENT_FENCE_IS_NOT_RELIABLE)) {
        features |= Feature::kPresentFences;
    }
    if (display->refreshRateSelector().kernelIdleTimerController()) {
        features |= Feature::kKernelIdleTimer;
    }
    if (mBackpressureGpuComposition) {
        features |= Feature::kBackpressureGpuComposition;
    }

    auto modulatorPtr = sp<VsyncModulator>::make(mVsyncConfiguration->getCurrentConfigs());

    mScheduler = std::make_unique<Scheduler>(static_cast<ICompositor&>(*this),
                                             static_cast<ISchedulerCallback&>(*this), features,
                                             std::move(modulatorPtr));
    mScheduler->registerDisplay(display->getPhysicalId(), display->holdRefreshRateSelector());
    mScheduler->startTimers();

    const auto configs = mVsyncConfiguration->getCurrentConfigs();

    mAppConnectionHandle =
            mScheduler->createEventThread(Scheduler::Cycle::Render,
                                          mFrameTimeline->getTokenManager(),
                                          /* workDuration */ configs.late.appWorkDuration,
                                          /* readyDuration */ configs.late.sfWorkDuration);
    mSfConnectionHandle =
            mScheduler->createEventThread(Scheduler::Cycle::LastComposite,
                                          mFrameTimeline->getTokenManager(),
                                          /* workDuration */ activeRefreshRate.getPeriod(),
                                          /* readyDuration */ configs.late.sfWorkDuration);

    mScheduler->initVsync(mScheduler->getVsyncSchedule()->getDispatch(),
                          *mFrameTimeline->getTokenManager(), configs.late.sfWorkDuration);

    mRegionSamplingThread =
            sp<RegionSamplingThread>::make(*this,
                                           RegionSamplingThread::EnvironmentTimingTunables());
    mFpsReporter = sp<FpsReporter>::make(*mFrameTimeline, *this);
}

void SurfaceFlinger::updatePhaseConfiguration(Fps refreshRate) {
    mVsyncConfiguration->setRefreshRateFps(refreshRate);
    mScheduler->setVsyncConfigSet(mVsyncConfiguration->getCurrentConfigs(),
                                  refreshRate.getPeriod());
}

void SurfaceFlinger::doCommitTransactions() {
    ATRACE_CALL();

    if (!mLayersPendingRemoval.isEmpty()) {
        // Notify removed layers now that they can't be drawn from
        for (const auto& l : mLayersPendingRemoval) {
            // Ensure any buffers set to display on any children are released.
            if (l->isRemovedFromCurrentState()) {
                l->latchAndReleaseBuffer();
            }

            // If a layer has a parent, we allow it to out-live it's handle
            // with the idea that the parent holds a reference and will eventually
            // be cleaned up. However no one cleans up the top-level so we do so
            // here.
            if (l->isAtRoot()) {
                l->setIsAtRoot(false);
                mCurrentState.layersSortedByZ.remove(l);
            }

            // If the layer has been removed and has no parent, then it will not be reachable
            // when traversing layers on screen. Add the layer to the offscreenLayers set to
            // ensure we can copy its current to drawing state.
            if (!l->getParent()) {
                mOffscreenLayers.emplace(l.get());
            }
        }
        mLayersPendingRemoval.clear();
    }

    mDrawingState = mCurrentState;
    // clear the "changed" flags in current state
    mCurrentState.colorMatrixChanged = false;

    if (mVisibleRegionsDirty) {
        for (const auto& rootLayer : mDrawingState.layersSortedByZ) {
            rootLayer->commitChildList();
        }
    }

    commitOffscreenLayers();
    if (mLayerMirrorRoots.size() > 0) {
        std::deque<Layer*> pendingUpdates;
        pendingUpdates.insert(pendingUpdates.end(), mLayerMirrorRoots.begin(),
                              mLayerMirrorRoots.end());
        std::vector<Layer*> needsUpdating;
        for (Layer* cloneRoot : mLayerMirrorRoots) {
            pendingUpdates.pop_front();
            if (cloneRoot->isRemovedFromCurrentState()) {
                continue;
            }
            if (cloneRoot->updateMirrorInfo(pendingUpdates)) {
            } else {
                needsUpdating.push_back(cloneRoot);
            }
        }
        for (Layer* cloneRoot : needsUpdating) {
            cloneRoot->updateMirrorInfo({});
        }
    }
}

void SurfaceFlinger::commitOffscreenLayers() {
    for (Layer* offscreenLayer : mOffscreenLayers) {
        offscreenLayer->traverse(LayerVector::StateSet::Drawing, [](Layer* layer) {
            if (layer->clearTransactionFlags(eTransactionNeeded)) {
                layer->doTransaction(0);
                layer->commitChildList();
            }
        });
    }
}

void SurfaceFlinger::invalidateLayerStack(const ui::LayerFilter& layerFilter, const Region& dirty) {
    for (const auto& [token, displayDevice] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        auto display = displayDevice->getCompositionDisplay();
        if (display->includesLayer(layerFilter)) {
            display->editState().dirtyRegion.orSelf(dirty);
        }
    }
}

bool SurfaceFlinger::latchBuffers() {
    ATRACE_CALL();

    const nsecs_t latchTime = systemTime();

    bool visibleRegions = false;
    bool frameQueued = false;
    bool newDataLatched = false;

    // Store the set of layers that need updates. This set must not change as
    // buffers are being latched, as this could result in a deadlock.
    // Example: Two producers share the same command stream and:
    // 1.) Layer 0 is latched
    // 2.) Layer 0 gets a new frame
    // 2.) Layer 1 gets a new frame
    // 3.) Layer 1 is latched.
    // Display is now waiting on Layer 1's frame, which is behind layer 0's
    // second frame. But layer 0's second frame could be waiting on display.
    mDrawingState.traverse([&](Layer* layer) {
        if (layer->clearTransactionFlags(eTransactionNeeded) || mForceTransactionDisplayChange) {
            const uint32_t flags = layer->doTransaction(0);
            if (flags & Layer::eVisibleRegion) {
                mVisibleRegionsDirty = true;
            }
        }

        if (layer->hasReadyFrame() || layer->willReleaseBufferOnLatch()) {
            frameQueued = true;
            mLayersWithQueuedFrames.emplace(sp<Layer>::fromExisting(layer));
        } else {
            layer->useEmptyDamage();
            if (!layer->hasBuffer()) {
                // The last latch time is used to classify a missed frame as buffer stuffing
                // instead of a missed frame. This is used to identify scenarios where we
                // could not latch a buffer or apply a transaction due to backpressure.
                // We only update the latch time for buffer less layers here, the latch time
                // is updated for buffer layers when the buffer is latched.
                layer->updateLastLatchTime(latchTime);
            }
        }
    });
    mForceTransactionDisplayChange = false;

    // The client can continue submitting buffers for offscreen layers, but they will not
    // be shown on screen. Therefore, we need to latch and release buffers of offscreen
    // layers to ensure dequeueBuffer doesn't block indefinitely.
    for (Layer* offscreenLayer : mOffscreenLayers) {
        offscreenLayer->traverse(LayerVector::StateSet::Drawing,
                                         [&](Layer* l) { l->latchAndReleaseBuffer(); });
    }

    if (!mLayersWithQueuedFrames.empty()) {
        // mStateLock is needed for latchBuffer as LayerRejecter::reject()
        // writes to Layer current state. See also b/119481871
        Mutex::Autolock lock(mStateLock);

        for (const auto& layer : mLayersWithQueuedFrames) {
            if (layer->willReleaseBufferOnLatch()) {
                mLayersWithBuffersRemoved.emplace(layer);
            }
            if (layer->latchBuffer(visibleRegions, latchTime)) {
                mLayersPendingRefresh.push_back(layer);
                newDataLatched = true;
            }
            layer->useSurfaceDamage();
        }
    }

    mVisibleRegionsDirty |= visibleRegions;

    // If we will need to wake up at some time in the future to deal with a
    // queued frame that shouldn't be displayed during this vsync period, wake
    // up during the next vsync period to check again.
    if (frameQueued && (mLayersWithQueuedFrames.empty() || !newDataLatched)) {
        scheduleCommit(FrameHint::kNone);
    }

    // enter boot animation on first buffer latch
    if (CC_UNLIKELY(mBootStage == BootStage::BOOTLOADER && newDataLatched)) {
        ALOGI("Enter boot animation");
        mBootStage = BootStage::BOOTANIMATION;
    }

    if (mLayerMirrorRoots.size() > 0) {
        mDrawingState.traverse([&](Layer* layer) { layer->updateCloneBufferInfo(); });
    }

    // Only continue with the refresh if there is actually new work to do
    return !mLayersWithQueuedFrames.empty() && newDataLatched;
}

status_t SurfaceFlinger::addClientLayer(LayerCreationArgs& args, const sp<IBinder>& handle,
                                        const sp<Layer>& layer, const wp<Layer>& parent,
                                        uint32_t* outTransformHint) {
    if (mNumLayers >= MAX_LAYERS) {
        ALOGE("AddClientLayer failed, mNumLayers (%zu) >= MAX_LAYERS (%zu)", mNumLayers.load(),
              MAX_LAYERS);
        static_cast<void>(mScheduler->schedule([=] {
            ALOGE("Dumping layer keeping > 20 children alive:");
            bool leakingParentLayerFound = false;
            mDrawingState.traverse([&](Layer* layer) {
                if (leakingParentLayerFound) {
                    return;
                }
                if (layer->getChildrenCount() > 20) {
                    leakingParentLayerFound = true;
                    sp<Layer> parent = sp<Layer>::fromExisting(layer);
                    while (parent) {
                        ALOGE("Parent Layer: %s%s", parent->getName().c_str(),
                              (parent->isHandleAlive() ? "handleAlive" : ""));
                        parent = parent->getParent();
                    }
                    // Sample up to 100 layers
                    ALOGE("Dumping random sampling of child layers total(%zu): ",
                          layer->getChildrenCount());
                    int sampleSize = (layer->getChildrenCount() / 100) + 1;
                    layer->traverseChildren([&](Layer* layer) {
                        if (rand() % sampleSize == 0) {
                            ALOGE("Child Layer: %s", layer->getName().c_str());
                        }
                    });
                }
            });

            int numLayers = 0;
            mDrawingState.traverse([&](Layer* layer) { numLayers++; });

            ALOGE("Dumping random sampling of on-screen layers total(%u):", numLayers);
            mDrawingState.traverse([&](Layer* layer) {
                // Aim to dump about 200 layers to avoid totally trashing
                // logcat. On the other hand, if there really are 4096 layers
                // something has gone totally wrong its probably the most
                // useful information in logcat.
                if (rand() % 20 == 13) {
                    ALOGE("Layer: %s%s", layer->getName().c_str(),
                          (layer->isHandleAlive() ? "handleAlive" : ""));
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            });
            ALOGE("Dumping random sampling of off-screen layers total(%zu): ",
                  mOffscreenLayers.size());
            for (Layer* offscreenLayer : mOffscreenLayers) {
                if (rand() % 20 == 13) {
                    ALOGE("Offscreen-layer: %s%s", offscreenLayer->getName().c_str(),
                          (offscreenLayer->isHandleAlive() ? "handleAlive" : ""));
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }
        }));
        return NO_MEMORY;
    }

    layer->updateTransformHint(mActiveDisplayTransformHint);
    if (outTransformHint) {
        *outTransformHint = mActiveDisplayTransformHint;
    }
    args.parentId = LayerHandle::getLayerId(args.parentHandle.promote());
    args.layerIdToMirror = LayerHandle::getLayerId(args.mirrorLayerHandle.promote());
    {
        std::scoped_lock<std::mutex> lock(mCreatedLayersLock);
        mCreatedLayers.emplace_back(layer, parent, args.addToRoot);
        mNewLayers.emplace_back(std::make_unique<frontend::RequestedLayerState>(args));
        args.mirrorLayerHandle.clear();
        args.parentHandle.clear();
        mNewLayerArgs.emplace_back(std::move(args));
    }

    setTransactionFlags(eTransactionNeeded);
    return NO_ERROR;
}

uint32_t SurfaceFlinger::getTransactionFlags() const {
    return mTransactionFlags;
}

uint32_t SurfaceFlinger::clearTransactionFlags(uint32_t mask) {
    uint32_t transactionFlags = mTransactionFlags.fetch_and(~mask);
    ATRACE_INT("mTransactionFlags", transactionFlags);
    return transactionFlags & mask;
}

void SurfaceFlinger::setTransactionFlags(uint32_t mask, TransactionSchedule schedule,
                                         const sp<IBinder>& applyToken, FrameHint frameHint) {
    mScheduler->modulateVsync({}, &VsyncModulator::setTransactionSchedule, schedule, applyToken);
    uint32_t transactionFlags = mTransactionFlags.fetch_or(mask);
    ATRACE_INT("mTransactionFlags", transactionFlags);

    if (const bool scheduled = transactionFlags & mask; !scheduled) {
        scheduleCommit(frameHint);
    } else if (frameHint == FrameHint::kActive) {
        // Even if the next frame is already scheduled, we should reset the idle timer
        // as a new activity just happened.
        mScheduler->resetIdleTimer();
    }
}

TransactionHandler::TransactionReadiness SurfaceFlinger::transactionReadyTimelineCheck(
        const TransactionHandler::TransactionFlushState& flushState) {
    const auto& transaction = *flushState.transaction;

    const TimePoint desiredPresentTime = TimePoint::fromNs(transaction.desiredPresentTime);
    const TimePoint expectedPresentTime = mScheduler->expectedPresentTimeForPacesetter();

    using TransactionReadiness = TransactionHandler::TransactionReadiness;

    // Do not present if the desiredPresentTime has not passed unless it is more than
    // one second in the future. We ignore timestamps more than 1 second in the future
    // for stability reasons.
    if (!transaction.isAutoTimestamp && desiredPresentTime >= expectedPresentTime &&
        desiredPresentTime < expectedPresentTime + 1s) {
        ATRACE_FORMAT("not current desiredPresentTime: %" PRId64 " expectedPresentTime: %" PRId64,
                      desiredPresentTime, expectedPresentTime);
        return TransactionReadiness::NotReady;
    }

    if (!mScheduler->isVsyncValid(expectedPresentTime, transaction.originUid)) {
        ATRACE_FORMAT("!isVsyncValid expectedPresentTime: %" PRId64 " uid: %d", expectedPresentTime,
                      transaction.originUid);
        return TransactionReadiness::NotReady;
    }

    // If the client didn't specify desiredPresentTime, use the vsyncId to determine the
    // expected present time of this transaction.
    if (transaction.isAutoTimestamp &&
        frameIsEarly(expectedPresentTime, VsyncId{transaction.frameTimelineInfo.vsyncId})) {
        ATRACE_FORMAT("frameIsEarly vsyncId: %" PRId64 " expectedPresentTime: %" PRId64,
                      transaction.frameTimelineInfo.vsyncId, expectedPresentTime);
        return TransactionReadiness::NotReady;
    }

    return TransactionReadiness::Ready;
}

TransactionHandler::TransactionReadiness SurfaceFlinger::transactionReadyBufferCheck(
        const TransactionHandler::TransactionFlushState& flushState) {
    using TransactionReadiness = TransactionHandler::TransactionReadiness;
    auto ready = TransactionReadiness::Ready;
    flushState.transaction->traverseStatesWithBuffersWhileTrue([&](const layer_state_t& s,
                                                                   const std::shared_ptr<
                                                                           renderengine::
                                                                                   ExternalTexture>&
                                                                           externalTexture)
                                                                       -> bool {
        sp<Layer> layer = LayerHandle::getLayer(s.surface);
        const auto& transaction = *flushState.transaction;
        // check for barrier frames
        if (s.bufferData->hasBarrier) {
            // The current producerId is already a newer producer than the buffer that has a
            // barrier. This means the incoming buffer is older and we can release it here. We
            // don't wait on the barrier since we know that's stale information.
            if (layer->getDrawingState().barrierProducerId > s.bufferData->producerId) {
                layer->callReleaseBufferCallback(s.bufferData->releaseBufferListener,
                                                 externalTexture->getBuffer(),
                                                 s.bufferData->frameNumber,
                                                 s.bufferData->acquireFence);
                // Delete the entire state at this point and not just release the buffer because
                // everything associated with the Layer in this Transaction is now out of date.
                ATRACE_FORMAT("DeleteStaleBuffer %s barrierProducerId:%d > %d",
                              layer->getDebugName(), layer->getDrawingState().barrierProducerId,
                              s.bufferData->producerId);
                return TraverseBuffersReturnValues::DELETE_AND_CONTINUE_TRAVERSAL;
            }

            if (layer->getDrawingState().barrierFrameNumber < s.bufferData->barrierFrameNumber) {
                const bool willApplyBarrierFrame =
                        flushState.bufferLayersReadyToPresent.contains(s.surface.get()) &&
                        ((flushState.bufferLayersReadyToPresent.get(s.surface.get()) >=
                          s.bufferData->barrierFrameNumber));
                if (!willApplyBarrierFrame) {
                    ATRACE_FORMAT("NotReadyBarrier %s barrierFrameNumber:%" PRId64 " > %" PRId64,
                                  layer->getDebugName(),
                                  layer->getDrawingState().barrierFrameNumber,
                                  s.bufferData->barrierFrameNumber);
                    ready = TransactionReadiness::NotReadyBarrier;
                    return TraverseBuffersReturnValues::STOP_TRAVERSAL;
                }
            }
        }

        // If backpressure is enabled and we already have a buffer to commit, keep
        // the transaction in the queue.
        const bool hasPendingBuffer =
                flushState.bufferLayersReadyToPresent.contains(s.surface.get());
        if (layer->backpressureEnabled() && hasPendingBuffer && transaction.isAutoTimestamp) {
            ATRACE_FORMAT("hasPendingBuffer %s", layer->getDebugName());
            ready = TransactionReadiness::NotReady;
            return TraverseBuffersReturnValues::STOP_TRAVERSAL;
        }

        // ignore the acquire fence if LatchUnsignaledConfig::Always is set.
        const bool checkAcquireFence = enableLatchUnsignaledConfig != LatchUnsignaledConfig::Always;
        const bool acquireFenceAvailable = s.bufferData &&
                s.bufferData->flags.test(BufferData::BufferDataChange::fenceChanged) &&
                s.bufferData->acquireFence;
        const bool fenceSignaled = !checkAcquireFence || !acquireFenceAvailable ||
                s.bufferData->acquireFence->getStatus() != Fence::Status::Unsignaled;
        if (!fenceSignaled) {
            // check fence status
            const bool allowLatchUnsignaled =
                    shouldLatchUnsignaled(layer, s, transaction.states.size(),
                                          flushState.firstTransaction);
            if (allowLatchUnsignaled) {
                ATRACE_FORMAT("fence unsignaled try allowLatchUnsignaled %s",
                              layer->getDebugName());
                ready = TransactionReadiness::NotReadyUnsignaled;
            } else {
                ready = TransactionReadiness::NotReady;
                auto& listener = s.bufferData->releaseBufferListener;
                if (listener &&
                    (flushState.queueProcessTime - transaction.postTime) >
                            std::chrono::nanoseconds(4s).count()) {
                    mTransactionHandler
                            .onTransactionQueueStalled(transaction.id,
                                                       {.pid = layer->getOwnerPid(),
                                                        .layerId = static_cast<uint32_t>(
                                                                layer->getSequence()),
                                                        .layerName = layer->getDebugName(),
                                                        .bufferId = s.bufferData->getId(),
                                                        .frameNumber = s.bufferData->frameNumber});
                }
                ATRACE_FORMAT("fence unsignaled %s", layer->getDebugName());
                return TraverseBuffersReturnValues::STOP_TRAVERSAL;
            }
        }
        return TraverseBuffersReturnValues::CONTINUE_TRAVERSAL;
    });
    return ready;
}

void SurfaceFlinger::addTransactionReadyFilters() {
    mTransactionHandler.addTransactionReadyFilter(
            std::bind(&SurfaceFlinger::transactionReadyTimelineCheck, this, std::placeholders::_1));
    mTransactionHandler.addTransactionReadyFilter(
            std::bind(&SurfaceFlinger::transactionReadyBufferCheck, this, std::placeholders::_1));
}

// For tests only
bool SurfaceFlinger::flushTransactionQueues(VsyncId vsyncId) {
    std::vector<TransactionState> transactions = mTransactionHandler.flushTransactions();
    return applyTransactions(transactions, vsyncId);
}

bool SurfaceFlinger::applyTransactions(std::vector<TransactionState>& transactions,
                                       VsyncId vsyncId) {
    Mutex::Autolock lock(mStateLock);
    return applyTransactionsLocked(transactions, vsyncId);
}

bool SurfaceFlinger::applyTransactionsLocked(std::vector<TransactionState>& transactions,
                                             VsyncId vsyncId) {
    bool needsTraversal = false;
    // Now apply all transactions.
    for (auto& transaction : transactions) {
        needsTraversal |=
                applyTransactionState(transaction.frameTimelineInfo, transaction.states,
                                      transaction.displays, transaction.flags,
                                      transaction.inputWindowCommands,
                                      transaction.desiredPresentTime, transaction.isAutoTimestamp,
                                      std::move(transaction.uncacheBufferIds), transaction.postTime,
                                      transaction.hasListenerCallbacks,
                                      transaction.listenerCallbacks, transaction.originPid,
                                      transaction.originUid, transaction.id);
    }
    return needsTraversal;
}

bool SurfaceFlinger::transactionFlushNeeded() {
    return mTransactionHandler.hasPendingTransactions();
}

bool SurfaceFlinger::frameIsEarly(TimePoint expectedPresentTime, VsyncId vsyncId) const {
    const auto prediction =
            mFrameTimeline->getTokenManager()->getPredictionsForToken(ftl::to_underlying(vsyncId));
    if (!prediction) {
        return false;
    }

    const auto predictedPresentTime = TimePoint::fromNs(prediction->presentTime);

    if (std::chrono::abs(predictedPresentTime - expectedPresentTime) >=
        scheduler::VsyncConfig::kEarlyLatchMaxThreshold) {
        return false;
    }

    const Duration earlyLatchVsyncThreshold = mScheduler->getVsyncSchedule()->period() / 2;

    return predictedPresentTime >= expectedPresentTime &&
            predictedPresentTime - expectedPresentTime >= earlyLatchVsyncThreshold;
}

bool SurfaceFlinger::shouldLatchUnsignaled(const sp<Layer>& layer, const layer_state_t& state,
                                           size_t numStates, bool firstTransaction) const {
    if (enableLatchUnsignaledConfig == LatchUnsignaledConfig::Disabled) {
        ATRACE_FORMAT_INSTANT("%s: false (LatchUnsignaledConfig::Disabled)", __func__);
        return false;
    }

    if (enableLatchUnsignaledConfig == LatchUnsignaledConfig::Always) {
        ATRACE_FORMAT_INSTANT("%s: true (LatchUnsignaledConfig::Always)", __func__);
        return true;
    }

    // We only want to latch unsignaled when a single layer is updated in this
    // transaction (i.e. not a blast sync transaction).
    if (numStates != 1) {
        ATRACE_FORMAT_INSTANT("%s: false (numStates=%zu)", __func__, numStates);
        return false;
    }

    if (enableLatchUnsignaledConfig == LatchUnsignaledConfig::AutoSingleLayer) {
        if (!firstTransaction) {
            ATRACE_FORMAT_INSTANT("%s: false (LatchUnsignaledConfig::AutoSingleLayer; not first "
                                  "transaction)",
                                  __func__);
            return false;
        }

        // We don't want to latch unsignaled if are in early / client composition
        // as it leads to jank due to RenderEngine waiting for unsignaled buffer
        // or window animations being slow.
        if (mScheduler->vsyncModulator().isVsyncConfigEarly()) {
            ATRACE_FORMAT_INSTANT("%s: false (LatchUnsignaledConfig::AutoSingleLayer; "
                                  "isVsyncConfigEarly)",
                                  __func__);
            return false;
        }
    }

    return layer->isSimpleBufferUpdate(state);
}

status_t SurfaceFlinger::setTransactionState(
        const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& states,
        const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
        InputWindowCommands inputWindowCommands, int64_t desiredPresentTime, bool isAutoTimestamp,
        const std::vector<client_cache_t>& uncacheBuffers, bool hasListenerCallbacks,
        const std::vector<ListenerCallbacks>& listenerCallbacks, uint64_t transactionId,
        const std::vector<uint64_t>& mergedTransactionIds) {
    ATRACE_CALL();

    IPCThreadState* ipc = IPCThreadState::self();
    const int originPid = ipc->getCallingPid();
    const int originUid = ipc->getCallingUid();
    uint32_t permissions = LayerStatePermissions::getTransactionPermissions(originPid, originUid);
    for (auto composerState : states) {
        composerState.state.sanitize(permissions);
    }

    for (DisplayState display : displays) {
        display.sanitize(permissions);
    }

    if (!inputWindowCommands.empty() &&
        (permissions & layer_state_t::Permission::ACCESS_SURFACE_FLINGER) == 0) {
        ALOGE("Only privileged callers are allowed to send input commands.");
        inputWindowCommands.clear();
    }

    if (flags & (eEarlyWakeupStart | eEarlyWakeupEnd)) {
        const bool hasPermission =
                (permissions & layer_state_t::Permission::ACCESS_SURFACE_FLINGER) ||
                callingThreadHasPermission(sWakeupSurfaceFlinger);
        if (!hasPermission) {
            ALOGE("Caller needs permission android.permission.WAKEUP_SURFACE_FLINGER to use "
                  "eEarlyWakeup[Start|End] flags");
            flags &= ~(eEarlyWakeupStart | eEarlyWakeupEnd);
        }
    }

    const int64_t postTime = systemTime();

    std::vector<uint64_t> uncacheBufferIds;
    uncacheBufferIds.reserve(uncacheBuffers.size());
    for (const auto& uncacheBuffer : uncacheBuffers) {
        sp<GraphicBuffer> buffer = ClientCache::getInstance().erase(uncacheBuffer);
        if (buffer != nullptr) {
            uncacheBufferIds.push_back(buffer->getId());
        }
    }

    std::vector<ResolvedComposerState> resolvedStates;
    resolvedStates.reserve(states.size());
    for (auto& state : states) {
        resolvedStates.emplace_back(std::move(state));
        auto& resolvedState = resolvedStates.back();
        if (resolvedState.state.hasBufferChanges() && resolvedState.state.hasValidBuffer() &&
            resolvedState.state.surface) {
            sp<Layer> layer = LayerHandle::getLayer(resolvedState.state.surface);
            std::string layerName = (layer) ?
                    layer->getDebugName() : std::to_string(resolvedState.state.layerId);
            resolvedState.externalTexture =
                    getExternalTextureFromBufferData(*resolvedState.state.bufferData,
                                                     layerName.c_str(), transactionId);
            if (resolvedState.externalTexture) {
                resolvedState.state.bufferData->buffer = resolvedState.externalTexture->getBuffer();
            }
            mBufferCountTracker.increment(resolvedState.state.surface->localBinder());
        }
        resolvedState.layerId = LayerHandle::getLayerId(resolvedState.state.surface);
        if (resolvedState.state.what & layer_state_t::eReparent) {
            resolvedState.parentId =
                    getLayerIdFromSurfaceControl(resolvedState.state.parentSurfaceControlForChild);
        }
        if (resolvedState.state.what & layer_state_t::eRelativeLayerChanged) {
            resolvedState.relativeParentId =
                    getLayerIdFromSurfaceControl(resolvedState.state.relativeLayerSurfaceControl);
        }
        if (resolvedState.state.what & layer_state_t::eInputInfoChanged) {
            wp<IBinder>& touchableRegionCropHandle =
                    resolvedState.state.windowInfoHandle->editInfo()->touchableRegionCropHandle;
            resolvedState.touchCropId =
                    LayerHandle::getLayerId(touchableRegionCropHandle.promote());
        }
    }

    TransactionState state{frameTimelineInfo,
                           resolvedStates,
                           displays,
                           flags,
                           applyToken,
                           std::move(inputWindowCommands),
                           desiredPresentTime,
                           isAutoTimestamp,
                           std::move(uncacheBufferIds),
                           postTime,
                           hasListenerCallbacks,
                           listenerCallbacks,
                           originPid,
                           originUid,
                           transactionId,
                           mergedTransactionIds};

    if (mTransactionTracing) {
        mTransactionTracing->addQueuedTransaction(state);
    }

    const auto schedule = [](uint32_t flags) {
        if (flags & eEarlyWakeupEnd) return TransactionSchedule::EarlyEnd;
        if (flags & eEarlyWakeupStart) return TransactionSchedule::EarlyStart;
        return TransactionSchedule::Late;
    }(state.flags);

    const auto frameHint = state.isFrameActive() ? FrameHint::kActive : FrameHint::kNone;
    mTransactionHandler.queueTransaction(std::move(state));
    setTransactionFlags(eTransactionFlushNeeded, schedule, applyToken, frameHint);
    return NO_ERROR;
}

bool SurfaceFlinger::applyTransactionState(const FrameTimelineInfo& frameTimelineInfo,
                                           std::vector<ResolvedComposerState>& states,
                                           Vector<DisplayState>& displays, uint32_t flags,
                                           const InputWindowCommands& inputWindowCommands,
                                           const int64_t desiredPresentTime, bool isAutoTimestamp,
                                           const std::vector<uint64_t>& uncacheBufferIds,
                                           const int64_t postTime, bool hasListenerCallbacks,
                                           const std::vector<ListenerCallbacks>& listenerCallbacks,
                                           int originPid, int originUid, uint64_t transactionId) {
    uint32_t transactionFlags = 0;
    if (!mLayerLifecycleManagerEnabled) {
        for (DisplayState& display : displays) {
            transactionFlags |= setDisplayStateLocked(display);
        }
    }

    // start and end registration for listeners w/ no surface so they can get their callback.  Note
    // that listeners with SurfaceControls will start registration during setClientStateLocked
    // below.
    for (const auto& listener : listenerCallbacks) {
        mTransactionCallbackInvoker.addEmptyTransaction(listener);
    }

    uint32_t clientStateFlags = 0;
    for (auto& resolvedState : states) {
        if (mLegacyFrontEndEnabled) {
            clientStateFlags |=
                    setClientStateLocked(frameTimelineInfo, resolvedState, desiredPresentTime,
                                         isAutoTimestamp, postTime, transactionId);

        } else /*mLayerLifecycleManagerEnabled*/ {
            clientStateFlags |= updateLayerCallbacksAndStats(frameTimelineInfo, resolvedState,
                                                             desiredPresentTime, isAutoTimestamp,
                                                             postTime, transactionId);
        }
        if ((flags & eAnimation) && resolvedState.state.surface) {
            if (const auto layer = LayerHandle::getLayer(resolvedState.state.surface)) {
                const auto layerProps = scheduler::LayerProps{
                        .visible = layer->isVisible(),
                        .bounds = layer->getBounds(),
                        .transform = layer->getTransform(),
                        .setFrameRateVote = layer->getFrameRateForLayerTree(),
                        .frameRateSelectionPriority = layer->getFrameRateSelectionPriority(),
                };
                layer->recordLayerHistoryAnimationTx(layerProps);
            }
        }
    }

    transactionFlags |= clientStateFlags;
    transactionFlags |= addInputWindowCommands(inputWindowCommands);

    for (uint64_t uncacheBufferId : uncacheBufferIds) {
        mBufferIdsToUncache.push_back(uncacheBufferId);
    }

    // If a synchronous transaction is explicitly requested without any changes, force a transaction
    // anyway. This can be used as a flush mechanism for previous async transactions.
    // Empty animation transaction can be used to simulate back-pressure, so also force a
    // transaction for empty animation transactions.
    if (transactionFlags == 0 && (flags & eAnimation)) {
        transactionFlags = eTransactionNeeded;
    }

    bool needsTraversal = false;
    if (transactionFlags) {
        // We are on the main thread, we are about to perform a traversal. Clear the traversal bit
        // so we don't have to wake up again next frame to perform an unnecessary traversal.
        if (transactionFlags & eTraversalNeeded) {
            transactionFlags = transactionFlags & (~eTraversalNeeded);
            needsTraversal = true;
        }
        if (transactionFlags) {
            setTransactionFlags(transactionFlags);
        }
    }

    return needsTraversal;
}

bool SurfaceFlinger::applyAndCommitDisplayTransactionStates(
        std::vector<TransactionState>& transactions) {
    Mutex::Autolock lock(mStateLock);
    bool needsTraversal = false;
    uint32_t transactionFlags = 0;
    for (auto& transaction : transactions) {
        for (DisplayState& display : transaction.displays) {
            transactionFlags |= setDisplayStateLocked(display);
        }
    }

    if (transactionFlags) {
        // We are on the main thread, we are about to perform a traversal. Clear the traversal bit
        // so we don't have to wake up again next frame to perform an unnecessary traversal.
        if (transactionFlags & eTraversalNeeded) {
            transactionFlags = transactionFlags & (~eTraversalNeeded);
            needsTraversal = true;
        }
        if (transactionFlags) {
            setTransactionFlags(transactionFlags);
        }
    }

    mFrontEndDisplayInfosChanged = mTransactionFlags & eDisplayTransactionNeeded;
    if (mFrontEndDisplayInfosChanged && !mLegacyFrontEndEnabled) {
        processDisplayChangesLocked();
        mFrontEndDisplayInfos.clear();
        for (const auto& [_, display] : mDisplays) {
            mFrontEndDisplayInfos.try_emplace(display->getLayerStack(), display->getFrontEndInfo());
        }
        needsTraversal = true;
    }

    return needsTraversal;
}

uint32_t SurfaceFlinger::setDisplayStateLocked(const DisplayState& s) {
    const ssize_t index = mCurrentState.displays.indexOfKey(s.token);
    if (index < 0) return 0;

    uint32_t flags = 0;
    DisplayDeviceState& state = mCurrentState.displays.editValueAt(index);

    const uint32_t what = s.what;
    if (what & DisplayState::eSurfaceChanged) {
        if (IInterface::asBinder(state.surface) != IInterface::asBinder(s.surface)) {
            state.surface = s.surface;
            flags |= eDisplayTransactionNeeded;
        }
    }
    if (what & DisplayState::eLayerStackChanged) {
        if (state.layerStack != s.layerStack) {
            state.layerStack = s.layerStack;
            flags |= eDisplayTransactionNeeded;
        }
    }
    if (what & DisplayState::eFlagsChanged) {
        if (state.flags != s.flags) {
            state.flags = s.flags;
            flags |= eDisplayTransactionNeeded;
        }
    }
    if (what & DisplayState::eDisplayProjectionChanged) {
        if (state.orientation != s.orientation) {
            state.orientation = s.orientation;
            flags |= eDisplayTransactionNeeded;
        }
        if (state.orientedDisplaySpaceRect != s.orientedDisplaySpaceRect) {
            state.orientedDisplaySpaceRect = s.orientedDisplaySpaceRect;
            flags |= eDisplayTransactionNeeded;
        }
        if (state.layerStackSpaceRect != s.layerStackSpaceRect) {
            state.layerStackSpaceRect = s.layerStackSpaceRect;
            flags |= eDisplayTransactionNeeded;
        }
    }
    if (what & DisplayState::eDisplaySizeChanged) {
        if (state.width != s.width) {
            state.width = s.width;
            flags |= eDisplayTransactionNeeded;
        }
        if (state.height != s.height) {
            state.height = s.height;
            flags |= eDisplayTransactionNeeded;
        }
    }

    return flags;
}

bool SurfaceFlinger::callingThreadHasUnscopedSurfaceFlingerAccess(bool usePermissionCache) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if ((uid != AID_GRAPHICS && uid != AID_SYSTEM) &&
        (usePermissionCache ? !PermissionCache::checkPermission(sAccessSurfaceFlinger, pid, uid)
                            : !checkPermission(sAccessSurfaceFlinger, pid, uid))) {
        return false;
    }
    return true;
}

uint32_t SurfaceFlinger::setClientStateLocked(const FrameTimelineInfo& frameTimelineInfo,
                                              ResolvedComposerState& composerState,
                                              int64_t desiredPresentTime, bool isAutoTimestamp,
                                              int64_t postTime, uint64_t transactionId) {
    layer_state_t& s = composerState.state;

    std::vector<ListenerCallbacks> filteredListeners;
    for (auto& listener : s.listeners) {
        // Starts a registration but separates the callback ids according to callback type. This
        // allows the callback invoker to send on latch callbacks earlier.
        // note that startRegistration will not re-register if the listener has
        // already be registered for a prior surface control

        ListenerCallbacks onCommitCallbacks = listener.filter(CallbackId::Type::ON_COMMIT);
        if (!onCommitCallbacks.callbackIds.empty()) {
            filteredListeners.push_back(onCommitCallbacks);
        }

        ListenerCallbacks onCompleteCallbacks = listener.filter(CallbackId::Type::ON_COMPLETE);
        if (!onCompleteCallbacks.callbackIds.empty()) {
            filteredListeners.push_back(onCompleteCallbacks);
        }
    }

    const uint64_t what = s.what;
    uint32_t flags = 0;
    sp<Layer> layer = nullptr;
    if (s.surface) {
        layer = LayerHandle::getLayer(s.surface);
    } else {
        // The client may provide us a null handle. Treat it as if the layer was removed.
        ALOGW("Attempt to set client state with a null layer handle");
    }
    if (layer == nullptr) {
        for (auto& [listener, callbackIds] : s.listeners) {
            mTransactionCallbackInvoker.addCallbackHandle(sp<CallbackHandle>::make(listener,
                                                                                   callbackIds,
                                                                                   s.surface),
                                                          std::vector<JankData>());
        }
        return 0;
    }
    MUTEX_ALIAS(mStateLock, layer->mFlinger->mStateLock);

    ui::LayerStack oldLayerStack = layer->getLayerStack(LayerVector::StateSet::Current);

    // Only set by BLAST adapter layers
    if (what & layer_state_t::eProducerDisconnect) {
        layer->onDisconnect();
    }

    if (what & layer_state_t::ePositionChanged) {
        if (layer->setPosition(s.x, s.y)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eLayerChanged) {
        // NOTE: index needs to be calculated before we update the state
        const auto& p = layer->getParent();
        if (p == nullptr) {
            ssize_t idx = mCurrentState.layersSortedByZ.indexOf(layer);
            if (layer->setLayer(s.z) && idx >= 0) {
                mCurrentState.layersSortedByZ.removeAt(idx);
                mCurrentState.layersSortedByZ.add(layer);
                // we need traversal (state changed)
                // AND transaction (list changed)
                flags |= eTransactionNeeded|eTraversalNeeded;
            }
        } else {
            if (p->setChildLayer(layer, s.z)) {
                flags |= eTransactionNeeded|eTraversalNeeded;
            }
        }
    }
    if (what & layer_state_t::eRelativeLayerChanged) {
        // NOTE: index needs to be calculated before we update the state
        const auto& p = layer->getParent();
        const auto& relativeHandle = s.relativeLayerSurfaceControl ?
                s.relativeLayerSurfaceControl->getHandle() : nullptr;
        if (p == nullptr) {
            ssize_t idx = mCurrentState.layersSortedByZ.indexOf(layer);
            if (layer->setRelativeLayer(relativeHandle, s.z) &&
                idx >= 0) {
                mCurrentState.layersSortedByZ.removeAt(idx);
                mCurrentState.layersSortedByZ.add(layer);
                // we need traversal (state changed)
                // AND transaction (list changed)
                flags |= eTransactionNeeded|eTraversalNeeded;
            }
        } else {
            if (p->setChildRelativeLayer(layer, relativeHandle, s.z)) {
                flags |= eTransactionNeeded|eTraversalNeeded;
            }
        }
    }
    if (what & layer_state_t::eAlphaChanged) {
        if (layer->setAlpha(s.color.a)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eColorChanged) {
        if (layer->setColor(s.color.rgb)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eColorTransformChanged) {
        if (layer->setColorTransform(s.colorTransform)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eBackgroundColorChanged) {
        if (layer->setBackgroundColor(s.bgColor.rgb, s.bgColor.a, s.bgColorDataspace)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eMatrixChanged) {
        if (layer->setMatrix(s.matrix)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eTransparentRegionChanged) {
        if (layer->setTransparentRegionHint(s.transparentRegion))
            flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eFlagsChanged) {
        if (layer->setFlags(s.flags, s.mask)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eCornerRadiusChanged) {
        if (layer->setCornerRadius(s.cornerRadius))
            flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eBackgroundBlurRadiusChanged && mSupportsBlur) {
        if (layer->setBackgroundBlurRadius(s.backgroundBlurRadius)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eBlurRegionsChanged) {
        if (layer->setBlurRegions(s.blurRegions)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eRenderBorderChanged) {
        if (layer->enableBorder(s.borderEnabled, s.borderWidth, s.borderColor)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eLayerStackChanged) {
        ssize_t idx = mCurrentState.layersSortedByZ.indexOf(layer);
        // We only allow setting layer stacks for top level layers,
        // everything else inherits layer stack from its parent.
        if (layer->hasParent()) {
            ALOGE("Attempt to set layer stack on layer with parent (%s) is invalid",
                  layer->getDebugName());
        } else if (idx < 0) {
            ALOGE("Attempt to set layer stack on layer without parent (%s) that "
                  "that also does not appear in the top level layer list. Something"
                  " has gone wrong.",
                  layer->getDebugName());
        } else if (layer->setLayerStack(s.layerStack)) {
            mCurrentState.layersSortedByZ.removeAt(idx);
            mCurrentState.layersSortedByZ.add(layer);
            // we need traversal (state changed)
            // AND transaction (list changed)
            flags |= eTransactionNeeded | eTraversalNeeded | eTransformHintUpdateNeeded;
        }
    }
    if (what & layer_state_t::eBufferTransformChanged) {
        if (layer->setTransform(s.bufferTransform)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eTransformToDisplayInverseChanged) {
        if (layer->setTransformToDisplayInverse(s.transformToDisplayInverse))
            flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eCropChanged) {
        if (layer->setCrop(s.crop)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eDataspaceChanged) {
        if (layer->setDataspace(s.dataspace)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eSurfaceDamageRegionChanged) {
        if (layer->setSurfaceDamageRegion(s.surfaceDamageRegion)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eApiChanged) {
        if (layer->setApi(s.api)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eSidebandStreamChanged) {
        if (layer->setSidebandStream(s.sidebandStream)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eInputInfoChanged) {
        layer->setInputInfo(*s.windowInfoHandle->getInfo());
        flags |= eTraversalNeeded;
    }
    std::optional<nsecs_t> dequeueBufferTimestamp;
    if (what & layer_state_t::eMetadataChanged) {
        dequeueBufferTimestamp = s.metadata.getInt64(gui::METADATA_DEQUEUE_TIME);

        if (const int32_t gameMode = s.metadata.getInt32(gui::METADATA_GAME_MODE, -1);
            gameMode != -1) {
            // The transaction will be received on the Task layer and needs to be applied to all
            // child layers. Child layers that are added at a later point will obtain the game mode
            // info through addChild().
            layer->setGameModeForTree(static_cast<GameMode>(gameMode));
        }

        if (layer->setMetadata(s.metadata)) {
            flags |= eTraversalNeeded;
            mLayerMetadataSnapshotNeeded = true;
        }
    }
    if (what & layer_state_t::eColorSpaceAgnosticChanged) {
        if (layer->setColorSpaceAgnostic(s.colorSpaceAgnostic)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eShadowRadiusChanged) {
        if (layer->setShadowRadius(s.shadowRadius)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eDefaultFrameRateCompatibilityChanged) {
        const auto compatibility =
                Layer::FrameRate::convertCompatibility(s.defaultFrameRateCompatibility);

        if (layer->setDefaultFrameRateCompatibility(compatibility)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eFrameRateSelectionPriority) {
        if (layer->setFrameRateSelectionPriority(s.frameRateSelectionPriority)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eFrameRateChanged) {
        const auto compatibility =
            Layer::FrameRate::convertCompatibility(s.frameRateCompatibility);
        const auto strategy =
            Layer::FrameRate::convertChangeFrameRateStrategy(s.changeFrameRateStrategy);

        if (layer->setFrameRate(
                Layer::FrameRate(Fps::fromValue(s.frameRate), compatibility, strategy))) {
          flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eFixedTransformHintChanged) {
        if (layer->setFixedTransformHint(s.fixedTransformHint)) {
            flags |= eTraversalNeeded | eTransformHintUpdateNeeded;
        }
    }
    if (what & layer_state_t::eAutoRefreshChanged) {
        layer->setAutoRefresh(s.autoRefresh);
    }
    if (what & layer_state_t::eDimmingEnabledChanged) {
        if (layer->setDimmingEnabled(s.dimmingEnabled)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eExtendedRangeBrightnessChanged) {
        if (layer->setExtendedRangeBrightness(s.currentHdrSdrRatio, s.desiredHdrSdrRatio)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eCachingHintChanged) {
        if (layer->setCachingHint(s.cachingHint)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eHdrMetadataChanged) {
        if (layer->setHdrMetadata(s.hdrMetadata)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eTrustedOverlayChanged) {
        if (layer->setTrustedOverlay(s.isTrustedOverlay)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eStretchChanged) {
        if (layer->setStretchEffect(s.stretchEffect)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eBufferCropChanged) {
        if (layer->setBufferCrop(s.bufferCrop)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eDestinationFrameChanged) {
        if (layer->setDestinationFrame(s.destinationFrame)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eDropInputModeChanged) {
        if (layer->setDropInputMode(s.dropInputMode)) {
            flags |= eTraversalNeeded;
            mUpdateInputInfo = true;
        }
    }
    // This has to happen after we reparent children because when we reparent to null we remove
    // child layers from current state and remove its relative z. If the children are reparented in
    // the same transaction, then we have to make sure we reparent the children first so we do not
    // lose its relative z order.
    if (what & layer_state_t::eReparent) {
        bool hadParent = layer->hasParent();
        auto parentHandle = (s.parentSurfaceControlForChild)
                ? s.parentSurfaceControlForChild->getHandle()
                : nullptr;
        if (layer->reparent(parentHandle)) {
            if (!hadParent) {
                layer->setIsAtRoot(false);
                mCurrentState.layersSortedByZ.remove(layer);
            }
            flags |= eTransactionNeeded | eTraversalNeeded;
        }
    }
    std::vector<sp<CallbackHandle>> callbackHandles;
    if ((what & layer_state_t::eHasListenerCallbacksChanged) && (!filteredListeners.empty())) {
        for (auto& [listener, callbackIds] : filteredListeners) {
            callbackHandles.emplace_back(
                    sp<CallbackHandle>::make(listener, callbackIds, s.surface));
        }
    }

    if (what & layer_state_t::eBufferChanged) {
        if (layer->setBuffer(composerState.externalTexture, *s.bufferData, postTime,
                             desiredPresentTime, isAutoTimestamp, dequeueBufferTimestamp,
                             frameTimelineInfo)) {
            flags |= eTraversalNeeded;
        }
    } else if (frameTimelineInfo.vsyncId != FrameTimelineInfo::INVALID_VSYNC_ID) {
        layer->setFrameTimelineVsyncForBufferlessTransaction(frameTimelineInfo, postTime);
    }

    if ((what & layer_state_t::eBufferChanged) == 0) {
        layer->setDesiredPresentTime(desiredPresentTime, isAutoTimestamp);
    }

    if (what & layer_state_t::eTrustedPresentationInfoChanged) {
        if (layer->setTrustedPresentationInfo(s.trustedPresentationThresholds,
                                              s.trustedPresentationListener)) {
            flags |= eTraversalNeeded;
        }
    }

    if (what & layer_state_t::eFlushJankData) {
        // Do nothing. Processing the transaction completed listeners currently cause the flush.
    }

    if (layer->setTransactionCompletedListeners(callbackHandles,
                                                layer->willPresentCurrentTransaction() ||
                                                        layer->willReleaseBufferOnLatch())) {
        flags |= eTraversalNeeded;
    }

    // Do not put anything that updates layer state or modifies flags after
    // setTransactionCompletedListener

    // if the layer has been parented on to a new display, update its transform hint.
    if (((flags & eTransformHintUpdateNeeded) == 0) &&
        oldLayerStack != layer->getLayerStack(LayerVector::StateSet::Current)) {
        flags |= eTransformHintUpdateNeeded;
    }

    return flags;
}

uint32_t SurfaceFlinger::updateLayerCallbacksAndStats(const FrameTimelineInfo& frameTimelineInfo,
                                                      ResolvedComposerState& composerState,
                                                      int64_t desiredPresentTime,
                                                      bool isAutoTimestamp, int64_t postTime,
                                                      uint64_t transactionId) {
    layer_state_t& s = composerState.state;

    std::vector<ListenerCallbacks> filteredListeners;
    for (auto& listener : s.listeners) {
        // Starts a registration but separates the callback ids according to callback type. This
        // allows the callback invoker to send on latch callbacks earlier.
        // note that startRegistration will not re-register if the listener has
        // already be registered for a prior surface control

        ListenerCallbacks onCommitCallbacks = listener.filter(CallbackId::Type::ON_COMMIT);
        if (!onCommitCallbacks.callbackIds.empty()) {
            filteredListeners.push_back(onCommitCallbacks);
        }

        ListenerCallbacks onCompleteCallbacks = listener.filter(CallbackId::Type::ON_COMPLETE);
        if (!onCompleteCallbacks.callbackIds.empty()) {
            filteredListeners.push_back(onCompleteCallbacks);
        }
    }

    const uint64_t what = s.what;
    uint32_t flags = 0;
    sp<Layer> layer = nullptr;
    if (s.surface) {
        layer = LayerHandle::getLayer(s.surface);
    } else {
        // The client may provide us a null handle. Treat it as if the layer was removed.
        ALOGW("Attempt to set client state with a null layer handle");
    }
    if (layer == nullptr) {
        for (auto& [listener, callbackIds] : s.listeners) {
            mTransactionCallbackInvoker.addCallbackHandle(sp<CallbackHandle>::make(listener,
                                                                                   callbackIds,
                                                                                   s.surface),
                                                          std::vector<JankData>());
        }
        return 0;
    }
    if (what & layer_state_t::eProducerDisconnect) {
        layer->onDisconnect();
    }
    std::optional<nsecs_t> dequeueBufferTimestamp;
    if (what & layer_state_t::eMetadataChanged) {
        dequeueBufferTimestamp = s.metadata.getInt64(gui::METADATA_DEQUEUE_TIME);
    }

    std::vector<sp<CallbackHandle>> callbackHandles;
    if ((what & layer_state_t::eHasListenerCallbacksChanged) && (!filteredListeners.empty())) {
        for (auto& [listener, callbackIds] : filteredListeners) {
            callbackHandles.emplace_back(
                    sp<CallbackHandle>::make(listener, callbackIds, s.surface));
        }
    }
    // TODO(b/238781169) remove after screenshot refactor, currently screenshots
    // requires to read drawing state from binder thread. So we need to fix that
    // before removing this.
    if (what & layer_state_t::eCropChanged) {
        if (layer->setCrop(s.crop)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eSidebandStreamChanged) {
        if (layer->setSidebandStream(s.sidebandStream)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eBufferChanged) {
        std::optional<ui::Transform::RotationFlags> transformHint = std::nullopt;
        frontend::LayerSnapshot* snapshot = mLayerSnapshotBuilder.getSnapshot(layer->sequence);
        if (snapshot) {
            transformHint = snapshot->transformHint;
        }
        layer->setTransformHint(transformHint);
        if (layer->setBuffer(composerState.externalTexture, *s.bufferData, postTime,
                             desiredPresentTime, isAutoTimestamp, dequeueBufferTimestamp,
                             frameTimelineInfo)) {
            flags |= eTraversalNeeded;
        }
        mLayersWithQueuedFrames.emplace(layer);
    } else if (frameTimelineInfo.vsyncId != FrameTimelineInfo::INVALID_VSYNC_ID) {
        layer->setFrameTimelineVsyncForBufferlessTransaction(frameTimelineInfo, postTime);
    }

    if ((what & layer_state_t::eBufferChanged) == 0) {
        layer->setDesiredPresentTime(desiredPresentTime, isAutoTimestamp);
    }

    if (what & layer_state_t::eTrustedPresentationInfoChanged) {
        if (layer->setTrustedPresentationInfo(s.trustedPresentationThresholds,
                                              s.trustedPresentationListener)) {
            flags |= eTraversalNeeded;
        }
    }

    const auto& requestedLayerState = mLayerLifecycleManager.getLayerFromId(layer->getSequence());
    bool willPresentCurrentTransaction = requestedLayerState &&
            (requestedLayerState->hasReadyFrame() ||
             requestedLayerState->willReleaseBufferOnLatch());
    if (layer->setTransactionCompletedListeners(callbackHandles, willPresentCurrentTransaction))
        flags |= eTraversalNeeded;

    return flags;
}

uint32_t SurfaceFlinger::addInputWindowCommands(const InputWindowCommands& inputWindowCommands) {
    bool hasChanges = mInputWindowCommands.merge(inputWindowCommands);
    return hasChanges ? eTraversalNeeded : 0;
}

status_t SurfaceFlinger::mirrorLayer(const LayerCreationArgs& args,
                                     const sp<IBinder>& mirrorFromHandle,
                                     gui::CreateSurfaceResult& outResult) {
    if (!mirrorFromHandle) {
        return NAME_NOT_FOUND;
    }

    sp<Layer> mirrorLayer;
    sp<Layer> mirrorFrom;
    LayerCreationArgs mirrorArgs = LayerCreationArgs::fromOtherArgs(args);
    {
        Mutex::Autolock _l(mStateLock);
        mirrorFrom = LayerHandle::getLayer(mirrorFromHandle);
        if (!mirrorFrom) {
            return NAME_NOT_FOUND;
        }
        mirrorArgs.flags |= ISurfaceComposerClient::eNoColorFill;
        mirrorArgs.mirrorLayerHandle = mirrorFromHandle;
        mirrorArgs.addToRoot = false;
        status_t result = createEffectLayer(mirrorArgs, &outResult.handle, &mirrorLayer);
        if (result != NO_ERROR) {
            return result;
        }

        mirrorLayer->setClonedChild(mirrorFrom->createClone(mirrorLayer->getSequence()));
    }

    outResult.layerId = mirrorLayer->sequence;
    outResult.layerName = String16(mirrorLayer->getDebugName());
    return addClientLayer(mirrorArgs, outResult.handle, mirrorLayer /* layer */,
                          nullptr /* parent */, nullptr /* outTransformHint */);
}

status_t SurfaceFlinger::mirrorDisplay(DisplayId displayId, const LayerCreationArgs& args,
                                       gui::CreateSurfaceResult& outResult) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();
    if (uid != AID_ROOT && uid != AID_GRAPHICS && uid != AID_SYSTEM && uid != AID_SHELL) {
        ALOGE("Permission denied when trying to mirror display");
        return PERMISSION_DENIED;
    }

    ui::LayerStack layerStack;
    sp<Layer> rootMirrorLayer;
    status_t result = 0;

    {
        Mutex::Autolock lock(mStateLock);

        const auto display = getDisplayDeviceLocked(displayId);
        if (!display) {
            return NAME_NOT_FOUND;
        }

        layerStack = display->getLayerStack();
        LayerCreationArgs mirrorArgs = LayerCreationArgs::fromOtherArgs(args);
        mirrorArgs.flags |= ISurfaceComposerClient::eNoColorFill;
        mirrorArgs.addToRoot = true;
        mirrorArgs.layerStackToMirror = layerStack;
        result = createEffectLayer(mirrorArgs, &outResult.handle, &rootMirrorLayer);
        outResult.layerId = rootMirrorLayer->sequence;
        outResult.layerName = String16(rootMirrorLayer->getDebugName());
        result |= addClientLayer(mirrorArgs, outResult.handle, rootMirrorLayer /* layer */,
                                 nullptr /* parent */, nullptr /* outTransformHint */);
    }

    if (result != NO_ERROR) {
        return result;
    }

    if (mLegacyFrontEndEnabled) {
        std::scoped_lock<std::mutex> lock(mMirrorDisplayLock);
        mMirrorDisplays.emplace_back(layerStack, outResult.handle, args.client);
    }

    setTransactionFlags(eTransactionFlushNeeded);
    return NO_ERROR;
}

status_t SurfaceFlinger::createLayer(LayerCreationArgs& args, gui::CreateSurfaceResult& outResult) {
    status_t result = NO_ERROR;

    sp<Layer> layer;

    switch (args.flags & ISurfaceComposerClient::eFXSurfaceMask) {
        case ISurfaceComposerClient::eFXSurfaceBufferQueue:
        case ISurfaceComposerClient::eFXSurfaceContainer:
        case ISurfaceComposerClient::eFXSurfaceBufferState:
            args.flags |= ISurfaceComposerClient::eNoColorFill;
            FMT_FALLTHROUGH;
        case ISurfaceComposerClient::eFXSurfaceEffect: {
            result = createBufferStateLayer(args, &outResult.handle, &layer);
            std::atomic<int32_t>* pendingBufferCounter = layer->getPendingBufferCounter();
            if (pendingBufferCounter) {
                std::string counterName = layer->getPendingBufferCounterName();
                mBufferCountTracker.add(outResult.handle->localBinder(), counterName,
                                        pendingBufferCounter);
            }
        } break;
        default:
            result = BAD_VALUE;
            break;
    }

    if (result != NO_ERROR) {
        return result;
    }

    args.addToRoot = args.addToRoot && callingThreadHasUnscopedSurfaceFlingerAccess();
    // We can safely promote the parent layer in binder thread because we have a strong reference
    // to the layer's handle inside this scope.
    sp<Layer> parent = LayerHandle::getLayer(args.parentHandle.promote());
    if (args.parentHandle != nullptr && parent == nullptr) {
        ALOGE("Invalid parent handle %p", args.parentHandle.promote().get());
        args.addToRoot = false;
    }

    uint32_t outTransformHint;
    result = addClientLayer(args, outResult.handle, layer, parent, &outTransformHint);
    if (result != NO_ERROR) {
        return result;
    }

    outResult.transformHint = static_cast<int32_t>(outTransformHint);
    outResult.layerId = layer->sequence;
    outResult.layerName = String16(layer->getDebugName());
    return result;
}

status_t SurfaceFlinger::createBufferStateLayer(LayerCreationArgs& args, sp<IBinder>* handle,
                                                sp<Layer>* outLayer) {
    args.textureName = getNewTexture();
    *outLayer = getFactory().createBufferStateLayer(args);
    *handle = (*outLayer)->getHandle();
    return NO_ERROR;
}

status_t SurfaceFlinger::createEffectLayer(const LayerCreationArgs& args, sp<IBinder>* handle,
                                           sp<Layer>* outLayer) {
    *outLayer = getFactory().createEffectLayer(args);
    *handle = (*outLayer)->getHandle();
    return NO_ERROR;
}

void SurfaceFlinger::markLayerPendingRemovalLocked(const sp<Layer>& layer) {
    mLayersPendingRemoval.add(layer);
    mLayersRemoved = true;
    setTransactionFlags(eTransactionNeeded);
}

void SurfaceFlinger::onHandleDestroyed(BBinder* handle, sp<Layer>& layer, uint32_t layerId) {
    {
        std::scoped_lock<std::mutex> lock(mCreatedLayersLock);
        mDestroyedHandles.emplace_back(layerId);
    }

    mTransactionHandler.onLayerDestroyed(layerId);

    Mutex::Autolock lock(mStateLock);
    markLayerPendingRemovalLocked(layer);
    layer->onHandleDestroyed();
    mBufferCountTracker.remove(handle);
    layer.clear();

    setTransactionFlags(eTransactionFlushNeeded);
}

void SurfaceFlinger::initializeDisplays() {
    const auto display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());
    if (!display) return;

    const sp<IBinder> token = display->getDisplayToken().promote();
    LOG_ALWAYS_FATAL_IF(token == nullptr);

    TransactionState state;
    state.inputWindowCommands = mInputWindowCommands;
    const nsecs_t now = systemTime();
    state.desiredPresentTime = now;
    state.postTime = now;
    state.originPid = mPid;
    state.originUid = static_cast<int>(getuid());
    const uint64_t transactionId = (static_cast<uint64_t>(mPid) << 32) | mUniqueTransactionId++;
    state.id = transactionId;

    // reset screen orientation and use primary layer stack
    Vector<DisplayState> displays;
    DisplayState d;
    d.what = DisplayState::eDisplayProjectionChanged |
             DisplayState::eLayerStackChanged;
    d.token = token;
    d.layerStack = ui::DEFAULT_LAYER_STACK;
    d.orientation = ui::ROTATION_0;
    d.orientedDisplaySpaceRect.makeInvalid();
    d.layerStackSpaceRect.makeInvalid();
    d.width = 0;
    d.height = 0;
    state.displays.add(d);

    std::vector<TransactionState> transactions;
    transactions.emplace_back(state);

    if (mLegacyFrontEndEnabled) {
        applyTransactions(transactions, VsyncId{0});
    } else {
        applyAndCommitDisplayTransactionStates(transactions);
    }

    {
        ftl::FakeGuard guard(mStateLock);
        setPowerModeInternal(display, hal::PowerMode::ON);
    }
}

void SurfaceFlinger::setPowerModeInternal(const sp<DisplayDevice>& display, hal::PowerMode mode) {
    if (display->isVirtual()) {
        ALOGE("%s: Invalid operation on virtual display", __func__);
        return;
    }

    const auto displayId = display->getPhysicalId();
    ALOGD("Setting power mode %d on display %s", mode, to_string(displayId).c_str());

    const auto currentModeOpt = display->getPowerMode();
    if (currentModeOpt == mode) {
        return;
    }

    const bool isInternalDisplay = mPhysicalDisplays.get(displayId)
                                           .transform(&PhysicalDisplay::isInternal)
                                           .value_or(false);

    const auto activeDisplay = getDisplayDeviceLocked(mActiveDisplayId);

    ALOGW_IF(display != activeDisplay && isInternalDisplay && activeDisplay &&
                     activeDisplay->isPoweredOn(),
             "Trying to change power mode on inactive display without powering off active display");

    display->setPowerMode(mode);

    const auto refreshRate = display->refreshRateSelector().getActiveMode().modePtr->getFps();
    if (!currentModeOpt || *currentModeOpt == hal::PowerMode::OFF) {
        // Turn on the display

        // Activate the display (which involves a modeset to the active mode) when the inner or
        // outer display of a foldable is powered on. This condition relies on the above
        // DisplayDevice::setPowerMode. If `display` and `activeDisplay` are the same display,
        // then the `activeDisplay->isPoweredOn()` below is true, such that the display is not
        // activated every time it is powered on.
        //
        // TODO(b/255635821): Remove the concept of active display.
        if (isInternalDisplay && (!activeDisplay || !activeDisplay->isPoweredOn())) {
            onActiveDisplayChangedLocked(activeDisplay.get(), *display);
        }

        if (displayId == mActiveDisplayId) {
            // TODO(b/281692563): Merge the syscalls. For now, keep uclamp in a separate syscall and
            // set it before SCHED_FIFO due to b/190237315.
            if (setSchedAttr(true) != NO_ERROR) {
                ALOGW("Failed to set uclamp.min after powering on active display: %s",
                      strerror(errno));
            }
            if (setSchedFifo(true) != NO_ERROR) {
                ALOGW("Failed to set SCHED_FIFO after powering on active display: %s",
                      strerror(errno));
            }
        }

        getHwComposer().setPowerMode(displayId, mode);
        if (displayId == mActiveDisplayId && mode != hal::PowerMode::DOZE_SUSPEND) {
            const bool enable =
                    mScheduler->getVsyncSchedule(displayId)->getPendingHardwareVsyncState();
            requestHardwareVsync(displayId, enable);

            mScheduler->enableSyntheticVsync(false);

            constexpr bool kAllowToEnable = true;
            mScheduler->resyncToHardwareVsync(displayId, kAllowToEnable, refreshRate);
        }

        mVisibleRegionsDirty = true;
        scheduleComposite(FrameHint::kActive);
    } else if (mode == hal::PowerMode::OFF) {
        // Turn off the display

        if (displayId == mActiveDisplayId) {
            if (const auto display = getActivatableDisplay()) {
                onActiveDisplayChangedLocked(activeDisplay.get(), *display);
            } else {
                if (setSchedFifo(false) != NO_ERROR) {
                    ALOGW("Failed to set SCHED_OTHER after powering off active display: %s",
                          strerror(errno));
                }
                if (setSchedAttr(false) != NO_ERROR) {
                    ALOGW("Failed set uclamp.min after powering off active display: %s",
                          strerror(errno));
                }

                if (*currentModeOpt != hal::PowerMode::DOZE_SUSPEND) {
                    mScheduler->disableHardwareVsync(displayId, true);
                    mScheduler->enableSyntheticVsync();
                }
            }
        }

        // Disable VSYNC before turning off the display.
        requestHardwareVsync(displayId, false);
        getHwComposer().setPowerMode(displayId, mode);

        mVisibleRegionsDirty = true;
        // from this point on, SF will stop drawing on this display
    } else if (mode == hal::PowerMode::DOZE || mode == hal::PowerMode::ON) {
        // Update display while dozing
        getHwComposer().setPowerMode(displayId, mode);
        if (displayId == mActiveDisplayId && *currentModeOpt == hal::PowerMode::DOZE_SUSPEND) {
            ALOGI("Force repainting for DOZE_SUSPEND -> DOZE or ON.");
            mVisibleRegionsDirty = true;
            scheduleRepaint();
            mScheduler->enableSyntheticVsync(false);
            mScheduler->resyncToHardwareVsync(displayId, true /* allowToEnable */, refreshRate);
        }
    } else if (mode == hal::PowerMode::DOZE_SUSPEND) {
        // Leave display going to doze
        if (displayId == mActiveDisplayId) {
            mScheduler->disableHardwareVsync(displayId, true);
            mScheduler->enableSyntheticVsync();
        }
        getHwComposer().setPowerMode(displayId, mode);
    } else {
        ALOGE("Attempting to set unknown power mode: %d\n", mode);
        getHwComposer().setPowerMode(displayId, mode);
    }

    if (displayId == mActiveDisplayId) {
        mTimeStats->setPowerMode(mode);
        mRefreshRateStats->setPowerMode(mode);
    }

    mScheduler->setDisplayPowerMode(displayId, mode);

    ALOGD("Finished setting power mode %d on display %s", mode, to_string(displayId).c_str());
}

void SurfaceFlinger::setPowerMode(const sp<IBinder>& displayToken, int mode) {
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) FTL_FAKE_GUARD(
                                               kMainThreadContext) {
        const auto display = getDisplayDeviceLocked(displayToken);
        if (!display) {
            ALOGE("Attempt to set power mode %d for invalid display token %p", mode,
                  displayToken.get());
        } else if (display->isVirtual()) {
            ALOGW("Attempt to set power mode %d for virtual display", mode);
        } else {
            setPowerModeInternal(display, static_cast<hal::PowerMode>(mode));
        }
    });

    future.wait();
}

status_t SurfaceFlinger::doDump(int fd, const DumpArgs& args, bool asProto) {
    std::string result;

    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();

    if ((uid != AID_SHELL) &&
            !PermissionCache::checkPermission(sDump, pid, uid)) {
        StringAppendF(&result, "Permission Denial: can't dump SurfaceFlinger from pid=%d, uid=%d\n",
                      pid, uid);
    } else {
        static const std::unordered_map<std::string, Dumper> dumpers = {
                {"--comp-displays"s, dumper(&SurfaceFlinger::dumpCompositionDisplays)},
                {"--display-id"s, dumper(&SurfaceFlinger::dumpDisplayIdentificationData)},
                {"--displays"s, dumper(&SurfaceFlinger::dumpDisplays)},
                {"--edid"s, argsDumper(&SurfaceFlinger::dumpRawDisplayIdentificationData)},
                {"--events"s, dumper(&SurfaceFlinger::dumpEvents)},
                {"--frametimeline"s, argsDumper(&SurfaceFlinger::dumpFrameTimeline)},
                {"--hwclayers"s, dumper(&SurfaceFlinger::dumpHwcLayersMinidumpLocked)},
                {"--latency"s, argsDumper(&SurfaceFlinger::dumpStatsLocked)},
                {"--latency-clear"s, argsDumper(&SurfaceFlinger::clearStatsLocked)},
                {"--list"s, dumper(&SurfaceFlinger::listLayersLocked)},
                {"--planner"s, argsDumper(&SurfaceFlinger::dumpPlannerInfo)},
                {"--scheduler"s, dumper(&SurfaceFlinger::dumpScheduler)},
                {"--timestats"s, protoDumper(&SurfaceFlinger::dumpTimeStats)},
                {"--vsync"s, dumper(&SurfaceFlinger::dumpVsync)},
                {"--wide-color"s, dumper(&SurfaceFlinger::dumpWideColorInfo)},
        };

        const auto flag = args.empty() ? ""s : std::string(String8(args[0]));

        // Traversal of drawing state must happen on the main thread.
        // Otherwise, SortedVector may have shared ownership during concurrent
        // traversals, which can result in use-after-frees.
        std::string compositionLayers;
        mScheduler
                ->schedule([&] {
                    StringAppendF(&compositionLayers, "Composition layers\n");
                    mDrawingState.traverseInZOrder([&](Layer* layer) {
                        auto* compositionState = layer->getCompositionState();
                        if (!compositionState || !compositionState->isVisible) return;

                        android::base::StringAppendF(&compositionLayers, "* Layer %p (%s)\n", layer,
                                                     layer->getDebugName() ? layer->getDebugName()
                                                                           : "<unknown>");
                        compositionState->dump(compositionLayers);
                    });
                })
                .get();

        bool dumpLayers = true;
        {
            TimedLock lock(mStateLock, s2ns(1), __func__);
            if (!lock.locked()) {
                StringAppendF(&result, "Dumping without lock after timeout: %s (%d)\n",
                              strerror(-lock.status), lock.status);
            }

            if (const auto it = dumpers.find(flag); it != dumpers.end()) {
                (it->second)(args, asProto, result);
                dumpLayers = false;
            } else if (!asProto) {
                dumpAllLocked(args, compositionLayers, result);
            }
        }

        if (dumpLayers) {
            LayersTraceFileProto traceFileProto = mLayerTracing.createTraceFileProto();
            LayersTraceProto* layersTrace = traceFileProto.add_entry();
            LayersProto layersProto = dumpProtoFromMainThread();
            layersTrace->mutable_layers()->Swap(&layersProto);
            auto displayProtos = dumpDisplayProto();
            layersTrace->mutable_displays()->Swap(&displayProtos);

            if (asProto) {
                result.append(traceFileProto.SerializeAsString());
            } else {
                // Dump info that we need to access from the main thread
                const auto layerTree = LayerProtoParser::generateLayerTree(layersTrace->layers());
                result.append(LayerProtoParser::layerTreeToString(layerTree));
                result.append("\n");
                dumpOffscreenLayers(result);
            }
        }
    }
    write(fd, result.c_str(), result.size());
    return NO_ERROR;
}

status_t SurfaceFlinger::dumpCritical(int fd, const DumpArgs&, bool asProto) {
    return doDump(fd, DumpArgs(), asProto);
}

void SurfaceFlinger::listLayersLocked(std::string& result) const {
    mCurrentState.traverseInZOrder(
            [&](Layer* layer) { StringAppendF(&result, "%s\n", layer->getDebugName()); });
}

void SurfaceFlinger::dumpStatsLocked(const DumpArgs& args, std::string& result) const {
    StringAppendF(&result, "%" PRId64 "\n", getVsyncPeriodFromHWC());
    if (args.size() < 2) return;

    const auto name = String8(args[1]);
    mCurrentState.traverseInZOrder([&](Layer* layer) {
        if (layer->getName() == name.string()) {
            layer->dumpFrameStats(result);
        }
    });
}

void SurfaceFlinger::clearStatsLocked(const DumpArgs& args, std::string&) {
    const bool clearAll = args.size() < 2;
    const auto name = clearAll ? String8() : String8(args[1]);

    mCurrentState.traverse([&](Layer* layer) {
        if (clearAll || layer->getName() == name.string()) {
            layer->clearFrameStats();
        }
    });
}

void SurfaceFlinger::dumpTimeStats(const DumpArgs& args, bool asProto, std::string& result) const {
    mTimeStats->parseArgs(asProto, args, result);
}

void SurfaceFlinger::dumpFrameTimeline(const DumpArgs& args, std::string& result) const {
    mFrameTimeline->parseArgs(args, result);
}

void SurfaceFlinger::logFrameStats(TimePoint now) {
    static TimePoint sTimestamp = now;
    if (now - sTimestamp < 30min) return;
    sTimestamp = now;

    ATRACE_CALL();
    mDrawingState.traverse([&](Layer* layer) { layer->logFrameStats(); });
}

void SurfaceFlinger::appendSfConfigString(std::string& result) const {
    result.append(" [sf");

    StringAppendF(&result, " PRESENT_TIME_OFFSET=%" PRId64, dispSyncPresentTimeOffset);
    StringAppendF(&result, " FORCE_HWC_FOR_RBG_TO_YUV=%d", useHwcForRgbToYuv);
    StringAppendF(&result, " MAX_VIRT_DISPLAY_DIM=%zu",
                  getHwComposer().getMaxVirtualDisplayDimension());
    StringAppendF(&result, " RUNNING_WITHOUT_SYNC_FRAMEWORK=%d", !hasSyncFramework);
    StringAppendF(&result, " NUM_FRAMEBUFFER_SURFACE_BUFFERS=%" PRId64,
                  maxFrameBufferAcquiredBuffers);
    result.append("]");
}

void SurfaceFlinger::dumpScheduler(std::string& result) const {
    utils::Dumper dumper{result};

    mScheduler->dump(dumper);

    // TODO(b/241285876): Move to DisplayModeController.
    dumper.dump("debugDisplayModeSetByBackdoor"sv, mDebugDisplayModeSetByBackdoor);
    dumper.eol();

    mRefreshRateStats->dump(result);
    dumper.eol();

    mVsyncConfiguration->dump(result);
    StringAppendF(&result,
                  "         present offset: %9" PRId64 " ns\t        VSYNC period: %9" PRId64
                  " ns\n\n",
                  dispSyncPresentTimeOffset, getVsyncPeriodFromHWC());
}

void SurfaceFlinger::dumpEvents(std::string& result) const {
    mScheduler->dump(mAppConnectionHandle, result);
}

void SurfaceFlinger::dumpVsync(std::string& result) const {
    mScheduler->dumpVsync(result);
}

void SurfaceFlinger::dumpPlannerInfo(const DumpArgs& args, std::string& result) const {
    for (const auto& [token, display] : mDisplays) {
        const auto compositionDisplay = display->getCompositionDisplay();
        compositionDisplay->dumpPlannerInfo(args, result);
    }
}

void SurfaceFlinger::dumpCompositionDisplays(std::string& result) const {
    for (const auto& [token, display] : mDisplays) {
        display->getCompositionDisplay()->dump(result);
        result += '\n';
    }
}

void SurfaceFlinger::dumpDisplays(std::string& result) const {
    utils::Dumper dumper{result};

    for (const auto& [id, display] : mPhysicalDisplays) {
        utils::Dumper::Section section(dumper, ftl::Concat("Display ", id.value).str());

        display.snapshot().dump(dumper);

        if (const auto device = getDisplayDeviceLocked(id)) {
            device->dump(dumper);
        }
    }

    for (const auto& [token, display] : mDisplays) {
        if (display->isVirtual()) {
            const auto displayId = display->getId();
            utils::Dumper::Section section(dumper,
                                           ftl::Concat("Virtual Display ", displayId.value).str());
            display->dump(dumper);
        }
    }
}

void SurfaceFlinger::dumpDisplayIdentificationData(std::string& result) const {
    for (const auto& [token, display] : mDisplays) {
        const auto displayId = PhysicalDisplayId::tryCast(display->getId());
        if (!displayId) {
            continue;
        }
        const auto hwcDisplayId = getHwComposer().fromPhysicalDisplayId(*displayId);
        if (!hwcDisplayId) {
            continue;
        }

        StringAppendF(&result,
                      "Display %s (HWC display %" PRIu64 "): ", to_string(*displayId).c_str(),
                      *hwcDisplayId);
        uint8_t port;
        DisplayIdentificationData data;
        if (!getHwComposer().getDisplayIdentificationData(*hwcDisplayId, &port, &data)) {
            result.append("no identification data\n");
            continue;
        }

        if (!isEdid(data)) {
            result.append("unknown identification data\n");
            continue;
        }

        const auto edid = parseEdid(data);
        if (!edid) {
            result.append("invalid EDID\n");
            continue;
        }

        StringAppendF(&result, "port=%u pnpId=%s displayName=\"", port, edid->pnpId.data());
        result.append(edid->displayName.data(), edid->displayName.length());
        result.append("\"\n");
    }
}

void SurfaceFlinger::dumpRawDisplayIdentificationData(const DumpArgs& args,
                                                      std::string& result) const {
    hal::HWDisplayId hwcDisplayId;
    uint8_t port;
    DisplayIdentificationData data;

    if (args.size() > 1 && base::ParseUint(String8(args[1]), &hwcDisplayId) &&
        getHwComposer().getDisplayIdentificationData(hwcDisplayId, &port, &data)) {
        result.append(reinterpret_cast<const char*>(data.data()), data.size());
    }
}

void SurfaceFlinger::dumpWideColorInfo(std::string& result) const {
    StringAppendF(&result, "Device supports wide color: %d\n", mSupportsWideColor);
    StringAppendF(&result, "Device uses color management: %d\n", useColorManagement);
    StringAppendF(&result, "DisplayColorSetting: %s\n",
                  decodeDisplayColorSetting(mDisplayColorSetting).c_str());

    // TODO: print out if wide-color mode is active or not

    for (const auto& [id, display] : mPhysicalDisplays) {
        StringAppendF(&result, "Display %s color modes:\n", to_string(id).c_str());
        for (const auto mode : display.snapshot().colorModes()) {
            StringAppendF(&result, "    %s (%d)\n", decodeColorMode(mode).c_str(), mode);
        }

        if (const auto display = getDisplayDeviceLocked(id)) {
            ui::ColorMode currentMode = display->getCompositionDisplay()->getState().colorMode;
            StringAppendF(&result, "    Current color mode: %s (%d)\n",
                          decodeColorMode(currentMode).c_str(), currentMode);
        }
    }
    result.append("\n");
}

LayersProto SurfaceFlinger::dumpDrawingStateProto(uint32_t traceFlags) const {
    std::unordered_set<uint64_t> stackIdsToSkip;

    // Determine if virtual layers display should be skipped
    if ((traceFlags & LayerTracing::TRACE_VIRTUAL_DISPLAYS) == 0) {
        for (const auto& [_, display] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
            if (display->isVirtual()) {
                stackIdsToSkip.insert(display->getLayerStack().id);
            }
        }
    }

    if (mLegacyFrontEndEnabled) {
        LayersProto layersProto;
        for (const sp<Layer>& layer : mDrawingState.layersSortedByZ) {
            if (stackIdsToSkip.find(layer->getLayerStack().id) != stackIdsToSkip.end()) {
                continue;
            }
            layer->writeToProto(layersProto, traceFlags);
        }
        return layersProto;
    }

    return LayerProtoFromSnapshotGenerator(mLayerSnapshotBuilder, mFrontEndDisplayInfos,
                                           mLegacyLayers, traceFlags)
            .generate(mLayerHierarchyBuilder.getHierarchy());
}

google::protobuf::RepeatedPtrField<DisplayProto> SurfaceFlinger::dumpDisplayProto() const {
    google::protobuf::RepeatedPtrField<DisplayProto> displays;
    for (const auto& [_, display] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        DisplayProto* displayProto = displays.Add();
        displayProto->set_id(display->getId().value);
        displayProto->set_name(display->getDisplayName());
        displayProto->set_layer_stack(display->getLayerStack().id);
        LayerProtoHelper::writeSizeToProto(display->getWidth(), display->getHeight(),
                                           [&]() { return displayProto->mutable_size(); });
        LayerProtoHelper::writeToProto(display->getLayerStackSpaceRect(), [&]() {
            return displayProto->mutable_layer_stack_space_rect();
        });
        LayerProtoHelper::writeTransformToProto(display->getTransform(),
                                                displayProto->mutable_transform());
        displayProto->set_is_virtual(display->isVirtual());
    }
    return displays;
}

void SurfaceFlinger::dumpHwc(std::string& result) const {
    getHwComposer().dump(result);
}

void SurfaceFlinger::dumpOffscreenLayersProto(LayersProto& layersProto, uint32_t traceFlags) const {
    // Add a fake invisible root layer to the proto output and parent all the offscreen layers to
    // it.
    LayerProto* rootProto = layersProto.add_layers();
    const int32_t offscreenRootLayerId = INT32_MAX - 2;
    rootProto->set_id(offscreenRootLayerId);
    rootProto->set_name("Offscreen Root");
    rootProto->set_parent(-1);

    for (Layer* offscreenLayer : mOffscreenLayers) {
        // Add layer as child of the fake root
        rootProto->add_children(offscreenLayer->sequence);

        // Add layer
        LayerProto* layerProto = offscreenLayer->writeToProto(layersProto, traceFlags);
        layerProto->set_parent(offscreenRootLayerId);
    }
}

LayersProto SurfaceFlinger::dumpProtoFromMainThread(uint32_t traceFlags) {
    return mScheduler->schedule([=] { return dumpDrawingStateProto(traceFlags); }).get();
}

void SurfaceFlinger::dumpOffscreenLayers(std::string& result) {
    auto future = mScheduler->schedule([this] {
        std::string result;
        for (Layer* offscreenLayer : mOffscreenLayers) {
            offscreenLayer->traverse(LayerVector::StateSet::Drawing,
                                     [&](Layer* layer) { layer->dumpOffscreenDebugInfo(result); });
        }
        return result;
    });

    result.append("Offscreen Layers:\n");
    result.append(future.get());
}

void SurfaceFlinger::dumpHwcLayersMinidumpLocked(std::string& result) const {
    for (const auto& [token, display] : mDisplays) {
        const auto displayId = HalDisplayId::tryCast(display->getId());
        if (!displayId) {
            continue;
        }

        StringAppendF(&result, "Display %s (%s) HWC layers:\n", to_string(*displayId).c_str(),
                      displayId == mActiveDisplayId ? "active" : "inactive");
        Layer::miniDumpHeader(result);

        const DisplayDevice& ref = *display;
        mDrawingState.traverseInZOrder([&](Layer* layer) { layer->miniDump(result, ref); });
        result.append("\n");
    }
}

void SurfaceFlinger::dumpAllLocked(const DumpArgs& args, const std::string& compositionLayers,
                                   std::string& result) const {
    const bool colorize = !args.empty() && args[0] == String16("--color");
    Colorizer colorizer(colorize);

    // figure out if we're stuck somewhere
    const nsecs_t now = systemTime();
    const nsecs_t inTransaction(mDebugInTransaction);
    nsecs_t inTransactionDuration = (inTransaction) ? now-inTransaction : 0;

    /*
     * Dump library configuration.
     */

    colorizer.bold(result);
    result.append("Build configuration:");
    colorizer.reset(result);
    appendSfConfigString(result);
    result.append("\n");

    result.append("\nDisplay identification data:\n");
    dumpDisplayIdentificationData(result);

    result.append("\nWide-Color information:\n");
    dumpWideColorInfo(result);

    colorizer.bold(result);
    result.append("Sync configuration: ");
    colorizer.reset(result);
    result.append(SyncFeatures::getInstance().toString());
    result.append("\n\n");

    colorizer.bold(result);
    result.append("Scheduler:\n");
    colorizer.reset(result);
    dumpScheduler(result);
    dumpEvents(result);
    dumpVsync(result);
    result.append("\n");

    /*
     * Dump the visible layer list
     */
    colorizer.bold(result);
    StringAppendF(&result, "Visible layers (count = %zu)\n", mNumLayers.load());
    colorizer.reset(result);

    result.append(compositionLayers);

    colorizer.bold(result);
    StringAppendF(&result, "Displays (%zu entries)\n", mDisplays.size());
    colorizer.reset(result);
    dumpDisplays(result);
    dumpCompositionDisplays(result);
    result.push_back('\n');

    mCompositionEngine->dump(result);

    /*
     * Dump SurfaceFlinger global state
     */

    colorizer.bold(result);
    result.append("SurfaceFlinger global state:\n");
    colorizer.reset(result);

    getRenderEngine().dump(result);

    result.append("ClientCache state:\n");
    ClientCache::getInstance().dump(result);
    DebugEGLImageTracker::getInstance()->dump(result);

    if (const auto display = getDefaultDisplayDeviceLocked()) {
        display->getCompositionDisplay()->getState().undefinedRegion.dump(result,
                                                                          "undefinedRegion");
        StringAppendF(&result, "  orientation=%s, isPoweredOn=%d\n",
                      toCString(display->getOrientation()), display->isPoweredOn());
    }
    StringAppendF(&result, "  transaction-flags         : %08x\n", mTransactionFlags.load());

    if (const auto display = getDefaultDisplayDeviceLocked()) {
        std::string fps, xDpi, yDpi;
        if (const auto activeModePtr =
                    display->refreshRateSelector().getActiveMode().modePtr.get()) {
            fps = to_string(activeModePtr->getFps());

            const auto dpi = activeModePtr->getDpi();
            xDpi = base::StringPrintf("%.2f", dpi.x);
            yDpi = base::StringPrintf("%.2f", dpi.y);
        } else {
            fps = "unknown";
            xDpi = "unknown";
            yDpi = "unknown";
        }
        StringAppendF(&result,
                      "  refresh-rate              : %s\n"
                      "  x-dpi                     : %s\n"
                      "  y-dpi                     : %s\n",
                      fps.c_str(), xDpi.c_str(), yDpi.c_str());
    }

    StringAppendF(&result, "  transaction time: %f us\n", inTransactionDuration / 1000.0);

    /*
     * Tracing state
     */
    mLayerTracing.dump(result);

    result.append("\nTransaction tracing: ");
    if (mTransactionTracing) {
        result.append("enabled\n");
        mTransactionTracing->dump(result);
    } else {
        result.append("disabled\n");
    }
    result.push_back('\n');

    dumpHwcLayersMinidumpLocked(result);

    {
        DumpArgs plannerArgs;
        plannerArgs.add(); // first argument is ignored
        plannerArgs.add(String16("--layers"));
        dumpPlannerInfo(plannerArgs, result);
    }

    /*
     * Dump HWComposer state
     */
    colorizer.bold(result);
    result.append("h/w composer state:\n");
    colorizer.reset(result);
    const bool hwcDisabled = mDebugDisableHWC || mDebugFlashDelay;
    StringAppendF(&result, "  h/w composer %s\n", hwcDisabled ? "disabled" : "enabled");
    dumpHwc(result);

    /*
     * Dump gralloc state
     */
    const GraphicBufferAllocator& alloc(GraphicBufferAllocator::get());
    alloc.dump(result);

    /*
     * Dump flag/property manager state
     */
    mFlagManager.dump(result);

    result.append(mTimeStats->miniDump());
    result.append("\n");

    result.append("Window Infos:\n");
    auto windowInfosDebug = mWindowInfosListenerInvoker->getDebugInfo();
    StringAppendF(&result, "  max send vsync id: %" PRId64 "\n",
                  ftl::to_underlying(windowInfosDebug.maxSendDelayVsyncId));
    StringAppendF(&result, "  max send delay (ns): %" PRId64 " ns\n",
                  windowInfosDebug.maxSendDelayDuration);
    StringAppendF(&result, "  unsent messages: %zu\n", windowInfosDebug.pendingMessageCount);
    result.append("\n");
}

mat4 SurfaceFlinger::calculateColorMatrix(float saturation) {
    if (saturation == 1) {
        return mat4();
    }

    float3 luminance{0.213f, 0.715f, 0.072f};
    luminance *= 1.0f - saturation;
    mat4 saturationMatrix = mat4(vec4{luminance.r + saturation, luminance.r, luminance.r, 0.0f},
                                 vec4{luminance.g, luminance.g + saturation, luminance.g, 0.0f},
                                 vec4{luminance.b, luminance.b, luminance.b + saturation, 0.0f},
                                 vec4{0.0f, 0.0f, 0.0f, 1.0f});
    return saturationMatrix;
}

void SurfaceFlinger::updateColorMatrixLocked() {
    mat4 colorMatrix =
            mClientColorMatrix * calculateColorMatrix(mGlobalSaturationFactor) * mDaltonizer();

    if (mCurrentState.colorMatrix != colorMatrix) {
        mCurrentState.colorMatrix = colorMatrix;
        mCurrentState.colorMatrixChanged = true;
        setTransactionFlags(eTransactionNeeded);
    }
}

status_t SurfaceFlinger::CheckTransactCodeCredentials(uint32_t code) {
#pragma clang diagnostic push
#pragma clang diagnostic error "-Wswitch-enum"
    switch (static_cast<ISurfaceComposerTag>(code)) {
        // These methods should at minimum make sure that the client requested
        // access to SF.
        case GET_HDR_CAPABILITIES:
        case GET_AUTO_LOW_LATENCY_MODE_SUPPORT:
        case GET_GAME_CONTENT_TYPE_SUPPORT:
        case ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN: {
            // OVERRIDE_HDR_TYPES is used by CTS tests, which acquire the necessary
            // permission dynamically. Don't use the permission cache for this check.
            bool usePermissionCache = code != OVERRIDE_HDR_TYPES;
            if (!callingThreadHasUnscopedSurfaceFlingerAccess(usePermissionCache)) {
                IPCThreadState* ipc = IPCThreadState::self();
                ALOGE("Permission Denial: can't access SurfaceFlinger pid=%d, uid=%d",
                        ipc->getCallingPid(), ipc->getCallingUid());
                return PERMISSION_DENIED;
            }
            return OK;
        }
        // The following calls are currently used by clients that do not
        // request necessary permissions. However, they do not expose any secret
        // information, so it is OK to pass them.
        case GET_ACTIVE_COLOR_MODE:
        case GET_ACTIVE_DISPLAY_MODE:
        case GET_DISPLAY_COLOR_MODES:
        case GET_DISPLAY_MODES:
        // Calling setTransactionState is safe, because you need to have been
        // granted a reference to Client* and Handle* to do anything with it.
        case SET_TRANSACTION_STATE: {
            // This is not sensitive information, so should not require permission control.
            return OK;
        }
        case BOOT_FINISHED:
        // Used by apps to hook Choreographer to SurfaceFlinger.
        case CREATE_DISPLAY_EVENT_CONNECTION:
        case CREATE_CONNECTION:
        case CREATE_DISPLAY:
        case DESTROY_DISPLAY:
        case GET_PRIMARY_PHYSICAL_DISPLAY_ID:
        case GET_PHYSICAL_DISPLAY_IDS:
        case GET_PHYSICAL_DISPLAY_TOKEN:
        case AUTHENTICATE_SURFACE:
        case SET_POWER_MODE:
        case GET_SUPPORTED_FRAME_TIMESTAMPS:
        case GET_DISPLAY_STATE:
        case GET_DISPLAY_STATS:
        case GET_STATIC_DISPLAY_INFO:
        case GET_DYNAMIC_DISPLAY_INFO:
        case GET_DISPLAY_NATIVE_PRIMARIES:
        case SET_ACTIVE_COLOR_MODE:
        case SET_BOOT_DISPLAY_MODE:
        case CLEAR_BOOT_DISPLAY_MODE:
        case GET_BOOT_DISPLAY_MODE_SUPPORT:
        case SET_AUTO_LOW_LATENCY_MODE:
        case SET_GAME_CONTENT_TYPE:
        case CAPTURE_LAYERS:
        case CAPTURE_DISPLAY:
        case CAPTURE_DISPLAY_BY_ID:
        case CLEAR_ANIMATION_FRAME_STATS:
        case GET_ANIMATION_FRAME_STATS:
        case OVERRIDE_HDR_TYPES:
        case ON_PULL_ATOM:
        case ENABLE_VSYNC_INJECTIONS:
        case INJECT_VSYNC:
        case GET_LAYER_DEBUG_INFO:
        case GET_COLOR_MANAGEMENT:
        case GET_COMPOSITION_PREFERENCE:
        case GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES:
        case SET_DISPLAY_CONTENT_SAMPLING_ENABLED:
        case GET_DISPLAYED_CONTENT_SAMPLE:
        case GET_PROTECTED_CONTENT_SUPPORT:
        case IS_WIDE_COLOR_DISPLAY:
        case ADD_REGION_SAMPLING_LISTENER:
        case REMOVE_REGION_SAMPLING_LISTENER:
        case ADD_FPS_LISTENER:
        case REMOVE_FPS_LISTENER:
        case ADD_TUNNEL_MODE_ENABLED_LISTENER:
        case REMOVE_TUNNEL_MODE_ENABLED_LISTENER:
        case ADD_WINDOW_INFOS_LISTENER:
        case REMOVE_WINDOW_INFOS_LISTENER:
        case SET_DESIRED_DISPLAY_MODE_SPECS:
        case GET_DESIRED_DISPLAY_MODE_SPECS:
        case GET_DISPLAY_BRIGHTNESS_SUPPORT:
        case SET_DISPLAY_BRIGHTNESS:
        case ADD_HDR_LAYER_INFO_LISTENER:
        case REMOVE_HDR_LAYER_INFO_LISTENER:
        case NOTIFY_POWER_BOOST:
        case SET_GLOBAL_SHADOW_SETTINGS:
        case GET_DISPLAY_DECORATION_SUPPORT:
        case SET_FRAME_RATE:
        case SET_OVERRIDE_FRAME_RATE:
        case SET_FRAME_TIMELINE_INFO:
        case ADD_TRANSACTION_TRACE_LISTENER:
        case GET_GPU_CONTEXT_PRIORITY:
        case GET_MAX_ACQUIRED_BUFFER_COUNT:
            LOG_FATAL("Deprecated opcode: %d, migrated to AIDL", code);
            return PERMISSION_DENIED;
    }

    // These codes are used for the IBinder protocol to either interrogate the recipient
    // side of the transaction for its canonical interface descriptor or to dump its state.
    // We let them pass by default.
    if (code == IBinder::INTERFACE_TRANSACTION || code == IBinder::DUMP_TRANSACTION ||
        code == IBinder::PING_TRANSACTION || code == IBinder::SHELL_COMMAND_TRANSACTION ||
        code == IBinder::SYSPROPS_TRANSACTION) {
        return OK;
    }
    // Numbers from 1000 to 1042 are currently used for backdoors. The code
    // in onTransact verifies that the user is root, and has access to use SF.
    if (code >= 1000 && code <= 1042) {
        ALOGV("Accessing SurfaceFlinger through backdoor code: %u", code);
        return OK;
    }
    ALOGE("Permission Denial: SurfaceFlinger did not recognize request code: %u", code);
    return PERMISSION_DENIED;
#pragma clang diagnostic pop
}

status_t SurfaceFlinger::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                    uint32_t flags) {
    if (const status_t error = CheckTransactCodeCredentials(code); error != OK) {
        return error;
    }

    status_t err = BnSurfaceComposer::onTransact(code, data, reply, flags);
    if (err == UNKNOWN_TRANSACTION || err == PERMISSION_DENIED) {
        CHECK_INTERFACE(ISurfaceComposer, data, reply);
        IPCThreadState* ipc = IPCThreadState::self();
        const int uid = ipc->getCallingUid();
        if (CC_UNLIKELY(uid != AID_SYSTEM
                && !PermissionCache::checkCallingPermission(sHardwareTest))) {
            const int pid = ipc->getCallingPid();
            ALOGE("Permission Denial: "
                    "can't access SurfaceFlinger pid=%d, uid=%d", pid, uid);
            return PERMISSION_DENIED;
        }
        int n;
        switch (code) {
            case 1000: // Unused.
            case 1001:
                return NAME_NOT_FOUND;
            case 1002: // Toggle flashing on surface damage.
                if (const int delay = data.readInt32(); delay > 0) {
                    mDebugFlashDelay = delay;
                } else {
                    mDebugFlashDelay = mDebugFlashDelay ? 0 : 1;
                }
                scheduleRepaint();
                return NO_ERROR;
            case 1004: // Force composite ahead of next VSYNC.
            case 1006:
                scheduleComposite(FrameHint::kActive);
                return NO_ERROR;
            case 1005: { // Force commit ahead of next VSYNC.
                Mutex::Autolock lock(mStateLock);
                setTransactionFlags(eTransactionNeeded | eDisplayTransactionNeeded |
                                    eTraversalNeeded);
                return NO_ERROR;
            }
            case 1007: // Unused.
                return NAME_NOT_FOUND;
            case 1008: // Toggle forced GPU composition.
                mDebugDisableHWC = data.readInt32() != 0;
                scheduleRepaint();
                return NO_ERROR;
            case 1009: // Toggle use of transform hint.
                mDebugDisableTransformHint = data.readInt32() != 0;
                scheduleRepaint();
                return NO_ERROR;
            case 1010: // Interrogate.
                reply->writeInt32(0);
                reply->writeInt32(0);
                reply->writeInt32(mDebugFlashDelay);
                reply->writeInt32(0);
                reply->writeInt32(mDebugDisableHWC);
                return NO_ERROR;
            case 1013: // Unused.
                return NAME_NOT_FOUND;
            case 1014: {
                Mutex::Autolock _l(mStateLock);
                // daltonize
                n = data.readInt32();
                switch (n % 10) {
                    case 1:
                        mDaltonizer.setType(ColorBlindnessType::Protanomaly);
                        break;
                    case 2:
                        mDaltonizer.setType(ColorBlindnessType::Deuteranomaly);
                        break;
                    case 3:
                        mDaltonizer.setType(ColorBlindnessType::Tritanomaly);
                        break;
                    default:
                        mDaltonizer.setType(ColorBlindnessType::None);
                        break;
                }
                if (n >= 10) {
                    mDaltonizer.setMode(ColorBlindnessMode::Correction);
                } else {
                    mDaltonizer.setMode(ColorBlindnessMode::Simulation);
                }

                updateColorMatrixLocked();
                return NO_ERROR;
            }
            case 1015: {
                Mutex::Autolock _l(mStateLock);
                // apply a color matrix
                n = data.readInt32();
                if (n) {
                    // color matrix is sent as a column-major mat4 matrix
                    for (size_t i = 0 ; i < 4; i++) {
                        for (size_t j = 0; j < 4; j++) {
                            mClientColorMatrix[i][j] = data.readFloat();
                        }
                    }
                } else {
                    mClientColorMatrix = mat4();
                }

                // Check that supplied matrix's last row is {0,0,0,1} so we can avoid
                // the division by w in the fragment shader
                float4 lastRow(transpose(mClientColorMatrix)[3]);
                if (any(greaterThan(abs(lastRow - float4{0, 0, 0, 1}), float4{1e-4f}))) {
                    ALOGE("The color transform's last row must be (0, 0, 0, 1)");
                }

                updateColorMatrixLocked();
                return NO_ERROR;
            }
            case 1016: { // Unused.
                return NAME_NOT_FOUND;
            }
            case 1017: {
                n = data.readInt32();
                mForceFullDamage = n != 0;
                return NO_ERROR;
            }
            case 1018: { // Modify Choreographer's duration
                n = data.readInt32();
                mScheduler->setDuration(mAppConnectionHandle, std::chrono::nanoseconds(n), 0ns);
                return NO_ERROR;
            }
            case 1019: { // Modify SurfaceFlinger's duration
                n = data.readInt32();
                mScheduler->setDuration(mSfConnectionHandle, std::chrono::nanoseconds(n), 0ns);
                return NO_ERROR;
            }
            case 1020: { // Unused
                return NAME_NOT_FOUND;
            }
            case 1021: { // Disable HWC virtual displays
                const bool enable = data.readInt32() != 0;
                static_cast<void>(
                        mScheduler->schedule([this, enable] { enableHalVirtualDisplays(enable); }));
                return NO_ERROR;
            }
            case 1022: { // Set saturation boost
                Mutex::Autolock _l(mStateLock);
                mGlobalSaturationFactor = std::max(0.0f, std::min(data.readFloat(), 2.0f));

                updateColorMatrixLocked();
                return NO_ERROR;
            }
            case 1023: { // Set color mode.
                mDisplayColorSetting = static_cast<DisplayColorSetting>(data.readInt32());

                if (int32_t colorMode; data.readInt32(&colorMode) == NO_ERROR) {
                    mForceColorMode = static_cast<ui::ColorMode>(colorMode);
                }
                scheduleRepaint();
                return NO_ERROR;
            }
            // Deprecate, use 1030 to check whether the device is color managed.
            case 1024: {
                return NAME_NOT_FOUND;
            }
            case 1025: { // Set layer tracing
                n = data.readInt32();
                bool tracingEnabledChanged;
                if (n == 1) {
                    int64_t fixedStartingTime = data.readInt64();
                    ALOGD("LayerTracing enabled");
                    tracingEnabledChanged = mLayerTracing.enable();
                    if (tracingEnabledChanged) {
                        const TimePoint startingTime = fixedStartingTime
                                ? TimePoint::fromNs(fixedStartingTime)
                                : TimePoint::now();

                        mScheduler
                                ->schedule([this, startingTime]() FTL_FAKE_GUARD(
                                                   mStateLock) FTL_FAKE_GUARD(kMainThreadContext) {
                                    constexpr bool kVisibleRegionDirty = true;
                                    addToLayerTracing(kVisibleRegionDirty, startingTime,
                                                      mLastCommittedVsyncId);
                                })
                                .wait();
                    }
                } else if (n == 2) {
                    std::string filename = std::string(data.readCString());
                    ALOGD("LayerTracing disabled. Trace wrote to %s", filename.c_str());
                    tracingEnabledChanged = mLayerTracing.disable(filename.c_str());
                } else {
                    ALOGD("LayerTracing disabled");
                    tracingEnabledChanged = mLayerTracing.disable();
                }
                mTracingEnabledChanged = tracingEnabledChanged;
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
            case 1026: { // Get layer tracing status
                reply->writeBool(mLayerTracing.isEnabled());
                return NO_ERROR;
            }
            // Is a DisplayColorSetting supported?
            case 1027: {
                const auto display = getDefaultDisplayDevice();
                if (!display) {
                    return NAME_NOT_FOUND;
                }

                DisplayColorSetting setting = static_cast<DisplayColorSetting>(data.readInt32());
                switch (setting) {
                    case DisplayColorSetting::kManaged:
                        reply->writeBool(useColorManagement);
                        break;
                    case DisplayColorSetting::kUnmanaged:
                        reply->writeBool(true);
                        break;
                    case DisplayColorSetting::kEnhanced:
                        reply->writeBool(display->hasRenderIntent(RenderIntent::ENHANCE));
                        break;
                    default: // vendor display color setting
                        reply->writeBool(
                                display->hasRenderIntent(static_cast<RenderIntent>(setting)));
                        break;
                }
                return NO_ERROR;
            }
            case 1028: { // Unused.
                return NAME_NOT_FOUND;
            }
            // Set buffer size for SF tracing (value in KB)
            case 1029: {
                n = data.readInt32();
                if (n <= 0 || n > MAX_TRACING_MEMORY) {
                    ALOGW("Invalid buffer size: %d KB", n);
                    reply->writeInt32(BAD_VALUE);
                    return BAD_VALUE;
                }

                ALOGD("Updating trace buffer to %d KB", n);
                mLayerTracing.setBufferSize(n * 1024);
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
            // Is device color managed?
            case 1030: {
                reply->writeBool(useColorManagement);
                return NO_ERROR;
            }
            // Override default composition data space
            // adb shell service call SurfaceFlinger 1031 i32 1 DATASPACE_NUMBER DATASPACE_NUMBER \
            // && adb shell stop zygote && adb shell start zygote
            // to restore: adb shell service call SurfaceFlinger 1031 i32 0 && \
            // adb shell stop zygote && adb shell start zygote
            case 1031: {
                Mutex::Autolock _l(mStateLock);
                n = data.readInt32();
                if (n) {
                    n = data.readInt32();
                    if (n) {
                        Dataspace dataspace = static_cast<Dataspace>(n);
                        if (!validateCompositionDataspace(dataspace)) {
                            return BAD_VALUE;
                        }
                        mDefaultCompositionDataspace = dataspace;
                    }
                    n = data.readInt32();
                    if (n) {
                        Dataspace dataspace = static_cast<Dataspace>(n);
                        if (!validateCompositionDataspace(dataspace)) {
                            return BAD_VALUE;
                        }
                        mWideColorGamutCompositionDataspace = dataspace;
                    }
                } else {
                    // restore composition data space.
                    mDefaultCompositionDataspace = defaultCompositionDataspace;
                    mWideColorGamutCompositionDataspace = wideColorGamutCompositionDataspace;
                }
                return NO_ERROR;
            }
            // Set trace flags
            case 1033: {
                n = data.readUint32();
                ALOGD("Updating trace flags to 0x%x", n);
                mLayerTracing.setTraceFlags(n);
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
            case 1034: {
                auto future = mScheduler->schedule(
                        [&]() FTL_FAKE_GUARD(mStateLock) FTL_FAKE_GUARD(kMainThreadContext) {
                            switch (n = data.readInt32()) {
                                case 0:
                                case 1:
                                    enableRefreshRateOverlay(static_cast<bool>(n));
                                    break;
                                default:
                                    reply->writeBool(isRefreshRateOverlayEnabled());
                            }
                        });

                future.wait();
                return NO_ERROR;
            }
            case 1035: {
                const int modeId = data.readInt32();

                const auto display = [&]() -> sp<IBinder> {
                    uint64_t value;
                    if (data.readUint64(&value) != NO_ERROR) {
                        return getDefaultDisplayDevice()->getDisplayToken().promote();
                    }

                    if (const auto id = DisplayId::fromValue<PhysicalDisplayId>(value)) {
                        return getPhysicalDisplayToken(*id);
                    }

                    ALOGE("Invalid physical display ID");
                    return nullptr;
                }();

                mDebugDisplayModeSetByBackdoor = false;
                const status_t result = setActiveModeFromBackdoor(display, DisplayModeId{modeId});
                mDebugDisplayModeSetByBackdoor = result == NO_ERROR;
                return result;
            }
            // Turn on/off frame rate flexibility mode. When turned on it overrides the display
            // manager frame rate policy a new policy which allows switching between all refresh
            // rates.
            case 1036: {
                if (data.readInt32() > 0) { // turn on
                    return mScheduler
                            ->schedule([this]() FTL_FAKE_GUARD(kMainThreadContext) {
                                const auto display =
                                        FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());

                                // This is a little racy, but not in a way that hurts anything. As
                                // we grab the defaultMode from the display manager policy, we could
                                // be setting a new display manager policy, leaving us using a stale
                                // defaultMode. The defaultMode doesn't matter for the override
                                // policy though, since we set allowGroupSwitching to true, so it's
                                // not a problem.
                                scheduler::RefreshRateSelector::OverridePolicy overridePolicy;
                                overridePolicy.defaultMode = display->refreshRateSelector()
                                                                     .getDisplayManagerPolicy()
                                                                     .defaultMode;
                                overridePolicy.allowGroupSwitching = true;
                                return setDesiredDisplayModeSpecsInternal(display, overridePolicy);
                            })
                            .get();
                } else { // turn off
                    return mScheduler
                            ->schedule([this]() FTL_FAKE_GUARD(kMainThreadContext) {
                                const auto display =
                                        FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());
                                return setDesiredDisplayModeSpecsInternal(
                                        display,
                                        scheduler::RefreshRateSelector::NoOverridePolicy{});
                            })
                            .get();
                }
            }
            // Inject a hotplug connected event for the primary display. This will deallocate and
            // reallocate the display state including framebuffers.
            case 1037: {
                const hal::HWDisplayId hwcId =
                        (Mutex::Autolock(mStateLock), getHwComposer().getPrimaryHwcDisplayId());

                onComposerHalHotplug(hwcId, hal::Connection::CONNECTED);
                return NO_ERROR;
            }
            // Modify the max number of display frames stored within FrameTimeline
            case 1038: {
                n = data.readInt32();
                if (n < 0 || n > MAX_ALLOWED_DISPLAY_FRAMES) {
                    ALOGW("Invalid max size. Maximum allowed is %d", MAX_ALLOWED_DISPLAY_FRAMES);
                    return BAD_VALUE;
                }
                if (n == 0) {
                    // restore to default
                    mFrameTimeline->reset();
                    return NO_ERROR;
                }
                mFrameTimeline->setMaxDisplayFrames(n);
                return NO_ERROR;
            }
            case 1039: {
                PhysicalDisplayId displayId = [&]() {
                    Mutex::Autolock lock(mStateLock);
                    return getDefaultDisplayDeviceLocked()->getPhysicalId();
                }();

                auto inUid = static_cast<uid_t>(data.readInt32());
                const auto refreshRate = data.readFloat();
                mScheduler->setPreferredRefreshRateForUid(FrameRateOverride{inUid, refreshRate});
                mScheduler->onFrameRateOverridesChanged(mAppConnectionHandle, displayId);
                return NO_ERROR;
            }
            // Toggle caching feature
            // First argument is an int32 - nonzero enables caching and zero disables caching
            // Second argument is an optional uint64 - if present, then limits enabling/disabling
            // caching to a particular physical display
            case 1040: {
                auto future = mScheduler->schedule([&] {
                    n = data.readInt32();
                    std::optional<PhysicalDisplayId> inputId = std::nullopt;
                    if (uint64_t inputDisplayId; data.readUint64(&inputDisplayId) == NO_ERROR) {
                        inputId = DisplayId::fromValue<PhysicalDisplayId>(inputDisplayId);
                        if (!inputId || getPhysicalDisplayToken(*inputId)) {
                            ALOGE("No display with id: %" PRIu64, inputDisplayId);
                            return NAME_NOT_FOUND;
                        }
                    }
                    {
                        Mutex::Autolock lock(mStateLock);
                        mLayerCachingEnabled = n != 0;
                        for (const auto& [_, display] : mDisplays) {
                            if (!inputId || *inputId == display->getPhysicalId()) {
                                display->enableLayerCaching(mLayerCachingEnabled);
                            }
                        }
                    }
                    return OK;
                });

                if (const status_t error = future.get(); error != OK) {
                    return error;
                }
                scheduleRepaint();
                return NO_ERROR;
            }
            case 1041: { // Transaction tracing
                if (mTransactionTracing) {
                    if (data.readInt32()) {
                        // Transaction tracing is always running but allow the user to temporarily
                        // increase the buffer when actively debugging.
                        mTransactionTracing->setBufferSize(
                                TransactionTracing::ACTIVE_TRACING_BUFFER_SIZE);
                    } else {
                        TransactionTraceWriter::getInstance().invoke("", /* overwrite= */ true);
                        mTransactionTracing->setBufferSize(
                                TransactionTracing::CONTINUOUS_TRACING_BUFFER_SIZE);
                    }
                }
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
            case 1042: { // Write layers trace or transaction trace to file
                if (mTransactionTracing) {
                    mTransactionTracing->writeToFile();
                }
                if (mLayerTracingEnabled) {
                    mLayerTracing.writeToFile();
                }
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
        }
    }
    return err;
}

void SurfaceFlinger::kernelTimerChanged(bool expired) {
    static bool updateOverlay =
            property_get_bool("debug.sf.kernel_idle_timer_update_overlay", true);
    if (!updateOverlay) return;

    // Update the overlay on the main thread to avoid race conditions with
    // RefreshRateSelector::getActiveMode
    static_cast<void>(mScheduler->schedule([=] {
        const auto display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());
        if (!display) {
            ALOGW("%s: default display is null", __func__);
            return;
        }
        if (!display->isRefreshRateOverlayEnabled()) return;

        const auto desiredActiveMode = display->getDesiredActiveMode();
        const std::optional<DisplayModeId> desiredModeId = desiredActiveMode
                ? std::make_optional(desiredActiveMode->modeOpt->modePtr->getId())

                : std::nullopt;

        const bool timerExpired = mKernelIdleTimerEnabled && expired;

        if (display->onKernelTimerChanged(desiredModeId, timerExpired)) {
            mScheduler->scheduleFrame();
        }
    }));
}

std::pair<std::optional<KernelIdleTimerController>, std::chrono::milliseconds>
SurfaceFlinger::getKernelIdleTimerProperties(DisplayId displayId) {
    const bool isKernelIdleTimerHwcSupported = getHwComposer().getComposer()->isSupported(
            android::Hwc2::Composer::OptionalFeature::KernelIdleTimer);
    const auto timeout = getIdleTimerTimeout(displayId);
    if (isKernelIdleTimerHwcSupported) {
        if (const auto id = PhysicalDisplayId::tryCast(displayId);
            getHwComposer().hasDisplayIdleTimerCapability(*id)) {
            // In order to decide if we can use the HWC api for idle timer
            // we query DisplayCapability::DISPLAY_IDLE_TIMER directly on the composer
            // without relying on hasDisplayCapability.
            // hasDisplayCapability relies on DisplayCapabilities
            // which are updated after we set the PowerMode::ON.
            // DISPLAY_IDLE_TIMER is a display driver property
            // and is available before the PowerMode::ON
            return {KernelIdleTimerController::HwcApi, timeout};
        }
        return {std::nullopt, timeout};
    }
    if (getKernelIdleTimerSyspropConfig(displayId)) {
        return {KernelIdleTimerController::Sysprop, timeout};
    }

    return {std::nullopt, timeout};
}

void SurfaceFlinger::updateKernelIdleTimer(std::chrono::milliseconds timeout,
                                           KernelIdleTimerController controller,
                                           PhysicalDisplayId displayId) {
    switch (controller) {
        case KernelIdleTimerController::HwcApi: {
            getHwComposer().setIdleTimerEnabled(displayId, timeout);
            break;
        }
        case KernelIdleTimerController::Sysprop: {
            base::SetProperty(KERNEL_IDLE_TIMER_PROP, timeout > 0ms ? "true" : "false");
            break;
        }
    }
}

void SurfaceFlinger::toggleKernelIdleTimer() {
    using KernelIdleTimerAction = scheduler::RefreshRateSelector::KernelIdleTimerAction;

    const auto display = getDefaultDisplayDeviceLocked();
    if (!display) {
        ALOGW("%s: default display is null", __func__);
        return;
    }

    // If the support for kernel idle timer is disabled for the active display,
    // don't do anything.
    const std::optional<KernelIdleTimerController> kernelIdleTimerController =
            display->refreshRateSelector().kernelIdleTimerController();
    if (!kernelIdleTimerController.has_value()) {
        return;
    }

    const KernelIdleTimerAction action = display->refreshRateSelector().getIdleTimerAction();

    switch (action) {
        case KernelIdleTimerAction::TurnOff:
            if (mKernelIdleTimerEnabled) {
                ATRACE_INT("KernelIdleTimer", 0);
                std::chrono::milliseconds constexpr kTimerDisabledTimeout = 0ms;
                updateKernelIdleTimer(kTimerDisabledTimeout, kernelIdleTimerController.value(),
                                      display->getPhysicalId());
                mKernelIdleTimerEnabled = false;
            }
            break;
        case KernelIdleTimerAction::TurnOn:
            if (!mKernelIdleTimerEnabled) {
                ATRACE_INT("KernelIdleTimer", 1);
                const std::chrono::milliseconds timeout =
                        display->refreshRateSelector().getIdleTimerTimeout();
                updateKernelIdleTimer(timeout, kernelIdleTimerController.value(),
                                      display->getPhysicalId());
                mKernelIdleTimerEnabled = true;
            }
            break;
    }
}

// A simple RAII class to disconnect from an ANativeWindow* when it goes out of scope
class WindowDisconnector {
public:
    WindowDisconnector(ANativeWindow* window, int api) : mWindow(window), mApi(api) {}
    ~WindowDisconnector() {
        native_window_api_disconnect(mWindow, mApi);
    }

private:
    ANativeWindow* mWindow;
    const int mApi;
};

static bool hasCaptureBlackoutContentPermission() {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    return uid == AID_GRAPHICS || uid == AID_SYSTEM ||
            PermissionCache::checkPermission(sCaptureBlackoutContent, pid, uid);
}

static status_t validateScreenshotPermissions(const CaptureArgs& captureArgs) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if (uid == AID_GRAPHICS || PermissionCache::checkPermission(sReadFramebuffer, pid, uid)) {
        return OK;
    }

    // If the caller doesn't have the correct permissions but is only attempting to screenshot
    // itself, we allow it to continue.
    if (captureArgs.uid == uid) {
        return OK;
    }

    ALOGE("Permission Denial: can't take screenshot pid=%d, uid=%d", pid, uid);
    return PERMISSION_DENIED;
}

status_t SurfaceFlinger::setSchedFifo(bool enabled) {
    static constexpr int kFifoPriority = 2;
    static constexpr int kOtherPriority = 0;

    struct sched_param param = {0};
    int sched_policy;
    if (enabled) {
        sched_policy = SCHED_FIFO;
        param.sched_priority = kFifoPriority;
    } else {
        sched_policy = SCHED_OTHER;
        param.sched_priority = kOtherPriority;
    }

    if (sched_setscheduler(0, sched_policy, &param) != 0) {
        return -errno;
    }

    return NO_ERROR;
}

status_t SurfaceFlinger::setSchedAttr(bool enabled) {
    static const unsigned int kUclampMin =
            base::GetUintProperty<unsigned int>("ro.surface_flinger.uclamp.min", 0U);

    if (!kUclampMin) {
        // uclamp.min set to 0 (default), skip setting
        return NO_ERROR;
    }

    // Currently, there is no wrapper in bionic: b/183240349.
    struct sched_attr {
        uint32_t size;
        uint32_t sched_policy;
        uint64_t sched_flags;
        int32_t sched_nice;
        uint32_t sched_priority;
        uint64_t sched_runtime;
        uint64_t sched_deadline;
        uint64_t sched_period;
        uint32_t sched_util_min;
        uint32_t sched_util_max;
    };

    sched_attr attr = {};
    attr.size = sizeof(attr);

    attr.sched_flags = (SCHED_FLAG_KEEP_ALL | SCHED_FLAG_UTIL_CLAMP);
    attr.sched_util_min = enabled ? kUclampMin : 0;
    attr.sched_util_max = 1024;

    if (syscall(__NR_sched_setattr, 0, &attr, 0)) {
        return -errno;
    }

    return NO_ERROR;
}

namespace {

ui::Dataspace pickBestDataspace(ui::Dataspace requestedDataspace, const DisplayDevice* display,
                                bool capturingHdrLayers, bool hintForSeamlessTransition) {
    if (requestedDataspace != ui::Dataspace::UNKNOWN || display == nullptr) {
        return requestedDataspace;
    }

    const auto& state = display->getCompositionDisplay()->getState();

    const auto dataspaceForColorMode = ui::pickDataspaceFor(state.colorMode);

    // TODO: Enable once HDR screenshots are ready.
    if constexpr (/* DISABLES CODE */ (false)) {
        // For now since we only support 8-bit screenshots, just use HLG and
        // assume that 1.0 >= display max luminance. This isn't quite as future
        // proof as PQ is, but is good enough.
        // Consider using PQ once we support 16-bit screenshots and we're able
        // to consistently supply metadata to image encoders.
        return ui::Dataspace::BT2020_HLG;
    }

    return dataspaceForColorMode;
}

} // namespace

status_t SurfaceFlinger::captureDisplay(const DisplayCaptureArgs& args,
                                        const sp<IScreenCaptureListener>& captureListener) {
    ATRACE_CALL();

    status_t validate = validateScreenshotPermissions(args);
    if (validate != OK) {
        return validate;
    }

    if (!args.displayToken) return BAD_VALUE;

    wp<const DisplayDevice> displayWeak;
    ui::LayerStack layerStack;
    ui::Size reqSize(args.width, args.height);
    std::unordered_set<uint32_t> excludeLayerIds;
    {
        Mutex::Autolock lock(mStateLock);
        sp<DisplayDevice> display = getDisplayDeviceLocked(args.displayToken);
        if (!display) return NAME_NOT_FOUND;
        displayWeak = display;
        layerStack = display->getLayerStack();

        // set the requested width/height to the logical display layer stack rect size by default
        if (args.width == 0 || args.height == 0) {
            reqSize = display->getLayerStackSpaceRect().getSize();
        }

        for (const auto& handle : args.excludeHandles) {
            uint32_t excludeLayer = LayerHandle::getLayerId(handle);
            if (excludeLayer != UNASSIGNED_LAYER_ID) {
                excludeLayerIds.emplace(excludeLayer);
            } else {
                ALOGW("Invalid layer handle passed as excludeLayer to captureDisplay");
                return NAME_NOT_FOUND;
            }
        }
    }

    RenderAreaFuture renderAreaFuture = ftl::defer([=] {
        return DisplayRenderArea::create(displayWeak, args.sourceCrop, reqSize, args.dataspace,
                                         args.useIdentityTransform, args.hintForSeamlessTransition,
                                         args.captureSecureLayers);
    });

    GetLayerSnapshotsFunction getLayerSnapshots;
    if (mLayerLifecycleManagerEnabled) {
        getLayerSnapshots =
                getLayerSnapshotsForScreenshots(layerStack, args.uid, std::move(excludeLayerIds));
    } else {
        auto traverseLayers = [this, args, excludeLayerIds,
                               layerStack](const LayerVector::Visitor& visitor) {
            traverseLayersInLayerStack(layerStack, args.uid, std::move(excludeLayerIds), visitor);
        };
        getLayerSnapshots = RenderArea::fromTraverseLayersLambda(traverseLayers);
    }

    auto future = captureScreenCommon(std::move(renderAreaFuture), getLayerSnapshots, reqSize,
                                      args.pixelFormat, args.allowProtected, args.grayscale,
                                      captureListener);
    return fenceStatus(future.get());
}

status_t SurfaceFlinger::captureDisplay(DisplayId displayId,
                                        const sp<IScreenCaptureListener>& captureListener) {
    ui::LayerStack layerStack;
    wp<const DisplayDevice> displayWeak;
    ui::Size size;
    {
        Mutex::Autolock lock(mStateLock);

        const auto display = getDisplayDeviceLocked(displayId);
        if (!display) {
            return NAME_NOT_FOUND;
        }

        displayWeak = display;
        layerStack = display->getLayerStack();
        size = display->getLayerStackSpaceRect().getSize();
    }

    RenderAreaFuture renderAreaFuture = ftl::defer([=] {
        return DisplayRenderArea::create(displayWeak, Rect(), size, ui::Dataspace::UNKNOWN,
                                         false /* useIdentityTransform */,
                                         false /* hintForSeamlessTransition */,
                                         false /* captureSecureLayers */);
    });

    GetLayerSnapshotsFunction getLayerSnapshots;
    if (mLayerLifecycleManagerEnabled) {
        getLayerSnapshots = getLayerSnapshotsForScreenshots(layerStack, CaptureArgs::UNSET_UID,
                                                            /*snapshotFilterFn=*/nullptr);
    } else {
        auto traverseLayers = [this, layerStack](const LayerVector::Visitor& visitor) {
            traverseLayersInLayerStack(layerStack, CaptureArgs::UNSET_UID, {}, visitor);
        };
        getLayerSnapshots = RenderArea::fromTraverseLayersLambda(traverseLayers);
    }

    if (captureListener == nullptr) {
        ALOGE("capture screen must provide a capture listener callback");
        return BAD_VALUE;
    }

    constexpr bool kAllowProtected = false;
    constexpr bool kGrayscale = false;

    auto future = captureScreenCommon(std::move(renderAreaFuture), getLayerSnapshots, size,
                                      ui::PixelFormat::RGBA_8888, kAllowProtected, kGrayscale,
                                      captureListener);
    return fenceStatus(future.get());
}

status_t SurfaceFlinger::captureLayers(const LayerCaptureArgs& args,
                                       const sp<IScreenCaptureListener>& captureListener) {
    ATRACE_CALL();

    status_t validate = validateScreenshotPermissions(args);
    if (validate != OK) {
        return validate;
    }

    ui::Size reqSize;
    sp<Layer> parent;
    Rect crop(args.sourceCrop);
    std::unordered_set<uint32_t> excludeLayerIds;
    ui::Dataspace dataspace = args.dataspace;

    // Call this before holding mStateLock to avoid any deadlocking.
    bool canCaptureBlackoutContent = hasCaptureBlackoutContentPermission();

    {
        Mutex::Autolock lock(mStateLock);

        parent = LayerHandle::getLayer(args.layerHandle);
        if (parent == nullptr) {
            ALOGE("captureLayers called with an invalid or removed parent");
            return NAME_NOT_FOUND;
        }

        if (!canCaptureBlackoutContent &&
            parent->getDrawingState().flags & layer_state_t::eLayerSecure) {
            ALOGW("Attempting to capture secure layer: PERMISSION_DENIED");
            return PERMISSION_DENIED;
        }

        Rect parentSourceBounds = parent->getCroppedBufferSize(parent->getDrawingState());
        if (args.sourceCrop.width() <= 0) {
            crop.left = 0;
            crop.right = parentSourceBounds.getWidth();
        }

        if (args.sourceCrop.height() <= 0) {
            crop.top = 0;
            crop.bottom = parentSourceBounds.getHeight();
        }

        if (crop.isEmpty() || args.frameScaleX <= 0.0f || args.frameScaleY <= 0.0f) {
            // Error out if the layer has no source bounds (i.e. they are boundless) and a source
            // crop was not specified, or an invalid frame scale was provided.
            return BAD_VALUE;
        }
        reqSize = ui::Size(crop.width() * args.frameScaleX, crop.height() * args.frameScaleY);

        for (const auto& handle : args.excludeHandles) {
            uint32_t excludeLayer = LayerHandle::getLayerId(handle);
            if (excludeLayer != UNASSIGNED_LAYER_ID) {
                excludeLayerIds.emplace(excludeLayer);
            } else {
                ALOGW("Invalid layer handle passed as excludeLayer to captureLayers");
                return NAME_NOT_FOUND;
            }
        }
    } // mStateLock

    // really small crop or frameScale
    if (reqSize.width <= 0 || reqSize.height <= 0) {
        ALOGW("Failed to captureLayes: crop or scale too small");
        return BAD_VALUE;
    }

    bool childrenOnly = args.childrenOnly;
    RenderAreaFuture renderAreaFuture = ftl::defer([=]() -> std::unique_ptr<RenderArea> {
        ui::Transform layerTransform;
        Rect layerBufferSize;
        if (mLayerLifecycleManagerEnabled) {
            frontend::LayerSnapshot* snapshot =
                    mLayerSnapshotBuilder.getSnapshot(parent->getSequence());
            if (!snapshot) {
                ALOGW("Couldn't find layer snapshot for %d", parent->getSequence());
            } else {
                layerTransform = snapshot->localTransform;
                layerBufferSize = snapshot->bufferSize;
            }
        } else {
            layerTransform = parent->getTransform();
            layerBufferSize = parent->getBufferSize(parent->getDrawingState());
        }

        return std::make_unique<LayerRenderArea>(*this, parent, crop, reqSize, dataspace,
                                                 childrenOnly, args.captureSecureLayers,
                                                 layerTransform, layerBufferSize,
                                                 args.hintForSeamlessTransition);
    });
    GetLayerSnapshotsFunction getLayerSnapshots;
    if (mLayerLifecycleManagerEnabled) {
        std::optional<FloatRect> parentCrop = std::nullopt;
        if (args.childrenOnly) {
            parentCrop = crop.isEmpty() ? FloatRect(0, 0, reqSize.width, reqSize.height)
                                        : crop.toFloatRect();
        }

        getLayerSnapshots = getLayerSnapshotsForScreenshots(parent->sequence, args.uid,
                                                            std::move(excludeLayerIds),
                                                            args.childrenOnly, parentCrop);
    } else {
        auto traverseLayers = [parent, args, excludeLayerIds](const LayerVector::Visitor& visitor) {
            parent->traverseChildrenInZOrder(LayerVector::StateSet::Drawing, [&](Layer* layer) {
                if (!layer->isVisible()) {
                    return;
                } else if (args.childrenOnly && layer == parent.get()) {
                    return;
                } else if (args.uid != CaptureArgs::UNSET_UID && args.uid != layer->getOwnerUid()) {
                    return;
                }

                auto p = sp<Layer>::fromExisting(layer);
                while (p != nullptr) {
                    if (excludeLayerIds.count(p->sequence) != 0) {
                        return;
                    }
                    p = p->getParent();
                }

                visitor(layer);
            });
        };
        getLayerSnapshots = RenderArea::fromTraverseLayersLambda(traverseLayers);
    }

    if (captureListener == nullptr) {
        ALOGE("capture screen must provide a capture listener callback");
        return BAD_VALUE;
    }

    auto future = captureScreenCommon(std::move(renderAreaFuture), getLayerSnapshots, reqSize,
                                      args.pixelFormat, args.allowProtected, args.grayscale,
                                      captureListener);
    return fenceStatus(future.get());
}

ftl::SharedFuture<FenceResult> SurfaceFlinger::captureScreenCommon(
        RenderAreaFuture renderAreaFuture, GetLayerSnapshotsFunction getLayerSnapshots,
        ui::Size bufferSize, ui::PixelFormat reqPixelFormat, bool allowProtected, bool grayscale,
        const sp<IScreenCaptureListener>& captureListener) {
    ATRACE_CALL();

    if (exceedsMaxRenderTargetSize(bufferSize.getWidth(), bufferSize.getHeight())) {
        ALOGE("Attempted to capture screen with size (%" PRId32 ", %" PRId32
              ") that exceeds render target size limit.",
              bufferSize.getWidth(), bufferSize.getHeight());
        return ftl::yield<FenceResult>(base::unexpected(BAD_VALUE)).share();
    }

    // Loop over all visible layers to see whether there's any protected layer. A protected layer is
    // typically a layer with DRM contents, or have the GRALLOC_USAGE_PROTECTED set on the buffer.
    // A protected layer has no implication on whether it's secure, which is explicitly set by
    // application to avoid being screenshot or drawn via unsecure display.
    const bool supportsProtected = getRenderEngine().supportsProtectedContent();
    bool hasProtectedLayer = false;
    if (allowProtected && supportsProtected) {
        hasProtectedLayer = mScheduler
                                    ->schedule([=]() {
                                        bool protectedLayerFound = false;
                                        auto layers = getLayerSnapshots();
                                        for (auto& [_, layerFe] : layers) {
                                            protectedLayerFound |=
                                                    (layerFe->mSnapshot->isVisible &&
                                                     layerFe->mSnapshot->hasProtectedContent);
                                        }
                                        return protectedLayerFound;
                                    })
                                    .get();
    }

    const uint32_t usage = GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_RENDER |
            GRALLOC_USAGE_HW_TEXTURE |
            (hasProtectedLayer && allowProtected && supportsProtected
                     ? GRALLOC_USAGE_PROTECTED
                     : GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN);
    sp<GraphicBuffer> buffer =
            getFactory().createGraphicBuffer(bufferSize.getWidth(), bufferSize.getHeight(),
                                             static_cast<android_pixel_format>(reqPixelFormat),
                                             1 /* layerCount */, usage, "screenshot");

    const status_t bufferStatus = buffer->initCheck();
    if (bufferStatus != OK) {
        // Animations may end up being really janky, but don't crash here.
        // Otherwise an irreponsible process may cause an SF crash by allocating
        // too much.
        ALOGE("%s: Buffer failed to allocate: %d", __func__, bufferStatus);
        return ftl::yield<FenceResult>(base::unexpected(bufferStatus)).share();
    }
    const std::shared_ptr<renderengine::ExternalTexture> texture = std::make_shared<
            renderengine::impl::ExternalTexture>(buffer, getRenderEngine(),
                                                 renderengine::impl::ExternalTexture::Usage::
                                                         WRITEABLE);
    return captureScreenCommon(std::move(renderAreaFuture), getLayerSnapshots, texture,
                               false /* regionSampling */, grayscale, captureListener);
}

ftl::SharedFuture<FenceResult> SurfaceFlinger::captureScreenCommon(
        RenderAreaFuture renderAreaFuture, GetLayerSnapshotsFunction getLayerSnapshots,
        const std::shared_ptr<renderengine::ExternalTexture>& buffer, bool regionSampling,
        bool grayscale, const sp<IScreenCaptureListener>& captureListener) {
    ATRACE_CALL();

    bool canCaptureBlackoutContent = hasCaptureBlackoutContentPermission();

    auto future = mScheduler->schedule(
            [=, renderAreaFuture = std::move(renderAreaFuture)]() FTL_FAKE_GUARD(
                    kMainThreadContext) mutable -> ftl::SharedFuture<FenceResult> {
                ScreenCaptureResults captureResults;
                std::shared_ptr<RenderArea> renderArea = renderAreaFuture.get();
                if (!renderArea) {
                    ALOGW("Skipping screen capture because of invalid render area.");
                    if (captureListener) {
                        captureResults.fenceResult = base::unexpected(NO_MEMORY);
                        captureListener->onScreenCaptureCompleted(captureResults);
                    }
                    return ftl::yield<FenceResult>(base::unexpected(NO_ERROR)).share();
                }

                ftl::SharedFuture<FenceResult> renderFuture;
                renderArea->render([&]() FTL_FAKE_GUARD(kMainThreadContext) {
                    renderFuture = renderScreenImpl(renderArea, getLayerSnapshots, buffer,
                                                    canCaptureBlackoutContent, regionSampling,
                                                    grayscale, captureResults);
                });

                if (captureListener) {
                    // Defer blocking on renderFuture back to the Binder thread.
                    return ftl::Future(std::move(renderFuture))
                            .then([captureListener, captureResults = std::move(captureResults)](
                                          FenceResult fenceResult) mutable -> FenceResult {
                                captureResults.fenceResult = std::move(fenceResult);
                                captureListener->onScreenCaptureCompleted(captureResults);
                                return base::unexpected(NO_ERROR);
                            })
                            .share();
                }
                return renderFuture;
            });

    // Flatten nested futures.
    auto chain = ftl::Future(std::move(future)).then([](ftl::SharedFuture<FenceResult> future) {
        return future;
    });

    return chain.share();
}

ftl::SharedFuture<FenceResult> SurfaceFlinger::renderScreenImpl(
        std::shared_ptr<const RenderArea> renderArea, GetLayerSnapshotsFunction getLayerSnapshots,
        const std::shared_ptr<renderengine::ExternalTexture>& buffer,
        bool canCaptureBlackoutContent, bool regionSampling, bool grayscale,
        ScreenCaptureResults& captureResults) {
    ATRACE_CALL();

    auto layers = getLayerSnapshots();

    for (auto& [_, layerFE] : layers) {
        frontend::LayerSnapshot* snapshot = layerFE->mSnapshot.get();
        captureResults.capturedSecureLayers |= (snapshot->isVisible && snapshot->isSecure);
        captureResults.capturedHdrLayers |= isHdrLayer(*snapshot);
        layerFE->mSnapshot->geomLayerTransform =
                renderArea->getTransform() * layerFE->mSnapshot->geomLayerTransform;
        layerFE->mSnapshot->geomInverseLayerTransform =
                layerFE->mSnapshot->geomLayerTransform.inverse();
    }

    // We allow the system server to take screenshots of secure layers for
    // use in situations like the Screen-rotation animation and place
    // the impetus on WindowManager to not persist them.
    if (captureResults.capturedSecureLayers && !canCaptureBlackoutContent) {
        ALOGW("FB is protected: PERMISSION_DENIED");
        return ftl::yield<FenceResult>(base::unexpected(PERMISSION_DENIED)).share();
    }

    auto capturedBuffer = buffer;

    auto requestedDataspace = renderArea->getReqDataSpace();
    auto parent = renderArea->getParentLayer();
    auto renderIntent = RenderIntent::TONE_MAP_COLORIMETRIC;
    auto sdrWhitePointNits = DisplayDevice::sDefaultMaxLumiance;
    auto displayBrightnessNits = DisplayDevice::sDefaultMaxLumiance;

    captureResults.capturedDataspace = requestedDataspace;

    {
        Mutex::Autolock lock(mStateLock);
        const DisplayDevice* display = nullptr;
        if (parent) {
            display = findDisplay([layerStack = parent->getLayerStack()](const auto& display) {
                          return display.getLayerStack() == layerStack;
                      }).get();
        }

        if (display == nullptr) {
            display = renderArea->getDisplayDevice().get();
        }

        if (display == nullptr) {
            display = getDefaultDisplayDeviceLocked().get();
        }

        if (display != nullptr) {
            const auto& state = display->getCompositionDisplay()->getState();
            captureResults.capturedDataspace =
                    pickBestDataspace(requestedDataspace, display, captureResults.capturedHdrLayers,
                                      renderArea->getHintForSeamlessTransition());
            sdrWhitePointNits = state.sdrWhitePointNits;

            if (!captureResults.capturedHdrLayers) {
                displayBrightnessNits = sdrWhitePointNits;
            } else {
                displayBrightnessNits = state.displayBrightnessNits;
                // Only clamp the display brightness if this is not a seamless transition. Otherwise
                // for seamless transitions it's important to match the current display state as the
                // buffer will be shown under these same conditions, and we want to avoid any
                // flickers
                if (sdrWhitePointNits > 1.0f && !renderArea->getHintForSeamlessTransition()) {
                    // Restrict the amount of HDR "headroom" in the screenshot to avoid over-dimming
                    // the SDR portion. 2.0 chosen by experimentation
                    constexpr float kMaxScreenshotHeadroom = 2.0f;
                    displayBrightnessNits = std::min(sdrWhitePointNits * kMaxScreenshotHeadroom,
                                                     displayBrightnessNits);
                }
            }

            // Screenshots leaving the device should be colorimetric
            if (requestedDataspace == ui::Dataspace::UNKNOWN &&
                renderArea->getHintForSeamlessTransition()) {
                renderIntent = state.renderIntent;
            }
        }
    }

    captureResults.buffer = capturedBuffer->getBuffer();

    ui::LayerStack layerStack{ui::DEFAULT_LAYER_STACK};
    if (!layers.empty()) {
        const sp<LayerFE>& layerFE = layers.back().second;
        layerStack = layerFE->getCompositionState()->outputFilter.layerStack;
    }

    auto copyLayerFEs = [&layers]() {
        std::vector<sp<compositionengine::LayerFE>> layerFEs;
        layerFEs.reserve(layers.size());
        for (const auto& [_, layerFE] : layers) {
            layerFEs.push_back(layerFE);
        }
        return layerFEs;
    };

    auto present = [this, buffer = capturedBuffer, dataspace = captureResults.capturedDataspace,
                    sdrWhitePointNits, displayBrightnessNits, grayscale, layerFEs = copyLayerFEs(),
                    layerStack, regionSampling, renderArea = std::move(renderArea),
                    renderIntent]() -> FenceResult {
        std::unique_ptr<compositionengine::CompositionEngine> compositionEngine =
                mFactory.createCompositionEngine();
        compositionEngine->setRenderEngine(mRenderEngine.get());

        compositionengine::Output::ColorProfile colorProfile{.dataspace = dataspace,
                                                             .renderIntent = renderIntent};

        float targetBrightness = 1.0f;
        if (dataspace == ui::Dataspace::BT2020_HLG) {
            const float maxBrightnessNits = displayBrightnessNits / sdrWhitePointNits * 203;
            // With a low dimming ratio, don't fit the entire curve. Otherwise mixed content
            // will appear way too bright.
            if (maxBrightnessNits < 1000.f) {
                targetBrightness = 1000.f / maxBrightnessNits;
            }
        }

        // Screenshots leaving the device must not dim in gamma space.
        const bool dimInGammaSpaceForEnhancedScreenshots = mDimInGammaSpaceForEnhancedScreenshots &&
                renderArea->getHintForSeamlessTransition();

        std::shared_ptr<ScreenCaptureOutput> output = createScreenCaptureOutput(
                ScreenCaptureOutputArgs{.compositionEngine = *compositionEngine,
                                        .colorProfile = colorProfile,
                                        .renderArea = *renderArea,
                                        .layerStack = layerStack,
                                        .buffer = std::move(buffer),
                                        .sdrWhitePointNits = sdrWhitePointNits,
                                        .displayBrightnessNits = displayBrightnessNits,
                                        .targetBrightness = targetBrightness,
                                        .regionSampling = regionSampling,
                                        .treat170mAsSrgb = mTreat170mAsSrgb,
                                        .dimInGammaSpaceForEnhancedScreenshots =
                                                dimInGammaSpaceForEnhancedScreenshots});

        const float colorSaturation = grayscale ? 0 : 1;
        compositionengine::CompositionRefreshArgs refreshArgs{
                .outputs = {output},
                .layers = std::move(layerFEs),
                .updatingOutputGeometryThisFrame = true,
                .updatingGeometryThisFrame = true,
                .colorTransformMatrix = calculateColorMatrix(colorSaturation),
        };
        compositionEngine->present(refreshArgs);

        return output->getRenderSurface()->getClientTargetAcquireFence();
    };

    // If RenderEngine is threaded, we can safely call CompositionEngine::present off the main
    // thread as the RenderEngine::drawLayers call will run on RenderEngine's thread. Otherwise,
    // we need RenderEngine to run on the main thread so we call CompositionEngine::present
    // immediately.
    //
    // TODO(b/196334700) Once we use RenderEngineThreaded everywhere we can always defer the call
    // to CompositionEngine::present.
    const bool renderEngineIsThreaded = [&]() {
        using Type = renderengine::RenderEngine::RenderEngineType;
        const auto type = mRenderEngine->getRenderEngineType();
        return type == Type::THREADED || type == Type::SKIA_GL_THREADED;
    }();
    auto presentFuture = renderEngineIsThreaded ? ftl::defer(std::move(present)).share()
                                                : ftl::yield(present()).share();

    for (auto& [layer, layerFE] : layers) {
        layer->onLayerDisplayed(ftl::Future(presentFuture)
                                        .then([layerFE = std::move(layerFE)](FenceResult) {
                                            return layerFE->stealCompositionResult()
                                                    .releaseFences.back()
                                                    .first.get();
                                        })
                                        .share(),
                                ui::INVALID_LAYER_STACK);
    }

    return presentFuture;
}

void SurfaceFlinger::traverseLegacyLayers(const LayerVector::Visitor& visitor) const {
    if (mLayerLifecycleManagerEnabled) {
        for (auto& layer : mLegacyLayers) {
            visitor(layer.second.get());
        }
    } else {
        mDrawingState.traverse(visitor);
    }
}

// ---------------------------------------------------------------------------

void SurfaceFlinger::State::traverse(const LayerVector::Visitor& visitor) const {
    layersSortedByZ.traverse(visitor);
}

void SurfaceFlinger::State::traverseInZOrder(const LayerVector::Visitor& visitor) const {
    layersSortedByZ.traverseInZOrder(stateSet, visitor);
}

void SurfaceFlinger::State::traverseInReverseZOrder(const LayerVector::Visitor& visitor) const {
    layersSortedByZ.traverseInReverseZOrder(stateSet, visitor);
}

void SurfaceFlinger::traverseLayersInLayerStack(ui::LayerStack layerStack, const int32_t uid,
                                                std::unordered_set<uint32_t> excludeLayerIds,
                                                const LayerVector::Visitor& visitor) {
    // We loop through the first level of layers without traversing,
    // as we need to determine which layers belong to the requested display.
    for (const auto& layer : mDrawingState.layersSortedByZ) {
        if (layer->getLayerStack() != layerStack) {
            continue;
        }
        // relative layers are traversed in Layer::traverseInZOrder
        layer->traverseInZOrder(LayerVector::StateSet::Drawing, [&](Layer* layer) {
            if (layer->isInternalDisplayOverlay()) {
                return;
            }
            if (!layer->isVisible()) {
                return;
            }
            if (uid != CaptureArgs::UNSET_UID && layer->getOwnerUid() != uid) {
                return;
            }

            if (!excludeLayerIds.empty()) {
                auto p = sp<Layer>::fromExisting(layer);
                while (p != nullptr) {
                    if (excludeLayerIds.count(p->sequence) != 0) {
                        return;
                    }
                    p = p->getParent();
                }
            }

            visitor(layer);
        });
    }
}

ftl::Optional<scheduler::FrameRateMode> SurfaceFlinger::getPreferredDisplayMode(
        PhysicalDisplayId displayId, DisplayModeId defaultModeId) const {
    if (const auto schedulerMode = mScheduler->getPreferredDisplayMode();
        schedulerMode.modePtr->getPhysicalDisplayId() == displayId) {
        return schedulerMode;
    }

    return mPhysicalDisplays.get(displayId)
            .transform(&PhysicalDisplay::snapshotRef)
            .and_then([&](const display::DisplaySnapshot& snapshot) {
                return snapshot.displayModes().get(defaultModeId);
            })
            .transform([](const DisplayModePtr& modePtr) {
                return scheduler::FrameRateMode{modePtr->getFps(), ftl::as_non_null(modePtr)};
            });
}

status_t SurfaceFlinger::setDesiredDisplayModeSpecsInternal(
        const sp<DisplayDevice>& display,
        const scheduler::RefreshRateSelector::PolicyVariant& policy) {
    const auto displayId = display->getPhysicalId();
    ATRACE_NAME(ftl::Concat(__func__, ' ', displayId.value).c_str());

    Mutex::Autolock lock(mStateLock);

    if (mDebugDisplayModeSetByBackdoor) {
        // ignore this request as mode is overridden by backdoor
        return NO_ERROR;
    }

    auto& selector = display->refreshRateSelector();
    using SetPolicyResult = scheduler::RefreshRateSelector::SetPolicyResult;

    switch (selector.setPolicy(policy)) {
        case SetPolicyResult::Invalid:
            return BAD_VALUE;
        case SetPolicyResult::Unchanged:
            return NO_ERROR;
        case SetPolicyResult::Changed:
            break;
    }

    if (!shouldApplyRefreshRateSelectorPolicy(*display)) {
        ALOGV("%s(%s): Skipped applying policy", __func__, to_string(displayId).c_str());
        return NO_ERROR;
    }

    return applyRefreshRateSelectorPolicy(displayId, selector);
}

bool SurfaceFlinger::shouldApplyRefreshRateSelectorPolicy(const DisplayDevice& display) const {
    if (display.isPoweredOn() || mPhysicalDisplays.size() == 1) return true;

    LOG_ALWAYS_FATAL_IF(display.isVirtual());
    const auto displayId = display.getPhysicalId();

    // The display is powered off, and this is a multi-display device. If the display is the
    // inactive internal display of a dual-display foldable, then the policy will be applied
    // when it becomes active upon powering on.
    //
    // TODO(b/255635711): Remove this function (i.e. returning `false` as a special case) once
    // concurrent mode setting across multiple (potentially powered off) displays is supported.
    //
    return displayId == mActiveDisplayId ||
            !mPhysicalDisplays.get(displayId)
                     .transform(&PhysicalDisplay::isInternal)
                     .value_or(false);
}

status_t SurfaceFlinger::applyRefreshRateSelectorPolicy(
        PhysicalDisplayId displayId, const scheduler::RefreshRateSelector& selector, bool force) {
    const scheduler::RefreshRateSelector::Policy currentPolicy = selector.getCurrentPolicy();
    ALOGV("Setting desired display mode specs: %s", currentPolicy.toString().c_str());

    // TODO(b/140204874): Leave the event in until we do proper testing with all apps that might
    // be depending in this callback.
    if (const auto activeMode = selector.getActiveMode(); displayId == mActiveDisplayId) {
        mScheduler->onPrimaryDisplayModeChanged(mAppConnectionHandle, activeMode);
        toggleKernelIdleTimer();
    } else {
        mScheduler->onNonPrimaryDisplayModeChanged(mAppConnectionHandle, activeMode);
    }

    auto preferredModeOpt = getPreferredDisplayMode(displayId, currentPolicy.defaultMode);
    if (!preferredModeOpt) {
        ALOGE("%s: Preferred mode is unknown", __func__);
        return NAME_NOT_FOUND;
    }

    auto preferredMode = std::move(*preferredModeOpt);
    const auto preferredModeId = preferredMode.modePtr->getId();

    ALOGV("Switching to Scheduler preferred mode %d (%s)", preferredModeId.value(),
          to_string(preferredMode.fps).c_str());

    if (!selector.isModeAllowed(preferredMode)) {
        ALOGE("%s: Preferred mode %d is disallowed", __func__, preferredModeId.value());
        return INVALID_OPERATION;
    }

    setDesiredActiveMode({std::move(preferredMode), .emitEvent = true}, force);
    return NO_ERROR;
}

namespace {
FpsRange translate(const gui::DisplayModeSpecs::RefreshRateRanges::RefreshRateRange& aidlRange) {
    return FpsRange{Fps::fromValue(aidlRange.min), Fps::fromValue(aidlRange.max)};
}

FpsRanges translate(const gui::DisplayModeSpecs::RefreshRateRanges& aidlRanges) {
    return FpsRanges{translate(aidlRanges.physical), translate(aidlRanges.render)};
}

gui::DisplayModeSpecs::RefreshRateRanges::RefreshRateRange translate(const FpsRange& range) {
    gui::DisplayModeSpecs::RefreshRateRanges::RefreshRateRange aidlRange;
    aidlRange.min = range.min.getValue();
    aidlRange.max = range.max.getValue();
    return aidlRange;
}

gui::DisplayModeSpecs::RefreshRateRanges translate(const FpsRanges& ranges) {
    gui::DisplayModeSpecs::RefreshRateRanges aidlRanges;
    aidlRanges.physical = translate(ranges.physical);
    aidlRanges.render = translate(ranges.render);
    return aidlRanges;
}

} // namespace

bool SurfaceFlinger::canAllocateHwcDisplayIdForVDS(uint64_t usage) {
    uint64_t flag_mask_pvt_wfd = ~0;
    uint64_t flag_mask_hw_video = ~0;
    char value[PROPERTY_VALUE_MAX] = {};
    property_get("vendor.display.vds_allow_hwc", value, "0");
    int allowHwcForVDS = atoi(value);
    // Reserve hardware acceleration for WFD use-case
    // GRALLOC_USAGE_PRIVATE_WFD + GRALLOC_USAGE_HW_VIDEO_ENCODER = WFD using HW composer.
    flag_mask_pvt_wfd = GRALLOC_USAGE_PRIVATE_WFD;
    flag_mask_hw_video = GRALLOC_USAGE_HW_VIDEO_ENCODER;
    return (allowHwcForVDS || ((usage & flag_mask_pvt_wfd) &&
            (usage & flag_mask_hw_video)));
}

status_t SurfaceFlinger::setDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                                    const gui::DisplayModeSpecs& specs) {
    ATRACE_CALL();

    if (!displayToken) {
        return BAD_VALUE;
    }

    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(kMainThreadContext) -> status_t {
        const auto display = FTL_FAKE_GUARD(mStateLock, getDisplayDeviceLocked(displayToken));
        if (!display) {
            ALOGE("Attempt to set desired display modes for invalid display token %p",
                  displayToken.get());
            return NAME_NOT_FOUND;
        } else if (display->isVirtual()) {
            ALOGW("Attempt to set desired display modes for virtual display");
            return INVALID_OPERATION;
        } else {
            using Policy = scheduler::RefreshRateSelector::DisplayManagerPolicy;
            const Policy policy{DisplayModeId(specs.defaultMode), translate(specs.primaryRanges),
                                translate(specs.appRequestRanges), specs.allowGroupSwitching};

            return setDesiredDisplayModeSpecsInternal(display, policy);
        }
    });

    return future.get();
}

status_t SurfaceFlinger::getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                                    gui::DisplayModeSpecs* outSpecs) {
    ATRACE_CALL();

    if (!displayToken || !outSpecs) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);
    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    if (display->isVirtual()) {
        return INVALID_OPERATION;
    }

    scheduler::RefreshRateSelector::Policy policy =
            display->refreshRateSelector().getDisplayManagerPolicy();
    outSpecs->defaultMode = policy.defaultMode.value();
    outSpecs->allowGroupSwitching = policy.allowGroupSwitching;
    outSpecs->primaryRanges = translate(policy.primaryRanges);
    outSpecs->appRequestRanges = translate(policy.appRequestRanges);
    return NO_ERROR;
}

void SurfaceFlinger::onLayerFirstRef(Layer* layer) {
    mNumLayers++;
    if (!layer->isRemovedFromCurrentState()) {
        mScheduler->registerLayer(layer);
    }
}

void SurfaceFlinger::onLayerDestroyed(Layer* layer) {
    mNumLayers--;
    removeHierarchyFromOffscreenLayers(layer);
    if (!layer->isRemovedFromCurrentState()) {
        mScheduler->deregisterLayer(layer);
    }
    if (mTransactionTracing) {
        mTransactionTracing->onLayerRemoved(layer->getSequence());
    }
}

void SurfaceFlinger::onLayerUpdate() {
    scheduleCommit(FrameHint::kActive);
}

// WARNING: ONLY CALL THIS FROM LAYER DTOR
// Here we add children in the current state to offscreen layers and remove the
// layer itself from the offscreen layer list.  Since
// this is the dtor, it is safe to access the current state.  This keeps us
// from dangling children layers such that they are not reachable from the
// Drawing state nor the offscreen layer list
// See b/141111965
void SurfaceFlinger::removeHierarchyFromOffscreenLayers(Layer* layer) {
    for (auto& child : layer->getCurrentChildren()) {
        mOffscreenLayers.emplace(child.get());
    }
    mOffscreenLayers.erase(layer);
}

void SurfaceFlinger::removeFromOffscreenLayers(Layer* layer) {
    mOffscreenLayers.erase(layer);
}

status_t SurfaceFlinger::setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                                 float lightPosY, float lightPosZ,
                                                 float lightRadius) {
    Mutex::Autolock _l(mStateLock);
    mCurrentState.globalShadowSettings.ambientColor = vec4(ambientColor);
    mCurrentState.globalShadowSettings.spotColor = vec4(spotColor);
    mCurrentState.globalShadowSettings.lightPos.y = lightPosY;
    mCurrentState.globalShadowSettings.lightPos.z = lightPosZ;
    mCurrentState.globalShadowSettings.lightRadius = lightRadius;

    // these values are overridden when calculating the shadow settings for a layer.
    mCurrentState.globalShadowSettings.lightPos.x = 0.f;
    mCurrentState.globalShadowSettings.length = 0.f;
    return NO_ERROR;
}

const std::unordered_map<std::string, uint32_t>& SurfaceFlinger::getGenericLayerMetadataKeyMap()
        const {
    // TODO(b/149500060): Remove this fixed/static mapping. Please prefer taking
    // on the work to remove the table in that bug rather than adding more to
    // it.
    static const std::unordered_map<std::string, uint32_t> genericLayerMetadataKeyMap{
            {"org.chromium.arc.V1_0.TaskId", gui::METADATA_TASK_ID},
            {"org.chromium.arc.V1_0.CursorInfo", gui::METADATA_MOUSE_CURSOR},
    };
    return genericLayerMetadataKeyMap;
}

status_t SurfaceFlinger::setOverrideFrameRate(uid_t uid, float frameRate) {
    PhysicalDisplayId displayId = [&]() {
        Mutex::Autolock lock(mStateLock);
        return getDefaultDisplayDeviceLocked()->getPhysicalId();
    }();

    mScheduler->setGameModeRefreshRateForUid(FrameRateOverride{static_cast<uid_t>(uid), frameRate});
    mScheduler->onFrameRateOverridesChanged(mAppConnectionHandle, displayId);
    return NO_ERROR;
}

status_t SurfaceFlinger::updateSmallAreaDetection(
        std::vector<std::pair<uid_t, float>>& uidThresholdMappings) {
    mScheduler->updateSmallAreaDetection(uidThresholdMappings);
    return NO_ERROR;
}

status_t SurfaceFlinger::setSmallAreaDetectionThreshold(uid_t uid, float threshold) {
    mScheduler->setSmallAreaDetectionThreshold(uid, threshold);
    return NO_ERROR;
}

void SurfaceFlinger::enableRefreshRateOverlay(bool enable) {
    bool setByHwc = getHwComposer().hasCapability(Capability::REFRESH_RATE_CHANGED_CALLBACK_DEBUG);
    for (const auto& [id, display] : mPhysicalDisplays) {
        if (display.snapshot().connectionType() == ui::DisplayConnectionType::Internal) {
            if (const auto device = getDisplayDeviceLocked(id)) {
                const auto enableOverlay = [&](const bool setByHwc) FTL_FAKE_GUARD(
                                                   kMainThreadContext) {
                    device->enableRefreshRateOverlay(enable, setByHwc, mRefreshRateOverlaySpinner,
                                                     mRefreshRateOverlayRenderRate,
                                                     mRefreshRateOverlayShowInMiddle);
                };
                enableOverlay(setByHwc);
                if (setByHwc) {
                    const auto status =
                            getHwComposer().setRefreshRateChangedCallbackDebugEnabled(id, enable);
                    if (status != NO_ERROR) {
                        ALOGE("Error updating the refresh rate changed callback debug enabled");
                        enableOverlay(/*setByHwc*/ false);
                    }
                }
            }
        }
    }
}

int SurfaceFlinger::getGpuContextPriority() {
    return getRenderEngine().getContextPriority();
}

int SurfaceFlinger::calculateMaxAcquiredBufferCount(Fps refreshRate,
                                                    std::chrono::nanoseconds presentLatency) {
    auto pipelineDepth = presentLatency.count() / refreshRate.getPeriodNsecs();
    if (presentLatency.count() % refreshRate.getPeriodNsecs()) {
        pipelineDepth++;
    }
    return std::max(1ll, pipelineDepth - 1);
}

status_t SurfaceFlinger::getMaxAcquiredBufferCount(int* buffers) const {
    Fps maxRefreshRate = 60_Hz;

    if (!getHwComposer().isHeadless()) {
        if (const auto display = getDefaultDisplayDevice()) {
            maxRefreshRate = display->refreshRateSelector().getSupportedRefreshRateRange().max;
        }
    }

    *buffers = getMaxAcquiredBufferCountForRefreshRate(maxRefreshRate);
    return NO_ERROR;
}

uint32_t SurfaceFlinger::getMaxAcquiredBufferCountForCurrentRefreshRate(uid_t uid) const {
    Fps refreshRate = 60_Hz;

    if (const auto frameRateOverride = mScheduler->getFrameRateOverride(uid)) {
        refreshRate = *frameRateOverride;
    } else if (!getHwComposer().isHeadless()) {
        if (const auto display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked())) {
            refreshRate = display->refreshRateSelector().getActiveMode().fps;
        }
    }

    return getMaxAcquiredBufferCountForRefreshRate(refreshRate);
}

int SurfaceFlinger::getMaxAcquiredBufferCountForRefreshRate(Fps refreshRate) const {
    const auto vsyncConfig = mVsyncConfiguration->getConfigsForRefreshRate(refreshRate).late;
    const auto presentLatency = vsyncConfig.appWorkDuration + vsyncConfig.sfWorkDuration;
    return calculateMaxAcquiredBufferCount(refreshRate, presentLatency);
}

void SurfaceFlinger::handleLayerCreatedLocked(const LayerCreatedState& state, VsyncId vsyncId) {
    sp<Layer> layer = state.layer.promote();
    if (!layer) {
        ALOGD("Layer was destroyed soon after creation %p", state.layer.unsafe_get());
        return;
    }
    MUTEX_ALIAS(mStateLock, layer->mFlinger->mStateLock);

    sp<Layer> parent;
    bool addToRoot = state.addToRoot;
    if (state.initialParent != nullptr) {
        parent = state.initialParent.promote();
        if (parent == nullptr) {
            ALOGD("Parent was destroyed soon after creation %p", state.initialParent.unsafe_get());
            addToRoot = false;
        }
    }

    if (parent == nullptr && addToRoot) {
        layer->setIsAtRoot(true);
        mCurrentState.layersSortedByZ.add(layer);
    } else if (parent == nullptr) {
        layer->onRemovedFromCurrentState();
    } else if (parent->isRemovedFromCurrentState()) {
        parent->addChild(layer);
        layer->onRemovedFromCurrentState();
    } else {
        parent->addChild(layer);
    }

    ui::LayerStack layerStack = layer->getLayerStack(LayerVector::StateSet::Current);
    sp<const DisplayDevice> hintDisplay;
    // Find the display that includes the layer.
    for (const auto& [token, display] : mDisplays) {
        if (display->getLayerStack() == layerStack) {
            hintDisplay = display;
            break;
        }
    }

    if (hintDisplay) {
        layer->updateTransformHint(hintDisplay->getTransformHint());
    }
}

void SurfaceFlinger::sample() {
    if (!mLumaSampling || !mRegionSamplingThread) {
        return;
    }

    mRegionSamplingThread->onCompositionComplete(mScheduler->getScheduledFrameTime());
}

void SurfaceFlinger::onActiveDisplaySizeChanged(const DisplayDevice& activeDisplay) {
    mScheduler->onActiveDisplayAreaChanged(activeDisplay.getWidth() * activeDisplay.getHeight());
    getRenderEngine().onActiveDisplaySizeChanged(activeDisplay.getSize());

    // Notify layers to update small dirty flag.
    if (mScheduler->supportSmallDirtyDetection()) {
        mCurrentState.traverse([&](Layer* layer) {
            if (layer->getLayerStack() == activeDisplay.getLayerStack()) {
                layer->setIsSmallDirty();
            }
        });
    }
}

sp<DisplayDevice> SurfaceFlinger::getActivatableDisplay() const {
    if (mPhysicalDisplays.size() == 1) return nullptr;

    // TODO(b/255635821): Choose the pacesetter display, considering both internal and external
    // displays. For now, pick the other internal display, assuming a dual-display foldable.
    return findDisplay([this](const DisplayDevice& display) REQUIRES(mStateLock) {
        const auto idOpt = PhysicalDisplayId::tryCast(display.getId());
        return idOpt && *idOpt != mActiveDisplayId && display.isPoweredOn() &&
                mPhysicalDisplays.get(*idOpt)
                        .transform(&PhysicalDisplay::isInternal)
                        .value_or(false);
    });
}

void SurfaceFlinger::onActiveDisplayChangedLocked(const DisplayDevice* inactiveDisplayPtr,
                                                  const DisplayDevice& activeDisplay) {
    ATRACE_CALL();

    // For the first display activated during boot, there is no need to force setDesiredActiveMode,
    // because DM is about to send its policy via setDesiredDisplayModeSpecs.
    bool forceApplyPolicy = false;

    if (inactiveDisplayPtr) {
        inactiveDisplayPtr->getCompositionDisplay()->setLayerCachingTexturePoolEnabled(false);
        forceApplyPolicy = true;
    }

    mActiveDisplayId = activeDisplay.getPhysicalId();
    activeDisplay.getCompositionDisplay()->setLayerCachingTexturePoolEnabled(true);

    resetPhaseConfiguration(activeDisplay.getActiveMode().fps);

    // TODO(b/255635711): Check for pending mode changes on other displays.
    mScheduler->setModeChangePending(false);

    mScheduler->setPacesetterDisplay(mActiveDisplayId);

    onActiveDisplaySizeChanged(activeDisplay);
    mActiveDisplayTransformHint = activeDisplay.getTransformHint();
    sActiveDisplayRotationFlags = ui::Transform::toRotationFlags(activeDisplay.getOrientation());

    // The policy of the new active/pacesetter display may have changed while it was inactive. In
    // that case, its preferred mode has not been propagated to HWC (via setDesiredActiveMode). In
    // either case, the Scheduler's cachedModeChangedParams must be initialized to the newly active
    // mode, and the kernel idle timer of the newly active display must be toggled.
    applyRefreshRateSelectorPolicy(mActiveDisplayId, activeDisplay.refreshRateSelector(),
                                   forceApplyPolicy);
}

status_t SurfaceFlinger::addWindowInfosListener(const sp<IWindowInfosListener>& windowInfosListener,
                                                gui::WindowInfosListenerInfo* outInfo) {
    mWindowInfosListenerInvoker->addWindowInfosListener(windowInfosListener, outInfo);
    setTransactionFlags(eInputInfoUpdateNeeded);
    return NO_ERROR;
}

status_t SurfaceFlinger::removeWindowInfosListener(
        const sp<IWindowInfosListener>& windowInfosListener) const {
    mWindowInfosListenerInvoker->removeWindowInfosListener(windowInfosListener);
    return NO_ERROR;
}

status_t SurfaceFlinger::getStalledTransactionInfo(
        int pid, std::optional<TransactionHandler::StalledTransactionInfo>& result) {
    result = mTransactionHandler.getStalledTransactionInfo(pid);
    return NO_ERROR;
}

std::shared_ptr<renderengine::ExternalTexture> SurfaceFlinger::getExternalTextureFromBufferData(
        BufferData& bufferData, const char* layerName, uint64_t transactionId) {
    if (bufferData.buffer &&
        exceedsMaxRenderTargetSize(bufferData.buffer->getWidth(), bufferData.buffer->getHeight())) {
        std::string errorMessage =
                base::StringPrintf("Attempted to create an ExternalTexture with size (%u, %u) for "
                                   "layer %s that exceeds render target size limit of %u.",
                                   bufferData.buffer->getWidth(), bufferData.buffer->getHeight(),
                                   layerName, static_cast<uint32_t>(mMaxRenderTargetSize));
        ALOGD("%s", errorMessage.c_str());
        if (bufferData.releaseBufferListener) {
            bufferData.releaseBufferListener->onTransactionQueueStalled(
                    String8(errorMessage.c_str()));
        }
        return nullptr;
    }

    bool cachedBufferChanged =
            bufferData.flags.test(BufferData::BufferDataChange::cachedBufferChanged);
    if (cachedBufferChanged && bufferData.buffer) {
        auto result = ClientCache::getInstance().add(bufferData.cachedBuffer, bufferData.buffer);
        if (result.ok()) {
            return result.value();
        }

        if (result.error() == ClientCache::AddError::CacheFull) {
            ALOGE("Attempted to create an ExternalTexture for layer %s but CacheFull", layerName);

            if (bufferData.releaseBufferListener) {
                bufferData.releaseBufferListener->onTransactionQueueStalled(
                        String8("Buffer processing hung due to full buffer cache"));
            }
        }

        return nullptr;
    }

    if (cachedBufferChanged) {
        return ClientCache::getInstance().get(bufferData.cachedBuffer);
    }

    if (bufferData.buffer) {
        return std::make_shared<
                renderengine::impl::ExternalTexture>(bufferData.buffer, getRenderEngine(),
                                                     renderengine::impl::ExternalTexture::Usage::
                                                             READABLE);
    }

    return nullptr;
}

bool SurfaceFlinger::commitMirrorDisplays(VsyncId vsyncId) {
    std::vector<MirrorDisplayState> mirrorDisplays;
    {
        std::scoped_lock<std::mutex> lock(mMirrorDisplayLock);
        mirrorDisplays = std::move(mMirrorDisplays);
        mMirrorDisplays.clear();
        if (mirrorDisplays.size() == 0) {
            return false;
        }
    }

    sp<IBinder> unused;
    for (const auto& mirrorDisplay : mirrorDisplays) {
        // Set mirror layer's default layer stack to -1 so it doesn't end up rendered on a display
        // accidentally.
        sp<Layer> rootMirrorLayer = LayerHandle::getLayer(mirrorDisplay.rootHandle);
        ssize_t idx = mCurrentState.layersSortedByZ.indexOf(rootMirrorLayer);
        bool ret = rootMirrorLayer->setLayerStack(ui::LayerStack::fromValue(-1));
        if (idx >= 0 && ret) {
            mCurrentState.layersSortedByZ.removeAt(idx);
            mCurrentState.layersSortedByZ.add(rootMirrorLayer);
        }

        for (const auto& layer : mDrawingState.layersSortedByZ) {
            if (layer->getLayerStack() != mirrorDisplay.layerStack ||
                layer->isInternalDisplayOverlay()) {
                continue;
            }

            LayerCreationArgs mirrorArgs(this, mirrorDisplay.client, "MirrorLayerParent",
                                         ISurfaceComposerClient::eNoColorFill,
                                         gui::LayerMetadata());
            sp<Layer> childMirror;
            {
                Mutex::Autolock lock(mStateLock);
                createEffectLayer(mirrorArgs, &unused, &childMirror);
                MUTEX_ALIAS(mStateLock, childMirror->mFlinger->mStateLock);
                childMirror->setClonedChild(layer->createClone(childMirror->getSequence()));
                childMirror->reparent(mirrorDisplay.rootHandle);
            }
            // lock on mStateLock needs to be released before binder handle gets destroyed
            unused.clear();
        }
    }
    return true;
}

bool SurfaceFlinger::commitCreatedLayers(VsyncId vsyncId,
                                         std::vector<LayerCreatedState>& createdLayers) {
    if (createdLayers.size() == 0) {
        return false;
    }

    Mutex::Autolock _l(mStateLock);
    for (const auto& createdLayer : createdLayers) {
        handleLayerCreatedLocked(createdLayer, vsyncId);
    }
    mLayersAdded = true;
    return mLayersAdded;
}

void SurfaceFlinger::updateLayerMetadataSnapshot() {
    LayerMetadata parentMetadata;
    for (const auto& layer : mDrawingState.layersSortedByZ) {
        layer->updateMetadataSnapshot(parentMetadata);
    }

    std::unordered_set<Layer*> visited;
    mDrawingState.traverse([&visited](Layer* layer) {
        if (visited.find(layer) != visited.end()) {
            return;
        }

        // If the layer isRelativeOf, then either it's relative metadata will be set
        // recursively when updateRelativeMetadataSnapshot is called on its relative parent or
        // it's relative parent has been deleted. Clear the layer's relativeLayerMetadata to ensure
        // that layers with deleted relative parents don't hold stale relativeLayerMetadata.
        if (layer->getDrawingState().isRelativeOf) {
            layer->editLayerSnapshot()->relativeLayerMetadata = {};
            return;
        }

        layer->updateRelativeMetadataSnapshot({}, visited);
    });
}

void SurfaceFlinger::moveSnapshotsFromCompositionArgs(
        compositionengine::CompositionRefreshArgs& refreshArgs,
        const std::vector<std::pair<Layer*, LayerFE*>>& layers) {
    if (mLayerLifecycleManagerEnabled) {
        std::vector<std::unique_ptr<frontend::LayerSnapshot>>& snapshots =
                mLayerSnapshotBuilder.getSnapshots();
        for (auto [_, layerFE] : layers) {
            auto i = layerFE->mSnapshot->globalZ;
            snapshots[i] = std::move(layerFE->mSnapshot);
        }
    }
    if (mLegacyFrontEndEnabled && !mLayerLifecycleManagerEnabled) {
        for (auto [layer, layerFE] : layers) {
            layer->updateLayerSnapshot(std::move(layerFE->mSnapshot));
        }
    }
}

std::vector<std::pair<Layer*, LayerFE*>> SurfaceFlinger::moveSnapshotsToCompositionArgs(
        compositionengine::CompositionRefreshArgs& refreshArgs, bool cursorOnly) {
    std::vector<std::pair<Layer*, LayerFE*>> layers;
    if (mLayerLifecycleManagerEnabled) {
        nsecs_t currentTime = systemTime();
        mLayerSnapshotBuilder.forEachVisibleSnapshot(
                [&](std::unique_ptr<frontend::LayerSnapshot>& snapshot) {
                    if (cursorOnly &&
                        snapshot->compositionType !=
                                aidl::android::hardware::graphics::composer3::Composition::CURSOR) {
                        return;
                    }

                    if (!snapshot->hasSomethingToDraw()) {
                        return;
                    }

                    auto it = mLegacyLayers.find(snapshot->sequence);
                    LOG_ALWAYS_FATAL_IF(it == mLegacyLayers.end(),
                                        "Couldnt find layer object for %s",
                                        snapshot->getDebugString().c_str());
                    auto& legacyLayer = it->second;
                    sp<LayerFE> layerFE = legacyLayer->getCompositionEngineLayerFE(snapshot->path);
                    snapshot->fps = getLayerFramerate(currentTime, snapshot->sequence);
                    layerFE->mSnapshot = std::move(snapshot);
                    refreshArgs.layers.push_back(layerFE);
                    layers.emplace_back(legacyLayer.get(), layerFE.get());
                });
    }
    if (mLegacyFrontEndEnabled && !mLayerLifecycleManagerEnabled) {
        auto moveSnapshots = [&layers, &refreshArgs, cursorOnly](Layer* layer) {
            if (const auto& layerFE = layer->getCompositionEngineLayerFE()) {
                if (cursorOnly &&
                    layer->getLayerSnapshot()->compositionType !=
                            aidl::android::hardware::graphics::composer3::Composition::CURSOR)
                    return;
                layer->updateSnapshot(refreshArgs.updatingGeometryThisFrame);
                layerFE->mSnapshot = layer->stealLayerSnapshot();
                refreshArgs.layers.push_back(layerFE);
                layers.emplace_back(layer, layerFE.get());
            }
        };

        if (cursorOnly || !mVisibleRegionsDirty) {
            // for hot path avoid traversals by walking though the previous composition list
            for (sp<Layer> layer : mPreviouslyComposedLayers) {
                moveSnapshots(layer.get());
            }
        } else {
            mPreviouslyComposedLayers.clear();
            mDrawingState.traverseInZOrder(
                    [&moveSnapshots](Layer* layer) { moveSnapshots(layer); });
            mPreviouslyComposedLayers.reserve(layers.size());
            for (auto [layer, _] : layers) {
                mPreviouslyComposedLayers.push_back(sp<Layer>::fromExisting(layer));
            }
        }
    }

    return layers;
}

std::function<std::vector<std::pair<Layer*, sp<LayerFE>>>()>
SurfaceFlinger::getLayerSnapshotsForScreenshots(
        std::optional<ui::LayerStack> layerStack, uint32_t uid,
        std::function<bool(const frontend::LayerSnapshot&, bool& outStopTraversal)>
                snapshotFilterFn) {
    return [&, layerStack, uid]() {
        std::vector<std::pair<Layer*, sp<LayerFE>>> layers;
        bool stopTraversal = false;
        mLayerSnapshotBuilder.forEachVisibleSnapshot(
                [&](std::unique_ptr<frontend::LayerSnapshot>& snapshot) {
                    if (stopTraversal) {
                        return;
                    }
                    if (layerStack && snapshot->outputFilter.layerStack != *layerStack) {
                        return;
                    }
                    if (uid != CaptureArgs::UNSET_UID && snapshot->uid != gui::Uid(uid)) {
                        return;
                    }
                    if (!snapshot->hasSomethingToDraw()) {
                        return;
                    }
                    if (snapshotFilterFn && !snapshotFilterFn(*snapshot, stopTraversal)) {
                        return;
                    }

                    auto it = mLegacyLayers.find(snapshot->sequence);
                    LOG_ALWAYS_FATAL_IF(it == mLegacyLayers.end(),
                                        "Couldnt find layer object for %s",
                                        snapshot->getDebugString().c_str());
                    Layer* legacyLayer = (it == mLegacyLayers.end()) ? nullptr : it->second.get();
                    sp<LayerFE> layerFE = getFactory().createLayerFE(snapshot->name);
                    layerFE->mSnapshot = std::make_unique<frontend::LayerSnapshot>(*snapshot);
                    layers.emplace_back(legacyLayer, std::move(layerFE));
                });

        return layers;
    };
}

std::function<std::vector<std::pair<Layer*, sp<LayerFE>>>()>
SurfaceFlinger::getLayerSnapshotsForScreenshots(std::optional<ui::LayerStack> layerStack,
                                                uint32_t uid,
                                                std::unordered_set<uint32_t> excludeLayerIds) {
    return [&, layerStack, uid, excludeLayerIds = std::move(excludeLayerIds)]() {
        if (excludeLayerIds.empty()) {
            auto getLayerSnapshotsFn =
                    getLayerSnapshotsForScreenshots(layerStack, uid, /*snapshotFilterFn=*/nullptr);
            std::vector<std::pair<Layer*, sp<LayerFE>>> layers = getLayerSnapshotsFn();
            return layers;
        }

        frontend::LayerSnapshotBuilder::Args
                args{.root = mLayerHierarchyBuilder.getHierarchy(),
                     .layerLifecycleManager = mLayerLifecycleManager,
                     .forceUpdate = frontend::LayerSnapshotBuilder::ForceUpdateFlags::HIERARCHY,
                     .displays = mFrontEndDisplayInfos,
                     .displayChanges = true,
                     .globalShadowSettings = mDrawingState.globalShadowSettings,
                     .supportsBlur = mSupportsBlur,
                     .forceFullDamage = mForceFullDamage,
                     .excludeLayerIds = std::move(excludeLayerIds),
                     .supportedLayerGenericMetadata =
                             getHwComposer().getSupportedLayerGenericMetadata(),
                     .genericLayerMetadataKeyMap = getGenericLayerMetadataKeyMap()};
        mLayerSnapshotBuilder.update(args);

        auto getLayerSnapshotsFn =
                getLayerSnapshotsForScreenshots(layerStack, uid, /*snapshotFilterFn=*/nullptr);
        std::vector<std::pair<Layer*, sp<LayerFE>>> layers = getLayerSnapshotsFn();

        args.excludeLayerIds.clear();
        mLayerSnapshotBuilder.update(args);

        return layers;
    };
}

std::function<std::vector<std::pair<Layer*, sp<LayerFE>>>()>
SurfaceFlinger::getLayerSnapshotsForScreenshots(uint32_t rootLayerId, uint32_t uid,
                                                std::unordered_set<uint32_t> excludeLayerIds,
                                                bool childrenOnly,
                                                const std::optional<FloatRect>& parentCrop) {
    return [&, rootLayerId, uid, excludeLayerIds = std::move(excludeLayerIds), childrenOnly,
            parentCrop]() {
        auto root = mLayerHierarchyBuilder.getPartialHierarchy(rootLayerId, childrenOnly);
        frontend::LayerSnapshotBuilder::Args
                args{.root = root,
                     .layerLifecycleManager = mLayerLifecycleManager,
                     .forceUpdate = frontend::LayerSnapshotBuilder::ForceUpdateFlags::HIERARCHY,
                     .displays = mFrontEndDisplayInfos,
                     .displayChanges = true,
                     .globalShadowSettings = mDrawingState.globalShadowSettings,
                     .supportsBlur = mSupportsBlur,
                     .forceFullDamage = mForceFullDamage,
                     .parentCrop = parentCrop,
                     .excludeLayerIds = std::move(excludeLayerIds),
                     .supportedLayerGenericMetadata =
                             getHwComposer().getSupportedLayerGenericMetadata(),
                     .genericLayerMetadataKeyMap = getGenericLayerMetadataKeyMap()};
        mLayerSnapshotBuilder.update(args);

        auto getLayerSnapshotsFn =
                getLayerSnapshotsForScreenshots({}, uid, /*snapshotFilterFn=*/nullptr);
        std::vector<std::pair<Layer*, sp<LayerFE>>> layers = getLayerSnapshotsFn();
        args.root = mLayerHierarchyBuilder.getHierarchy();
        args.parentCrop.reset();
        args.excludeLayerIds.clear();
        mLayerSnapshotBuilder.update(args);
        return layers;
    };
}

frontend::Update SurfaceFlinger::flushLifecycleUpdates() {
    frontend::Update update;
    ATRACE_NAME("TransactionHandler:flushTransactions");
    // Locking:
    // 1. to prevent onHandleDestroyed from being called while the state lock is held,
    // we must keep a copy of the transactions (specifically the composer
    // states) around outside the scope of the lock.
    // 2. Transactions and created layers do not share a lock. To prevent applying
    // transactions with layers still in the createdLayer queue, flush the transactions
    // before committing the created layers.
    update.transactions = mTransactionHandler.flushTransactions();
    {
        // TODO(b/238781169) lockless queue this and keep order.
        std::scoped_lock<std::mutex> lock(mCreatedLayersLock);
        update.layerCreatedStates = std::move(mCreatedLayers);
        mCreatedLayers.clear();
        update.newLayers = std::move(mNewLayers);
        mNewLayers.clear();
        update.layerCreationArgs = std::move(mNewLayerArgs);
        mNewLayerArgs.clear();
        update.destroyedHandles = std::move(mDestroyedHandles);
        mDestroyedHandles.clear();
    }
    return update;
}

void SurfaceFlinger::addToLayerTracing(bool visibleRegionDirty, TimePoint time, VsyncId vsyncId) {
    const uint32_t tracingFlags = mLayerTracing.getFlags();
    LayersProto layers(dumpDrawingStateProto(tracingFlags));
    if (tracingFlags & LayerTracing::TRACE_EXTRA) {
        dumpOffscreenLayersProto(layers);
    }
    std::string hwcDump;
    if (tracingFlags & LayerTracing::TRACE_HWC) {
        dumpHwc(hwcDump);
    }
    auto displays = dumpDisplayProto();
    mLayerTracing.notify(visibleRegionDirty, time.ns(), ftl::to_underlying(vsyncId), &layers,
                         std::move(hwcDump), &displays);
}

// gui::ISurfaceComposer

binder::Status SurfaceComposerAIDL::bootFinished() {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }
    mFlinger->bootFinished();
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::createDisplayEventConnection(
        VsyncSource vsyncSource, EventRegistration eventRegistration,
        const sp<IBinder>& layerHandle, sp<IDisplayEventConnection>* outConnection) {
    sp<IDisplayEventConnection> conn =
            mFlinger->createDisplayEventConnection(vsyncSource, eventRegistration, layerHandle);
    if (conn == nullptr) {
        *outConnection = nullptr;
        return binderStatusFromStatusT(BAD_VALUE);
    } else {
        *outConnection = conn;
        return binder::Status::ok();
    }
}

binder::Status SurfaceComposerAIDL::createConnection(sp<gui::ISurfaceComposerClient>* outClient) {
    const sp<Client> client = sp<Client>::make(mFlinger);
    if (client->initCheck() == NO_ERROR) {
        *outClient = client;
        return binder::Status::ok();
    } else {
        *outClient = nullptr;
        return binderStatusFromStatusT(BAD_VALUE);
    }
}

binder::Status SurfaceComposerAIDL::createDisplay(const std::string& displayName, bool secure,
                                                  float requestedRefreshRate,
                                                  sp<IBinder>* outDisplay) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }
    String8 displayName8 = String8::format("%s", displayName.c_str());
    *outDisplay = mFlinger->createDisplay(displayName8, secure, requestedRefreshRate);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::destroyDisplay(const sp<IBinder>& display) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }
    mFlinger->destroyDisplay(display);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::getPhysicalDisplayIds(std::vector<int64_t>* outDisplayIds) {
    std::vector<PhysicalDisplayId> physicalDisplayIds = mFlinger->getPhysicalDisplayIds();
    std::vector<int64_t> displayIds;
    displayIds.reserve(physicalDisplayIds.size());
    for (auto item : physicalDisplayIds) {
        displayIds.push_back(static_cast<int64_t>(item.value));
    }
    *outDisplayIds = displayIds;
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::getPhysicalDisplayToken(int64_t displayId,
                                                            sp<IBinder>* outDisplay) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }
    const auto id = DisplayId::fromValue<PhysicalDisplayId>(static_cast<uint64_t>(displayId));
    *outDisplay = mFlinger->getPhysicalDisplayToken(*id);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::setPowerMode(const sp<IBinder>& display, int mode) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }
    mFlinger->setPowerMode(display, mode);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::getSupportedFrameTimestamps(
        std::vector<FrameEvent>* outSupported) {
    status_t status;
    if (!outSupported) {
        status = UNEXPECTED_NULL;
    } else {
        outSupported->clear();
        status = mFlinger->getSupportedFrameTimestamps(outSupported);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayStats(const sp<IBinder>& display,
                                                    gui::DisplayStatInfo* outStatInfo) {
    DisplayStatInfo statInfo;
    status_t status = mFlinger->getDisplayStats(display, &statInfo);
    if (status == NO_ERROR) {
        outStatInfo->vsyncTime = static_cast<long>(statInfo.vsyncTime);
        outStatInfo->vsyncPeriod = static_cast<long>(statInfo.vsyncPeriod);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayState(const sp<IBinder>& display,
                                                    gui::DisplayState* outState) {
    ui::DisplayState state;
    status_t status = mFlinger->getDisplayState(display, &state);
    if (status == NO_ERROR) {
        outState->layerStack = state.layerStack.id;
        outState->orientation = static_cast<gui::Rotation>(state.orientation);
        outState->layerStackSpaceRect.width = state.layerStackSpaceRect.width;
        outState->layerStackSpaceRect.height = state.layerStackSpaceRect.height;
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getStaticDisplayInfo(int64_t displayId,
                                                         gui::StaticDisplayInfo* outInfo) {
    using Tag = gui::DeviceProductInfo::ManufactureOrModelDate::Tag;
    ui::StaticDisplayInfo info;

    status_t status = mFlinger->getStaticDisplayInfo(displayId, &info);
    if (status == NO_ERROR) {
        // convert ui::StaticDisplayInfo to gui::StaticDisplayInfo
        outInfo->connectionType = static_cast<gui::DisplayConnectionType>(info.connectionType);
        outInfo->density = info.density;
        outInfo->secure = info.secure;
        outInfo->installOrientation = static_cast<gui::Rotation>(info.installOrientation);

        if (const std::optional<DeviceProductInfo> dpi = info.deviceProductInfo) {
            gui::DeviceProductInfo dinfo;
            dinfo.name = std::move(dpi->name);
            dinfo.manufacturerPnpId = std::vector<uint8_t>(dpi->manufacturerPnpId.begin(),
                                                           dpi->manufacturerPnpId.end());
            dinfo.productId = dpi->productId;
            dinfo.relativeAddress =
                    std::vector<uint8_t>(dpi->relativeAddress.begin(), dpi->relativeAddress.end());
            if (const auto* model =
                        std::get_if<DeviceProductInfo::ModelYear>(&dpi->manufactureOrModelDate)) {
                gui::DeviceProductInfo::ModelYear modelYear;
                modelYear.year = model->year;
                dinfo.manufactureOrModelDate.set<Tag::modelYear>(modelYear);
            } else if (const auto* manufacture = std::get_if<DeviceProductInfo::ManufactureYear>(
                               &dpi->manufactureOrModelDate)) {
                gui::DeviceProductInfo::ManufactureYear date;
                date.modelYear.year = manufacture->year;
                dinfo.manufactureOrModelDate.set<Tag::manufactureYear>(date);
            } else if (const auto* manufacture =
                               std::get_if<DeviceProductInfo::ManufactureWeekAndYear>(
                                       &dpi->manufactureOrModelDate)) {
                gui::DeviceProductInfo::ManufactureWeekAndYear date;
                date.manufactureYear.modelYear.year = manufacture->year;
                date.week = manufacture->week;
                dinfo.manufactureOrModelDate.set<Tag::manufactureWeekAndYear>(date);
            }

            outInfo->deviceProductInfo = dinfo;
        }
    }
    return binderStatusFromStatusT(status);
}

void SurfaceComposerAIDL::getDynamicDisplayInfoInternal(ui::DynamicDisplayInfo& info,
                                                        gui::DynamicDisplayInfo*& outInfo) {
    // convert ui::DynamicDisplayInfo to gui::DynamicDisplayInfo
    outInfo->supportedDisplayModes.clear();
    outInfo->supportedDisplayModes.reserve(info.supportedDisplayModes.size());
    for (const auto& mode : info.supportedDisplayModes) {
        gui::DisplayMode outMode;
        outMode.id = mode.id;
        outMode.resolution.width = mode.resolution.width;
        outMode.resolution.height = mode.resolution.height;
        outMode.xDpi = mode.xDpi;
        outMode.yDpi = mode.yDpi;
        outMode.refreshRate = mode.refreshRate;
        outMode.appVsyncOffset = mode.appVsyncOffset;
        outMode.sfVsyncOffset = mode.sfVsyncOffset;
        outMode.presentationDeadline = mode.presentationDeadline;
        outMode.group = mode.group;
        std::transform(mode.supportedHdrTypes.begin(), mode.supportedHdrTypes.end(),
                       std::back_inserter(outMode.supportedHdrTypes),
                       [](const ui::Hdr& value) { return static_cast<int32_t>(value); });
        outInfo->supportedDisplayModes.push_back(outMode);
    }

    outInfo->activeDisplayModeId = info.activeDisplayModeId;
    outInfo->renderFrameRate = info.renderFrameRate;

    outInfo->supportedColorModes.clear();
    outInfo->supportedColorModes.reserve(info.supportedColorModes.size());
    for (const auto& cmode : info.supportedColorModes) {
        outInfo->supportedColorModes.push_back(static_cast<int32_t>(cmode));
    }

    outInfo->activeColorMode = static_cast<int32_t>(info.activeColorMode);

    gui::HdrCapabilities& hdrCapabilities = outInfo->hdrCapabilities;
    hdrCapabilities.supportedHdrTypes.clear();
    hdrCapabilities.supportedHdrTypes.reserve(info.hdrCapabilities.getSupportedHdrTypes().size());
    for (const auto& hdr : info.hdrCapabilities.getSupportedHdrTypes()) {
        hdrCapabilities.supportedHdrTypes.push_back(static_cast<int32_t>(hdr));
    }
    hdrCapabilities.maxLuminance = info.hdrCapabilities.getDesiredMaxLuminance();
    hdrCapabilities.maxAverageLuminance = info.hdrCapabilities.getDesiredMaxAverageLuminance();
    hdrCapabilities.minLuminance = info.hdrCapabilities.getDesiredMinLuminance();

    outInfo->autoLowLatencyModeSupported = info.autoLowLatencyModeSupported;
    outInfo->gameContentTypeSupported = info.gameContentTypeSupported;
    outInfo->preferredBootDisplayMode = info.preferredBootDisplayMode;
}

binder::Status SurfaceComposerAIDL::getDynamicDisplayInfoFromToken(
        const sp<IBinder>& display, gui::DynamicDisplayInfo* outInfo) {
    ui::DynamicDisplayInfo info;
    status_t status = mFlinger->getDynamicDisplayInfoFromToken(display, &info);
    if (status == NO_ERROR) {
        getDynamicDisplayInfoInternal(info, outInfo);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDynamicDisplayInfoFromId(int64_t displayId,
                                                                gui::DynamicDisplayInfo* outInfo) {
    ui::DynamicDisplayInfo info;
    status_t status = mFlinger->getDynamicDisplayInfoFromId(displayId, &info);
    if (status == NO_ERROR) {
        getDynamicDisplayInfoInternal(info, outInfo);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayNativePrimaries(const sp<IBinder>& display,
                                                              gui::DisplayPrimaries* outPrimaries) {
    ui::DisplayPrimaries primaries;
    status_t status = mFlinger->getDisplayNativePrimaries(display, primaries);
    if (status == NO_ERROR) {
        outPrimaries->red.X = primaries.red.X;
        outPrimaries->red.Y = primaries.red.Y;
        outPrimaries->red.Z = primaries.red.Z;

        outPrimaries->green.X = primaries.green.X;
        outPrimaries->green.Y = primaries.green.Y;
        outPrimaries->green.Z = primaries.green.Z;

        outPrimaries->blue.X = primaries.blue.X;
        outPrimaries->blue.Y = primaries.blue.Y;
        outPrimaries->blue.Z = primaries.blue.Z;

        outPrimaries->white.X = primaries.white.X;
        outPrimaries->white.Y = primaries.white.Y;
        outPrimaries->white.Z = primaries.white.Z;
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setActiveColorMode(const sp<IBinder>& display, int colorMode) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->setActiveColorMode(display, static_cast<ui::ColorMode>(colorMode));
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setBootDisplayMode(const sp<IBinder>& display,
                                                       int displayModeId) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->setBootDisplayMode(display, DisplayModeId{displayModeId});
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::clearBootDisplayMode(const sp<IBinder>& display) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->clearBootDisplayMode(display);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getOverlaySupport(gui::OverlayProperties* outProperties) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->getOverlaySupport(outProperties);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getBootDisplayModeSupport(bool* outMode) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->getBootDisplayModeSupport(outMode);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getHdrConversionCapabilities(
        std::vector<gui::HdrConversionCapability>* hdrConversionCapabilities) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->getHdrConversionCapabilities(hdrConversionCapabilities);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setHdrConversionStrategy(
        const gui::HdrConversionStrategy& hdrConversionStrategy,
        int32_t* outPreferredHdrOutputType) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->setHdrConversionStrategy(hdrConversionStrategy,
                                                    outPreferredHdrOutputType);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getHdrOutputConversionSupport(bool* outMode) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->getHdrOutputConversionSupport(outMode);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setAutoLowLatencyMode(const sp<IBinder>& display, bool on) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }
    mFlinger->setAutoLowLatencyMode(display, on);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::setGameContentType(const sp<IBinder>& display, bool on) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }
    mFlinger->setGameContentType(display, on);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::captureDisplay(
        const DisplayCaptureArgs& args, const sp<IScreenCaptureListener>& captureListener) {
    status_t status = mFlinger->captureDisplay(args, captureListener);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::captureDisplayById(
        int64_t displayId, const sp<IScreenCaptureListener>& captureListener) {
    status_t status;
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();
    if (uid == AID_ROOT || uid == AID_GRAPHICS || uid == AID_SYSTEM || uid == AID_SHELL) {
        std::optional<DisplayId> id = DisplayId::fromValue(static_cast<uint64_t>(displayId));
        status = mFlinger->captureDisplay(*id, captureListener);
    } else {
        status = PERMISSION_DENIED;
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::captureLayers(
        const LayerCaptureArgs& args, const sp<IScreenCaptureListener>& captureListener) {
    status_t status = mFlinger->captureLayers(args, captureListener);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::overrideHdrTypes(const sp<IBinder>& display,
                                                     const std::vector<int32_t>& hdrTypes) {
    // overrideHdrTypes is used by CTS tests, which acquire the necessary
    // permission dynamically. Don't use the permission cache for this check.
    status_t status = checkAccessPermission(false);
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }

    std::vector<ui::Hdr> hdrTypesVector;
    for (int32_t i : hdrTypes) {
        hdrTypesVector.push_back(static_cast<ui::Hdr>(i));
    }
    status = mFlinger->overrideHdrTypes(display, hdrTypesVector);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::onPullAtom(int32_t atomId, gui::PullAtomData* outPullData) {
    status_t status;
    const int uid = IPCThreadState::self()->getCallingUid();
    if (uid != AID_SYSTEM) {
        status = PERMISSION_DENIED;
    } else {
        status = mFlinger->onPullAtom(atomId, &outPullData->data, &outPullData->success);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getLayerDebugInfo(std::vector<gui::LayerDebugInfo>* outLayers) {
    if (!outLayers) {
        return binderStatusFromStatusT(UNEXPECTED_NULL);
    }

    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if ((uid != AID_SHELL) && !PermissionCache::checkPermission(sDump, pid, uid)) {
        ALOGE("Layer debug info permission denied for pid=%d, uid=%d", pid, uid);
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    status_t status = mFlinger->getLayerDebugInfo(outLayers);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getColorManagement(bool* outGetColorManagement) {
    status_t status = mFlinger->getColorManagement(outGetColorManagement);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getCompositionPreference(gui::CompositionPreference* outPref) {
    ui::Dataspace dataspace;
    ui::PixelFormat pixelFormat;
    ui::Dataspace wideColorGamutDataspace;
    ui::PixelFormat wideColorGamutPixelFormat;
    status_t status =
            mFlinger->getCompositionPreference(&dataspace, &pixelFormat, &wideColorGamutDataspace,
                                               &wideColorGamutPixelFormat);
    if (status == NO_ERROR) {
        outPref->defaultDataspace = static_cast<int32_t>(dataspace);
        outPref->defaultPixelFormat = static_cast<int32_t>(pixelFormat);
        outPref->wideColorGamutDataspace = static_cast<int32_t>(wideColorGamutDataspace);
        outPref->wideColorGamutPixelFormat = static_cast<int32_t>(wideColorGamutPixelFormat);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayedContentSamplingAttributes(
        const sp<IBinder>& display, gui::ContentSamplingAttributes* outAttrs) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }

    ui::PixelFormat format;
    ui::Dataspace dataspace;
    uint8_t componentMask;
    status = mFlinger->getDisplayedContentSamplingAttributes(display, &format, &dataspace,
                                                             &componentMask);
    if (status == NO_ERROR) {
        outAttrs->format = static_cast<int32_t>(format);
        outAttrs->dataspace = static_cast<int32_t>(dataspace);
        outAttrs->componentMask = static_cast<int8_t>(componentMask);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setDisplayContentSamplingEnabled(const sp<IBinder>& display,
                                                                     bool enable,
                                                                     int8_t componentMask,
                                                                     int64_t maxFrames) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->setDisplayContentSamplingEnabled(display, enable,
                                                            static_cast<uint8_t>(componentMask),
                                                            static_cast<uint64_t>(maxFrames));
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayedContentSample(const sp<IBinder>& display,
                                                              int64_t maxFrames, int64_t timestamp,
                                                              gui::DisplayedFrameStats* outStats) {
    if (!outStats) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }

    DisplayedFrameStats stats;
    status = mFlinger->getDisplayedContentSample(display, static_cast<uint64_t>(maxFrames),
                                                 static_cast<uint64_t>(timestamp), &stats);
    if (status == NO_ERROR) {
        // convert from ui::DisplayedFrameStats to gui::DisplayedFrameStats
        outStats->numFrames = static_cast<int64_t>(stats.numFrames);
        outStats->component_0_sample.reserve(stats.component_0_sample.size());
        for (const auto& s : stats.component_0_sample) {
            outStats->component_0_sample.push_back(static_cast<int64_t>(s));
        }
        outStats->component_1_sample.reserve(stats.component_1_sample.size());
        for (const auto& s : stats.component_1_sample) {
            outStats->component_1_sample.push_back(static_cast<int64_t>(s));
        }
        outStats->component_2_sample.reserve(stats.component_2_sample.size());
        for (const auto& s : stats.component_2_sample) {
            outStats->component_2_sample.push_back(static_cast<int64_t>(s));
        }
        outStats->component_3_sample.reserve(stats.component_3_sample.size());
        for (const auto& s : stats.component_3_sample) {
            outStats->component_3_sample.push_back(static_cast<int64_t>(s));
        }
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getProtectedContentSupport(bool* outSupported) {
    status_t status = mFlinger->getProtectedContentSupport(outSupported);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::isWideColorDisplay(const sp<IBinder>& token,
                                                       bool* outIsWideColorDisplay) {
    status_t status = mFlinger->isWideColorDisplay(token, outIsWideColorDisplay);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::addRegionSamplingListener(
        const gui::ARect& samplingArea, const sp<IBinder>& stopLayerHandle,
        const sp<gui::IRegionSamplingListener>& listener) {
    status_t status = checkReadFrameBufferPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }
    android::Rect rect;
    rect.left = samplingArea.left;
    rect.top = samplingArea.top;
    rect.right = samplingArea.right;
    rect.bottom = samplingArea.bottom;
    status = mFlinger->addRegionSamplingListener(rect, stopLayerHandle, listener);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::removeRegionSamplingListener(
        const sp<gui::IRegionSamplingListener>& listener) {
    status_t status = checkReadFrameBufferPermission();
    if (status == OK) {
        status = mFlinger->removeRegionSamplingListener(listener);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::addFpsListener(int32_t taskId,
                                                   const sp<gui::IFpsListener>& listener) {
    status_t status = checkReadFrameBufferPermission();
    if (status == OK) {
        status = mFlinger->addFpsListener(taskId, listener);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::removeFpsListener(const sp<gui::IFpsListener>& listener) {
    status_t status = checkReadFrameBufferPermission();
    if (status == OK) {
        status = mFlinger->removeFpsListener(listener);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::addTunnelModeEnabledListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->addTunnelModeEnabledListener(listener);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::removeTunnelModeEnabledListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->removeTunnelModeEnabledListener(listener);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                                               const gui::DisplayModeSpecs& specs) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->setDesiredDisplayModeSpecs(displayToken, specs);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                                               gui::DisplayModeSpecs* outSpecs) {
    if (!outSpecs) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }

    status = mFlinger->getDesiredDisplayModeSpecs(displayToken, outSpecs);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayBrightnessSupport(const sp<IBinder>& displayToken,
                                                                bool* outSupport) {
    status_t status = mFlinger->getDisplayBrightnessSupport(displayToken, outSupport);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setDisplayBrightness(const sp<IBinder>& displayToken,
                                                         const gui::DisplayBrightness& brightness) {
    status_t status = checkControlDisplayBrightnessPermission();
    if (status == OK) {
        status = mFlinger->setDisplayBrightness(displayToken, brightness);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::addHdrLayerInfoListener(
        const sp<IBinder>& displayToken, const sp<gui::IHdrLayerInfoListener>& listener) {
    status_t status = checkControlDisplayBrightnessPermission();
    if (status == OK) {
        status = mFlinger->addHdrLayerInfoListener(displayToken, listener);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::removeHdrLayerInfoListener(
        const sp<IBinder>& displayToken, const sp<gui::IHdrLayerInfoListener>& listener) {
    status_t status = checkControlDisplayBrightnessPermission();
    if (status == OK) {
        status = mFlinger->removeHdrLayerInfoListener(displayToken, listener);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::notifyPowerBoost(int boostId) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        status = mFlinger->notifyPowerBoost(boostId);
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setGlobalShadowSettings(const gui::Color& ambientColor,
                                                            const gui::Color& spotColor,
                                                            float lightPosY, float lightPosZ,
                                                            float lightRadius) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binderStatusFromStatusT(status);
    }

    half4 ambientColorHalf = {ambientColor.r, ambientColor.g, ambientColor.b, ambientColor.a};
    half4 spotColorHalf = {spotColor.r, spotColor.g, spotColor.b, spotColor.a};
    status = mFlinger->setGlobalShadowSettings(ambientColorHalf, spotColorHalf, lightPosY,
                                               lightPosZ, lightRadius);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayDecorationSupport(
        const sp<IBinder>& displayToken, std::optional<gui::DisplayDecorationSupport>* outSupport) {
    std::optional<aidl::android::hardware::graphics::common::DisplayDecorationSupport> support;
    status_t status = mFlinger->getDisplayDecorationSupport(displayToken, &support);
    if (status != NO_ERROR) {
        ALOGE("getDisplayDecorationSupport failed with error %d", status);
        return binderStatusFromStatusT(status);
    }

    if (!support || !support.has_value()) {
        outSupport->reset();
    } else {
        outSupport->emplace();
        outSupport->value().format = static_cast<int32_t>(support->format);
        outSupport->value().alphaInterpretation =
                static_cast<int32_t>(support->alphaInterpretation);
    }

    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::setOverrideFrameRate(int32_t uid, float frameRate) {
    status_t status;
    const int c_uid = IPCThreadState::self()->getCallingUid();
    if (c_uid == AID_ROOT || c_uid == AID_SYSTEM) {
        status = mFlinger->setOverrideFrameRate(uid, frameRate);
    } else {
        ALOGE("setOverrideFrameRate() permission denied for uid: %d", c_uid);
        status = PERMISSION_DENIED;
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::updateSmallAreaDetection(const std::vector<int32_t>& uids,
                                                             const std::vector<float>& thresholds) {
    status_t status;
    const int c_uid = IPCThreadState::self()->getCallingUid();
    if (c_uid == AID_ROOT || c_uid == AID_SYSTEM) {
        if (uids.size() != thresholds.size()) return binderStatusFromStatusT(BAD_VALUE);

        std::vector<std::pair<uid_t, float>> mappings;
        const size_t size = uids.size();
        mappings.reserve(size);
        for (int i = 0; i < size; i++) {
            auto row = std::make_pair(static_cast<uid_t>(uids[i]), thresholds[i]);
            mappings.push_back(row);
        }
        status = mFlinger->updateSmallAreaDetection(mappings);
    } else {
        ALOGE("updateSmallAreaDetection() permission denied for uid: %d", c_uid);
        status = PERMISSION_DENIED;
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setSmallAreaDetectionThreshold(int32_t uid, float threshold) {
    status_t status;
    const int c_uid = IPCThreadState::self()->getCallingUid();
    if (c_uid == AID_ROOT || c_uid == AID_SYSTEM) {
        status = mFlinger->setSmallAreaDetectionThreshold(uid, threshold);
    } else {
        ALOGE("setSmallAreaDetectionThreshold() permission denied for uid: %d", c_uid);
        status = PERMISSION_DENIED;
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getGpuContextPriority(int32_t* outPriority) {
    *outPriority = mFlinger->getGpuContextPriority();
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::getMaxAcquiredBufferCount(int32_t* buffers) {
    status_t status = mFlinger->getMaxAcquiredBufferCount(buffers);
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::addWindowInfosListener(
        const sp<gui::IWindowInfosListener>& windowInfosListener,
        gui::WindowInfosListenerInfo* outInfo) {
    status_t status;
    const int pid = IPCThreadState::self()->getCallingPid();
    const int uid = IPCThreadState::self()->getCallingUid();
    // TODO(b/270566761) update permissions check so that only system_server and shell can add
    // WindowInfosListeners
    if (uid == AID_SYSTEM || uid == AID_GRAPHICS ||
        checkPermission(sAccessSurfaceFlinger, pid, uid)) {
        status = mFlinger->addWindowInfosListener(windowInfosListener, outInfo);
    } else {
        status = PERMISSION_DENIED;
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::removeWindowInfosListener(
        const sp<gui::IWindowInfosListener>& windowInfosListener) {
    status_t status;
    const int pid = IPCThreadState::self()->getCallingPid();
    const int uid = IPCThreadState::self()->getCallingUid();
    if (uid == AID_SYSTEM || uid == AID_GRAPHICS ||
        checkPermission(sAccessSurfaceFlinger, pid, uid)) {
        status = mFlinger->removeWindowInfosListener(windowInfosListener);
    } else {
        status = PERMISSION_DENIED;
    }
    return binderStatusFromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getStalledTransactionInfo(
        int pid, std::optional<gui::StalledTransactionInfo>* outInfo) {
    const int callingPid = IPCThreadState::self()->getCallingPid();
    const int callingUid = IPCThreadState::self()->getCallingUid();
    if (!checkPermission(sAccessSurfaceFlinger, callingPid, callingUid)) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    std::optional<TransactionHandler::StalledTransactionInfo> stalledTransactionInfo;
    status_t status = mFlinger->getStalledTransactionInfo(pid, stalledTransactionInfo);
    if (stalledTransactionInfo) {
        gui::StalledTransactionInfo result;
        result.layerName = String16{stalledTransactionInfo->layerName.c_str()},
        result.bufferId = stalledTransactionInfo->bufferId,
        result.frameNumber = stalledTransactionInfo->frameNumber,
        outInfo->emplace(std::move(result));
    } else {
        outInfo->reset();
    }
    return binderStatusFromStatusT(status);
}

status_t SurfaceComposerAIDL::checkAccessPermission(bool usePermissionCache) {
    if (!mFlinger->callingThreadHasUnscopedSurfaceFlingerAccess(usePermissionCache)) {
        IPCThreadState* ipc = IPCThreadState::self();
        ALOGE("Permission Denial: can't access SurfaceFlinger pid=%d, uid=%d", ipc->getCallingPid(),
              ipc->getCallingUid());
        return PERMISSION_DENIED;
    }
    return OK;
}

status_t SurfaceComposerAIDL::checkControlDisplayBrightnessPermission() {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if ((uid != AID_GRAPHICS) && (uid != AID_SYSTEM) &&
        !PermissionCache::checkPermission(sControlDisplayBrightness, pid, uid)) {
        ALOGE("Permission Denial: can't control brightness pid=%d, uid=%d", pid, uid);
        return PERMISSION_DENIED;
    }
    return OK;
}

status_t SurfaceComposerAIDL::checkReadFrameBufferPermission() {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if ((uid != AID_GRAPHICS) && !PermissionCache::checkPermission(sReadFramebuffer, pid, uid)) {
        ALOGE("Permission Denial: can't read framebuffer pid=%d, uid=%d", pid, uid);
        return PERMISSION_DENIED;
    }
    return OK;
}

void SurfaceFlinger::forceFutureUpdate(int delayInMs) {
    static_cast<void>(mScheduler->scheduleDelayed([&]() { scheduleRepaint(); }, ms2ns(delayInMs)));
}

const DisplayDevice* SurfaceFlinger::getDisplayFromLayerStack(ui::LayerStack layerStack) {
    for (const auto& [_, display] : mDisplays) {
        if (display->getLayerStack() == layerStack) {
            return display.get();
        }
    }
    return nullptr;
}

} // namespace android

#if defined(__gl_h_)
#error "don't include gl/gl.h in this file"
#endif

#if defined(__gl2_h_)
#error "don't include gl2/gl2.h in this file"
#endif

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
