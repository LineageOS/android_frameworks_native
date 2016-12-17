/*
 * Copyright 2015 The Android Open Source Project
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

// #define LOG_NDEBUG 0

#undef LOG_TAG
#define LOG_TAG "HWC2"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "HWC2.h"
#include "ComposerHal.h"

#include "FloatRect.h"

#include <ui/Fence.h>
#include <ui/GraphicBuffer.h>
#include <ui/Region.h>

#include <android/configuration.h>

#include <algorithm>
#include <inttypes.h>

extern "C" {
    static void hotplug_hook(hwc2_callback_data_t callbackData,
            hwc2_display_t displayId, int32_t intConnected) {
        auto device = static_cast<HWC2::Device*>(callbackData);
        auto display = device->getDisplayById(displayId);
        if (display) {
            auto connected = static_cast<HWC2::Connection>(intConnected);
            device->callHotplug(std::move(display), connected);
        } else {
            ALOGE("Hotplug callback called with unknown display %" PRIu64,
                    displayId);
        }
    }

    static void refresh_hook(hwc2_callback_data_t callbackData,
            hwc2_display_t displayId) {
        auto device = static_cast<HWC2::Device*>(callbackData);
        auto display = device->getDisplayById(displayId);
        if (display) {
            device->callRefresh(std::move(display));
        } else {
            ALOGE("Refresh callback called with unknown display %" PRIu64,
                    displayId);
        }
    }

    static void vsync_hook(hwc2_callback_data_t callbackData,
            hwc2_display_t displayId, int64_t timestamp) {
        auto device = static_cast<HWC2::Device*>(callbackData);
        auto display = device->getDisplayById(displayId);
        if (display) {
            device->callVsync(std::move(display), timestamp);
        } else {
            ALOGE("Vsync callback called with unknown display %" PRIu64,
                    displayId);
        }
    }
}

using android::Fence;
using android::FloatRect;
using android::GraphicBuffer;
using android::HdrCapabilities;
using android::Rect;
using android::Region;
using android::sp;
using android::hardware::Return;
using android::hardware::Void;

namespace HWC2 {

namespace Hwc2 = android::Hwc2;

// Device methods

#ifdef BYPASS_IHWC
Device::Device(hwc2_device_t* device)
  : mHwcDevice(device),
    mCreateVirtualDisplay(nullptr),
    mDestroyVirtualDisplay(nullptr),
    mDump(nullptr),
    mGetMaxVirtualDisplayCount(nullptr),
    mRegisterCallback(nullptr),
    mAcceptDisplayChanges(nullptr),
    mCreateLayer(nullptr),
    mDestroyLayer(nullptr),
    mGetActiveConfig(nullptr),
    mGetChangedCompositionTypes(nullptr),
    mGetColorModes(nullptr),
    mGetDisplayAttribute(nullptr),
    mGetDisplayConfigs(nullptr),
    mGetDisplayName(nullptr),
    mGetDisplayRequests(nullptr),
    mGetDisplayType(nullptr),
    mGetDozeSupport(nullptr),
    mGetHdrCapabilities(nullptr),
    mGetReleaseFences(nullptr),
    mPresentDisplay(nullptr),
    mSetActiveConfig(nullptr),
    mSetClientTarget(nullptr),
    mSetColorMode(nullptr),
    mSetColorTransform(nullptr),
    mSetOutputBuffer(nullptr),
    mSetPowerMode(nullptr),
    mSetVsyncEnabled(nullptr),
    mValidateDisplay(nullptr),
    mSetCursorPosition(nullptr),
    mSetLayerBuffer(nullptr),
    mSetLayerSurfaceDamage(nullptr),
    mSetLayerBlendMode(nullptr),
    mSetLayerColor(nullptr),
    mSetLayerCompositionType(nullptr),
    mSetLayerDataspace(nullptr),
    mSetLayerDisplayFrame(nullptr),
    mSetLayerPlaneAlpha(nullptr),
    mSetLayerSidebandStream(nullptr),
    mSetLayerSourceCrop(nullptr),
    mSetLayerTransform(nullptr),
    mSetLayerVisibleRegion(nullptr),
    mSetLayerZOrder(nullptr),
#else
Device::Device()
  : mComposer(std::make_unique<Hwc2::Composer>()),
#endif // BYPASS_IHWC
    mCapabilities(),
    mDisplays(),
    mHotplug(),
    mPendingHotplugs(),
    mRefresh(),
    mPendingRefreshes(),
    mVsync(),
    mPendingVsyncs()
{
    loadCapabilities();
    loadFunctionPointers();
    registerCallbacks();
}

Device::~Device()
{
#ifdef BYPASS_IHWC
    if (mHwcDevice == nullptr) {
        return;
    }
#endif

    for (auto element : mDisplays) {
        auto display = element.second.lock();
        if (!display) {
            ALOGE("~Device: Found a display (%" PRId64 " that has already been"
                    " destroyed", element.first);
            continue;
        }

        DisplayType displayType = HWC2::DisplayType::Invalid;
        auto error = display->getType(&displayType);
        if (error != Error::None) {
            ALOGE("~Device: Failed to determine type of display %" PRIu64
                    ": %s (%d)", display->getId(), to_string(error).c_str(),
                    static_cast<int32_t>(error));
            continue;
        }

        if (displayType == HWC2::DisplayType::Physical) {
            error = display->setVsyncEnabled(HWC2::Vsync::Disable);
            if (error != Error::None) {
                ALOGE("~Device: Failed to disable vsync for display %" PRIu64
                        ": %s (%d)", display->getId(), to_string(error).c_str(),
                        static_cast<int32_t>(error));
            }
        }
    }

#ifdef BYPASS_IHWC
    hwc2_close(mHwcDevice);
#endif
}

// Required by HWC2 device

std::string Device::dump() const
{
#ifdef BYPASS_IHWC
    uint32_t numBytes = 0;
    mDump(mHwcDevice, &numBytes, nullptr);

    std::vector<char> buffer(numBytes);
    mDump(mHwcDevice, &numBytes, buffer.data());

    return std::string(buffer.data(), buffer.size());
#else
    return mComposer->dumpDebugInfo();
#endif
}

uint32_t Device::getMaxVirtualDisplayCount() const
{
#ifdef BYPASS_IHWC
    return mGetMaxVirtualDisplayCount(mHwcDevice);
#else
    return mComposer->getMaxVirtualDisplayCount();
#endif
}

Error Device::createVirtualDisplay(uint32_t width, uint32_t height,
        android_pixel_format_t* format, std::shared_ptr<Display>* outDisplay)
{
    ALOGI("Creating virtual display");

    hwc2_display_t displayId = 0;
#ifdef BYPASS_IHWC
    int32_t intFormat = static_cast<int32_t>(*format);
    int32_t intError = mCreateVirtualDisplay(mHwcDevice, width, height,
            &intFormat, &displayId);
#else
    auto intFormat = static_cast<Hwc2::PixelFormat>(*format);
    auto intError = mComposer->createVirtualDisplay(width, height,
            intFormat, displayId);
#endif
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    ALOGI("Created virtual display");
    *format = static_cast<android_pixel_format_t>(intFormat);
    *outDisplay = getDisplayById(displayId);
    if (!*outDisplay) {
        ALOGE("Failed to get display by id");
        return Error::BadDisplay;
    }
    (*outDisplay)->setVirtual();
    return Error::None;
}

void Device::registerHotplugCallback(HotplugCallback hotplug)
{
    ALOGV("registerHotplugCallback");
    mHotplug = hotplug;
    for (auto& pending : mPendingHotplugs) {
        auto& display = pending.first;
        auto connected = pending.second;
        ALOGV("Sending pending hotplug(%" PRIu64 ", %s)", display->getId(),
                to_string(connected).c_str());
        mHotplug(std::move(display), connected);
    }
}

void Device::registerRefreshCallback(RefreshCallback refresh)
{
    mRefresh = refresh;
    for (auto& pending : mPendingRefreshes) {
        mRefresh(std::move(pending));
    }
}

void Device::registerVsyncCallback(VsyncCallback vsync)
{
    mVsync = vsync;
    for (auto& pending : mPendingVsyncs) {
        auto& display = pending.first;
        auto timestamp = pending.second;
        mVsync(std::move(display), timestamp);
    }
}

// For use by Device callbacks

void Device::callHotplug(std::shared_ptr<Display> display, Connection connected)
{
    if (connected == Connection::Connected) {
        if (!display->isConnected()) {
#ifndef BYPASS_IHWC
            mComposer->setClientTargetSlotCount(display->getId());
#endif
            display->loadConfigs();
            display->setConnected(true);
        }
    } else {
        display->setConnected(false);
        mDisplays.erase(display->getId());
    }

    if (mHotplug) {
        mHotplug(std::move(display), connected);
    } else {
        ALOGV("callHotplug called, but no valid callback registered, storing");
        mPendingHotplugs.emplace_back(std::move(display), connected);
    }
}

void Device::callRefresh(std::shared_ptr<Display> display)
{
    if (mRefresh) {
        mRefresh(std::move(display));
    } else {
        ALOGV("callRefresh called, but no valid callback registered, storing");
        mPendingRefreshes.emplace_back(std::move(display));
    }
}

void Device::callVsync(std::shared_ptr<Display> display, nsecs_t timestamp)
{
    if (mVsync) {
        mVsync(std::move(display), timestamp);
    } else {
        ALOGV("callVsync called, but no valid callback registered, storing");
        mPendingVsyncs.emplace_back(std::move(display), timestamp);
    }
}

// Other Device methods

std::shared_ptr<Display> Device::getDisplayById(hwc2_display_t id) {
    if (mDisplays.count(id) != 0) {
        auto strongDisplay = mDisplays[id].lock();
        ALOGE_IF(!strongDisplay, "Display %" PRId64 " is in mDisplays but is no"
                " longer alive", id);
        return strongDisplay;
    }

    auto display = std::make_shared<Display>(*this, id);
    mDisplays.emplace(id, display);
    return display;
}

// Device initialization methods

void Device::loadCapabilities()
{
    static_assert(sizeof(Capability) == sizeof(int32_t),
            "Capability size has changed");
#ifdef BYPASS_IHWC
    uint32_t numCapabilities = 0;
    mHwcDevice->getCapabilities(mHwcDevice, &numCapabilities, nullptr);
    std::vector<Capability> capabilities(numCapabilities);
    auto asInt = reinterpret_cast<int32_t*>(capabilities.data());
    mHwcDevice->getCapabilities(mHwcDevice, &numCapabilities, asInt);
    for (auto capability : capabilities) {
        mCapabilities.emplace(capability);
    }
#else
    auto capabilities = mComposer->getCapabilities();
    for (auto capability : capabilities) {
        mCapabilities.emplace(static_cast<Capability>(capability));
    }
#endif
}

bool Device::hasCapability(HWC2::Capability capability) const
{
    return std::find(mCapabilities.cbegin(), mCapabilities.cend(),
            capability) != mCapabilities.cend();
}

void Device::loadFunctionPointers()
{
#ifdef BYPASS_IHWC
    // For all of these early returns, we log an error message inside
    // loadFunctionPointer specifying which function failed to load

    // Display function pointers
    if (!loadFunctionPointer(FunctionDescriptor::CreateVirtualDisplay,
            mCreateVirtualDisplay)) return;
    if (!loadFunctionPointer(FunctionDescriptor::DestroyVirtualDisplay,
            mDestroyVirtualDisplay)) return;
    if (!loadFunctionPointer(FunctionDescriptor::Dump, mDump)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetMaxVirtualDisplayCount,
            mGetMaxVirtualDisplayCount)) return;
    if (!loadFunctionPointer(FunctionDescriptor::RegisterCallback,
            mRegisterCallback)) return;

    // Device function pointers
    if (!loadFunctionPointer(FunctionDescriptor::AcceptDisplayChanges,
            mAcceptDisplayChanges)) return;
    if (!loadFunctionPointer(FunctionDescriptor::CreateLayer,
            mCreateLayer)) return;
    if (!loadFunctionPointer(FunctionDescriptor::DestroyLayer,
            mDestroyLayer)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetActiveConfig,
            mGetActiveConfig)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetChangedCompositionTypes,
            mGetChangedCompositionTypes)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetColorModes,
            mGetColorModes)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetDisplayAttribute,
            mGetDisplayAttribute)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetDisplayConfigs,
            mGetDisplayConfigs)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetDisplayName,
            mGetDisplayName)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetDisplayRequests,
            mGetDisplayRequests)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetDisplayType,
            mGetDisplayType)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetDozeSupport,
            mGetDozeSupport)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetHdrCapabilities,
            mGetHdrCapabilities)) return;
    if (!loadFunctionPointer(FunctionDescriptor::GetReleaseFences,
            mGetReleaseFences)) return;
    if (!loadFunctionPointer(FunctionDescriptor::PresentDisplay,
            mPresentDisplay)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetActiveConfig,
            mSetActiveConfig)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetClientTarget,
            mSetClientTarget)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetColorMode,
            mSetColorMode)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetColorTransform,
            mSetColorTransform)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetOutputBuffer,
            mSetOutputBuffer)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetPowerMode,
            mSetPowerMode)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetVsyncEnabled,
            mSetVsyncEnabled)) return;
    if (!loadFunctionPointer(FunctionDescriptor::ValidateDisplay,
            mValidateDisplay)) return;

    // Layer function pointers
    if (!loadFunctionPointer(FunctionDescriptor::SetCursorPosition,
            mSetCursorPosition)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerBuffer,
            mSetLayerBuffer)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerSurfaceDamage,
            mSetLayerSurfaceDamage)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerBlendMode,
            mSetLayerBlendMode)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerColor,
            mSetLayerColor)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerCompositionType,
            mSetLayerCompositionType)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerDataspace,
            mSetLayerDataspace)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerDisplayFrame,
            mSetLayerDisplayFrame)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerPlaneAlpha,
            mSetLayerPlaneAlpha)) return;
    if (hasCapability(Capability::SidebandStream)) {
        if (!loadFunctionPointer(FunctionDescriptor::SetLayerSidebandStream,
                mSetLayerSidebandStream)) return;
    }
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerSourceCrop,
            mSetLayerSourceCrop)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerTransform,
            mSetLayerTransform)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerVisibleRegion,
            mSetLayerVisibleRegion)) return;
    if (!loadFunctionPointer(FunctionDescriptor::SetLayerZOrder,
            mSetLayerZOrder)) return;
#endif // BYPASS_IHWC
}

namespace {
class ComposerCallback : public Hwc2::IComposerCallback {
public:
    ComposerCallback(Device* device) : mDevice(device) {}

    Return<void> onHotplug(Hwc2::Display display,
            Connection connected) override
    {
        hotplug_hook(mDevice, display, static_cast<int32_t>(connected));
        return Void();
    }

    Return<void> onRefresh(Hwc2::Display display) override
    {
        refresh_hook(mDevice, display);
        return Void();
    }

    Return<void> onVsync(Hwc2::Display display, int64_t timestamp) override
    {
        vsync_hook(mDevice, display, timestamp);
        return Void();
    }

private:
    Device* mDevice;
};
} // namespace anonymous

void Device::registerCallbacks()
{
#ifdef BYPASS_IHWC
    registerCallback<HWC2_PFN_HOTPLUG>(Callback::Hotplug, hotplug_hook);
    registerCallback<HWC2_PFN_REFRESH>(Callback::Refresh, refresh_hook);
    registerCallback<HWC2_PFN_VSYNC>(Callback::Vsync, vsync_hook);
#else
    sp<ComposerCallback> callback = new ComposerCallback(this);
    mComposer->registerCallback(callback);
#endif
}


// For use by Display

void Device::destroyVirtualDisplay(hwc2_display_t display)
{
    ALOGI("Destroying virtual display");
#ifdef BYPASS_IHWC
    int32_t intError = mDestroyVirtualDisplay(mHwcDevice, display);
#else
    auto intError = mComposer->destroyVirtualDisplay(display);
#endif
    auto error = static_cast<Error>(intError);
    ALOGE_IF(error != Error::None, "destroyVirtualDisplay(%" PRIu64 ") failed:"
            " %s (%d)", display, to_string(error).c_str(), intError);
    mDisplays.erase(display);
}

// Display methods

Display::Display(Device& device, hwc2_display_t id)
  : mDevice(device),
    mId(id),
    mIsConnected(false),
    mIsVirtual(false)
{
    ALOGV("Created display %" PRIu64, id);
}

Display::~Display()
{
    ALOGV("Destroyed display %" PRIu64, mId);
    if (mIsVirtual) {
        mDevice.destroyVirtualDisplay(mId);
    }
}

Display::Config::Config(Display& display, hwc2_config_t id)
  : mDisplay(display),
    mId(id),
    mWidth(-1),
    mHeight(-1),
    mVsyncPeriod(-1),
    mDpiX(-1),
    mDpiY(-1) {}

Display::Config::Builder::Builder(Display& display, hwc2_config_t id)
  : mConfig(new Config(display, id)) {}

float Display::Config::Builder::getDefaultDensity() {
    // Default density is based on TVs: 1080p displays get XHIGH density, lower-
    // resolution displays get TV density. Maybe eventually we'll need to update
    // it for 4k displays, though hopefully those will just report accurate DPI
    // information to begin with. This is also used for virtual displays and
    // older HWC implementations, so be careful about orientation.

    auto longDimension = std::max(mConfig->mWidth, mConfig->mHeight);
    if (longDimension >= 1080) {
        return ACONFIGURATION_DENSITY_XHIGH;
    } else {
        return ACONFIGURATION_DENSITY_TV;
    }
}

// Required by HWC2 display

Error Display::acceptChanges()
{
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mAcceptDisplayChanges(mDevice.mHwcDevice, mId);
#else
    auto intError = mDevice.mComposer->acceptDisplayChanges(mId);
#endif
    return static_cast<Error>(intError);
}

Error Display::createLayer(std::shared_ptr<Layer>* outLayer)
{
    hwc2_layer_t layerId = 0;
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mCreateLayer(mDevice.mHwcDevice, mId, &layerId);
#else
    auto intError = mDevice.mComposer->createLayer(mId, layerId);
#endif
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    auto layer = std::make_shared<Layer>(shared_from_this(), layerId);
    mLayers.emplace(layerId, layer);
    *outLayer = std::move(layer);
    return Error::None;
}

Error Display::getActiveConfig(
        std::shared_ptr<const Display::Config>* outConfig) const
{
    ALOGV("[%" PRIu64 "] getActiveConfig", mId);
    hwc2_config_t configId = 0;
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mGetActiveConfig(mDevice.mHwcDevice, mId,
            &configId);
#else
    auto intError = mDevice.mComposer->getActiveConfig(mId, configId);
#endif
    auto error = static_cast<Error>(intError);

    if (error != Error::None) {
        ALOGE("Unable to get active config for mId:[%" PRIu64 "]", mId);
        *outConfig = nullptr;
        return error;
    }

    if (mConfigs.count(configId) != 0) {
        *outConfig = mConfigs.at(configId);
    } else {
        ALOGE("[%" PRIu64 "] getActiveConfig returned unknown config %u", mId,
                configId);
        // Return no error, but the caller needs to check for a null pointer to
        // detect this case
        *outConfig = nullptr;
    }

    return Error::None;
}

Error Display::getChangedCompositionTypes(
        std::unordered_map<std::shared_ptr<Layer>, Composition>* outTypes)
{
#ifdef BYPASS_IHWC
    uint32_t numElements = 0;
    int32_t intError = mDevice.mGetChangedCompositionTypes(mDevice.mHwcDevice,
            mId, &numElements, nullptr, nullptr);
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    std::vector<hwc2_layer_t> layerIds(numElements);
    std::vector<int32_t> types(numElements);
    intError = mDevice.mGetChangedCompositionTypes(mDevice.mHwcDevice, mId,
            &numElements, layerIds.data(), types.data());
#else
    std::vector<Hwc2::Layer> layerIds;
    std::vector<Hwc2::IComposerClient::Composition> types;
    auto intError = mDevice.mComposer->getChangedCompositionTypes(mId,
            layerIds, types);
    uint32_t numElements = layerIds.size();
    auto error = static_cast<Error>(intError);
#endif
    error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    outTypes->clear();
    outTypes->reserve(numElements);
    for (uint32_t element = 0; element < numElements; ++element) {
        auto layer = getLayerById(layerIds[element]);
        if (layer) {
            auto type = static_cast<Composition>(types[element]);
            ALOGV("getChangedCompositionTypes: adding %" PRIu64 " %s",
                    layer->getId(), to_string(type).c_str());
            outTypes->emplace(layer, type);
        } else {
            ALOGE("getChangedCompositionTypes: invalid layer %" PRIu64 " found"
                    " on display %" PRIu64, layerIds[element], mId);
        }
    }

    return Error::None;
}

Error Display::getColorModes(std::vector<android_color_mode_t>* outModes) const
{
#ifdef BYPASS_IHWC
    uint32_t numModes = 0;
    int32_t intError = mDevice.mGetColorModes(mDevice.mHwcDevice, mId,
            &numModes, nullptr);
    auto error = static_cast<Error>(intError);
    if (error != Error::None)  {
        return error;
    }

    std::vector<int32_t> modes(numModes);
    intError = mDevice.mGetColorModes(mDevice.mHwcDevice, mId, &numModes,
            modes.data());
    error = static_cast<Error>(intError);
#else
    std::vector<Hwc2::ColorMode> modes;
    auto intError = mDevice.mComposer->getColorModes(mId, modes);
    uint32_t numModes = modes.size();
    auto error = static_cast<Error>(intError);
#endif
    if (error != Error::None) {
        return error;
    }

    outModes->resize(numModes);
    for (size_t i = 0; i < numModes; i++) {
        (*outModes)[i] = static_cast<android_color_mode_t>(modes[i]);
    }
    return Error::None;
}

std::vector<std::shared_ptr<const Display::Config>> Display::getConfigs() const
{
    std::vector<std::shared_ptr<const Config>> configs;
    for (const auto& element : mConfigs) {
        configs.emplace_back(element.second);
    }
    return configs;
}

Error Display::getName(std::string* outName) const
{
#ifdef BYPASS_IHWC
    uint32_t size;
    int32_t intError = mDevice.mGetDisplayName(mDevice.mHwcDevice, mId, &size,
            nullptr);
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    std::vector<char> rawName(size);
    intError = mDevice.mGetDisplayName(mDevice.mHwcDevice, mId, &size,
            rawName.data());
    error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    *outName = std::string(rawName.cbegin(), rawName.cend());
    return Error::None;
#else
    auto intError = mDevice.mComposer->getDisplayName(mId, *outName);
    return static_cast<Error>(intError);
#endif
}

Error Display::getRequests(HWC2::DisplayRequest* outDisplayRequests,
        std::unordered_map<std::shared_ptr<Layer>, LayerRequest>*
                outLayerRequests)
{
#ifdef BYPASS_IHWC
    int32_t intDisplayRequests = 0;
    uint32_t numElements = 0;
    int32_t intError = mDevice.mGetDisplayRequests(mDevice.mHwcDevice, mId,
            &intDisplayRequests, &numElements, nullptr, nullptr);
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    std::vector<hwc2_layer_t> layerIds(numElements);
    std::vector<int32_t> layerRequests(numElements);
    intError = mDevice.mGetDisplayRequests(mDevice.mHwcDevice, mId,
            &intDisplayRequests, &numElements, layerIds.data(),
            layerRequests.data());
    error = static_cast<Error>(intError);
#else
    uint32_t intDisplayRequests;
    std::vector<Hwc2::Layer> layerIds;
    std::vector<uint32_t> layerRequests;
    auto intError = mDevice.mComposer->getDisplayRequests(mId,
            intDisplayRequests, layerIds, layerRequests);
    uint32_t numElements = layerIds.size();
    auto error = static_cast<Error>(intError);
#endif
    if (error != Error::None) {
        return error;
    }

    *outDisplayRequests = static_cast<DisplayRequest>(intDisplayRequests);
    outLayerRequests->clear();
    outLayerRequests->reserve(numElements);
    for (uint32_t element = 0; element < numElements; ++element) {
        auto layer = getLayerById(layerIds[element]);
        if (layer) {
            auto layerRequest =
                    static_cast<LayerRequest>(layerRequests[element]);
            outLayerRequests->emplace(layer, layerRequest);
        } else {
            ALOGE("getRequests: invalid layer %" PRIu64 " found on display %"
                    PRIu64, layerIds[element], mId);
        }
    }

    return Error::None;
}

Error Display::getType(DisplayType* outType) const
{
#ifdef BYPASS_IHWC
    int32_t intType = 0;
    int32_t intError = mDevice.mGetDisplayType(mDevice.mHwcDevice, mId,
            &intType);
#else
    Hwc2::IComposerClient::DisplayType intType =
        Hwc2::IComposerClient::DisplayType::INVALID;
    auto intError = mDevice.mComposer->getDisplayType(mId, intType);
#endif
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    *outType = static_cast<DisplayType>(intType);
    return Error::None;
}

Error Display::supportsDoze(bool* outSupport) const
{
#ifdef BYPASS_IHWC
    int32_t intSupport = 0;
    int32_t intError = mDevice.mGetDozeSupport(mDevice.mHwcDevice, mId,
            &intSupport);
#else
    bool intSupport = false;
    auto intError = mDevice.mComposer->getDozeSupport(mId, intSupport);
#endif
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }
    *outSupport = static_cast<bool>(intSupport);
    return Error::None;
}

Error Display::getHdrCapabilities(
        std::unique_ptr<HdrCapabilities>* outCapabilities) const
{
    uint32_t numTypes = 0;
    float maxLuminance = -1.0f;
    float maxAverageLuminance = -1.0f;
    float minLuminance = -1.0f;
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mGetHdrCapabilities(mDevice.mHwcDevice, mId,
            &numTypes, nullptr, &maxLuminance, &maxAverageLuminance,
            &minLuminance);
    auto error = static_cast<HWC2::Error>(intError);
    if (error != Error::None) {
        return error;
    }

    std::vector<int32_t> types(numTypes);
    intError = mDevice.mGetHdrCapabilities(mDevice.mHwcDevice, mId, &numTypes,
            types.data(), &maxLuminance, &maxAverageLuminance, &minLuminance);
    error = static_cast<HWC2::Error>(intError);
#else
    std::vector<Hwc2::Hdr> intTypes;
    auto intError = mDevice.mComposer->getHdrCapabilities(mId, intTypes,
            maxLuminance, maxAverageLuminance, minLuminance);
    auto error = static_cast<HWC2::Error>(intError);

    std::vector<int32_t> types;
    for (auto type : intTypes) {
        types.push_back(static_cast<int32_t>(type));
    }
    numTypes = types.size();
#endif
    if (error != Error::None) {
        return error;
    }

    *outCapabilities = std::make_unique<HdrCapabilities>(std::move(types),
            maxLuminance, maxAverageLuminance, minLuminance);
    return Error::None;
}

Error Display::getReleaseFences(
        std::unordered_map<std::shared_ptr<Layer>, sp<Fence>>* outFences) const
{
#ifdef BYPASS_IHWC
    uint32_t numElements = 0;
    int32_t intError = mDevice.mGetReleaseFences(mDevice.mHwcDevice, mId,
            &numElements, nullptr, nullptr);
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    std::vector<hwc2_layer_t> layerIds(numElements);
    std::vector<int32_t> fenceFds(numElements);
    intError = mDevice.mGetReleaseFences(mDevice.mHwcDevice, mId, &numElements,
            layerIds.data(), fenceFds.data());
    error = static_cast<Error>(intError);
#else
    std::vector<Hwc2::Layer> layerIds;
    std::vector<int> fenceFds;
    auto intError = mDevice.mComposer->getReleaseFences(mId,
            layerIds, fenceFds);
    auto error = static_cast<Error>(intError);
    uint32_t numElements = layerIds.size();
#endif
    if (error != Error::None) {
        return error;
    }

    std::unordered_map<std::shared_ptr<Layer>, sp<Fence>> releaseFences;
    releaseFences.reserve(numElements);
    for (uint32_t element = 0; element < numElements; ++element) {
        auto layer = getLayerById(layerIds[element]);
        if (layer) {
            sp<Fence> fence(new Fence(fenceFds[element]));
            releaseFences.emplace(std::move(layer), fence);
        } else {
            ALOGE("getReleaseFences: invalid layer %" PRIu64
                    " found on display %" PRIu64, layerIds[element], mId);
            return Error::BadLayer;
        }
    }

    *outFences = std::move(releaseFences);
    return Error::None;
}

Error Display::present(sp<Fence>* outPresentFence)
{
    int32_t presentFenceFd = 0;
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mPresentDisplay(mDevice.mHwcDevice, mId,
            &presentFenceFd);
#else
    auto intError = mDevice.mComposer->presentDisplay(mId, presentFenceFd);
#endif
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        return error;
    }

    *outPresentFence = new Fence(presentFenceFd);
    return Error::None;
}

Error Display::setActiveConfig(const std::shared_ptr<const Config>& config)
{
    if (config->getDisplayId() != mId) {
        ALOGE("setActiveConfig received config %u for the wrong display %"
                PRIu64 " (expected %" PRIu64 ")", config->getId(),
                config->getDisplayId(), mId);
        return Error::BadConfig;
    }
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetActiveConfig(mDevice.mHwcDevice, mId,
            config->getId());
#else
    auto intError = mDevice.mComposer->setActiveConfig(mId, config->getId());
#endif
    return static_cast<Error>(intError);
}

Error Display::setClientTarget(buffer_handle_t target,
        const sp<Fence>& acquireFence, android_dataspace_t dataspace)
{
    // TODO: Properly encode client target surface damage
    int32_t fenceFd = acquireFence->dup();
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetClientTarget(mDevice.mHwcDevice, mId, target,
            fenceFd, static_cast<int32_t>(dataspace), {0, nullptr});
#else
    auto intError = mDevice.mComposer->setClientTarget(mId, target, fenceFd,
            static_cast<Hwc2::Dataspace>(dataspace),
            std::vector<Hwc2::IComposerClient::Rect>());
#endif
    return static_cast<Error>(intError);
}

Error Display::setColorMode(android_color_mode_t mode)
{
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetColorMode(mDevice.mHwcDevice, mId, mode);
#else
    auto intError = mDevice.mComposer->setColorMode(mId,
            static_cast<Hwc2::ColorMode>(mode));
#endif
    return static_cast<Error>(intError);
}

Error Display::setColorTransform(const android::mat4& matrix,
        android_color_transform_t hint)
{
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetColorTransform(mDevice.mHwcDevice, mId,
            matrix.asArray(), static_cast<int32_t>(hint));
#else
    auto intError = mDevice.mComposer->setColorTransform(mId,
            matrix.asArray(), static_cast<Hwc2::ColorTransform>(hint));
#endif
    return static_cast<Error>(intError);
}

Error Display::setOutputBuffer(const sp<GraphicBuffer>& buffer,
        const sp<Fence>& releaseFence)
{
    int32_t fenceFd = releaseFence->dup();
    auto handle = buffer->getNativeBuffer()->handle;
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetOutputBuffer(mDevice.mHwcDevice, mId, handle,
            fenceFd);
#else
    auto intError = mDevice.mComposer->setOutputBuffer(mId, handle, fenceFd);
#endif
    close(fenceFd);
    return static_cast<Error>(intError);
}

Error Display::setPowerMode(PowerMode mode)
{
#ifdef BYPASS_IHWC
    auto intMode = static_cast<int32_t>(mode);
    int32_t intError = mDevice.mSetPowerMode(mDevice.mHwcDevice, mId, intMode);
#else
    auto intMode = static_cast<Hwc2::IComposerClient::PowerMode>(mode);
    auto intError = mDevice.mComposer->setPowerMode(mId, intMode);
#endif
    return static_cast<Error>(intError);
}

Error Display::setVsyncEnabled(Vsync enabled)
{
#ifdef BYPASS_IHWC
    auto intEnabled = static_cast<int32_t>(enabled);
    int32_t intError = mDevice.mSetVsyncEnabled(mDevice.mHwcDevice, mId,
            intEnabled);
#else
    auto intEnabled = static_cast<Hwc2::IComposerClient::Vsync>(enabled);
    auto intError = mDevice.mComposer->setVsyncEnabled(mId, intEnabled);
#endif
    return static_cast<Error>(intError);
}

Error Display::validate(uint32_t* outNumTypes, uint32_t* outNumRequests)
{
    uint32_t numTypes = 0;
    uint32_t numRequests = 0;
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mValidateDisplay(mDevice.mHwcDevice, mId,
            &numTypes, &numRequests);
#else
    auto intError = mDevice.mComposer->validateDisplay(mId,
            numTypes, numRequests);
#endif
    auto error = static_cast<Error>(intError);
    if (error != Error::None && error != Error::HasChanges) {
        return error;
    }

    *outNumTypes = numTypes;
    *outNumRequests = numRequests;
    return error;
}

// For use by Device

int32_t Display::getAttribute(hwc2_config_t configId, Attribute attribute)
{
    int32_t value = 0;
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mGetDisplayAttribute(mDevice.mHwcDevice, mId,
            configId, static_cast<int32_t>(attribute), &value);
#else
    auto intError = mDevice.mComposer->getDisplayAttribute(mId,
            configId, static_cast<Hwc2::IComposerClient::Attribute>(attribute),
            value);
#endif
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        ALOGE("getDisplayAttribute(%" PRIu64 ", %u, %s) failed: %s (%d)", mId,
                configId, to_string(attribute).c_str(),
                to_string(error).c_str(), intError);
        return -1;
    }
    return value;
}

void Display::loadConfig(hwc2_config_t configId)
{
    ALOGV("[%" PRIu64 "] loadConfig(%u)", mId, configId);

    auto config = Config::Builder(*this, configId)
            .setWidth(getAttribute(configId, Attribute::Width))
            .setHeight(getAttribute(configId, Attribute::Height))
            .setVsyncPeriod(getAttribute(configId, Attribute::VsyncPeriod))
            .setDpiX(getAttribute(configId, Attribute::DpiX))
            .setDpiY(getAttribute(configId, Attribute::DpiY))
            .build();
    mConfigs.emplace(configId, std::move(config));
}

void Display::loadConfigs()
{
    ALOGV("[%" PRIu64 "] loadConfigs", mId);

#ifdef BYPASS_IHWC
    uint32_t numConfigs = 0;
    int32_t intError = mDevice.mGetDisplayConfigs(mDevice.mHwcDevice, mId,
            &numConfigs, nullptr);
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        ALOGE("[%" PRIu64 "] getDisplayConfigs [1] failed: %s (%d)", mId,
                to_string(error).c_str(), intError);
        return;
    }

    std::vector<hwc2_config_t> configIds(numConfigs);
    intError = mDevice.mGetDisplayConfigs(mDevice.mHwcDevice, mId, &numConfigs,
            configIds.data());
    error = static_cast<Error>(intError);
#else
    std::vector<Hwc2::Config> configIds;
    auto intError = mDevice.mComposer->getDisplayConfigs(mId, configIds);
    auto error = static_cast<Error>(intError);
#endif
    if (error != Error::None) {
        ALOGE("[%" PRIu64 "] getDisplayConfigs [2] failed: %s (%d)", mId,
                to_string(error).c_str(), intError);
        return;
    }

    for (auto configId : configIds) {
        loadConfig(configId);
    }
}

// For use by Layer

void Display::destroyLayer(hwc2_layer_t layerId)
{
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mDestroyLayer(mDevice.mHwcDevice, mId, layerId);
#else
    auto intError =mDevice.mComposer->destroyLayer(mId, layerId);
#endif
    auto error = static_cast<Error>(intError);
    ALOGE_IF(error != Error::None, "destroyLayer(%" PRIu64 ", %" PRIu64 ")"
            " failed: %s (%d)", mId, layerId, to_string(error).c_str(),
            intError);
    mLayers.erase(layerId);
}

// Other Display methods

std::shared_ptr<Layer> Display::getLayerById(hwc2_layer_t id) const
{
    if (mLayers.count(id) == 0) {
        return nullptr;
    }

    auto layer = mLayers.at(id).lock();
    return layer;
}

// Layer methods

Layer::Layer(const std::shared_ptr<Display>& display, hwc2_layer_t id)
  : mDisplay(display),
    mDisplayId(display->getId()),
    mDevice(display->getDevice()),
    mId(id)
{
    ALOGV("Created layer %" PRIu64 " on display %" PRIu64, id,
            display->getId());
}

Layer::~Layer()
{
    auto display = mDisplay.lock();
    if (display) {
        display->destroyLayer(mId);
    }
}

Error Layer::setCursorPosition(int32_t x, int32_t y)
{
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetCursorPosition(mDevice.mHwcDevice,
            mDisplayId, mId, x, y);
#else
    auto intError = mDevice.mComposer->setCursorPosition(mDisplayId,
            mId, x, y);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setBuffer(buffer_handle_t buffer,
        const sp<Fence>& acquireFence)
{
    int32_t fenceFd = acquireFence->dup();
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetLayerBuffer(mDevice.mHwcDevice, mDisplayId,
            mId, buffer, fenceFd);
#else
    auto intError = mDevice.mComposer->setLayerBuffer(mDisplayId,
            mId, buffer, fenceFd);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setSurfaceDamage(const Region& damage)
{
    // We encode default full-screen damage as INVALID_RECT upstream, but as 0
    // rects for HWC
#ifdef BYPASS_IHWC
    int32_t intError = 0;
#else
    Hwc2::Error intError = Hwc2::Error::NONE;
#endif
    if (damage.isRect() && damage.getBounds() == Rect::INVALID_RECT) {
#ifdef BYPASS_IHWC
        intError = mDevice.mSetLayerSurfaceDamage(mDevice.mHwcDevice,
                mDisplayId, mId, {0, nullptr});
#else
        intError = mDevice.mComposer->setLayerSurfaceDamage(mDisplayId,
                mId, std::vector<Hwc2::IComposerClient::Rect>());
#endif
    } else {
        size_t rectCount = 0;
        auto rectArray = damage.getArray(&rectCount);

#ifdef BYPASS_IHWC
        std::vector<hwc_rect_t> hwcRects;
#else
        std::vector<Hwc2::IComposerClient::Rect> hwcRects;
#endif
        for (size_t rect = 0; rect < rectCount; ++rect) {
            hwcRects.push_back({rectArray[rect].left, rectArray[rect].top,
                    rectArray[rect].right, rectArray[rect].bottom});
        }

#ifdef BYPASS_IHWC
        hwc_region_t hwcRegion = {};
        hwcRegion.numRects = rectCount;
        hwcRegion.rects = hwcRects.data();

        intError = mDevice.mSetLayerSurfaceDamage(mDevice.mHwcDevice,
                mDisplayId, mId, hwcRegion);
#else
        intError = mDevice.mComposer->setLayerSurfaceDamage(mDisplayId,
                mId, hwcRects);
#endif
    }

    return static_cast<Error>(intError);
}

Error Layer::setBlendMode(BlendMode mode)
{
#ifdef BYPASS_IHWC
    auto intMode = static_cast<int32_t>(mode);
    int32_t intError = mDevice.mSetLayerBlendMode(mDevice.mHwcDevice,
            mDisplayId, mId, intMode);
#else
    auto intMode = static_cast<Hwc2::IComposerClient::BlendMode>(mode);
    auto intError = mDevice.mComposer->setLayerBlendMode(mDisplayId,
            mId, intMode);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setColor(hwc_color_t color)
{
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetLayerColor(mDevice.mHwcDevice, mDisplayId,
            mId, color);
#else
    Hwc2::IComposerClient::Color hwcColor{color.r, color.g, color.b, color.a};
    auto intError = mDevice.mComposer->setLayerColor(mDisplayId,
            mId, hwcColor);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setCompositionType(Composition type)
{
#ifdef BYPASS_IHWC
    auto intType = static_cast<int32_t>(type);
    int32_t intError = mDevice.mSetLayerCompositionType(mDevice.mHwcDevice,
            mDisplayId, mId, intType);
#else
    auto intType = static_cast<Hwc2::IComposerClient::Composition>(type);
    auto intError = mDevice.mComposer->setLayerCompositionType(mDisplayId,
            mId, intType);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setDataspace(android_dataspace_t dataspace)
{
#ifdef BYPASS_IHWC
    auto intDataspace = static_cast<int32_t>(dataspace);
    int32_t intError = mDevice.mSetLayerDataspace(mDevice.mHwcDevice,
            mDisplayId, mId, intDataspace);
#else
    auto intDataspace = static_cast<Hwc2::Dataspace>(dataspace);
    auto intError = mDevice.mComposer->setLayerDataspace(mDisplayId,
            mId, intDataspace);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setDisplayFrame(const Rect& frame)
{
#ifdef BYPASS_IHWC
    hwc_rect_t hwcRect{frame.left, frame.top, frame.right, frame.bottom};
    int32_t intError = mDevice.mSetLayerDisplayFrame(mDevice.mHwcDevice,
            mDisplayId, mId, hwcRect);
#else
    Hwc2::IComposerClient::Rect hwcRect{frame.left, frame.top,
        frame.right, frame.bottom};
    auto intError = mDevice.mComposer->setLayerDisplayFrame(mDisplayId,
            mId, hwcRect);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setPlaneAlpha(float alpha)
{
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetLayerPlaneAlpha(mDevice.mHwcDevice,
            mDisplayId, mId, alpha);
#else
    auto intError = mDevice.mComposer->setLayerPlaneAlpha(mDisplayId,
            mId, alpha);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setSidebandStream(const native_handle_t* stream)
{
    if (!mDevice.hasCapability(Capability::SidebandStream)) {
        ALOGE("Attempted to call setSidebandStream without checking that the "
                "device supports sideband streams");
        return Error::Unsupported;
    }
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetLayerSidebandStream(mDevice.mHwcDevice,
            mDisplayId, mId, stream);
#else
    auto intError = mDevice.mComposer->setLayerSidebandStream(mDisplayId,
            mId, stream);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setSourceCrop(const FloatRect& crop)
{
#ifdef BYPASS_IHWC
    hwc_frect_t hwcRect{crop.left, crop.top, crop.right, crop.bottom};
    int32_t intError = mDevice.mSetLayerSourceCrop(mDevice.mHwcDevice,
            mDisplayId, mId, hwcRect);
#else
    Hwc2::IComposerClient::FRect hwcRect{
        crop.left, crop.top, crop.right, crop.bottom};
    auto intError = mDevice.mComposer->setLayerSourceCrop(mDisplayId,
            mId, hwcRect);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setTransform(Transform transform)
{
#ifdef BYPASS_IHWC
    auto intTransform = static_cast<int32_t>(transform);
    int32_t intError = mDevice.mSetLayerTransform(mDevice.mHwcDevice,
            mDisplayId, mId, intTransform);
#else
    auto intTransform = static_cast<Hwc2::Transform>(transform);
    auto intError = mDevice.mComposer->setLayerTransform(mDisplayId,
            mId, intTransform);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setVisibleRegion(const Region& region)
{
    size_t rectCount = 0;
    auto rectArray = region.getArray(&rectCount);

#ifdef BYPASS_IHWC
    std::vector<hwc_rect_t> hwcRects;
#else
    std::vector<Hwc2::IComposerClient::Rect> hwcRects;
#endif
    for (size_t rect = 0; rect < rectCount; ++rect) {
        hwcRects.push_back({rectArray[rect].left, rectArray[rect].top,
                rectArray[rect].right, rectArray[rect].bottom});
    }

#ifdef BYPASS_IHWC
    hwc_region_t hwcRegion = {};
    hwcRegion.numRects = rectCount;
    hwcRegion.rects = hwcRects.data();

    int32_t intError = mDevice.mSetLayerVisibleRegion(mDevice.mHwcDevice,
            mDisplayId, mId, hwcRegion);
#else
    auto intError = mDevice.mComposer->setLayerVisibleRegion(mDisplayId,
            mId, hwcRects);
#endif
    return static_cast<Error>(intError);
}

Error Layer::setZOrder(uint32_t z)
{
#ifdef BYPASS_IHWC
    int32_t intError = mDevice.mSetLayerZOrder(mDevice.mHwcDevice, mDisplayId,
            mId, z);
#else
    auto intError = mDevice.mComposer->setLayerZOrder(mDisplayId, mId, z);
#endif
    return static_cast<Error>(intError);
}

} // namespace HWC2
