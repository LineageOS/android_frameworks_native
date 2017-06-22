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

#include <ui/Fence.h>
#include <ui/FloatRect.h>
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

Device::Device(bool useVrComposer)
  : mComposer(std::make_unique<Hwc2::Composer>(useVrComposer)),
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
    registerCallbacks();
}

Device::~Device()
{
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
}

// Required by HWC2 device

std::string Device::dump() const
{
    return mComposer->dumpDebugInfo();
}

uint32_t Device::getMaxVirtualDisplayCount() const
{
    return mComposer->getMaxVirtualDisplayCount();
}

Error Device::createVirtualDisplay(uint32_t width, uint32_t height,
        android_pixel_format_t* format, std::shared_ptr<Display>* outDisplay)
{
    ALOGI("Creating virtual display");

    hwc2_display_t displayId = 0;
    auto intFormat = static_cast<Hwc2::PixelFormat>(*format);
    auto intError = mComposer->createVirtualDisplay(width, height,
            &intFormat, &displayId);
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
    (*outDisplay)->setConnected(true);
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
            mComposer->setClientTargetSlotCount(display->getId());
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
    auto capabilities = mComposer->getCapabilities();
    for (auto capability : capabilities) {
        mCapabilities.emplace(static_cast<Capability>(capability));
    }
}

bool Device::hasCapability(HWC2::Capability capability) const
{
    return std::find(mCapabilities.cbegin(), mCapabilities.cend(),
            capability) != mCapabilities.cend();
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
    sp<ComposerCallback> callback = new ComposerCallback(this);
    mComposer->registerCallback(callback);
}


// For use by Display

void Device::destroyVirtualDisplay(hwc2_display_t display)
{
    ALOGI("Destroying virtual display");
    auto intError = mComposer->destroyVirtualDisplay(display);
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
    mType(DisplayType::Invalid)
{
    ALOGV("Created display %" PRIu64, id);

    auto intError = mDevice.mComposer->getDisplayType(mId,
            reinterpret_cast<Hwc2::IComposerClient::DisplayType *>(&mType));
    auto error = static_cast<Error>(intError);
    if (error != Error::None) {
        ALOGE("getDisplayType(%" PRIu64 ") failed: %s (%d)",
              id, to_string(error).c_str(), intError);
    }
}

Display::~Display()
{
    ALOGV("Destroyed display %" PRIu64, mId);
    if (mType == DisplayType::Virtual) {
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
    auto intError = mDevice.mComposer->acceptDisplayChanges(mId);
    return static_cast<Error>(intError);
}

Error Display::createLayer(std::shared_ptr<Layer>* outLayer)
{
    hwc2_layer_t layerId = 0;
    auto intError = mDevice.mComposer->createLayer(mId, &layerId);
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
    auto intError = mDevice.mComposer->getActiveConfig(mId, &configId);
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
    std::vector<Hwc2::Layer> layerIds;
    std::vector<Hwc2::IComposerClient::Composition> types;
    auto intError = mDevice.mComposer->getChangedCompositionTypes(mId,
            &layerIds, &types);
    uint32_t numElements = layerIds.size();
    auto error = static_cast<Error>(intError);
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
    std::vector<Hwc2::ColorMode> modes;
    auto intError = mDevice.mComposer->getColorModes(mId, &modes);
    uint32_t numModes = modes.size();
    auto error = static_cast<Error>(intError);
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
    auto intError = mDevice.mComposer->getDisplayName(mId, outName);
    return static_cast<Error>(intError);
}

Error Display::getRequests(HWC2::DisplayRequest* outDisplayRequests,
        std::unordered_map<std::shared_ptr<Layer>, LayerRequest>*
                outLayerRequests)
{
    uint32_t intDisplayRequests;
    std::vector<Hwc2::Layer> layerIds;
    std::vector<uint32_t> layerRequests;
    auto intError = mDevice.mComposer->getDisplayRequests(mId,
            &intDisplayRequests, &layerIds, &layerRequests);
    uint32_t numElements = layerIds.size();
    auto error = static_cast<Error>(intError);
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
    *outType = mType;
    return Error::None;
}

Error Display::supportsDoze(bool* outSupport) const
{
    bool intSupport = false;
    auto intError = mDevice.mComposer->getDozeSupport(mId, &intSupport);
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
    std::vector<Hwc2::Hdr> intTypes;
    auto intError = mDevice.mComposer->getHdrCapabilities(mId, &intTypes,
            &maxLuminance, &maxAverageLuminance, &minLuminance);
    auto error = static_cast<HWC2::Error>(intError);

    std::vector<int32_t> types;
    for (auto type : intTypes) {
        types.push_back(static_cast<int32_t>(type));
    }
    numTypes = types.size();
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
    std::vector<Hwc2::Layer> layerIds;
    std::vector<int> fenceFds;
    auto intError = mDevice.mComposer->getReleaseFences(mId,
            &layerIds, &fenceFds);
    auto error = static_cast<Error>(intError);
    uint32_t numElements = layerIds.size();
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
            for (; element < numElements; ++element) {
                close(fenceFds[element]);
            }
            return Error::BadLayer;
        }
    }

    *outFences = std::move(releaseFences);
    return Error::None;
}

Error Display::present(sp<Fence>* outPresentFence)
{
    int32_t presentFenceFd = -1;
    auto intError = mDevice.mComposer->presentDisplay(mId, &presentFenceFd);
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
    auto intError = mDevice.mComposer->setActiveConfig(mId, config->getId());
    return static_cast<Error>(intError);
}

Error Display::setClientTarget(uint32_t slot, const sp<GraphicBuffer>& target,
        const sp<Fence>& acquireFence, android_dataspace_t dataspace)
{
    // TODO: Properly encode client target surface damage
    int32_t fenceFd = acquireFence->dup();
    auto intError = mDevice.mComposer->setClientTarget(mId, slot, target,
            fenceFd, static_cast<Hwc2::Dataspace>(dataspace),
            std::vector<Hwc2::IComposerClient::Rect>());
    return static_cast<Error>(intError);
}

Error Display::setColorMode(android_color_mode_t mode)
{
    auto intError = mDevice.mComposer->setColorMode(mId,
            static_cast<Hwc2::ColorMode>(mode));
    return static_cast<Error>(intError);
}

Error Display::setColorTransform(const android::mat4& matrix,
        android_color_transform_t hint)
{
    auto intError = mDevice.mComposer->setColorTransform(mId,
            matrix.asArray(), static_cast<Hwc2::ColorTransform>(hint));
    return static_cast<Error>(intError);
}

Error Display::setOutputBuffer(const sp<GraphicBuffer>& buffer,
        const sp<Fence>& releaseFence)
{
    int32_t fenceFd = releaseFence->dup();
    auto handle = buffer->getNativeBuffer()->handle;
    auto intError = mDevice.mComposer->setOutputBuffer(mId, handle, fenceFd);
    close(fenceFd);
    return static_cast<Error>(intError);
}

Error Display::setPowerMode(PowerMode mode)
{
    auto intMode = static_cast<Hwc2::IComposerClient::PowerMode>(mode);
    auto intError = mDevice.mComposer->setPowerMode(mId, intMode);
    return static_cast<Error>(intError);
}

Error Display::setVsyncEnabled(Vsync enabled)
{
    auto intEnabled = static_cast<Hwc2::IComposerClient::Vsync>(enabled);
    auto intError = mDevice.mComposer->setVsyncEnabled(mId, intEnabled);
    return static_cast<Error>(intError);
}

Error Display::validate(uint32_t* outNumTypes, uint32_t* outNumRequests)
{
    uint32_t numTypes = 0;
    uint32_t numRequests = 0;
    auto intError = mDevice.mComposer->validateDisplay(mId,
            &numTypes, &numRequests);
    auto error = static_cast<Error>(intError);
    if (error != Error::None && error != Error::HasChanges) {
        return error;
    }

    *outNumTypes = numTypes;
    *outNumRequests = numRequests;
    return error;
}

Error Display::presentOrValidate(uint32_t* outNumTypes, uint32_t* outNumRequests,
                                 sp<android::Fence>* outPresentFence, uint32_t* state) {

    uint32_t numTypes = 0;
    uint32_t numRequests = 0;
    int32_t presentFenceFd = -1;
    auto intError = mDevice.mComposer->presentOrValidateDisplay(mId, &numTypes, &numRequests, &presentFenceFd, state);
    auto error = static_cast<Error>(intError);
    if (error != Error::None && error != Error::HasChanges) {
        return error;
    }

    if (*state == 1) {
        *outPresentFence = new Fence(presentFenceFd);
    }

    if (*state == 0) {
        *outNumTypes = numTypes;
        *outNumRequests = numRequests;
    }
    return error;
}

void Display::discardCommands()
{
    mDevice.mComposer->resetCommands();
}

// For use by Device

int32_t Display::getAttribute(hwc2_config_t configId, Attribute attribute)
{
    int32_t value = 0;
    auto intError = mDevice.mComposer->getDisplayAttribute(mId, configId,
            static_cast<Hwc2::IComposerClient::Attribute>(attribute),
            &value);
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

    std::vector<Hwc2::Config> configIds;
    auto intError = mDevice.mComposer->getDisplayConfigs(mId, &configIds);
    auto error = static_cast<Error>(intError);
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
    auto intError =mDevice.mComposer->destroyLayer(mId, layerId);
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
    auto intError = mDevice.mComposer->setCursorPosition(mDisplayId,
            mId, x, y);
    return static_cast<Error>(intError);
}

Error Layer::setBuffer(uint32_t slot, const sp<GraphicBuffer>& buffer,
        const sp<Fence>& acquireFence)
{
    int32_t fenceFd = acquireFence->dup();
    auto intError = mDevice.mComposer->setLayerBuffer(mDisplayId,
            mId, slot, buffer, fenceFd);
    return static_cast<Error>(intError);
}

Error Layer::setSurfaceDamage(const Region& damage)
{
    // We encode default full-screen damage as INVALID_RECT upstream, but as 0
    // rects for HWC
    Hwc2::Error intError = Hwc2::Error::NONE;
    if (damage.isRect() && damage.getBounds() == Rect::INVALID_RECT) {
        intError = mDevice.mComposer->setLayerSurfaceDamage(mDisplayId,
                mId, std::vector<Hwc2::IComposerClient::Rect>());
    } else {
        size_t rectCount = 0;
        auto rectArray = damage.getArray(&rectCount);

        std::vector<Hwc2::IComposerClient::Rect> hwcRects;
        for (size_t rect = 0; rect < rectCount; ++rect) {
            hwcRects.push_back({rectArray[rect].left, rectArray[rect].top,
                    rectArray[rect].right, rectArray[rect].bottom});
        }

        intError = mDevice.mComposer->setLayerSurfaceDamage(mDisplayId,
                mId, hwcRects);
    }

    return static_cast<Error>(intError);
}

Error Layer::setBlendMode(BlendMode mode)
{
    auto intMode = static_cast<Hwc2::IComposerClient::BlendMode>(mode);
    auto intError = mDevice.mComposer->setLayerBlendMode(mDisplayId,
            mId, intMode);
    return static_cast<Error>(intError);
}

Error Layer::setColor(hwc_color_t color)
{
    Hwc2::IComposerClient::Color hwcColor{color.r, color.g, color.b, color.a};
    auto intError = mDevice.mComposer->setLayerColor(mDisplayId,
            mId, hwcColor);
    return static_cast<Error>(intError);
}

Error Layer::setCompositionType(Composition type)
{
    auto intType = static_cast<Hwc2::IComposerClient::Composition>(type);
    auto intError = mDevice.mComposer->setLayerCompositionType(mDisplayId,
            mId, intType);
    return static_cast<Error>(intError);
}

Error Layer::setDataspace(android_dataspace_t dataspace)
{
    auto intDataspace = static_cast<Hwc2::Dataspace>(dataspace);
    auto intError = mDevice.mComposer->setLayerDataspace(mDisplayId,
            mId, intDataspace);
    return static_cast<Error>(intError);
}

Error Layer::setDisplayFrame(const Rect& frame)
{
    Hwc2::IComposerClient::Rect hwcRect{frame.left, frame.top,
        frame.right, frame.bottom};
    auto intError = mDevice.mComposer->setLayerDisplayFrame(mDisplayId,
            mId, hwcRect);
    return static_cast<Error>(intError);
}

Error Layer::setPlaneAlpha(float alpha)
{
    auto intError = mDevice.mComposer->setLayerPlaneAlpha(mDisplayId,
            mId, alpha);
    return static_cast<Error>(intError);
}

Error Layer::setSidebandStream(const native_handle_t* stream)
{
    if (!mDevice.hasCapability(Capability::SidebandStream)) {
        ALOGE("Attempted to call setSidebandStream without checking that the "
                "device supports sideband streams");
        return Error::Unsupported;
    }
    auto intError = mDevice.mComposer->setLayerSidebandStream(mDisplayId,
            mId, stream);
    return static_cast<Error>(intError);
}

Error Layer::setSourceCrop(const FloatRect& crop)
{
    Hwc2::IComposerClient::FRect hwcRect{
        crop.left, crop.top, crop.right, crop.bottom};
    auto intError = mDevice.mComposer->setLayerSourceCrop(mDisplayId,
            mId, hwcRect);
    return static_cast<Error>(intError);
}

Error Layer::setTransform(Transform transform)
{
    auto intTransform = static_cast<Hwc2::Transform>(transform);
    auto intError = mDevice.mComposer->setLayerTransform(mDisplayId,
            mId, intTransform);
    return static_cast<Error>(intError);
}

Error Layer::setVisibleRegion(const Region& region)
{
    size_t rectCount = 0;
    auto rectArray = region.getArray(&rectCount);

    std::vector<Hwc2::IComposerClient::Rect> hwcRects;
    for (size_t rect = 0; rect < rectCount; ++rect) {
        hwcRects.push_back({rectArray[rect].left, rectArray[rect].top,
                rectArray[rect].right, rectArray[rect].bottom});
    }

    auto intError = mDevice.mComposer->setLayerVisibleRegion(mDisplayId,
            mId, hwcRects);
    return static_cast<Error>(intError);
}

Error Layer::setZOrder(uint32_t z)
{
    auto intError = mDevice.mComposer->setLayerZOrder(mDisplayId, mId, z);
    return static_cast<Error>(intError);
}

Error Layer::setInfo(uint32_t type, uint32_t appId)
{
  auto intError = mDevice.mComposer->setLayerInfo(mDisplayId, mId, type, appId);
  return static_cast<Error>(intError);
}

} // namespace HWC2
