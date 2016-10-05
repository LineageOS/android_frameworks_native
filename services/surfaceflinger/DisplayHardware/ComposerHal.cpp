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

#undef LOG_TAG
#define LOG_TAG "HwcComposer"

#include <inttypes.h>
#include <log/log.h>

#include "ComposerHal.h"

namespace android {

using hardware::Return;
using hardware::hidl_vec;

namespace Hwc2 {

namespace {

class BufferHandle {
public:
    BufferHandle(const native_handle_t* buffer)
    {
        // nullptr is not a valid handle to HIDL
        mHandle = (buffer) ? buffer : native_handle_init(mStorage, 0, 0);
    }

    operator const native_handle_t*() const
    {
        return mHandle;
    }

private:
    NATIVE_HANDLE_DECLARE_STORAGE(mStorage, 0, 0);
    const native_handle_t* mHandle;
};

class FenceHandle
{
public:
    FenceHandle(int fd, bool owned)
        : mOwned(owned)
    {
        if (fd >= 0) {
            mHandle = native_handle_init(mStorage, 1, 0);
            mHandle->data[0] = fd;
        } else {
            // nullptr is not a valid handle to HIDL
            mHandle = native_handle_init(mStorage, 0, 0);
        }
    }

    ~FenceHandle()
    {
        if (mOwned) {
            native_handle_close(mHandle);
        }
    }

    operator const native_handle_t*() const
    {
        return mHandle;
    }

private:
    bool mOwned;
    NATIVE_HANDLE_DECLARE_STORAGE(mStorage, 1, 0);
    native_handle_t* mHandle;
};

// assume NO_RESOURCES when Status::isOk returns false
constexpr Error kDefaultError = Error::NO_RESOURCES;

template<typename T, typename U>
T unwrapRet(Return<T>& ret, const U& default_val)
{
    return (ret.getStatus().isOk()) ? static_cast<T>(ret) :
        static_cast<T>(default_val);
}

Error unwrapRet(Return<Error>& ret)
{
    return unwrapRet(ret, kDefaultError);
}

template<typename T>
void assignFromHidlVec(std::vector<T>& vec, const hidl_vec<T>& data)
{
    vec.clear();
    vec.insert(vec.begin(), &data[0], &data[data.size()]);
}

} // anonymous namespace

Composer::Composer()
{
    mService = IComposer::getService("hwcomposer");
    if (mService == nullptr) {
        LOG_ALWAYS_FATAL("failed to get hwcomposer service");
    }
}

std::vector<IComposer::Capability> Composer::getCapabilities() const
{
    std::vector<IComposer::Capability> capabilities;
    mService->getCapabilities(
            [&](const auto& tmpCapabilities) {
                assignFromHidlVec(capabilities, tmpCapabilities);
            });

    return capabilities;
}

std::string Composer::dumpDebugInfo() const
{
    std::string info;
    mService->dumpDebugInfo([&](const auto& tmpInfo) {
        info = tmpInfo.c_str();
    });

    return info;
}

void Composer::registerCallback(const sp<IComposerCallback>& callback) const
{
    auto ret = mService->registerCallback(callback);
    if (!ret.getStatus().isOk()) {
        ALOGE("failed to register IComposerCallback");
    }
}

uint32_t Composer::getMaxVirtualDisplayCount() const
{
    auto ret = mService->getMaxVirtualDisplayCount();
    return unwrapRet(ret, 0);
}

Error Composer::createVirtualDisplay(uint32_t width, uint32_t height,
            PixelFormat& format, Display& display) const
{
    Error error = kDefaultError;
    mService->createVirtualDisplay(width, height, format,
            [&](const auto& tmpError, const auto& tmpDisplay,
                const auto& tmpFormat) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                display = tmpDisplay;
                format = tmpFormat;
            });

    return error;
}

Error Composer::destroyVirtualDisplay(Display display) const
{
    auto ret = mService->destroyVirtualDisplay(display);
    return unwrapRet(ret);
}

Error Composer::acceptDisplayChanges(Display display) const
{
    auto ret = mService->acceptDisplayChanges(display);
    return unwrapRet(ret);
}

Error Composer::createLayer(Display display, Layer& layer) const
{
    Error error = kDefaultError;
    mService->createLayer(display,
            [&](const auto& tmpError, const auto& tmpLayer) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                layer = tmpLayer;
            });

    return error;
}

Error Composer::destroyLayer(Display display, Layer layer) const
{
    auto ret = mService->destroyLayer(display, layer);
    return unwrapRet(ret);
}

Error Composer::getActiveConfig(Display display, Config& config) const
{
    Error error = kDefaultError;
    mService->getActiveConfig(display,
            [&](const auto& tmpError, const auto& tmpConfig) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                config = tmpConfig;
            });

    return error;
}

Error Composer::getChangedCompositionTypes(Display display,
        std::vector<Layer>& layers,
        std::vector<IComposer::Composition>& types) const
{
    Error error = kDefaultError;
    mService->getChangedCompositionTypes(display,
            [&](const auto& tmpError, const auto& tmpLayers,
                const auto& tmpTypes) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                assignFromHidlVec(layers, tmpLayers);
                assignFromHidlVec(types, tmpTypes);
            });

    return error;
}

Error Composer::getColorModes(Display display,
        std::vector<ColorMode>& modes) const
{
    Error error = kDefaultError;
    mService->getColorModes(display,
            [&](const auto& tmpError, const auto& tmpModes) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                assignFromHidlVec(modes, tmpModes);
            });

    return error;
}

Error Composer::getDisplayAttribute(Display display, Config config,
        IComposer::Attribute attribute, int32_t& value) const
{
    Error error = kDefaultError;
    mService->getDisplayAttribute(display, config, attribute,
            [&](const auto& tmpError, const auto& tmpValue) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                value = tmpValue;
            });

    return error;
}

Error Composer::getDisplayConfigs(Display display,
        std::vector<Config>& configs) const
{
    Error error = kDefaultError;
    mService->getDisplayConfigs(display,
            [&](const auto& tmpError, const auto& tmpConfigs) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                assignFromHidlVec(configs, tmpConfigs);
            });

    return error;
}

Error Composer::getDisplayName(Display display, std::string& name) const
{
    Error error = kDefaultError;
    mService->getDisplayName(display,
            [&](const auto& tmpError, const auto& tmpName) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                name = tmpName.c_str();
            });

    return error;
}

Error Composer::getDisplayRequests(Display display,
        uint32_t& displayRequestMask, std::vector<Layer>& layers,
        std::vector<uint32_t>& layerRequestMasks) const
{
    Error error = kDefaultError;
    mService->getDisplayRequests(display,
            [&](const auto& tmpError, const auto& tmpDisplayRequestMask,
                const auto& tmpLayers, const auto& tmpLayerRequestMasks) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                displayRequestMask = tmpDisplayRequestMask;
                assignFromHidlVec(layers, tmpLayers);
                assignFromHidlVec(layerRequestMasks, tmpLayerRequestMasks);
            });

    return error;
}

Error Composer::getDisplayType(Display display, IComposer::DisplayType& type) const
{
    Error error = kDefaultError;
    mService->getDisplayType(display,
            [&](const auto& tmpError, const auto& tmpType) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                type = tmpType;
            });

    return error;
}

Error Composer::getDozeSupport(Display display, bool& support) const
{
    Error error = kDefaultError;
    mService->getDozeSupport(display,
            [&](const auto& tmpError, const auto& tmpSupport) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                support = tmpSupport;
            });

    return error;
}

Error Composer::getHdrCapabilities(Display display, std::vector<Hdr>& types,
        float& maxLuminance, float& maxAverageLuminance,
        float& minLuminance) const
{
    Error error = kDefaultError;
    mService->getHdrCapabilities(display,
            [&](const auto& tmpError, const auto& tmpTypes,
                const auto& tmpMaxLuminance,
                const auto& tmpMaxAverageLuminance,
                const auto& tmpMinLuminance) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                assignFromHidlVec(types, tmpTypes);
                maxLuminance = tmpMaxLuminance;
                maxAverageLuminance = tmpMaxAverageLuminance;
                minLuminance = tmpMinLuminance;
            });

    return error;
}

Error Composer::getReleaseFences(Display display, std::vector<Layer>& layers,
        std::vector<int>& releaseFences) const
{
    Error error = kDefaultError;
    mService->getReleaseFences(display,
            [&](const auto& tmpError, const auto& tmpLayers,
                const auto& tmpReleaseFences) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                if (static_cast<int>(tmpLayers.size()) !=
                        tmpReleaseFences->numFds) {
                    ALOGE("invalid releaseFences outputs: "
                          "layer count %zu != fence count %d",
                          tmpLayers.size(), tmpReleaseFences->numFds);
                    error = Error::NO_RESOURCES;
                    return;
                }

                // dup the file descriptors
                std::vector<int> tmpFds;
                tmpFds.reserve(tmpReleaseFences->numFds);
                for (int i = 0; i < tmpReleaseFences->numFds; i++) {
                    int fd = dup(tmpReleaseFences->data[i]);
                    if (fd < 0) {
                        break;
                    }
                    tmpFds.push_back(fd);
                }
                if (static_cast<int>(tmpFds.size()) <
                        tmpReleaseFences->numFds) {
                    for (auto fd : tmpFds) {
                        close(fd);
                    }

                    error = Error::NO_RESOURCES;
                    return;
                }

                assignFromHidlVec(layers, tmpLayers);
                releaseFences = std::move(tmpFds);
            });

    return error;
}

Error Composer::presentDisplay(Display display, int& presentFence) const
{
    Error error = kDefaultError;
    mService->presentDisplay(display,
            [&](const auto& tmpError, const auto& tmpPresentFence) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                if (tmpPresentFence->numFds == 1) {
                    int fd = dup(tmpPresentFence->data[0]);
                    if (fd >= 0) {
                        presentFence = fd;
                    } else {
                        error = Error::NO_RESOURCES;
                    }
                } else {
                    presentFence = -1;
                }
            });

    return error;
}

Error Composer::setActiveConfig(Display display, Config config) const
{
    auto ret = mService->setActiveConfig(display, config);
    return unwrapRet(ret);
}

Error Composer::setClientTarget(Display display, const native_handle_t* target,
        int acquireFence, Dataspace dataspace,
        const std::vector<IComposer::Rect>& damage) const
{
    BufferHandle tmpTarget(target);
    FenceHandle tmpAcquireFence(acquireFence, true);

    hidl_vec<IComposer::Rect> tmpDamage;
    tmpDamage.setToExternal(const_cast<IComposer::Rect*>(damage.data()),
            damage.size());

    auto ret = mService->setClientTarget(display, tmpTarget,
            tmpAcquireFence, dataspace, tmpDamage);
    return unwrapRet(ret);
}

Error Composer::setColorMode(Display display, ColorMode mode) const
{
    auto ret = mService->setColorMode(display, mode);
    return unwrapRet(ret);
}

Error Composer::setColorTransform(Display display, const float* matrix,
        ColorTransform hint) const
{
    hidl_vec<float> tmpMatrix;
    tmpMatrix.setToExternal(const_cast<float*>(matrix), 16);

    auto ret = mService->setColorTransform(display, tmpMatrix, hint);
    return unwrapRet(ret);
}

Error Composer::setOutputBuffer(Display display, const native_handle_t* buffer,
        int releaseFence) const
{
    BufferHandle tmpBuffer(buffer);
    FenceHandle tmpReleaseFence(releaseFence, false);

    auto ret = mService->setOutputBuffer(display, tmpBuffer, tmpReleaseFence);
    return unwrapRet(ret);
}

Error Composer::setPowerMode(Display display, IComposer::PowerMode mode) const
{
    auto ret = mService->setPowerMode(display, mode);
    return unwrapRet(ret);
}

Error Composer::setVsyncEnabled(Display display, IComposer::Vsync enabled) const
{
    auto ret = mService->setVsyncEnabled(display, enabled);
    return unwrapRet(ret);
}

Error Composer::validateDisplay(Display display, uint32_t& numTypes, uint32_t&
        numRequests) const
{
    Error error = kDefaultError;
    mService->validateDisplay(display,
            [&](const auto& tmpError, const auto& tmpNumTypes,
                const auto& tmpNumRequests) {
                error = tmpError;
                if (error != Error::NONE) {
                    return;
                }

                numTypes = tmpNumTypes;
                numRequests = tmpNumRequests;
            });

    return error;
}

Error Composer::setCursorPosition(Display display, Layer layer,
        int32_t x, int32_t y) const
{
    auto ret = mService->setCursorPosition(display, layer, x, y);
    return unwrapRet(ret);
}

Error Composer::setLayerBuffer(Display display, Layer layer,
        const native_handle_t* buffer, int acquireFence) const
{
    BufferHandle tmpBuffer(buffer);
    FenceHandle tmpAcquireFence(acquireFence, true);

    auto ret = mService->setLayerBuffer(display, layer,
            tmpBuffer, tmpAcquireFence);
    return unwrapRet(ret);
}

Error Composer::setLayerSurfaceDamage(Display display, Layer layer,
        const std::vector<IComposer::Rect>& damage) const
{
    hidl_vec<IComposer::Rect> tmpDamage;
    tmpDamage.setToExternal(const_cast<IComposer::Rect*>(damage.data()),
            damage.size());

    auto ret = mService->setLayerSurfaceDamage(display, layer, tmpDamage);
    return unwrapRet(ret);
}

Error Composer::setLayerBlendMode(Display display, Layer layer,
        IComposer::BlendMode mode) const
{
    auto ret = mService->setLayerBlendMode(display, layer, mode);
    return unwrapRet(ret);
}

Error Composer::setLayerColor(Display display, Layer layer,
        const IComposer::Color& color) const
{
    auto ret = mService->setLayerColor(display, layer, color);
    return unwrapRet(ret);
}

Error Composer::setLayerCompositionType(Display display, Layer layer,
        IComposer::Composition type) const
{
    auto ret = mService->setLayerCompositionType(display, layer, type);
    return unwrapRet(ret);
}

Error Composer::setLayerDataspace(Display display, Layer layer,
        Dataspace dataspace) const
{
    auto ret = mService->setLayerDataspace(display, layer, dataspace);
    return unwrapRet(ret);
}

Error Composer::setLayerDisplayFrame(Display display, Layer layer,
        const IComposer::Rect& frame) const
{
    auto ret = mService->setLayerDisplayFrame(display, layer, frame);
    return unwrapRet(ret);
}

Error Composer::setLayerPlaneAlpha(Display display, Layer layer,
        float alpha) const
{
    auto ret = mService->setLayerPlaneAlpha(display, layer, alpha);
    return unwrapRet(ret);
}

Error Composer::setLayerSidebandStream(Display display, Layer layer,
        const native_handle_t* stream) const
{
    BufferHandle tmpStream(stream);

    auto ret = mService->setLayerSidebandStream(display, layer, tmpStream);
    return unwrapRet(ret);
}

Error Composer::setLayerSourceCrop(Display display, Layer layer,
        const IComposer::FRect& crop) const
{
    auto ret = mService->setLayerSourceCrop(display, layer, crop);
    return unwrapRet(ret);
}

Error Composer::setLayerTransform(Display display, Layer layer,
        Transform transform) const
{
    auto ret = mService->setLayerTransform(display, layer, transform);
    return unwrapRet(ret);
}

Error Composer::setLayerVisibleRegion(Display display, Layer layer,
        const std::vector<IComposer::Rect>& visible) const
{
    hidl_vec<IComposer::Rect> tmpVisible;
    tmpVisible.setToExternal(const_cast<IComposer::Rect*>(visible.data()),
            visible.size());

    auto ret = mService->setLayerVisibleRegion(display, layer, tmpVisible);
    return unwrapRet(ret);
}

Error Composer::setLayerZOrder(Display display, Layer layer, uint32_t z) const
{
    auto ret = mService->setLayerZOrder(display, layer, z);
    return unwrapRet(ret);
}

} // namespace Hwc2

} // namespace android
