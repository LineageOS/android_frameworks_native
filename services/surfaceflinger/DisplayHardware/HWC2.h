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

#ifndef ANDROID_SF_HWC2_H
#define ANDROID_SF_HWC2_H

#define HWC2_INCLUDE_STRINGIFICATION
#define HWC2_USE_CPP11
#include <hardware/hwcomposer2.h>
#undef HWC2_INCLUDE_STRINGIFICATION
#undef HWC2_USE_CPP11

#include <ui/HdrCapabilities.h>
#include <math/mat4.h>

#include <utils/Log.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <map>

namespace android {
    class Fence;
    class FloatRect;
    class GraphicBuffer;
    class Rect;
    class Region;
    namespace Hwc2 {
        class Composer;
    }
}

namespace HWC2 {

class Display;
class Layer;

typedef std::function<void(std::shared_ptr<Display>, Connection)>
        HotplugCallback;
typedef std::function<void(std::shared_ptr<Display>)> RefreshCallback;
typedef std::function<void(std::shared_ptr<Display>, nsecs_t)> VsyncCallback;

// C++ Wrapper around hwc2_device_t. Load all functions pointers
// and handle callback registration.
class Device
{
public:
    // useVrComposer is passed to the composer HAL. When true, the composer HAL
    // will use the vr composer service, otherwise it uses the real hardware
    // composer.
    Device(bool useVrComposer);
    ~Device();

    friend class HWC2::Display;
    friend class HWC2::Layer;

    // Required by HWC2

    std::string dump() const;

    const std::unordered_set<Capability>& getCapabilities() const {
        return mCapabilities;
    };

    uint32_t getMaxVirtualDisplayCount() const;
    Error createVirtualDisplay(uint32_t width, uint32_t height,
            android_pixel_format_t* format,
            std::shared_ptr<Display>* outDisplay);

    void registerHotplugCallback(HotplugCallback hotplug);
    void registerRefreshCallback(RefreshCallback refresh);
    void registerVsyncCallback(VsyncCallback vsync);

    // For use by callbacks

    void callHotplug(std::shared_ptr<Display> display, Connection connected);
    void callRefresh(std::shared_ptr<Display> display);
    void callVsync(std::shared_ptr<Display> display, nsecs_t timestamp);

    // Other Device methods

    // This will create a Display if one is not found, but it will not be marked
    // as connected. This Display may be null if the display has been torn down
    // but has not been removed from the map yet.
    std::shared_ptr<Display> getDisplayById(hwc2_display_t id);

    bool hasCapability(HWC2::Capability capability) const;

    android::Hwc2::Composer* getComposer() { return mComposer.get(); }

private:
    // Initialization methods

    void loadCapabilities();
    void registerCallbacks();

    // For use by Display

    void destroyVirtualDisplay(hwc2_display_t display);

    // Member variables
    std::unique_ptr<android::Hwc2::Composer> mComposer;

    std::unordered_set<Capability> mCapabilities;
    std::unordered_map<hwc2_display_t, std::weak_ptr<Display>> mDisplays;

    HotplugCallback mHotplug;
    std::vector<std::pair<std::shared_ptr<Display>, Connection>>
            mPendingHotplugs;
    RefreshCallback mRefresh;
    std::vector<std::shared_ptr<Display>> mPendingRefreshes;
    VsyncCallback mVsync;
    std::vector<std::pair<std::shared_ptr<Display>, nsecs_t>> mPendingVsyncs;
};

// Convenience C++ class to access hwc2_device_t Display functions directly.
class Display : public std::enable_shared_from_this<Display>
{
public:
    Display(Device& device, hwc2_display_t id);
    ~Display();

    friend class HWC2::Device;
    friend class HWC2::Layer;

    class Config
    {
    public:
        class Builder
        {
        public:
            Builder(Display& display, hwc2_config_t id);

            std::shared_ptr<const Config> build() {
                return std::const_pointer_cast<const Config>(
                        std::move(mConfig));
            }

            Builder& setWidth(int32_t width) {
                mConfig->mWidth = width;
                return *this;
            }
            Builder& setHeight(int32_t height) {
                mConfig->mHeight = height;
                return *this;
            }
            Builder& setVsyncPeriod(int32_t vsyncPeriod) {
                mConfig->mVsyncPeriod = vsyncPeriod;
                return *this;
            }
            Builder& setDpiX(int32_t dpiX) {
                if (dpiX == -1) {
                    mConfig->mDpiX = getDefaultDensity();
                } else {
                    mConfig->mDpiX = dpiX / 1000.0f;
                }
                return *this;
            }
            Builder& setDpiY(int32_t dpiY) {
                if (dpiY == -1) {
                    mConfig->mDpiY = getDefaultDensity();
                } else {
                    mConfig->mDpiY = dpiY / 1000.0f;
                }
                return *this;
            }

        private:
            float getDefaultDensity();
            std::shared_ptr<Config> mConfig;
        };

        hwc2_display_t getDisplayId() const { return mDisplay.getId(); }
        hwc2_config_t getId() const { return mId; }

        int32_t getWidth() const { return mWidth; }
        int32_t getHeight() const { return mHeight; }
        nsecs_t getVsyncPeriod() const { return mVsyncPeriod; }
        float getDpiX() const { return mDpiX; }
        float getDpiY() const { return mDpiY; }

    private:
        Config(Display& display, hwc2_config_t id);

        Display& mDisplay;
        hwc2_config_t mId;

        int32_t mWidth;
        int32_t mHeight;
        nsecs_t mVsyncPeriod;
        float mDpiX;
        float mDpiY;
    };

    // Required by HWC2

    [[clang::warn_unused_result]] Error acceptChanges();
    [[clang::warn_unused_result]] Error createLayer(
            std::shared_ptr<Layer>* outLayer);
    [[clang::warn_unused_result]] Error getActiveConfig(
            std::shared_ptr<const Config>* outConfig) const;
    [[clang::warn_unused_result]] Error getChangedCompositionTypes(
            std::unordered_map<std::shared_ptr<Layer>, Composition>* outTypes);
    [[clang::warn_unused_result]] Error getColorModes(
            std::vector<android_color_mode_t>* outModes) const;

    // Doesn't call into the HWC2 device, so no errors are possible
    std::vector<std::shared_ptr<const Config>> getConfigs() const;

    [[clang::warn_unused_result]] Error getName(std::string* outName) const;
    [[clang::warn_unused_result]] Error getRequests(
            DisplayRequest* outDisplayRequests,
            std::unordered_map<std::shared_ptr<Layer>, LayerRequest>*
                    outLayerRequests);
    [[clang::warn_unused_result]] Error getType(DisplayType* outType) const;
    [[clang::warn_unused_result]] Error supportsDoze(bool* outSupport) const;
    [[clang::warn_unused_result]] Error getHdrCapabilities(
            std::unique_ptr<android::HdrCapabilities>* outCapabilities) const;
    [[clang::warn_unused_result]] Error getReleaseFences(
            std::unordered_map<std::shared_ptr<Layer>,
                    android::sp<android::Fence>>* outFences) const;
    [[clang::warn_unused_result]] Error present(
            android::sp<android::Fence>* outPresentFence);
    [[clang::warn_unused_result]] Error setActiveConfig(
            const std::shared_ptr<const Config>& config);
    [[clang::warn_unused_result]] Error setClientTarget(
            uint32_t slot, const android::sp<android::GraphicBuffer>& target,
            const android::sp<android::Fence>& acquireFence,
            android_dataspace_t dataspace);
    [[clang::warn_unused_result]] Error setColorMode(android_color_mode_t mode);
    [[clang::warn_unused_result]] Error setColorTransform(
            const android::mat4& matrix, android_color_transform_t hint);
    [[clang::warn_unused_result]] Error setOutputBuffer(
            const android::sp<android::GraphicBuffer>& buffer,
            const android::sp<android::Fence>& releaseFence);
    [[clang::warn_unused_result]] Error setPowerMode(PowerMode mode);
    [[clang::warn_unused_result]] Error setVsyncEnabled(Vsync enabled);
    [[clang::warn_unused_result]] Error validate(uint32_t* outNumTypes,
            uint32_t* outNumRequests);
    [[clang::warn_unused_result]] Error presentOrValidate(uint32_t* outNumTypes,
                                                 uint32_t* outNumRequests,
                                                          android::sp<android::Fence>* outPresentFence, uint32_t* state);

    // Most methods in this class write a command to a command buffer.  The
    // command buffer is implicitly submitted in validate, present, and
    // presentOrValidate.  This method provides a way to discard the commands,
    // which can be used to discard stale commands.
    void discardCommands();

    // Other Display methods

    Device& getDevice() const { return mDevice; }
    hwc2_display_t getId() const { return mId; }
    bool isConnected() const { return mIsConnected; }

private:
    // For use by Device

    void setConnected(bool connected) { mIsConnected = connected; }
    int32_t getAttribute(hwc2_config_t configId, Attribute attribute);
    void loadConfig(hwc2_config_t configId);
    void loadConfigs();

    // For use by Layer
    void destroyLayer(hwc2_layer_t layerId);

    // This may fail (and return a null pointer) if no layer with this ID exists
    // on this display
    std::shared_ptr<Layer> getLayerById(hwc2_layer_t id) const;

    // Member variables

    Device& mDevice;
    hwc2_display_t mId;
    bool mIsConnected;
    DisplayType mType;
    std::unordered_map<hwc2_layer_t, std::weak_ptr<Layer>> mLayers;
    // The ordering in this map matters, for getConfigs(), when it is
    // converted to a vector
    std::map<hwc2_config_t, std::shared_ptr<const Config>> mConfigs;
};

// Convenience C++ class to access hwc2_device_t Layer functions directly.
class Layer
{
public:
    Layer(const std::shared_ptr<Display>& display, hwc2_layer_t id);
    ~Layer();

    bool isAbandoned() const { return mDisplay.expired(); }
    hwc2_layer_t getId() const { return mId; }

    [[clang::warn_unused_result]] Error setCursorPosition(int32_t x, int32_t y);
    [[clang::warn_unused_result]] Error setBuffer(uint32_t slot,
            const android::sp<android::GraphicBuffer>& buffer,
            const android::sp<android::Fence>& acquireFence);
    [[clang::warn_unused_result]] Error setSurfaceDamage(
            const android::Region& damage);

    [[clang::warn_unused_result]] Error setBlendMode(BlendMode mode);
    [[clang::warn_unused_result]] Error setColor(hwc_color_t color);
    [[clang::warn_unused_result]] Error setCompositionType(Composition type);
    [[clang::warn_unused_result]] Error setDataspace(
            android_dataspace_t dataspace);
    [[clang::warn_unused_result]] Error setDisplayFrame(
            const android::Rect& frame);
    [[clang::warn_unused_result]] Error setPlaneAlpha(float alpha);
    [[clang::warn_unused_result]] Error setSidebandStream(
            const native_handle_t* stream);
    [[clang::warn_unused_result]] Error setSourceCrop(
            const android::FloatRect& crop);
    [[clang::warn_unused_result]] Error setTransform(Transform transform);
    [[clang::warn_unused_result]] Error setVisibleRegion(
            const android::Region& region);
    [[clang::warn_unused_result]] Error setZOrder(uint32_t z);
    [[clang::warn_unused_result]] Error setInfo(uint32_t type, uint32_t appId);
    [[clang::warn_unused_result]] Error setAnimating(bool animating);

private:
    std::weak_ptr<Display> mDisplay;
    hwc2_display_t mDisplayId;
    Device& mDevice;
    hwc2_layer_t mId;
};

} // namespace HWC2

#endif // ANDROID_SF_HWC2_H
