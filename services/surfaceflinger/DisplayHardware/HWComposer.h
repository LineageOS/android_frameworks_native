/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_SF_HWCOMPOSER_H
#define ANDROID_SF_HWCOMPOSER_H

#include "HWC2.h"

#include <stdint.h>
#include <sys/types.h>

#include <ui/Fence.h>
#include <ui/GraphicTypes.h>
#include <utils/BitSet.h>
#include <utils/Condition.h>
#include <utils/Mutex.h>
#include <utils/StrongPointer.h>
#include <utils/Thread.h>
#include <utils/Timers.h>
#include <utils/Vector.h>

#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "DisplayIdentification.h"

extern "C" int clock_nanosleep(clockid_t clock_id, int flags,
                           const struct timespec *request,
                           struct timespec *remain);

struct framebuffer_device_t;

namespace HWC2 {
    class Device;
    class Display;
}

namespace android {
// ---------------------------------------------------------------------------

class DisplayDevice;
class Fence;
class FloatRect;
class GraphicBuffer;
class NativeHandle;
class Region;
class String8;
class TestableSurfaceFlinger;
struct CompositionInfo;

namespace Hwc2 {
class Composer;
} // namespace Hwc2

class HWComposer
{
public:
    explicit HWComposer(std::unique_ptr<android::Hwc2::Composer> composer);

    ~HWComposer();

    void registerCallback(HWC2::ComposerCallback* callback,
                          int32_t sequenceId);

    bool getDisplayIdentificationData(hwc2_display_t hwcDisplayId, uint8_t* outPort,
                                      DisplayIdentificationData* outData) const;

    bool hasCapability(HWC2::Capability capability) const;

    // Attempts to allocate a virtual display and returns its ID if created on the HWC device.
    std::optional<DisplayId> allocateVirtualDisplay(uint32_t width, uint32_t height,
                                                    ui::PixelFormat* format);

    // Attempts to create a new layer on this display
    HWC2::Layer* createLayer(DisplayId displayId);
    // Destroy a previously created layer
    void destroyLayer(DisplayId displayId, HWC2::Layer* layer);

    // Asks the HAL what it can do
    status_t prepare(DisplayId displayId, std::vector<CompositionInfo>& compositionData);

    status_t setClientTarget(DisplayId displayId, uint32_t slot, const sp<Fence>& acquireFence,
                             const sp<GraphicBuffer>& target, ui::Dataspace dataspace);

    // Present layers to the display and read releaseFences.
    status_t presentAndGetReleaseFences(DisplayId displayId);

    // set power mode
    status_t setPowerMode(DisplayId displayId, int mode);

    // set active config
    status_t setActiveConfig(DisplayId displayId, size_t configId);

    // Sets a color transform to be applied to the result of composition
    status_t setColorTransform(DisplayId displayId, const mat4& transform);

    // reset state when an external, non-virtual display is disconnected
    void disconnectDisplay(DisplayId displayId);

    // does this display have layers handled by HWC
    bool hasDeviceComposition(const std::optional<DisplayId>& displayId) const;

    // does this display have pending request to flip client target
    bool hasFlipClientTargetRequest(const std::optional<DisplayId>& displayId) const;

    // does this display have layers handled by GLES
    bool hasClientComposition(const std::optional<DisplayId>& displayId) const;

    // get the present fence received from the last call to present.
    sp<Fence> getPresentFence(DisplayId displayId) const;

    // Get last release fence for the given layer
    sp<Fence> getLayerReleaseFence(DisplayId displayId, HWC2::Layer* layer) const;

    // Set the output buffer and acquire fence for a virtual display.
    // Returns INVALID_OPERATION if displayId is not a virtual display.
    status_t setOutputBuffer(DisplayId displayId, const sp<Fence>& acquireFence,
                             const sp<GraphicBuffer>& buffer);

    // After SurfaceFlinger has retrieved the release fences for all the frames,
    // it can call this to clear the shared pointers in the release fence map
    void clearReleaseFences(DisplayId displayId);

    // Fetches the HDR capabilities of the given display
    status_t getHdrCapabilities(DisplayId displayId, HdrCapabilities* outCapabilities);

    int32_t getSupportedPerFrameMetadata(DisplayId displayId) const;

    // Returns the available RenderIntent of the given display.
    std::vector<ui::RenderIntent> getRenderIntents(DisplayId displayId,
                                                   ui::ColorMode colorMode) const;

    mat4 getDataspaceSaturationMatrix(DisplayId displayId, ui::Dataspace dataspace);

    // Events handling ---------------------------------------------------------

    // Returns stable display ID (and display name on connection of new or previously disconnected
    // display), or std::nullopt if hotplug event was ignored.
    std::optional<DisplayIdentificationInfo> onHotplug(hwc2_display_t hwcDisplayId,
                                                       HWC2::Connection connection);

    bool onVsync(hwc2_display_t hwcDisplayId, int64_t timestamp);
    void setVsyncEnabled(DisplayId displayId, HWC2::Vsync enabled);

    nsecs_t getRefreshTimestamp(DisplayId displayId) const;
    bool isConnected(DisplayId displayId) const;

    // Non-const because it can update configMap inside of mDisplayData
    std::vector<std::shared_ptr<const HWC2::Display::Config>> getConfigs(DisplayId displayId) const;

    std::shared_ptr<const HWC2::Display::Config> getActiveConfig(DisplayId displayId) const;
    int getActiveConfigIndex(DisplayId displayId) const;

    std::vector<ui::ColorMode> getColorModes(DisplayId displayId) const;

    status_t setActiveColorMode(DisplayId displayId, ui::ColorMode mode,
                                ui::RenderIntent renderIntent);

    bool isUsingVrComposer() const;

    // for debugging ----------------------------------------------------------
    void dump(String8& out) const;

    android::Hwc2::Composer* getComposer() const { return mHwcDevice->getComposer(); }

    // TODO(b/74619554): Remove special cases for internal/external display.
    std::optional<hwc2_display_t> getInternalHwcDisplayId() const { return mInternalHwcDisplayId; }
    std::optional<hwc2_display_t> getExternalHwcDisplayId() const { return mExternalHwcDisplayId; }

    std::optional<DisplayId> toPhysicalDisplayId(hwc2_display_t hwcDisplayId) const;
    std::optional<hwc2_display_t> fromPhysicalDisplayId(DisplayId displayId) const;

private:
    // For unit tests
    friend TestableSurfaceFlinger;

    std::optional<DisplayIdentificationInfo> onHotplugConnect(hwc2_display_t hwcDisplayId);

    static void validateChange(HWC2::Composition from, HWC2::Composition to);

    struct cb_context;

    struct DisplayData {
        bool isVirtual = false;
        bool hasClientComposition = false;
        bool hasDeviceComposition = false;
        HWC2::Display* hwcDisplay = nullptr;
        HWC2::DisplayRequest displayRequests;
        sp<Fence> lastPresentFence = Fence::NO_FENCE; // signals when the last set op retires
        std::unordered_map<HWC2::Layer*, sp<Fence>> releaseFences;
        buffer_handle_t outbufHandle = nullptr;
        sp<Fence> outbufAcquireFence = Fence::NO_FENCE;
        mutable std::unordered_map<int32_t,
                std::shared_ptr<const HWC2::Display::Config>> configMap;

        // protected by mVsyncLock
        HWC2::Vsync vsyncEnabled = HWC2::Vsync::Disable;

        bool validateWasSkipped;
        HWC2::Error presentError;
    };

    std::unordered_map<DisplayId, DisplayData> mDisplayData;

    // This must be destroyed before mDisplayData, because destructor may call back into HWComposer
    // and look up DisplayData.
    std::unique_ptr<HWC2::Device> mHwcDevice;

    std::unordered_map<hwc2_display_t, DisplayId> mPhysicalDisplayIdMap;
    std::optional<hwc2_display_t> mInternalHwcDisplayId;
    std::optional<hwc2_display_t> mExternalHwcDisplayId;
    bool mHasMultiDisplaySupport = false;

    // protect mDisplayData from races between prepare and dump
    mutable Mutex mDisplayLock;

    cb_context* mCBContext = nullptr;
    std::unordered_map<DisplayId, size_t> mVSyncCounts;

    std::unordered_set<DisplayId> mFreeVirtualDisplayIds;
    uint32_t mNextVirtualDisplayId = 0;
    uint32_t mRemainingHwcVirtualDisplays{mHwcDevice->getMaxVirtualDisplayCount()};

    // protected by mLock
    mutable Mutex mLock;
    mutable std::unordered_map<DisplayId, nsecs_t> mLastHwVSync;

    // thread-safe
    mutable Mutex mVsyncLock;
};

// ---------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_SF_HWCOMPOSER_H
