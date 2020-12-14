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

#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/thread_annotations.h>
#include <ui/Fence.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <ui/GraphicTypes.h>
#pragma clang diagnostic pop

#include <utils/StrongPointer.h>
#include <utils/Timers.h>

#include "DisplayIdGenerator.h"
#include "DisplayIdentification.h"
#include "HWC2.h"
#include "Hal.h"

namespace android {

namespace hal = hardware::graphics::composer::hal;

struct DisplayedFrameStats;
class GraphicBuffer;
class TestableSurfaceFlinger;
struct CompositionInfo;

namespace Hwc2 {
class Composer;
} // namespace Hwc2

namespace compositionengine {
class Output;
} // namespace compositionengine

struct KnownHWCGenericLayerMetadata {
    const char* name;
    const uint32_t id;
};

// See the comment for SurfaceFlinger::getHwComposer for the thread safety rules for accessing
// this class.
class HWComposer {
public:
    struct DeviceRequestedChanges {
        using ChangedTypes = std::unordered_map<HWC2::Layer*, hal::Composition>;
        using ClientTargetProperty = hal::ClientTargetProperty;
        using DisplayRequests = hal::DisplayRequest;
        using LayerRequests = std::unordered_map<HWC2::Layer*, hal::LayerRequest>;

        ChangedTypes changedTypes;
        DisplayRequests displayRequests;
        LayerRequests layerRequests;
        ClientTargetProperty clientTargetProperty;
    };

    virtual ~HWComposer();

    virtual void setConfiguration(HWC2::ComposerCallback* callback, int32_t sequenceId) = 0;

    virtual bool getDisplayIdentificationData(hal::HWDisplayId, uint8_t* outPort,
                                              DisplayIdentificationData* outData) const = 0;

    virtual bool hasCapability(hal::Capability) const = 0;
    virtual bool hasDisplayCapability(HalDisplayId, hal::DisplayCapability) const = 0;

    // Attempts to allocate a virtual display and returns its ID if created on the HWC device.
    virtual std::optional<DisplayId> allocateVirtualDisplay(uint32_t width, uint32_t height,
                                                            ui::PixelFormat*) = 0;

    virtual void allocatePhysicalDisplay(hal::HWDisplayId, PhysicalDisplayId) = 0;

    // Attempts to create a new layer on this display
    virtual HWC2::Layer* createLayer(HalDisplayId) = 0;
    // Destroy a previously created layer
    virtual void destroyLayer(HalDisplayId, HWC2::Layer*) = 0;

    // Gets any required composition change requests from the HWC device.
    //
    // Note that frameUsesClientComposition must be set correctly based on
    // whether the current frame appears to use client composition. If it is
    // false some internal optimizations are allowed to present the display
    // with fewer handshakes, but this does not work if client composition is
    // expected.
    virtual status_t getDeviceCompositionChanges(
            HalDisplayId, bool frameUsesClientComposition,
            std::optional<DeviceRequestedChanges>* outChanges) = 0;

    virtual status_t setClientTarget(HalDisplayId, uint32_t slot, const sp<Fence>& acquireFence,
                                     const sp<GraphicBuffer>& target, ui::Dataspace) = 0;

    // Present layers to the display and read releaseFences.
    virtual status_t presentAndGetReleaseFences(HalDisplayId) = 0;

    // set power mode
    virtual status_t setPowerMode(PhysicalDisplayId, hal::PowerMode) = 0;

    // Sets a color transform to be applied to the result of composition
    virtual status_t setColorTransform(HalDisplayId, const mat4& transform) = 0;

    // reset state when a display is disconnected
    virtual void disconnectDisplay(HalDisplayId) = 0;

    // get the present fence received from the last call to present.
    virtual sp<Fence> getPresentFence(HalDisplayId) const = 0;

    // Get last release fence for the given layer
    virtual sp<Fence> getLayerReleaseFence(HalDisplayId, HWC2::Layer*) const = 0;

    // Set the output buffer and acquire fence for a virtual display.
    virtual status_t setOutputBuffer(HalVirtualDisplayId, const sp<Fence>& acquireFence,
                                     const sp<GraphicBuffer>& buffer) = 0;

    // After SurfaceFlinger has retrieved the release fences for all the frames,
    // it can call this to clear the shared pointers in the release fence map
    virtual void clearReleaseFences(HalDisplayId) = 0;

    // Fetches the HDR capabilities of the given display
    virtual status_t getHdrCapabilities(HalDisplayId, HdrCapabilities* outCapabilities) = 0;

    virtual int32_t getSupportedPerFrameMetadata(HalDisplayId) const = 0;

    // Returns the available RenderIntent of the given display.
    virtual std::vector<ui::RenderIntent> getRenderIntents(HalDisplayId, ui::ColorMode) const = 0;

    virtual mat4 getDataspaceSaturationMatrix(HalDisplayId, ui::Dataspace) = 0;

    // Returns the attributes of the color sampling engine.
    virtual status_t getDisplayedContentSamplingAttributes(HalDisplayId, ui::PixelFormat* outFormat,
                                                           ui::Dataspace* outDataspace,
                                                           uint8_t* outComponentMask) = 0;
    virtual status_t setDisplayContentSamplingEnabled(HalDisplayId, bool enabled,
                                                      uint8_t componentMask,
                                                      uint64_t maxFrames) = 0;
    virtual status_t getDisplayedContentSample(HalDisplayId, uint64_t maxFrames, uint64_t timestamp,
                                               DisplayedFrameStats* outStats) = 0;

    // Sets the brightness of a display.
    virtual std::future<status_t> setDisplayBrightness(PhysicalDisplayId, float brightness) = 0;

    // Events handling ---------------------------------------------------------

    // Returns stable display ID (and display name on connection of new or previously disconnected
    // display), or std::nullopt if hotplug event was ignored.
    // This function is called from SurfaceFlinger.
    virtual std::optional<DisplayIdentificationInfo> onHotplug(hal::HWDisplayId,
                                                               hal::Connection) = 0;

    // If true we'll update the DeviceProductInfo on subsequent hotplug connected events.
    // TODO(b/157555476): Remove when the framework has proper support for headless mode
    virtual bool updatesDeviceProductInfoOnHotplugReconnect() const = 0;

    virtual bool onVsync(hal::HWDisplayId, int64_t timestamp) = 0;
    virtual void setVsyncEnabled(PhysicalDisplayId, hal::Vsync enabled) = 0;

    virtual nsecs_t getRefreshTimestamp(PhysicalDisplayId) const = 0;
    virtual bool isConnected(PhysicalDisplayId) const = 0;

    virtual std::vector<std::shared_ptr<const HWC2::Display::Config>> getConfigs(
            PhysicalDisplayId) const = 0;

    virtual std::shared_ptr<const HWC2::Display::Config> getActiveConfig(
            PhysicalDisplayId) const = 0;
    virtual int getActiveConfigIndex(PhysicalDisplayId) const = 0;

    virtual std::vector<ui::ColorMode> getColorModes(PhysicalDisplayId) const = 0;

    virtual status_t setActiveColorMode(PhysicalDisplayId, ui::ColorMode mode,
                                        ui::RenderIntent) = 0;

    // Composer 2.4
    virtual DisplayConnectionType getDisplayConnectionType(PhysicalDisplayId) const = 0;
    virtual bool isVsyncPeriodSwitchSupported(PhysicalDisplayId) const = 0;
    virtual nsecs_t getDisplayVsyncPeriod(PhysicalDisplayId) const = 0;
    virtual status_t setActiveConfigWithConstraints(
            PhysicalDisplayId, size_t configId, const hal::VsyncPeriodChangeConstraints&,
            hal::VsyncPeriodChangeTimeline* outTimeline) = 0;
    virtual status_t setAutoLowLatencyMode(PhysicalDisplayId, bool on) = 0;
    virtual status_t getSupportedContentTypes(
            PhysicalDisplayId, std::vector<hal::ContentType>* outSupportedContentTypes) = 0;
    virtual status_t setContentType(PhysicalDisplayId, hal::ContentType) = 0;
    virtual const std::unordered_map<std::string, bool>& getSupportedLayerGenericMetadata()
            const = 0;

    // for debugging ----------------------------------------------------------
    virtual void dump(std::string& out) const = 0;

    virtual Hwc2::Composer* getComposer() const = 0;

    // TODO(b/74619554): Remove special cases for internal/external display.
    virtual std::optional<hal::HWDisplayId> getInternalHwcDisplayId() const = 0;
    virtual std::optional<hal::HWDisplayId> getExternalHwcDisplayId() const = 0;

    virtual std::optional<PhysicalDisplayId> toPhysicalDisplayId(hal::HWDisplayId) const = 0;
    virtual std::optional<hal::HWDisplayId> fromPhysicalDisplayId(PhysicalDisplayId) const = 0;
};

namespace impl {

class HWComposer final : public android::HWComposer {
public:
    explicit HWComposer(std::unique_ptr<Hwc2::Composer> composer);
    explicit HWComposer(const std::string& composerServiceName);

    ~HWComposer() override;

    void setConfiguration(HWC2::ComposerCallback* callback, int32_t sequenceId) override;

    bool getDisplayIdentificationData(hal::HWDisplayId, uint8_t* outPort,
                                      DisplayIdentificationData* outData) const override;

    bool hasCapability(hal::Capability) const override;
    bool hasDisplayCapability(HalDisplayId, hal::DisplayCapability) const override;

    // Attempts to allocate a virtual display and returns its ID if created on the HWC device.
    std::optional<DisplayId> allocateVirtualDisplay(uint32_t width, uint32_t height,
                                                    ui::PixelFormat*) override;

    // Called from SurfaceFlinger, when the state for a new physical display needs to be recreated.
    void allocatePhysicalDisplay(hal::HWDisplayId, PhysicalDisplayId) override;

    // Attempts to create a new layer on this display
    HWC2::Layer* createLayer(HalDisplayId) override;
    // Destroy a previously created layer
    void destroyLayer(HalDisplayId, HWC2::Layer*) override;

    status_t getDeviceCompositionChanges(
            HalDisplayId, bool frameUsesClientComposition,
            std::optional<DeviceRequestedChanges>* outChanges) override;

    status_t setClientTarget(HalDisplayId, uint32_t slot, const sp<Fence>& acquireFence,
                             const sp<GraphicBuffer>& target, ui::Dataspace) override;

    // Present layers to the display and read releaseFences.
    status_t presentAndGetReleaseFences(HalDisplayId) override;

    // set power mode
    status_t setPowerMode(PhysicalDisplayId, hal::PowerMode mode) override;

    // Sets a color transform to be applied to the result of composition
    status_t setColorTransform(HalDisplayId, const mat4& transform) override;

    // reset state when a display is disconnected
    void disconnectDisplay(HalDisplayId) override;

    // get the present fence received from the last call to present.
    sp<Fence> getPresentFence(HalDisplayId) const override;

    // Get last release fence for the given layer
    sp<Fence> getLayerReleaseFence(HalDisplayId, HWC2::Layer*) const override;

    // Set the output buffer and acquire fence for a virtual display.
    status_t setOutputBuffer(HalVirtualDisplayId, const sp<Fence>& acquireFence,
                             const sp<GraphicBuffer>& buffer) override;

    // After SurfaceFlinger has retrieved the release fences for all the frames,
    // it can call this to clear the shared pointers in the release fence map
    void clearReleaseFences(HalDisplayId) override;

    // Fetches the HDR capabilities of the given display
    status_t getHdrCapabilities(HalDisplayId, HdrCapabilities* outCapabilities) override;

    int32_t getSupportedPerFrameMetadata(HalDisplayId) const override;

    // Returns the available RenderIntent of the given display.
    std::vector<ui::RenderIntent> getRenderIntents(HalDisplayId, ui::ColorMode) const override;

    mat4 getDataspaceSaturationMatrix(HalDisplayId, ui::Dataspace) override;

    // Returns the attributes of the color sampling engine.
    status_t getDisplayedContentSamplingAttributes(HalDisplayId, ui::PixelFormat* outFormat,
                                                   ui::Dataspace* outDataspace,
                                                   uint8_t* outComponentMask) override;
    status_t setDisplayContentSamplingEnabled(HalDisplayId, bool enabled, uint8_t componentMask,
                                              uint64_t maxFrames) override;
    status_t getDisplayedContentSample(HalDisplayId, uint64_t maxFrames, uint64_t timestamp,
                                       DisplayedFrameStats* outStats) override;
    std::future<status_t> setDisplayBrightness(PhysicalDisplayId, float brightness) override;

    // Events handling ---------------------------------------------------------

    // Returns PhysicalDisplayId (and display name on connection of new or previously disconnected
    // display), or std::nullopt if hotplug event was ignored.
    std::optional<DisplayIdentificationInfo> onHotplug(hal::HWDisplayId, hal::Connection) override;

    bool updatesDeviceProductInfoOnHotplugReconnect() const override;

    bool onVsync(hal::HWDisplayId, int64_t timestamp) override;
    void setVsyncEnabled(PhysicalDisplayId, hal::Vsync enabled) override;

    nsecs_t getRefreshTimestamp(PhysicalDisplayId) const override;
    bool isConnected(PhysicalDisplayId) const override;

    std::vector<std::shared_ptr<const HWC2::Display::Config>> getConfigs(
            PhysicalDisplayId) const override;

    std::shared_ptr<const HWC2::Display::Config> getActiveConfig(PhysicalDisplayId) const override;
    int getActiveConfigIndex(PhysicalDisplayId) const override;

    std::vector<ui::ColorMode> getColorModes(PhysicalDisplayId) const override;

    status_t setActiveColorMode(PhysicalDisplayId, ui::ColorMode, ui::RenderIntent) override;

    // Composer 2.4
    DisplayConnectionType getDisplayConnectionType(PhysicalDisplayId) const override;
    bool isVsyncPeriodSwitchSupported(PhysicalDisplayId) const override;
    nsecs_t getDisplayVsyncPeriod(PhysicalDisplayId) const override;
    status_t setActiveConfigWithConstraints(PhysicalDisplayId, size_t configId,
                                            const hal::VsyncPeriodChangeConstraints&,
                                            hal::VsyncPeriodChangeTimeline* outTimeline) override;
    status_t setAutoLowLatencyMode(PhysicalDisplayId, bool) override;
    status_t getSupportedContentTypes(PhysicalDisplayId, std::vector<hal::ContentType>*) override;
    status_t setContentType(PhysicalDisplayId, hal::ContentType) override;

    const std::unordered_map<std::string, bool>& getSupportedLayerGenericMetadata() const override;

    // for debugging ----------------------------------------------------------
    void dump(std::string& out) const override;

    Hwc2::Composer* getComposer() const override { return mComposer.get(); }

    // TODO(b/74619554): Remove special cases for internal/external display.
    std::optional<hal::HWDisplayId> getInternalHwcDisplayId() const override {
        return mInternalHwcDisplayId;
    }
    std::optional<hal::HWDisplayId> getExternalHwcDisplayId() const override {
        return mExternalHwcDisplayId;
    }

    std::optional<PhysicalDisplayId> toPhysicalDisplayId(hal::HWDisplayId) const override;
    std::optional<hal::HWDisplayId> fromPhysicalDisplayId(PhysicalDisplayId) const override;

private:
    // For unit tests
    friend TestableSurfaceFlinger;

    std::optional<DisplayIdentificationInfo> onHotplugConnect(hal::HWDisplayId);
    std::optional<DisplayIdentificationInfo> onHotplugDisconnect(hal::HWDisplayId);
    bool shouldIgnoreHotplugConnect(hal::HWDisplayId, bool hasDisplayIdentificationData) const;

    void loadCapabilities();
    void loadLayerMetadataSupport();
    uint32_t getMaxVirtualDisplayCount() const;

    struct DisplayData {
        bool isVirtual = false;
        std::unique_ptr<HWC2::Display> hwcDisplay;
        sp<Fence> lastPresentFence = Fence::NO_FENCE; // signals when the last set op retires
        std::unordered_map<HWC2::Layer*, sp<Fence>> releaseFences;
        buffer_handle_t outbufHandle = nullptr;
        sp<Fence> outbufAcquireFence = Fence::NO_FENCE;
        std::vector<std::shared_ptr<const HWC2::Display::Config>> configs;

        bool validateWasSkipped;
        hal::Error presentError;

        bool vsyncTraceToggle = false;

        std::mutex vsyncEnabledLock;
        hal::Vsync vsyncEnabled GUARDED_BY(vsyncEnabledLock) = hal::Vsync::DISABLE;

        mutable std::mutex lastHwVsyncLock;
        nsecs_t lastHwVsync GUARDED_BY(lastHwVsyncLock) = 0;
    };

    std::unordered_map<HalDisplayId, DisplayData> mDisplayData;

    std::unique_ptr<android::Hwc2::Composer> mComposer;
    std::unordered_set<hal::Capability> mCapabilities;
    std::unordered_map<std::string, bool> mSupportedLayerGenericMetadata;
    bool mRegisteredCallback = false;

    std::unordered_map<hal::HWDisplayId, PhysicalDisplayId> mPhysicalDisplayIdMap;
    std::optional<hal::HWDisplayId> mInternalHwcDisplayId;
    std::optional<hal::HWDisplayId> mExternalHwcDisplayId;
    bool mHasMultiDisplaySupport = false;

    RandomDisplayIdGenerator<HalVirtualDisplayId> mVirtualIdGenerator{getMaxVirtualDisplayCount()};

    const bool mUpdateDeviceProductInfoOnHotplugReconnect;
};

} // namespace impl
} // namespace android

#endif // ANDROID_SF_HWCOMPOSER_H
