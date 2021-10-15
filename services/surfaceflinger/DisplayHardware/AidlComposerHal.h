/*
 * Copyright 2021 The Android Open Source Project
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

#include "ComposerHal.h"

#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <android/hardware/graphics/composer/2.4/IComposer.h>
#include <android/hardware/graphics/composer/2.4/IComposerClient.h>

#include <aidl/android/hardware/graphics/composer3/IComposer.h>
#include <aidl/android/hardware/graphics/composer3/IComposerClient.h>
#include <android/hardware/graphics/composer3/command-buffer.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

namespace android::Hwc2 {

using AidlCommandWriterBase = aidl::android::hardware::graphics::composer3::CommandWriterBase;
using AidlCommandReaderBase = aidl::android::hardware::graphics::composer3::CommandReaderBase;

class AidlIComposerCallbackWrapper;

class AidlCommandReader : public AidlCommandReaderBase {
public:
    ~AidlCommandReader();

    // Parse and execute commands from the command queue.  The commands are
    // actually return values from the server and will be saved in ReturnData.
    int parse();

    // Get and clear saved errors.
    struct CommandError {
        uint32_t location;
        Error error;
    };
    std::vector<CommandError> takeErrors();

    bool hasChanges(Display display, uint32_t* outNumChangedCompositionTypes,
                    uint32_t* outNumLayerRequestMasks) const;

    // Get and clear saved changed composition types.
    void takeChangedCompositionTypes(Display display, std::vector<Layer>* outLayers,
                                     std::vector<IComposerClient::Composition>* outTypes);

    // Get and clear saved display requests.
    void takeDisplayRequests(Display display, uint32_t* outDisplayRequestMask,
                             std::vector<Layer>* outLayers,
                             std::vector<uint32_t>* outLayerRequestMasks);

    // Get and clear saved release fences.
    void takeReleaseFences(Display display, std::vector<Layer>* outLayers,
                           std::vector<int>* outReleaseFences);

    // Get and clear saved present fence.
    void takePresentFence(Display display, int* outPresentFence);

    // Get what stage succeeded during PresentOrValidate: Present or Validate
    void takePresentOrValidateStage(Display display, uint32_t* state);

    // Get the client target properties requested by hardware composer.
    void takeClientTargetProperty(Display display,
                                  IComposerClient::ClientTargetProperty* outClientTargetProperty);

private:
    void resetData();

    bool parseSelectDisplay(uint16_t length);
    bool parseSetError(uint16_t length);
    bool parseSetChangedCompositionTypes(uint16_t length);
    bool parseSetDisplayRequests(uint16_t length);
    bool parseSetPresentFence(uint16_t length);
    bool parseSetReleaseFences(uint16_t length);
    bool parseSetPresentOrValidateDisplayResult(uint16_t length);
    bool parseSetClientTargetProperty(uint16_t length);

    struct ReturnData {
        uint32_t displayRequests = 0;

        std::vector<Layer> changedLayers;
        std::vector<IComposerClient::Composition> compositionTypes;

        std::vector<Layer> requestedLayers;
        std::vector<uint32_t> requestMasks;

        int presentFence = -1;

        std::vector<Layer> releasedLayers;
        std::vector<int> releaseFences;

        uint32_t presentOrValidateState;

        // Composer 2.4 implementation can return a client target property
        // structure to indicate the client target properties that hardware
        // composer requests. The composer client must change the client target
        // properties to match this request.
        IComposerClient::ClientTargetProperty clientTargetProperty{PixelFormat::RGBA_8888,
                                                                   Dataspace::UNKNOWN};
    };

    std::vector<CommandError> mErrors;
    std::unordered_map<Display, ReturnData> mReturnData;

    // When SELECT_DISPLAY is parsed, this is updated to point to the
    // display's return data in mReturnData.  We use it to avoid repeated
    // map lookups.
    ReturnData* mCurrentReturnData;
};

// Composer is a wrapper to IComposer, a proxy to server-side composer.
class AidlComposer final : public Hwc2::Composer {
public:
    static bool isDeclared(const std::string& serviceName);

    explicit AidlComposer(const std::string& serviceName);
    ~AidlComposer() override;

    std::vector<IComposer::Capability> getCapabilities() override;
    std::string dumpDebugInfo() override;

    void registerCallback(const sp<IComposerCallback>& callback) override;

    // Reset all pending commands in the command buffer. Useful if you want to
    // skip a frame but have already queued some commands.
    void resetCommands() override;

    // Explicitly flush all pending commands in the command buffer.
    Error executeCommands() override;

    uint32_t getMaxVirtualDisplayCount() override;
    Error createVirtualDisplay(uint32_t width, uint32_t height, PixelFormat* format,
                               Display* outDisplay) override;
    Error destroyVirtualDisplay(Display display) override;

    Error acceptDisplayChanges(Display display) override;

    Error createLayer(Display display, Layer* outLayer) override;
    Error destroyLayer(Display display, Layer layer) override;

    Error getActiveConfig(Display display, Config* outConfig) override;
    Error getChangedCompositionTypes(Display display, std::vector<Layer>* outLayers,
                                     std::vector<IComposerClient::Composition>* outTypes) override;
    Error getColorModes(Display display, std::vector<ColorMode>* outModes) override;
    Error getDisplayAttribute(Display display, Config config, IComposerClient::Attribute attribute,
                              int32_t* outValue) override;
    Error getDisplayConfigs(Display display, std::vector<Config>* outConfigs);
    Error getDisplayName(Display display, std::string* outName) override;

    Error getDisplayRequests(Display display, uint32_t* outDisplayRequestMask,
                             std::vector<Layer>* outLayers,
                             std::vector<uint32_t>* outLayerRequestMasks) override;

    Error getDozeSupport(Display display, bool* outSupport) override;
    Error getHdrCapabilities(Display display, std::vector<Hdr>* outTypes, float* outMaxLuminance,
                             float* outMaxAverageLuminance, float* outMinLuminance) override;

    Error getReleaseFences(Display display, std::vector<Layer>* outLayers,
                           std::vector<int>* outReleaseFences) override;

    Error presentDisplay(Display display, int* outPresentFence) override;

    Error setActiveConfig(Display display, Config config) override;

    /*
     * The composer caches client targets internally.  When target is nullptr,
     * the composer uses slot to look up the client target from its cache.
     * When target is not nullptr, the cache is updated with the new target.
     */
    Error setClientTarget(Display display, uint32_t slot, const sp<GraphicBuffer>& target,
                          int acquireFence, Dataspace dataspace,
                          const std::vector<IComposerClient::Rect>& damage) override;
    Error setColorMode(Display display, ColorMode mode, RenderIntent renderIntent) override;
    Error setColorTransform(Display display, const float* matrix, ColorTransform hint) override;
    Error setOutputBuffer(Display display, const native_handle_t* buffer,
                          int releaseFence) override;
    Error setPowerMode(Display display, IComposerClient::PowerMode mode) override;
    Error setVsyncEnabled(Display display, IComposerClient::Vsync enabled) override;

    Error setClientTargetSlotCount(Display display) override;

    Error validateDisplay(Display display, uint32_t* outNumTypes,
                          uint32_t* outNumRequests) override;

    Error presentOrValidateDisplay(Display display, uint32_t* outNumTypes, uint32_t* outNumRequests,
                                   int* outPresentFence, uint32_t* state) override;

    Error setCursorPosition(Display display, Layer layer, int32_t x, int32_t y) override;
    /* see setClientTarget for the purpose of slot */
    Error setLayerBuffer(Display display, Layer layer, uint32_t slot,
                         const sp<GraphicBuffer>& buffer, int acquireFence) override;
    Error setLayerSurfaceDamage(Display display, Layer layer,
                                const std::vector<IComposerClient::Rect>& damage) override;
    Error setLayerBlendMode(Display display, Layer layer, IComposerClient::BlendMode mode) override;
    Error setLayerColor(Display display, Layer layer, const IComposerClient::Color& color) override;
    Error setLayerCompositionType(Display display, Layer layer,
                                  IComposerClient::Composition type) override;
    Error setLayerDataspace(Display display, Layer layer, Dataspace dataspace) override;
    Error setLayerDisplayFrame(Display display, Layer layer,
                               const IComposerClient::Rect& frame) override;
    Error setLayerPlaneAlpha(Display display, Layer layer, float alpha) override;
    Error setLayerSidebandStream(Display display, Layer layer,
                                 const native_handle_t* stream) override;
    Error setLayerSourceCrop(Display display, Layer layer,
                             const IComposerClient::FRect& crop) override;
    Error setLayerTransform(Display display, Layer layer, Transform transform) override;
    Error setLayerVisibleRegion(Display display, Layer layer,
                                const std::vector<IComposerClient::Rect>& visible) override;
    Error setLayerZOrder(Display display, Layer layer, uint32_t z) override;

    // Composer HAL 2.2
    Error setLayerPerFrameMetadata(
            Display display, Layer layer,
            const std::vector<IComposerClient::PerFrameMetadata>& perFrameMetadatas) override;
    std::vector<IComposerClient::PerFrameMetadataKey> getPerFrameMetadataKeys(
            Display display) override;
    Error getRenderIntents(Display display, ColorMode colorMode,
                           std::vector<RenderIntent>* outRenderIntents) override;
    Error getDataspaceSaturationMatrix(Dataspace dataspace, mat4* outMatrix) override;

    // Composer HAL 2.3
    Error getDisplayIdentificationData(Display display, uint8_t* outPort,
                                       std::vector<uint8_t>* outData) override;
    Error setLayerColorTransform(Display display, Layer layer, const float* matrix) override;
    Error getDisplayedContentSamplingAttributes(Display display, PixelFormat* outFormat,
                                                Dataspace* outDataspace,
                                                uint8_t* outComponentMask) override;
    Error setDisplayContentSamplingEnabled(Display display, bool enabled, uint8_t componentMask,
                                           uint64_t maxFrames) override;
    Error getDisplayedContentSample(Display display, uint64_t maxFrames, uint64_t timestamp,
                                    DisplayedFrameStats* outStats) override;
    Error setLayerPerFrameMetadataBlobs(
            Display display, Layer layer,
            const std::vector<IComposerClient::PerFrameMetadataBlob>& metadata) override;
    Error setDisplayBrightness(Display display, float brightness) override;

    // Composer HAL 2.4
    bool isVsyncPeriodSwitchSupported() override { return true; }
    Error getDisplayCapabilities(Display display,
                                 std::vector<DisplayCapability>* outCapabilities) override;
    V2_4::Error getDisplayConnectionType(Display display,
                                         IComposerClient::DisplayConnectionType* outType) override;
    V2_4::Error getDisplayVsyncPeriod(Display display, VsyncPeriodNanos* outVsyncPeriod) override;
    V2_4::Error setActiveConfigWithConstraints(
            Display display, Config config,
            const IComposerClient::VsyncPeriodChangeConstraints& vsyncPeriodChangeConstraints,
            VsyncPeriodChangeTimeline* outTimeline) override;
    V2_4::Error setAutoLowLatencyMode(Display displayId, bool on) override;
    V2_4::Error getSupportedContentTypes(
            Display displayId,
            std::vector<IComposerClient::ContentType>* outSupportedContentTypes) override;
    V2_4::Error setContentType(Display displayId,
                               IComposerClient::ContentType contentType) override;
    V2_4::Error setLayerGenericMetadata(Display display, Layer layer, const std::string& key,
                                        bool mandatory, const std::vector<uint8_t>& value) override;
    V2_4::Error getLayerGenericMetadataKeys(
            std::vector<IComposerClient::LayerGenericMetadataKey>* outKeys) override;
    Error getClientTargetProperty(
            Display display,
            IComposerClient::ClientTargetProperty* outClientTargetProperty) override;

private:
    class AidlCommandWriter : public AidlCommandWriterBase {
    public:
        explicit AidlCommandWriter(uint32_t initialMaxSize)
              : AidlCommandWriterBase(initialMaxSize) {}
        ~AidlCommandWriter() override {}
    };

    // Many public functions above simply write a command into the command
    // queue to batch the calls.  validateDisplay and presentDisplay will call
    // this function to execute the command queue.
    Error execute();

    // returns the default instance name for the given service
    static std::string instance(const std::string& serviceName);

    // 64KiB minus a small space for metadata such as read/write pointers
    static constexpr size_t kWriterInitialSize = 64 * 1024 / sizeof(uint32_t) - 16;
    // Max number of buffers that may be cached for a given layer
    // We obtain this number by:
    // 1. Tightly coupling this cache to the max size of BufferQueue
    // 2. Adding an additional slot for the layer caching feature in SurfaceFlinger (see: Planner.h)
    static const constexpr uint32_t kMaxLayerBufferCount = BufferQueue::NUM_BUFFER_SLOTS + 1;
    AidlCommandWriter mWriter;
    AidlCommandReader mReader;

    // Aidl interface
    using AidlIComposer = aidl::android::hardware::graphics::composer3::IComposer;
    using AidlIComposerClient = aidl::android::hardware::graphics::composer3::IComposerClient;
    std::shared_ptr<AidlIComposer> mAidlComposer;
    std::shared_ptr<AidlIComposerClient> mAidlComposerClient;
    std::shared_ptr<AidlIComposerCallbackWrapper> mAidlComposerCallback;
};

} // namespace android::Hwc2
