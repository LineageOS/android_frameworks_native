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

#ifndef ANDROID_SF_COMPOSER_HAL_H
#define ANDROID_SF_COMPOSER_HAL_H

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <android/hardware/graphics/composer/2.1/IComposer.h>
#include <utils/StrongPointer.h>
#include <IComposerCommandBuffer.h>
#include <MessageQueue.h>

namespace android {

namespace Hwc2 {

using android::hardware::graphics::common::V1_0::ColorMode;
using android::hardware::graphics::common::V1_0::ColorTransform;
using android::hardware::graphics::common::V1_0::Dataspace;
using android::hardware::graphics::common::V1_0::Hdr;
using android::hardware::graphics::common::V1_0::PixelFormat;
using android::hardware::graphics::common::V1_0::Transform;

using android::hardware::graphics::composer::V2_1::IComposer;
using android::hardware::graphics::composer::V2_1::IComposerCallback;
using android::hardware::graphics::composer::V2_1::IComposerClient;
using android::hardware::graphics::composer::V2_1::Error;
using android::hardware::graphics::composer::V2_1::Display;
using android::hardware::graphics::composer::V2_1::Layer;
using android::hardware::graphics::composer::V2_1::Config;

using android::hardware::graphics::composer::V2_1::CommandWriter;
using android::hardware::graphics::composer::V2_1::CommandReaderBase;

using android::hardware::kSynchronizedReadWrite;
using android::hardware::MessageQueue;
using android::hardware::MQDescriptorSync;
using android::hardware::hidl_vec;
using android::hardware::hidl_handle;

class CommandReader : public CommandReaderBase {
public:
    ~CommandReader();

    // Parse and execute commands from the command queue.  The commands are
    // actually return values from the server and will be saved in ReturnData.
    Error parse();

    // Get and clear saved errors.
    struct CommandError {
        uint32_t location;
        Error error;
    };
    std::vector<CommandError> takeErrors();

    bool hasChanges(Display display, uint32_t& numChangedCompositionTypes,
            uint32_t& numLayerRequestMasks) const;

    // Get and clear saved changed composition types.
    void takeChangedCompositionTypes(Display display,
            std::vector<Layer>& layers,
            std::vector<IComposerClient::Composition>& types);

    // Get and clear saved display requests.
    void takeDisplayRequests(Display display,
        uint32_t& displayRequestMask, std::vector<Layer>& layers,
        std::vector<uint32_t>& layerRequestMasks);

    // Get and clear saved release fences.
    void takeReleaseFences(Display display, std::vector<Layer>& layers,
            std::vector<int>& releaseFences);

    // Get and clear saved present fence.
    void takePresentFence(Display display, int& presentFence);

private:
    void resetData();

    bool parseSelectDisplay(uint16_t length);
    bool parseSetError(uint16_t length);
    bool parseSetChangedCompositionTypes(uint16_t length);
    bool parseSetDisplayRequests(uint16_t length);
    bool parseSetPresentFence(uint16_t length);
    bool parseSetReleaseFences(uint16_t length);

    struct ReturnData {
        uint32_t displayRequests = 0;

        std::vector<Layer> changedLayers;
        std::vector<IComposerClient::Composition> compositionTypes;

        std::vector<Layer> requestedLayers;
        std::vector<uint32_t> requestMasks;

        int presentFence = -1;

        std::vector<Layer> releasedLayers;
        std::vector<int> releaseFences;
    };

    std::vector<CommandError> mErrors;
    std::unordered_map<Display, ReturnData> mReturnData;

    // When SELECT_DISPLAY is parsed, this is updated to point to the
    // display's return data in mReturnData.  We use it to avoid repeated
    // map lookups.
    ReturnData* mCurrentReturnData;
};

// Composer is a wrapper to IComposer, a proxy to server-side composer.
class Composer {
public:
    Composer();

    std::vector<IComposer::Capability> getCapabilities();
    std::string dumpDebugInfo();

    void registerCallback(const sp<IComposerCallback>& callback);

    uint32_t getMaxVirtualDisplayCount();
    Error createVirtualDisplay(uint32_t width, uint32_t height,
            PixelFormat& format, Display& display);
    Error destroyVirtualDisplay(Display display);

    Error acceptDisplayChanges(Display display);

    Error createLayer(Display display, Layer& layer);
    Error destroyLayer(Display display, Layer layer);

    Error getActiveConfig(Display display, Config& config);
    Error getChangedCompositionTypes(Display display,
            std::vector<Layer>& layers,
            std::vector<IComposerClient::Composition>& types);
    Error getColorModes(Display display, std::vector<ColorMode>& modes);
    Error getDisplayAttribute(Display display, Config config,
            IComposerClient::Attribute attribute, int32_t& value);
    Error getDisplayConfigs(Display display,
            std::vector<Config>& configs);
    Error getDisplayName(Display display, std::string& name);

    Error getDisplayRequests(Display display, uint32_t& displayRequestMask,
            std::vector<Layer>& layers,
            std::vector<uint32_t>& layerRequestMasks);

    Error getDisplayType(Display display, IComposerClient::DisplayType& type);
    Error getDozeSupport(Display display, bool& support);
    Error getHdrCapabilities(Display display, std::vector<Hdr>& types,
            float& maxLuminance, float& maxAverageLuminance,
            float& minLuminance);

    Error getReleaseFences(Display display, std::vector<Layer>& layers,
            std::vector<int>& releaseFences);

    Error presentDisplay(Display display, int& presentFence);

    Error setActiveConfig(Display display, Config config);
    Error setClientTarget(Display display, const native_handle_t* target,
            int acquireFence, Dataspace dataspace,
            const std::vector<IComposerClient::Rect>& damage);
    Error setColorMode(Display display, ColorMode mode);
    Error setColorTransform(Display display, const float* matrix,
            ColorTransform hint);
    Error setOutputBuffer(Display display, const native_handle_t* buffer,
            int releaseFence);
    Error setPowerMode(Display display, IComposerClient::PowerMode mode);
    Error setVsyncEnabled(Display display, IComposerClient::Vsync enabled);

    Error setClientTargetSlotCount(Display display);

    Error validateDisplay(Display display, uint32_t& numTypes,
            uint32_t& numRequests);

    Error setCursorPosition(Display display, Layer layer,
            int32_t x, int32_t y);
    Error setLayerBuffer(Display display, Layer layer,
            const native_handle_t* buffer, int acquireFence);
    Error setLayerSurfaceDamage(Display display, Layer layer,
            const std::vector<IComposerClient::Rect>& damage);
    Error setLayerBlendMode(Display display, Layer layer,
            IComposerClient::BlendMode mode);
    Error setLayerColor(Display display, Layer layer,
            const IComposerClient::Color& color);
    Error setLayerCompositionType(Display display, Layer layer,
            IComposerClient::Composition type);
    Error setLayerDataspace(Display display, Layer layer,
            Dataspace dataspace);
    Error setLayerDisplayFrame(Display display, Layer layer,
            const IComposerClient::Rect& frame);
    Error setLayerPlaneAlpha(Display display, Layer layer,
            float alpha);
    Error setLayerSidebandStream(Display display, Layer layer,
            const native_handle_t* stream);
    Error setLayerSourceCrop(Display display, Layer layer,
            const IComposerClient::FRect& crop);
    Error setLayerTransform(Display display, Layer layer,
            Transform transform);
    Error setLayerVisibleRegion(Display display, Layer layer,
            const std::vector<IComposerClient::Rect>& visible);
    Error setLayerZOrder(Display display, Layer layer, uint32_t z);

private:
    // Many public functions above simply write a command into the command
    // queue to batch the calls.  validateDisplay and presentDisplay will call
    // this function to execute the command queue.
    Error execute();

    sp<IComposer> mComposer;
    sp<IComposerClient> mClient;

    // 64KiB minus a small space for metadata such as read/write pointers
    static constexpr size_t kWriterInitialSize =
        64 * 1024 / sizeof(uint32_t) - 16;
    CommandWriter mWriter;
    CommandReader mReader;
};

} // namespace Hwc2

} // namespace android

#endif // ANDROID_SF_COMPOSER_HAL_H
