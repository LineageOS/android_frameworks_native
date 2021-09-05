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

#undef LOG_TAG
#define LOG_TAG "HwcComposer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "ComposerHal.h"

#include <android/binder_ibinder_platform.h>
#include <android/binder_manager.h>
#include <log/log.h>
#include <utils/Trace.h>

#include <aidl/android/hardware/graphics/composer3/BnComposerCallback.h>

#include <algorithm>
#include <cinttypes>

namespace android {

using hardware::hidl_handle;
using hardware::hidl_vec;
using hardware::Return;

using aidl::android::hardware::graphics::composer3::BnComposerCallback;
using aidl::android::hardware::graphics::composer3::Capability;
using aidl::android::hardware::graphics::composer3::PowerMode;
using aidl::android::hardware::graphics::composer3::VirtualDisplay;

using AidlColorMode = aidl::android::hardware::graphics::composer3::ColorMode;
using AidlContentType = aidl::android::hardware::graphics::composer3::ContentType;
using AidlDisplayIdentification =
        aidl::android::hardware::graphics::composer3::DisplayIdentification;
using AidlDisplayContentSample = aidl::android::hardware::graphics::composer3::DisplayContentSample;
using AidlDisplayAttribute = aidl::android::hardware::graphics::composer3::DisplayAttribute;
using AidlDisplayCapability = aidl::android::hardware::graphics::composer3::DisplayCapability;
using AidlExecuteCommandsStatus =
        aidl::android::hardware::graphics::composer3::ExecuteCommandsStatus;
using AidlHdrCapabilities = aidl::android::hardware::graphics::composer3::HdrCapabilities;
using AidlPerFrameMetadata = aidl::android::hardware::graphics::composer3::PerFrameMetadata;
using AidlPerFrameMetadataKey = aidl::android::hardware::graphics::composer3::PerFrameMetadataKey;
using AidlPerFrameMetadataBlob = aidl::android::hardware::graphics::composer3::PerFrameMetadataBlob;
using AidlRenderIntent = aidl::android::hardware::graphics::composer3::RenderIntent;
using AidlVsyncPeriodChangeConstraints =
        aidl::android::hardware::graphics::composer3::VsyncPeriodChangeConstraints;
using AidlVsyncPeriodChangeTimeline =
        aidl::android::hardware::graphics::composer3::VsyncPeriodChangeTimeline;
using AidlLayerGenericMetadataKey =
        aidl::android::hardware::graphics::composer3::LayerGenericMetadataKey;
using AidlDisplayContentSamplingAttributes =
        aidl::android::hardware::graphics::composer3::DisplayContentSamplingAttributes;
using AidlFormatColorComponent = aidl::android::hardware::graphics::composer3::FormatColorComponent;
using AidlDisplayConnectionType =
        aidl::android::hardware::graphics::composer3::DisplayConnectionType;
using AidlIComposerClient = aidl::android::hardware::graphics::composer3::IComposerClient;

using AidlColorTransform = aidl::android::hardware::graphics::common::ColorTransform;
using AidlDataspace = aidl::android::hardware::graphics::common::Dataspace;
using AidlFRect = aidl::android::hardware::graphics::common::FRect;
using AidlRect = aidl::android::hardware::graphics::common::Rect;
using AidlTransform = aidl::android::hardware::graphics::common::Transform;

namespace Hwc2 {

namespace {

template <typename To, typename From>
To translate(From x) {
    return static_cast<To>(x);
}

template <typename To, typename From>
std::vector<To> translate(const std::vector<From>& in) {
    std::vector<To> out;
    out.reserve(in.size());
    std::transform(in.begin(), in.end(), std::back_inserter(out),
                   [](From x) { return translate<To>(x); });
    return out;
}

template <>
AidlRect translate(IComposerClient::Rect x) {
    return AidlRect{
            .left = x.left,
            .top = x.top,
            .right = x.right,
            .bottom = x.bottom,
    };
}

template <>
AidlFRect translate(IComposerClient::FRect x) {
    return AidlFRect{
            .left = x.left,
            .top = x.top,
            .right = x.right,
            .bottom = x.bottom,
    };
}

template <>
Color translate(IComposerClient::Color x) {
    return Color{
            .r = static_cast<int8_t>(x.r),
            .g = static_cast<int8_t>(x.g),
            .b = static_cast<int8_t>(x.b),
            .a = static_cast<int8_t>(x.a),
    };
}

template <>
AidlPerFrameMetadataBlob translate(IComposerClient::PerFrameMetadataBlob x) {
    AidlPerFrameMetadataBlob blob;
    blob.key = translate<AidlPerFrameMetadataKey>(x.key),
    std::copy(blob.blob.begin(), blob.blob.end(), x.blob.begin());
    return blob;
}

template <>
AidlPerFrameMetadata translate(IComposerClient::PerFrameMetadata x) {
    return AidlPerFrameMetadata{
            .key = translate<AidlPerFrameMetadataKey>(x.key),
            .value = x.value,
    };
}

template <>
DisplayedFrameStats translate(AidlDisplayContentSample x) {
    return DisplayedFrameStats{
            .numFrames = static_cast<uint64_t>(x.frameCount),
            .component_0_sample = translate<uint64_t>(x.sampleComponent0),
            .component_1_sample = translate<uint64_t>(x.sampleComponent1),
            .component_2_sample = translate<uint64_t>(x.sampleComponent2),
            .component_3_sample = translate<uint64_t>(x.sampleComponent3),
    };
}

template <>
AidlVsyncPeriodChangeConstraints translate(IComposerClient::VsyncPeriodChangeConstraints x) {
    return AidlVsyncPeriodChangeConstraints{
            .desiredTimeNanos = x.desiredTimeNanos,
            .seamlessRequired = x.seamlessRequired,
    };
}

template <>
VsyncPeriodChangeTimeline translate(AidlVsyncPeriodChangeTimeline x) {
    return VsyncPeriodChangeTimeline{
            .newVsyncAppliedTimeNanos = x.newVsyncAppliedTimeNanos,
            .refreshRequired = x.refreshRequired,
            .refreshTimeNanos = x.refreshTimeNanos,
    };
}

template <>
IComposerClient::LayerGenericMetadataKey translate(AidlLayerGenericMetadataKey x) {
    return IComposerClient::LayerGenericMetadataKey{
            .name = x.name,
            .mandatory = x.mandatory,
    };
}

mat4 makeMat4(std::vector<float> in) {
    return mat4(static_cast<const float*>(in.data()));
}

} // namespace

class AidlIComposerCallbackWrapper : public BnComposerCallback {
public:
    AidlIComposerCallbackWrapper(sp<V2_4::IComposerCallback> callback)
          : mCallback(std::move(callback)) {}

    ::ndk::ScopedAStatus onHotplug(int64_t in_display, bool in_connected) override {
        const auto connection = in_connected ? V2_4::IComposerCallback::Connection::CONNECTED
                                             : V2_4::IComposerCallback::Connection::DISCONNECTED;
        mCallback->onHotplug(translate<Display>(in_display), connection);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onRefresh(int64_t in_display) override {
        mCallback->onRefresh(translate<Display>(in_display));
        return ::ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus onSeamlessPossible(int64_t in_display) override {
        mCallback->onSeamlessPossible(translate<Display>(in_display));
        return ::ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus onVsync(int64_t in_display, int64_t in_timestamp,
                                 int32_t in_vsyncPeriodNanos) override {
        mCallback->onVsync_2_4(translate<Display>(in_display), in_timestamp,
                               static_cast<uint32_t>(in_vsyncPeriodNanos));
        return ::ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus onVsyncPeriodTimingChanged(
            int64_t in_display, const AidlVsyncPeriodChangeTimeline& in_updatedTimeline) override {
        mCallback->onVsyncPeriodTimingChanged(translate<Display>(in_display),
                                              translate<V2_4::VsyncPeriodChangeTimeline>(
                                                      in_updatedTimeline));
        return ::ndk::ScopedAStatus::ok();
    }

private:
    sp<V2_4::IComposerCallback> mCallback;
};

namespace impl {

AidlComposer::AidlComposer(const std::string& serviceName) : mWriter(kWriterInitialSize) {
    // This only waits if the service is actually declared
    mAidlComposer = AidlIComposer::fromBinder(ndk::SpAIBinder(
            AServiceManager_waitForService((AidlIComposer::descriptor + serviceName).c_str())));
    if (!mAidlComposer) {
        LOG_ALWAYS_FATAL("Failed to get AIDL composer service");
        return;
    }

    if (!mAidlComposer->createClient(&mAidlComposerClient).isOk()) {
        LOG_ALWAYS_FATAL("Can't create AidlComposerClient, fallback to HIDL");
        return;
    }

    ALOGI("Loaded AIDL composer3 HAL service");
}

AidlComposer::~AidlComposer() = default;

std::vector<IComposer::Capability> AidlComposer::getCapabilities() {
    std::vector<Capability> capabilities;
    const auto status = mAidlComposer->getCapabilities(&capabilities);
    if (!status.isOk()) {
        ALOGE("getCapabilities failed %s", status.getDescription().c_str());
        return {};
    }
    return translate<IComposer::Capability>(capabilities);
}

std::string AidlComposer::dumpDebugInfo() {
    std::string info;
    const auto status = mAidlComposer->dumpDebugInfo(&info);
    if (!status.isOk()) {
        ALOGE("dumpDebugInfo failed %s", status.getDescription().c_str());
        return {};
    }
    return info;
}

void AidlComposer::registerCallback(const sp<IComposerCallback>& callback) {
    if (mAidlComposerCallback) {
        ALOGE("Callback already registered");
    }
    mAidlComposerCallback = std::make_shared<AidlIComposerCallbackWrapper>(callback);
    AIBinder_setMinSchedulerPolicy(mAidlComposerCallback->asBinder().get(), SCHED_FIFO, 2);

    const auto status = mAidlComposerClient->registerCallback(mAidlComposerCallback);
    if (!status.isOk()) {
        ALOGE("registerCallback failed %s", status.getDescription().c_str());
    }
}

void AidlComposer::resetCommands() {
    mWriter.reset();
}

Error AidlComposer::executeCommands() {
    return execute();
}

uint32_t AidlComposer::getMaxVirtualDisplayCount() {
    int32_t count = 0;
    const auto status = mAidlComposerClient->getMaxVirtualDisplayCount(&count);
    if (!status.isOk()) {
        ALOGE("getMaxVirtualDisplayCount failed %s", status.getDescription().c_str());
        return 0;
    }
    return static_cast<uint32_t>(count);
}

Error AidlComposer::createVirtualDisplay(uint32_t width, uint32_t height, PixelFormat* format,
                                         Display* outDisplay) {
    using AidlPixelFormat = aidl::android::hardware::graphics::common::PixelFormat;
    const int32_t bufferSlotCount = 1;
    VirtualDisplay virtualDisplay;
    const auto status =
            mAidlComposerClient->createVirtualDisplay(static_cast<int32_t>(width),
                                                      static_cast<int32_t>(height),
                                                      static_cast<AidlPixelFormat>(*format),
                                                      bufferSlotCount, &virtualDisplay);

    if (!status.isOk()) {
        ALOGE("createVirtualDisplay failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }

    *outDisplay = translate<Display>(virtualDisplay.display);
    *format = static_cast<PixelFormat>(virtualDisplay.format);
    return Error::NONE;
}

Error AidlComposer::destroyVirtualDisplay(Display display) {
    const auto status = mAidlComposerClient->destroyVirtualDisplay(translate<int64_t>(display));
    if (!status.isOk()) {
        ALOGE("destroyVirtualDisplay failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::acceptDisplayChanges(Display display) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.acceptDisplayChanges();
    return Error::NONE;
}

Error AidlComposer::createLayer(Display display, Layer* outLayer) {
    int64_t layer;
    const auto status = mAidlComposerClient->createLayer(translate<int64_t>(display),
                                                         kMaxLayerBufferCount, &layer);
    if (!status.isOk()) {
        ALOGE("createLayer failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }

    *outLayer = translate<Layer>(layer);
    return Error::NONE;
}

Error AidlComposer::destroyLayer(Display display, Layer layer) {
    const auto status = mAidlComposerClient->destroyLayer(translate<int64_t>(display),
                                                          translate<int64_t>(layer));
    if (!status.isOk()) {
        ALOGE("destroyLayer failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::getActiveConfig(Display display, Config* outConfig) {
    int32_t config;
    const auto status = mAidlComposerClient->getActiveConfig(translate<int64_t>(display), &config);
    if (!status.isOk()) {
        ALOGE("getActiveConfig failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    *outConfig = translate<Config>(config);
    return Error::NONE;
}

Error AidlComposer::getChangedCompositionTypes(
        Display display, std::vector<Layer>* outLayers,
        std::vector<IComposerClient::Composition>* outTypes) {
    mReader.takeChangedCompositionTypes(display, outLayers, outTypes);
    return Error::NONE;
}

Error AidlComposer::getColorModes(Display display, std::vector<ColorMode>* outModes) {
    std::vector<AidlColorMode> modes;
    const auto status = mAidlComposerClient->getColorModes(translate<int64_t>(display), &modes);
    if (!status.isOk()) {
        ALOGE("getColorModes failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    *outModes = translate<ColorMode>(modes);
    return Error::NONE;
}

Error AidlComposer::getDisplayAttribute(Display display, Config config,
                                        IComposerClient::Attribute attribute, int32_t* outValue) {
    const auto status =
            mAidlComposerClient->getDisplayAttribute(translate<int64_t>(display),
                                                     translate<int32_t>(config),
                                                     static_cast<AidlDisplayAttribute>(attribute),
                                                     outValue);
    if (!status.isOk()) {
        ALOGE("getDisplayAttribute failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::getDisplayConfigs(Display display, std::vector<Config>* outConfigs) {
    std::vector<int32_t> configs;
    const auto status =
            mAidlComposerClient->getDisplayConfigs(translate<int64_t>(display), &configs);
    if (!status.isOk()) {
        ALOGE("getDisplayConfigs failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    *outConfigs = translate<Config>(configs);
    return Error::NONE;
}

Error AidlComposer::getDisplayName(Display display, std::string* outName) {
    const auto status = mAidlComposerClient->getDisplayName(translate<int64_t>(display), outName);
    if (!status.isOk()) {
        ALOGE("getDisplayName failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::getDisplayRequests(Display display, uint32_t* outDisplayRequestMask,
                                       std::vector<Layer>* outLayers,
                                       std::vector<uint32_t>* outLayerRequestMasks) {
    mReader.takeDisplayRequests(display, outDisplayRequestMask, outLayers, outLayerRequestMasks);
    return Error::NONE;
}

Error AidlComposer::getDozeSupport(Display display, bool* outSupport) {
    const auto status =
            mAidlComposerClient->getDozeSupport(translate<int64_t>(display), outSupport);
    if (!status.isOk()) {
        ALOGE("getDozeSupport failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::getHdrCapabilities(Display display, std::vector<Hdr>* outTypes,
                                       float* outMaxLuminance, float* outMaxAverageLuminance,
                                       float* outMinLuminance) {
    AidlHdrCapabilities capabilities;
    const auto status =
            mAidlComposerClient->getHdrCapabilities(translate<int64_t>(display), &capabilities);
    if (!status.isOk()) {
        ALOGE("getHdrCapabilities failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }

    *outTypes = translate<Hdr>(capabilities.types);
    *outMaxLuminance = capabilities.maxLuminance;
    *outMaxAverageLuminance = capabilities.maxAverageLuminance;
    *outMinLuminance = capabilities.minLuminance;
    return Error::NONE;
}

Error AidlComposer::getReleaseFences(Display display, std::vector<Layer>* outLayers,
                                     std::vector<int>* outReleaseFences) {
    mReader.takeReleaseFences(display, outLayers, outReleaseFences);
    return Error::NONE;
}

Error AidlComposer::presentDisplay(Display display, int* outPresentFence) {
    ATRACE_NAME("HwcPresentDisplay");
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.presentDisplay();

    Error error = execute();
    if (error != Error::NONE) {
        return error;
    }

    mReader.takePresentFence(display, outPresentFence);

    return Error::NONE;
}

Error AidlComposer::setActiveConfig(Display display, Config config) {
    const auto status = mAidlComposerClient->setActiveConfig(translate<int64_t>(display),
                                                             translate<int32_t>(config));
    if (!status.isOk()) {
        ALOGE("setActiveConfig failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::setClientTarget(Display display, uint32_t slot, const sp<GraphicBuffer>& target,
                                    int acquireFence, Dataspace dataspace,
                                    const std::vector<IComposerClient::Rect>& damage) {
    mWriter.selectDisplay(translate<int64_t>(display));

    const native_handle_t* handle = nullptr;
    if (target.get()) {
        handle = target->getNativeBuffer()->handle;
    }

    mWriter.setClientTarget(slot, handle, acquireFence,
                            translate<aidl::android::hardware::graphics::common::Dataspace>(
                                    dataspace),
                            translate<AidlRect>(damage));
    return Error::NONE;
}

Error AidlComposer::setColorMode(Display display, ColorMode mode, RenderIntent renderIntent) {
    const auto status =
            mAidlComposerClient->setColorMode(translate<int64_t>(display),
                                              translate<AidlColorMode>(mode),
                                              translate<AidlRenderIntent>(renderIntent));
    if (!status.isOk()) {
        ALOGE("setColorMode failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::setColorTransform(Display display, const float* matrix, ColorTransform hint) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.setColorTransform(matrix, translate<AidlColorTransform>(hint));
    return Error::NONE;
}

Error AidlComposer::setOutputBuffer(Display display, const native_handle_t* buffer,
                                    int releaseFence) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.setOutputBuffer(0, buffer, dup(releaseFence));
    return Error::NONE;
}

Error AidlComposer::setPowerMode(Display display, IComposerClient::PowerMode mode) {
    const auto status = mAidlComposerClient->setPowerMode(translate<int64_t>(display),
                                                          translate<PowerMode>(mode));
    if (!status.isOk()) {
        ALOGE("setPowerMode failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::setVsyncEnabled(Display display, IComposerClient::Vsync enabled) {
    const bool enableVsync = enabled == IComposerClient::Vsync::ENABLE;
    const auto status =
            mAidlComposerClient->setVsyncEnabled(translate<int64_t>(display), enableVsync);
    if (!status.isOk()) {
        ALOGE("setVsyncEnabled failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::setClientTargetSlotCount(Display display) {
    const int32_t bufferSlotCount = BufferQueue::NUM_BUFFER_SLOTS;
    const auto status = mAidlComposerClient->setClientTargetSlotCount(translate<int64_t>(display),
                                                                      bufferSlotCount);
    if (!status.isOk()) {
        ALOGE("setClientTargetSlotCount failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::validateDisplay(Display display, uint32_t* outNumTypes,
                                    uint32_t* outNumRequests) {
    ATRACE_NAME("HwcValidateDisplay");
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.validateDisplay();

    Error error = execute();
    if (error != Error::NONE) {
        return error;
    }

    mReader.hasChanges(display, outNumTypes, outNumRequests);

    return Error::NONE;
}

Error AidlComposer::presentOrValidateDisplay(Display display, uint32_t* outNumTypes,
                                             uint32_t* outNumRequests, int* outPresentFence,
                                             uint32_t* state) {
    ATRACE_NAME("HwcPresentOrValidateDisplay");
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.presentOrvalidateDisplay();

    Error error = execute();
    if (error != Error::NONE) {
        return error;
    }

    mReader.takePresentOrValidateStage(display, state);

    if (*state == 1) { // Present succeeded
        mReader.takePresentFence(display, outPresentFence);
    }

    if (*state == 0) { // Validate succeeded.
        mReader.hasChanges(display, outNumTypes, outNumRequests);
    }

    return Error::NONE;
}

Error AidlComposer::setCursorPosition(Display display, Layer layer, int32_t x, int32_t y) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerCursorPosition(x, y);
    return Error::NONE;
}

Error AidlComposer::setLayerBuffer(Display display, Layer layer, uint32_t slot,
                                   const sp<GraphicBuffer>& buffer, int acquireFence) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));

    const native_handle_t* handle = nullptr;
    if (buffer.get()) {
        handle = buffer->getNativeBuffer()->handle;
    }

    mWriter.setLayerBuffer(slot, handle, acquireFence);
    return Error::NONE;
}

Error AidlComposer::setLayerSurfaceDamage(Display display, Layer layer,
                                          const std::vector<IComposerClient::Rect>& damage) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerSurfaceDamage(translate<AidlRect>(damage));
    return Error::NONE;
}

Error AidlComposer::setLayerBlendMode(Display display, Layer layer,
                                      IComposerClient::BlendMode mode) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerBlendMode(translate<BlendMode>(mode));
    return Error::NONE;
}

Error AidlComposer::setLayerColor(Display display, Layer layer,
                                  const IComposerClient::Color& color) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerColor(translate<Color>(color));
    return Error::NONE;
}

Error AidlComposer::setLayerCompositionType(Display display, Layer layer,
                                            IComposerClient::Composition type) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerCompositionType(translate<Composition>(type));
    return Error::NONE;
}

Error AidlComposer::setLayerDataspace(Display display, Layer layer, Dataspace dataspace) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerDataspace(translate<AidlDataspace>(dataspace));
    return Error::NONE;
}

Error AidlComposer::setLayerDisplayFrame(Display display, Layer layer,
                                         const IComposerClient::Rect& frame) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerDisplayFrame(translate<AidlRect>(frame));
    return Error::NONE;
}

Error AidlComposer::setLayerPlaneAlpha(Display display, Layer layer, float alpha) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerPlaneAlpha(alpha);
    return Error::NONE;
}

Error AidlComposer::setLayerSidebandStream(Display display, Layer layer,
                                           const native_handle_t* stream) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerSidebandStream(stream);
    return Error::NONE;
}

Error AidlComposer::setLayerSourceCrop(Display display, Layer layer,
                                       const IComposerClient::FRect& crop) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerSourceCrop(translate<AidlFRect>(crop));
    return Error::NONE;
}

Error AidlComposer::setLayerTransform(Display display, Layer layer, Transform transform) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerTransform(translate<AidlTransform>(transform));
    return Error::NONE;
}

Error AidlComposer::setLayerVisibleRegion(Display display, Layer layer,
                                          const std::vector<IComposerClient::Rect>& visible) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerVisibleRegion(translate<AidlRect>(visible));
    return Error::NONE;
}

Error AidlComposer::setLayerZOrder(Display display, Layer layer, uint32_t z) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerZOrder(z);
    return Error::NONE;
}

Error AidlComposer::execute() {
    // prepare input command queue
    bool queueChanged = false;
    int32_t commandLength = 0;
    std::vector<aidl::android::hardware::common::NativeHandle> commandHandles;
    if (!mWriter.writeQueue(&queueChanged, &commandLength, &commandHandles)) {
        mWriter.reset();
        return Error::NO_RESOURCES;
    }

    // set up new input command queue if necessary
    if (queueChanged) {
        const auto status = mAidlComposerClient->setInputCommandQueue(mWriter.getMQDescriptor());
        if (!status.isOk()) {
            ALOGE("setInputCommandQueue failed %s", status.getDescription().c_str());
            mWriter.reset();
            return static_cast<Error>(status.getServiceSpecificError());
        }
    }

    if (commandLength == 0) {
        mWriter.reset();
        return Error::NONE;
    }

    AidlExecuteCommandsStatus commandStatus;
    auto status =
            mAidlComposerClient->executeCommands(commandLength, commandHandles, &commandStatus);
    // executeCommands can fail because of out-of-fd and we do not want to
    // abort() in that case
    if (!status.isOk()) {
        ALOGE("executeCommands failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }

    // set up new output command queue if necessary
    if (commandStatus.queueChanged) {
        ::aidl::android::hardware::common::fmq::MQDescriptor<
                int32_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>
                outputCommandQueue;
        status = mAidlComposerClient->getOutputCommandQueue(&outputCommandQueue);
        if (!status.isOk()) {
            ALOGE("getOutputCommandQueue failed %s", status.getDescription().c_str());
            return static_cast<Error>(status.getServiceSpecificError());
        }

        mReader.setMQDescriptor(outputCommandQueue);
    }

    Error error;
    if (mReader.readQueue(commandStatus.length, std::move(commandStatus.handles))) {
        error = static_cast<Error>(mReader.parse());
        mReader.reset();
    } else {
        error = Error::NO_RESOURCES;
    }

    if (error == Error::NONE) {
        std::vector<AidlCommandReader::CommandError> commandErrors = mReader.takeErrors();

        for (const auto& cmdErr : commandErrors) {
            auto command = mWriter.getCommand(cmdErr.location);
            if (command == Command::VALIDATE_DISPLAY || command == Command::PRESENT_DISPLAY ||
                command == Command::PRESENT_OR_VALIDATE_DISPLAY) {
                error = cmdErr.error;
            } else {
                ALOGW("command 0x%x generated error %d", command, cmdErr.error);
            }
        }
    }

    mWriter.reset();

    return error;
}

Error AidlComposer::setLayerPerFrameMetadata(
        Display display, Layer layer,
        const std::vector<IComposerClient::PerFrameMetadata>& perFrameMetadatas) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerPerFrameMetadata(translate<AidlPerFrameMetadata>(perFrameMetadatas));
    return Error::NONE;
}

std::vector<IComposerClient::PerFrameMetadataKey> AidlComposer::getPerFrameMetadataKeys(
        Display display) {
    std::vector<AidlPerFrameMetadataKey> keys;
    const auto status =
            mAidlComposerClient->getPerFrameMetadataKeys(translate<int64_t>(display), &keys);
    if (!status.isOk()) {
        ALOGE("getPerFrameMetadataKeys failed %s", status.getDescription().c_str());
        return {};
    }
    return translate<IComposerClient::PerFrameMetadataKey>(keys);
}

Error AidlComposer::getRenderIntents(Display display, ColorMode colorMode,
                                     std::vector<RenderIntent>* outRenderIntents) {
    std::vector<AidlRenderIntent> renderIntents;
    const auto status = mAidlComposerClient->getRenderIntents(translate<int64_t>(display),
                                                              translate<AidlColorMode>(colorMode),
                                                              &renderIntents);
    if (!status.isOk()) {
        ALOGE("getRenderIntents failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    *outRenderIntents = translate<RenderIntent>(renderIntents);
    return Error::NONE;
}

Error AidlComposer::getDataspaceSaturationMatrix(Dataspace dataspace, mat4* outMatrix) {
    std::vector<float> matrix;
    const auto status =
            mAidlComposerClient->getDataspaceSaturationMatrix(translate<AidlDataspace>(dataspace),
                                                              &matrix);
    if (!status.isOk()) {
        ALOGE("getDataspaceSaturationMatrix failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    *outMatrix = makeMat4(matrix);
    return Error::NONE;
}

Error AidlComposer::getDisplayIdentificationData(Display display, uint8_t* outPort,
                                                 std::vector<uint8_t>* outData) {
    AidlDisplayIdentification displayIdentification;
    const auto status =
            mAidlComposerClient->getDisplayIdentificationData(translate<int64_t>(display),
                                                              &displayIdentification);
    if (!status.isOk()) {
        ALOGE("getDisplayIdentificationData failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }

    *outPort = static_cast<uint8_t>(displayIdentification.port);
    *outData = displayIdentification.data;

    return Error::NONE;
}

Error AidlComposer::setLayerColorTransform(Display display, Layer layer, const float* matrix) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerColorTransform(matrix);
    return Error::NONE;
}

Error AidlComposer::getDisplayedContentSamplingAttributes(Display display, PixelFormat* outFormat,
                                                          Dataspace* outDataspace,
                                                          uint8_t* outComponentMask) {
    if (!outFormat || !outDataspace || !outComponentMask) {
        return Error::BAD_PARAMETER;
    }

    AidlDisplayContentSamplingAttributes attributes;
    const auto status =
            mAidlComposerClient->getDisplayedContentSamplingAttributes(translate<int64_t>(display),
                                                                       &attributes);
    if (!status.isOk()) {
        ALOGE("getDisplayedContentSamplingAttributes failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }

    *outFormat = translate<PixelFormat>(attributes.format);
    *outDataspace = translate<Dataspace>(attributes.dataspace);
    *outComponentMask = static_cast<uint8_t>(attributes.componentMask);
    return Error::NONE;
}

Error AidlComposer::setDisplayContentSamplingEnabled(Display display, bool enabled,
                                                     uint8_t componentMask, uint64_t maxFrames) {
    const auto status =
            mAidlComposerClient
                    ->setDisplayedContentSamplingEnabled(translate<int64_t>(display), enabled,
                                                         static_cast<AidlFormatColorComponent>(
                                                                 componentMask),
                                                         static_cast<int64_t>(maxFrames));
    if (!status.isOk()) {
        ALOGE("setDisplayedContentSamplingEnabled failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::getDisplayedContentSample(Display display, uint64_t maxFrames,
                                              uint64_t timestamp, DisplayedFrameStats* outStats) {
    if (!outStats) {
        return Error::BAD_PARAMETER;
    }

    AidlDisplayContentSample sample;
    const auto status =
            mAidlComposerClient->getDisplayedContentSample(translate<int64_t>(display),
                                                           static_cast<int64_t>(maxFrames),
                                                           static_cast<int64_t>(timestamp),
                                                           &sample);
    if (!status.isOk()) {
        ALOGE("getDisplayedContentSample failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    *outStats = translate<DisplayedFrameStats>(sample);
    return Error::NONE;
}

Error AidlComposer::setLayerPerFrameMetadataBlobs(
        Display display, Layer layer,
        const std::vector<IComposerClient::PerFrameMetadataBlob>& metadata) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerPerFrameMetadataBlobs(translate<AidlPerFrameMetadataBlob>(metadata));
    return Error::NONE;
}

Error AidlComposer::setDisplayBrightness(Display display, float brightness) {
    const auto status =
            mAidlComposerClient->setDisplayBrightness(translate<int64_t>(display), brightness);
    if (!status.isOk()) {
        ALOGE("setDisplayBrightness failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    return Error::NONE;
}

Error AidlComposer::getDisplayCapabilities(Display display,
                                           std::vector<DisplayCapability>* outCapabilities) {
    std::vector<AidlDisplayCapability> capabilities;
    const auto status =
            mAidlComposerClient->getDisplayCapabilities(translate<int64_t>(display), &capabilities);
    if (!status.isOk()) {
        ALOGE("getDisplayCapabilities failed %s", status.getDescription().c_str());
        return static_cast<Error>(status.getServiceSpecificError());
    }
    *outCapabilities = translate<DisplayCapability>(capabilities);
    return Error::NONE;
}

V2_4::Error AidlComposer::getDisplayConnectionType(
        Display display, IComposerClient::DisplayConnectionType* outType) {
    AidlDisplayConnectionType type;
    const auto status =
            mAidlComposerClient->getDisplayConnectionType(translate<int64_t>(display), &type);
    if (!status.isOk()) {
        ALOGE("getDisplayConnectionType failed %s", status.getDescription().c_str());
        return static_cast<V2_4::Error>(status.getServiceSpecificError());
    }
    *outType = translate<IComposerClient::DisplayConnectionType>(type);
    return V2_4::Error::NONE;
}

V2_4::Error AidlComposer::getDisplayVsyncPeriod(Display display, VsyncPeriodNanos* outVsyncPeriod) {
    int32_t vsyncPeriod;
    const auto status =
            mAidlComposerClient->getDisplayVsyncPeriod(translate<int64_t>(display), &vsyncPeriod);
    if (!status.isOk()) {
        ALOGE("getDisplayVsyncPeriod failed %s", status.getDescription().c_str());
        return static_cast<V2_4::Error>(status.getServiceSpecificError());
    }
    *outVsyncPeriod = translate<VsyncPeriodNanos>(vsyncPeriod);
    return V2_4::Error::NONE;
}

V2_4::Error AidlComposer::setActiveConfigWithConstraints(
        Display display, Config config,
        const IComposerClient::VsyncPeriodChangeConstraints& vsyncPeriodChangeConstraints,
        VsyncPeriodChangeTimeline* outTimeline) {
    AidlVsyncPeriodChangeTimeline timeline;
    const auto status =
            mAidlComposerClient
                    ->setActiveConfigWithConstraints(translate<int64_t>(display),
                                                     translate<int32_t>(config),
                                                     translate<AidlVsyncPeriodChangeConstraints>(
                                                             vsyncPeriodChangeConstraints),
                                                     &timeline);
    if (!status.isOk()) {
        ALOGE("setActiveConfigWithConstraints failed %s", status.getDescription().c_str());
        return static_cast<V2_4::Error>(status.getServiceSpecificError());
    }
    *outTimeline = translate<VsyncPeriodChangeTimeline>(timeline);
    return V2_4::Error::NONE;
}

V2_4::Error AidlComposer::setAutoLowLatencyMode(Display display, bool on) {
    const auto status = mAidlComposerClient->setAutoLowLatencyMode(translate<int64_t>(display), on);
    if (!status.isOk()) {
        ALOGE("setAutoLowLatencyMode failed %s", status.getDescription().c_str());
        return static_cast<V2_4::Error>(status.getServiceSpecificError());
    }
    return V2_4::Error::NONE;
}

V2_4::Error AidlComposer::getSupportedContentTypes(
        Display displayId, std::vector<IComposerClient::ContentType>* outSupportedContentTypes) {
    std::vector<AidlContentType> types;
    const auto status =
            mAidlComposerClient->getSupportedContentTypes(translate<int64_t>(displayId), &types);
    if (!status.isOk()) {
        ALOGE("getSupportedContentTypes failed %s", status.getDescription().c_str());
        return static_cast<V2_4::Error>(status.getServiceSpecificError());
    }
    *outSupportedContentTypes = translate<IComposerClient::ContentType>(types);
    return V2_4::Error::NONE;
}

V2_4::Error AidlComposer::setContentType(Display display,
                                         IComposerClient::ContentType contentType) {
    const auto status =
            mAidlComposerClient->setContentType(translate<int64_t>(display),
                                                translate<AidlContentType>(contentType));
    if (!status.isOk()) {
        ALOGE("setContentType failed %s", status.getDescription().c_str());
        return static_cast<V2_4::Error>(status.getServiceSpecificError());
    }
    return V2_4::Error::NONE;
}

V2_4::Error AidlComposer::setLayerGenericMetadata(Display display, Layer layer,
                                                  const std::string& key, bool mandatory,
                                                  const std::vector<uint8_t>& value) {
    mWriter.selectDisplay(translate<int64_t>(display));
    mWriter.selectLayer(translate<int64_t>(layer));
    mWriter.setLayerGenericMetadata(key, mandatory, value);
    return V2_4::Error::NONE;
}

V2_4::Error AidlComposer::getLayerGenericMetadataKeys(
        std::vector<IComposerClient::LayerGenericMetadataKey>* outKeys) {
    std::vector<AidlLayerGenericMetadataKey> keys;
    const auto status = mAidlComposerClient->getLayerGenericMetadataKeys(&keys);
    if (!status.isOk()) {
        ALOGE("getLayerGenericMetadataKeys failed %s", status.getDescription().c_str());
        return static_cast<V2_4::Error>(status.getServiceSpecificError());
    }
    *outKeys = translate<IComposerClient::LayerGenericMetadataKey>(keys);
    return V2_4::Error::NONE;
}

Error AidlComposer::getClientTargetProperty(
        Display display, IComposerClient::ClientTargetProperty* outClientTargetProperty) {
    mReader.takeClientTargetProperty(display, outClientTargetProperty);
    return Error::NONE;
}

AidlCommandReader::~AidlCommandReader() {
    resetData();
}

int AidlCommandReader::parse() {
    resetData();

    Command command;
    uint16_t length = 0;

    while (!isEmpty()) {
        if (!beginCommand(&command, &length)) {
            break;
        }

        bool parsed = false;
        switch (command) {
            case Command::SELECT_DISPLAY:
                parsed = parseSelectDisplay(length);
                break;
            case Command::SET_ERROR:
                parsed = parseSetError(length);
                break;
            case Command::SET_CHANGED_COMPOSITION_TYPES:
                parsed = parseSetChangedCompositionTypes(length);
                break;
            case Command::SET_DISPLAY_REQUESTS:
                parsed = parseSetDisplayRequests(length);
                break;
            case Command::SET_PRESENT_FENCE:
                parsed = parseSetPresentFence(length);
                break;
            case Command::SET_RELEASE_FENCES:
                parsed = parseSetReleaseFences(length);
                break;
            case Command ::SET_PRESENT_OR_VALIDATE_DISPLAY_RESULT:
                parsed = parseSetPresentOrValidateDisplayResult(length);
                break;
            case Command::SET_CLIENT_TARGET_PROPERTY:
                parsed = parseSetClientTargetProperty(length);
                break;
            default:
                parsed = false;
                break;
        }

        endCommand();

        if (!parsed) {
            ALOGE("failed to parse command 0x%x length %" PRIu16, command, length);
            break;
        }
    }

    return isEmpty() ? 0 : AidlIComposerClient::EX_NO_RESOURCES;
}

bool AidlCommandReader::parseSelectDisplay(uint16_t length) {
    if (length != CommandWriterBase::kSelectDisplayLength) {
        return false;
    }

    mCurrentReturnData = &mReturnData[read64()];

    return true;
}

bool AidlCommandReader::parseSetError(uint16_t length) {
    if (length != CommandWriterBase::kSetErrorLength) {
        return false;
    }

    auto location = read();
    auto error = static_cast<Error>(readSigned());

    mErrors.emplace_back(CommandError{location, error});

    return true;
}

bool AidlCommandReader::parseSetChangedCompositionTypes(uint16_t length) {
    // (layer id [64bit], composition type [32bit]) pairs
    static constexpr int kCommandWords = 3;

    if (length % kCommandWords != 0 || !mCurrentReturnData) {
        return false;
    }

    uint32_t count = length / kCommandWords;
    mCurrentReturnData->changedLayers.reserve(count);
    mCurrentReturnData->compositionTypes.reserve(count);
    while (count > 0) {
        auto layer = read64();
        auto type = static_cast<IComposerClient::Composition>(readSigned());

        mCurrentReturnData->changedLayers.push_back(layer);
        mCurrentReturnData->compositionTypes.push_back(type);

        count--;
    }

    return true;
}

bool AidlCommandReader::parseSetDisplayRequests(uint16_t length) {
    // display requests [32 bit] followed by
    // (layer id [64bit], layer requests [32bit]) pairs
    static constexpr int kDisplayRequestsWords = 1;
    static constexpr int kCommandWords = 3;
    if (length % kCommandWords != kDisplayRequestsWords || !mCurrentReturnData) {
        return false;
    }

    mCurrentReturnData->displayRequests = read();

    uint32_t count = (length - kDisplayRequestsWords) / kCommandWords;
    mCurrentReturnData->requestedLayers.reserve(count);
    mCurrentReturnData->requestMasks.reserve(count);
    while (count > 0) {
        auto layer = read64();
        auto layerRequestMask = read();

        mCurrentReturnData->requestedLayers.push_back(layer);
        mCurrentReturnData->requestMasks.push_back(layerRequestMask);

        count--;
    }

    return true;
}

bool AidlCommandReader::parseSetPresentFence(uint16_t length) {
    if (length != CommandWriterBase::kSetPresentFenceLength || !mCurrentReturnData) {
        return false;
    }

    if (mCurrentReturnData->presentFence >= 0) {
        close(mCurrentReturnData->presentFence);
    }
    mCurrentReturnData->presentFence = readFence();

    return true;
}

bool AidlCommandReader::parseSetReleaseFences(uint16_t length) {
    // (layer id [64bit], release fence index [32bit]) pairs
    static constexpr int kCommandWords = 3;

    if (length % kCommandWords != 0 || !mCurrentReturnData) {
        return false;
    }

    uint32_t count = length / kCommandWords;
    mCurrentReturnData->releasedLayers.reserve(count);
    mCurrentReturnData->releaseFences.reserve(count);
    while (count > 0) {
        auto layer = read64();
        auto fence = readFence();

        mCurrentReturnData->releasedLayers.push_back(layer);
        mCurrentReturnData->releaseFences.push_back(fence);

        count--;
    }

    return true;
}

bool AidlCommandReader::parseSetPresentOrValidateDisplayResult(uint16_t length) {
    if (length != CommandWriterBase::kPresentOrValidateDisplayResultLength || !mCurrentReturnData) {
        return false;
    }
    mCurrentReturnData->presentOrValidateState = read();
    return true;
}

bool AidlCommandReader::parseSetClientTargetProperty(uint16_t length) {
    if (length != CommandWriterBase::kSetClientTargetPropertyLength || !mCurrentReturnData) {
        return false;
    }
    mCurrentReturnData->clientTargetProperty.pixelFormat = static_cast<PixelFormat>(readSigned());
    mCurrentReturnData->clientTargetProperty.dataspace = static_cast<Dataspace>(readSigned());
    return true;
}

void AidlCommandReader::resetData() {
    mErrors.clear();

    for (auto& data : mReturnData) {
        if (data.second.presentFence >= 0) {
            close(data.second.presentFence);
        }
        for (auto fence : data.second.releaseFences) {
            if (fence >= 0) {
                close(fence);
            }
        }
    }

    mReturnData.clear();
    mCurrentReturnData = nullptr;
}

std::vector<AidlCommandReader::CommandError> AidlCommandReader::takeErrors() {
    return std::move(mErrors);
}

bool AidlCommandReader::hasChanges(Display display, uint32_t* outNumChangedCompositionTypes,
                                   uint32_t* outNumLayerRequestMasks) const {
    auto found = mReturnData.find(display);
    if (found == mReturnData.end()) {
        *outNumChangedCompositionTypes = 0;
        *outNumLayerRequestMasks = 0;
        return false;
    }

    const ReturnData& data = found->second;

    *outNumChangedCompositionTypes = static_cast<uint32_t>(data.compositionTypes.size());
    *outNumLayerRequestMasks = static_cast<uint32_t>(data.requestMasks.size());

    return !(data.compositionTypes.empty() && data.requestMasks.empty());
}

void AidlCommandReader::takeChangedCompositionTypes(
        Display display, std::vector<Layer>* outLayers,
        std::vector<IComposerClient::Composition>* outTypes) {
    auto found = mReturnData.find(display);
    if (found == mReturnData.end()) {
        outLayers->clear();
        outTypes->clear();
        return;
    }

    ReturnData& data = found->second;

    *outLayers = std::move(data.changedLayers);
    *outTypes = std::move(data.compositionTypes);
}

void AidlCommandReader::takeDisplayRequests(Display display, uint32_t* outDisplayRequestMask,
                                            std::vector<Layer>* outLayers,
                                            std::vector<uint32_t>* outLayerRequestMasks) {
    auto found = mReturnData.find(display);
    if (found == mReturnData.end()) {
        *outDisplayRequestMask = 0;
        outLayers->clear();
        outLayerRequestMasks->clear();
        return;
    }

    ReturnData& data = found->second;

    *outDisplayRequestMask = data.displayRequests;
    *outLayers = std::move(data.requestedLayers);
    *outLayerRequestMasks = std::move(data.requestMasks);
}

void AidlCommandReader::takeReleaseFences(Display display, std::vector<Layer>* outLayers,
                                          std::vector<int>* outReleaseFences) {
    auto found = mReturnData.find(display);
    if (found == mReturnData.end()) {
        outLayers->clear();
        outReleaseFences->clear();
        return;
    }

    ReturnData& data = found->second;

    *outLayers = std::move(data.releasedLayers);
    *outReleaseFences = std::move(data.releaseFences);
}

void AidlCommandReader::takePresentFence(Display display, int* outPresentFence) {
    auto found = mReturnData.find(display);
    if (found == mReturnData.end()) {
        *outPresentFence = -1;
        return;
    }

    ReturnData& data = found->second;

    *outPresentFence = data.presentFence;
    data.presentFence = -1;
}

void AidlCommandReader::takePresentOrValidateStage(Display display, uint32_t* state) {
    auto found = mReturnData.find(display);
    if (found == mReturnData.end()) {
        *state = static_cast<uint32_t>(-1);
        return;
    }
    ReturnData& data = found->second;
    *state = data.presentOrValidateState;
}

void AidlCommandReader::takeClientTargetProperty(
        Display display, IComposerClient::ClientTargetProperty* outClientTargetProperty) {
    auto found = mReturnData.find(display);

    // If not found, return the default values.
    if (found == mReturnData.end()) {
        outClientTargetProperty->pixelFormat = PixelFormat::RGBA_8888;
        outClientTargetProperty->dataspace = Dataspace::UNKNOWN;
        return;
    }

    ReturnData& data = found->second;
    *outClientTargetProperty = data.clientTargetProperty;
}

} // namespace impl
} // namespace Hwc2
} // namespace android
