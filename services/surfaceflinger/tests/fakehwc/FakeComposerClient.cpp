/*
 * Copyright (C) 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "FakeComposer"

#include "FakeComposerClient.h"

#include <gui/SurfaceComposerClient.h>

#include <log/log.h>

#include <gtest/gtest.h>

#include <inttypes.h>
#include <time.h>
#include <algorithm>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

constexpr Config NULL_DISPLAY_CONFIG = static_cast<Config>(0);

using namespace sftest;

using android::Condition;
using android::Mutex;

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

namespace {

// Internal state of a layer in the HWC API.
class LayerImpl {
public:
    LayerImpl() = default;

    bool mValid = true;
    RenderState mRenderState;
    uint32_t mZ = 0;
};

// Struct for storing per frame rectangle state. Contains the render
// state shared to the test case. Basically a snapshot and a subset of
// LayerImpl sufficient to re-create the pixels of a layer for the
// frame.
struct FrameRect {
public:
    FrameRect(Layer layer_, const RenderState& state, uint32_t z_)
          : layer(layer_), renderState(state), z(z_) {}

    const Layer layer;
    const RenderState renderState;
    const uint32_t z;
};

// Collection of FrameRects forming one rendered frame. Could store
// related fences and other data in the future.
class Frame {
public:
    Frame() = default;
    std::vector<std::unique_ptr<FrameRect>> rectangles;
};

class DelayedEventGenerator {
public:
    explicit DelayedEventGenerator(std::function<void()> onTimerExpired)
          : mOnTimerExpired(onTimerExpired), mThread([this]() { loop(); }) {}

    ~DelayedEventGenerator() {
        ALOGI("DelayedEventGenerator exiting.");
        {
            std::unique_lock<std::mutex> lock(mMutex);
            mRunning = false;
            mWakeups.clear();
            mCondition.notify_one();
        }
        mThread.join();
        ALOGI("DelayedEventGenerator exited.");
    }

    void wakeAfter(std::chrono::nanoseconds waitTime) {
        std::unique_lock<std::mutex> lock(mMutex);
        mWakeups.insert(Clock::now() + waitTime);
        mCondition.notify_one();
    }

private:
    void loop() {
        while (true) {
            // Lock scope
            {
                std::unique_lock<std::mutex> lock(mMutex);
                mCondition.wait(lock, [this]() { return !mRunning || !mWakeups.empty(); });
                if (!mRunning && mWakeups.empty()) {
                    // This thread should only exit once the destructor has been called and all
                    // wakeups have been processed
                    return;
                }

                // At this point, mWakeups will not be empty

                TimePoint target = *(mWakeups.begin());
                auto status = mCondition.wait_until(lock, target);
                while (status == std::cv_status::no_timeout) {
                    // This was either a spurious wakeup or another wakeup was added, so grab the
                    // oldest point and wait again
                    target = *(mWakeups.begin());
                    status = mCondition.wait_until(lock, target);
                }

                // status must have been timeout, so we can finally clear this point
                mWakeups.erase(target);
            }
            // Callback *without* locks!
            mOnTimerExpired();
        }
    }

    std::function<void()> mOnTimerExpired;
    std::thread mThread;
    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mRunning = true;
    std::set<TimePoint> mWakeups;
};

} // namespace

FakeComposerClient::FakeComposerClient()
      : mEventCallback(nullptr),
        mEventCallback_2_4(nullptr),
        mCurrentConfig(NULL_DISPLAY_CONFIG),
        mVsyncEnabled(false),
        mLayers(),
        mDelayedEventGenerator(
                std::make_unique<DelayedEventGenerator>([this]() { this->requestVSync(); })),
        mSurfaceComposer(nullptr) {}

FakeComposerClient::~FakeComposerClient() {}

bool FakeComposerClient::hasCapability(hwc2_capability_t /*capability*/) {
    return false;
}

std::string FakeComposerClient::dumpDebugInfo() {
    return {};
}

void FakeComposerClient::registerEventCallback(EventCallback* callback) {
    ALOGV("registerEventCallback");
    LOG_FATAL_IF(mEventCallback_2_4 != nullptr,
                 "already registered using registerEventCallback_2_4");

    mEventCallback = callback;
    if (mEventCallback) {
        mEventCallback->onHotplug(PRIMARY_DISPLAY, IComposerCallback::Connection::CONNECTED);
    }
}

void FakeComposerClient::unregisterEventCallback() {
    ALOGV("unregisterEventCallback");
    mEventCallback = nullptr;
}

void FakeComposerClient::hotplugDisplay(Display display, IComposerCallback::Connection state) {
    if (mEventCallback) {
        mEventCallback->onHotplug(display, state);
    } else if (mEventCallback_2_4) {
        mEventCallback_2_4->onHotplug(display, state);
    }
}

void FakeComposerClient::refreshDisplay(Display display) {
    if (mEventCallback) {
        mEventCallback->onRefresh(display);
    } else if (mEventCallback_2_4) {
        mEventCallback_2_4->onRefresh(display);
    }
}

uint32_t FakeComposerClient::getMaxVirtualDisplayCount() {
    ALOGV("getMaxVirtualDisplayCount");
    return 1;
}

V2_1::Error FakeComposerClient::createVirtualDisplay(uint32_t /*width*/, uint32_t /*height*/,
                                                     V1_0::PixelFormat* /*format*/,
                                                     Display* /*outDisplay*/) {
    ALOGV("createVirtualDisplay");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::destroyVirtualDisplay(Display /*display*/) {
    ALOGV("destroyVirtualDisplay");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::createLayer(Display /*display*/, Layer* outLayer) {
    ALOGV("createLayer");
    *outLayer = mLayers.size();
    auto newLayer = std::make_unique<LayerImpl>();
    mLayers.push_back(std::move(newLayer));
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::destroyLayer(Display /*display*/, Layer layer) {
    ALOGV("destroyLayer");
    mLayers[layer]->mValid = false;
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::getActiveConfig(Display display, Config* outConfig) {
    ALOGV("getActiveConfig");
    if (mMockHal) {
        return mMockHal->getActiveConfig(display, outConfig);
    }

    // TODO Assert outConfig != nullptr

    // TODO This is my reading of the
    // IComposerClient::getActiveConfig, but returning BAD_CONFIG
    // seems to not fit SurfaceFlinger plans. See version 2 below.
    // if (mCurrentConfig == NULL_DISPLAY_CONFIG) {
    //     return V2_1::Error::BAD_CONFIG;
    // }
    //*outConfig = mCurrentConfig;
    *outConfig = 1; // Very special config for you my friend
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::getClientTargetSupport(Display /*display*/, uint32_t /*width*/,
                                                       uint32_t /*height*/,
                                                       V1_0::PixelFormat /*format*/,
                                                       V1_0::Dataspace /*dataspace*/) {
    ALOGV("getClientTargetSupport");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::getColorModes(Display /*display*/,
                                              hidl_vec<V1_0::ColorMode>* /*outModes*/) {
    ALOGV("getColorModes");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::getDisplayAttribute(Display display, Config config,
                                                    V2_1::IComposerClient::Attribute attribute,
                                                    int32_t* outValue) {
    auto tmpError =
            getDisplayAttribute_2_4(display, config,
                                    static_cast<IComposerClient::Attribute>(attribute), outValue);
    return static_cast<V2_1::Error>(tmpError);
}

V2_1::Error FakeComposerClient::getDisplayConfigs(Display display, hidl_vec<Config>* outConfigs) {
    ALOGV("getDisplayConfigs");
    if (mMockHal) {
        return mMockHal->getDisplayConfigs(display, outConfigs);
    }

    // TODO assert display == 1, outConfigs != nullptr

    outConfigs->resize(1);
    (*outConfigs)[0] = 1;

    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::getDisplayName(Display /*display*/, hidl_string* /*outName*/) {
    ALOGV("getDisplayName");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::getDisplayType(Display /*display*/,
                                               IComposerClient::DisplayType* outType) {
    ALOGV("getDisplayType");
    // TODO: This setting nothing on the output had no effect on initial trials. Is first display
    // assumed to be physical?
    *outType = static_cast<IComposerClient::DisplayType>(HWC2_DISPLAY_TYPE_PHYSICAL);
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::getDozeSupport(Display /*display*/, bool* /*outSupport*/) {
    ALOGV("getDozeSupport");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::getHdrCapabilities(Display /*display*/,
                                                   hidl_vec<V1_0::Hdr>* /*outTypes*/,
                                                   float* /*outMaxLuminance*/,
                                                   float* /*outMaxAverageLuminance*/,
                                                   float* /*outMinLuminance*/) {
    ALOGV("getHdrCapabilities");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setActiveConfig(Display display, Config config) {
    ALOGV("setActiveConfig");
    if (mMockHal) {
        return mMockHal->setActiveConfig(display, config);
    }
    mCurrentConfig = config;
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setColorMode(Display /*display*/, V1_0::ColorMode /*mode*/) {
    ALOGV("setColorMode");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setPowerMode(Display /*display*/,
                                             V2_1::IComposerClient::PowerMode /*mode*/) {
    ALOGV("setPowerMode");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setVsyncEnabled(Display /*display*/,
                                                IComposerClient::Vsync enabled) {
    mVsyncEnabled = (enabled == IComposerClient::Vsync::ENABLE);
    ALOGV("setVsyncEnabled(%s)", mVsyncEnabled ? "ENABLE" : "DISABLE");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setColorTransform(Display /*display*/, const float* /*matrix*/,
                                                  int32_t /*hint*/) {
    ALOGV("setColorTransform");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setClientTarget(Display /*display*/, buffer_handle_t /*target*/,
                                                int32_t /*acquireFence*/, int32_t /*dataspace*/,
                                                const std::vector<hwc_rect_t>& /*damage*/) {
    ALOGV("setClientTarget");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setOutputBuffer(Display /*display*/, buffer_handle_t /*buffer*/,
                                                int32_t /*releaseFence*/) {
    ALOGV("setOutputBuffer");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::validateDisplay(
        Display /*display*/, std::vector<Layer>* /*outChangedLayers*/,
        std::vector<IComposerClient::Composition>* /*outCompositionTypes*/,
        uint32_t* /*outDisplayRequestMask*/, std::vector<Layer>* /*outRequestedLayers*/,
        std::vector<uint32_t>* /*outRequestMasks*/) {
    ALOGV("validateDisplay");
    // TODO: Assume touching nothing means All Korrekt!
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::acceptDisplayChanges(Display /*display*/) {
    ALOGV("acceptDisplayChanges");
    // Didn't ask for changes because software is omnipotent.
    return V2_1::Error::NONE;
}

bool layerZOrdering(const std::unique_ptr<FrameRect>& a, const std::unique_ptr<FrameRect>& b) {
    return a->z <= b->z;
}

V2_1::Error FakeComposerClient::presentDisplay(Display /*display*/, int32_t* /*outPresentFence*/,
                                               std::vector<Layer>* /*outLayers*/,
                                               std::vector<int32_t>* /*outReleaseFences*/) {
    ALOGV("presentDisplay");
    // TODO Leaving layers and their fences out for now. Doing so
    // means that we've already processed everything. Important to
    // test that the fences are respected, though. (How?)

    std::unique_ptr<Frame> newFrame(new Frame);
    for (uint64_t layer = 0; layer < mLayers.size(); layer++) {
        const LayerImpl& layerImpl = *mLayers[layer];

        if (!layerImpl.mValid) continue;

        auto rect = std::make_unique<FrameRect>(layer, layerImpl.mRenderState, layerImpl.mZ);
        newFrame->rectangles.push_back(std::move(rect));
    }
    std::sort(newFrame->rectangles.begin(), newFrame->rectangles.end(), layerZOrdering);
    {
        Mutex::Autolock _l(mStateMutex);
        mFrames.push_back(std::move(newFrame));
        mFramesAvailable.broadcast();
    }
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerCursorPosition(Display /*display*/, Layer /*layer*/,
                                                       int32_t /*x*/, int32_t /*y*/) {
    ALOGV("setLayerCursorPosition");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerBuffer(Display /*display*/, Layer layer,
                                               buffer_handle_t buffer, int32_t acquireFence) {
    ALOGV("setLayerBuffer");
    LayerImpl& l = getLayerImpl(layer);
    if (buffer != l.mRenderState.mBuffer) {
        l.mRenderState.mSwapCount++; // TODO: Is setting to same value a swap or not?
    }
    l.mRenderState.mBuffer = buffer;
    l.mRenderState.mAcquireFence = acquireFence;

    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerSurfaceDamage(Display /*display*/, Layer /*layer*/,
                                                      const std::vector<hwc_rect_t>& /*damage*/) {
    ALOGV("setLayerSurfaceDamage");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerBlendMode(Display /*display*/, Layer layer, int32_t mode) {
    ALOGV("setLayerBlendMode");
    getLayerImpl(layer).mRenderState.mBlendMode = static_cast<hwc2_blend_mode_t>(mode);
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerColor(Display /*display*/, Layer layer,
                                              IComposerClient::Color color) {
    ALOGV("setLayerColor");
    getLayerImpl(layer).mRenderState.mLayerColor.r = color.r;
    getLayerImpl(layer).mRenderState.mLayerColor.g = color.g;
    getLayerImpl(layer).mRenderState.mLayerColor.b = color.b;
    getLayerImpl(layer).mRenderState.mLayerColor.a = color.a;
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerCompositionType(Display /*display*/, Layer /*layer*/,
                                                        int32_t /*type*/) {
    ALOGV("setLayerCompositionType");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerDataspace(Display /*display*/, Layer /*layer*/,
                                                  int32_t /*dataspace*/) {
    ALOGV("setLayerDataspace");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerDisplayFrame(Display /*display*/, Layer layer,
                                                     const hwc_rect_t& frame) {
    ALOGV("setLayerDisplayFrame (%d, %d, %d, %d)", frame.left, frame.top, frame.right,
          frame.bottom);
    getLayerImpl(layer).mRenderState.mDisplayFrame = frame;
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerPlaneAlpha(Display /*display*/, Layer layer, float alpha) {
    ALOGV("setLayerPlaneAlpha");
    getLayerImpl(layer).mRenderState.mPlaneAlpha = alpha;
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerSidebandStream(Display /*display*/, Layer /*layer*/,
                                                       buffer_handle_t /*stream*/) {
    ALOGV("setLayerSidebandStream");
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerSourceCrop(Display /*display*/, Layer layer,
                                                   const hwc_frect_t& crop) {
    ALOGV("setLayerSourceCrop");
    getLayerImpl(layer).mRenderState.mSourceCrop = crop;
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerTransform(Display /*display*/, Layer layer,
                                                  int32_t transform) {
    ALOGV("setLayerTransform");
    getLayerImpl(layer).mRenderState.mTransform = static_cast<hwc_transform_t>(transform);
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerVisibleRegion(Display /*display*/, Layer layer,
                                                      const std::vector<hwc_rect_t>& visible) {
    ALOGV("setLayerVisibleRegion");
    getLayerImpl(layer).mRenderState.mVisibleRegion = visible;
    return V2_1::Error::NONE;
}

V2_1::Error FakeComposerClient::setLayerZOrder(Display /*display*/, Layer layer, uint32_t z) {
    ALOGV("setLayerZOrder");
    getLayerImpl(layer).mZ = z;
    return V2_1::Error::NONE;
}

// Composer 2.2
V2_1::Error FakeComposerClient::getPerFrameMetadataKeys(
        Display /*display*/, std::vector<V2_2::IComposerClient::PerFrameMetadataKey>* /*outKeys*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setLayerPerFrameMetadata(
        Display /*display*/, Layer /*layer*/,
        const std::vector<V2_2::IComposerClient::PerFrameMetadata>& /*metadata*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getReadbackBufferAttributes(
        Display /*display*/, graphics::common::V1_1::PixelFormat* /*outFormat*/,
        graphics::common::V1_1::Dataspace* /*outDataspace*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setReadbackBuffer(Display /*display*/,
                                                  const native_handle_t* /*bufferHandle*/,
                                                  android::base::unique_fd /*fenceFd*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getReadbackBufferFence(Display /*display*/,
                                                       android::base::unique_fd* /*outFenceFd*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::createVirtualDisplay_2_2(
        uint32_t /*width*/, uint32_t /*height*/, graphics::common::V1_1::PixelFormat* /*format*/,
        Display* /*outDisplay*/) {
    return V2_1::Error::UNSUPPORTED;
}
V2_1::Error FakeComposerClient::getClientTargetSupport_2_2(
        Display /*display*/, uint32_t /*width*/, uint32_t /*height*/,
        graphics::common::V1_1::PixelFormat /*format*/,
        graphics::common::V1_1::Dataspace /*dataspace*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setPowerMode_2_2(Display /*display*/,
                                                 V2_2::IComposerClient::PowerMode /*mode*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setLayerFloatColor(Display /*display*/, Layer /*layer*/,
                                                   V2_2::IComposerClient::FloatColor /*color*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getColorModes_2_2(
        Display /*display*/, hidl_vec<graphics::common::V1_1::ColorMode>* /*outModes*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getRenderIntents(
        Display /*display*/, graphics::common::V1_1::ColorMode /*mode*/,
        std::vector<graphics::common::V1_1::RenderIntent>* /*outIntents*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setColorMode_2_2(Display /*display*/,
                                                 graphics::common::V1_1::ColorMode /*mode*/,
                                                 graphics::common::V1_1::RenderIntent /*intent*/) {
    return V2_1::Error::UNSUPPORTED;
}

std::array<float, 16> FakeComposerClient::getDataspaceSaturationMatrix(
        graphics::common::V1_1::Dataspace /*dataspace*/) {
    return {};
}

// Composer 2.3
V2_1::Error FakeComposerClient::getPerFrameMetadataKeys_2_3(
        Display /*display*/, std::vector<V2_3::IComposerClient::PerFrameMetadataKey>* /*outKeys*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setColorMode_2_3(Display /*display*/,
                                                 graphics::common::V1_2::ColorMode /*mode*/,
                                                 graphics::common::V1_1::RenderIntent /*intent*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getRenderIntents_2_3(
        Display /*display*/, graphics::common::V1_2::ColorMode /*mode*/,
        std::vector<graphics::common::V1_1::RenderIntent>* /*outIntents*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getColorModes_2_3(
        Display /*display*/, hidl_vec<graphics::common::V1_2::ColorMode>* /*outModes*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getClientTargetSupport_2_3(
        Display /*display*/, uint32_t /*width*/, uint32_t /*height*/,
        graphics::common::V1_2::PixelFormat /*format*/,
        graphics::common::V1_2::Dataspace /*dataspace*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getReadbackBufferAttributes_2_3(
        Display /*display*/, graphics::common::V1_2::PixelFormat* /*outFormat*/,
        graphics::common::V1_2::Dataspace* /*outDataspace*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getHdrCapabilities_2_3(
        Display /*display*/, hidl_vec<graphics::common::V1_2::Hdr>* /*outTypes*/,
        float* /*outMaxLuminance*/, float* /*outMaxAverageLuminance*/, float* /*outMinLuminance*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setLayerPerFrameMetadata_2_3(
        Display /*display*/, Layer /*layer*/,
        const std::vector<V2_3::IComposerClient::PerFrameMetadata>& /*metadata*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getDisplayIdentificationData(Display /*display*/,
                                                             uint8_t* /*outPort*/,
                                                             std::vector<uint8_t>* /*outData*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setLayerColorTransform(Display /*display*/, Layer /*layer*/,
                                                       const float* /*matrix*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getDisplayedContentSamplingAttributes(
        uint64_t /*display*/, graphics::common::V1_2::PixelFormat& /*format*/,
        graphics::common::V1_2::Dataspace& /*dataspace*/,
        hidl_bitfield<V2_3::IComposerClient::FormatColorComponent>& /*componentMask*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setDisplayedContentSamplingEnabled(
        uint64_t /*display*/, V2_3::IComposerClient::DisplayedContentSampling /*enable*/,
        hidl_bitfield<V2_3::IComposerClient::FormatColorComponent> /*componentMask*/,
        uint64_t /*maxFrames*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getDisplayedContentSample(
        uint64_t /*display*/, uint64_t /*maxFrames*/, uint64_t /*timestamp*/,
        uint64_t& /*frameCount*/, hidl_vec<uint64_t>& /*sampleComponent0*/,
        hidl_vec<uint64_t>& /*sampleComponent1*/, hidl_vec<uint64_t>& /*sampleComponent2*/,
        hidl_vec<uint64_t>& /*sampleComponent3*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getDisplayCapabilities(
        Display /*display*/,
        std::vector<V2_3::IComposerClient::DisplayCapability>* /*outCapabilities*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setLayerPerFrameMetadataBlobs(
        Display /*display*/, Layer /*layer*/,
        std::vector<V2_3::IComposerClient::PerFrameMetadataBlob>& /*blobs*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::getDisplayBrightnessSupport(Display /*display*/,
                                                            bool* /*outSupport*/) {
    return V2_1::Error::UNSUPPORTED;
}

V2_1::Error FakeComposerClient::setDisplayBrightness(Display /*display*/, float /*brightness*/) {
    return V2_1::Error::UNSUPPORTED;
}

// Composer 2.4
void FakeComposerClient::registerEventCallback_2_4(EventCallback_2_4* callback) {
    ALOGV("registerEventCallback_2_4");
    LOG_FATAL_IF(mEventCallback != nullptr, "already registered using registerEventCallback");

    mEventCallback_2_4 = callback;
    if (mEventCallback_2_4) {
        mEventCallback_2_4->onHotplug(PRIMARY_DISPLAY, IComposerCallback::Connection::CONNECTED);
    }
}

void FakeComposerClient::unregisterEventCallback_2_4() {
    ALOGV("unregisterEventCallback_2_4");
    mEventCallback_2_4 = nullptr;
}

V2_4::Error FakeComposerClient::getDisplayCapabilities_2_4(
        Display /*display*/,
        std::vector<V2_4::IComposerClient::DisplayCapability>* /*outCapabilities*/) {
    return V2_4::Error::UNSUPPORTED;
}

V2_4::Error FakeComposerClient::getDisplayConnectionType(
        Display /*display*/, V2_4::IComposerClient::DisplayConnectionType* /*outType*/) {
    return V2_4::Error::UNSUPPORTED;
}

V2_4::Error FakeComposerClient::getDisplayAttribute_2_4(Display display, Config config,
                                                        IComposerClient::Attribute attribute,
                                                        int32_t* outValue) {
    ALOGV("getDisplayAttribute (%d, %d, %d, %p)", static_cast<int>(display),
          static_cast<int>(config), static_cast<int>(attribute), outValue);
    if (mMockHal) {
        return mMockHal->getDisplayAttribute_2_4(display, config, attribute, outValue);
    }

    // TODO: SOOO much fun to be had with these alone
    switch (attribute) {
        case IComposerClient::Attribute::WIDTH:
            *outValue = 1920;
            break;
        case IComposerClient::Attribute::HEIGHT:
            *outValue = 1080;
            break;
        case IComposerClient::Attribute::VSYNC_PERIOD:
            *outValue = 1666666666;
            break; // TOOD: Tests break down if lowered to 16ms?
        case IComposerClient::Attribute::DPI_X:
            *outValue = 240;
            break;
        case IComposerClient::Attribute::DPI_Y:
            *outValue = 240;
            break;
        default:
            LOG_ALWAYS_FATAL("Say what!?! New attribute");
    }

    return Error::NONE;
}

V2_4::Error FakeComposerClient::getDisplayVsyncPeriod(Display display,
                                                      V2_4::VsyncPeriodNanos* outVsyncPeriod) {
    ALOGV("getDisplayVsyncPeriod");
    if (mMockHal) {
        return mMockHal->getDisplayVsyncPeriod(display, outVsyncPeriod);
    }

    return V2_4::Error::UNSUPPORTED;
}

V2_4::Error FakeComposerClient::setActiveConfigWithConstraints(
        Display display, Config config,
        const V2_4::IComposerClient::VsyncPeriodChangeConstraints& vsyncPeriodChangeConstraints,
        VsyncPeriodChangeTimeline* timeline) {
    ALOGV("setActiveConfigWithConstraints");
    if (mMockHal) {
        return mMockHal->setActiveConfigWithConstraints(display, config,
                                                        vsyncPeriodChangeConstraints, timeline);
    }
    return V2_4::Error::UNSUPPORTED;
}

V2_4::Error FakeComposerClient::setAutoLowLatencyMode(Display, bool) {
    ALOGV("setAutoLowLatencyMode");
    return V2_4::Error::UNSUPPORTED;
}

V2_4::Error FakeComposerClient::getSupportedContentTypes(
        Display, std::vector<IComposerClient::ContentType>*) {
    ALOGV("getSupportedContentTypes");
    return V2_4::Error::UNSUPPORTED;
}

V2_4::Error FakeComposerClient::setContentType(Display, IComposerClient::ContentType) {
    ALOGV("setContentType");
    return V2_4::Error::UNSUPPORTED;
}

V2_4::Error FakeComposerClient::validateDisplay_2_4(
        Display /*display*/, std::vector<Layer>* /*outChangedLayers*/,
        std::vector<IComposerClient::Composition>* /*outCompositionTypes*/,
        uint32_t* /*outDisplayRequestMask*/, std::vector<Layer>* /*outRequestedLayers*/,
        std::vector<uint32_t>* /*outRequestMasks*/,
        IComposerClient::ClientTargetProperty* /*outClientTargetProperty*/) {
    return V2_4::Error::NONE;
}

V2_4::Error FakeComposerClient::setLayerGenericMetadata(Display, Layer, const std::string&, bool,
                                                        const std::vector<uint8_t>&) {
    ALOGV("setLayerGenericMetadata");
    return V2_4::Error::UNSUPPORTED;
}

V2_4::Error FakeComposerClient::getLayerGenericMetadataKeys(
        std::vector<IComposerClient::LayerGenericMetadataKey>*) {
    ALOGV("getLayerGenericMetadataKeys");
    return V2_4::Error::UNSUPPORTED;
}

//////////////////////////////////////////////////////////////////

void FakeComposerClient::requestVSync(uint64_t vsyncTime) {
    if (mEventCallback || mEventCallback_2_4) {
        uint64_t timestamp = vsyncTime;
        ALOGV("Vsync");
        if (timestamp == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            timestamp = ts.tv_sec * 1000 * 1000 * 1000 + ts.tv_nsec;
        }
        if (mSurfaceComposer != nullptr) {
            mSurfaceComposer->injectVSync(timestamp);
        } else if (mEventCallback) {
            mEventCallback->onVsync(PRIMARY_DISPLAY, timestamp);
        } else {
            mEventCallback_2_4->onVsync_2_4(PRIMARY_DISPLAY, timestamp, 16'666'666);
        }
    }
}

void FakeComposerClient::runVSyncAfter(std::chrono::nanoseconds wait) {
    mDelayedEventGenerator->wakeAfter(wait);
}

LayerImpl& FakeComposerClient::getLayerImpl(Layer handle) {
    // TODO Change these to an internal state check that can be
    // invoked from the gtest? GTest macros do not seem all that safe
    // when used outside the test class
    EXPECT_GE(handle, static_cast<Layer>(0));
    EXPECT_LT(handle, mLayers.size());
    return *(mLayers[handle]);
}

int FakeComposerClient::getFrameCount() const {
    return mFrames.size();
}

static std::vector<RenderState> extractRenderState(
        const std::vector<std::unique_ptr<FrameRect>>& internalRects) {
    std::vector<RenderState> result;
    result.reserve(internalRects.size());
    for (const std::unique_ptr<FrameRect>& rect : internalRects) {
        result.push_back(rect->renderState);
    }
    return result;
}

std::vector<RenderState> FakeComposerClient::getFrameRects(int frame) const {
    Mutex::Autolock _l(mStateMutex);
    return extractRenderState(mFrames[frame]->rectangles);
}

std::vector<RenderState> FakeComposerClient::getLatestFrame() const {
    Mutex::Autolock _l(mStateMutex);
    return extractRenderState(mFrames[mFrames.size() - 1]->rectangles);
}

void FakeComposerClient::runVSyncAndWait(std::chrono::nanoseconds maxWait) {
    int currentFrame = 0;
    {
        Mutex::Autolock _l(mStateMutex); // I hope this is ok...
        currentFrame = static_cast<int>(mFrames.size());
        requestVSync();
    }
    waitUntilFrame(currentFrame + 1, maxWait);
}

void FakeComposerClient::waitUntilFrame(int targetFrame, std::chrono::nanoseconds maxWait) const {
    Mutex::Autolock _l(mStateMutex);
    while (mFrames.size() < static_cast<size_t>(targetFrame)) {
        android::status_t result = mFramesAvailable.waitRelative(mStateMutex, maxWait.count());
        if (result == android::TIMED_OUT) {
            ALOGE("Waiting for frame %d (at frame %zu now) timed out after %lld ns", targetFrame,
                  mFrames.size(), maxWait.count());
            return;
        }
    }
}

void FakeComposerClient::clearFrames() {
    Mutex::Autolock _l(mStateMutex);
    mFrames.clear();
    for (const std::unique_ptr<LayerImpl>& layer : mLayers) {
        if (layer->mValid) {
            layer->mRenderState.mSwapCount = 0;
        }
    }
}

void FakeComposerClient::onSurfaceFlingerStart() {
    mSurfaceComposer = nullptr;
    do {
        mSurfaceComposer = new android::SurfaceComposerClient;
        android::status_t initResult = mSurfaceComposer->initCheck();
        if (initResult != android::NO_ERROR) {
            ALOGD("Init result: %d", initResult);
            mSurfaceComposer = nullptr;
            std::this_thread::sleep_for(10ms);
        }
    } while (mSurfaceComposer == nullptr);
    ALOGD("SurfaceComposerClient created");
    mSurfaceComposer->enableVSyncInjections(true);
}

void FakeComposerClient::onSurfaceFlingerStop() {
    mSurfaceComposer->dispose();
    mSurfaceComposer.clear();
}

// Includes destroyed layers, stored in order of creation.
int FakeComposerClient::getLayerCount() const {
    return mLayers.size();
}

Layer FakeComposerClient::getLayer(size_t index) const {
    // NOTE: If/when passing calls through to actual implementation,
    // this might get more involving.
    return static_cast<Layer>(index);
}

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
