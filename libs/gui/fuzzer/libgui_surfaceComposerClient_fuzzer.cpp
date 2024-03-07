/*
 * Copyright 2022 The Android Open Source Project
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
#include <aidl/android/hardware/power/Boost.h>
#include <fuzzbinder/libbinder_driver.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <libgui_fuzzer_utils.h>
#include "android-base/stringprintf.h"

using namespace android;

constexpr int32_t kRandomStringMaxBytes = 256;

constexpr ui::ColorMode kColormodes[] = {ui::ColorMode::NATIVE,
                                         ui::ColorMode::STANDARD_BT601_625,
                                         ui::ColorMode::STANDARD_BT601_625_UNADJUSTED,
                                         ui::ColorMode::STANDARD_BT601_525,
                                         ui::ColorMode::STANDARD_BT601_525_UNADJUSTED,
                                         ui::ColorMode::STANDARD_BT709,
                                         ui::ColorMode::DCI_P3,
                                         ui::ColorMode::SRGB,
                                         ui::ColorMode::ADOBE_RGB,
                                         ui::ColorMode::DISPLAY_P3,
                                         ui::ColorMode::BT2020,
                                         ui::ColorMode::BT2100_PQ,
                                         ui::ColorMode::BT2100_HLG,
                                         ui::ColorMode::DISPLAY_BT2020};

constexpr aidl::android::hardware::power::Boost kBoost[] = {
        aidl::android::hardware::power::Boost::INTERACTION,
        aidl::android::hardware::power::Boost::DISPLAY_UPDATE_IMMINENT,
        aidl::android::hardware::power::Boost::ML_ACC,
        aidl::android::hardware::power::Boost::AUDIO_LAUNCH,
        aidl::android::hardware::power::Boost::CAMERA_LAUNCH,
        aidl::android::hardware::power::Boost::CAMERA_SHOT,
};

constexpr gui::TouchOcclusionMode kMode[] = {
        gui::TouchOcclusionMode::BLOCK_UNTRUSTED,
        gui::TouchOcclusionMode::USE_OPACITY,
        gui::TouchOcclusionMode::ALLOW,
};

constexpr gui::WindowInfo::Flag kFlags[] = {
        gui::WindowInfo::Flag::ALLOW_LOCK_WHILE_SCREEN_ON,
        gui::WindowInfo::Flag::DIM_BEHIND,
        gui::WindowInfo::Flag::BLUR_BEHIND,
        gui::WindowInfo::Flag::NOT_FOCUSABLE,
        gui::WindowInfo::Flag::NOT_TOUCHABLE,
        gui::WindowInfo::Flag::NOT_TOUCH_MODAL,
        gui::WindowInfo::Flag::TOUCHABLE_WHEN_WAKING,
        gui::WindowInfo::Flag::KEEP_SCREEN_ON,
        gui::WindowInfo::Flag::LAYOUT_IN_SCREEN,
        gui::WindowInfo::Flag::LAYOUT_NO_LIMITS,
        gui::WindowInfo::Flag::FULLSCREEN,
        gui::WindowInfo::Flag::FORCE_NOT_FULLSCREEN,
        gui::WindowInfo::Flag::DITHER,
        gui::WindowInfo::Flag::SECURE,
        gui::WindowInfo::Flag::SCALED,
        gui::WindowInfo::Flag::IGNORE_CHEEK_PRESSES,
        gui::WindowInfo::Flag::LAYOUT_INSET_DECOR,
        gui::WindowInfo::Flag::ALT_FOCUSABLE_IM,
        gui::WindowInfo::Flag::WATCH_OUTSIDE_TOUCH,
        gui::WindowInfo::Flag::SHOW_WHEN_LOCKED,
        gui::WindowInfo::Flag::SHOW_WALLPAPER,
        gui::WindowInfo::Flag::TURN_SCREEN_ON,
        gui::WindowInfo::Flag::DISMISS_KEYGUARD,
        gui::WindowInfo::Flag::SPLIT_TOUCH,
        gui::WindowInfo::Flag::HARDWARE_ACCELERATED,
        gui::WindowInfo::Flag::LAYOUT_IN_OVERSCAN,
        gui::WindowInfo::Flag::TRANSLUCENT_STATUS,
        gui::WindowInfo::Flag::TRANSLUCENT_NAVIGATION,
        gui::WindowInfo::Flag::LOCAL_FOCUS_MODE,
        gui::WindowInfo::Flag::SLIPPERY,
        gui::WindowInfo::Flag::LAYOUT_ATTACHED_IN_DECOR,
        gui::WindowInfo::Flag::DRAWS_SYSTEM_BAR_BACKGROUNDS,
};

constexpr gui::WindowInfo::Type kType[] = {
        gui::WindowInfo::Type::UNKNOWN,
        gui::WindowInfo::Type::FIRST_APPLICATION_WINDOW,
        gui::WindowInfo::Type::BASE_APPLICATION,
        gui::WindowInfo::Type::APPLICATION,
        gui::WindowInfo::Type::APPLICATION_STARTING,
        gui::WindowInfo::Type::LAST_APPLICATION_WINDOW,
        gui::WindowInfo::Type::FIRST_SUB_WINDOW,
        gui::WindowInfo::Type::APPLICATION_PANEL,
        gui::WindowInfo::Type::APPLICATION_MEDIA,
        gui::WindowInfo::Type::APPLICATION_SUB_PANEL,
        gui::WindowInfo::Type::APPLICATION_ATTACHED_DIALOG,
        gui::WindowInfo::Type::APPLICATION_MEDIA_OVERLAY,
};

constexpr gui::WindowInfo::InputConfig kFeatures[] = {
        gui::WindowInfo::InputConfig::NO_INPUT_CHANNEL,
        gui::WindowInfo::InputConfig::DISABLE_USER_ACTIVITY,
        gui::WindowInfo::InputConfig::DROP_INPUT,
        gui::WindowInfo::InputConfig::DROP_INPUT_IF_OBSCURED,
        gui::WindowInfo::InputConfig::SPY,
        gui::WindowInfo::InputConfig::INTERCEPTS_STYLUS,
};

class SurfaceComposerClientFuzzer {
public:
    SurfaceComposerClientFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

private:
    void invokeSurfaceComposerClient();
    void invokeSurfaceComposerClientBinder();
    void invokeSurfaceComposerTransaction();
    void getWindowInfo(gui::WindowInfo*);
    sp<SurfaceControl> makeSurfaceControl();
    BlurRegion getBlurRegion();
    void fuzzOnPullAtom();
    gui::DisplayModeSpecs getDisplayModeSpecs();

    FuzzedDataProvider mFdp;
};

gui::DisplayModeSpecs SurfaceComposerClientFuzzer::getDisplayModeSpecs() {
    const auto getRefreshRateRange = [&] {
        gui::DisplayModeSpecs::RefreshRateRanges::RefreshRateRange range;
        range.min = mFdp.ConsumeFloatingPoint<float>();
        range.max = mFdp.ConsumeFloatingPoint<float>();
        return range;
    };

    const auto getRefreshRateRanges = [&] {
        gui::DisplayModeSpecs::RefreshRateRanges ranges;
        ranges.physical = getRefreshRateRange();
        ranges.render = getRefreshRateRange();
        return ranges;
    };

    String8 displayName((mFdp.ConsumeRandomLengthString(kRandomStringMaxBytes)).c_str());
    sp<IBinder> displayToken =
            SurfaceComposerClient::createDisplay(displayName, mFdp.ConsumeBool() /*secure*/);
    gui::DisplayModeSpecs specs;
    specs.defaultMode = mFdp.ConsumeIntegral<int32_t>();
    specs.allowGroupSwitching = mFdp.ConsumeBool();
    specs.primaryRanges = getRefreshRateRanges();
    specs.appRequestRanges = getRefreshRateRanges();
    return specs;
}

BlurRegion SurfaceComposerClientFuzzer::getBlurRegion() {
    int32_t left = mFdp.ConsumeIntegral<int32_t>();
    int32_t right = mFdp.ConsumeIntegral<int32_t>();
    int32_t top = mFdp.ConsumeIntegral<int32_t>();
    int32_t bottom = mFdp.ConsumeIntegral<int32_t>();
    uint32_t blurRadius = mFdp.ConsumeIntegral<uint32_t>();
    float alpha = mFdp.ConsumeFloatingPoint<float>();
    float cornerRadiusTL = mFdp.ConsumeFloatingPoint<float>();
    float cornerRadiusTR = mFdp.ConsumeFloatingPoint<float>();
    float cornerRadiusBL = mFdp.ConsumeFloatingPoint<float>();
    float cornerRadiusBR = mFdp.ConsumeFloatingPoint<float>();
    return BlurRegion{blurRadius,     cornerRadiusTL, cornerRadiusTR, cornerRadiusBL,
                      cornerRadiusBR, alpha,          left,           top,
                      right,          bottom};
}

void SurfaceComposerClientFuzzer::getWindowInfo(gui::WindowInfo* windowInfo) {
    windowInfo->id = mFdp.ConsumeIntegral<int32_t>();
    windowInfo->name = mFdp.ConsumeRandomLengthString(kRandomStringMaxBytes);
    windowInfo->layoutParamsFlags = mFdp.PickValueInArray(kFlags);
    windowInfo->layoutParamsType = mFdp.PickValueInArray(kType);
    windowInfo->frame = Rect(mFdp.ConsumeIntegral<int32_t>(), mFdp.ConsumeIntegral<int32_t>(),
                             mFdp.ConsumeIntegral<int32_t>(), mFdp.ConsumeIntegral<int32_t>());
    windowInfo->surfaceInset = mFdp.ConsumeIntegral<int32_t>();
    windowInfo->alpha = mFdp.ConsumeFloatingPointInRange<float>(0, 1);
    ui::Transform transform(mFdp.PickValueInArray(kOrientation));
    windowInfo->transform = transform;
    windowInfo->touchableRegion = Region(getRect(&mFdp));
    windowInfo->replaceTouchableRegionWithCrop = mFdp.ConsumeBool();
    windowInfo->touchOcclusionMode = mFdp.PickValueInArray(kMode);
    windowInfo->ownerPid = gui::Pid{mFdp.ConsumeIntegral<pid_t>()};
    windowInfo->ownerUid = gui::Uid{mFdp.ConsumeIntegral<uid_t>()};
    windowInfo->packageName = mFdp.ConsumeRandomLengthString(kRandomStringMaxBytes);
    windowInfo->inputConfig = mFdp.PickValueInArray(kFeatures);
}

sp<SurfaceControl> SurfaceComposerClientFuzzer::makeSurfaceControl() {
    sp<IBinder> handle;
    const sp<FakeBnSurfaceComposerClient> testClient(new FakeBnSurfaceComposerClient());
    sp<SurfaceComposerClient> client = new SurfaceComposerClient(testClient);
    sp<BnGraphicBufferProducer> producer;
    uint32_t width = mFdp.ConsumeIntegral<uint32_t>();
    uint32_t height = mFdp.ConsumeIntegral<uint32_t>();
    uint32_t transformHint = mFdp.ConsumeIntegral<uint32_t>();
    uint32_t flags = mFdp.ConsumeIntegral<uint32_t>();
    int32_t format = mFdp.ConsumeIntegral<int32_t>();
    int32_t layerId = mFdp.ConsumeIntegral<int32_t>();
    std::string layerName = base::StringPrintf("#%d", layerId);
    return new SurfaceControl(client, handle, layerId, layerName, width, height, format,
                              transformHint, flags);
}

void SurfaceComposerClientFuzzer::invokeSurfaceComposerTransaction() {
    sp<SurfaceControl> surface = makeSurfaceControl();

    SurfaceComposerClient::Transaction transaction;
    int32_t layer = mFdp.ConsumeIntegral<int32_t>();
    transaction.setLayer(surface, layer);

    sp<SurfaceControl> relativeSurface = makeSurfaceControl();
    transaction.setRelativeLayer(surface, relativeSurface, layer);

    Region transparentRegion(getRect(&mFdp));
    transaction.setTransparentRegionHint(surface, transparentRegion);
    transaction.setAlpha(surface, mFdp.ConsumeFloatingPoint<float>());

    transaction.setCornerRadius(surface, mFdp.ConsumeFloatingPoint<float>());
    transaction.setBackgroundBlurRadius(surface, mFdp.ConsumeFloatingPoint<float>());
    std::vector<BlurRegion> regions;
    uint32_t vectorSize = mFdp.ConsumeIntegralInRange<uint32_t>(0, 100);
    regions.resize(vectorSize);
    for (size_t idx = 0; idx < vectorSize; ++idx) {
        regions.push_back(getBlurRegion());
    }
    transaction.setBlurRegions(surface, regions);

    transaction.setLayerStack(surface, {mFdp.ConsumeIntegral<uint32_t>()});
    half3 color = {mFdp.ConsumeIntegral<uint32_t>(), mFdp.ConsumeIntegral<uint32_t>(),
                   mFdp.ConsumeIntegral<uint32_t>()};
    transaction.setColor(surface, color);
    transaction.setBackgroundColor(surface, color, mFdp.ConsumeFloatingPoint<float>(),
                                   mFdp.PickValueInArray(kDataspaces));

    transaction.setApi(surface, mFdp.ConsumeIntegral<int32_t>());
    transaction.setFrameRateSelectionPriority(surface, mFdp.ConsumeIntegral<int32_t>());
    transaction.setColorSpaceAgnostic(surface, mFdp.ConsumeBool() /*agnostic*/);

    gui::WindowInfo windowInfo;
    getWindowInfo(&windowInfo);
    transaction.setInputWindowInfo(surface, windowInfo);
    Parcel windowParcel;
    windowInfo.writeToParcel(&windowParcel);
    windowParcel.setDataPosition(0);
    windowInfo.readFromParcel(&windowParcel);

    windowInfo.addTouchableRegion(getRect(&mFdp));
    int32_t pointX = mFdp.ConsumeIntegral<int32_t>();
    int32_t pointY = mFdp.ConsumeIntegral<int32_t>();
    windowInfo.touchableRegionContainsPoint(pointX, pointY);
    windowInfo.frameContainsPoint(pointX, pointY);

    Parcel transactionParcel;
    transaction.writeToParcel(&transactionParcel);
    transactionParcel.setDataPosition(0);
    transaction.readFromParcel(&transactionParcel);
    SurfaceComposerClient::Transaction::createFromParcel(&transactionParcel);
}

void SurfaceComposerClientFuzzer::fuzzOnPullAtom() {
    std::string outData;
    bool success;
    SurfaceComposerClient::onPullAtom(mFdp.ConsumeIntegral<int32_t>(), &outData, &success);
}

void SurfaceComposerClientFuzzer::invokeSurfaceComposerClient() {
    String8 displayName((mFdp.ConsumeRandomLengthString(kRandomStringMaxBytes)).c_str());
    sp<IBinder> displayToken =
            SurfaceComposerClient::createDisplay(displayName, mFdp.ConsumeBool() /*secure*/);
    SurfaceComposerClient::setDesiredDisplayModeSpecs(displayToken, getDisplayModeSpecs());

    ui::ColorMode colorMode = mFdp.PickValueInArray(kColormodes);
    SurfaceComposerClient::setActiveColorMode(displayToken, colorMode);
    SurfaceComposerClient::setAutoLowLatencyMode(displayToken, mFdp.ConsumeBool() /*on*/);
    SurfaceComposerClient::setGameContentType(displayToken, mFdp.ConsumeBool() /*on*/);
    SurfaceComposerClient::setDisplayPowerMode(displayToken, mFdp.ConsumeIntegral<int32_t>());
    SurfaceComposerClient::doUncacheBufferTransaction(mFdp.ConsumeIntegral<uint64_t>());

    SurfaceComposerClient::setDisplayBrightness(displayToken, getBrightness(&mFdp));
    aidl::android::hardware::power::Boost boostId = mFdp.PickValueInArray(kBoost);
    SurfaceComposerClient::notifyPowerBoost((int32_t)boostId);

    String8 surfaceName((mFdp.ConsumeRandomLengthString(kRandomStringMaxBytes)).c_str());
    sp<BBinder> handle(new BBinder());
    sp<BnGraphicBufferProducer> producer;
    sp<Surface> surfaceParent(
            new Surface(producer, mFdp.ConsumeBool() /*controlledByApp*/, handle));

    fuzzOnPullAtom();
    SurfaceComposerClient::setDisplayContentSamplingEnabled(displayToken,
                                                            mFdp.ConsumeBool() /*enable*/,
                                                            mFdp.ConsumeIntegral<uint8_t>(),
                                                            mFdp.ConsumeIntegral<uint64_t>());

    sp<IBinder> stopLayerHandle;
    sp<gui::IRegionSamplingListener> listener = sp<gui::IRegionSamplingListenerDefault>::make();
    sp<gui::IRegionSamplingListenerDelegator> sampleListener =
            new gui::IRegionSamplingListenerDelegator(listener);
    SurfaceComposerClient::addRegionSamplingListener(getRect(&mFdp), stopLayerHandle,
                                                     sampleListener);
    sp<gui::IFpsListenerDefault> fpsListener;
    SurfaceComposerClient::addFpsListener(mFdp.ConsumeIntegral<int32_t>(), fpsListener);
}

void SurfaceComposerClientFuzzer::invokeSurfaceComposerClientBinder() {
    sp<FakeBnSurfaceComposerClient> client(new FakeBnSurfaceComposerClient());
    fuzzService(client.get(), std::move(mFdp));
}

void SurfaceComposerClientFuzzer::process() {
    invokeSurfaceComposerClient();
    invokeSurfaceComposerTransaction();
    invokeSurfaceComposerClientBinder();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    SurfaceComposerClientFuzzer surfaceComposerClientFuzzer(data, size);
    surfaceComposerClientFuzzer.process();
    return 0;
}
