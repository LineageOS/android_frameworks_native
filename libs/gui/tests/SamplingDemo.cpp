/*
 * Copyright 2019 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#define LOG_TAG "SamplingTest"

#include <chrono>
#include <thread>

#include <android/gui/BnRegionSamplingListener.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <gui/ISurfaceComposer.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>
#include <private/gui/ComposerServiceAIDL.h>
#include <utils/Trace.h>

using namespace std::chrono_literals;

namespace android {

class Button : public gui::BnRegionSamplingListener {
public:
    Button(const char* name, const Rect& samplingArea) {
        sp<SurfaceComposerClient> client = new SurfaceComposerClient;

        mButton = client->createSurface(String8(name), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                        ISurfaceComposerClient::eFXSurfaceEffect);

        const int32_t width = samplingArea.getWidth();
        const int32_t height = samplingArea.getHeight();

        SurfaceComposerClient::Transaction{}
                .setLayer(mButton, 0x7fffffff)
                .setCrop(mButton, {0, 0, width - 2 * BUTTON_PADDING, height - 2 * BUTTON_PADDING})
                .setPosition(mButton, samplingArea.left + BUTTON_PADDING,
                             samplingArea.top + BUTTON_PADDING)
                .setColor(mButton, half3{1, 1, 1})
                .show(mButton)
                .apply();

        mButtonBlend = client->createSurface(String8(name) + "Blend", 0, 0, PIXEL_FORMAT_RGBA_8888,
                                             ISurfaceComposerClient::eFXSurfaceEffect);

        SurfaceComposerClient::Transaction{}
                .setLayer(mButtonBlend, 0x7ffffffe)
                .setCrop(mButtonBlend,
                         {0, 0, width - 2 * SAMPLE_AREA_PADDING, height - 2 * SAMPLE_AREA_PADDING})
                .setPosition(mButtonBlend, samplingArea.left + SAMPLE_AREA_PADDING,
                             samplingArea.top + SAMPLE_AREA_PADDING)
                .setColor(mButtonBlend, half3{1, 1, 1})
                .setAlpha(mButtonBlend, 0.2)
                .show(mButtonBlend)
                .apply(true);

        const bool HIGHLIGHT_SAMPLING_AREA = false;
        if (HIGHLIGHT_SAMPLING_AREA) {
            mSamplingArea =
                    client->createSurface(String8("SamplingArea"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                          ISurfaceComposerClient::eFXSurfaceEffect);

            SurfaceComposerClient::Transaction{}
                    .setLayer(mSamplingArea, 0x7ffffffd)
                    .setCrop(mSamplingArea, {0, 0, 100, 32})
                    .setPosition(mSamplingArea, 490, 1606)
                    .setColor(mSamplingArea, half3{0, 1, 0})
                    .setAlpha(mSamplingArea, 0.1)
                    .show(mSamplingArea)
                    .apply();
        }
    }

    sp<IBinder> getStopLayerHandle() { return mButtonBlend->getHandle(); }

private:
    static const int32_t BLEND_WIDTH = 2;
    static const int32_t SAMPLE_AREA_PADDING = 8;
    static const int32_t BUTTON_PADDING = BLEND_WIDTH + SAMPLE_AREA_PADDING;

    void setColor(float color) {
        const float complement = std::fmod(color + 0.5f, 1.0f);
        SurfaceComposerClient::Transaction{}
                .setColor(mButton, half3{complement, complement, complement})
                .setColor(mButtonBlend, half3{color, color, color})
                .apply();
    }

    binder::Status onSampleCollected(float medianLuma) override {
        ATRACE_CALL();
        setColor(medianLuma);
        return binder::Status::ok();
    }

    sp<SurfaceComposerClient> mClient;
    sp<SurfaceControl> mButton;
    sp<SurfaceControl> mButtonBlend;
    sp<SurfaceControl> mSamplingArea;
};

} // namespace android

using namespace android;

int main(int, const char**) {
    const Rect homeButtonArea{490, 1606, 590, 1654};
    sp<android::Button> homeButton = new android::Button("HomeButton", homeButtonArea);
    const Rect backButtonArea{200, 1606, 248, 1654};
    sp<android::Button> backButton = new android::Button("BackButton", backButtonArea);

    gui::ARect homeButtonAreaA;
    homeButtonAreaA.left = 490;
    homeButtonAreaA.top = 1606;
    homeButtonAreaA.right = 590;
    homeButtonAreaA.bottom = 1654;

    gui::ARect backButtonAreaA;
    backButtonAreaA.left = 200;
    backButtonAreaA.top = 1606;
    backButtonAreaA.right = 248;
    backButtonAreaA.bottom = 1654;

    sp<gui::ISurfaceComposer> composer = ComposerServiceAIDL::getComposerService();
    composer->addRegionSamplingListener(homeButtonAreaA, homeButton->getStopLayerHandle(),
                                        homeButton);
    composer->addRegionSamplingListener(backButtonAreaA, backButton->getStopLayerHandle(),
                                        backButton);

    ProcessState::self()->startThreadPool();
    IPCThreadState::self()->joinThreadPool();

    return 0;
}
