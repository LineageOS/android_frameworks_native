//
// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#include <ui/DisplayInfo.h>
#include <gui/bufferqueue/2.0/B2HGraphicBufferProducer.h>

#include "CarWindowService.h"

namespace android {
namespace frameworks {
namespace automotive {
namespace display {
namespace V1_0 {
namespace implementation {

Return<sp<IGraphicBufferProducer>>
    CarWindowService::getIGraphicBufferProducer() {
    if (mSurface == nullptr) {
        status_t err;
        mSurfaceComposerClient = new SurfaceComposerClient();

        err = mSurfaceComposerClient->initCheck();
        if (err != NO_ERROR) {
            ALOGE("SurfaceComposerClient::initCheck error: %#x", err);
            mSurfaceComposerClient = nullptr;
            return nullptr;
        }

        // Get main display parameters.
        sp<IBinder> mainDpy = SurfaceComposerClient::getInternalDisplayToken();
        if (mainDpy == nullptr) {
            ALOGE("Failed to get internal display ");
            return nullptr;
        }
        DisplayInfo mainDpyInfo;
        err = SurfaceComposerClient::getDisplayInfo(mainDpy, &mainDpyInfo);
        if (err != NO_ERROR) {
            ALOGE("Failed to get display characteristics");
            return nullptr;
        }
        unsigned int mWidth, mHeight;
        if (mainDpyInfo.orientation != ui::ROTATION_0 &&
            mainDpyInfo.orientation != ui::ROTATION_180) {
            // rotated
            mWidth = mainDpyInfo.h;
            mHeight = mainDpyInfo.w;
        } else {
            mWidth = mainDpyInfo.w;
            mHeight = mainDpyInfo.h;
        }

        mSurfaceControl = mSurfaceComposerClient->createSurface(
                String8("Automotive Display"), mWidth, mHeight,
                PIXEL_FORMAT_RGBX_8888, ISurfaceComposerClient::eOpaque);
        if (mSurfaceControl == nullptr || !mSurfaceControl->isValid()) {
            ALOGE("Failed to create SurfaceControl");
            mSurfaceComposerClient = nullptr;
            mSurfaceControl = nullptr;
            return nullptr;
        }

        // SurfaceControl::getSurface is guaranteed to be not null.
        mSurface = mSurfaceControl->getSurface();
    }

    return new ::android::hardware::graphics::bufferqueue::V2_0::utils::
                    B2HGraphicBufferProducer(
                        mSurface->getIGraphicBufferProducer());
}

Return<bool> CarWindowService::showWindow() {
    status_t status = NO_ERROR;

    if (mSurfaceControl != nullptr) {
        status = SurfaceComposerClient::Transaction{}
                         .setLayer(
                             mSurfaceControl, 0x7FFFFFFF) // always on top
                         .show(mSurfaceControl)
                         .apply();
    } else {
        ALOGE("showWindow: Failed to get a valid SurfaceControl!");
        return false;
    }

    return status == NO_ERROR;
}

Return<bool> CarWindowService::hideWindow() {
    status_t status = NO_ERROR;

    if (mSurfaceControl != nullptr) {
        status = SurfaceComposerClient::Transaction{}
                        .hide(mSurfaceControl)
                        .apply();
    } else {
        ALOGE("hideWindow: Failed to get a valid SurfaceControl!");
        return false;
    }

    return status == NO_ERROR;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace display
}  // namespace automotive
}  // namespace frameworks
}  // namespace android

