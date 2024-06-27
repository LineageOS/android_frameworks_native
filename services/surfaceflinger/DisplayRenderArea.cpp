/*
 * Copyright 2020 The Android Open Source Project
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

#include "DisplayRenderArea.h"
#include "DisplayDevice.h"

namespace android {

std::unique_ptr<RenderArea> DisplayRenderArea::create(wp<const DisplayDevice> displayWeak,
                                                      const Rect& sourceCrop, ui::Size reqSize,
                                                      ui::Dataspace reqDataSpace,
                                                      ftl::Flags<Options> options) {
    if (auto display = displayWeak.promote()) {
        // Using new to access a private constructor.
        return std::unique_ptr<DisplayRenderArea>(new DisplayRenderArea(std::move(display),
                                                                        sourceCrop, reqSize,
                                                                        reqDataSpace, options));
    }
    return nullptr;
}

DisplayRenderArea::DisplayRenderArea(sp<const DisplayDevice> display, const Rect& sourceCrop,
                                     ui::Size reqSize, ui::Dataspace reqDataSpace,
                                     ftl::Flags<Options> options)
      : RenderArea(reqSize, CaptureFill::OPAQUE, reqDataSpace, options),
        mDisplay(std::move(display)),
        mSourceCrop(sourceCrop) {}

const ui::Transform& DisplayRenderArea::getTransform() const {
    return mTransform;
}

bool DisplayRenderArea::isSecure() const {
    return mOptions.test(Options::CAPTURE_SECURE_LAYERS) && mDisplay->isSecure();
}

sp<const DisplayDevice> DisplayRenderArea::getDisplayDevice() const {
    return mDisplay;
}

Rect DisplayRenderArea::getSourceCrop() const {
    // use the projected display viewport by default.
    if (mSourceCrop.isEmpty()) {
        return mDisplay->getLayerStackSpaceRect();
    }
    return mSourceCrop;
}

} // namespace android
