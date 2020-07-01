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
namespace {

RenderArea::RotationFlags applyDeviceOrientation(RenderArea::RotationFlags rotation,
                                                 const DisplayDevice& display) {
    uint32_t inverseRotate90 = 0;
    uint32_t inverseReflect = 0;

    // Reverse the logical orientation.
    ui::Rotation logicalOrientation = display.getOrientation();
    if (logicalOrientation == ui::Rotation::Rotation90) {
        logicalOrientation = ui::Rotation::Rotation270;
    } else if (logicalOrientation == ui::Rotation::Rotation270) {
        logicalOrientation = ui::Rotation::Rotation90;
    }

    const ui::Rotation orientation = display.getPhysicalOrientation() + logicalOrientation;

    switch (orientation) {
        case ui::ROTATION_0:
            return rotation;

        case ui::ROTATION_90:
            inverseRotate90 = ui::Transform::ROT_90;
            inverseReflect = ui::Transform::ROT_180;
            break;

        case ui::ROTATION_180:
            inverseReflect = ui::Transform::ROT_180;
            break;

        case ui::ROTATION_270:
            inverseRotate90 = ui::Transform::ROT_90;
            break;
    }

    const uint32_t rotate90 = rotation & ui::Transform::ROT_90;
    uint32_t reflect = rotation & ui::Transform::ROT_180;

    // Apply reflection for double rotation.
    if (rotate90 & inverseRotate90) {
        reflect = ~reflect & ui::Transform::ROT_180;
    }

    return static_cast<RenderArea::RotationFlags>((rotate90 ^ inverseRotate90) |
                                                  (reflect ^ inverseReflect));
}

} // namespace

std::unique_ptr<RenderArea> DisplayRenderArea::create(wp<const DisplayDevice> displayWeak,
                                                      const Rect& sourceCrop, ui::Size reqSize,
                                                      ui::Dataspace reqDataSpace,
                                                      RotationFlags rotation,
                                                      bool allowSecureLayers) {
    if (auto display = displayWeak.promote()) {
        // Using new to access a private constructor.
        return std::unique_ptr<DisplayRenderArea>(
                new DisplayRenderArea(std::move(display), sourceCrop, reqSize, reqDataSpace,
                                      rotation, allowSecureLayers));
    }
    return nullptr;
}

DisplayRenderArea::DisplayRenderArea(sp<const DisplayDevice> display, const Rect& sourceCrop,
                                     ui::Size reqSize, ui::Dataspace reqDataSpace,
                                     RotationFlags rotation, bool allowSecureLayers)
      : RenderArea(reqSize, CaptureFill::OPAQUE, reqDataSpace, display->getViewport(),
                   applyDeviceOrientation(rotation, *display)),
        mDisplay(std::move(display)),
        mSourceCrop(sourceCrop),
        mAllowSecureLayers(allowSecureLayers) {}

const ui::Transform& DisplayRenderArea::getTransform() const {
    return mTransform;
}

Rect DisplayRenderArea::getBounds() const {
    return mDisplay->getBounds();
}

int DisplayRenderArea::getHeight() const {
    return mDisplay->getHeight();
}

int DisplayRenderArea::getWidth() const {
    return mDisplay->getWidth();
}

bool DisplayRenderArea::isSecure() const {
    return mAllowSecureLayers && mDisplay->isSecure();
}

sp<const DisplayDevice> DisplayRenderArea::getDisplayDevice() const {
    return mDisplay;
}

bool DisplayRenderArea::needsFiltering() const {
    // check if the projection from the logical render area
    // to the physical render area requires filtering
    const Rect& sourceCrop = getSourceCrop();
    int width = sourceCrop.width();
    int height = sourceCrop.height();
    if (getRotationFlags() & ui::Transform::ROT_90) {
        std::swap(width, height);
    }
    return width != getReqWidth() || height != getReqHeight();
}

Rect DisplayRenderArea::getSourceCrop() const {
    // use the projected display viewport by default.
    if (mSourceCrop.isEmpty()) {
        return mDisplay->getSourceClip();
    }

    // If there is a source crop provided then it is assumed that the device
    // was in portrait orientation. This may not logically be true, so
    // correct for the orientation error by undoing the rotation

    ui::Rotation logicalOrientation = mDisplay->getOrientation();
    if (logicalOrientation == ui::Rotation::Rotation90) {
        logicalOrientation = ui::Rotation::Rotation270;
    } else if (logicalOrientation == ui::Rotation::Rotation270) {
        logicalOrientation = ui::Rotation::Rotation90;
    }

    const auto flags = ui::Transform::toRotationFlags(logicalOrientation);
    int width = mDisplay->getSourceClip().getWidth();
    int height = mDisplay->getSourceClip().getHeight();
    ui::Transform rotation;
    rotation.set(flags, width, height);
    return rotation.transform(mSourceCrop);
}

} // namespace android