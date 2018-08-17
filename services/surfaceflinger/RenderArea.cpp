#include "RenderArea.h"

#include <gui/LayerState.h>

namespace android {

ui::Transform::orientation_flags fromRotation(ISurfaceComposer::Rotation rotation) {
    switch (rotation) {
        case ISurfaceComposer::eRotateNone:
            return ui::Transform::ROT_0;
        case ISurfaceComposer::eRotate90:
            return ui::Transform::ROT_90;
        case ISurfaceComposer::eRotate180:
            return ui::Transform::ROT_180;
        case ISurfaceComposer::eRotate270:
            return ui::Transform::ROT_270;
    }
    ALOGE("Invalid rotation passed to captureScreen(): %d\n", rotation);
    return ui::Transform::ROT_0;
}

RenderArea::RenderArea(uint32_t reqHeight, uint32_t reqWidth, CaptureFill captureFill,
                       ISurfaceComposer::Rotation rotation)
      : mReqHeight(reqHeight), mReqWidth(reqWidth), mCaptureFill(captureFill) {
    mRotationFlags = fromRotation(rotation);
}

float RenderArea::getCaptureFillValue(CaptureFill captureFill) {
    switch(captureFill) {
        case CaptureFill::CLEAR:
            return 0.0f;
        case CaptureFill::OPAQUE:
        default:
            return 1.0f;
    }
}
/*
 * Checks that the requested width and height are valid and updates them to the render area
 * dimensions if they are set to 0
 */
status_t RenderArea::updateDimensions(int displayRotation) {
    // get screen geometry

    uint32_t width = getWidth();
    uint32_t height = getHeight();

    if (mRotationFlags & ui::Transform::ROT_90) {
        std::swap(width, height);
    }

    if (displayRotation & DisplayState::eOrientationSwapMask) {
        std::swap(width, height);
    }

    if ((mReqWidth > width) || (mReqHeight > height)) {
        ALOGE("size mismatch (%d, %d) > (%d, %d)", mReqWidth, mReqHeight, width, height);
        return BAD_VALUE;
    }

    if (mReqWidth == 0) {
        mReqWidth = width;
    }
    if (mReqHeight == 0) {
        mReqHeight = height;
    }

    return NO_ERROR;
}

} // namespace android
