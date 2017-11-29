#pragma once

#include "Transform.h"

namespace android {

class RenderArea {
public:
    RenderArea(uint32_t reqHeight, uint32_t reqWidth,
               ISurfaceComposer::Rotation rotation = ISurfaceComposer::eRotateNone)
          : mReqHeight(reqHeight), mReqWidth(reqWidth) {
        mRotationFlags = Transform::fromRotation(rotation);
    }

    virtual ~RenderArea() = default;

    virtual const Transform& getTransform() const = 0;
    virtual Rect getBounds() const = 0;
    virtual int getHeight() const = 0;
    virtual int getWidth() const = 0;
    virtual bool isSecure() const = 0;
    virtual bool needsFiltering() const = 0;
    virtual Rect getSourceCrop() const = 0;

    int getReqHeight() const { return mReqHeight; };
    int getReqWidth() const { return mReqWidth; };
    Transform::orientation_flags getRotationFlags() const { return mRotationFlags; };
    virtual bool getWideColorSupport() const = 0;
    virtual android_color_mode_t getActiveColorMode() const = 0;

    status_t updateDimensions();

private:
    uint32_t mReqHeight;
    uint32_t mReqWidth;
    Transform::orientation_flags mRotationFlags;
};

} // namespace android
