#pragma once

#include <gui/ISurfaceComposer.h>
#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

#include <functional>

namespace android {

class RenderArea {

public:
    enum class CaptureFill {CLEAR, OPAQUE};

    static float getCaptureFillValue(CaptureFill captureFill);

    RenderArea(uint32_t reqHeight, uint32_t reqWidth, CaptureFill captureFill,
               ISurfaceComposer::Rotation rotation = ISurfaceComposer::eRotateNone);

    virtual ~RenderArea() = default;

    virtual const ui::Transform& getTransform() const = 0;
    virtual Rect getBounds() const = 0;
    virtual int getHeight() const = 0;
    virtual int getWidth() const = 0;
    virtual bool isSecure() const = 0;
    virtual bool needsFiltering() const = 0;
    virtual Rect getSourceCrop() const = 0;

    virtual void render(std::function<void()> drawLayers) { drawLayers(); }

    int getReqHeight() const { return mReqHeight; };
    int getReqWidth() const { return mReqWidth; };
    ui::Transform::orientation_flags getRotationFlags() const { return mRotationFlags; };
    status_t updateDimensions(int displayRotation);

    CaptureFill getCaptureFill() const { return mCaptureFill; };

private:
    uint32_t mReqHeight;
    uint32_t mReqWidth;
    ui::Transform::orientation_flags mRotationFlags;
    CaptureFill mCaptureFill;
};

} // namespace android
