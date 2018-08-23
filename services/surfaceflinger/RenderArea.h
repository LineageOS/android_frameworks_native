#pragma once

#include <ui/GraphicTypes.h>

#include "Transform.h"

#include <functional>

namespace android {

// RenderArea describes a rectangular area that layers can be rendered to.
//
// There is a logical render area and a physical render area.  When a layer is
// rendered to the render area, it is first transformed and clipped to the logical
// render area.  The transformed and clipped layer is then projected onto the
// physical render area.
class RenderArea {
public:
    enum class CaptureFill {CLEAR, OPAQUE};

    static float getCaptureFillValue(CaptureFill captureFill);

    RenderArea(uint32_t reqHeight, uint32_t reqWidth, CaptureFill captureFill,
               ISurfaceComposer::Rotation rotation = ISurfaceComposer::eRotateNone)
          : mReqHeight(reqHeight), mReqWidth(reqWidth), mCaptureFill(captureFill) {
        mRotationFlags = Transform::fromRotation(rotation);
    }

    virtual ~RenderArea() = default;

    // Invoke drawLayers to render layers into the render area.
    virtual void render(std::function<void()> drawLayers) { drawLayers(); }

    // Returns true if the render area is secure.  A secure layer should be
    // blacked out / skipped when rendered to an insecure render area.
    virtual bool isSecure() const = 0;

    // Returns true if the otherwise disabled layer filtering should be
    // enabled when rendering to this render area.
    virtual bool needsFiltering() const = 0;

    // Returns the transform to be applied on layers to transform them into
    // the logical render area.
    virtual const Transform& getTransform() const = 0;

    // Returns the size of the logical render area.  Layers are clipped to the
    // logical render area.
    virtual int getWidth() const = 0;
    virtual int getHeight() const = 0;
    virtual Rect getBounds() const = 0;

    // Returns the source crop of the render area.  The source crop defines
    // how layers are projected from the logical render area onto the physical
    // render area.  It can be larger than the logical render area.  It can
    // also be optionally rotated.
    //
    // Layers are first clipped to the source crop (in addition to being
    // clipped to the logical render area already).  The source crop and the
    // layers are then rotated around the center of the source crop, and
    // scaled to the physical render area linearly.
    virtual Rect getSourceCrop() const = 0;

    // Returns the rotation of the source crop and the layers.
    Transform::orientation_flags getRotationFlags() const { return mRotationFlags; };

    // Returns the size of the physical render area.
    int getReqWidth() const { return mReqWidth; };
    int getReqHeight() const { return mReqHeight; };

    // Returns the fill color of the physical render area.  Regions not
    // covered by any rendered layer should be filled with this color.
    CaptureFill getCaptureFill() const { return mCaptureFill; };

    status_t updateDimensions(int displayRotation);

private:
    uint32_t mReqHeight;
    uint32_t mReqWidth;
    Transform::orientation_flags mRotationFlags;
    CaptureFill mCaptureFill;
};

} // namespace android
