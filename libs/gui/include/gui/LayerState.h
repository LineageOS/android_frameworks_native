/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef ANDROID_SF_LAYER_STATE_H
#define ANDROID_SF_LAYER_STATE_H

#include <stdint.h>
#include <sys/types.h>

#include <android/native_window.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ITransactionCompletedListener.h>
#include <math/mat4.h>

#include <android/gui/DropInputMode.h>
#ifndef NO_INPUT
#include <input/InputWindow.h>
#endif

#include <gui/LayerMetadata.h>
#include <math/vec3.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/Rotation.h>
#include <ui/Transform.h>
#include <utils/Errors.h>

namespace android {

class Parcel;
class ISurfaceComposerClient;

struct client_cache_t {
    wp<IBinder> token = nullptr;
    uint64_t id;

    bool operator==(const client_cache_t& other) const { return id == other.id; }

    bool isValid() const { return token != nullptr; }
};

/*
 * Used to communicate layer information between SurfaceFlinger and its clients.
 */
struct layer_state_t {
    enum {
        eLayerHidden = 0x01, // SURFACE_HIDDEN in SurfaceControl.java
        eLayerOpaque = 0x02, // SURFACE_OPAQUE
        eLayerSecure = 0x80, // SECURE
    };

    enum {
        ePositionChanged = 0x00000001,
        eLayerChanged = 0x00000002,
        eSizeChanged = 0x00000004,
        eAlphaChanged = 0x00000008,
        eMatrixChanged = 0x00000010,
        eTransparentRegionChanged = 0x00000020,
        eFlagsChanged = 0x00000040,
        eLayerStackChanged = 0x00000080,
        eCropChanged_legacy = 0x00000100,
        eDeferTransaction_legacy = 0x00000200,
        eOverrideScalingModeChanged = 0x00000400,
        eShadowRadiusChanged = 0x00000800,
        eReparentChildren = 0x00001000,
        eDetachChildren = 0x00002000,
        eRelativeLayerChanged = 0x00004000,
        eReparent = 0x00008000,
        eColorChanged = 0x00010000,
        eDestroySurface = 0x00020000,
        eTransformChanged = 0x00040000,
        eTransformToDisplayInverseChanged = 0x00080000,
        eCropChanged = 0x00100000,
        eBufferChanged = 0x00200000,
        eAcquireFenceChanged = 0x00400000,
        eDataspaceChanged = 0x00800000,
        eHdrMetadataChanged = 0x01000000,
        eSurfaceDamageRegionChanged = 0x02000000,
        eApiChanged = 0x04000000,
        eSidebandStreamChanged = 0x08000000,
        eColorTransformChanged = 0x10000000,
        eHasListenerCallbacksChanged = 0x20000000,
        eInputInfoChanged = 0x40000000,
        eCornerRadiusChanged = 0x80000000,
        eFrameChanged = 0x1'00000000,
        eCachedBufferChanged = 0x2'00000000,
        eBackgroundColorChanged = 0x4'00000000,
        eMetadataChanged = 0x8'00000000,
        eColorSpaceAgnosticChanged = 0x10'00000000,
        eFrameRateSelectionPriority = 0x20'00000000,
        eFrameRateChanged = 0x40'00000000,
        eBackgroundBlurRadiusChanged = 0x80'00000000,
        eProducerDisconnect = 0x100'00000000,
        eFixedTransformHintChanged = 0x200'00000000,
        eTrustedOverlayChanged = 0x400'00000000,
        eDropInputModeChanged = 0x8000'00000000,
    };

    layer_state_t()
          : what(0),
            x(0),
            y(0),
            z(0),
            w(0),
            h(0),
            layerStack(0),
            alpha(0),
            flags(0),
            mask(0),
            reserved(0),
            crop_legacy(Rect::INVALID_RECT),
            cornerRadius(0.0f),
            backgroundBlurRadius(0),
            frameNumber_legacy(0),
            overrideScalingMode(-1),
            transform(0),
            transformToDisplayInverse(false),
            crop(Rect::INVALID_RECT),
            frame(Rect::INVALID_RECT),
            dataspace(ui::Dataspace::UNKNOWN),
            surfaceDamageRegion(),
            api(-1),
            colorTransform(mat4()),
            bgColorAlpha(0),
            bgColorDataspace(ui::Dataspace::UNKNOWN),
            colorSpaceAgnostic(false),
            shadowRadius(0.0f),
            frameRateSelectionPriority(-1),
            frameRate(0.0f),
            frameRateCompatibility(ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT),
            fixedTransformHint(ui::Transform::ROT_INVALID),
            isTrustedOverlay(false),
            dropInputMode(gui::DropInputMode::NONE) {
        matrix.dsdx = matrix.dtdy = 1.0f;
        matrix.dsdy = matrix.dtdx = 0.0f;
        hdrMetadata.validTypes = 0;
    }

    void merge(const layer_state_t& other);
    status_t write(Parcel& output) const;
    status_t read(const Parcel& input);

    struct matrix22_t {
        float dsdx{0};
        float dtdx{0};
        float dtdy{0};
        float dsdy{0};
    };
    sp<IBinder> surface;
    uint64_t what;
    float x;
    float y;
    int32_t z;
    uint32_t w;
    uint32_t h;
    uint32_t layerStack;
    float alpha;
    uint8_t flags;
    uint8_t mask;
    uint8_t reserved;
    matrix22_t matrix;
    Rect crop_legacy;
    float cornerRadius;
    uint32_t backgroundBlurRadius;
    sp<IBinder> barrierHandle_legacy;
    sp<IBinder> reparentHandle;
    uint64_t frameNumber_legacy;
    int32_t overrideScalingMode;

    sp<IGraphicBufferProducer> barrierGbp_legacy;

    sp<IBinder> relativeLayerHandle;

    sp<IBinder> parentHandleForChild;

    half3 color;

    // non POD must be last. see write/read
    Region transparentRegion;

    uint32_t transform;
    bool transformToDisplayInverse;
    Rect crop;
    Rect frame;
    sp<GraphicBuffer> buffer;
    sp<Fence> acquireFence;
    ui::Dataspace dataspace;
    HdrMetadata hdrMetadata;
    Region surfaceDamageRegion;
    int32_t api;
    sp<NativeHandle> sidebandStream;
    mat4 colorTransform;

#ifndef NO_INPUT
    InputWindowInfo inputInfo;
#endif

    client_cache_t cachedBuffer;

    LayerMetadata metadata;

    // The following refer to the alpha, and dataspace, respectively of
    // the background color layer
    float bgColorAlpha;
    ui::Dataspace bgColorDataspace;

    // A color space agnostic layer means the color of this layer can be
    // interpreted in any color space.
    bool colorSpaceAgnostic;

    std::vector<ListenerCallbacks> listeners;

    // Draws a shadow around the surface.
    float shadowRadius;

    // Priority of the layer assigned by Window Manager.
    int32_t frameRateSelectionPriority;

    // Layer frame rate and compatibility. See ANativeWindow_setFrameRate().
    float frameRate;
    int8_t frameRateCompatibility;

    // Set by window manager indicating the layer and all its children are
    // in a different orientation than the display. The hint suggests that
    // the graphic producers should receive a transform hint as if the
    // display was in this orientation. When the display changes to match
    // the layer orientation, the graphic producer may not need to allocate
    // a buffer of a different size. -1 means the transform hint is not set,
    // otherwise the value will be a valid ui::Rotation.
    ui::Transform::RotationFlags fixedTransformHint;

    // An inherited state that indicates that this surface control and its children
    // should be trusted for input occlusion detection purposes
    bool isTrustedOverlay;

    // Force inputflinger to drop all input events for the layer and its children.
    gui::DropInputMode dropInputMode;
};

struct ComposerState {
    layer_state_t state;
    status_t write(Parcel& output) const;
    status_t read(const Parcel& input);
};

struct DisplayState {
    enum {
        eSurfaceChanged = 0x01,
        eLayerStackChanged = 0x02,
        eDisplayProjectionChanged = 0x04,
        eDisplaySizeChanged = 0x08
    };

    DisplayState();
    void merge(const DisplayState& other);

    uint32_t what;
    sp<IBinder> token;
    sp<IGraphicBufferProducer> surface;
    uint32_t layerStack;

    // These states define how layers are projected onto the physical display.
    //
    // Layers are first clipped to `viewport'.  They are then translated and
    // scaled from `viewport' to `frame'.  Finally, they are rotated according
    // to `orientation', `width', and `height'.
    //
    // For example, assume viewport is Rect(0, 0, 200, 100), frame is Rect(20,
    // 10, 420, 210), and the size of the display is WxH.  When orientation is
    // 0, layers will be scaled by a factor of 2 and translated by (20, 10).
    // When orientation is 1, layers will be additionally rotated by 90
    // degrees around the origin clockwise and translated by (W, 0).
    ui::Rotation orientation = ui::ROTATION_0;
    Rect viewport;
    Rect frame;

    uint32_t width, height;

    status_t write(Parcel& output) const;
    status_t read(const Parcel& input);
};

struct InputWindowCommands {
    bool syncInputWindows{false};

    void merge(const InputWindowCommands& other);
    void clear();
    void write(Parcel& output) const;
    void read(const Parcel& input);
};

static inline int compare_type(const ComposerState& lhs, const ComposerState& rhs) {
    if (lhs.state.surface < rhs.state.surface) return -1;
    if (lhs.state.surface > rhs.state.surface) return 1;
    return 0;
}

static inline int compare_type(const DisplayState& lhs, const DisplayState& rhs) {
    return compare_type(lhs.token, rhs.token);
}

// Returns true if the frameRate and compatibility are valid values, false
// othwerise. If either of the params are invalid, an error log is printed, and
// functionName is added to the log to indicate which function call failed.
// functionName can be null.
bool ValidateFrameRate(float frameRate, int8_t compatibility, const char* functionName);

}; // namespace android

#endif // ANDROID_SF_LAYER_STATE_H
