/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef ANDROID_DISPLAY_DEVICE_H
#define ANDROID_DISPLAY_DEVICE_H

#include "Transform.h"

#include <stdlib.h>
#include <unordered_map>

#include <math/mat4.h>

#include <binder/IBinder.h>
#include <gui/LayerState.h>
#include <hardware/hwcomposer_defs.h>
#include <ui/GraphicTypes.h>
#include <ui/HdrCapabilities.h>
#include <ui/Region.h>
#include <utils/RefBase.h>
#include <utils/Mutex.h>
#include <utils/String8.h>
#include <utils/Timers.h>

#include "RenderArea.h"
#include "RenderEngine/Surface.h"

#include <memory>

struct ANativeWindow;

namespace android {

struct DisplayInfo;
class DisplaySurface;
class Fence;
class IGraphicBufferProducer;
class Layer;
class SurfaceFlinger;
class HWComposer;

class DisplayDevice : public LightRefBase<DisplayDevice>
{
public:
    constexpr static float sDefaultMinLumiance = 0.0;
    constexpr static float sDefaultMaxLumiance = 500.0;

    // region in layer-stack space
    mutable Region dirtyRegion;
    // region in screen space
    Region undefinedRegion;
    bool lastCompositionHadVisibleLayers;

    enum DisplayType {
        DISPLAY_ID_INVALID = -1,
        DISPLAY_PRIMARY     = HWC_DISPLAY_PRIMARY,
        DISPLAY_EXTERNAL    = HWC_DISPLAY_EXTERNAL,
        DISPLAY_VIRTUAL     = HWC_DISPLAY_VIRTUAL,
        NUM_BUILTIN_DISPLAY_TYPES = HWC_NUM_PHYSICAL_DISPLAY_TYPES,
    };

    enum {
        NO_LAYER_STACK = 0xFFFFFFFF,
    };

    // clang-format off
    DisplayDevice(
            const sp<SurfaceFlinger>& flinger,
            DisplayType type,
            int32_t hwcId,
            bool isSecure,
            const wp<IBinder>& displayToken,
            const sp<ANativeWindow>& nativeWindow,
            const sp<DisplaySurface>& displaySurface,
            std::unique_ptr<RE::Surface> renderSurface,
            int displayWidth,
            int displayHeight,
            int displayInstallOrientation,
            bool hasWideColorGamut,
            const HdrCapabilities& hdrCapabilities,
            const int32_t supportedPerFrameMetadata,
            const std::unordered_map<ui::ColorMode, std::vector<ui::RenderIntent>>& hwcColorModes,
            int initialPowerMode);
    // clang-format on

    ~DisplayDevice();

    // whether this is a valid object. An invalid DisplayDevice is returned
    // when an non existing id is requested
    bool isValid() const;

    // isSecure indicates whether this display can be trusted to display
    // secure surfaces.
    bool isSecure() const { return mIsSecure; }

    // Flip the front and back buffers if the back buffer is "dirty".  Might
    // be instantaneous, might involve copying the frame buffer around.
    void flip() const;

    int         getWidth() const;
    int         getHeight() const;
    int         getInstallOrientation() const { return mDisplayInstallOrientation; }

    void                    setVisibleLayersSortedByZ(const Vector< sp<Layer> >& layers);
    const Vector< sp<Layer> >& getVisibleLayersSortedByZ() const;
    void                    setLayersNeedingFences(const Vector< sp<Layer> >& layers);
    const Vector< sp<Layer> >& getLayersNeedingFences() const;
    Region                  getDirtyRegion(bool repaintEverything) const;

    void                    setLayerStack(uint32_t stack);
    void                    setDisplaySize(const int newWidth, const int newHeight);
    void                    setProjection(int orientation, const Rect& viewport, const Rect& frame);

    int                     getOrientation() const { return mOrientation; }
    uint32_t                getOrientationTransform() const;
    static uint32_t         getPrimaryDisplayOrientationTransform();
    const Transform&        getTransform() const { return mGlobalTransform; }
    const Rect              getViewport() const { return mViewport; }
    const Rect              getFrame() const { return mFrame; }
    const Rect&             getScissor() const { return mScissor; }
    bool                    needsFiltering() const { return mNeedsFiltering; }

    uint32_t                getLayerStack() const { return mLayerStack; }
    int32_t                 getDisplayType() const { return mType; }
    bool                    isPrimary() const { return mType == DISPLAY_PRIMARY; }
    int32_t                 getHwcDisplayId() const { return mHwcDisplayId; }
    const wp<IBinder>&      getDisplayToken() const { return mDisplayToken; }

    int32_t getSupportedPerFrameMetadata() const { return mSupportedPerFrameMetadata; }

    // We pass in mustRecompose so we can keep VirtualDisplaySurface's state
    // machine happy without actually queueing a buffer if nothing has changed
    status_t beginFrame(bool mustRecompose) const;
    status_t prepareFrame(HWComposer& hwc);

    bool hasWideColorGamut() const { return mHasWideColorGamut; }
    // Whether h/w composer has native support for specific HDR type.
    bool hasHDR10Support() const { return mHasHdr10; }
    bool hasHLGSupport() const { return mHasHLG; }
    bool hasDolbyVisionSupport() const { return mHasDolbyVision; }

    // Return true if the HDR dataspace is supported but
    // there is no corresponding color mode.
    bool hasLegacyHdrSupport(ui::Dataspace dataspace) const;

    // The returned HdrCapabilities is the combination of HDR capabilities from
    // hardware composer and RenderEngine. When the DisplayDevice supports wide
    // color gamut, RenderEngine is able to simulate HDR support in Display P3
    // color space for both PQ and HLG HDR contents. The minimum and maximum
    // luminance will be set to sDefaultMinLumiance and sDefaultMaxLumiance
    // respectively if hardware composer doesn't return meaningful values.
    const HdrCapabilities& getHdrCapabilities() const { return mHdrCapabilities; }

    // Return true if intent is supported by the display.
    bool hasRenderIntent(ui::RenderIntent intent) const;

    void getBestColorMode(ui::Dataspace dataspace, ui::RenderIntent intent,
                          ui::Dataspace* outDataspace, ui::ColorMode* outMode,
                          ui::RenderIntent* outIntent) const;

    void swapBuffers(HWComposer& hwc) const;

    // called after h/w composer has completed its set() call
    void onSwapBuffersCompleted() const;

    Rect getBounds() const {
        return Rect(mDisplayWidth, mDisplayHeight);
    }
    inline Rect bounds() const { return getBounds(); }

    void setDisplayName(const String8& displayName);
    const String8& getDisplayName() const { return mDisplayName; }

    bool makeCurrent() const;
    void setViewportAndProjection() const;

    const sp<Fence>& getClientTargetAcquireFence() const;

    /* ------------------------------------------------------------------------
     * Display power mode management.
     */
    int getPowerMode() const;
    void setPowerMode(int mode);
    bool isDisplayOn() const;

    ui::ColorMode getActiveColorMode() const;
    void setActiveColorMode(ui::ColorMode mode);
    ui::RenderIntent getActiveRenderIntent() const;
    void setActiveRenderIntent(ui::RenderIntent renderIntent);
    android_color_transform_t getColorTransform() const;
    void setColorTransform(const mat4& transform);
    void setCompositionDataSpace(ui::Dataspace dataspace);
    ui::Dataspace getCompositionDataSpace() const;

    /* ------------------------------------------------------------------------
     * Display active config management.
     */
    int getActiveConfig() const;
    void setActiveConfig(int mode);

    // release HWC resources (if any) for removable displays
    void disconnect(HWComposer& hwc);

    /* ------------------------------------------------------------------------
     * Debugging
     */
    uint32_t getPageFlipCount() const;
    void dump(String8& result) const;

private:
    /*
     *  Constants, set during initialization
     */
    sp<SurfaceFlinger> mFlinger;
    DisplayType mType;
    int32_t mHwcDisplayId;
    wp<IBinder> mDisplayToken;

    // ANativeWindow this display is rendering into
    sp<ANativeWindow> mNativeWindow;
    sp<DisplaySurface> mDisplaySurface;

    std::unique_ptr<RE::Surface> mSurface;
    int             mDisplayWidth;
    int             mDisplayHeight;
    const int       mDisplayInstallOrientation;
    mutable uint32_t mPageFlipCount;
    String8         mDisplayName;
    bool            mIsSecure;

    /*
     * Can only accessed from the main thread, these members
     * don't need synchronization.
     */

    // list of visible layers on that display
    Vector< sp<Layer> > mVisibleLayersSortedByZ;
    // list of layers needing fences
    Vector< sp<Layer> > mLayersNeedingFences;

    /*
     * Transaction state
     */
    static status_t orientationToTransfrom(int orientation,
            int w, int h, Transform* tr);

    // The identifier of the active layer stack for this display. Several displays
    // can use the same layer stack: A z-ordered group of layers (sometimes called
    // "surfaces"). Any given layer can only be on a single layer stack.
    uint32_t mLayerStack;

    int mOrientation;
    static uint32_t sPrimaryDisplayOrientation;
    // user-provided visible area of the layer stack
    Rect mViewport;
    // user-provided rectangle where mViewport gets mapped to
    Rect mFrame;
    // pre-computed scissor to apply to the display
    Rect mScissor;
    Transform mGlobalTransform;
    bool mNeedsFiltering;
    // Current power mode
    int mPowerMode;
    // Current active config
    int mActiveConfig;
    // current active color mode
    ui::ColorMode mActiveColorMode = ui::ColorMode::NATIVE;
    // Current active render intent.
    ui::RenderIntent mActiveRenderIntent = ui::RenderIntent::COLORIMETRIC;
    ui::Dataspace mCompositionDataSpace = ui::Dataspace::UNKNOWN;
    // Current color transform
    android_color_transform_t mColorTransform;

    // Need to know if display is wide-color capable or not.
    // Initialized by SurfaceFlinger when the DisplayDevice is created.
    // Fed to RenderEngine during composition.
    bool mHasWideColorGamut;
    bool mHasHdr10;
    bool mHasHLG;
    bool mHasDolbyVision;
    HdrCapabilities mHdrCapabilities;
    const int32_t mSupportedPerFrameMetadata;

    // Mappings from desired Dataspace/RenderIntent to the supported
    // Dataspace/ColorMode/RenderIntent.
    using ColorModeKey = uint64_t;
    struct ColorModeValue {
        ui::Dataspace dataspace;
        ui::ColorMode colorMode;
        ui::RenderIntent renderIntent;
    };

    static ColorModeKey getColorModeKey(ui::Dataspace dataspace, ui::RenderIntent intent) {
        return (static_cast<uint64_t>(dataspace) << 32) | static_cast<uint32_t>(intent);
    }
    void populateColorModes(
            const std::unordered_map<ui::ColorMode, std::vector<ui::RenderIntent>>& hwcColorModes);
    void addColorMode(
            const std::unordered_map<ui::ColorMode, std::vector<ui::RenderIntent>>& hwcColorModes,
            const ui::ColorMode mode, const ui::RenderIntent intent);

    std::unordered_map<ColorModeKey, ColorModeValue> mColorModes;
};

struct DisplayDeviceState {
    DisplayDeviceState() = default;
    DisplayDeviceState(DisplayDevice::DisplayType type, bool isSecure);

    bool isValid() const { return type >= 0; }
    bool isMainDisplay() const { return type == DisplayDevice::DISPLAY_PRIMARY; }
    bool isVirtualDisplay() const { return type >= DisplayDevice::DISPLAY_VIRTUAL; }

    static std::atomic<int32_t> nextDisplayId;
    int32_t displayId = nextDisplayId++;
    DisplayDevice::DisplayType type = DisplayDevice::DISPLAY_ID_INVALID;
    sp<IGraphicBufferProducer> surface;
    uint32_t layerStack = DisplayDevice::NO_LAYER_STACK;
    Rect viewport;
    Rect frame;
    uint8_t orientation = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    String8 displayName;
    bool isSecure = false;
};

class DisplayRenderArea : public RenderArea {
public:
    DisplayRenderArea(const sp<const DisplayDevice> device,
                      Transform::orientation_flags rotation = Transform::ROT_0)
          : DisplayRenderArea(device, device->getBounds(), device->getWidth(), device->getHeight(),
                              rotation) {}
    DisplayRenderArea(const sp<const DisplayDevice> device, Rect sourceCrop, uint32_t reqWidth,
                      uint32_t reqHeight, Transform::orientation_flags rotation,
                      bool allowSecureLayers = true)
          : RenderArea(reqWidth, reqHeight, CaptureFill::OPAQUE,
                       getDisplayRotation(rotation, device->getInstallOrientation())),
            mDevice(device),
            mSourceCrop(sourceCrop),
            mAllowSecureLayers(allowSecureLayers) {}

    const Transform& getTransform() const override { return mDevice->getTransform(); }
    Rect getBounds() const override { return mDevice->getBounds(); }
    int getHeight() const override { return mDevice->getHeight(); }
    int getWidth() const override { return mDevice->getWidth(); }
    bool isSecure() const override { return mAllowSecureLayers && mDevice->isSecure(); }

    bool needsFiltering() const override {
        // check if the projection from the logical display to the physical
        // display needs filtering
        if (mDevice->needsFiltering()) {
            return true;
        }

        // check if the projection from the logical render area (i.e., the
        // physical display) to the physical render area requires filtering
        const Rect sourceCrop = getSourceCrop();
        int width = sourceCrop.width();
        int height = sourceCrop.height();
        if (getRotationFlags() & Transform::ROT_90) {
            std::swap(width, height);
        }
        return width != getReqWidth() || height != getReqHeight();
    }

    Rect getSourceCrop() const override {
        // use the projected display viewport by default.
        if (mSourceCrop.isEmpty()) {
            return mDevice->getScissor();
        }

        // Recompute the device transformation for the source crop.
        Transform rotation;
        Transform translatePhysical;
        Transform translateLogical;
        Transform scale;
        const Rect& viewport = mDevice->getViewport();
        const Rect& scissor = mDevice->getScissor();
        const Rect& frame = mDevice->getFrame();

        const int orientation = mDevice->getInstallOrientation();
        // Install orientation is transparent to the callers.  Apply it now.
        uint32_t flags = 0x00;
        switch (orientation) {
            case DisplayState::eOrientation90:
                flags = Transform::ROT_90;
                break;
            case DisplayState::eOrientation180:
                flags = Transform::ROT_180;
                break;
            case DisplayState::eOrientation270:
                flags = Transform::ROT_270;
                break;
            default:
                break;
        }
        rotation.set(flags, getWidth(), getHeight());
        translateLogical.set(-viewport.left, -viewport.top);
        translatePhysical.set(scissor.left, scissor.top);
        scale.set(frame.getWidth() / float(viewport.getWidth()), 0, 0,
                  frame.getHeight() / float(viewport.getHeight()));
        const Transform finalTransform =
                rotation * translatePhysical * scale * translateLogical;
        return finalTransform.transform(mSourceCrop);
    }

private:
    // Install orientation is transparent to the callers.  We need to cancel
    // it out by modifying rotation flags.
    static Transform::orientation_flags getDisplayRotation(
            Transform::orientation_flags rotation, int orientation) {
        if (orientation == DisplayState::eOrientationDefault) {
            return rotation;
        }

        // convert hw orientation into flag presentation
        // here inverse transform needed
        uint8_t hw_rot_90 = 0x00;
        uint8_t hw_flip_hv = 0x00;
        switch (orientation) {
            case DisplayState::eOrientation90:
                hw_rot_90 = Transform::ROT_90;
                hw_flip_hv = Transform::ROT_180;
                break;
            case DisplayState::eOrientation180:
                hw_flip_hv = Transform::ROT_180;
                break;
            case DisplayState::eOrientation270:
                hw_rot_90 = Transform::ROT_90;
                break;
        }

        // transform flags operation
        // 1) flip H V if both have ROT_90 flag
        // 2) XOR these flags
        uint8_t rotation_rot_90 = rotation & Transform::ROT_90;
        uint8_t rotation_flip_hv = rotation & Transform::ROT_180;
        if (rotation_rot_90 & hw_rot_90) {
            rotation_flip_hv = (~rotation_flip_hv) & Transform::ROT_180;
        }

        return static_cast<Transform::orientation_flags>(
                (rotation_rot_90 ^ hw_rot_90) | (rotation_flip_hv ^ hw_flip_hv));
    }

    const sp<const DisplayDevice> mDevice;
    const Rect mSourceCrop;
    const bool mAllowSecureLayers;
};

}; // namespace android

#endif // ANDROID_DISPLAY_DEVICE_H
