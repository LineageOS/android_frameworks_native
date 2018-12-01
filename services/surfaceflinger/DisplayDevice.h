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

#include <stdlib.h>

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include <android/native_window.h>
#include <binder/IBinder.h>
#include <gui/LayerState.h>
#include <hardware/hwcomposer_defs.h>
#include <math/mat4.h>
#include <renderengine/RenderEngine.h>
#include <system/window.h>
#include <ui/GraphicTypes.h>
#include <ui/HdrCapabilities.h>
#include <ui/Region.h>
#include <ui/Transform.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include "DisplayHardware/DisplayIdentification.h"
#include "RenderArea.h"

namespace android {

class DisplaySurface;
class Fence;
class HWComposer;
class IGraphicBufferProducer;
class Layer;
class SurfaceFlinger;

struct CompositionInfo;
struct DisplayDeviceCreationArgs;
struct DisplayInfo;

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

    enum {
        NO_LAYER_STACK = 0xFFFFFFFF,
    };

    explicit DisplayDevice(DisplayDeviceCreationArgs&& args);
    ~DisplayDevice();

    bool isVirtual() const { return mIsVirtual; }
    bool isPrimary() const { return mIsPrimary; }

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
    const ui::Transform&   getTransform() const { return mGlobalTransform; }
    const Rect              getViewport() const { return mViewport; }
    const Rect              getFrame() const { return mFrame; }
    const Rect&             getScissor() const { return mScissor; }
    bool                    needsFiltering() const { return mNeedsFiltering; }

    uint32_t                getLayerStack() const { return mLayerStack; }

    const std::optional<DisplayId>& getId() const { return mId; }
    const wp<IBinder>& getDisplayToken() const { return mDisplayToken; }

    int32_t getSupportedPerFrameMetadata() const { return mSupportedPerFrameMetadata; }

    // We pass in mustRecompose so we can keep VirtualDisplaySurface's state
    // machine happy without actually queueing a buffer if nothing has changed
    status_t beginFrame(bool mustRecompose) const;
    status_t prepareFrame(HWComposer& hwc, std::vector<CompositionInfo>& compositionInfo);

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

    void setProtected(bool useProtected);
    // Queues the drawn buffer for consumption by HWC.
    void queueBuffer(HWComposer& hwc);
    // Allocates a buffer as scratch space for GPU composition
    sp<GraphicBuffer> dequeueBuffer();

    // called after h/w composer has completed its set() call
    void onPresentDisplayCompleted();

    Rect getBounds() const {
        return Rect(mDisplayWidth, mDisplayHeight);
    }
    inline Rect bounds() const { return getBounds(); }

    void setDisplayName(const std::string& displayName);
    const std::string& getDisplayName() const { return mDisplayName; }

    // Acquires a new buffer for GPU composition.
    void readyNewBuffer();
    // Marks the current buffer has finished, so that it can be presented and
    // swapped out.
    void finishBuffer();
    void setViewportAndProjection() const;

    const sp<Fence>& getClientTargetAcquireFence() const;

    /* ------------------------------------------------------------------------
     * Display power mode management.
     */
    int getPowerMode() const;
    void setPowerMode(int mode);
    bool isPoweredOn() const;

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
    std::string getDebugName() const;
    void dump(std::string& result) const;

private:
    const sp<SurfaceFlinger> mFlinger;
    const wp<IBinder> mDisplayToken;

    std::optional<DisplayId> mId;

    // ANativeWindow this display is rendering into
    sp<ANativeWindow> mNativeWindow;
    // Current buffer that this display can render to.
    sp<GraphicBuffer> mGraphicBuffer;
    sp<DisplaySurface> mDisplaySurface;
    // File descriptor indicating that mGraphicBuffer is ready for display, i.e.
    // that drawing to the buffer is now complete.
    base::unique_fd mBufferReady;

    int             mDisplayWidth;
    int             mDisplayHeight;
    const int       mDisplayInstallOrientation;
    mutable uint32_t mPageFlipCount;
    std::string     mDisplayName;

    const bool mIsVirtual;
    const bool mIsSecure;

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
                                           int w, int h, ui::Transform* tr);

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
    ui::Transform mGlobalTransform;
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

    // TODO(b/74619554): Remove special cases for primary display.
    const bool mIsPrimary;
};

struct DisplayDeviceState {
    bool isVirtual() const { return !displayId.has_value(); }

    int32_t sequenceId = sNextSequenceId++;
    std::optional<DisplayId> displayId;
    sp<IGraphicBufferProducer> surface;
    uint32_t layerStack = DisplayDevice::NO_LAYER_STACK;
    Rect viewport;
    Rect frame;
    uint8_t orientation = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    std::string displayName;
    bool isSecure = false;

private:
    static std::atomic<int32_t> sNextSequenceId;
};

struct DisplayDeviceCreationArgs {
    // We use a constructor to ensure some of the values are set, without
    // assuming a default value.
    DisplayDeviceCreationArgs(const sp<SurfaceFlinger>& flinger, const wp<IBinder>& displayToken,
                              const std::optional<DisplayId>& displayId);

    const sp<SurfaceFlinger> flinger;
    const wp<IBinder> displayToken;
    const std::optional<DisplayId> displayId;

    bool isVirtual{false};
    bool isSecure{false};
    sp<ANativeWindow> nativeWindow;
    sp<DisplaySurface> displaySurface;
    int displayInstallOrientation{DisplayState::eOrientationDefault};
    bool hasWideColorGamut{false};
    HdrCapabilities hdrCapabilities;
    int32_t supportedPerFrameMetadata{0};
    std::unordered_map<ui::ColorMode, std::vector<ui::RenderIntent>> hwcColorModes;
    int initialPowerMode{HWC_POWER_MODE_NORMAL};
    bool isPrimary{false};
};

class DisplayRenderArea : public RenderArea {
public:
    DisplayRenderArea(const sp<const DisplayDevice> device,
                      ui::Transform::orientation_flags rotation = ui::Transform::ROT_0)
          : DisplayRenderArea(device, device->getBounds(), device->getWidth(), device->getHeight(),
                              device->getCompositionDataSpace(), rotation) {}
    DisplayRenderArea(const sp<const DisplayDevice> device, Rect sourceCrop, uint32_t reqWidth,
                      uint32_t reqHeight, ui::Dataspace reqDataSpace,
                      ui::Transform::orientation_flags rotation)
          : RenderArea(reqWidth, reqHeight, CaptureFill::OPAQUE, reqDataSpace,
                       getDisplayRotation(rotation, device->getInstallOrientation())),
            mDevice(device),
            mSourceCrop(sourceCrop) {}

    const ui::Transform& getTransform() const override { return mDevice->getTransform(); }
    Rect getBounds() const override { return mDevice->getBounds(); }
    int getHeight() const override { return mDevice->getHeight(); }
    int getWidth() const override { return mDevice->getWidth(); }
    bool isSecure() const override { return mDevice->isSecure(); }

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
        if (getRotationFlags() & ui::Transform::ROT_90) {
            std::swap(width, height);
        }
        return width != getReqWidth() || height != getReqHeight();
    }

    Rect getSourceCrop() const override {
        // use the (projected) logical display viewport by default
        if (mSourceCrop.isEmpty()) {
            return mDevice->getScissor();
        }

        const int orientation = mDevice->getInstallOrientation();
        if (orientation == DisplayState::eOrientationDefault) {
            return mSourceCrop;
        }

        // Install orientation is transparent to the callers.  Apply it now.
        uint32_t flags = 0x00;
        switch (orientation) {
            case DisplayState::eOrientation90:
                flags = ui::Transform::ROT_90;
                break;
            case DisplayState::eOrientation180:
                flags = ui::Transform::ROT_180;
                break;
            case DisplayState::eOrientation270:
                flags = ui::Transform::ROT_270;
                break;
        }
        ui::Transform tr;
        tr.set(flags, getWidth(), getHeight());
        return tr.transform(mSourceCrop);
    }

private:
    // Install orientation is transparent to the callers.  We need to cancel
    // it out by modifying rotation flags.
    static ui::Transform::orientation_flags getDisplayRotation(
            ui::Transform::orientation_flags rotation, int orientation) {
        if (orientation == DisplayState::eOrientationDefault) {
            return rotation;
        }

        // convert hw orientation into flag presentation
        // here inverse transform needed
        uint8_t hw_rot_90 = 0x00;
        uint8_t hw_flip_hv = 0x00;
        switch (orientation) {
            case DisplayState::eOrientation90:
                hw_rot_90 = ui::Transform::ROT_90;
                hw_flip_hv = ui::Transform::ROT_180;
                break;
            case DisplayState::eOrientation180:
                hw_flip_hv = ui::Transform::ROT_180;
                break;
            case DisplayState::eOrientation270:
                hw_rot_90 = ui::Transform::ROT_90;
                break;
        }

        // transform flags operation
        // 1) flip H V if both have ROT_90 flag
        // 2) XOR these flags
        uint8_t rotation_rot_90 = rotation & ui::Transform::ROT_90;
        uint8_t rotation_flip_hv = rotation & ui::Transform::ROT_180;
        if (rotation_rot_90 & hw_rot_90) {
            rotation_flip_hv = (~rotation_flip_hv) & ui::Transform::ROT_180;
        }

        return static_cast<ui::Transform::orientation_flags>(
                (rotation_rot_90 ^ hw_rot_90) | (rotation_flip_hv ^ hw_flip_hv));
    }

    const sp<const DisplayDevice> mDevice;
    const Rect mSourceCrop;
};

}; // namespace android

#endif // ANDROID_DISPLAY_DEVICE_H
