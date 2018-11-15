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

#ifndef ANDROID_GUI_SURFACE_COMPOSER_CLIENT_H
#define ANDROID_GUI_SURFACE_COMPOSER_CLIENT_H

#include <stdint.h>
#include <sys/types.h>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include <binder/IBinder.h>

#include <utils/RefBase.h>
#include <utils/Singleton.h>
#include <utils/SortedVector.h>
#include <utils/threads.h>

#include <ui/FrameStats.h>
#include <ui/GraphicTypes.h>
#include <ui/PixelFormat.h>

#include <gui/CpuConsumer.h>
#include <gui/ITransactionCompletedListener.h>
#include <gui/LayerState.h>
#include <gui/SurfaceControl.h>
#include <math/vec3.h>

namespace android {

// ---------------------------------------------------------------------------

struct DisplayInfo;
class HdrCapabilities;
class ISurfaceComposerClient;
class IGraphicBufferProducer;
class Region;

// ---------------------------------------------------------------------------

using TransactionCompletedCallbackTakesContext =
        std::function<void(void* /*context*/, const TransactionStats&)>;
using TransactionCompletedCallback = std::function<void(const TransactionStats&)>;

class TransactionCompletedListener : public BnTransactionCompletedListener {
    TransactionCompletedListener();

    CallbackId getNextIdLocked() REQUIRES(mMutex);

    std::mutex mMutex;

    bool mListening GUARDED_BY(mMutex) = false;

    CallbackId mCallbackIdCounter GUARDED_BY(mMutex) = 1;

    std::map<CallbackId, TransactionCompletedCallback> mCallbacks GUARDED_BY(mMutex);

public:
    static sp<TransactionCompletedListener> getInstance();
    static sp<ITransactionCompletedListener> getIInstance();

    void startListeningLocked() REQUIRES(mMutex);

    CallbackId addCallback(const TransactionCompletedCallback& callback);

    // Overrides BnTransactionCompletedListener's onTransactionCompleted
    void onTransactionCompleted(ListenerStats stats) override;
};

// ---------------------------------------------------------------------------

class SurfaceComposerClient : public RefBase
{
    friend class Composer;
public:
                SurfaceComposerClient();
                SurfaceComposerClient(const sp<ISurfaceComposerClient>& client);
                SurfaceComposerClient(const sp<IGraphicBufferProducer>& parent);
    virtual     ~SurfaceComposerClient();

    // Always make sure we could initialize
    status_t    initCheck() const;

    // Return the connection of this client
    sp<IBinder> connection() const;

    // Forcibly remove connection before all references have gone away.
    void        dispose();

    // callback when the composer is dies
    status_t linkToComposerDeath(const sp<IBinder::DeathRecipient>& recipient,
            void* cookie = nullptr, uint32_t flags = 0);

    // Get a list of supported configurations for a given display
    static status_t getDisplayConfigs(const sp<IBinder>& display,
            Vector<DisplayInfo>* configs);

    // Get the DisplayInfo for the currently-active configuration
    static status_t getDisplayInfo(const sp<IBinder>& display,
            DisplayInfo* info);

    // Get the index of the current active configuration (relative to the list
    // returned by getDisplayInfo)
    static int getActiveConfig(const sp<IBinder>& display);

    // Set a new active configuration using an index relative to the list
    // returned by getDisplayInfo
    static status_t setActiveConfig(const sp<IBinder>& display, int id);

    // Gets the list of supported color modes for the given display
    static status_t getDisplayColorModes(const sp<IBinder>& display,
            Vector<ui::ColorMode>* outColorModes);

    // Gets the active color mode for the given display
    static ui::ColorMode getActiveColorMode(const sp<IBinder>& display);

    // Sets the active color mode for the given display
    static status_t setActiveColorMode(const sp<IBinder>& display,
            ui::ColorMode colorMode);

    /* Triggers screen on/off or low power mode and waits for it to complete */
    static void setDisplayPowerMode(const sp<IBinder>& display, int mode);

    /* Returns the composition preference of the default data space and default pixel format,
     * as well as the wide color gamut data space and wide color gamut pixel format.
     * If the wide color gamut data space is V0_SRGB, then it implies that the platform
     * has no wide color gamut support.
     */
    static status_t getCompositionPreference(ui::Dataspace* defaultDataspace,
                                             ui::PixelFormat* defaultPixelFormat,
                                             ui::Dataspace* wideColorGamutDataspace,
                                             ui::PixelFormat* wideColorGamutPixelFormat);

    // ------------------------------------------------------------------------
    // surface creation / destruction

    //! Create a surface
    sp<SurfaceControl> createSurface(
            const String8& name,// name of the surface
            uint32_t w,         // width in pixel
            uint32_t h,         // height in pixel
            PixelFormat format, // pixel-format desired
            uint32_t flags = 0, // usage flags
            SurfaceControl* parent = nullptr, // parent
            int32_t windowType = -1, // from WindowManager.java (STATUS_BAR, INPUT_METHOD, etc.)
            int32_t ownerUid = -1 // UID of the task
    );

    status_t createSurfaceChecked(
            const String8& name,// name of the surface
            uint32_t w,         // width in pixel
            uint32_t h,         // height in pixel
            PixelFormat format, // pixel-format desired
            sp<SurfaceControl>* outSurface,
            uint32_t flags = 0, // usage flags
            SurfaceControl* parent = nullptr, // parent
            int32_t windowType = -1, // from WindowManager.java (STATUS_BAR, INPUT_METHOD, etc.)
            int32_t ownerUid = -1 // UID of the task
    );

    //! Create a virtual display
    static sp<IBinder> createDisplay(const String8& displayName, bool secure);

    //! Destroy a virtual display
    static void destroyDisplay(const sp<IBinder>& display);

    //! Get the token for the existing default displays.
    //! Possible values for id are eDisplayIdMain and eDisplayIdHdmi.
    static sp<IBinder> getBuiltInDisplay(int32_t id);

    static status_t enableVSyncInjections(bool enable);

    static status_t injectVSync(nsecs_t when);

    struct SCHash {
        std::size_t operator()(const sp<SurfaceControl>& sc) const {
            return std::hash<SurfaceControl *>{}(sc.get());
        }
    };

    struct TCLHash {
        std::size_t operator()(const sp<ITransactionCompletedListener>& tcl) const {
            return std::hash<IBinder*>{}((tcl) ? IInterface::asBinder(tcl).get() : nullptr);
        }
    };

    struct CallbackInfo {
        // All the callbacks that have been requested for a TransactionCompletedListener in the
        // Transaction
        std::unordered_set<CallbackId> callbackIds;
        // All the SurfaceControls that have been modified in this TransactionCompletedListener's
        // process that require a callback if there is one or more callbackIds set.
        std::unordered_set<sp<SurfaceControl>, SCHash> surfaceControls;
    };

    class Transaction {
        std::unordered_map<sp<SurfaceControl>, ComposerState, SCHash> mComposerStates;
        SortedVector<DisplayState > mDisplayStates;
        std::unordered_map<sp<ITransactionCompletedListener>, CallbackInfo, TCLHash>
                mListenerCallbacks;

        uint32_t                    mForceSynchronous = 0;
        uint32_t                    mTransactionNestCount = 0;
        bool                        mAnimation = false;
        bool                        mEarlyWakeup = false;

        int mStatus = NO_ERROR;

        layer_state_t* getLayerState(const sp<SurfaceControl>& sc);
        DisplayState& getDisplayState(const sp<IBinder>& token);

        void registerSurfaceControlForCallback(const sp<SurfaceControl>& sc);

    public:
        Transaction() = default;
        virtual ~Transaction() = default;
        Transaction(Transaction const& other);

        status_t apply(bool synchronous = false);
        // Merge another transaction in to this one, clearing other
        // as if it had been applied.
        Transaction& merge(Transaction&& other);
        Transaction& show(const sp<SurfaceControl>& sc);
        Transaction& hide(const sp<SurfaceControl>& sc);
        Transaction& setPosition(const sp<SurfaceControl>& sc,
                float x, float y);
        Transaction& setSize(const sp<SurfaceControl>& sc,
                uint32_t w, uint32_t h);
        Transaction& setLayer(const sp<SurfaceControl>& sc,
                int32_t z);

        // Sets a Z order relative to the Surface specified by "relativeTo" but
        // without becoming a full child of the relative. Z-ordering works exactly
        // as if it were a child however.
        //
        // As a nod to sanity, only non-child surfaces may have a relative Z-order.
        //
        // This overrides any previous call and is overriden by any future calls
        // to setLayer.
        //
        // If the relative is removed, the Surface will have no layer and be
        // invisible, until the next time set(Relative)Layer is called.
        Transaction& setRelativeLayer(const sp<SurfaceControl>& sc,
                const sp<IBinder>& relativeTo, int32_t z);
        Transaction& setFlags(const sp<SurfaceControl>& sc,
                uint32_t flags, uint32_t mask);
        Transaction& setTransparentRegionHint(const sp<SurfaceControl>& sc,
                const Region& transparentRegion);
        Transaction& setAlpha(const sp<SurfaceControl>& sc,
                float alpha);
        Transaction& setMatrix(const sp<SurfaceControl>& sc,
                float dsdx, float dtdx, float dtdy, float dsdy);
        Transaction& setCrop_legacy(const sp<SurfaceControl>& sc, const Rect& crop);
        Transaction& setLayerStack(const sp<SurfaceControl>& sc, uint32_t layerStack);
        // Defers applying any changes made in this transaction until the Layer
        // identified by handle reaches the given frameNumber. If the Layer identified
        // by handle is removed, then we will apply this transaction regardless of
        // what frame number has been reached.
        Transaction& deferTransactionUntil_legacy(const sp<SurfaceControl>& sc,
                                                  const sp<IBinder>& handle, uint64_t frameNumber);
        // A variant of deferTransactionUntil_legacy which identifies the Layer we wait for by
        // Surface instead of Handle. Useful for clients which may not have the
        // SurfaceControl for some of their Surfaces. Otherwise behaves identically.
        Transaction& deferTransactionUntil_legacy(const sp<SurfaceControl>& sc,
                                                  const sp<Surface>& barrierSurface,
                                                  uint64_t frameNumber);
        // Reparents all children of this layer to the new parent handle.
        Transaction& reparentChildren(const sp<SurfaceControl>& sc,
                const sp<IBinder>& newParentHandle);

        /// Reparents the current layer to the new parent handle. The new parent must not be null.
        // This can be used instead of reparentChildren if the caller wants to
        // only re-parent a specific child.
        Transaction& reparent(const sp<SurfaceControl>& sc,
                const sp<IBinder>& newParentHandle);

        Transaction& setColor(const sp<SurfaceControl>& sc, const half3& color);

        Transaction& setTransform(const sp<SurfaceControl>& sc, uint32_t transform);
        Transaction& setTransformToDisplayInverse(const sp<SurfaceControl>& sc,
                                                  bool transformToDisplayInverse);
        Transaction& setCrop(const sp<SurfaceControl>& sc, const Rect& crop);
        Transaction& setBuffer(const sp<SurfaceControl>& sc, const sp<GraphicBuffer>& buffer);
        Transaction& setAcquireFence(const sp<SurfaceControl>& sc, const sp<Fence>& fence);
        Transaction& setDataspace(const sp<SurfaceControl>& sc, ui::Dataspace dataspace);
        Transaction& setHdrMetadata(const sp<SurfaceControl>& sc, const HdrMetadata& hdrMetadata);
        Transaction& setSurfaceDamageRegion(const sp<SurfaceControl>& sc,
                                            const Region& surfaceDamageRegion);
        Transaction& setApi(const sp<SurfaceControl>& sc, int32_t api);
        Transaction& setSidebandStream(const sp<SurfaceControl>& sc,
                                       const sp<NativeHandle>& sidebandStream);

        Transaction& addTransactionCompletedCallback(
                TransactionCompletedCallbackTakesContext callback, void* callbackContext);

        // Detaches all child surfaces (and their children recursively)
        // from their SurfaceControl.
        // The child SurfaceControls will not throw exceptions or return errors,
        // but transactions will have no effect.
        // The child surfaces will continue to follow their parent surfaces,
        // and remain eligible for rendering, but their relative state will be
        // frozen. We use this in the WindowManager, in app shutdown/relaunch
        // scenarios, where the app would otherwise clean up its child Surfaces.
        // Sometimes the WindowManager needs to extend their lifetime slightly
        // in order to perform an exit animation or prevent flicker.
        Transaction& detachChildren(const sp<SurfaceControl>& sc);
        // Set an override scaling mode as documented in <system/window.h>
        // the override scaling mode will take precedence over any client
        // specified scaling mode. -1 will clear the override scaling mode.
        Transaction& setOverrideScalingMode(const sp<SurfaceControl>& sc,
                int32_t overrideScalingMode);

        // If the size changes in this transaction, all geometry updates specified
        // in this transaction will not complete until a buffer of the new size
        // arrives. As some elements normally apply immediately, this enables
        // freezing the total geometry of a surface until a resize is completed.
        Transaction& setGeometryAppliesWithResize(const sp<SurfaceControl>& sc);

#ifndef NO_INPUT
        Transaction& setInputWindowInfo(const sp<SurfaceControl>& sc, const InputWindowInfo& info);
#endif

        Transaction& destroySurface(const sp<SurfaceControl>& sc);

        // Set a color transform matrix on the given layer on the built-in display.
        Transaction& setColorTransform(const sp<SurfaceControl>& sc, const mat3& matrix,
                                       const vec3& translation);

        status_t setDisplaySurface(const sp<IBinder>& token,
                const sp<IGraphicBufferProducer>& bufferProducer);

        void setDisplayLayerStack(const sp<IBinder>& token, uint32_t layerStack);

        /* setDisplayProjection() defines the projection of layer stacks
         * to a given display.
         *
         * - orientation defines the display's orientation.
         * - layerStackRect defines which area of the window manager coordinate
         * space will be used.
         * - displayRect defines where on the display will layerStackRect be
         * mapped to. displayRect is specified post-orientation, that is
         * it uses the orientation seen by the end-user.
         */
        void setDisplayProjection(const sp<IBinder>& token,
                uint32_t orientation,
                const Rect& layerStackRect,
                const Rect& displayRect);
        void setDisplaySize(const sp<IBinder>& token, uint32_t width, uint32_t height);
        void setAnimationTransaction();
        void setEarlyWakeup();
    };

    status_t    destroySurface(const sp<IBinder>& id);

    status_t clearLayerFrameStats(const sp<IBinder>& token) const;
    status_t getLayerFrameStats(const sp<IBinder>& token, FrameStats* outStats) const;
    static status_t clearAnimationFrameStats();
    static status_t getAnimationFrameStats(FrameStats* outStats);

    static status_t getHdrCapabilities(const sp<IBinder>& display,
            HdrCapabilities* outCapabilities);

    static void setDisplayProjection(const sp<IBinder>& token,
            uint32_t orientation,
            const Rect& layerStackRect,
            const Rect& displayRect);

    inline sp<ISurfaceComposerClient> getClient() { return mClient; }

private:
    virtual void onFirstRef();

    mutable     Mutex                       mLock;
                status_t                    mStatus;
                sp<ISurfaceComposerClient>  mClient;
                wp<IGraphicBufferProducer>  mParent;
};

// ---------------------------------------------------------------------------

class ScreenshotClient {
public:
    // if cropping isn't required, callers may pass in a default Rect, e.g.:
    //   capture(display, producer, Rect(), reqWidth, ...);
    static status_t capture(const sp<IBinder>& display, const ui::Dataspace reqDataSpace,
                            const ui::PixelFormat reqPixelFormat, Rect sourceCrop,
                            uint32_t reqWidth, uint32_t reqHeight, bool useIdentityTransform,
                            uint32_t rotation, sp<GraphicBuffer>* outBuffer);
    static status_t captureLayers(const sp<IBinder>& layerHandle, const ui::Dataspace reqDataSpace,
                                  const ui::PixelFormat reqPixelFormat, Rect sourceCrop,
                                  float frameScale, sp<GraphicBuffer>* outBuffer);
    static status_t captureChildLayers(const sp<IBinder>& layerHandle,
                                       const ui::Dataspace reqDataSpace,
                                       const ui::PixelFormat reqPixelFormat, Rect sourceCrop,
                                       float frameScale, sp<GraphicBuffer>* outBuffer);
};

// ---------------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_GUI_SURFACE_COMPOSER_CLIENT_H
