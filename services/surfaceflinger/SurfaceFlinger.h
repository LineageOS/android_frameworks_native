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

#ifndef ANDROID_SURFACE_FLINGER_H
#define ANDROID_SURFACE_FLINGER_H

#include <sys/types.h>

/*
 * NOTE: Make sure this file doesn't include  anything from <gl/ > or <gl2/ >
 */

#include <android-base/thread_annotations.h>
#include <cutils/atomic.h>
#include <cutils/compiler.h>
#include <gui/BufferQueue.h>
#include <gui/FrameTimestamps.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
#include <gui/OccupancyTracker.h>
#include <hardware/hwcomposer_defs.h>
#include <layerproto/LayerProtoHeader.h>
#include <math/mat4.h>
#include <serviceutils/PriorityDumper.h>
#include <system/graphics.h>
#include <ui/FenceTime.h>
#include <ui/PixelFormat.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/RefBase.h>
#include <utils/SortedVector.h>
#include <utils/Trace.h>
#include <utils/threads.h>

#include "Barrier.h"
#include "BufferStateLayerCache.h"
#include "DisplayDevice.h"
#include "DisplayHardware/HWC2.h"
#include "DisplayHardware/HWComposer.h"
#include "Effects/Daltonizer.h"
#include "FrameTracker.h"
#include "LayerBE.h"
#include "LayerStats.h"
#include "LayerVector.h"
#include "Scheduler/DispSync.h"
#include "Scheduler/EventThread.h"
#include "Scheduler/MessageQueue.h"
#include "Scheduler/PhaseOffsets.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "Scheduler/RefreshRateStats.h"
#include "Scheduler/Scheduler.h"
#include "Scheduler/VSyncModulator.h"
#include "SurfaceFlingerFactory.h"
#include "SurfaceInterceptor.h"
#include "SurfaceTracing.h"
#include "TransactionCompletedThread.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>

using namespace android::surfaceflinger;

namespace android {

// ---------------------------------------------------------------------------

class Client;
class ColorLayer;
class DisplayEventConnection;
class EventControlThread;
class EventThread;
class IGraphicBufferConsumer;
class IGraphicBufferProducer;
class IInputFlinger;
class InjectVSyncSource;
class Layer;
class Surface;
class SurfaceFlingerBE;
class TimeStats;
class VSyncSource;
struct CompositionInfo;

namespace compositionengine {
class DisplaySurface;
} // namespace compositionengine

namespace impl {
class EventThread;
} // namespace impl

namespace renderengine {
class RenderEngine;
}

typedef std::function<void(const LayerVector::Visitor&)> TraverseLayersFunction;

namespace dvr {
class VrFlinger;
} // namespace dvr

namespace surfaceflinger {
class NativeWindowSurface;
} // namespace surfaceflinger

// ---------------------------------------------------------------------------

enum {
    eTransactionNeeded        = 0x01,
    eTraversalNeeded          = 0x02,
    eDisplayTransactionNeeded = 0x04,
    eDisplayLayerStackChanged = 0x08,
    eTransactionMask          = 0x0f,
};

enum class DisplayColorSetting : int32_t {
    MANAGED = 0,
    UNMANAGED = 1,
    ENHANCED = 2,
};

class SurfaceFlingerBE
{
public:
    SurfaceFlingerBE();

    const std::string mHwcServiceName; // "default" for real use, something else for testing.

    FenceTimeline mGlCompositionDoneTimeline;
    FenceTimeline mDisplayTimeline;

    // protected by mCompositorTimingLock;
    mutable std::mutex mCompositorTimingLock;
    CompositorTiming mCompositorTiming;

    // Only accessed from the main thread.
    struct CompositePresentTime {
        nsecs_t composite { -1 };
        std::shared_ptr<FenceTime> display { FenceTime::NO_FENCE };
    };
    std::queue<CompositePresentTime> mCompositePresentTimes;

    static const size_t NUM_BUCKETS = 8; // < 1-7, 7+
    nsecs_t mFrameBuckets[NUM_BUCKETS];
    nsecs_t mTotalTime;
    std::atomic<nsecs_t> mLastSwapTime;

    // Synchronization fence from a GL composition.
    sp<Fence> flushFence = Fence::NO_FENCE;

    // Double- vs. triple-buffering stats
    struct BufferingStats {
        BufferingStats()
          : numSegments(0),
            totalTime(0),
            twoBufferTime(0),
            doubleBufferedTime(0),
            tripleBufferedTime(0) {}

        size_t numSegments;
        nsecs_t totalTime;

        // "Two buffer" means that a third buffer was never used, whereas
        // "double-buffered" means that on average the segment only used two
        // buffers (though it may have used a third for some part of the
        // segment)
        nsecs_t twoBufferTime;
        nsecs_t doubleBufferedTime;
        nsecs_t tripleBufferedTime;
    };
    mutable Mutex mBufferingStatsMutex;
    std::unordered_map<std::string, BufferingStats> mBufferingStats;

    // The composer sequence id is a monotonically increasing integer that we
    // use to differentiate callbacks from different hardware composer
    // instances. Each hardware composer instance gets a different sequence id.
    int32_t mComposerSequenceId;

    std::map<wp<IBinder>, std::vector<CompositionInfo>> mCompositionInfo;
    std::map<wp<IBinder>, std::vector<CompositionInfo>> mEndOfFrameCompositionInfo;
};


class SurfaceFlinger : public BnSurfaceComposer,
                       public PriorityDumper,
                       private IBinder::DeathRecipient,
                       private HWC2::ComposerCallback
{
public:
    SurfaceFlingerBE& getBE() { return mBE; }
    const SurfaceFlingerBE& getBE() const { return mBE; }

    // This is the phase offset in nanoseconds of the software vsync event
    // relative to the vsync event reported by HWComposer.  The software vsync
    // event is when SurfaceFlinger and Choreographer-based applications run each
    // frame.
    //
    // This phase offset allows adjustment of the minimum latency from application
    // wake-up time (by Choreographer) to the time at which the resulting window
    // image is displayed.  This value may be either positive (after the HW vsync)
    // or negative (before the HW vsync). Setting it to 0 will result in a lower
    // latency bound of two vsync periods because the app and SurfaceFlinger
    // will run just after the HW vsync.  Setting it to a positive number will
    // result in the minimum latency being:
    //
    //     (2 * VSYNC_PERIOD - (vsyncPhaseOffsetNs % VSYNC_PERIOD))
    //
    // Note that reducing this latency makes it more likely for the applications
    // to not have their window content image ready in time.  When this happens
    // the latency will end up being an additional vsync period, and animations
    // will hiccup.  Therefore, this latency should be tuned somewhat
    // conservatively (or at least with awareness of the trade-off being made).
    static int64_t vsyncPhaseOffsetNs;
    static int64_t sfVsyncPhaseOffsetNs;

    // If fences from sync Framework are supported.
    static bool hasSyncFramework;

    // The offset in nanoseconds to use when DispSync timestamps present fence
    // signaling time.
    static int64_t dispSyncPresentTimeOffset;

    // Some hardware can do RGB->YUV conversion more efficiently in hardware
    // controlled by HWC than in hardware controlled by the video encoder.
    // This instruct VirtualDisplaySurface to use HWC for such conversion on
    // GL composition.
    static bool useHwcForRgbToYuv;

    // Maximum dimension supported by HWC for virtual display.
    // Equal to min(max_height, max_width).
    static uint64_t maxVirtualDisplaySize;

    // Controls the number of buffers SurfaceFlinger will allocate for use in
    // FramebufferSurface
    static int64_t maxFrameBufferAcquiredBuffers;

    // Indicate if a device has wide color gamut display. This is typically
    // found on devices with wide color gamut (e.g. Display-P3) display.
    static bool hasWideColorDisplay;

    static int primaryDisplayOrientation;

    // Indicate if device wants color management on its display.
    static bool useColorManagement;

    static bool useContextPriority;

    // The data space and pixel format that SurfaceFlinger expects hardware composer
    // to composite efficiently. Meaning under most scenarios, hardware composer
    // will accept layers with the data space and pixel format.
    static ui::Dataspace defaultCompositionDataspace;
    static ui::PixelFormat defaultCompositionPixelFormat;

    // The data space and pixel format that SurfaceFlinger expects hardware composer
    // to composite efficiently for wide color gamut surfaces. Meaning under most scenarios,
    // hardware composer will accept layers with the data space and pixel format.
    static ui::Dataspace wideColorGamutCompositionDataspace;
    static ui::PixelFormat wideColorGamutCompositionPixelFormat;

    static char const* getServiceName() ANDROID_API {
        return "SurfaceFlinger";
    }

    struct SkipInitializationTag {};
    static constexpr SkipInitializationTag SkipInitialization;
    SurfaceFlinger(surfaceflinger::Factory&, SkipInitializationTag) ANDROID_API;
    explicit SurfaceFlinger(surfaceflinger::Factory&) ANDROID_API;

    // must be called before clients can connect
    void init() ANDROID_API;

    // starts SurfaceFlinger main loop in the current thread
    void run() ANDROID_API;

    // post an asynchronous message to the main thread
    status_t postMessageAsync(const sp<MessageBase>& msg, nsecs_t reltime = 0, uint32_t flags = 0);

    // post a synchronous message to the main thread
    status_t postMessageSync(const sp<MessageBase>& msg, nsecs_t reltime = 0, uint32_t flags = 0);

    // force full composition on all displays
    void repaintEverything();

    // force full composition on all displays without resetting the scheduler idle timer.
    void repaintEverythingForHWC();

    surfaceflinger::Factory& getFactory() { return mFactory; }

    // The CompositionEngine encapsulates all composition related interfaces and actions.
    compositionengine::CompositionEngine& getCompositionEngine() const;

    // returns the default Display
    sp<const DisplayDevice> getDefaultDisplayDevice() {
        Mutex::Autolock _l(mStateLock);
        return getDefaultDisplayDeviceLocked();
    }

    // Obtains a name from the texture pool, or, if the pool is empty, posts a
    // synchronous message to the main thread to obtain one on the fly
    uint32_t getNewTexture();

    // utility function to delete a texture on the main thread
    void deleteTextureAsync(uint32_t texture);

    // enable/disable h/w composer event
    // TODO: this should be made accessible only to EventThread
    void setPrimaryVsyncEnabled(bool enabled);

    // called on the main thread by MessageQueue when an internal message
    // is received
    // TODO: this should be made accessible only to MessageQueue
    void onMessageReceived(int32_t what);

    // for debugging only
    // TODO: this should be made accessible only to HWComposer
    const Vector<sp<Layer>>& getLayerSortedByZForHwcDisplay(DisplayId displayId);

    renderengine::RenderEngine& getRenderEngine() const;

    bool authenticateSurfaceTextureLocked(
        const sp<IGraphicBufferProducer>& bufferProducer) const;

    inline void onLayerCreated() { mNumLayers++; }
    inline void onLayerDestroyed() { mNumLayers--; }

    TransactionCompletedThread& getTransactionCompletedThread() {
        return mTransactionCompletedThread;
    }

private:
    friend class Client;
    friend class DisplayEventConnection;
    friend class impl::EventThread;
    friend class Layer;
    friend class BufferLayer;
    friend class BufferQueueLayer;
    friend class BufferStateLayer;
    friend class MonitoredProducer;

    // For unit tests
    friend class TestableSurfaceFlinger;

    // This value is specified in number of frames.  Log frame stats at most
    // every half hour.
    enum { LOG_FRAME_STATS_PERIOD =  30*60*60 };

    static const size_t MAX_LAYERS = 4096;

    // We're reference counted, never destroy SurfaceFlinger directly
    virtual ~SurfaceFlinger();

    /* ------------------------------------------------------------------------
     * Internal data structures
     */

    class State {
    public:
        explicit State(LayerVector::StateSet set) : stateSet(set), layersSortedByZ(set) {}
        State& operator=(const State& other) {
            // We explicitly don't copy stateSet so that, e.g., mDrawingState
            // always uses the Drawing StateSet.
            layersSortedByZ = other.layersSortedByZ;
            displays = other.displays;
            colorMatrixChanged = other.colorMatrixChanged;
            if (colorMatrixChanged) {
                colorMatrix = other.colorMatrix;
            }
            return *this;
        }

        const LayerVector::StateSet stateSet = LayerVector::StateSet::Invalid;
        LayerVector layersSortedByZ;
        DefaultKeyedVector< wp<IBinder>, DisplayDeviceState> displays;

        bool colorMatrixChanged = true;
        mat4 colorMatrix;

        void traverseInZOrder(const LayerVector::Visitor& visitor) const;
        void traverseInReverseZOrder(const LayerVector::Visitor& visitor) const;
    };

    /* ------------------------------------------------------------------------
     * IBinder interface
     */
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override;
    status_t dump(int fd, const Vector<String16>& args) override { return priorityDump(fd, args); }

    /* ------------------------------------------------------------------------
     * ISurfaceComposer interface
     */
    sp<ISurfaceComposerClient> createConnection() override;
    sp<IBinder> createDisplay(const String8& displayName, bool secure) override;
    void destroyDisplay(const sp<IBinder>& displayToken) override;
    std::vector<PhysicalDisplayId> getPhysicalDisplayIds() const override;
    sp<IBinder> getPhysicalDisplayToken(PhysicalDisplayId displayId) const override;
    void setTransactionState(const Vector<ComposerState>& state,
                             const Vector<DisplayState>& displays, uint32_t flags,
                             const sp<IBinder>& applyToken,
                             const InputWindowCommands& inputWindowCommands,
                             int64_t desiredPresentTime) override;
    void bootFinished() override;
    bool authenticateSurfaceTexture(
            const sp<IGraphicBufferProducer>& bufferProducer) const override;
    status_t getSupportedFrameTimestamps(std::vector<FrameEvent>* outSupported) const override;
    sp<IDisplayEventConnection> createDisplayEventConnection(
            ISurfaceComposer::VsyncSource vsyncSource = eVsyncSourceApp) override;
    status_t captureScreen(const sp<IBinder>& displayToken, sp<GraphicBuffer>* outBuffer,
                           const ui::Dataspace reqDataspace, const ui::PixelFormat reqPixelFormat,
                           Rect sourceCrop, uint32_t reqWidth, uint32_t reqHeight,
                           bool useIdentityTransform, ISurfaceComposer::Rotation rotation) override;
    status_t captureLayers(const sp<IBinder>& parentHandle, sp<GraphicBuffer>* outBuffer,
                           const ui::Dataspace reqDataspace, const ui::PixelFormat reqPixelFormat,
                           const Rect& sourceCrop, float frameScale, bool childrenOnly) override;
    status_t getDisplayStats(const sp<IBinder>& displayToken, DisplayStatInfo* stats) override;
    status_t getDisplayConfigs(const sp<IBinder>& displayToken,
                               Vector<DisplayInfo>* configs) override {
        Mutex::Autolock _l(mStateLock);
        return getDisplayConfigsLocked(displayToken, configs);
    }
    status_t getDisplayConfigsLocked(const sp<IBinder>& displayToken, Vector<DisplayInfo>* configs)
            REQUIRES(mStateLock);
    int getActiveConfig(const sp<IBinder>& displayToken) override;
    status_t getDisplayColorModes(const sp<IBinder>& displayToken,
                                  Vector<ui::ColorMode>* configs) override;
    status_t getDisplayNativePrimaries(const sp<IBinder>& displayToken,
                                       ui::DisplayPrimaries &primaries);
    ui::ColorMode getActiveColorMode(const sp<IBinder>& displayToken) override;
    status_t setActiveColorMode(const sp<IBinder>& displayToken, ui::ColorMode colorMode) override;
    void setPowerMode(const sp<IBinder>& displayToken, int mode) override;
    status_t setActiveConfig(const sp<IBinder>& displayToken, int id) override;
    status_t clearAnimationFrameStats() override;
    status_t getAnimationFrameStats(FrameStats* outStats) const override;
    status_t getHdrCapabilities(const sp<IBinder>& displayToken,
                                HdrCapabilities* outCapabilities) const override;
    status_t enableVSyncInjections(bool enable) override;
    status_t injectVSync(nsecs_t when) override;
    status_t getLayerDebugInfo(std::vector<LayerDebugInfo>* outLayers) const override;
    status_t getColorManagement(bool* outGetColorManagement) const override;
    status_t getCompositionPreference(ui::Dataspace* outDataspace, ui::PixelFormat* outPixelFormat,
                                      ui::Dataspace* outWideColorGamutDataspace,
                                      ui::PixelFormat* outWideColorGamutPixelFormat) const override;
    status_t getDisplayedContentSamplingAttributes(const sp<IBinder>& display,
                                                   ui::PixelFormat* outFormat,
                                                   ui::Dataspace* outDataspace,
                                                   uint8_t* outComponentMask) const override;
    status_t setDisplayContentSamplingEnabled(const sp<IBinder>& display, bool enable,
                                              uint8_t componentMask,
                                              uint64_t maxFrames) const override;
    status_t getDisplayedContentSample(const sp<IBinder>& display, uint64_t maxFrames,
                                       uint64_t timestamp,
                                       DisplayedFrameStats* outStats) const override;
    status_t getProtectedContentSupport(bool* outSupported) const override;
    status_t isWideColorDisplay(const sp<IBinder>& displayToken,
                                bool* outIsWideColorDisplay) const override;

    /* ------------------------------------------------------------------------
     * DeathRecipient interface
     */
    void binderDied(const wp<IBinder>& who) override;

    /* ------------------------------------------------------------------------
     * RefBase interface
     */
    void onFirstRef() override;

    /* ------------------------------------------------------------------------
     * HWC2::ComposerCallback / HWComposer::EventHandler interface
     */
    void onVsyncReceived(int32_t sequenceId, hwc2_display_t hwcDisplayId,
                         int64_t timestamp) override;
    void onHotplugReceived(int32_t sequenceId, hwc2_display_t hwcDisplayId,
                           HWC2::Connection connection) override;
    void onRefreshReceived(int32_t sequenceId, hwc2_display_t hwcDisplayId) override;

    /* ------------------------------------------------------------------------
     * Message handling
     */
    void waitForEvent();
    // Can only be called from the main thread or with mStateLock held
    void signalTransaction();
    // Can only be called from the main thread or with mStateLock held
    void signalLayerUpdate();
    void signalRefresh();

    // called on the main thread in response to initializeDisplays()
    void onInitializeDisplays() REQUIRES(mStateLock);
    // Sets the desired active config bit. It obtains the lock, and sets mDesiredActiveConfig.
    void setDesiredActiveConfig(const sp<IBinder>& displayToken, int mode) REQUIRES(mStateLock);
    // Calls setActiveConfig in HWC.
    void setActiveConfigInHWC();
    // Once HWC has returned the present fence, this sets the active config and a new refresh
    // rate in SF. It also triggers HWC vsync.
    void setActiveConfigInternal() REQUIRES(mStateLock);
    // Active config is updated on INVALIDATE call in a state machine-like manner. When the
    // desired config was set, HWC needs to update the pannel on the next refresh, and when
    // we receive the fence back, we know that the process was complete. It returns whether
    // the invalidate process should continue.
    bool updateSetActiveConfigStateMachine();
    // called on the main thread in response to setPowerMode()
    void setPowerModeInternal(const sp<DisplayDevice>& display, int mode) REQUIRES(mStateLock);

    // Returns whether the transaction actually modified any state
    bool handleMessageTransaction();

    // Returns whether a new buffer has been latched (see handlePageFlip())
    bool handleMessageInvalidate();

    void handleMessageRefresh();

    void handleTransaction(uint32_t transactionFlags);
    void handleTransactionLocked(uint32_t transactionFlags);

    void updateInputFlinger();
    void updateInputWindowInfo();
    void executeInputWindowCommands();
    void updateCursorAsync();

    /* handlePageFlip - latch a new buffer if available and compute the dirty
     * region. Returns whether a new buffer has been latched, i.e., whether it
     * is necessary to perform a refresh during this vsync.
     */
    bool handlePageFlip();

    /* ------------------------------------------------------------------------
     * Transactions
     */
    void applyTransactionState(const Vector<ComposerState>& state,
                               const Vector<DisplayState>& displays, uint32_t flags,
                               const InputWindowCommands& inputWindowCommands) REQUIRES(mStateLock);
    bool flushTransactionQueues();
    uint32_t getTransactionFlags(uint32_t flags);
    uint32_t peekTransactionFlags();
    // Can only be called from the main thread or with mStateLock held
    uint32_t setTransactionFlags(uint32_t flags);
    uint32_t setTransactionFlags(uint32_t flags, Scheduler::TransactionStart transactionStart);
    void latchAndReleaseBuffer(const sp<Layer>& layer);
    void commitTransaction();
    bool containsAnyInvalidClientState(const Vector<ComposerState>& states);
    bool transactionIsReadyToBeApplied(int64_t desiredPresentTime,
                                       const Vector<ComposerState>& states);
    uint32_t setClientStateLocked(const ComposerState& composerState);
    uint32_t setDisplayStateLocked(const DisplayState& s);
    uint32_t addInputWindowCommands(const InputWindowCommands& inputWindowCommands);

    /* ------------------------------------------------------------------------
     * Layer management
     */
    status_t createLayer(const String8& name, const sp<Client>& client, uint32_t w, uint32_t h,
                         PixelFormat format, uint32_t flags, LayerMetadata metadata,
                         sp<IBinder>* handle, sp<IGraphicBufferProducer>* gbp, sp<Layer>* parent);

    status_t createBufferQueueLayer(const sp<Client>& client, const String8& name, uint32_t w,
                                    uint32_t h, uint32_t flags, PixelFormat& format,
                                    sp<IBinder>* outHandle, sp<IGraphicBufferProducer>* outGbp,
                                    sp<Layer>* outLayer);

    status_t createBufferStateLayer(const sp<Client>& client, const String8& name, uint32_t w,
                                    uint32_t h, uint32_t flags, sp<IBinder>* outHandle,
                                    sp<Layer>* outLayer);

    status_t createColorLayer(const sp<Client>& client, const String8& name,
            uint32_t w, uint32_t h, uint32_t flags, sp<IBinder>* outHandle,
            sp<Layer>* outLayer);

    status_t createContainerLayer(const sp<Client>& client, const String8& name,
            uint32_t w, uint32_t h, uint32_t flags, sp<IBinder>* outHandle,
            sp<Layer>* outLayer);

    String8 getUniqueLayerName(const String8& name);

    // called when all clients have released all their references to
    // this layer meaning it is entirely safe to destroy all
    // resources associated to this layer.
    void onHandleDestroyed(sp<Layer>& layer);
    void markLayerPendingRemovalLocked(const sp<Layer>& layer);

    // add a layer to SurfaceFlinger
    status_t addClientLayer(const sp<Client>& client,
            const sp<IBinder>& handle,
            const sp<IGraphicBufferProducer>& gbc,
            const sp<Layer>& lbc,
            const sp<Layer>& parent,
            bool addToCurrentState);

    /* ------------------------------------------------------------------------
     * Boot animation, on/off animations and screen capture
     */

    void startBootAnim();

    void renderScreenImplLocked(const RenderArea& renderArea, TraverseLayersFunction traverseLayers,
                                ANativeWindowBuffer* buffer, bool useIdentityTransform,
                                int* outSyncFd);
    status_t captureScreenCommon(RenderArea& renderArea, TraverseLayersFunction traverseLayers,
                                 sp<GraphicBuffer>* outBuffer, const ui::PixelFormat reqPixelFormat,
                                 bool useIdentityTransform);
    status_t captureScreenImplLocked(const RenderArea& renderArea,
                                     TraverseLayersFunction traverseLayers,
                                     ANativeWindowBuffer* buffer, bool useIdentityTransform,
                                     bool forSystem, int* outSyncFd);
    void traverseLayersInDisplay(const sp<const DisplayDevice>& display,
                                 const LayerVector::Visitor& visitor);

    sp<StartPropertySetThread> mStartPropertySetThread;

    /* ------------------------------------------------------------------------
     * Properties
     */
    void readPersistentProperties();

    /* ------------------------------------------------------------------------
     * EGL
     */
    size_t getMaxTextureSize() const;
    size_t getMaxViewportDims() const;

    /* ------------------------------------------------------------------------
     * Display and layer stack management
     */
    // called when starting, or restarting after system_server death
    void initializeDisplays();

    sp<const DisplayDevice> getDisplayDevice(const wp<IBinder>& displayToken) const {
        Mutex::Autolock _l(mStateLock);
        return getDisplayDeviceLocked(displayToken);
    }

    sp<DisplayDevice> getDisplayDevice(const wp<IBinder>& displayToken) {
        Mutex::Autolock _l(mStateLock);
        return getDisplayDeviceLocked(displayToken);
    }

    // NOTE: can only be called from the main thread or with mStateLock held
    sp<const DisplayDevice> getDisplayDeviceLocked(const wp<IBinder>& displayToken) const {
        return const_cast<SurfaceFlinger*>(this)->getDisplayDeviceLocked(displayToken);
    }

    // NOTE: can only be called from the main thread or with mStateLock held
    sp<DisplayDevice> getDisplayDeviceLocked(const wp<IBinder>& displayToken) {
        const auto it = mDisplays.find(displayToken);
        return it == mDisplays.end() ? nullptr : it->second;
    }

    sp<const DisplayDevice> getDefaultDisplayDeviceLocked() const {
        return const_cast<SurfaceFlinger*>(this)->getDefaultDisplayDeviceLocked();
    }

    sp<DisplayDevice> getDefaultDisplayDeviceLocked() {
        if (const auto token = getInternalDisplayTokenLocked()) {
            return getDisplayDeviceLocked(token);
        }
        return nullptr;
    }

    // mark a region of a layer stack dirty. this updates the dirty
    // region of all screens presenting this layer stack.
    void invalidateLayerStack(const sp<const Layer>& layer, const Region& dirty);

    // Initialize structures containing information about the internal
    // display's native color coordinates using default data
    void initDefaultDisplayNativePrimaries();

    /* ------------------------------------------------------------------------
     * H/W composer
     */

    // The current hardware composer interface.
    //
    // The following thread safety rules apply when accessing mHwc, either
    // directly or via getHwComposer():
    //
    // 1. When recreating mHwc, acquire mStateLock. We currently recreate mHwc
    //    only when switching into and out of vr. Recreating mHwc must only be
    //    done on the main thread.
    //
    // 2. When accessing mHwc on the main thread, it's not necessary to acquire
    //    mStateLock.
    //
    // 3. When accessing mHwc on a thread other than the main thread, we always
    //    need to acquire mStateLock. This is because the main thread could be
    //    in the process of destroying the current mHwc instance.
    //
    // The above thread safety rules only apply to SurfaceFlinger.cpp. In
    // SurfaceFlinger_hwc1.cpp we create mHwc at surface flinger init and never
    // destroy it, so it's always safe to access mHwc from any thread without
    // acquiring mStateLock.
    HWComposer& getHwComposer() const;

    /* ------------------------------------------------------------------------
     * Compositing
     */
    void invalidateHwcGeometry();
    void computeVisibleRegions(const sp<const DisplayDevice>& display, Region& dirtyRegion,
                               Region& opaqueRegion);

    void preComposition();
    void postComposition();
    void getCompositorTiming(CompositorTiming* compositorTiming);
    void updateCompositorTiming(const DisplayStatInfo& stats, nsecs_t compositeTime,
                                std::shared_ptr<FenceTime>& presentFenceTime);
    void setCompositorTimingSnapped(const DisplayStatInfo& stats,
                                    nsecs_t compositeToPresentLatency);
    void rebuildLayerStacks();

    ui::Dataspace getBestDataspace(const sp<const DisplayDevice>& display,
                                   ui::Dataspace* outHdrDataSpace) const;

    // Returns the appropriate ColorMode, Dataspace and RenderIntent for the
    // DisplayDevice. The function only returns the supported ColorMode,
    // Dataspace and RenderIntent.
    void pickColorMode(const sp<DisplayDevice>& display, ui::ColorMode* outMode,
                       ui::Dataspace* outDataSpace, ui::RenderIntent* outRenderIntent) const;

    void calculateWorkingSet();
    /*
     * beginFrame - This function handles any pre-frame processing that needs to be
     * prior to any CompositionInfo handling and is not dependent on data in
     * CompositionInfo
     */
    void beginFrame(const sp<DisplayDevice>& display);
    /* prepareFrame - This function will call into the DisplayDevice to prepare a
     * frame after CompositionInfo has been programmed.   This provides a mechanism
     * to prepare the hardware composer
     */
    void prepareFrame(const sp<DisplayDevice>& display);
    void doComposition(const sp<DisplayDevice>& display, bool repainEverything);
    void doDebugFlashRegions(const sp<DisplayDevice>& display, bool repaintEverything);
    void doTracing(const char* where);
    void logLayerStats();
    void doDisplayComposition(const sp<DisplayDevice>& display, const Region& dirtyRegion);

    // This fails if using GL and the surface has been destroyed. readyFence
    // will be populated if using GL and native fence sync is supported, to
    // signal when drawing has completed.
    bool doComposeSurfaces(const sp<DisplayDevice>& display, const Region& debugRegionm,
                           base::unique_fd* readyFence);

    void postFramebuffer(const sp<DisplayDevice>& display);
    void postFrame();
    void drawWormhole(const Region& region) const;

    /* ------------------------------------------------------------------------
     * Display management
     */
    sp<DisplayDevice> setupNewDisplayDeviceInternal(
            const wp<IBinder>& displayToken, const std::optional<DisplayId>& displayId,
            const DisplayDeviceState& state,
            const sp<compositionengine::DisplaySurface>& dispSurface,
            const sp<IGraphicBufferProducer>& producer);
    void processDisplayChangesLocked();
    void processDisplayHotplugEventsLocked();

    void dispatchDisplayHotplugEvent(PhysicalDisplayId displayId, bool connected);

    /* ------------------------------------------------------------------------
     * VSync
     */
    nsecs_t getVsyncPeriod() const REQUIRES(mStateLock);
    void enableHardwareVsync();
    void resyncToHardwareVsync(bool makeAvailable, nsecs_t period);
    void disableHardwareVsync(bool makeUnavailable);

    // Sets the refresh rate by switching active configs, if they are available for
    // the desired refresh rate.
    void setRefreshRateTo(scheduler::RefreshRateConfigs::RefreshRateType) REQUIRES(mStateLock);

    using GetVsyncPeriod = std::function<nsecs_t()>;

    // Stores per-display state about VSYNC.
    struct VsyncState {
        explicit VsyncState(SurfaceFlinger& flinger) : flinger(flinger) {}

        void resync(const GetVsyncPeriod&);

        SurfaceFlinger& flinger;
        std::atomic<nsecs_t> lastResyncTime = 0;
    };

    const std::shared_ptr<VsyncState> mPrimaryVsyncState{std::make_shared<VsyncState>(*this)};

    auto makeResyncCallback(GetVsyncPeriod&& getVsyncPeriod) {
        std::weak_ptr<VsyncState> ptr = mPrimaryVsyncState;
        return [ptr, getVsyncPeriod = std::move(getVsyncPeriod)]() {
            if (const auto vsync = ptr.lock()) {
                vsync->resync(getVsyncPeriod);
            }
        };
    }

    /*
     * Display identification
     */
    sp<IBinder> getPhysicalDisplayTokenLocked(DisplayId displayId) const {
        const auto it = mPhysicalDisplayTokens.find(displayId);
        return it != mPhysicalDisplayTokens.end() ? it->second : nullptr;
    }

    std::optional<DisplayId> getPhysicalDisplayIdLocked(const sp<IBinder>& displayToken) const {
        for (const auto& [id, token] : mPhysicalDisplayTokens) {
            if (token == displayToken) {
                return id;
            }
        }
        return {};
    }

    // TODO(b/74619554): Remove special cases for primary display.
    sp<IBinder> getInternalDisplayTokenLocked() const {
        const auto displayId = getInternalDisplayIdLocked();
        return displayId ? getPhysicalDisplayTokenLocked(*displayId) : nullptr;
    }

    std::optional<DisplayId> getInternalDisplayIdLocked() const {
        const auto hwcDisplayId = getHwComposer().getInternalHwcDisplayId();
        return hwcDisplayId ? getHwComposer().toPhysicalDisplayId(*hwcDisplayId) : std::nullopt;
    }

    /*
     * Debugging & dumpsys
     */
    using DumpArgs = Vector<String16>;
    using Dumper = std::function<void(const DumpArgs&, bool asProto, std::string&)>;

    template <typename F, std::enable_if_t<!std::is_member_function_pointer_v<F>>* = nullptr>
    static Dumper dumper(F&& dump) {
        using namespace std::placeholders;
        return std::bind(std::forward<F>(dump), _3);
    }

    template <typename F, std::enable_if_t<std::is_member_function_pointer_v<F>>* = nullptr>
    Dumper dumper(F dump) {
        using namespace std::placeholders;
        return std::bind(dump, this, _3);
    }

    template <typename F>
    Dumper argsDumper(F dump) {
        using namespace std::placeholders;
        return std::bind(dump, this, _1, _3);
    }

    template <typename F>
    Dumper protoDumper(F dump) {
        using namespace std::placeholders;
        return std::bind(dump, this, _1, _2, _3);
    }

    void dumpAllLocked(const DumpArgs& args, std::string& result) const REQUIRES(mStateLock);

    void appendSfConfigString(std::string& result) const;
    void listLayersLocked(std::string& result) const;
    void dumpStatsLocked(const DumpArgs& args, std::string& result) const REQUIRES(mStateLock);
    void clearStatsLocked(const DumpArgs& args, std::string& result);
    void dumpTimeStats(const DumpArgs& args, bool asProto, std::string& result) const;
    void logFrameStats();

    void dumpVSync(std::string& result) const REQUIRES(mStateLock);
    void dumpStaticScreenStats(std::string& result) const;
    // Not const because each Layer needs to query Fences and cache timestamps.
    void dumpFrameEventsLocked(std::string& result);

    void recordBufferingStats(const char* layerName,
            std::vector<OccupancyTracker::Segment>&& history);
    void dumpBufferingStats(std::string& result) const;
    void dumpDisplayIdentificationData(std::string& result) const;
    void dumpWideColorInfo(std::string& result) const;
    void dumpFrameCompositionInfo(std::string& result) const;
    LayersProto dumpProtoInfo(LayerVector::StateSet stateSet) const;
    LayersProto dumpVisibleLayersProtoInfo(const DisplayDevice& display) const;

    bool isLayerTripleBufferingDisabled() const {
        return this->mLayerTripleBufferingDisabled;
    }

    status_t doDump(int fd, const DumpArgs& args, bool asProto);

    status_t dumpCritical(int fd, const DumpArgs&, bool asProto) override {
        return doDump(fd, DumpArgs(), asProto);
    }

    status_t dumpAll(int fd, const DumpArgs& args, bool asProto) override {
        return doDump(fd, args, asProto);
    }

    /* ------------------------------------------------------------------------
     * VrFlinger
     */
    void resetDisplayState();

    // Check to see if we should handoff to vr flinger.
    void updateVrFlinger();

    void updateColorMatrixLocked();

    /* ------------------------------------------------------------------------
     * Attributes
     */

    surfaceflinger::Factory& mFactory;

    // access must be protected by mStateLock
    mutable Mutex mStateLock;
    State mCurrentState{LayerVector::StateSet::Current};
    std::atomic<int32_t> mTransactionFlags{0};
    Condition mTransactionCV;
    bool mTransactionPending;
    bool mAnimTransactionPending;
    SortedVector< sp<Layer> > mLayersPendingRemoval;

    // global color transform states
    Daltonizer mDaltonizer;
    float mGlobalSaturationFactor = 1.0f;
    mat4 mClientColorMatrix;

    // Can't be unordered_set because wp<> isn't hashable
    std::set<wp<IBinder>> mGraphicBufferProducerList;
    size_t mMaxGraphicBufferProducerListSize = MAX_LAYERS;

    // protected by mStateLock (but we could use another lock)
    bool mLayersRemoved;
    bool mLayersAdded;

    std::atomic<bool> mRepaintEverything{false};

    // constant members (no synchronization needed for access)
    nsecs_t mBootTime;
    bool mGpuToCpuSupported;
    std::unique_ptr<EventThread> mEventThread;
    std::unique_ptr<EventThread> mSFEventThread;
    std::unique_ptr<EventThread> mInjectorEventThread;
    std::unique_ptr<VSyncSource> mEventThreadSource;
    std::unique_ptr<VSyncSource> mSfEventThreadSource;
    std::unique_ptr<InjectVSyncSource> mVSyncInjector;
    std::unique_ptr<EventControlThread> mEventControlThread;

    // Calculates correct offsets.
    VSyncModulator mVsyncModulator;
    // Keeps track of all available phase offsets for different refresh types.
    std::unique_ptr<scheduler::PhaseOffsets> mPhaseOffsets;

    // Can only accessed from the main thread, these members
    // don't need synchronization
    State mDrawingState{LayerVector::StateSet::Drawing};
    bool mVisibleRegionsDirty;
    // Set during transaction commit stage to track if the input info for a layer has changed.
    bool mInputInfoChanged{false};
    bool mGeometryInvalid;
    bool mAnimCompositionPending;
    std::vector<sp<Layer>> mLayersWithQueuedFrames;
    // Tracks layers that need to update a display's dirty region.
    std::vector<sp<Layer>> mLayersPendingRefresh;
    sp<Fence> mPreviousPresentFence = Fence::NO_FENCE;
    bool mHadClientComposition = false;

    enum class BootStage {
        BOOTLOADER,
        BOOTANIMATION,
        FINISHED,
    };
    BootStage mBootStage;

    struct HotplugEvent {
        hwc2_display_t hwcDisplayId;
        HWC2::Connection connection = HWC2::Connection::Invalid;
    };
    // protected by mStateLock
    std::vector<HotplugEvent> mPendingHotplugEvents;

    // this may only be written from the main thread with mStateLock held
    // it may be read from other threads with mStateLock held
    std::map<wp<IBinder>, sp<DisplayDevice>> mDisplays;
    std::unordered_map<DisplayId, sp<IBinder>> mPhysicalDisplayTokens;

    // don't use a lock for these, we don't care
    int mDebugRegion;
    int mDebugDisableHWC;
    int mDebugDisableTransformHint;
    volatile nsecs_t mDebugInSwapBuffers;
    volatile nsecs_t mDebugInTransaction;
    nsecs_t mLastTransactionTime;
    nsecs_t mPostFramebufferTime;
    bool mForceFullDamage;
    bool mPropagateBackpressure = true;
    std::unique_ptr<SurfaceInterceptor> mInterceptor{mFactory.createSurfaceInterceptor(this)};
    SurfaceTracing mTracing;
    LayerStats mLayerStats;
    std::shared_ptr<TimeStats> mTimeStats;
    bool mUseHwcVirtualDisplays = false;
    std::atomic<uint32_t> mFrameMissedCount{0};

    TransactionCompletedThread mTransactionCompletedThread;

    // Restrict layers to use two buffers in their bufferqueues.
    bool mLayerTripleBufferingDisabled = false;

    // these are thread safe
    mutable std::unique_ptr<MessageQueue> mEventQueue{mFactory.createMessageQueue()};
    FrameTracker mAnimFrameTracker;
    std::unique_ptr<DispSync> mPrimaryDispSync;

    // protected by mDestroyedLayerLock;
    mutable Mutex mDestroyedLayerLock;
    Vector<Layer const *> mDestroyedLayers;

    // protected by mHWVsyncLock
    Mutex mHWVsyncLock;
    bool mPrimaryHWVsyncEnabled;
    bool mHWVsyncAvailable;
    nsecs_t mRefreshStartTime;

    std::atomic<bool> mRefreshPending{false};

    // We maintain a pool of pre-generated texture names to hand out to avoid
    // layer creation needing to run on the main thread (which it would
    // otherwise need to do to access RenderEngine).
    std::mutex mTexturePoolMutex;
    uint32_t mTexturePoolSize = 0;
    std::vector<uint32_t> mTexturePool;

    struct IBinderHash {
        std::size_t operator()(const sp<IBinder>& strongPointer) const {
            return std::hash<IBinder*>{}(strongPointer.get());
        }
    };
    struct TransactionState {
        TransactionState(const Vector<ComposerState>& composerStates,
                         const Vector<DisplayState>& displayStates, uint32_t transactionFlags,
                         int64_t desiredPresentTime)
              : states(composerStates),
                displays(displayStates),
                flags(transactionFlags),
                time(desiredPresentTime) {}

        Vector<ComposerState> states;
        Vector<DisplayState> displays;
        uint32_t flags;
        int64_t time;
    };
    std::unordered_map<sp<IBinder>, std::queue<TransactionState>, IBinderHash> mTransactionQueues;

    /* ------------------------------------------------------------------------
     * Feature prototyping
     */

    bool mInjectVSyncs;

    // Static screen stats
    bool mHasPoweredOff;

    size_t mNumLayers;

    // Verify that transaction is being called by an approved process:
    // either AID_GRAPHICS or AID_SYSTEM.
    status_t CheckTransactCodeCredentials(uint32_t code);

    std::unique_ptr<dvr::VrFlinger> mVrFlinger;
    std::atomic<bool> mVrFlingerRequestsDisplay;
    static bool useVrFlinger;
    std::thread::id mMainThreadId;

    DisplayColorSetting mDisplayColorSetting = DisplayColorSetting::ENHANCED;

    ui::Dataspace mDefaultCompositionDataspace;
    ui::Dataspace mWideColorGamutCompositionDataspace;

    SurfaceFlingerBE mBE;
    std::unique_ptr<compositionengine::CompositionEngine> mCompositionEngine;

    /* ------------------------------------------------------------------------
     * Scheduler
     */
    bool mUseScheduler = false;
    std::unique_ptr<Scheduler> mScheduler;
    sp<Scheduler::ConnectionHandle> mAppConnectionHandle;
    sp<Scheduler::ConnectionHandle> mSfConnectionHandle;
    std::unique_ptr<scheduler::RefreshRateStats> mRefreshRateStats;

    // The following structs are used for configuring active config state at a desired time,
    // which is once per vsync at invalidate time.
    enum SetActiveConfigState {
        NONE,            // not in progress
        NOTIFIED_HWC,    // call to HWC has been made
        REFRESH_RECEIVED // onRefresh was received from HWC
    };
    std::atomic<SetActiveConfigState> mSetActiveConfigState = SetActiveConfigState::NONE;

    struct ActiveConfigInfo {
        int configId;
        sp<IBinder> displayToken;

        bool operator!=(const ActiveConfigInfo& other) const {
            if (configId != other.configId) {
                return true;
            }
            return (displayToken != other.displayToken);
        }
    };
    std::mutex mActiveConfigLock;
    // This bit is set once we start setting the config. We read from this bit during the
    // process. If at the end, this bit is different than mDesiredActiveConfig, we restart
    // the process.
    ActiveConfigInfo mUpcomingActiveConfig; // Always read and written on the main thread.
    // This bit can be set at any point in time when the system wants the new config.
    ActiveConfigInfo mDesiredActiveConfig GUARDED_BY(mActiveConfigLock);

    /* ------------------------------------------------------------------------ */
    sp<IInputFlinger> mInputFlinger;

    InputWindowCommands mInputWindowCommands;

    ui::DisplayPrimaries mInternalDisplayPrimaries;
};
}; // namespace android

#endif // ANDROID_SURFACE_FLINGER_H
