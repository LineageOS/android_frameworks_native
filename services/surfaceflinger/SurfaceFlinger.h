/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <sys/types.h>

/*
 * NOTE: Make sure this file doesn't include  anything from <gl/ > or <gl2/ >
 */

#include <android-base/thread_annotations.h>
#include <android/gui/BnSurfaceComposer.h>
#include <android/gui/DisplayStatInfo.h>
#include <android/gui/DisplayState.h>
#include <android/gui/ISurfaceComposerClient.h>
#include <cutils/atomic.h>
#include <cutils/compiler.h>
#include <ftl/algorithm.h>
#include <ftl/future.h>
#include <ftl/non_null.h>
#include <gui/BufferQueue.h>
#include <gui/CompositorTiming.h>
#include <gui/FrameTimestamps.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ITransactionCompletedListener.h>
#include <gui/LayerDebugInfo.h>
#include <gui/LayerState.h>
#include <layerproto/LayerProtoHeader.h>
#include <math/mat4.h>
#include <renderengine/LayerSettings.h>
#include <serviceutils/PriorityDumper.h>
#include <system/graphics.h>
#include <ui/DisplayMap.h>
#include <ui/FenceTime.h>
#include <ui/PixelFormat.h>
#include <ui/Size.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/RefBase.h>
#include <utils/SortedVector.h>
#include <utils/Trace.h>
#include <utils/threads.h>

#include <compositionengine/OutputColorSetting.h>
#include <scheduler/Fps.h>
#include <scheduler/PresentLatencyTracker.h>
#include <scheduler/Time.h>
#include <scheduler/TransactionSchedule.h>
#include <scheduler/interface/CompositionCoverage.h>
#include <scheduler/interface/ICompositor.h>
#include <ui/FenceResult.h>

#include "Display/PhysicalDisplay.h"
#include "DisplayDevice.h"
#include "DisplayHardware/HWC2.h"
#include "DisplayHardware/PowerAdvisor.h"
#include "DisplayIdGenerator.h"
#include "Effects/Daltonizer.h"
#include "FlagManager.h"
#include "FrontEnd/DisplayInfo.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "FrontEnd/LayerLifecycleManager.h"
#include "FrontEnd/LayerSnapshot.h"
#include "FrontEnd/LayerSnapshotBuilder.h"
#include "FrontEnd/TransactionHandler.h"
#include "LayerVector.h"
#include "Scheduler/ISchedulerCallback.h"
#include "Scheduler/RefreshRateSelector.h"
#include "Scheduler/RefreshRateStats.h"
#include "Scheduler/Scheduler.h"
#include "SurfaceFlingerFactory.h"
#include "ThreadContext.h"
#include "Tracing/LayerTracing.h"
#include "Tracing/TransactionTracing.h"
#include "TransactionCallbackInvoker.h"
#include "TransactionState.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <aidl/android/hardware/graphics/common/DisplayDecorationSupport.h>
#include <aidl/android/hardware/graphics/composer3/RefreshRateChangedDebugData.h>
#include "Client.h"

using namespace android::surfaceflinger;

namespace android {

class EventThread;
class FlagManager;
class FpsReporter;
class TunnelModeEnabledReporter;
class HdrLayerInfoReporter;
class HWComposer;
class IGraphicBufferProducer;
class Layer;
class MessageBase;
class RefreshRateOverlay;
class RegionSamplingThread;
class RenderArea;
class TimeStats;
class FrameTracer;
class ScreenCapturer;
class WindowInfosListenerInvoker;

using ::aidl::android::hardware::graphics::composer3::RefreshRateChangedDebugData;
using frontend::TransactionHandler;
using gui::CaptureArgs;
using gui::DisplayCaptureArgs;
using gui::IRegionSamplingListener;
using gui::LayerCaptureArgs;
using gui::ScreenCaptureResults;

namespace frametimeline {
class FrameTimeline;
}

namespace os {
    class IInputFlinger;
}

namespace compositionengine {
class DisplaySurface;
class OutputLayer;

struct CompositionRefreshArgs;
} // namespace compositionengine

namespace renderengine {
class RenderEngine;
} // namespace renderengine

enum {
    eTransactionNeeded = 0x01,
    eTraversalNeeded = 0x02,
    eDisplayTransactionNeeded = 0x04,
    eTransformHintUpdateNeeded = 0x08,
    eTransactionFlushNeeded = 0x10,
    eInputInfoUpdateNeeded = 0x20,
    eTransactionMask = 0x3f,
};

// Latch Unsignaled buffer behaviours
enum class LatchUnsignaledConfig {
    // All buffers are latched signaled.
    Disabled,

    // Latch unsignaled is permitted when a single layer is updated in a frame,
    // and the update includes just a buffer update (i.e. no sync transactions
    // or geometry changes).
    // Latch unsignaled is also only permitted when a single transaction is ready
    // to be applied. If we pass an unsignaled fence to HWC, HWC might miss presenting
    // the frame if the fence does not fire in time. If we apply another transaction,
    // we may penalize the other transaction unfairly.
    AutoSingleLayer,

    // All buffers are latched unsignaled. This behaviour is discouraged as it
    // can break sync transactions, stall the display and cause undesired side effects.
    // This is equivalent to ignoring the acquire fence when applying transactions.
    Always,
};

using DisplayColorSetting = compositionengine::OutputColorSetting;

class SurfaceFlinger : public BnSurfaceComposer,
                       public PriorityDumper,
                       private IBinder::DeathRecipient,
                       private HWC2::ComposerCallback,
                       private ICompositor,
                       private scheduler::ISchedulerCallback,
                       private compositionengine::ICEPowerCallback {
public:
    struct SkipInitializationTag {};

    SurfaceFlinger(surfaceflinger::Factory&, SkipInitializationTag) ANDROID_API;
    explicit SurfaceFlinger(surfaceflinger::Factory&) ANDROID_API;

    // set main thread scheduling policy
    static status_t setSchedFifo(bool enabled) ANDROID_API;

    // set main thread scheduling attributes
    static status_t setSchedAttr(bool enabled);

    static char const* getServiceName() ANDROID_API { return "SurfaceFlinger"; }

    // If fences from sync Framework are supported.
    static bool hasSyncFramework;

    // The offset in nanoseconds to use when VsyncController timestamps present fence
    // signaling time.
    static int64_t dispSyncPresentTimeOffset;

    // Some hardware can do RGB->YUV conversion more efficiently in hardware
    // controlled by HWC than in hardware controlled by the video encoder.
    // This instruct VirtualDisplaySurface to use HWC for such conversion on
    // GL composition.
    static bool useHwcForRgbToYuv;

    // Controls the number of buffers SurfaceFlinger will allocate for use in
    // FramebufferSurface
    static int64_t maxFrameBufferAcquiredBuffers;

    // Controls the maximum width and height in pixels that the graphics pipeline can support for
    // GPU fallback composition. For example, 8k devices with 4k GPUs, or 4k devices with 2k GPUs.
    static uint32_t maxGraphicsWidth;
    static uint32_t maxGraphicsHeight;

    // Indicate if device wants color management on its display.
    static const constexpr bool useColorManagement = true;

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

    static constexpr SkipInitializationTag SkipInitialization;

    static LatchUnsignaledConfig enableLatchUnsignaledConfig;

    // must be called before clients can connect
    void init() ANDROID_API;

    // starts SurfaceFlinger main loop in the current thread
    void run() ANDROID_API;

    // Indicates frame activity, i.e. whether commit and/or composite is taking place.
    enum class FrameHint { kNone, kActive };

    // Schedule commit of transactions on the main thread ahead of the next VSYNC.
    void scheduleCommit(FrameHint);
    // As above, but also force composite regardless if transactions were committed.
    void scheduleComposite(FrameHint);
    // As above, but also force dirty geometry to repaint.
    void scheduleRepaint();
    // Schedule sampling independently from commit or composite.
    void scheduleSample();

    surfaceflinger::Factory& getFactory() { return mFactory; }

    // The CompositionEngine encapsulates all composition related interfaces and actions.
    compositionengine::CompositionEngine& getCompositionEngine() const;

    // Obtains a name from the texture pool, or, if the pool is empty, posts a
    // synchronous message to the main thread to obtain one on the fly
    uint32_t getNewTexture();

    // utility function to delete a texture on the main thread
    void deleteTextureAsync(uint32_t texture);

    renderengine::RenderEngine& getRenderEngine() const;

    void onLayerFirstRef(Layer*);
    void onLayerDestroyed(Layer*);
    void onLayerUpdate();

    void removeHierarchyFromOffscreenLayers(Layer* layer);
    void removeFromOffscreenLayers(Layer* layer);

    // Called when all clients have released all their references to
    // this layer. The layer may still be kept alive by its parents but
    // the client can no longer modify this layer directly.
    void onHandleDestroyed(BBinder* handle, sp<Layer>& layer, uint32_t layerId);

    std::vector<Layer*> mLayerMirrorRoots;

    TransactionCallbackInvoker& getTransactionCallbackInvoker() {
        return mTransactionCallbackInvoker;
    }

    // If set, disables reusing client composition buffers. This can be set by
    // debug.sf.disable_client_composition_cache
    bool mDisableClientCompositionCache = false;

    // Disables expensive rendering for all displays
    // This is scheduled on the main thread
    void disableExpensiveRendering();
    FloatRect getMaxDisplayBounds();

    // If set, composition engine tries to predict the composition strategy provided by HWC
    // based on the previous frame. If the strategy can be predicted, gpu composition will
    // run parallel to the hwc validateDisplay call and re-run if the predition is incorrect.
    bool mPredictCompositionStrategy = false;

    // If true, then any layer with a SMPTE 170M transfer function is decoded using the sRGB
    // transfer instead. This is mainly to preserve legacy behavior, where implementations treated
    // SMPTE 170M as sRGB prior to color management being implemented, and now implementations rely
    // on this behavior to increase contrast for some media sources.
    bool mTreat170mAsSrgb = false;

    // If true, then screenshots with an enhanced render intent will dim in gamma space.
    // The purpose is to ensure that screenshots appear correct during system animations for devices
    // that require that dimming must occur in gamma space.
    bool mDimInGammaSpaceForEnhancedScreenshots = false;

    // Allows to ignore physical orientation provided through hwc API in favour of
    // 'ro.surface_flinger.primary_display_orientation'.
    // TODO(b/246793311): Clean up a temporary property
    bool mIgnoreHwcPhysicalDisplayOrientation = false;

    void forceFutureUpdate(int delayInMs);
    const DisplayDevice* getDisplayFromLayerStack(ui::LayerStack)
            REQUIRES(mStateLock, kMainThreadContext);

    // TODO (b/259407931): Remove.
    // TODO (b/281857977): This should be annotated with REQUIRES(kMainThreadContext), but this
    // would require thread safety annotations throughout the frontend (in particular Layer and
    // LayerFE).
    static ui::Transform::RotationFlags getActiveDisplayRotationFlags() {
        return sActiveDisplayRotationFlags;
    }

protected:
    // We're reference counted, never destroy SurfaceFlinger directly
    virtual ~SurfaceFlinger();

    virtual void processDisplayAdded(const wp<IBinder>& displayToken, const DisplayDeviceState&)
            REQUIRES(mStateLock);

    virtual std::shared_ptr<renderengine::ExternalTexture> getExternalTextureFromBufferData(
            BufferData& bufferData, const char* layerName, uint64_t transactionId);

    // Returns true if any display matches a `bool(const DisplayDevice&)` predicate.
    template <typename Predicate>
    bool hasDisplay(Predicate p) const REQUIRES(mStateLock) {
        return static_cast<bool>(findDisplay(p));
    }

    bool exceedsMaxRenderTargetSize(uint32_t width, uint32_t height) const {
        return width > mMaxRenderTargetSize || height > mMaxRenderTargetSize;
    }

private:
    friend class BufferLayer;
    friend class Client;
    friend class FpsReporter;
    friend class TunnelModeEnabledReporter;
    friend class Layer;
    friend class RefreshRateOverlay;
    friend class RegionSamplingThread;
    friend class LayerRenderArea;
    friend class LayerTracing;
    friend class SurfaceComposerAIDL;
    friend class DisplayRenderArea;

    // For unit tests
    friend class TestableSurfaceFlinger;
    friend class TransactionApplicationTest;
    friend class TunnelModeEnabledReporterTest;

    using TransactionSchedule = scheduler::TransactionSchedule;
    using GetLayerSnapshotsFunction = std::function<std::vector<std::pair<Layer*, sp<LayerFE>>>()>;
    using RenderAreaFuture = ftl::Future<std::unique_ptr<RenderArea>>;
    using DumpArgs = Vector<String16>;
    using Dumper = std::function<void(const DumpArgs&, bool asProto, std::string&)>;

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
            globalShadowSettings = other.globalShadowSettings;

            return *this;
        }

        const LayerVector::StateSet stateSet = LayerVector::StateSet::Invalid;
        LayerVector layersSortedByZ;

        // TODO(b/241285876): Replace deprecated DefaultKeyedVector with ftl::SmallMap.
        DefaultKeyedVector<wp<IBinder>, DisplayDeviceState> displays;

        std::optional<size_t> getDisplayIndex(PhysicalDisplayId displayId) const {
            for (size_t i = 0; i < displays.size(); i++) {
                const auto& state = displays.valueAt(i);
                if (state.physical && state.physical->id == displayId) {
                    return i;
                }
            }

            return {};
        }

        bool colorMatrixChanged = true;
        mat4 colorMatrix;

        renderengine::ShadowSettings globalShadowSettings;

        void traverse(const LayerVector::Visitor& visitor) const;
        void traverseInZOrder(const LayerVector::Visitor& visitor) const;
        void traverseInReverseZOrder(const LayerVector::Visitor& visitor) const;
    };

    // Keeps track of pending buffers per layer handle in the transaction queue or current/drawing
    // state before the buffers are latched. The layer owns the atomic counters and decrements the
    // count in the main thread when dropping or latching a buffer.
    //
    // The binder threads increment the same counter when a new transaction containing a buffer is
    // added to the transaction queue. The map is updated with the layer handle lifecycle updates.
    // This is done to avoid lock contention with the main thread.
    class BufferCountTracker {
    public:
        void increment(BBinder* layerHandle) {
            std::lock_guard<std::mutex> lock(mLock);
            auto it = mCounterByLayerHandle.find(layerHandle);
            if (it != mCounterByLayerHandle.end()) {
                auto [name, pendingBuffers] = it->second;
                int32_t count = ++(*pendingBuffers);
                ATRACE_INT(name.c_str(), count);
            } else {
                ALOGW("Handle not found! %p", layerHandle);
            }
        }

        void add(BBinder* layerHandle, const std::string& name, std::atomic<int32_t>* counter) {
            std::lock_guard<std::mutex> lock(mLock);
            mCounterByLayerHandle[layerHandle] = std::make_pair(name, counter);
        }

        void remove(BBinder* layerHandle) {
            std::lock_guard<std::mutex> lock(mLock);
            mCounterByLayerHandle.erase(layerHandle);
        }

    private:
        std::mutex mLock;
        std::unordered_map<BBinder*, std::pair<std::string, std::atomic<int32_t>*>>
                mCounterByLayerHandle GUARDED_BY(mLock);
    };

    enum class BootStage {
        BOOTLOADER,
        BOOTANIMATION,
        FINISHED,
    };

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

    // Maximum allowed number of display frames that can be set through backdoor
    static const int MAX_ALLOWED_DISPLAY_FRAMES = 2048;

    static const size_t MAX_LAYERS = 4096;

    // Implements IBinder.
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override;
    status_t dump(int fd, const Vector<String16>& args) override { return priorityDump(fd, args); }
    bool callingThreadHasUnscopedSurfaceFlingerAccess(bool usePermissionCache = true)
            EXCLUDES(mStateLock);

    // Implements ISurfaceComposer
    sp<IBinder> createDisplay(const String8& displayName, bool secure,
                              float requestedRefreshRate = 0.0f);
    void destroyDisplay(const sp<IBinder>& displayToken);
    std::vector<PhysicalDisplayId> getPhysicalDisplayIds() const EXCLUDES(mStateLock) {
        Mutex::Autolock lock(mStateLock);
        return getPhysicalDisplayIdsLocked();
    }

    sp<IBinder> getPhysicalDisplayToken(PhysicalDisplayId displayId) const;
    status_t setTransactionState(
            const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& state,
            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
            InputWindowCommands inputWindowCommands, int64_t desiredPresentTime,
            bool isAutoTimestamp, const std::vector<client_cache_t>& uncacheBuffers,
            bool hasListenerCallbacks, const std::vector<ListenerCallbacks>& listenerCallbacks,
            uint64_t transactionId, const std::vector<uint64_t>& mergedTransactionIds) override;
    void bootFinished();
    virtual status_t getSupportedFrameTimestamps(std::vector<FrameEvent>* outSupported) const;
    sp<IDisplayEventConnection> createDisplayEventConnection(
            gui::ISurfaceComposer::VsyncSource vsyncSource =
                    gui::ISurfaceComposer::VsyncSource::eVsyncSourceApp,
            EventRegistrationFlags eventRegistration = {},
            const sp<IBinder>& layerHandle = nullptr);

    status_t captureDisplay(const DisplayCaptureArgs&, const sp<IScreenCaptureListener>&);
    status_t captureDisplay(DisplayId, const sp<IScreenCaptureListener>&);
    status_t captureLayers(const LayerCaptureArgs&, const sp<IScreenCaptureListener>&);

    status_t getDisplayStats(const sp<IBinder>& displayToken, DisplayStatInfo* stats);
    status_t getDisplayState(const sp<IBinder>& displayToken, ui::DisplayState*)
            EXCLUDES(mStateLock);
    status_t getStaticDisplayInfo(int64_t displayId, ui::StaticDisplayInfo*) EXCLUDES(mStateLock);
    status_t getDynamicDisplayInfoFromId(int64_t displayId, ui::DynamicDisplayInfo*)
            EXCLUDES(mStateLock);
    status_t getDynamicDisplayInfoFromToken(const sp<IBinder>& displayToken,
                                            ui::DynamicDisplayInfo*) EXCLUDES(mStateLock);
    void getDynamicDisplayInfoInternal(ui::DynamicDisplayInfo*&, const sp<DisplayDevice>&,
                                       const display::DisplaySnapshot&);
    status_t getDisplayNativePrimaries(const sp<IBinder>& displayToken, ui::DisplayPrimaries&);
    status_t setActiveColorMode(const sp<IBinder>& displayToken, ui::ColorMode colorMode);
    status_t getBootDisplayModeSupport(bool* outSupport) const;
    status_t setBootDisplayMode(const sp<display::DisplayToken>&, DisplayModeId);
    status_t getOverlaySupport(gui::OverlayProperties* outProperties) const;
    status_t clearBootDisplayMode(const sp<IBinder>& displayToken);
    status_t getHdrConversionCapabilities(
            std::vector<gui::HdrConversionCapability>* hdrConversionCapaabilities) const;
    status_t setHdrConversionStrategy(const gui::HdrConversionStrategy& hdrConversionStrategy,
                                      int32_t*);
    status_t getHdrOutputConversionSupport(bool* outSupport) const;
    void setAutoLowLatencyMode(const sp<IBinder>& displayToken, bool on);
    void setGameContentType(const sp<IBinder>& displayToken, bool on);
    void setPowerMode(const sp<IBinder>& displayToken, int mode);
    status_t overrideHdrTypes(const sp<IBinder>& displayToken,
                              const std::vector<ui::Hdr>& hdrTypes);
    status_t onPullAtom(const int32_t atomId, std::vector<uint8_t>* pulledData, bool* success);
    status_t getLayerDebugInfo(std::vector<gui::LayerDebugInfo>* outLayers);
    status_t getColorManagement(bool* outGetColorManagement) const;
    status_t getCompositionPreference(ui::Dataspace* outDataspace, ui::PixelFormat* outPixelFormat,
                                      ui::Dataspace* outWideColorGamutDataspace,
                                      ui::PixelFormat* outWideColorGamutPixelFormat) const;
    status_t getDisplayedContentSamplingAttributes(const sp<IBinder>& displayToken,
                                                   ui::PixelFormat* outFormat,
                                                   ui::Dataspace* outDataspace,
                                                   uint8_t* outComponentMask) const;
    status_t setDisplayContentSamplingEnabled(const sp<IBinder>& displayToken, bool enable,
                                              uint8_t componentMask, uint64_t maxFrames);
    status_t getDisplayedContentSample(const sp<IBinder>& displayToken, uint64_t maxFrames,
                                       uint64_t timestamp, DisplayedFrameStats* outStats) const;
    status_t getProtectedContentSupport(bool* outSupported) const;
    status_t isWideColorDisplay(const sp<IBinder>& displayToken, bool* outIsWideColorDisplay) const;
    status_t addRegionSamplingListener(const Rect& samplingArea, const sp<IBinder>& stopLayerHandle,
                                       const sp<IRegionSamplingListener>& listener);
    status_t removeRegionSamplingListener(const sp<IRegionSamplingListener>& listener);
    status_t addFpsListener(int32_t taskId, const sp<gui::IFpsListener>& listener);
    status_t removeFpsListener(const sp<gui::IFpsListener>& listener);
    status_t addTunnelModeEnabledListener(const sp<gui::ITunnelModeEnabledListener>& listener);
    status_t removeTunnelModeEnabledListener(const sp<gui::ITunnelModeEnabledListener>& listener);
    status_t setDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                        const gui::DisplayModeSpecs&);
    status_t getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken, gui::DisplayModeSpecs*);
    status_t getDisplayBrightnessSupport(const sp<IBinder>& displayToken, bool* outSupport) const;
    status_t setDisplayBrightness(const sp<IBinder>& displayToken,
                                  const gui::DisplayBrightness& brightness);
    status_t addHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                     const sp<gui::IHdrLayerInfoListener>& listener);
    status_t removeHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                        const sp<gui::IHdrLayerInfoListener>& listener);
    status_t notifyPowerBoost(int32_t boostId);
    status_t setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                     float lightPosY, float lightPosZ, float lightRadius);
    status_t getDisplayDecorationSupport(
            const sp<IBinder>& displayToken,
            std::optional<aidl::android::hardware::graphics::common::DisplayDecorationSupport>*
                    outSupport) const;
    status_t setFrameRate(const sp<IGraphicBufferProducer>& surface, float frameRate,
                          int8_t compatibility, int8_t changeFrameRateStrategy);

    status_t setFrameTimelineInfo(const sp<IGraphicBufferProducer>& surface,
                                  const gui::FrameTimelineInfo& frameTimelineInfo);

    status_t setOverrideFrameRate(uid_t uid, float frameRate);

    status_t updateSmallAreaDetection(std::vector<std::pair<uid_t, float>>& uidThresholdMappings);

    status_t setSmallAreaDetectionThreshold(uid_t uid, float threshold);

    int getGpuContextPriority();

    status_t getMaxAcquiredBufferCount(int* buffers) const;

    status_t addWindowInfosListener(const sp<gui::IWindowInfosListener>& windowInfosListener,
                                    gui::WindowInfosListenerInfo* outResult);
    status_t removeWindowInfosListener(
            const sp<gui::IWindowInfosListener>& windowInfosListener) const;

    status_t getStalledTransactionInfo(
            int pid, std::optional<TransactionHandler::StalledTransactionInfo>& result);

    // Implements IBinder::DeathRecipient.
    void binderDied(const wp<IBinder>& who) override;

    // HWC2::ComposerCallback overrides:
    void onComposerHalVsync(hal::HWDisplayId, nsecs_t timestamp,
                            std::optional<hal::VsyncPeriodNanos>) override;
    void onComposerHalHotplug(hal::HWDisplayId, hal::Connection) override;
    void onComposerHalRefresh(hal::HWDisplayId) override;
    void onComposerHalVsyncPeriodTimingChanged(hal::HWDisplayId,
                                               const hal::VsyncPeriodChangeTimeline&) override;
    void onComposerHalSeamlessPossible(hal::HWDisplayId) override;
    void onComposerHalVsyncIdle(hal::HWDisplayId) override;
    void onRefreshRateChangedDebug(const RefreshRateChangedDebugData&) override;

    // ICompositor overrides:
    void configure() override REQUIRES(kMainThreadContext);
    bool commit(PhysicalDisplayId pacesetterId, const scheduler::FrameTargets&) override
            REQUIRES(kMainThreadContext);
    CompositeResultsPerDisplay composite(PhysicalDisplayId pacesetterId,
                                         const scheduler::FrameTargeters&) override
            REQUIRES(kMainThreadContext);

    void sample() override;

    // ISchedulerCallback overrides:
    void requestHardwareVsync(PhysicalDisplayId, bool) override;
    void requestDisplayModes(std::vector<display::DisplayModeRequest>) override;
    void kernelTimerChanged(bool expired) override;
    void triggerOnFrameRateOverridesChanged() override;

    // ICEPowerCallback overrides:
    void notifyCpuLoadUp() override;

    // Toggles the kernel idle timer on or off depending the policy decisions around refresh rates.
    void toggleKernelIdleTimer() REQUIRES(mStateLock);

    using KernelIdleTimerController = scheduler::RefreshRateSelector::KernelIdleTimerController;

    // Get the controller and timeout that will help decide how the kernel idle timer will be
    // configured and what value to use as the timeout.
    std::pair<std::optional<KernelIdleTimerController>, std::chrono::milliseconds>
            getKernelIdleTimerProperties(DisplayId) REQUIRES(mStateLock);
    // Updates the kernel idle timer either through HWC or through sysprop
    // depending on which controller is provided
    void updateKernelIdleTimer(std::chrono::milliseconds timeoutMs, KernelIdleTimerController,
                               PhysicalDisplayId) REQUIRES(mStateLock);
    // Keeps track of whether the kernel idle timer is currently enabled, so we don't have to
    // make calls to sys prop each time.
    bool mKernelIdleTimerEnabled = false;
    // Show spinner with refresh rate overlay
    bool mRefreshRateOverlaySpinner = false;
    // Show render rate with refresh rate overlay
    bool mRefreshRateOverlayRenderRate = false;
    // Show render rate overlay offseted to the middle of the screen (e.g. for circular displays)
    bool mRefreshRateOverlayShowInMiddle = false;

    void setDesiredActiveMode(display::DisplayModeRequest&&, bool force = false)
            REQUIRES(mStateLock);

    status_t setActiveModeFromBackdoor(const sp<display::DisplayToken>&, DisplayModeId);

    void initiateDisplayModeChanges() REQUIRES(mStateLock, kMainThreadContext);
    void finalizeDisplayModeChange(DisplayDevice&) REQUIRES(mStateLock, kMainThreadContext);

    void clearDesiredActiveModeState(const sp<DisplayDevice>&) REQUIRES(mStateLock);
    // Called when active mode is no longer is progress
    void desiredActiveModeChangeDone(const sp<DisplayDevice>&) REQUIRES(mStateLock);
    // Called on the main thread in response to setPowerMode()
    void setPowerModeInternal(const sp<DisplayDevice>& display, hal::PowerMode mode)
            REQUIRES(mStateLock, kMainThreadContext);

    // Returns the preferred mode for PhysicalDisplayId if the Scheduler has selected one for that
    // display. Falls back to the display's defaultModeId otherwise.
    ftl::Optional<scheduler::FrameRateMode> getPreferredDisplayMode(
            PhysicalDisplayId, DisplayModeId defaultModeId) const REQUIRES(mStateLock);

    status_t setDesiredDisplayModeSpecsInternal(
            const sp<DisplayDevice>&, const scheduler::RefreshRateSelector::PolicyVariant&)
            EXCLUDES(mStateLock) REQUIRES(kMainThreadContext);

    bool shouldApplyRefreshRateSelectorPolicy(const DisplayDevice&) const
            REQUIRES(mStateLock, kMainThreadContext);

    // TODO(b/241285191): Look up RefreshRateSelector on Scheduler to remove redundant parameter.
    status_t applyRefreshRateSelectorPolicy(PhysicalDisplayId,
                                            const scheduler::RefreshRateSelector&,
                                            bool force = false)
            REQUIRES(mStateLock, kMainThreadContext);

    void commitTransactions() EXCLUDES(mStateLock) REQUIRES(kMainThreadContext);
    void commitTransactionsLocked(uint32_t transactionFlags)
            REQUIRES(mStateLock, kMainThreadContext);
    void doCommitTransactions() REQUIRES(mStateLock);

    // Returns whether a new buffer has been latched.
    bool latchBuffers();

    void updateLayerGeometry();
    void updateLayerMetadataSnapshot();
    std::vector<std::pair<Layer*, LayerFE*>> moveSnapshotsToCompositionArgs(
            compositionengine::CompositionRefreshArgs& refreshArgs, bool cursorOnly);
    void moveSnapshotsFromCompositionArgs(compositionengine::CompositionRefreshArgs& refreshArgs,
                                          const std::vector<std::pair<Layer*, LayerFE*>>& layers);
    bool updateLayerSnapshotsLegacy(VsyncId vsyncId, frontend::Update& update,
                                    bool transactionsFlushed, bool& out)
            REQUIRES(kMainThreadContext);
    bool updateLayerSnapshots(VsyncId vsyncId, frontend::Update& update, bool transactionsFlushed,
                              bool& out) REQUIRES(kMainThreadContext);
    void updateLayerHistory(const frontend::LayerSnapshot& snapshot);
    frontend::Update flushLifecycleUpdates() REQUIRES(kMainThreadContext);

    void updateInputFlinger(VsyncId vsyncId, TimePoint frameTime);
    void persistDisplayBrightness(bool needsComposite) REQUIRES(kMainThreadContext);
    void buildWindowInfos(std::vector<gui::WindowInfo>& outWindowInfos,
                          std::vector<gui::DisplayInfo>& outDisplayInfos);
    void commitInputWindowCommands() REQUIRES(mStateLock);
    void updateCursorAsync();

    void initScheduler(const sp<const DisplayDevice>&) REQUIRES(kMainThreadContext, mStateLock);

    void resetPhaseConfiguration(Fps) REQUIRES(mStateLock, kMainThreadContext);
    void updatePhaseConfiguration(Fps) REQUIRES(mStateLock);

    /*
     * Transactions
     */
    bool applyTransactionState(const FrameTimelineInfo& info,
                               std::vector<ResolvedComposerState>& state,
                               Vector<DisplayState>& displays, uint32_t flags,
                               const InputWindowCommands& inputWindowCommands,
                               const int64_t desiredPresentTime, bool isAutoTimestamp,
                               const std::vector<uint64_t>& uncacheBufferIds,
                               const int64_t postTime, bool hasListenerCallbacks,
                               const std::vector<ListenerCallbacks>& listenerCallbacks,
                               int originPid, int originUid, uint64_t transactionId)
            REQUIRES(mStateLock);
    // Flush pending transactions that were presented after desiredPresentTime.
    // For test only
    bool flushTransactionQueues(VsyncId) REQUIRES(kMainThreadContext);

    bool applyTransactions(std::vector<TransactionState>&, VsyncId) REQUIRES(kMainThreadContext);
    bool applyAndCommitDisplayTransactionStates(std::vector<TransactionState>& transactions)
            REQUIRES(kMainThreadContext);

    // Returns true if there is at least one transaction that needs to be flushed
    bool transactionFlushNeeded();
    void addTransactionReadyFilters();
    TransactionHandler::TransactionReadiness transactionReadyTimelineCheck(
            const TransactionHandler::TransactionFlushState& flushState)
            REQUIRES(kMainThreadContext);
    TransactionHandler::TransactionReadiness transactionReadyBufferCheck(
            const TransactionHandler::TransactionFlushState& flushState)
            REQUIRES(kMainThreadContext);

    uint32_t setClientStateLocked(const FrameTimelineInfo&, ResolvedComposerState&,
                                  int64_t desiredPresentTime, bool isAutoTimestamp,
                                  int64_t postTime, uint64_t transactionId) REQUIRES(mStateLock);
    uint32_t updateLayerCallbacksAndStats(const FrameTimelineInfo&, ResolvedComposerState&,
                                          int64_t desiredPresentTime, bool isAutoTimestamp,
                                          int64_t postTime, uint64_t transactionId)
            REQUIRES(mStateLock);
    uint32_t getTransactionFlags() const;

    // Sets the masked bits, and schedules a commit if needed.
    void setTransactionFlags(uint32_t mask, TransactionSchedule = TransactionSchedule::Late,
                             const sp<IBinder>& applyToken = nullptr,
                             FrameHint = FrameHint::kActive);

    // Clears and returns the masked bits.
    uint32_t clearTransactionFlags(uint32_t mask);

    void commitOffscreenLayers();

    static LatchUnsignaledConfig getLatchUnsignaledConfig();
    bool shouldLatchUnsignaled(const sp<Layer>& layer, const layer_state_t&, size_t numStates,
                               bool firstTransaction) const;
    bool applyTransactionsLocked(std::vector<TransactionState>& transactions, VsyncId)
            REQUIRES(mStateLock);
    uint32_t setDisplayStateLocked(const DisplayState& s) REQUIRES(mStateLock);
    uint32_t addInputWindowCommands(const InputWindowCommands& inputWindowCommands)
            REQUIRES(mStateLock);
    bool frameIsEarly(TimePoint expectedPresentTime, VsyncId) const;

    /*
     * Layer management
     */
    status_t createLayer(LayerCreationArgs& args, gui::CreateSurfaceResult& outResult);

    status_t createBufferStateLayer(LayerCreationArgs& args, sp<IBinder>* outHandle,
                                    sp<Layer>* outLayer);

    status_t createEffectLayer(const LayerCreationArgs& args, sp<IBinder>* outHandle,
                               sp<Layer>* outLayer);

    status_t mirrorLayer(const LayerCreationArgs& args, const sp<IBinder>& mirrorFromHandle,
                         gui::CreateSurfaceResult& outResult);

    status_t mirrorDisplay(DisplayId displayId, const LayerCreationArgs& args,
                           gui::CreateSurfaceResult& outResult);

    void markLayerPendingRemovalLocked(const sp<Layer>& layer) REQUIRES(mStateLock);

    // add a layer to SurfaceFlinger
    status_t addClientLayer(LayerCreationArgs& args, const sp<IBinder>& handle,
                            const sp<Layer>& layer, const wp<Layer>& parentLayer,
                            uint32_t* outTransformHint);

    // Traverse through all the layers and compute and cache its bounds.
    void computeLayerBounds();

    // Boot animation, on/off animations and screen capture
    void startBootAnim();

    ftl::SharedFuture<FenceResult> captureScreenCommon(RenderAreaFuture, GetLayerSnapshotsFunction,
                                                       ui::Size bufferSize, ui::PixelFormat,
                                                       bool allowProtected, bool grayscale,
                                                       const sp<IScreenCaptureListener>&);
    ftl::SharedFuture<FenceResult> captureScreenCommon(
            RenderAreaFuture, GetLayerSnapshotsFunction,
            const std::shared_ptr<renderengine::ExternalTexture>&, bool regionSampling,
            bool grayscale, const sp<IScreenCaptureListener>&);
    ftl::SharedFuture<FenceResult> renderScreenImpl(
            std::shared_ptr<const RenderArea>, GetLayerSnapshotsFunction,
            const std::shared_ptr<renderengine::ExternalTexture>&, bool canCaptureBlackoutContent,
            bool regionSampling, bool grayscale, ScreenCaptureResults&) EXCLUDES(mStateLock)
            REQUIRES(kMainThreadContext);

    bool canAllocateHwcDisplayIdForVDS(uint64_t usage);

    // If the uid provided is not UNSET_UID, the traverse will skip any layers that don't have a
    // matching ownerUid
    void traverseLayersInLayerStack(ui::LayerStack, const int32_t uid,
                                    std::unordered_set<uint32_t> excludeLayerIds,
                                    const LayerVector::Visitor&);

    void readPersistentProperties();

    uint32_t getMaxAcquiredBufferCountForCurrentRefreshRate(uid_t uid) const;

    /*
     * Display and layer stack management
     */

    // Called during boot, and restart after system_server death.
    void initializeDisplays() REQUIRES(kMainThreadContext);

    sp<const DisplayDevice> getDisplayDeviceLocked(const wp<IBinder>& displayToken) const
            REQUIRES(mStateLock) {
        return const_cast<SurfaceFlinger*>(this)->getDisplayDeviceLocked(displayToken);
    }

    sp<DisplayDevice> getDisplayDeviceLocked(const wp<IBinder>& displayToken) REQUIRES(mStateLock) {
        return mDisplays.get(displayToken)
                .or_else(ftl::static_ref<sp<DisplayDevice>>([] { return nullptr; }))
                .value();
    }

    sp<const DisplayDevice> getDisplayDeviceLocked(PhysicalDisplayId id) const
            REQUIRES(mStateLock) {
        return const_cast<SurfaceFlinger*>(this)->getDisplayDeviceLocked(id);
    }

    sp<DisplayDevice> getDisplayDeviceLocked(PhysicalDisplayId id) REQUIRES(mStateLock) {
        if (const auto token = getPhysicalDisplayTokenLocked(id)) {
            return getDisplayDeviceLocked(token);
        }
        return nullptr;
    }

    sp<const DisplayDevice> getDisplayDeviceLocked(DisplayId id) const REQUIRES(mStateLock) {
        // TODO(b/182939859): Replace tokens with IDs for display lookup.
        return findDisplay([id](const auto& display) { return display.getId() == id; });
    }

    std::shared_ptr<compositionengine::Display> getCompositionDisplayLocked(DisplayId id) const
            REQUIRES(mStateLock) {
        if (const auto display = getDisplayDeviceLocked(id)) {
            return display->getCompositionDisplay();
        }
        return nullptr;
    }

    // Returns the primary display or (for foldables) the active display, assuming that the inner
    // and outer displays have mutually exclusive power states.
    sp<const DisplayDevice> getDefaultDisplayDeviceLocked() const REQUIRES(mStateLock) {
        return const_cast<SurfaceFlinger*>(this)->getDefaultDisplayDeviceLocked();
    }

    sp<DisplayDevice> getDefaultDisplayDeviceLocked() REQUIRES(mStateLock) {
        if (const auto display = getDisplayDeviceLocked(mActiveDisplayId)) {
            return display;
        }
        // The active display is outdated, so fall back to the primary display.
        mActiveDisplayId = getPrimaryDisplayIdLocked();
        return getDisplayDeviceLocked(mActiveDisplayId);
    }

    sp<const DisplayDevice> getDefaultDisplayDevice() const EXCLUDES(mStateLock) {
        Mutex::Autolock lock(mStateLock);
        return getDefaultDisplayDeviceLocked();
    }

    using DisplayDeviceAndSnapshot =
            std::pair<sp<DisplayDevice>, display::PhysicalDisplay::SnapshotRef>;

    // Combinator for ftl::Optional<PhysicalDisplay>::and_then.
    auto getDisplayDeviceAndSnapshot() REQUIRES(mStateLock) {
        return [this](const display::PhysicalDisplay& display) REQUIRES(
                       mStateLock) -> ftl::Optional<DisplayDeviceAndSnapshot> {
            if (auto device = getDisplayDeviceLocked(display.snapshot().displayId())) {
                return std::make_pair(std::move(device), display.snapshotRef());
            }

            return {};
        };
    }

    // Returns the first display that matches a `bool(const DisplayDevice&)` predicate.
    template <typename Predicate>
    sp<DisplayDevice> findDisplay(Predicate p) const REQUIRES(mStateLock) {
        const auto it = std::find_if(mDisplays.begin(), mDisplays.end(),
                                     [&](const auto& pair)
                                             REQUIRES(mStateLock) { return p(*pair.second); });

        return it == mDisplays.end() ? nullptr : it->second;
    }

    std::vector<PhysicalDisplayId> getPhysicalDisplayIdsLocked() const REQUIRES(mStateLock);

    // mark a region of a layer stack dirty. this updates the dirty
    // region of all screens presenting this layer stack.
    void invalidateLayerStack(const ui::LayerFilter& layerFilter, const Region& dirty);

    ui::LayerFilter makeLayerFilterForDisplay(DisplayId displayId, ui::LayerStack layerStack)
            REQUIRES(mStateLock) {
        return {layerStack,
                PhysicalDisplayId::tryCast(displayId)
                        .and_then(display::getPhysicalDisplay(mPhysicalDisplays))
                        .transform(&display::PhysicalDisplay::isInternal)
                        .value_or(false)};
    }

    /*
     * H/W composer
     */
    // The following thread safety rules apply when accessing HWComposer:
    // 1. When reading display state from HWComposer on the main thread, it's not necessary to
    //    acquire mStateLock.
    // 2. When accessing HWComposer on a thread other than the main thread, we always
    //    need to acquire mStateLock. This is because the main thread could be
    //    in the process of writing display state, e.g. creating or destroying a display.
    HWComposer& getHwComposer() const;

    /*
     * Compositing
     */
    void postComposition(PhysicalDisplayId pacesetterId, const scheduler::FrameTargeters&,
                         nsecs_t presentStartTime) REQUIRES(kMainThreadContext);

    /*
     * Display management
     */
    std::pair<DisplayModes, DisplayModePtr> loadDisplayModes(PhysicalDisplayId) const
            REQUIRES(mStateLock);

    // TODO(b/241285876): Move to DisplayConfigurator.
    //
    // Returns whether displays have been added/changed/removed, i.e. whether ICompositor should
    // commit display transactions.
    bool configureLocked() REQUIRES(mStateLock) REQUIRES(kMainThreadContext)
            EXCLUDES(mHotplugMutex);

    // Returns a string describing the hotplug, or nullptr if it was rejected.
    const char* processHotplug(PhysicalDisplayId, hal::HWDisplayId, bool connected,
                               DisplayIdentificationInfo&&) REQUIRES(mStateLock)
            REQUIRES(kMainThreadContext);

    sp<DisplayDevice> setupNewDisplayDeviceInternal(
            const wp<IBinder>& displayToken,
            std::shared_ptr<compositionengine::Display> compositionDisplay,
            const DisplayDeviceState& state,
            const sp<compositionengine::DisplaySurface>& displaySurface,
            const sp<IGraphicBufferProducer>& producer) REQUIRES(mStateLock);
    void processDisplayChangesLocked() REQUIRES(mStateLock, kMainThreadContext);
    void processDisplayRemoved(const wp<IBinder>& displayToken)
            REQUIRES(mStateLock, kMainThreadContext);
    void processDisplayChanged(const wp<IBinder>& displayToken,
                               const DisplayDeviceState& currentState,
                               const DisplayDeviceState& drawingState)
            REQUIRES(mStateLock, kMainThreadContext);

    void dispatchDisplayHotplugEvent(PhysicalDisplayId, bool connected);
    void dispatchDisplayModeChangeEvent(PhysicalDisplayId, const scheduler::FrameRateMode&)
            REQUIRES(mStateLock);

    /*
     * VSYNC
     */
    nsecs_t getVsyncPeriodFromHWC() const REQUIRES(mStateLock);

    /*
     * Display identification
     */
    sp<display::DisplayToken> getPhysicalDisplayTokenLocked(PhysicalDisplayId displayId) const
            REQUIRES(mStateLock) {
        return mPhysicalDisplays.get(displayId)
                .transform([](const display::PhysicalDisplay& display) { return display.token(); })
                .or_else([] { return std::optional<sp<display::DisplayToken>>(nullptr); })
                .value();
    }

    std::optional<PhysicalDisplayId> getPhysicalDisplayIdLocked(
            const sp<display::DisplayToken>&) const REQUIRES(mStateLock);

    // Returns the first display connected at boot.
    //
    // TODO(b/229851933): SF conflates the primary display with the first display connected at boot,
    // which typically has DisplayConnectionType::Internal. (Theoretically, it must be an internal
    // display because SF does not support disconnecting it, though in practice HWC may circumvent
    // this limitation.)
    sp<IBinder> getPrimaryDisplayTokenLocked() const REQUIRES(mStateLock) {
        return getPhysicalDisplayTokenLocked(getPrimaryDisplayIdLocked());
    }

    PhysicalDisplayId getPrimaryDisplayIdLocked() const REQUIRES(mStateLock) {
        return getHwComposer().getPrimaryDisplayId();
    }

    // Toggles use of HAL/GPU virtual displays.
    void enableHalVirtualDisplays(bool);

    // Virtual display lifecycle for ID generation and HAL allocation.
    VirtualDisplayId acquireVirtualDisplay(ui::Size, ui::PixelFormat, bool canAllocateHwcForVDS)
            REQUIRES(mStateLock);
    void releaseVirtualDisplay(VirtualDisplayId);

    // Returns a display other than `mActiveDisplayId` that can be activated, if any.
    sp<DisplayDevice> getActivatableDisplay() const REQUIRES(mStateLock, kMainThreadContext);

    void onActiveDisplayChangedLocked(const DisplayDevice* inactiveDisplayPtr,
                                      const DisplayDevice& activeDisplay)
            REQUIRES(mStateLock, kMainThreadContext);

    void onActiveDisplaySizeChanged(const DisplayDevice&);

    /*
     * Debugging & dumpsys
     */
    void dumpAllLocked(const DumpArgs& args, const std::string& compositionLayers,
                       std::string& result) const REQUIRES(mStateLock);
    void dumpHwcLayersMinidumpLocked(std::string& result) const REQUIRES(mStateLock);

    void appendSfConfigString(std::string& result) const;
    void listLayersLocked(std::string& result) const;
    void dumpStatsLocked(const DumpArgs& args, std::string& result) const REQUIRES(mStateLock);
    void clearStatsLocked(const DumpArgs& args, std::string& result);
    void dumpTimeStats(const DumpArgs& args, bool asProto, std::string& result) const;
    void dumpFrameTimeline(const DumpArgs& args, std::string& result) const;
    void logFrameStats(TimePoint now) REQUIRES(kMainThreadContext);

    void dumpScheduler(std::string& result) const REQUIRES(mStateLock);
    void dumpEvents(std::string& result) const REQUIRES(mStateLock);
    void dumpVsync(std::string& result) const REQUIRES(mStateLock);

    void dumpCompositionDisplays(std::string& result) const REQUIRES(mStateLock);
    void dumpDisplays(std::string& result) const REQUIRES(mStateLock);
    void dumpDisplayIdentificationData(std::string& result) const REQUIRES(mStateLock);
    void dumpRawDisplayIdentificationData(const DumpArgs&, std::string& result) const;
    void dumpWideColorInfo(std::string& result) const REQUIRES(mStateLock);

    LayersProto dumpDrawingStateProto(uint32_t traceFlags) const;
    void dumpOffscreenLayersProto(LayersProto& layersProto,
                                  uint32_t traceFlags = LayerTracing::TRACE_ALL) const;
    google::protobuf::RepeatedPtrField<DisplayProto> dumpDisplayProto() const;
    void addToLayerTracing(bool visibleRegionDirty, TimePoint, VsyncId)
            REQUIRES(kMainThreadContext);

    // Dumps state from HW Composer
    void dumpHwc(std::string& result) const;
    LayersProto dumpProtoFromMainThread(uint32_t traceFlags = LayerTracing::TRACE_ALL)
            EXCLUDES(mStateLock);
    void dumpOffscreenLayers(std::string& result) EXCLUDES(mStateLock);
    void dumpPlannerInfo(const DumpArgs& args, std::string& result) const REQUIRES(mStateLock);

    status_t doDump(int fd, const DumpArgs& args, bool asProto);

    status_t dumpCritical(int fd, const DumpArgs&, bool asProto);

    status_t dumpAll(int fd, const DumpArgs& args, bool asProto) override {
        return doDump(fd, args, asProto);
    }

    static mat4 calculateColorMatrix(float saturation);

    void updateColorMatrixLocked();

    // Verify that transaction is being called by an approved process:
    // either AID_GRAPHICS or AID_SYSTEM.
    status_t CheckTransactCodeCredentials(uint32_t code);

    // Add transaction to the Transaction Queue

    /*
     * Generic Layer Metadata
     */
    const std::unordered_map<std::string, uint32_t>& getGenericLayerMetadataKeyMap() const;

    static int calculateMaxAcquiredBufferCount(Fps refreshRate,
                                               std::chrono::nanoseconds presentLatency);
    int getMaxAcquiredBufferCountForRefreshRate(Fps refreshRate) const;

    bool isHdrLayer(const frontend::LayerSnapshot& snapshot) const;

    ui::Rotation getPhysicalDisplayOrientation(DisplayId, bool isPrimary) const
            REQUIRES(mStateLock);
    void traverseLegacyLayers(const LayerVector::Visitor& visitor) const;

    sp<StartPropertySetThread> mStartPropertySetThread;
    surfaceflinger::Factory& mFactory;
    pid_t mPid;
    std::future<void> mRenderEnginePrimeCacheFuture;

    // mStateLock has conventions related to the current thread, because only
    // the main thread should modify variables protected by mStateLock.
    // - read access from a non-main thread must lock mStateLock, since the main
    // thread may modify these variables.
    // - write access from a non-main thread is not permitted.
    // - read access from the main thread can use an ftl::FakeGuard, since other
    // threads must not modify these variables.
    // - write access from the main thread must lock mStateLock, since another
    // thread may be reading these variables.
    mutable Mutex mStateLock;
    State mCurrentState{LayerVector::StateSet::Current};
    std::atomic<int32_t> mTransactionFlags = 0;
    std::atomic<uint32_t> mUniqueTransactionId = 1;
    SortedVector<sp<Layer>> mLayersPendingRemoval;

    // Buffers that have been discarded by clients and need to be evicted from per-layer caches so
    // the graphics memory can be immediately freed.
    std::vector<uint64_t> mBufferIdsToUncache;

    // global color transform states
    Daltonizer mDaltonizer;
    float mGlobalSaturationFactor = 1.0f;
    mat4 mClientColorMatrix;

    size_t mMaxGraphicBufferProducerListSize = MAX_LAYERS;
    // If there are more GraphicBufferProducers tracked by SurfaceFlinger than
    // this threshold, then begin logging.
    size_t mGraphicBufferProducerListSizeLogThreshold =
            static_cast<size_t>(0.95 * static_cast<double>(MAX_LAYERS));

    // protected by mStateLock (but we could use another lock)
    bool mLayersRemoved = false;
    bool mLayersAdded = false;

    std::atomic_bool mMustComposite = false;
    std::atomic_bool mGeometryDirty = false;

    // constant members (no synchronization needed for access)
    const nsecs_t mBootTime = systemTime();
    bool mIsUserBuild = true;

    // Can only accessed from the main thread, these members
    // don't need synchronization
    State mDrawingState{LayerVector::StateSet::Drawing};
    bool mVisibleRegionsDirty = false;

    bool mHdrLayerInfoChanged = false;

    // Used to ensure we omit a callback when HDR layer info listener is newly added but the
    // scene hasn't changed
    bool mAddingHDRLayerInfoListener = false;
    bool mIgnoreHdrCameraLayers = false;

    // Set during transaction application stage to track if the input info or children
    // for a layer has changed.
    // TODO: Also move visibleRegions over to a boolean system.
    bool mUpdateInputInfo = false;
    bool mSomeChildrenChanged;
    bool mForceTransactionDisplayChange = false;

    // Set if LayerMetadata has changed since the last LayerMetadata snapshot.
    bool mLayerMetadataSnapshotNeeded = false;

    // TODO(b/238781169) validate these on composition
    // Tracks layers that have pending frames which are candidates for being
    // latched.
    std::unordered_set<sp<Layer>, SpHash<Layer>> mLayersWithQueuedFrames;
    std::unordered_set<sp<Layer>, SpHash<Layer>> mLayersWithBuffersRemoved;
    // Tracks layers that need to update a display's dirty region.
    std::vector<sp<Layer>> mLayersPendingRefresh;
    // Sorted list of layers that were composed during previous frame. This is used to
    // avoid an expensive traversal of the layer hierarchy when there are no
    // visible region changes. Because this is a list of strong pointers, this will
    // extend the life of the layer but this list is only updated in the main thread.
    std::vector<sp<Layer>> mPreviouslyComposedLayers;

    BootStage mBootStage = BootStage::BOOTLOADER;

    struct HotplugEvent {
        hal::HWDisplayId hwcDisplayId;
        hal::Connection connection = hal::Connection::INVALID;
    };

    std::mutex mHotplugMutex;
    std::vector<HotplugEvent> mPendingHotplugEvents GUARDED_BY(mHotplugMutex);

    // Displays are composited in `mDisplays` order. Internal displays are inserted at boot and
    // never removed, so take precedence over external and virtual displays.
    //
    // May be read from any thread, but must only be written from the main thread.
    ui::DisplayMap<wp<IBinder>, const sp<DisplayDevice>> mDisplays GUARDED_BY(mStateLock);

    display::PhysicalDisplays mPhysicalDisplays GUARDED_BY(mStateLock);

    // The inner or outer display for foldables, assuming they have mutually exclusive power states.
    // Atomic because writes from onActiveDisplayChangedLocked are not always under mStateLock, but
    // reads from ISchedulerCallback::requestDisplayModes may happen concurrently.
    std::atomic<PhysicalDisplayId> mActiveDisplayId GUARDED_BY(mStateLock);

    struct {
        DisplayIdGenerator<GpuVirtualDisplayId> gpu;
        std::optional<DisplayIdGenerator<HalVirtualDisplayId>> hal;
    } mVirtualDisplayIdGenerators;

    std::atomic_uint mDebugFlashDelay = 0;
    std::atomic_bool mDebugDisableHWC = false;
    std::atomic_bool mDebugDisableTransformHint = false;
    std::atomic<nsecs_t> mDebugInTransaction = 0;
    std::atomic_bool mForceFullDamage = false;

    bool mLayerCachingEnabled = false;
    bool mBackpressureGpuComposition = false;

    LayerTracing mLayerTracing;
    bool mLayerTracingEnabled = false;

    std::optional<TransactionTracing> mTransactionTracing;
    std::atomic<bool> mTracingEnabledChanged = false;

    const std::shared_ptr<TimeStats> mTimeStats;
    const std::unique_ptr<FrameTracer> mFrameTracer;
    const std::unique_ptr<frametimeline::FrameTimeline> mFrameTimeline;

    VsyncId mLastCommittedVsyncId;

    // If blurs should be enabled on this device.
    bool mSupportsBlur = false;

    TransactionCallbackInvoker mTransactionCallbackInvoker;

    // We maintain a pool of pre-generated texture names to hand out to avoid
    // layer creation needing to run on the main thread (which it would
    // otherwise need to do to access RenderEngine).
    std::mutex mTexturePoolMutex;
    uint32_t mTexturePoolSize = 0;
    std::vector<uint32_t> mTexturePool;

    std::atomic<size_t> mNumLayers = 0;

    // to linkToDeath
    sp<IBinder> mWindowManager;
    // We want to avoid multiple calls to BOOT_FINISHED as they come in on
    // different threads without a lock and could trigger unsynchronized writes to
    // to mWindowManager or mInputFlinger
    std::atomic<bool> mBootFinished = false;

    std::thread::id mMainThreadId = std::this_thread::get_id();

    DisplayColorSetting mDisplayColorSetting = DisplayColorSetting::kEnhanced;

    // Color mode forced by setting persist.sys.sf.color_mode, it must:
    //     1. not be NATIVE color mode, NATIVE color mode means no forced color mode;
    //     2. be one of the supported color modes returned by hardware composer, otherwise
    //        it will not be respected.
    // persist.sys.sf.color_mode will only take effect when persist.sys.sf.native_mode
    // is not set to 1.
    // This property can be used to force SurfaceFlinger to always pick a certain color mode.
    ui::ColorMode mForceColorMode = ui::ColorMode::NATIVE;

    // Whether to enable wide color gamut (e.g. Display P3) for internal displays that support it.
    // If false, wide color modes are filtered out for all internal displays.
    bool mSupportsWideColor = false;

    ui::Dataspace mDefaultCompositionDataspace;
    ui::Dataspace mWideColorGamutCompositionDataspace;
    ui::Dataspace mColorSpaceAgnosticDataspace;
    float mDimmingRatio = -1.f;

    std::unique_ptr<renderengine::RenderEngine> mRenderEngine;
    std::atomic<int> mNumTrustedPresentationListeners = 0;

    std::unique_ptr<compositionengine::CompositionEngine> mCompositionEngine;

    CompositionCoveragePerDisplay mCompositionCoverage;

    // mMaxRenderTargetSize is only set once in init() so it doesn't need to be protected by
    // any mutex.
    size_t mMaxRenderTargetSize{1};

    const std::string mHwcServiceName;

    /*
     * Scheduler
     */
    std::unique_ptr<scheduler::Scheduler> mScheduler;
    scheduler::ConnectionHandle mAppConnectionHandle;
    scheduler::ConnectionHandle mSfConnectionHandle;

    // Stores phase offsets configured per refresh rate.
    std::unique_ptr<scheduler::VsyncConfiguration> mVsyncConfiguration;

    std::unique_ptr<scheduler::RefreshRateStats> mRefreshRateStats;
    scheduler::PresentLatencyTracker mPresentLatencyTracker GUARDED_BY(kMainThreadContext);

    bool mLumaSampling = true;
    sp<RegionSamplingThread> mRegionSamplingThread;
    sp<FpsReporter> mFpsReporter;
    sp<TunnelModeEnabledReporter> mTunnelModeEnabledReporter;
    ui::DisplayPrimaries mInternalDisplayPrimaries;

    const float mEmulatedDisplayDensity;
    const float mInternalDisplayDensity;

    // Should only be accessed by the main thread.
    sp<os::IInputFlinger> mInputFlinger;
    InputWindowCommands mInputWindowCommands;

    std::unique_ptr<Hwc2::PowerAdvisor> mPowerAdvisor;

    void enableRefreshRateOverlay(bool enable) REQUIRES(mStateLock, kMainThreadContext);

    // Flag used to set override desired display mode from backdoor
    bool mDebugDisplayModeSetByBackdoor = false;

    // A set of layers that have no parent so they are not drawn on screen.
    // Should only be accessed by the main thread.
    // The Layer pointer is removed from the set when the destructor is called so there shouldn't
    // be any issues with a raw pointer referencing an invalid object.
    std::unordered_set<Layer*> mOffscreenLayers;

    BufferCountTracker mBufferCountTracker;

    std::unordered_map<DisplayId, sp<HdrLayerInfoReporter>> mHdrLayerInfoListeners
            GUARDED_BY(mStateLock);

    mutable std::mutex mCreatedLayersLock;

    // A temporay pool that store the created layers and will be added to current state in main
    // thread.
    std::vector<LayerCreatedState> mCreatedLayers GUARDED_BY(mCreatedLayersLock);
    bool commitCreatedLayers(VsyncId, std::vector<LayerCreatedState>& createdLayers);
    void handleLayerCreatedLocked(const LayerCreatedState&, VsyncId) REQUIRES(mStateLock);

    mutable std::mutex mMirrorDisplayLock;
    struct MirrorDisplayState {
        MirrorDisplayState(ui::LayerStack layerStack, sp<IBinder>& rootHandle,
                           const sp<Client>& client)
              : layerStack(layerStack), rootHandle(rootHandle), client(client) {}

        ui::LayerStack layerStack;
        sp<IBinder> rootHandle;
        const sp<Client> client;
    };
    std::vector<MirrorDisplayState> mMirrorDisplays GUARDED_BY(mMirrorDisplayLock);
    bool commitMirrorDisplays(VsyncId);

    std::atomic<ui::Transform::RotationFlags> mActiveDisplayTransformHint;

    // Must only be accessed on the main thread.
    // TODO (b/259407931): Remove.
    static ui::Transform::RotationFlags sActiveDisplayRotationFlags;

    bool isRefreshRateOverlayEnabled() const REQUIRES(mStateLock) {
        return hasDisplay(
                [](const auto& display) { return display.isRefreshRateOverlayEnabled(); });
    }
    std::function<std::vector<std::pair<Layer*, sp<LayerFE>>>()> getLayerSnapshotsForScreenshots(
            std::optional<ui::LayerStack> layerStack, uint32_t uid,
            std::function<bool(const frontend::LayerSnapshot&, bool& outStopTraversal)>
                    snapshotFilterFn);
    std::function<std::vector<std::pair<Layer*, sp<LayerFE>>>()> getLayerSnapshotsForScreenshots(
            std::optional<ui::LayerStack> layerStack, uint32_t uid,
            std::unordered_set<uint32_t> excludeLayerIds);
    std::function<std::vector<std::pair<Layer*, sp<LayerFE>>>()> getLayerSnapshotsForScreenshots(
            uint32_t rootLayerId, uint32_t uid, std::unordered_set<uint32_t> excludeLayerIds,
            bool childrenOnly, const std::optional<FloatRect>& optionalParentCrop);

    const sp<WindowInfosListenerInvoker> mWindowInfosListenerInvoker;

    FlagManager mFlagManager;

    // returns the framerate of the layer with the given sequence ID
    float getLayerFramerate(nsecs_t now, int32_t id) const {
        return mScheduler->getLayerFramerate(now, id);
    }

    bool mPowerHintSessionEnabled;

    bool mLayerLifecycleManagerEnabled = false;
    bool mLegacyFrontEndEnabled = true;

    frontend::LayerLifecycleManager mLayerLifecycleManager;
    frontend::LayerHierarchyBuilder mLayerHierarchyBuilder{{}};
    frontend::LayerSnapshotBuilder mLayerSnapshotBuilder;

    std::vector<uint32_t> mDestroyedHandles;
    std::vector<std::unique_ptr<frontend::RequestedLayerState>> mNewLayers;
    std::vector<LayerCreationArgs> mNewLayerArgs;
    // These classes do not store any client state but help with managing transaction callbacks
    // and stats.
    std::unordered_map<uint32_t, sp<Layer>> mLegacyLayers;

    TransactionHandler mTransactionHandler;
    ui::DisplayMap<ui::LayerStack, frontend::DisplayInfo> mFrontEndDisplayInfos;
    bool mFrontEndDisplayInfosChanged = false;

    // WindowInfo ids visible during the last commit.
    std::unordered_set<int32_t> mVisibleWindowIds;
};

class SurfaceComposerAIDL : public gui::BnSurfaceComposer {
public:
    SurfaceComposerAIDL(sp<SurfaceFlinger> sf) : mFlinger(std::move(sf)) {}

    binder::Status bootFinished() override;
    binder::Status createDisplayEventConnection(
            VsyncSource vsyncSource, EventRegistration eventRegistration,
            const sp<IBinder>& layerHandle,
            sp<gui::IDisplayEventConnection>* outConnection) override;
    binder::Status createConnection(sp<gui::ISurfaceComposerClient>* outClient) override;
    binder::Status createDisplay(const std::string& displayName, bool secure,
                                 float requestedRefreshRate, sp<IBinder>* outDisplay) override;
    binder::Status destroyDisplay(const sp<IBinder>& display) override;
    binder::Status getPhysicalDisplayIds(std::vector<int64_t>* outDisplayIds) override;
    binder::Status getPhysicalDisplayToken(int64_t displayId, sp<IBinder>* outDisplay) override;
    binder::Status setPowerMode(const sp<IBinder>& display, int mode) override;
    binder::Status getSupportedFrameTimestamps(std::vector<FrameEvent>* outSupported) override;
    binder::Status getDisplayStats(const sp<IBinder>& display,
                                   gui::DisplayStatInfo* outStatInfo) override;
    binder::Status getDisplayState(const sp<IBinder>& display,
                                   gui::DisplayState* outState) override;
    binder::Status getStaticDisplayInfo(int64_t displayId,
                                        gui::StaticDisplayInfo* outInfo) override;
    binder::Status getDynamicDisplayInfoFromId(int64_t displayId,
                                               gui::DynamicDisplayInfo* outInfo) override;
    binder::Status getDynamicDisplayInfoFromToken(const sp<IBinder>& display,
                                                  gui::DynamicDisplayInfo* outInfo) override;
    binder::Status getDisplayNativePrimaries(const sp<IBinder>& display,
                                             gui::DisplayPrimaries* outPrimaries) override;
    binder::Status setActiveColorMode(const sp<IBinder>& display, int colorMode) override;
    binder::Status setBootDisplayMode(const sp<IBinder>& display, int displayModeId) override;
    binder::Status clearBootDisplayMode(const sp<IBinder>& display) override;
    binder::Status getBootDisplayModeSupport(bool* outMode) override;
    binder::Status getOverlaySupport(gui::OverlayProperties* outProperties) override;
    binder::Status getHdrConversionCapabilities(
            std::vector<gui::HdrConversionCapability>*) override;
    binder::Status setHdrConversionStrategy(const gui::HdrConversionStrategy& hdrConversionStrategy,
                                            int32_t*) override;
    binder::Status getHdrOutputConversionSupport(bool* outSupport) override;
    binder::Status setAutoLowLatencyMode(const sp<IBinder>& display, bool on) override;
    binder::Status setGameContentType(const sp<IBinder>& display, bool on) override;
    binder::Status captureDisplay(const DisplayCaptureArgs&,
                                  const sp<IScreenCaptureListener>&) override;
    binder::Status captureDisplayById(int64_t, const sp<IScreenCaptureListener>&) override;
    binder::Status captureLayers(const LayerCaptureArgs&,
                                 const sp<IScreenCaptureListener>&) override;

    // TODO(b/239076119): Remove deprecated AIDL.
    [[deprecated]] binder::Status clearAnimationFrameStats() override {
        return binder::Status::ok();
    }
    [[deprecated]] binder::Status getAnimationFrameStats(gui::FrameStats*) override {
        return binder::Status::ok();
    }

    binder::Status overrideHdrTypes(const sp<IBinder>& display,
                                    const std::vector<int32_t>& hdrTypes) override;
    binder::Status onPullAtom(int32_t atomId, gui::PullAtomData* outPullData) override;
    binder::Status getLayerDebugInfo(std::vector<gui::LayerDebugInfo>* outLayers) override;
    binder::Status getColorManagement(bool* outGetColorManagement) override;
    binder::Status getCompositionPreference(gui::CompositionPreference* outPref) override;
    binder::Status getDisplayedContentSamplingAttributes(
            const sp<IBinder>& display, gui::ContentSamplingAttributes* outAttrs) override;
    binder::Status setDisplayContentSamplingEnabled(const sp<IBinder>& display, bool enable,
                                                    int8_t componentMask,
                                                    int64_t maxFrames) override;
    binder::Status getDisplayedContentSample(const sp<IBinder>& display, int64_t maxFrames,
                                             int64_t timestamp,
                                             gui::DisplayedFrameStats* outStats) override;
    binder::Status getProtectedContentSupport(bool* outSupporte) override;
    binder::Status isWideColorDisplay(const sp<IBinder>& token,
                                      bool* outIsWideColorDisplay) override;
    binder::Status addRegionSamplingListener(
            const gui::ARect& samplingArea, const sp<IBinder>& stopLayerHandle,
            const sp<gui::IRegionSamplingListener>& listener) override;
    binder::Status removeRegionSamplingListener(
            const sp<gui::IRegionSamplingListener>& listener) override;
    binder::Status addFpsListener(int32_t taskId, const sp<gui::IFpsListener>& listener) override;
    binder::Status removeFpsListener(const sp<gui::IFpsListener>& listener) override;
    binder::Status addTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& listener) override;
    binder::Status removeTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& listener) override;
    binder::Status setDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                              const gui::DisplayModeSpecs&) override;
    binder::Status getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                              gui::DisplayModeSpecs* outSpecs) override;
    binder::Status getDisplayBrightnessSupport(const sp<IBinder>& displayToken,
                                               bool* outSupport) override;
    binder::Status setDisplayBrightness(const sp<IBinder>& displayToken,
                                        const gui::DisplayBrightness& brightness) override;
    binder::Status addHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                           const sp<gui::IHdrLayerInfoListener>& listener) override;
    binder::Status removeHdrLayerInfoListener(
            const sp<IBinder>& displayToken,
            const sp<gui::IHdrLayerInfoListener>& listener) override;

    binder::Status notifyPowerBoost(int boostId) override;
    binder::Status setGlobalShadowSettings(const gui::Color& ambientColor,
                                           const gui::Color& spotColor, float lightPosY,
                                           float lightPosZ, float lightRadius) override;
    binder::Status getDisplayDecorationSupport(
            const sp<IBinder>& displayToken,
            std::optional<gui::DisplayDecorationSupport>* outSupport) override;
    binder::Status setOverrideFrameRate(int32_t uid, float frameRate) override;
    binder::Status updateSmallAreaDetection(const std::vector<int32_t>& uids,
                                            const std::vector<float>& thresholds) override;
    binder::Status setSmallAreaDetectionThreshold(int32_t uid, float threshold) override;
    binder::Status getGpuContextPriority(int32_t* outPriority) override;
    binder::Status getMaxAcquiredBufferCount(int32_t* buffers) override;
    binder::Status addWindowInfosListener(const sp<gui::IWindowInfosListener>& windowInfosListener,
                                          gui::WindowInfosListenerInfo* outInfo) override;
    binder::Status removeWindowInfosListener(
            const sp<gui::IWindowInfosListener>& windowInfosListener) override;
    binder::Status getStalledTransactionInfo(int pid,
                                             std::optional<gui::StalledTransactionInfo>* outInfo);

private:
    static const constexpr bool kUsePermissionCache = true;
    status_t checkAccessPermission(bool usePermissionCache = kUsePermissionCache);
    status_t checkControlDisplayBrightnessPermission();
    status_t checkReadFrameBufferPermission();
    static void getDynamicDisplayInfoInternal(ui::DynamicDisplayInfo& info,
                                              gui::DynamicDisplayInfo*& outInfo);

private:
    sp<SurfaceFlinger> mFlinger;
};

} // namespace android
