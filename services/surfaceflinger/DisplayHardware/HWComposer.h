/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_SF_HWCOMPOSER_H
#define ANDROID_SF_HWCOMPOSER_H

#include <stdint.h>
#include <sys/types.h>

#include <hardware/hwcomposer_defs.h>

#include <ui/Fence.h>

#include <utils/BitSet.h>
#include <utils/Condition.h>
#include <utils/Mutex.h>
#include <utils/StrongPointer.h>
#include <utils/Thread.h>
#include <utils/Timers.h>
#include <utils/Vector.h>

#define MAX_LAYER_COUNT 32

extern "C" int clock_nanosleep(clockid_t clock_id, int flags,
                           const struct timespec *request,
                           struct timespec *remain);

struct hwc_composer_device_1;
struct hwc_display_contents_1;
struct hwc_layer_1;
struct hwc_procs;
struct framebuffer_device_t;

namespace android {
// ---------------------------------------------------------------------------

class Fence;
class FloatRect;
class GraphicBuffer;
class NativeHandle;
class Region;
class String8;
class SurfaceFlinger;

class HWComposer
{
public:
    class EventHandler {
        friend class HWComposer;
        virtual void onVSyncReceived(int disp, nsecs_t timestamp) = 0;
        virtual void onHotplugReceived(int disp, bool connected) = 0;
    protected:
        virtual ~EventHandler() {}
    };

    enum {
        NUM_BUILTIN_DISPLAYS = HWC_NUM_PHYSICAL_DISPLAY_TYPES,
        MAX_HWC_DISPLAYS = HWC_NUM_DISPLAY_TYPES,
        VIRTUAL_DISPLAY_ID_BASE = HWC_DISPLAY_VIRTUAL,
    };

    HWComposer(
            const sp<SurfaceFlinger>& flinger,
            EventHandler& handler);

    ~HWComposer();

    status_t initCheck() const;

    // Returns a display ID starting at VIRTUAL_DISPLAY_ID_BASE, this ID is to
    // be used with createWorkList (and all other methods requiring an ID
    // below).
    // IDs below NUM_BUILTIN_DISPLAYS are pre-defined and therefore are
    // always valid.
    // Returns -1 if an ID cannot be allocated
    int32_t allocateDisplayId();

    // Recycles the given virtual display ID and frees the associated worklist.
    // IDs below NUM_BUILTIN_DISPLAYS are not recycled.
    status_t freeDisplayId(int32_t id);


    // Asks the HAL what it can do
    status_t prepare();

    // commits the list
    status_t commit();

    // set power mode
    status_t setPowerMode(int disp, int mode);

    // set active config
    status_t setActiveConfig(int disp, int mode);

    // get active config
    int getActiveConfig(int disp) const;

    // reset state when an external, non-virtual display is disconnected
    void disconnectDisplay(int disp);

    // create a work list for numLayers layer. sets HWC_GEOMETRY_CHANGED.
    status_t createWorkList(int32_t id, size_t numLayers);

    bool supportsFramebufferTarget() const;

    // does this display have layers handled by HWC
    bool hasHwcComposition(int32_t id) const;

    // does this display have layers handled by GLES
    bool hasGlesComposition(int32_t id) const;

#ifdef QCOM_BSP
    // does this display have layers handled by BLIT HW
    bool hasBlitComposition(int32_t id) const;

    //GPUTiledRect : function to find out if DR can be used in GPU Comp.
    bool canUseTiledDR(int32_t id, Rect& dr);
#endif

    // get the releaseFence file descriptor for a display's framebuffer layer.
    // the release fence is only valid after commit()
    sp<Fence> getAndResetReleaseFence(int32_t id);

    // is VDS solution enabled
    inline bool isVDSEnabled() const { return mVDSEnabled; };

    // needed forward declarations
    class LayerListIterator;

    // return the visual id to be used to find a suitable EGLConfig for
    // *ALL* displays.
    int getVisualID() const;

    // Forwarding to FB HAL for pre-HWC-1.1 code (see FramebufferSurface).
    int fbPost(int32_t id, const sp<Fence>& acquireFence, const sp<GraphicBuffer>& buf);
    int fbCompositionComplete();
    void fbDump(String8& result);

    // Set the output buffer and acquire fence for a virtual display.
    // Returns INVALID_OPERATION if id is not a virtual display.
    status_t setOutputBuffer(int32_t id, const sp<Fence>& acquireFence,
            const sp<GraphicBuffer>& buf);

    // Get the retire fence for the last committed frame. This fence will
    // signal when the h/w composer is completely finished with the frame.
    // For physical displays, it is no longer being displayed. For virtual
    // displays, writes to the output buffer are complete.
    sp<Fence> getLastRetireFence(int32_t id) const;

    status_t setCursorPositionAsync(int32_t id, const Rect &pos);

    /*
     * Interface to hardware composer's layers functionality.
     * This abstracts the HAL interface to layers which can evolve in
     * incompatible ways from one release to another.
     * The idea is that we could extend this interface as we add
     * features to h/w composer.
     */
    class HWCLayerInterface {
    protected:
        virtual ~HWCLayerInterface() { }
    public:
        virtual int32_t getCompositionType() const = 0;
        virtual uint32_t getHints() const = 0;
        virtual sp<Fence> getAndResetReleaseFence() = 0;
        virtual void setDefaultState() = 0;
        virtual void setSkip(bool skip) = 0;
        virtual void setIsCursorLayerHint(bool isCursor = true) = 0;
        virtual void setAnimating(bool animating) = 0;
        virtual void setBlending(uint32_t blending) = 0;
        virtual void setTransform(uint32_t transform) = 0;
        virtual void setFrame(const Rect& frame) = 0;
        virtual void setCrop(const FloatRect& crop) = 0;
        virtual void setVisibleRegionScreen(const Region& reg) = 0;
        virtual void setSidebandStream(const sp<NativeHandle>& stream) = 0;
#ifdef QCOM_BSP
        virtual void setDirtyRect(const Rect& dirtyRect) = 0;
#endif
        virtual void setBuffer(const sp<GraphicBuffer>& buffer) = 0;
        virtual void setAcquireFenceFd(int fenceFd) = 0;
        virtual void setPlaneAlpha(uint8_t alpha) = 0;
        virtual void onDisplayed() = 0;
    };

    /*
     * Interface used to implement an iterator to a list
     * of HWCLayer.
     */
    class HWCLayer : public HWCLayerInterface {
        friend class LayerListIterator;
        // select the layer at the given index
        virtual status_t setLayer(size_t index) = 0;
        virtual HWCLayer* dup() = 0;
        static HWCLayer* copy(HWCLayer *rhs) {
            return rhs ? rhs->dup() : NULL;
        }
    protected:
        virtual ~HWCLayer() { }
    };

    /*
     * Iterator through a HWCLayer list.
     * This behaves more or less like a forward iterator.
     */
    class LayerListIterator {
        friend struct HWComposer;
        HWCLayer* const mLayerList;
        size_t mIndex;

        LayerListIterator() : mLayerList(NULL), mIndex(0) { }

        LayerListIterator(HWCLayer* layer, size_t index)
            : mLayerList(layer), mIndex(index) { }

        // we don't allow assignment, because we don't need it for now
        LayerListIterator& operator = (const LayerListIterator& rhs);

    public:
        // copy operators
        LayerListIterator(const LayerListIterator& rhs)
            : mLayerList(HWCLayer::copy(rhs.mLayerList)), mIndex(rhs.mIndex) {
        }

        ~LayerListIterator() { delete mLayerList; }

        // pre-increment
        LayerListIterator& operator++() {
            mLayerList->setLayer(++mIndex);
            return *this;
        }

        // dereference
        HWCLayerInterface& operator * () { return *mLayerList; }
        HWCLayerInterface* operator -> () { return mLayerList; }

        // comparison
        bool operator == (const LayerListIterator& rhs) const {
            return mIndex == rhs.mIndex;
        }
        bool operator != (const LayerListIterator& rhs) const {
            return !operator==(rhs);
        }
    };

    // Returns an iterator to the beginning of the layer list
    LayerListIterator begin(int32_t id);

    // Returns an iterator to the end of the layer list
    LayerListIterator end(int32_t id);


    // Events handling ---------------------------------------------------------

    enum {
        EVENT_VSYNC = HWC_EVENT_VSYNC,
        EVENT_ORIENTATION = HWC_EVENT_ORIENTATION
    };

    void eventControl(int disp, int event, int enabled);

    struct DisplayConfig {
        uint32_t width;
        uint32_t height;
        float xdpi;
        float ydpi;
#ifdef QCOM_BSP
        bool secure;
#endif
        nsecs_t refresh;
    };

    // Query display parameters.  Pass in a display index (e.g.
    // HWC_DISPLAY_PRIMARY).
    nsecs_t getRefreshTimestamp(int disp) const;
    sp<Fence> getDisplayFence(int disp) const;
    uint32_t getFormat(int disp) const;
    bool isConnected(int disp) const;
#ifdef QCOM_BSP
    bool isSecure(int disp) const;
#endif

    // These return the values for the current config of a given display index.
    // To get the values for all configs, use getConfigs below.
    uint32_t getWidth(int disp) const;
    uint32_t getHeight(int disp) const;
    float getDpiX(int disp) const;
    float getDpiY(int disp) const;
    nsecs_t getRefreshPeriod(int disp) const;

    const Vector<DisplayConfig>& getConfigs(int disp) const;
    size_t getCurrentConfig(int disp) const;

    status_t setVirtualDisplayProperties(int32_t id, uint32_t w, uint32_t h,
            uint32_t format);

    // this class is only used to fake the VSync event on systems that don't
    // have it.
    class VSyncThread : public Thread {
        HWComposer& mHwc;
        mutable Mutex mLock;
        Condition mCondition;
        bool mEnabled;
        mutable nsecs_t mNextFakeVSync;
        nsecs_t mRefreshPeriod;
        virtual void onFirstRef();
        virtual bool threadLoop();
    public:
        VSyncThread(HWComposer& hwc);
        void setEnabled(bool enabled);
    };

    friend class VSyncThread;

    // for debugging ----------------------------------------------------------
    void dump(String8& out) const;

private:
    void loadHwcModule();
    int loadFbHalModule();

    LayerListIterator getLayerIterator(int32_t id, size_t index);

    struct cb_context;

    static void hook_invalidate(const struct hwc_procs* procs);
    static void hook_vsync(const struct hwc_procs* procs, int disp,
            int64_t timestamp);
    static void hook_hotplug(const struct hwc_procs* procs, int disp,
            int connected);

    inline void invalidate();
    inline void vsync(int disp, int64_t timestamp);
    inline void hotplug(int disp, int connected);

    status_t queryDisplayProperties(int disp);

    status_t setFramebufferTarget(int32_t id,
            const sp<Fence>& acquireFence, const sp<GraphicBuffer>& buf);

    struct DisplayData {
        DisplayData();
        ~DisplayData();
        Vector<DisplayConfig> configs;
        size_t currentConfig;
        uint32_t format;    // pixel format from FB hal, for pre-hwc-1.1
        bool connected;
        bool hasFbComp;
        bool hasOvComp;
#ifdef QCOM_BSP
        bool hasBlitComp;
#endif
        size_t capacity;
        hwc_display_contents_1* list;
        hwc_layer_1* framebufferTarget;
        buffer_handle_t fbTargetHandle;
        sp<Fence> lastRetireFence;  // signals when the last set op retires
        sp<Fence> lastDisplayFence; // signals when the last set op takes
                                    // effect on screen
        buffer_handle_t outbufHandle;
        sp<Fence> outbufAcquireFence;

        // protected by mEventControlLock
        int32_t events;
    };

    sp<SurfaceFlinger>              mFlinger;
    framebuffer_device_t*           mFbDev;
    struct hwc_composer_device_1*   mHwc;
    // invariant: mLists[0] != NULL iff mHwc != NULL
    // mLists[i>0] can be NULL. that display is to be ignored
    struct hwc_display_contents_1*  mLists[MAX_HWC_DISPLAYS];
    DisplayData                     mDisplayData[MAX_HWC_DISPLAYS];
    size_t                          mNumDisplays;

    cb_context*                     mCBContext;
    EventHandler&                   mEventHandler;
    size_t                          mVSyncCounts[HWC_NUM_PHYSICAL_DISPLAY_TYPES];
    sp<VSyncThread>                 mVSyncThread;
    bool                            mDebugForceFakeVSync;
    BitSet32                        mAllocatedDisplayIDs;
    bool                            mVDSEnabled;
    // protected by mLock
    mutable Mutex mLock;
    // synchronization between Draw call and Dumpsys call
    mutable Mutex mDrawLock;
    mutable nsecs_t mLastHwVSync[HWC_NUM_PHYSICAL_DISPLAY_TYPES];

    // thread-safe
    mutable Mutex mEventControlLock;

    //GPUTileRect : CompMap, class to track the composition type of layers
    struct CompMap {
        int32_t count;
        int32_t compType[MAX_LAYER_COUNT];
        CompMap () {
            reset();
        }
        void reset () {
            count=0;
            for(size_t i= 0; i <MAX_LAYER_COUNT; i++) {
                compType[i] = -1;
            }
        }
        CompMap& operator=(const CompMap &rhs) {
            if(this != &rhs) {
                reset();
                count = rhs.count;
                for(int32_t i=0; i<count; i++) {
                    compType[i] = rhs.compType[i];
                }
            }
            return *this;
        }
        bool operator== (CompMap &rhs) {
            if( count != rhs.count)
                return false;
            for(int32_t i=0; i<count; i++) {
                if(compType[i] != rhs.compType[i])
                    return false;
            }
            return true;
        }
    };

#ifdef QCOM_BSP
    //GPUTileRect Optimization Functions.
    CompMap prev_comp_map[MAX_HWC_DISPLAYS], current_comp_map[MAX_HWC_DISPLAYS];
    bool isCompositionMapChanged(int32_t id);
    bool isGeometryChanged(int32_t id);
    void computeUnionDirtyRect(int32_t id, Rect& unionDirtyRect);
    bool areVisibleRegionsOverlapping(int32_t id );
    bool needsScaling(int32_t id);
    float mDynThreshold;
    bool canHandleOverlapArea(int32_t id, Rect unionDr);
#endif
};

// ---------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_SF_HWCOMPOSER_H
