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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

// Uncomment this to remove support for HWC_DEVICE_API_VERSION_0_3 and older
// #define HWC_REMOVE_DEPRECATED_VERSIONS 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/misc.h>
#include <utils/String8.h>
#include <utils/Thread.h>
#include <utils/Trace.h>
#include <utils/Vector.h>

#include <ui/GraphicBuffer.h>

#include <hardware/hardware.h>
#include <hardware/hwcomposer.h>

#include <cutils/log.h>
#include <cutils/properties.h>

#include "Layer.h"           // needed only for debugging
#include "LayerBase.h"
#include "HWComposer.h"
#include "SurfaceFlinger.h"
#include <utils/CallStack.h>

namespace android {

// ---------------------------------------------------------------------------
// Support for HWC_DEVICE_API_VERSION_0_3 and older:
// Since v0.3 is deprecated and support will be dropped soon, as much as
// possible the code is written to target v1.0. When using a v0.3 HWC, we
// allocate v0.3 structures, but assign them to v1.0 pointers.

#if HWC_REMOVE_DEPRECATED_VERSIONS
// We need complete types to satisfy semantic checks, even though the code
// paths that use these won't get executed at runtime (and will likely be dead-
// code-eliminated). When we remove the code to support v0.3 we can remove
// these as well.
typedef hwc_layer_1_t hwc_layer_t;
typedef hwc_display_contents_1_t hwc_layer_list_t;
typedef hwc_composer_device_1_t hwc_composer_device_t;
#endif

// This function assumes we've already rejected HWC's with lower-than-required
// versions. Don't use it for the initial "does HWC meet requirements" check!

#define MIN_HWC_HEADER_VERSION 0


static uint32_t hwcApiVersion(const hwc_composer_device_1_t* hwc) {
    uint32_t hwcVersion = hwc->common.version;
    if (MIN_HWC_HEADER_VERSION == 0 &&
            (hwcVersion & HARDWARE_API_VERSION_2_MAJ_MIN_MASK) == 0) {
        // legacy version encoding
        hwcVersion <<= 16;
    }
    return hwcVersion & HARDWARE_API_VERSION_2_MAJ_MIN_MASK;
}

static uint32_t hwcHeaderVersion(const hwc_composer_device_1_t* hwc) {
    uint32_t hwcVersion = hwc->common.version;
    if (MIN_HWC_HEADER_VERSION == 0 &&
            (hwcVersion & HARDWARE_API_VERSION_2_MAJ_MIN_MASK) == 0) {
        // legacy version encoding
        hwcVersion <<= 16;
    }
    return hwcVersion & HARDWARE_API_VERSION_2_HEADER_MASK;
}

static bool hwcHasApiVersion(const hwc_composer_device_1_t* hwc,
        uint32_t version) {
    return hwcApiVersion(hwc) >= (version & HARDWARE_API_VERSION_2_MAJ_MIN_MASK);
}

static bool hwcHasVsyncEvent(const hwc_composer_device_1_t* hwc) {
    return hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_0_3);
}

static size_t sizeofHwcLayerList(const hwc_composer_device_1_t* hwc,
        size_t numLayers) {
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_1_0)) {
        return sizeof(hwc_display_contents_1_t) + numLayers*sizeof(hwc_layer_1_t);
    } else {
        return sizeof(hwc_layer_list_t) + numLayers*sizeof(hwc_layer_t);
    }
}

static int hwcEventControl(hwc_composer_device_1_t* hwc, int dpy,
        int event, int enabled) {
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_1_0)) {
        return hwc->eventControl(hwc, dpy, event, enabled);
    } else {
        hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(hwc);
        return hwc0->methods->eventControl(hwc0, event, enabled);
    }
}

static int hwcBlank(hwc_composer_device_1_t* hwc, int dpy, int blank) {
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_1_0)) {
        return hwc->blank(hwc, dpy, blank);
    } else {
        if (blank) {
            hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(hwc);
            return hwc0->set(hwc0, NULL, NULL, NULL);
        } else {
            // HWC 0.x turns the screen on at the next set()
            return NO_ERROR;
        }
    }
}

static int hwcPrepare(hwc_composer_device_1_t* hwc,
        size_t numDisplays, hwc_display_contents_1_t** displays) {
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_1_0)) {
        return hwc->prepare(hwc, numDisplays, displays);
    } else {
        hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(hwc);
        hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(displays[0]);
        // In the past, SurfaceFlinger would pass a NULL list when doing full
        // OpenGL ES composition. I don't know what, if any, dependencies there
        // are on this behavior, so I'm playing it safe and preserving it.
        // ... and I'm removing it. NULL layers kill the Tegra compositor (RC, Nov 2012)
        /*if (list0->numHwLayers == 0)
            return hwc0->prepare(hwc0, NULL);
        else*/
            return hwc0->prepare(hwc0, list0);
    }
}
static int hwcSet(hwc_composer_device_1_t* hwc, EGLDisplay dpy, EGLSurface sur,
        size_t numDisplays, hwc_display_contents_1_t** displays) {
    int err;
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_1_0)) {
        displays[0]->dpy = dpy;
        displays[0]->sur = sur;
        err = hwc->set(hwc, numDisplays, displays);
    } else {
        hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(hwc);
        hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(displays[0]);
        err = hwc0->set(hwc0, dpy, sur, list0);
    }
    return err;
}

static uint32_t& hwcFlags(hwc_composer_device_1_t* hwc,
        hwc_display_contents_1_t* display) {
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_1_0)) {
        return display->flags;
    } else {
        hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(display);
        return list0->flags;
    }
}

static size_t& hwcNumHwLayers(hwc_composer_device_1_t* hwc,
        hwc_display_contents_1_t* display) {
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_1_0)) {
        return display->numHwLayers;
    } else {
        hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(display);
        return list0->numHwLayers;
    }
}

static void hwcDump(hwc_composer_device_1_t* hwc, char* buff, int buff_len) {
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_1_0)) {
        if (hwc->dump)
            hwc->dump(hwc, buff, buff_len);
    } else if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_0_1)) {
        hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(hwc);
        if (hwc0->dump)
            hwc0->dump(hwc0, buff, buff_len);
    }
}

// ---------------------------------------------------------------------------

struct HWComposer::cb_context {
    struct callbacks : public hwc_procs_t {
        // these are here to facilitate the transition when adding
        // new callbacks (an implementation can check for NULL before
        // calling a new callback).
        void (*zero[4])(void);
    };
    callbacks procs;
    HWComposer* hwc;
};

// ---------------------------------------------------------------------------

HWComposer::HWComposer(
        const sp<SurfaceFlinger>& flinger,
        EventHandler& handler)
    : mFlinger(flinger),
      mFbDev(0), mHwc(0), mNumDisplays(1),
      mCBContext(new cb_context),
      mEventHandler(handler),
      mVSyncCount(0), mDebugForceFakeVSync(false)
{
    for (size_t i =0 ; i<MAX_DISPLAYS ; i++) {
        mLists[i] = 0;
    }

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.no_hw_vsync", value, "0");
    mDebugForceFakeVSync = atoi(value);

    bool needVSyncThread = true;

    // Note: some devices may insist that the FB HAL be opened before HWC.
    loadFbHalModule();
    loadHwcModule();

    if (mFbDev && mHwc && hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
        // close FB HAL if we don't needed it.
        // FIXME: this is temporary until we're not forced to open FB HAL
        // before HWC.
        framebuffer_close(mFbDev);
        mFbDev = NULL;
    }

    // If we have no HWC, or a pre-1.1 HWC, an FB dev is mandatory.
    if ((!mHwc || !hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1))
            && !mFbDev) {
        ALOGE("ERROR: failed to open framebuffer, aborting");
        abort();
    }

    // these display IDs are always reserved
    for (size_t i=0 ; i<HWC_NUM_DISPLAY_TYPES ; i++) {
        mAllocatedDisplayIDs.markBit(i);
    }

    if (mHwc) {
        ALOGI("Using %s version %u.%u", HWC_HARDWARE_COMPOSER,
              (hwcApiVersion(mHwc) >> 24) & 0xff,
              (hwcApiVersion(mHwc) >> 16) & 0xff);
        if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0)) {
            if (mHwc->registerProcs) {
                mCBContext->hwc = this;
                mCBContext->procs.invalidate = &hook_invalidate;
                mCBContext->procs.vsync = &hook_vsync;
                if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1))
                    mCBContext->procs.hotplug = &hook_hotplug;
                else
                    mCBContext->procs.hotplug = NULL;
                memset(mCBContext->procs.zero, 0, sizeof(mCBContext->procs.zero));
                mHwc->registerProcs(mHwc, &mCBContext->procs);
            }
        } else {
            hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(mHwc);
            if (hwc0->registerProcs) {
                mCBContext->hwc = this;
                mCBContext->procs.invalidate = &hook_invalidate;
                mCBContext->procs.vsync = &hook_vsync;
                memset(mCBContext->procs.zero, 0, sizeof(mCBContext->procs.zero));
                hwc0->registerProcs(hwc0, &mCBContext->procs);
            }
        }

        // don't need a vsync thread if we have a hardware composer
        needVSyncThread = false;
        // always turn vsync off when we start
        if (hwcHasVsyncEvent(mHwc)) {
            eventControl(HWC_DISPLAY_PRIMARY, HWC_EVENT_VSYNC, 0);

            // the number of displays we actually have depends on the
            // hw composer version
            if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_2)) {
                // 1.2 adds support for virtual displays
                mNumDisplays = MAX_DISPLAYS;
            } else if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
                // 1.1 adds support for multiple displays
                mNumDisplays = HWC_NUM_DISPLAY_TYPES;
            } else {
                mNumDisplays = 1;
            }
        } else {
            needVSyncThread = true;
            mNumDisplays = 1;
        }
    }

    if (mFbDev) {
        ALOG_ASSERT(!(mHwc && hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)),
                "should only have fbdev if no hwc or hwc is 1.0");

        DisplayData& disp(mDisplayData[HWC_DISPLAY_PRIMARY]);
        disp.connected = true;
        disp.width = mFbDev->width;
        disp.height = mFbDev->height;
        disp.format = mFbDev->format;
        disp.xdpi = mFbDev->xdpi;
        disp.ydpi = mFbDev->ydpi;
        if (disp.refresh == 0) {
            disp.refresh = nsecs_t(1e9 / mFbDev->fps);
            ALOGW("getting VSYNC period from fb HAL: %lld", disp.refresh);
        }
        if (disp.refresh == 0) {
            disp.refresh = nsecs_t(1e9 / 60.0);
            ALOGW("getting VSYNC period from thin air: %lld",
                    mDisplayData[HWC_DISPLAY_PRIMARY].refresh);
        }
    } else if (mHwc) {
        // here we're guaranteed to have at least HWC 1.1
        for (size_t i =0 ; i<HWC_NUM_DISPLAY_TYPES ; i++) {
            queryDisplayProperties(i);
        }
    }

    if (needVSyncThread) {
        // we don't have VSYNC support, we need to fake it
        mVSyncThread = new VSyncThread(*this);
    }
}

HWComposer::~HWComposer() {
    if (mHwc) {
        eventControl(HWC_DISPLAY_PRIMARY, HWC_EVENT_VSYNC, 0);
    }
    if (mVSyncThread != NULL) {
        mVSyncThread->requestExitAndWait();
    }
    if (mHwc) {
        hwc_close_1(mHwc);
    }
    if (mFbDev) {
        framebuffer_close(mFbDev);
    }
    delete mCBContext;
}

// Load and prepare the hardware composer module.  Sets mHwc.
void HWComposer::loadHwcModule()
{
    hw_module_t const* module;

    if (hw_get_module(HWC_HARDWARE_MODULE_ID, &module) != 0) {
        ALOGE("%s module not found", HWC_HARDWARE_MODULE_ID);
        return;
    }

    int err = hwc_open_1(module, &mHwc);
    if (err) {
        ALOGE("%s device failed to initialize (%s)",
              HWC_HARDWARE_COMPOSER, strerror(-err));
        return;
    }

    if (HWC_REMOVE_DEPRECATED_VERSIONS &&
        (!hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0) ||
            hwcHeaderVersion(mHwc) < MIN_HWC_HEADER_VERSION ||
            hwcHeaderVersion(mHwc) > HWC_HEADER_VERSION)) {
        ALOGE("%s device version %#x unsupported, will not be used",
              HWC_HARDWARE_COMPOSER, mHwc->common.version);
        hwc_close_1(mHwc);
        mHwc = NULL;
        return;
    }
}

// Load and prepare the FB HAL, which uses the gralloc module.  Sets mFbDev.
void HWComposer::loadFbHalModule()
{
    hw_module_t const* module;

    if (hw_get_module(GRALLOC_HARDWARE_MODULE_ID, &module) != 0) {
        ALOGE("%s module not found", GRALLOC_HARDWARE_MODULE_ID);
        return;
    }

    int err = framebuffer_open(module, &mFbDev);
    if (err) {
        ALOGE("framebuffer_open failed (%s)", strerror(-err));
        return;
    }
}

status_t HWComposer::initCheck() const {
    return mHwc ? NO_ERROR : NO_INIT;
}

void HWComposer::hook_invalidate(const struct hwc_procs* procs) {
    cb_context* ctx = reinterpret_cast<cb_context*>(
            const_cast<hwc_procs_t*>(procs));
    ctx->hwc->invalidate();
}

void HWComposer::hook_vsync(const struct hwc_procs* procs, int disp,
        int64_t timestamp) {
    cb_context* ctx = reinterpret_cast<cb_context*>(
            const_cast<hwc_procs_t*>(procs));
    ctx->hwc->vsync(disp, timestamp);
}

void HWComposer::hook_hotplug(const struct hwc_procs* procs, int disp,
        int connected) {
    cb_context* ctx = reinterpret_cast<cb_context*>(
            const_cast<hwc_procs_t*>(procs));
    ctx->hwc->hotplug(disp, connected);
}

void HWComposer::invalidate() {
    mFlinger->repaintEverything();
}

void HWComposer::vsync(int disp, int64_t timestamp) {
    ATRACE_INT("VSYNC", ++mVSyncCount&1);
    mEventHandler.onVSyncReceived(disp, timestamp);
    Mutex::Autolock _l(mLock);
    mLastHwVSync = timestamp;
}

void HWComposer::hotplug(int disp, int connected) {
    if (disp == HWC_DISPLAY_PRIMARY || disp >= HWC_NUM_DISPLAY_TYPES) {
        ALOGE("hotplug event received for invalid display: disp=%d connected=%d",
                disp, connected);
        return;
    }
    queryDisplayProperties(disp);
    mEventHandler.onHotplugReceived(disp, bool(connected));
}

static const uint32_t DISPLAY_ATTRIBUTES[] = {
    HWC_DISPLAY_VSYNC_PERIOD,
    HWC_DISPLAY_WIDTH,
    HWC_DISPLAY_HEIGHT,
    HWC_DISPLAY_DPI_X,
    HWC_DISPLAY_DPI_Y,
    HWC_DISPLAY_NO_ATTRIBUTE,
};
#define NUM_DISPLAY_ATTRIBUTES (sizeof(DISPLAY_ATTRIBUTES) / sizeof(DISPLAY_ATTRIBUTES)[0])

// http://developer.android.com/reference/android/util/DisplayMetrics.html
#define ANDROID_DENSITY_TV    213
#define ANDROID_DENSITY_XHIGH 320

status_t HWComposer::queryDisplayProperties(int disp) {

    LOG_ALWAYS_FATAL_IF(!mHwc || !hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1));

    // use zero as default value for unspecified attributes
    int32_t values[NUM_DISPLAY_ATTRIBUTES - 1];
    memset(values, 0, sizeof(values));

    uint32_t config;
    size_t numConfigs = 1;
    status_t err = mHwc->getDisplayConfigs(mHwc, disp, &config, &numConfigs);
    if (err != NO_ERROR) {
        // this can happen if an unpluggable display is not connected
        mDisplayData[disp].connected = false;
        return err;
    }

    err = mHwc->getDisplayAttributes(mHwc, disp, config, DISPLAY_ATTRIBUTES, values);
    if (err != NO_ERROR) {
        // we can't get this display's info. turn it off.
        mDisplayData[disp].connected = false;
        return err;
    }

    int32_t w = 0, h = 0;
    for (size_t i = 0; i < NUM_DISPLAY_ATTRIBUTES - 1; i++) {
        switch (DISPLAY_ATTRIBUTES[i]) {
        case HWC_DISPLAY_VSYNC_PERIOD:
            mDisplayData[disp].refresh = nsecs_t(values[i]);
            break;
        case HWC_DISPLAY_WIDTH:
            mDisplayData[disp].width = values[i];
            break;
        case HWC_DISPLAY_HEIGHT:
            mDisplayData[disp].height = values[i];
            break;
        case HWC_DISPLAY_DPI_X:
            mDisplayData[disp].xdpi = values[i] / 1000.0f;
            break;
        case HWC_DISPLAY_DPI_Y:
            mDisplayData[disp].ydpi = values[i] / 1000.0f;
            break;
        default:
            ALOG_ASSERT(false, "unknown display attribute[%d] %#x",
                    i, DISPLAY_ATTRIBUTES[i]);
            break;
        }
    }

    // FIXME: what should we set the format to?
    mDisplayData[disp].format = HAL_PIXEL_FORMAT_RGBA_8888;
    mDisplayData[disp].connected = true;
    if (mDisplayData[disp].xdpi == 0.0f || mDisplayData[disp].ydpi == 0.0f) {
        // is there anything smarter we can do?
        if (h >= 1080) {
            mDisplayData[disp].xdpi = ANDROID_DENSITY_XHIGH;
            mDisplayData[disp].ydpi = ANDROID_DENSITY_XHIGH;
        } else {
            mDisplayData[disp].xdpi = ANDROID_DENSITY_TV;
            mDisplayData[disp].ydpi = ANDROID_DENSITY_TV;
        }
    }
    return NO_ERROR;
}

int32_t HWComposer::allocateDisplayId() {
    if (mAllocatedDisplayIDs.count() >= mNumDisplays) {
        return NO_MEMORY;
    }
    int32_t id = mAllocatedDisplayIDs.firstUnmarkedBit();
    mAllocatedDisplayIDs.markBit(id);
    return id;
}

status_t HWComposer::freeDisplayId(int32_t id) {
    if (id < HWC_NUM_DISPLAY_TYPES) {
        // cannot free the reserved IDs
        return BAD_VALUE;
    }
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id)) {
        return BAD_INDEX;
    }
    mAllocatedDisplayIDs.clearBit(id);
    return NO_ERROR;
}

nsecs_t HWComposer::getRefreshPeriod(int disp) const {
    return mDisplayData[disp].refresh;
}

nsecs_t HWComposer::getRefreshTimestamp(int disp) const {
    // this returns the last refresh timestamp.
    // if the last one is not available, we estimate it based on
    // the refresh period and whatever closest timestamp we have.
    Mutex::Autolock _l(mLock);
    nsecs_t now = systemTime(CLOCK_MONOTONIC);
    return now - ((now - mLastHwVSync) %  mDisplayData[disp].refresh);
}

uint32_t HWComposer::getWidth(int disp) const {
    return mDisplayData[disp].width;
}

uint32_t HWComposer::getHeight(int disp) const {
    return mDisplayData[disp].height;
}

uint32_t HWComposer::getFormat(int disp) const {
    return mDisplayData[disp].format;
}

float HWComposer::getDpiX(int disp) const {
    return mDisplayData[disp].xdpi;
}

float HWComposer::getDpiY(int disp) const {
    return mDisplayData[disp].ydpi;
}

bool HWComposer::isConnected(int disp) const {
    return mDisplayData[disp].connected;
}

void HWComposer::eventControl(int disp, int event, int enabled) {
    if (uint32_t(disp)>31 || !mAllocatedDisplayIDs.hasBit(disp)) {
        ALOGD("eventControl ignoring event %d on unallocated disp %d (en=%d)",
              event, disp, enabled);
        return;
    }
    if (event != EVENT_VSYNC) {
        ALOGW("eventControl got unexpected event %d (disp=%d en=%d)",
              event, disp, enabled);
        return;
    }
    status_t err = NO_ERROR;
    if (mHwc && !mDebugForceFakeVSync && hwcHasVsyncEvent(mHwc))  {
        if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0)) {
            // NOTE: we use our own internal lock here because we have to call
            // into the HWC with the lock held, and we want to make sure
            // that even if HWC blocks (which it shouldn't), it won't
            // affect other threads.
            Mutex::Autolock _l(mEventControlLock);
            const int32_t eventBit = 1UL << event;
            const int32_t newValue = enabled ? eventBit : 0;
            const int32_t oldValue = mDisplayData[disp].events & eventBit;
            if (newValue != oldValue) {
                ATRACE_CALL();
                err = hwcEventControl(mHwc, disp, event, enabled);
                if (!err) {
                    int32_t& events(mDisplayData[disp].events);
                    events = (events & ~eventBit) | newValue;
                }
            }
        } else {
            err = hwcEventControl(mHwc, disp, event, enabled);
        }
        // error here should not happen -- not sure what we should
        // do if it does.
        ALOGE_IF(err, "eventControl(%d, %d) failed %s",
                event, enabled, strerror(-err));
    }

    if (err == NO_ERROR && mVSyncThread != NULL) {
        mVSyncThread->setEnabled(enabled);
    }
}

status_t HWComposer::createWorkList(int32_t id, size_t numLayers) {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id)) {
        return BAD_INDEX;
    }

    if (mHwc) {
        DisplayData& disp(mDisplayData[id]);
        if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
            // we need space for the HWC_FRAMEBUFFER_TARGET
            numLayers++;
        }
        if (disp.capacity < numLayers || disp.list == NULL) {
            size_t size = sizeofHwcLayerList(mHwc, numLayers);
            free(disp.list);
            disp.list = (hwc_display_contents_1_t*)malloc(size);
            disp.capacity = numLayers;
        }
        if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
            disp.framebufferTarget = &disp.list->hwLayers[numLayers - 1];
            memset(disp.framebufferTarget, 0, sizeof(hwc_layer_1_t));
            const hwc_rect_t r = { 0, 0, disp.width, disp.height };
            disp.framebufferTarget->compositionType = HWC_FRAMEBUFFER_TARGET;
            disp.framebufferTarget->hints = 0;
            disp.framebufferTarget->flags = 0;
            disp.framebufferTarget->handle = disp.fbTargetHandle;
            disp.framebufferTarget->transform = 0;
            disp.framebufferTarget->blending = HWC_BLENDING_PREMULT;
            disp.framebufferTarget->sourceCrop = r;
            disp.framebufferTarget->displayFrame = r;
            disp.framebufferTarget->visibleRegionScreen.numRects = 1;
            disp.framebufferTarget->visibleRegionScreen.rects =
                &disp.framebufferTarget->displayFrame;
            disp.framebufferTarget->acquireFenceFd = -1;
            disp.framebufferTarget->releaseFenceFd = -1;
        }
        if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0)) {
            disp.list->retireFenceFd = -1;
        }
        hwcFlags(mHwc, disp.list) = HWC_GEOMETRY_CHANGED;
        hwcNumHwLayers(mHwc, disp.list) = numLayers;
    }
    return NO_ERROR;
}

status_t HWComposer::setFramebufferTarget(int32_t id,
        const sp<Fence>& acquireFence, const sp<GraphicBuffer>& buf) {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id)) {
        return BAD_INDEX;
    }
    DisplayData& disp(mDisplayData[id]);
    if (!disp.framebufferTarget) {
        // this should never happen, but apparently eglCreateWindowSurface()
        // triggers a SurfaceTextureClient::queueBuffer()  on some
        // devices (!?) -- log and ignore.
        ALOGE("HWComposer: framebufferTarget is null");
//        CallStack stack;
//        stack.update();
//        stack.dump("");
        return NO_ERROR;
    }

    int acquireFenceFd = -1;
    if (acquireFence != NULL) {
        acquireFenceFd = acquireFence->dup();
    }

    // ALOGD("fbPost: handle=%p, fence=%d", buf->handle, acquireFenceFd);
    disp.fbTargetHandle = buf->handle;
    disp.framebufferTarget->handle = disp.fbTargetHandle;
    disp.framebufferTarget->acquireFenceFd = acquireFenceFd;
    return NO_ERROR;
}

status_t HWComposer::prepare() {
    for (size_t i=0 ; i<mNumDisplays ; i++) {
        DisplayData& disp(mDisplayData[i]);
        if (disp.framebufferTarget) {
            // make sure to reset the type to HWC_FRAMEBUFFER_TARGET
            // DO NOT reset the handle field to NULL, because it's possible
            // that we have nothing to redraw (eg: eglSwapBuffers() not called)
            // in which case, we should continue to use the same buffer.
            LOG_FATAL_IF(disp.list == NULL);
            disp.framebufferTarget->compositionType = HWC_FRAMEBUFFER_TARGET;
        }
        if (!disp.connected && disp.list != NULL) {
            ALOGW("WARNING: disp %d: connected, non-null list, layers=%d",
                    i, hwcNumHwLayers(mHwc, disp.list));
        }
        mLists[i] = disp.list;
        if (mLists[i]) {
            if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_2)) {
                mLists[i]->outbuf = NULL;
                mLists[i]->outbufAcquireFenceFd = -1;
            } else if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
                // garbage data to catch improper use
                mLists[i]->dpy = (hwc_display_t)0xDEADBEEF;
                mLists[i]->sur = (hwc_surface_t)0xDEADBEEF;
            } else if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0)) {
                mLists[i]->dpy = EGL_NO_DISPLAY;
                mLists[i]->sur = EGL_NO_SURFACE;
            }
        }
    }
    int err = hwcPrepare(mHwc, mNumDisplays, mLists);
    ALOGE_IF(err, "HWComposer: prepare failed (%s)", strerror(-err));

    if (err == NO_ERROR) {
        if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0)) {
            // here we're just making sure that "skip" layers are set
            // to HWC_FRAMEBUFFER and we're also counting how many layers
            // we have of each type.
            for (size_t i=0 ; i<mNumDisplays ; i++) {
                DisplayData& disp(mDisplayData[i]);
                disp.hasFbComp = false;
                disp.hasOvComp = false;
                if (disp.list) {
                    for (size_t i=0 ; i<hwcNumHwLayers(mHwc, disp.list) ; i++) {
                        hwc_layer_1_t& l = disp.list->hwLayers[i];

                        //ALOGD("prepare: %d, type=%d, handle=%p",
                        //        i, l.compositionType, l.handle);

                        if (l.flags & HWC_SKIP_LAYER) {
                            l.compositionType = HWC_FRAMEBUFFER;
                        }
                        if (l.compositionType == HWC_FRAMEBUFFER) {
                            disp.hasFbComp = true;
                        }
                        if (l.compositionType == HWC_OVERLAY) {
                            disp.hasOvComp = true;
                        }
                    }
                }
            }
        } else {
            DisplayData& disp(mDisplayData[0]);
            disp.hasFbComp = false;
            disp.hasOvComp = false;
            if (disp.list) {
                hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(disp.list);
                for (size_t i=0 ; i<hwcNumHwLayers(mHwc, disp.list) ; i++) {
                    hwc_layer_t& l = list0->hwLayers[i];

                    //ALOGD("prepare: %d, type=%d, handle=%p",
                    //        i, l.compositionType, l.handle);

                    if (l.flags & HWC_SKIP_LAYER) {
                        l.compositionType = HWC_FRAMEBUFFER;
                    }
                    if (l.compositionType == HWC_FRAMEBUFFER) {
                        disp.hasFbComp = true;
                    }
                    // If the composition type is BLIT, we set this to
                    // trigger a FLIP
                    if(l.compositionType == HWC_BLIT) {
                        disp.hasFbComp = true;
                    }
                    if (l.compositionType == HWC_OVERLAY) {
                        disp.hasOvComp = true;
                    }
                }
            }

        }

    }
    return (status_t)err;
}

bool HWComposer::hasHwcComposition(int32_t id) const {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return false;
    return mDisplayData[id].hasOvComp;
}

bool HWComposer::hasGlesComposition(int32_t id) const {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return false;
    return mDisplayData[id].hasFbComp;
}

int HWComposer::getAndResetReleaseFenceFd(int32_t id) {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return BAD_INDEX;

    int fd = INVALID_OPERATION;
    if (mHwc && hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
        const DisplayData& disp(mDisplayData[id]);
        if (disp.framebufferTarget) {
            fd = disp.framebufferTarget->releaseFenceFd;
            disp.framebufferTarget->acquireFenceFd = -1;
            disp.framebufferTarget->releaseFenceFd = -1;
        }
    }
    return fd;
}

status_t HWComposer::commit() {
    int err = NO_ERROR;
    if (mHwc) {
        if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0)) {
            if (!hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
                // On version 1.0, the OpenGL ES target surface is communicated
                // by the (dpy, sur) fields and we are guaranteed to have only
                // a single display.
                mLists[0]->dpy = eglGetCurrentDisplay();
                mLists[0]->sur = eglGetCurrentSurface(EGL_DRAW);
            }
            err = hwcSet(mHwc, mLists[0]->dpy, mLists[0]->sur, mNumDisplays,
                    const_cast<hwc_display_contents_1_t**>(mLists));
        } else {
            err = hwcSet(mHwc, eglGetCurrentDisplay(), eglGetCurrentSurface(EGL_DRAW), mNumDisplays,
                    const_cast<hwc_display_contents_1_t**>(mLists));
        }


        for (size_t i=0 ; i<mNumDisplays ; i++) {
            DisplayData& disp(mDisplayData[i]);
            if (disp.list) {
                if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0)) {
                    if (disp.list->retireFenceFd != -1) {
                        close(disp.list->retireFenceFd);
                        disp.list->retireFenceFd = -1;
                    }
                }
                hwcFlags(mHwc, disp.list) &= ~HWC_GEOMETRY_CHANGED;
            }
        }
    }
    return (status_t)err;
}

status_t HWComposer::release(int disp) {
    LOG_FATAL_IF(disp >= HWC_NUM_DISPLAY_TYPES);
    if (mHwc) {
        if (hwcHasVsyncEvent(mHwc)) {
            eventControl(disp, HWC_EVENT_VSYNC, 0);
        }
        return (status_t)hwcBlank(mHwc, disp, 1);
    }
    return NO_ERROR;
}

status_t HWComposer::acquire(int disp) {
    LOG_FATAL_IF(disp >= HWC_NUM_DISPLAY_TYPES);
    if (mHwc) {
        return (status_t)hwcBlank(mHwc, disp, 0);
    }
    return NO_ERROR;
}

void HWComposer::disconnectDisplay(int disp) {
    LOG_ALWAYS_FATAL_IF(disp < 0 || disp == HWC_DISPLAY_PRIMARY);
    if (disp >= HWC_NUM_DISPLAY_TYPES) {
        // nothing to do for these yet
        return;
    }
    DisplayData& dd(mDisplayData[disp]);
    if (dd.list != NULL) {
        free(dd.list);
        dd.list = NULL;
        dd.framebufferTarget = NULL;    // points into dd.list
        dd.fbTargetHandle = NULL;
    }
}

int HWComposer::getVisualID() const {
    if (mHwc && hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
        // FIXME: temporary hack until HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED
        // is supported by the implementation. we can only be in this case
        // if we have HWC 1.1
        return HAL_PIXEL_FORMAT_RGBA_8888;
        //return HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
    } else {
        return mFbDev->format;
    }
}

bool HWComposer::supportsFramebufferTarget() const {
    return (mHwc && hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1));
}

int HWComposer::fbPost(int32_t id,
        const sp<Fence>& acquireFence, const sp<GraphicBuffer>& buffer) {
    if (mHwc && hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
        return setFramebufferTarget(id, acquireFence, buffer);
    } else {
        if (acquireFence != NULL) {
            acquireFence->waitForever(1000, "HWComposer::fbPost");
        }
        return mFbDev->post(mFbDev, buffer->handle);
    }
}

int HWComposer::fbCompositionComplete() {
    if (mHwc && hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1))
        return NO_ERROR;

    if (mFbDev->compositionComplete) {
        return mFbDev->compositionComplete(mFbDev);
    } else {
        return INVALID_OPERATION;
    }
}

void HWComposer::fbDump(String8& result) {
    if (mFbDev && mFbDev->common.version >= 1 && mFbDev->dump) {
        const size_t SIZE = 4096;
        char buffer[SIZE];
        mFbDev->dump(mFbDev, buffer, SIZE);
        result.append(buffer);
    }
}

/*
 * Helper template to implement a concrete HWCLayer
 * This holds the pointer to the concrete hwc layer type
 * and implements the "iterable" side of HWCLayer.
 */
template<typename CONCRETE, typename HWCTYPE>
class Iterable : public HWComposer::HWCLayer {
protected:
    HWCTYPE* const mLayerList;
    HWCTYPE* mCurrentLayer;
    Iterable(HWCTYPE* layer) : mLayerList(layer), mCurrentLayer(layer) { }
    inline HWCTYPE const * getLayer() const { return mCurrentLayer; }
    inline HWCTYPE* getLayer() { return mCurrentLayer; }
    virtual ~Iterable() { }
private:
    // returns a copy of ourselves
    virtual HWComposer::HWCLayer* dup() {
        return new CONCRETE( static_cast<const CONCRETE&>(*this) );
    }
    virtual status_t setLayer(size_t index) {
        mCurrentLayer = &mLayerList[index];
        return NO_ERROR;
    }
};

// #if !HWC_REMOVE_DEPRECATED_VERSIONS
/*
 * Concrete implementation of HWCLayer for HWC_DEVICE_API_VERSION_0_3
 * This implements the HWCLayer side of HWCIterableLayer.
 */
class HWCLayerVersion0 : public Iterable<HWCLayerVersion0, hwc_layer_t> {
public:
    HWCLayerVersion0(hwc_layer_t* layer)
        : Iterable<HWCLayerVersion0, hwc_layer_t>(layer) { }

    virtual int32_t getCompositionType() const {
        return getLayer()->compositionType;
    }
    virtual uint32_t getHints() const {
        return getLayer()->hints;
    }
    virtual int getAndResetReleaseFenceFd() {
        // not supported on VERSION_03
        return -1;
    }
    virtual void setAcquireFenceFd(int fenceFd) {
        if (fenceFd != -1) {
            ALOGE("HWC 0.x can't handle acquire fences");
            close(fenceFd);
        }
    }

    virtual void setDefaultState() {
        getLayer()->compositionType = HWC_FRAMEBUFFER;
        getLayer()->hints = 0;
        getLayer()->flags = HWC_SKIP_LAYER;
        getLayer()->handle = 0;
        getLayer()->transform = 0;
        getLayer()->blending = HWC_BLENDING_NONE;
        getLayer()->visibleRegionScreen.numRects = 0;
        getLayer()->visibleRegionScreen.rects = NULL;
    }
    virtual void setPerFrameDefaultState() {
        //getLayer()->compositionType = HWC_FRAMEBUFFER;
    }
    virtual void setSkip(bool skip) {
        if (skip) {
            getLayer()->flags |= HWC_SKIP_LAYER;
        } else {
            getLayer()->flags &= ~HWC_SKIP_LAYER;
        }
    }
    virtual void setBlending(uint32_t blending) {
        getLayer()->blending = blending;
    }
    virtual void setTransform(uint32_t transform) {
        getLayer()->transform = transform;
    }
    virtual void setFrame(const Rect& frame) {
        reinterpret_cast<Rect&>(getLayer()->displayFrame) = frame;
    }
    virtual void setCrop(const Rect& crop) {
        reinterpret_cast<Rect&>(getLayer()->sourceCrop) = crop;
    }
    virtual void setVisibleRegionScreen(const Region& reg) {
        // Region::getSharedBuffer creates a reference to the underlying
        // SharedBuffer of this Region, this reference is freed
        // in onDisplayed()
        hwc_region_t& visibleRegion = getLayer()->visibleRegionScreen;
        SharedBuffer const* sb = reg.getSharedBuffer(&visibleRegion.numRects);
        visibleRegion.rects = reinterpret_cast<hwc_rect_t const *>(sb->data());
    }
    virtual void setBuffer(const sp<GraphicBuffer>& buffer) {
        if (buffer == 0 || buffer->handle == 0) {
            getLayer()->compositionType = HWC_FRAMEBUFFER;
            getLayer()->flags |= HWC_SKIP_LAYER;
            getLayer()->handle = 0;
        } else {
            getLayer()->handle = buffer->handle;
        }
    }
    virtual void onDisplayed() {
        hwc_region_t& visibleRegion = getLayer()->visibleRegionScreen;
        SharedBuffer const* sb = SharedBuffer::bufferFromData(visibleRegion.rects);
        if (sb) {
            sb->release();
            // not technically needed but safer
            visibleRegion.numRects = 0;
            visibleRegion.rects = NULL;
        }

    }
};
// #endif // !HWC_REMOVE_DEPRECATED_VERSIONS

/*
 * Concrete implementation of HWCLayer for HWC_DEVICE_API_VERSION_1_0.
 * This implements the HWCLayer side of HWCIterableLayer.
 */
class HWCLayerVersion1 : public Iterable<HWCLayerVersion1, hwc_layer_1_t> {
public:
    HWCLayerVersion1(hwc_layer_1_t* layer)
        : Iterable<HWCLayerVersion1, hwc_layer_1_t>(layer) { }

    virtual int32_t getCompositionType() const {
        return getLayer()->compositionType;
    }
    virtual uint32_t getHints() const {
        return getLayer()->hints;
    }
    virtual int getAndResetReleaseFenceFd() {
        int fd = getLayer()->releaseFenceFd;
        getLayer()->releaseFenceFd = -1;
        return fd;
    }
    virtual void setAcquireFenceFd(int fenceFd) {
        getLayer()->acquireFenceFd = fenceFd;
    }
    virtual void setPerFrameDefaultState() {
        //getLayer()->compositionType = HWC_FRAMEBUFFER;
    }
    virtual void setDefaultState() {
        getLayer()->compositionType = HWC_FRAMEBUFFER;
        getLayer()->hints = 0;
        getLayer()->flags = HWC_SKIP_LAYER;
        getLayer()->handle = 0;
        getLayer()->transform = 0;
        getLayer()->blending = HWC_BLENDING_NONE;
        getLayer()->visibleRegionScreen.numRects = 0;
        getLayer()->visibleRegionScreen.rects = NULL;
        getLayer()->acquireFenceFd = -1;
        getLayer()->releaseFenceFd = -1;
    }
    virtual void setSkip(bool skip) {
        if (skip) {
            getLayer()->flags |= HWC_SKIP_LAYER;
        } else {
            getLayer()->flags &= ~HWC_SKIP_LAYER;
        }
    }
    virtual void setBlending(uint32_t blending) {
        getLayer()->blending = blending;
    }
    virtual void setTransform(uint32_t transform) {
        getLayer()->transform = transform;
    }
    virtual void setFrame(const Rect& frame) {
        reinterpret_cast<Rect&>(getLayer()->displayFrame) = frame;
    }
    virtual void setCrop(const Rect& crop) {
        reinterpret_cast<Rect&>(getLayer()->sourceCrop) = crop;
    }
    virtual void setVisibleRegionScreen(const Region& reg) {
        // Region::getSharedBuffer creates a reference to the underlying
        // SharedBuffer of this Region, this reference is freed
        // in onDisplayed()
        hwc_region_t& visibleRegion = getLayer()->visibleRegionScreen;
        SharedBuffer const* sb = reg.getSharedBuffer(&visibleRegion.numRects);
        visibleRegion.rects = reinterpret_cast<hwc_rect_t const *>(sb->data());
    }
    virtual void setBuffer(const sp<GraphicBuffer>& buffer) {
        if (buffer == 0 || buffer->handle == 0) {
            getLayer()->compositionType = HWC_FRAMEBUFFER;
            getLayer()->flags |= HWC_SKIP_LAYER;
            getLayer()->handle = 0;
        } else {
            getLayer()->handle = buffer->handle;
        }
    }
    virtual void onDisplayed() {
        hwc_region_t& visibleRegion = getLayer()->visibleRegionScreen;
        SharedBuffer const* sb = SharedBuffer::bufferFromData(visibleRegion.rects);
        if (sb) {
            sb->release();
            // not technically needed but safer
            visibleRegion.numRects = 0;
            visibleRegion.rects = NULL;
        }

        getLayer()->acquireFenceFd = -1;
    }
};

/*
 * returns an iterator initialized at a given index in the layer list
 */
HWComposer::LayerListIterator HWComposer::getLayerIterator(int32_t id, size_t index) {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id)) {
        return LayerListIterator();
    }
    const DisplayData& disp(mDisplayData[id]);
    if (!mHwc || !disp.list || index > hwcNumHwLayers(mHwc,disp.list)) {
        return LayerListIterator();
    }
    if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_0)) {
       return LayerListIterator(new HWCLayerVersion1(disp.list->hwLayers), index);
    } else {
       hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(disp.list);
       return LayerListIterator(new HWCLayerVersion0(list0->hwLayers), index);
    }
}

/*
 * returns an iterator on the beginning of the layer list
 */
HWComposer::LayerListIterator HWComposer::begin(int32_t id) {
    return getLayerIterator(id, 0);
}

/*
 * returns an iterator on the end of the layer list
 */
HWComposer::LayerListIterator HWComposer::end(int32_t id) {
    size_t numLayers = 0;
    if (uint32_t(id) <= 31 && mAllocatedDisplayIDs.hasBit(id)) {
        const DisplayData& disp(mDisplayData[id]);
        if (mHwc && disp.list) {
            numLayers = hwcNumHwLayers(mHwc, disp.list);
            if (hwcHasApiVersion(mHwc, HWC_DEVICE_API_VERSION_1_1)) {
                // with HWC 1.1, the last layer is always the HWC_FRAMEBUFFER_TARGET,
                // which we ignore when iterating through the layer list.
                ALOGE_IF(!numLayers, "mDisplayData[%d].list->numHwLayers is 0", id);
                if (numLayers) {
                    numLayers--;
                }
            }
        }
    }
    return getLayerIterator(id, numLayers);
}

void HWComposer::dump(String8& result, char* buffer, size_t SIZE) const {
    if (mHwc) {
        result.appendFormat("Hardware Composer state (version %8x):\n", hwcApiVersion(mHwc));
        result.appendFormat("  mDebugForceFakeVSync=%d\n", mDebugForceFakeVSync);
        for (size_t i=0 ; i<mNumDisplays ; i++) {
            const DisplayData& disp(mDisplayData[i]);

            const Vector< sp<LayerBase> >& visibleLayersSortedByZ =
                    mFlinger->getLayerSortedByZForHwcDisplay(i);

            if (disp.connected) {
                result.appendFormat(
                        "  Display[%d] : %ux%u, xdpi=%f, ydpi=%f, refresh=%lld\n",
                        i, disp.width, disp.height, disp.xdpi, disp.ydpi, disp.refresh);
            }

            if (disp.list && disp.connected) {
                result.appendFormat(
                        "  numHwLayers=%u, flags=%08x\n",
                        disp.list->numHwLayers, disp.list->flags);

                result.append(
                        "    type    |  handle  |   hints  |   flags  | tr | blend |  format  |       source crop         |           frame           name \n"
                        "------------+----------+----------+----------+----+-------+----------+---------------------------+--------------------------------\n");
                //      " __________ | ________ | ________ | ________ | __ | _____ | ________ | [_____,_____,_____,_____] | [_____,_____,_____,_____]
                for (size_t i=0 ; i<disp.list->numHwLayers ; i++) {
                    const hwc_layer_1_t&l = disp.list->hwLayers[i];
                    int32_t format = -1;
                    String8 name("unknown");

                    if (i < visibleLayersSortedByZ.size()) {
                        const sp<LayerBase>& layer(visibleLayersSortedByZ[i]);
                        if (layer->getLayer() != NULL) {
                            const sp<GraphicBuffer>& buffer(
                                layer->getLayer()->getActiveBuffer());
                            if (buffer != NULL) {
                                format = buffer->getPixelFormat();
                            }
                        }
                        name = layer->getName();
                    }

                    int type = l.compositionType;
                    if (type == HWC_FRAMEBUFFER_TARGET) {
                        name = "HWC_FRAMEBUFFER_TARGET";
                        format = disp.format;
                    }

                    static char const* compositionTypeName[] = {
                            "GLES",
                            "HWC",
                            "BACKGROUND",
                            "FB TARGET",
                            "FB_BLIT",
                            "UNKNOWN"};
                    if (type >= NELEM(compositionTypeName))
                        type = NELEM(compositionTypeName) - 1;

                    result.appendFormat(
                            " %10s | %08x | %08x | %08x | %02x | %05x | %08x | [%5d,%5d,%5d,%5d] | [%5d,%5d,%5d,%5d] %s\n",
                                    compositionTypeName[type],
                                    intptr_t(l.handle), l.hints, l.flags, l.transform, l.blending, format,
                                    l.sourceCrop.left, l.sourceCrop.top, l.sourceCrop.right, l.sourceCrop.bottom,
                                    l.displayFrame.left, l.displayFrame.top, l.displayFrame.right, l.displayFrame.bottom,
                                    name.string());
                }
            }
        }
    }
    if (mHwc) {
        hwcDump(mHwc, buffer, SIZE);
        result.append(buffer);
    }
}

// ---------------------------------------------------------------------------

HWComposer::VSyncThread::VSyncThread(HWComposer& hwc)
    : mHwc(hwc), mEnabled(false),
      mNextFakeVSync(0),
      mRefreshPeriod(hwc.getRefreshPeriod(HWC_DISPLAY_PRIMARY))
{
}

void HWComposer::VSyncThread::setEnabled(bool enabled) {
    Mutex::Autolock _l(mLock);
    if (mEnabled != enabled) {
        mEnabled = enabled;
        mCondition.signal();
    }
}

void HWComposer::VSyncThread::onFirstRef() {
    run("VSyncThread", PRIORITY_URGENT_DISPLAY + PRIORITY_MORE_FAVORABLE);
}

bool HWComposer::VSyncThread::threadLoop() {
    { // scope for lock
        Mutex::Autolock _l(mLock);
        while (!mEnabled) {
            mCondition.wait(mLock);
        }
    }

    const nsecs_t period = mRefreshPeriod;
    const nsecs_t now = systemTime(CLOCK_MONOTONIC);
    nsecs_t next_vsync = mNextFakeVSync;
    nsecs_t sleep = next_vsync - now;
    if (sleep < 0) {
        // we missed, find where the next vsync should be
        sleep = (period - ((now - next_vsync) % period));
        next_vsync = now + sleep;
    }
    mNextFakeVSync = next_vsync + period;

    struct timespec spec;
    spec.tv_sec  = next_vsync / 1000000000;
    spec.tv_nsec = next_vsync % 1000000000;

    int err;
    do {
        err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &spec, NULL);
    } while (err<0 && errno == EINTR);

    if (err == 0 && mEnabled) {
        mHwc.mEventHandler.onVSyncReceived(0, next_vsync);
    }

    return true;
}

// ---------------------------------------------------------------------------
}; // namespace android
