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

#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/misc.h>
#include <utils/NativeHandle.h>
#include <utils/String8.h>
#include <utils/Thread.h>
#include <utils/Trace.h>
#include <utils/Vector.h>

#include <ui/GraphicBuffer.h>

#include <hardware/hardware.h>
#include <hardware/hwcomposer.h>

#include <android/configuration.h>

#include <cutils/log.h>
#include <cutils/properties.h>

#include "HWComposer.h"

#include "../Layer.h"           // needed only for debugging
#include "../SurfaceFlinger.h"

#define GPUTILERECT_DEBUG 0

namespace android {

#define MIN_HWC_HEADER_VERSION HWC_HEADER_VERSION

static uint32_t hwcApiVersion(const hwc_composer_device_1_t* hwc) {
    uint32_t hwcVersion = hwc->common.version;
    return hwcVersion & HARDWARE_API_VERSION_2_MAJ_MIN_MASK;
}

static uint32_t hwcHeaderVersion(const hwc_composer_device_1_t* hwc) {
    uint32_t hwcVersion = hwc->common.version;
    return hwcVersion & HARDWARE_API_VERSION_2_HEADER_MASK;
}

static bool hwcHasApiVersion(const hwc_composer_device_1_t* hwc,
        uint32_t version) {
    return hwcApiVersion(hwc) >= (version & HARDWARE_API_VERSION_2_MAJ_MIN_MASK);
}

static bool hwcHasVsyncEvent(const hwc_composer_device_1_t* hwc) {
    return hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_0_3) ||
           hwcHeaderVersion(hwc) >= 3;
}

static size_t sizeofHwcLayerList(size_t numLayers) {
    return sizeof(hwc_layer_list_t) + numLayers*sizeof(hwc_layer_t);
}

static int hwcEventControl(hwc_composer_device_1_t* hwc,
        int event, int enabled) {
    hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(hwc);
    return hwc0->methods->eventControl(hwc0, event, enabled);
}

static int hwcBlank(hwc_composer_device_1_t* hwc, int blank) {
    if (blank) {
        hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(hwc);
        return hwc0->set(hwc0, NULL, NULL, NULL);
    } else {
        // HWC 0.x turns the screen on at the next set()
        return NO_ERROR;
    }
}

static int hwcPrepare(hwc_composer_device_1_t* hwc,
        hwc_display_contents_1_t** displays) {
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

static int hwcSet(hwc_composer_device_1_t* hwc, EGLDisplay dpy, EGLSurface sur,
        hwc_display_contents_1_t** displays) {
    int err;
    hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(hwc);
    hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(displays[0]);
    err = hwc0->set(hwc0, dpy, sur, list0);
    return err;
}

static uint32_t& hwcFlags(hwc_display_contents_1_t* display) {
    hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(display);
    return list0->flags;
}

static size_t& hwcNumHwLayers(hwc_display_contents_1_t* display) {
    hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(display);
    return list0->numHwLayers;
}

static void hwcDump(hwc_composer_device_1_t* hwc, char* buff, int buff_len) {
    if (hwcHasApiVersion(hwc, HWC_DEVICE_API_VERSION_0_1)) {
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
      mDebugForceFakeVSync(false),
      mVDSEnabled(false)
{
    for (size_t i =0 ; i<MAX_HWC_DISPLAYS ; i++) {
        mLists[i] = 0;
    }

    for (size_t i=0 ; i<HWC_NUM_PHYSICAL_DISPLAY_TYPES ; i++) {
        mLastHwVSync[i] = 0;
        mVSyncCounts[i] = 0;
    }

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.no_hw_vsync", value, "0");
    mDebugForceFakeVSync = atoi(value);

    bool needVSyncThread = true;

    // Note: some devices may insist that the FB HAL be opened before HWC.
    int fberr = loadFbHalModule();
    loadHwcModule();

    // If we have no HWC, or a pre-1.1 HWC, an FB dev is mandatory.
    if (!mHwc && !mFbDev) {
        ALOGE("ERROR: failed to open framebuffer (%s), aborting",
                strerror(-fberr));
        abort();
    }

    // these display IDs are always reserved
    for (size_t i=0 ; i<NUM_BUILTIN_DISPLAYS ; i++) {
        mAllocatedDisplayIDs.markBit(i);
    }

    if (mHwc) {
        ALOGI("Using %s version %u.%u", HWC_HARDWARE_COMPOSER,
              (hwcApiVersion(mHwc) >> 24) & 0xff,
              (hwcApiVersion(mHwc) >> 16) & 0xff);
        hwc_composer_device_t* hwc0 = reinterpret_cast<hwc_composer_device_t*>(mHwc);
        if (hwc0->registerProcs) {
            mCBContext->hwc = this;
            mCBContext->procs.invalidate = &hook_invalidate;
            mCBContext->procs.vsync = &hook_vsync;
            memset(mCBContext->procs.zero, 0, sizeof(mCBContext->procs.zero));
            hwc0->registerProcs(hwc0, &mCBContext->procs);
        }
            
        // don't need a vsync thread if we have a hardware composer
        needVSyncThread = false;
        // always turn vsync off when we start
        if (hwcHasVsyncEvent(mHwc)) {
            eventControl(HWC_DISPLAY_PRIMARY, HWC_EVENT_VSYNC, 0);
            // the number of displays we actually have depends on the
            // hw composer version
           mNumDisplays = 1;
        } else {
            needVSyncThread = true;
            mNumDisplays = 1;
        }
    }

    if (mFbDev) {
        ALOG_ASSERT(!(mHwc),
                "should only have fbdev if no hwc");

        DisplayData& disp(mDisplayData[HWC_DISPLAY_PRIMARY]);
        disp.connected = true;
        disp.format = mFbDev->format;
        DisplayConfig config = DisplayConfig();
        config.width = mFbDev->width;
        config.height = mFbDev->height;
        config.xdpi = mFbDev->xdpi;
        config.ydpi = mFbDev->ydpi;
#ifdef QCOM_BSP
        config.secure = true; //XXX: Assuming primary is always true
#endif
        config.refresh = nsecs_t(1e9 / mFbDev->fps);
        disp.configs.push_back(config);
        disp.currentConfig = 0;
    } else if (mHwc) {
        // here we're guaranteed to have at least HWC 1.1
        for (size_t i =0 ; i<NUM_BUILTIN_DISPLAYS ; i++) {
            queryDisplayProperties(i);
        }
    }

    // read system property for VDS solution
    // This property is expected to be setup once during bootup
    if( (property_get("persist.hwc.enable_vds", value, NULL) > 0) &&
        ((!strncmp(value, "1", strlen("1"))) ||
        !strncasecmp(value, "true", strlen("true")))) {
        //HAL virtual display is using VDS based implementation
        mVDSEnabled = true;
    }

    if (needVSyncThread) {
        // we don't have VSYNC support, we need to fake it
        mVSyncThread = new VSyncThread(*this);
    }
#ifdef QCOM_BSP
    // Threshold Area to enable GPU Tiled Rect.
    property_get("debug.hwc.gpuTiledThreshold", value, "1.9");
    mDynThreshold = atof(value);
#endif
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

    if ((hwcHeaderVersion(mHwc) < MIN_HWC_HEADER_VERSION ||
            hwcHeaderVersion(mHwc) > HWC_HEADER_VERSION)) {
        ALOGE("%s device version %#x unsupported, will not be used",
              HWC_HARDWARE_COMPOSER, mHwc->common.version);
        hwc_close_1(mHwc);
        mHwc = NULL;
        return;
    }
}

// Load and prepare the FB HAL, which uses the gralloc module.  Sets mFbDev.
int HWComposer::loadFbHalModule()
{
    hw_module_t const* module;

    int err = hw_get_module(GRALLOC_HARDWARE_MODULE_ID, &module);
    if (err != 0) {
        ALOGE("%s module not found", GRALLOC_HARDWARE_MODULE_ID);
        return err;
    }

    return framebuffer_open(module, &mFbDev);
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
    if (uint32_t(disp) < HWC_NUM_PHYSICAL_DISPLAY_TYPES) {
        {
            Mutex::Autolock _l(mLock);

            // There have been reports of HWCs that signal several vsync events
            // with the same timestamp when turning the display off and on. This
            // is a bug in the HWC implementation, but filter the extra events
            // out here so they don't cause havoc downstream.
            if (timestamp == mLastHwVSync[disp]) {
                ALOGW("Ignoring duplicate VSYNC event from HWC (t=%" PRId64 ")",
                        timestamp);
                return;
            }

            mLastHwVSync[disp] = timestamp;
        }

        char tag[16];
        snprintf(tag, sizeof(tag), "HW_VSYNC_%1u", disp);
        ATRACE_INT(tag, ++mVSyncCounts[disp] & 1);

        mEventHandler.onVSyncReceived(disp, timestamp);
    }
}

void HWComposer::hotplug(int disp, int connected) {
    if (disp == HWC_DISPLAY_PRIMARY || disp >= VIRTUAL_DISPLAY_ID_BASE) {
        ALOGE("hotplug event received for invalid display: disp=%d connected=%d",
                disp, connected);
        return;
    }
    queryDisplayProperties(disp);
    mEventHandler.onHotplugReceived(disp, bool(connected));
}

static float getDefaultDensity(uint32_t width, uint32_t height) {
    // Default density is based on TVs: 1080p displays get XHIGH density,
    // lower-resolution displays get TV density. Maybe eventually we'll need
    // to update it for 4K displays, though hopefully those just report
    // accurate DPI information to begin with. This is also used for virtual
    // displays and even primary displays with older hwcomposers, so be
    // careful about orientation.

    uint32_t h = width < height ? width : height;
    if (h >= 1080) return ACONFIGURATION_DENSITY_XHIGH;
    else           return ACONFIGURATION_DENSITY_TV;
}

static const uint32_t DISPLAY_ATTRIBUTES[] = {
    HWC_DISPLAY_VSYNC_PERIOD,
    HWC_DISPLAY_WIDTH,
    HWC_DISPLAY_HEIGHT,
    HWC_DISPLAY_DPI_X,
    HWC_DISPLAY_DPI_Y,
#ifdef QCOM_BSP
    //To specify if display is secure
    //Primary is considered as secure always
    //HDMI can be secure based on HDCP
    HWC_DISPLAY_SECURE,
#endif
    HWC_DISPLAY_NO_ATTRIBUTE,
};
#define NUM_DISPLAY_ATTRIBUTES (sizeof(DISPLAY_ATTRIBUTES) / sizeof(DISPLAY_ATTRIBUTES)[0])

status_t HWComposer::queryDisplayProperties(int disp) {

    LOG_ALWAYS_FATAL_IF(!mHwc);

    // use zero as default value for unspecified attributes
    int32_t values[NUM_DISPLAY_ATTRIBUTES - 1];
    memset(values, 0, sizeof(values));

    const size_t MAX_NUM_CONFIGS = 128;
    uint32_t configs[MAX_NUM_CONFIGS] = {0};
    size_t numConfigs = MAX_NUM_CONFIGS;
    status_t err = mHwc->getDisplayConfigs(mHwc, disp, configs, &numConfigs);
    if (err != NO_ERROR) {
        // this can happen if an unpluggable display is not connected
        mDisplayData[disp].connected = false;
        return err;
    }

    int currentConfig = getActiveConfig(disp);
    if (currentConfig < 0 || currentConfig > (numConfigs-1)) {
        ALOGE("%s: Invalid display config! %d", __FUNCTION__, currentConfig);
        currentConfig = 0;
    }

    mDisplayData[disp].currentConfig = currentConfig;
    for (size_t c = 0; c < numConfigs; ++c) {
        err = mHwc->getDisplayAttributes(mHwc, disp, configs[c],
                DISPLAY_ATTRIBUTES, values);
        if (err != NO_ERROR) {
            // we can't get this display's info. turn it off.
            mDisplayData[disp].connected = false;
            return err;
        }

        DisplayConfig config = DisplayConfig();
        for (size_t i = 0; i < NUM_DISPLAY_ATTRIBUTES - 1; i++) {
            switch (DISPLAY_ATTRIBUTES[i]) {
                case HWC_DISPLAY_VSYNC_PERIOD:
                    config.refresh = nsecs_t(values[i]);
                    break;
                case HWC_DISPLAY_WIDTH:
                    config.width = values[i];
                    break;
                case HWC_DISPLAY_HEIGHT:
                    config.height = values[i];
                    break;
                case HWC_DISPLAY_DPI_X:
                    config.xdpi = values[i] / 1000.0f;
                    break;
                case HWC_DISPLAY_DPI_Y:
                    config.ydpi = values[i] / 1000.0f;
                    break;
#ifdef QCOM_BSP
                case HWC_DISPLAY_SECURE:
                    config.secure = values[i];
                    break;
#endif
                default:
                    ALOG_ASSERT(false, "unknown display attribute[%zu] %#x",
                            i, DISPLAY_ATTRIBUTES[i]);
                    break;
            }
        }

        if (config.xdpi == 0.0f || config.ydpi == 0.0f) {
            float dpi = getDefaultDensity(config.width, config.height);
            config.xdpi = dpi;
            config.ydpi = dpi;
        }

        mDisplayData[disp].configs.push_back(config);
    }

    // FIXME: what should we set the format to?
    mDisplayData[disp].format = HAL_PIXEL_FORMAT_RGBA_8888;
    mDisplayData[disp].connected = true;
    return NO_ERROR;
}

status_t HWComposer::setVirtualDisplayProperties(int32_t id,
        uint32_t w, uint32_t h, uint32_t format) {
    if (id < VIRTUAL_DISPLAY_ID_BASE || id >= int32_t(mNumDisplays) ||
            !mAllocatedDisplayIDs.hasBit(id)) {
        return BAD_INDEX;
    }
    size_t configId = mDisplayData[id].currentConfig;
    mDisplayData[id].format = format;
    DisplayConfig& config = mDisplayData[id].configs.editItemAt(configId);
    config.width = w;
    config.height = h;
    config.xdpi = config.ydpi = getDefaultDensity(w, h);
    //XXXX: No need to set secure for virtual display's as its initiated by
    //the frameworks
    return NO_ERROR;
}

int32_t HWComposer::allocateDisplayId() {
    if (mAllocatedDisplayIDs.count() >= mNumDisplays) {
        return NO_MEMORY;
    }
    int32_t id = mAllocatedDisplayIDs.firstUnmarkedBit();
    mAllocatedDisplayIDs.markBit(id);
    mDisplayData[id].connected = true;
    mDisplayData[id].configs.resize(1);
    mDisplayData[id].currentConfig = 0;
    return id;
}

status_t HWComposer::freeDisplayId(int32_t id) {
    if (id < NUM_BUILTIN_DISPLAYS) {
        // cannot free the reserved IDs
        return BAD_VALUE;
    }
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id)) {
        return BAD_INDEX;
    }
    mAllocatedDisplayIDs.clearBit(id);
    mDisplayData[id].connected = false;
    return NO_ERROR;
}

nsecs_t HWComposer::getRefreshTimestamp(int disp) const {
    // this returns the last refresh timestamp.
    // if the last one is not available, we estimate it based on
    // the refresh period and whatever closest timestamp we have.
    Mutex::Autolock _l(mLock);
    nsecs_t now = systemTime(CLOCK_MONOTONIC);
    size_t configId = mDisplayData[disp].currentConfig;
    return now - ((now - mLastHwVSync[disp]) %
            mDisplayData[disp].configs[configId].refresh);
}

sp<Fence> HWComposer::getDisplayFence(int disp) const {
    return mDisplayData[disp].lastDisplayFence;
}

uint32_t HWComposer::getFormat(int disp) const {
    if (uint32_t(disp)>31 || !mAllocatedDisplayIDs.hasBit(disp)) {
        return HAL_PIXEL_FORMAT_RGBA_8888;
    } else {
        return mDisplayData[disp].format;
    }
}

bool HWComposer::isConnected(int disp) const {
    return mDisplayData[disp].connected;
}

uint32_t HWComposer::getWidth(int disp) const {
    size_t currentConfig = mDisplayData[disp].currentConfig;
    return mDisplayData[disp].configs[currentConfig].width;
}

uint32_t HWComposer::getHeight(int disp) const {
    size_t currentConfig = mDisplayData[disp].currentConfig;
    return mDisplayData[disp].configs[currentConfig].height;
}

float HWComposer::getDpiX(int disp) const {
    size_t currentConfig = mDisplayData[disp].currentConfig;
    return mDisplayData[disp].configs[currentConfig].xdpi;
}

float HWComposer::getDpiY(int disp) const {
    size_t currentConfig = mDisplayData[disp].currentConfig;
    return mDisplayData[disp].configs[currentConfig].ydpi;
}

#ifdef QCOM_BSP
bool HWComposer::isSecure(int disp) const {
    size_t currentConfig = mDisplayData[disp].currentConfig;
    return mDisplayData[disp].configs[currentConfig].secure;
}
#endif


nsecs_t HWComposer::getRefreshPeriod(int disp) const {
    size_t currentConfig = mDisplayData[disp].currentConfig;
    return mDisplayData[disp].configs[currentConfig].refresh;
}

const Vector<HWComposer::DisplayConfig>& HWComposer::getConfigs(int disp) const {
    return mDisplayData[disp].configs;
}

size_t HWComposer::getCurrentConfig(int disp) const {
    return mDisplayData[disp].currentConfig;
}

void HWComposer::eventControl(int disp, int event, int enabled) {
    if (uint32_t(disp)>31 || !mAllocatedDisplayIDs.hasBit(disp)) {
        ALOGD("eventControl ignoring event %d on unallocated disp %d (en=%d)",
              event, disp, enabled);
        return;
    }
    status_t err = NO_ERROR;
    switch(event) {
        case EVENT_VSYNC:
            if (mHwc && !mDebugForceFakeVSync && hwcHasVsyncEvent(mHwc)) {
                err = hwcEventControl(mHwc, event, enabled);
                // error here should not happen -- not sure what we should
                // do if it does.
                ALOGE_IF(err, "eventControl(%d, %d) failed %s",
                         event, enabled, strerror(-err));
            }

            if (err == NO_ERROR && mVSyncThread != NULL) {
                mVSyncThread->setEnabled(enabled);
            }
            break;
        case EVENT_ORIENTATION:
            // Orientation event
             break;
        default:
            ALOGW("eventControl got unexpected event %d (disp=%d en=%d)",
                    event, disp, enabled);
            break;
    }
    return;
}

status_t HWComposer::createWorkList(int32_t id, size_t numLayers) {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id)) {
        return BAD_INDEX;
    }

    if (mHwc) {
        DisplayData& disp(mDisplayData[id]);
        if (disp.capacity < numLayers || disp.list == NULL) {
            size_t size = sizeofHwcLayerList(numLayers);
            free(disp.list);
            disp.list = (hwc_display_contents_1_t*)malloc(size);
            if(disp.list == NULL)
                return NO_MEMORY;
            disp.capacity = numLayers;
        }
        hwcFlags(disp.list) = HWC_GEOMETRY_CHANGED;
        hwcNumHwLayers(disp.list) = numLayers;
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
        // triggers a Surface::queueBuffer()  on some
        // devices (!?) -- log and ignore.
        ALOGE("HWComposer: framebufferTarget is null");
        return NO_ERROR;
    }

    int acquireFenceFd = -1;
    if (acquireFence->isValid()) {
        acquireFenceFd = acquireFence->dup();
    }

    // ALOGD("fbPost: handle=%p, fence=%d", buf->handle, acquireFenceFd);
    disp.fbTargetHandle = buf->handle;
    disp.framebufferTarget->handle = disp.fbTargetHandle;
    disp.framebufferTarget->acquireFenceFd = acquireFenceFd;
    return NO_ERROR;
}

status_t HWComposer::prepare() {
    Mutex::Autolock _l(mDrawLock);
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
            ALOGW("WARNING: disp %zu: connected, non-null list, layers=%zu",
                  i, hwcNumHwLayers(disp.list));
        }
        mLists[i] = disp.list;
    }

    int err = hwcPrepare(mHwc, mLists);
    ALOGE_IF(err, "HWComposer: prepare failed (%s)", strerror(-err));

    if (err == NO_ERROR) {
        DisplayData& disp(mDisplayData[0]);
        disp.hasFbComp = false;
        disp.hasOvComp = false;
#ifdef QCOM_BSP
        disp.hasBlitComp = false;
#endif

        if (disp.list) {
#ifdef QCOM_BSP
           //GPUTILERECT
           prev_comp_map[i] = current_comp_map[i];
           current_comp_map[i].reset();
           current_comp_map[i].count = disp.list->numHwLayers-1;
#endif
            hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(disp.list);
            for (size_t i=0 ; i<hwcNumHwLayers(disp.list) ; i++) {
                hwc_layer_t& l = list0->hwLayers[i];

                //ALOGD("prepare: %d, type=%d, handle=%p",
                //        j, l.compositionType, l.handle);

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
#ifdef QCOM_BSP
                    disp.hasBlitComp = true;
#endif
                }
                if (l.compositionType == HWC_OVERLAY) {
                    disp.hasOvComp = true;
                }
                if (l.compositionType == HWC_CURSOR_OVERLAY) {
                    disp.hasOvComp = true;
                }
#ifdef QCOM_BSP
                //GPUTILERECT
                if(l.compositionType != HWC_FRAMEBUFFER_TARGET) {
                    current_comp_map[i].compType[j] = l.compositionType;
                }
#endif
            }
            if (disp.list->numHwLayers == (disp.framebufferTarget ? 1 : 0)) {
                disp.hasFbComp = true;
            }
        } else {
            disp.hasFbComp = true;
        }
    }
    return (status_t)err;
}

#ifdef QCOM_BSP
bool HWComposer::hasBlitComposition(int32_t id) const {
    if (!mHwc || uint32_t(id) > 31 || !mAllocatedDisplayIDs.hasBit(id))
        return false;
    return mDisplayData[id].hasBlitComp;
}
#endif
bool HWComposer::hasHwcComposition(int32_t id) const {
    if (!mHwc || uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return false;
    return mDisplayData[id].hasOvComp;
}

bool HWComposer::hasGlesComposition(int32_t id) const {
    if (!mHwc || uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return true;
    return mDisplayData[id].hasFbComp;
}

sp<Fence> HWComposer::getAndResetReleaseFence(int32_t id) {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return Fence::NO_FENCE;

    int fd = INVALID_OPERATION;

    return fd >= 0 ? new Fence(fd) : Fence::NO_FENCE;
}

status_t HWComposer::commit() {
    int err = NO_ERROR;
    if (mHwc) {
        err = hwcSet(mHwc, eglGetCurrentDisplay(), eglGetCurrentSurface(EGL_DRAW),
                const_cast<hwc_display_contents_1_t**>(mLists));
    }
    for (size_t i=0 ; i<mNumDisplays ; i++) {
        DisplayData& disp(mDisplayData[i]);
        disp.lastDisplayFence = disp.lastRetireFence;
        disp.lastRetireFence = Fence::NO_FENCE;
        if (disp.list) {
            hwcFlags(disp.list) &= ~HWC_GEOMETRY_CHANGED;
        }
    }
    return (status_t)err;
}

status_t HWComposer::setPowerMode(int disp, int mode) {
    LOG_FATAL_IF(disp >= VIRTUAL_DISPLAY_ID_BASE);
    if (mHwc) {
        if (mode == HWC_POWER_MODE_OFF) {
            if (hwcHasVsyncEvent(mHwc)) {
                eventControl(disp, HWC_EVENT_VSYNC, 0);
            }
        }
            return (status_t)hwcBlank(mHwc,
                    mode == HWC_POWER_MODE_OFF ? 1 : 0);
    }
    return NO_ERROR;
}

status_t HWComposer::setActiveConfig(int disp, int mode) {
    LOG_FATAL_IF(disp >= VIRTUAL_DISPLAY_ID_BASE);
    DisplayData& dd(mDisplayData[disp]);
    LOG_FATAL_IF(mode != 0);

    return NO_ERROR;
}

int HWComposer::getActiveConfig(int disp) const {
    LOG_FATAL_IF(disp >= VIRTUAL_DISPLAY_ID_BASE);
    return 0;
}

void HWComposer::disconnectDisplay(int disp) {
    LOG_ALWAYS_FATAL_IF(disp < 0 || disp == HWC_DISPLAY_PRIMARY);
    DisplayData& dd(mDisplayData[disp]);
    free(dd.list);
    dd.list = NULL;
    dd.framebufferTarget = NULL;    // points into dd.list
    dd.fbTargetHandle = NULL;
    dd.outbufHandle = NULL;
    dd.lastRetireFence = Fence::NO_FENCE;
    dd.lastDisplayFence = Fence::NO_FENCE;
    dd.outbufAcquireFence = Fence::NO_FENCE;
    // clear all the previous configs and repopulate when a new
    // device is added
    dd.configs.clear();
}

int HWComposer::getVisualID() const {
    return mFbDev->format;
}

bool HWComposer::supportsFramebufferTarget() const {
    return false;
}

int HWComposer::fbPost(int32_t id,
        const sp<Fence>& acquireFence, const sp<GraphicBuffer>& buffer) {
    acquireFence->waitForever("HWComposer::fbPost");
    return mFbDev->post(mFbDev, buffer->handle);
}

int HWComposer::fbCompositionComplete() {
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

status_t HWComposer::setOutputBuffer(int32_t id, const sp<Fence>& acquireFence,
        const sp<GraphicBuffer>& buf) {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return BAD_INDEX;
    if (id < VIRTUAL_DISPLAY_ID_BASE)
        return INVALID_OPERATION;

    DisplayData& disp(mDisplayData[id]);
    disp.outbufHandle = buf->handle;
    disp.outbufAcquireFence = acquireFence;
    return NO_ERROR;
}

sp<Fence> HWComposer::getLastRetireFence(int32_t id) const {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return Fence::NO_FENCE;
    return mDisplayData[id].lastRetireFence;
}

status_t HWComposer::setCursorPositionAsync(int32_t id, const Rect& pos)
{
    if (mHwc->setCursorPositionAsync) {
        return (status_t)mHwc->setCursorPositionAsync(mHwc, id, pos.left, pos.top);
    }
    else {
        return NO_ERROR;
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
    virtual sp<Fence> getAndResetReleaseFence() {
        // not supported on VERSION_03
        return Fence::NO_FENCE;
    }
    bool isStatusBar(hwc_layer_t* layer) {
        /* Getting the display details into the iterator is more trouble than
         * it's worth, so do a rough approximation */

        // Aligned to the top-left corner and less than 60px tall
        if (layer->displayFrame.top == 0 &&
            layer->displayFrame.left == 0 && layer->displayFrame.bottom < 60) {
            return true;
        }
        // Landscape:
        // Aligned to the top, right-cropped at less than 60px
        if (layer->displayFrame.top == 0 &&
            layer->sourceCrop.right < 60) {
            return true;
        }
        // Upside-down:
        // Left-aligned, bottom-cropped at less than 60, and the projected frame matches the crop height
        if (layer->displayFrame.left == 0 && layer->sourceCrop.bottom < 60 &&
            layer->displayFrame.bottom - layer->displayFrame.top == layer->sourceCrop.bottom) {
            return true;
        }
        return false;
    }

    virtual void setPlaneAlpha(uint8_t alpha) {
        bool forceSkip = false;
        // PREMULT on the statusbar layer will artifact miserably on VERSION_03
        // due to the translucency, so skip compositing
        if (getLayer()->blending == HWC_BLENDING_PREMULT && isStatusBar(getLayer())) {
            forceSkip = true;
        }
        if (alpha < 0xFF || forceSkip) {
            getLayer()->flags |= HWC_SKIP_LAYER;
        }
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
    virtual void setCrop(const FloatRect& crop) {
        /*
         * Since h/w composer didn't support a flot crop rect before version 1.3,
         * using integer coordinates instead produces a different output from the GL code in
         * Layer::drawWithOpenGL(). The difference can be large if the buffer crop to
         * window size ratio is large and a window crop is defined
         * (i.e.: if we scale the buffer a lot and we also crop it with a window crop).
         */
        hwc_rect_t& r = getLayer()->sourceCrop;
        r.left  = int(ceilf(crop.left));
        r.top   = int(ceilf(crop.top));
        r.right = int(floorf(crop.right));
        r.bottom= int(floorf(crop.bottom));
    }
    virtual void setVisibleRegionScreen(const Region& reg) {
        // Region::getSharedBuffer creates a reference to the underlying
        // SharedBuffer of this Region, this reference is freed
        // in onDisplayed()
        hwc_region_t& visibleRegion = getLayer()->visibleRegionScreen;
        SharedBuffer const* sb = reg.getSharedBuffer(&visibleRegion.numRects);
        visibleRegion.rects = reinterpret_cast<hwc_rect_t const *>(sb->data());
    }
#ifdef QCOM_BSP
    virtual void setDirtyRect(const Rect& dirtyRect) {
        // Unimplemented
    }
#endif
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

/*
 * returns an iterator initialized at a given index in the layer list
 */
HWComposer::LayerListIterator HWComposer::getLayerIterator(int32_t id, size_t index) {
    if (uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id)) {
        return LayerListIterator();
    }
    const DisplayData& disp(mDisplayData[id]);
    if (!mHwc || !disp.list || index > hwcNumHwLayers(disp.list))
        return LayerListIterator();
    hwc_layer_list_t* list0 = reinterpret_cast<hwc_layer_list_t*>(disp.list);
    return LayerListIterator(new HWCLayerVersion0(list0->hwLayers), index);
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
            numLayers = hwcNumHwLayers(disp.list);
        }
    }
    return getLayerIterator(id, numLayers);
}

// Converts a PixelFormat to a human-readable string.  Max 11 chars.
// (Could use a table of prefab String8 objects.)
static String8 getFormatStr(PixelFormat format) {
    switch (format) {
    case PIXEL_FORMAT_RGBA_8888:    return String8("RGBA_8888");
    case PIXEL_FORMAT_RGBA_4444:    return String8("RGBA_4444");
    case PIXEL_FORMAT_RGBA_5551:    return String8("RGBA_5551");
    case PIXEL_FORMAT_RGBX_8888:    return String8("RGBx_8888");
    case PIXEL_FORMAT_RGB_888:      return String8("RGB_888");
    case PIXEL_FORMAT_RGB_565:      return String8("RGB_565");
    case PIXEL_FORMAT_BGRA_8888:    return String8("BGRA_8888");
    case PIXEL_FORMAT_sRGB_A_8888:  return String8("sRGB_A_8888");
    case PIXEL_FORMAT_sRGB_X_8888:  return String8("sRGB_x_8888");
    case HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED:
                                    return String8("ImplDef");
    default:
        String8 result;
        result.appendFormat("? %08x", format);
        return result;
    }
}

void HWComposer::dump(String8& result) const {
    Mutex::Autolock _l(mDrawLock);
    if (mHwc) {
        result.appendFormat("Hardware Composer state (version %08x):\n", hwcApiVersion(mHwc));
        result.appendFormat("  mDebugForceFakeVSync=%d\n", mDebugForceFakeVSync);
        for (size_t i=0 ; i<mNumDisplays ; i++) {
            const DisplayData& disp(mDisplayData[i]);
            if (!disp.connected)
                continue;

            const Vector< sp<Layer> >& visibleLayersSortedByZ =
                    mFlinger->getLayerSortedByZForHwcDisplay(i);


            result.appendFormat("  Display[%zd] configurations (* current):\n", i);
            for (size_t c = 0; c < disp.configs.size(); ++c) {
                const DisplayConfig& config(disp.configs[c]);
#ifdef QCOM_BSP
                result.appendFormat("    %s%zd: %ux%u, xdpi=%f, ydpi=%f, secure=%d refresh=%" PRId64 "\n",
                        c == disp.currentConfig ? "* " : "", c, config.width, config.height,
                        config.xdpi, config.ydpi, config.secure, config.refresh);
#else
                result.appendFormat("    %s%zd: %ux%u, xdpi=%f, ydpi=%f, refresh=%" PRId64 "\n",
                        c == disp.currentConfig ? "* " : "", c, config.width, config.height,
                        config.xdpi, config.ydpi, config.refresh);
#endif
            }

            if (disp.list) {
                result.appendFormat(
                        "  numHwLayers=%zu, flags=%08x\n",
                        disp.list->numHwLayers, disp.list->flags);
                result.append(

                        "    type   |  handle  | hint | flag | tr | blnd |  format     |     source crop(l,t,r,b)       |           frame        |      dirtyRect         |  name \n"
                        "------------+----------+----------+----------+----+-------+----------+-----------------------------------+---------------------------+-------------------\n");
                //      " __________ | ________ | ________ | ________ | __ | _____ | ________ | [_____._,_____._,_____._,_____._] | [_____,_____,_____,_____] | [_____,_____,_____,_____] |
                for (size_t i=0 ; i<disp.list->numHwLayers ; i++) {
                    const hwc_layer_1_t&l = disp.list->hwLayers[i];
                    int32_t format = -1;
                    String8 name("unknown");

                    if (i < visibleLayersSortedByZ.size()) {
                        const sp<Layer>& layer(visibleLayersSortedByZ[i]);
                        const sp<GraphicBuffer>& buffer(
                                layer->getActiveBuffer());
                        if (buffer != NULL) {
                            format = buffer->getPixelFormat();
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
                            "BKGND",
                            "FB TARGET",
                            "SIDEBAND",
                            "HWC_CURSOR",
                            "FB_BLIT",
                            "UNKNOWN"};
                    if (type >= NELEM(compositionTypeName))
                        type = NELEM(compositionTypeName) - 1;

                    String8 formatStr = getFormatStr(format);
                    result.appendFormat(
                            " %9s | %08" PRIxPTR " | %04x | %04x | %02x | %04x | %-11s |%7d,%7d,%7d,%7d |%5d,%5d,%5d,%5d | [%5d,%5d,%5d,%5d] | %s\n",
                                    compositionTypeName[type],
                                    intptr_t(l.handle), l.hints, l.flags, l.transform, l.blending, formatStr.string(),
                                    l.sourceCrop.left, l.sourceCrop.top, l.sourceCrop.right, l.sourceCrop.bottom,
                                    l.displayFrame.left, l.displayFrame.top, l.displayFrame.right, l.displayFrame.bottom,
#ifdef QCOM_BSP
                                    l.dirtyRect.left, l.dirtyRect.top, l.dirtyRect.right, l.dirtyRect.bottom,
#else
                                    0, 0, 0, 0,
#endif
                                    name.string());
                }
            }
        }
    }

    if (mHwc) {
        const size_t SIZE = 4096;
        char buffer[SIZE];
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

HWComposer::DisplayData::DisplayData()
:   configs(),
    currentConfig(0),
    format(HAL_PIXEL_FORMAT_RGBA_8888),
    connected(false),
    hasFbComp(false), hasOvComp(false),
    capacity(0), list(NULL),
    framebufferTarget(NULL), fbTargetHandle(0),
    lastRetireFence(Fence::NO_FENCE), lastDisplayFence(Fence::NO_FENCE),
    outbufHandle(NULL), outbufAcquireFence(Fence::NO_FENCE),
    events(0)
{}

HWComposer::DisplayData::~DisplayData() {
    free(list);
}

#ifdef QCOM_BSP
//======================== GPU TiledRect/DR changes =====================
bool HWComposer::areVisibleRegionsOverlapping(int32_t id ) {
    if (!mHwc || uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return false;
    const Vector< sp<Layer> >& currentLayers  =
            mFlinger->getLayerSortedByZForHwcDisplay(id);
    size_t count = currentLayers.size();
    Region consolidatedVisibleRegion;

    for (size_t i=0; i<count; i++) {
        //If there are any overlapping visible regions, disable GPUTileRect
        if(!consolidatedVisibleRegion.intersect(
                 currentLayers[i]->visibleRegion).isEmpty()){
            return true;
        }
        consolidatedVisibleRegion.orSelf(currentLayers[i]->visibleRegion);
    }
    return false;
}

bool HWComposer::canHandleOverlapArea(int32_t id, Rect unionDr) {
    DisplayData& disp(mDisplayData[id]);
    float layerAreaSum = 0;
    float drArea = ((unionDr.right-unionDr.left)* (unionDr.bottom-unionDr.top));
    hwc_layer_1_t& fbLayer = disp.list->hwLayers[disp.list->numHwLayers-1];
    hwc_rect_t fbDisplayFrame  = fbLayer.displayFrame;
    float fbLayerArea = ((fbDisplayFrame.right - fbDisplayFrame.left)*
              (fbDisplayFrame.bottom - fbDisplayFrame.top));

    //Compute sum of the Areas of FB layers intersecting with Union Dirty Rect
    for (size_t i=0; i<disp.list->numHwLayers-1; i++) {
        hwc_layer_1_t& layer = disp.list->hwLayers[i];
        if(layer.compositionType != HWC_FRAMEBUFFER)
           continue;

        hwc_rect_t displayFrame  = layer.displayFrame;
        Rect df(displayFrame.left, displayFrame.top,
              displayFrame.right, displayFrame.bottom);
        Rect df_dirty;
        df_dirty.clear();
        if(df.intersect(unionDr, &df_dirty))
            layerAreaSum += ((df_dirty.right - df_dirty.left)*
                  (df_dirty.bottom - df_dirty.top));
    }
    ALOGD_IF(GPUTILERECT_DEBUG,"GPUTileRect: overlap/FB : %f",
           (layerAreaSum/fbLayerArea));
    // Return false, if the sum of layer Areas intersecting with union Dr is
    // more than the threshold as we are not getting better performance.
    return (mDynThreshold > (layerAreaSum/fbLayerArea));
}

bool HWComposer::needsScaling(int32_t id) {
    if (!mHwc || uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return false;
    DisplayData& disp(mDisplayData[id]);
    for (size_t i=0; i<disp.list->numHwLayers-1; i++) {
        int dst_w, dst_h, src_w, src_h;
        hwc_layer_1_t& layer = disp.list->hwLayers[i];
        hwc_rect_t displayFrame  = layer.displayFrame;

        hwc_rect_t sourceCropI = {0,0,0,0};
        sourceCropI.left = int(ceilf(layer.sourceCropf.left));
        sourceCropI.top = int(ceilf(layer.sourceCropf.top));
        sourceCropI.right = int(floorf(layer.sourceCropf.right));
        sourceCropI.bottom = int(floorf(layer.sourceCropf.bottom));

        dst_w = displayFrame.right - displayFrame.left;
        dst_h = displayFrame.bottom - displayFrame.top;
        src_w = sourceCropI.right - sourceCropI.left;
        src_h = sourceCropI.bottom - sourceCropI.top;

        if(((src_w != dst_w) || (src_h != dst_h))) {
            return true;
        }
    }
    return false;
}

void HWComposer::computeUnionDirtyRect(int32_t id, Rect& unionDirtyRect) {
    if (!mHwc || uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return;
    const Vector< sp<Layer> >& currentLayers =
            mFlinger->getLayerSortedByZForHwcDisplay(id);
    size_t count = currentLayers.size();
    Region unionDirtyRegion;
    DisplayData& disp(mDisplayData[id]);

    // Find UnionDr of all layers
    for (size_t i=0; i<count; i++) {
        hwc_layer_1_t& l = disp.list->hwLayers[i];
        Rect dr;
        dr.clear();
        if((l.compositionType == HWC_FRAMEBUFFER) &&
              currentLayers[i]->hasNewFrame()) {
            dr = Rect(l.dirtyRect.left, l.dirtyRect.top, l.dirtyRect.right,
                  l.dirtyRect.bottom);
            hwc_rect_t dst = l.displayFrame;

            //Map dirtyRect to layer destination before using
            hwc_rect_t src = {0,0,0,0};
            src.left = int(ceilf(l.sourceCropf.left));
            src.top = int(ceilf(l.sourceCropf.top));
            src.right = int(floorf(l.sourceCropf.right));
            src.bottom = int(floorf(l.sourceCropf.bottom));

            int x_off = dst.left - src.left;
            int y_off = dst.top - src.top;
            dr = dr.offsetBy(x_off, y_off);
            unionDirtyRegion = unionDirtyRegion.orSelf(dr);
        }
    }
    unionDirtyRect = unionDirtyRegion.getBounds();
}
bool HWComposer::isCompositionMapChanged(int32_t id) {
    if (prev_comp_map[id] == current_comp_map[id]) {
        return false;
    }
    return true;
}
bool HWComposer::isGeometryChanged(int32_t id) {
    if (!mHwc || uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return false;
    DisplayData& disp(mDisplayData[id]);
    return ( disp.list->flags & HWC_GEOMETRY_CHANGED );
}
/* Finds if we can enable DR optimization for GpuComp
 * 1. return false if geometry is changed
 * 2. if overlapping visible regions present.
 * 3. Compute a Union Dirty Rect to operate on. */
bool HWComposer::canUseTiledDR(int32_t id, Rect& unionDr ){
    if (!mHwc || uint32_t(id)>31 || !mAllocatedDisplayIDs.hasBit(id))
        return false;

    bool status = true;
    if (isGeometryChanged(id)) {
        ALOGD_IF(GPUTILERECT_DEBUG, "GPUTileRect : geometrychanged, disable");
        status = false;
    } else if ( hasBlitComposition(id)) {
        ALOGD_IF(GPUTILERECT_DEBUG, "GPUTileRect: Blit comp, disable");
        status = false;
    } else if ( isCompositionMapChanged(id)) {
        ALOGD_IF(GPUTILERECT_DEBUG, "GPUTileRect: comp map changed, disable");
        status = false;
    } else if (needsScaling(id)) {
       /* Do Not use TiledDR optimization, if layers need scaling */
       ALOGD_IF(GPUTILERECT_DEBUG, "GPUTileRect: Layers need scaling, disable");
       status = false;
    } else {
        computeUnionDirtyRect(id, unionDr);
        if(areVisibleRegionsOverlapping(id) &&
              !canHandleOverlapArea(id, unionDr)){
           /* With DR optimizaton, On certain targets we are seeing slightly
            * lower FPS in use cases where visible regions overlap &
            * the total dirty area of layers is greater than a threshold value.
            * Hence this optimization has been disabled for such use cases */
            ALOGD_IF(GPUTILERECT_DEBUG, "GPUTileRect: Visible \
                 regions overlap & Total Dirty Area > Threashold, disable");
            status = false;
        } else if(unionDr.isEmpty()) {
            ALOGD_IF(GPUTILERECT_DEBUG,"GPUTileRect: UnionDr is emtpy, \
                  No need to PRESERVE");
            status = false;
        }
    }
    return status;
}
#endif

}; // namespace android
