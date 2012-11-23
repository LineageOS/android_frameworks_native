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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/String8.h>
#include <utils/Thread.h>
#include <utils/Trace.h>
#include <utils/Vector.h>

#include <hardware/hardware.h>
#include <hardware/hwcomposer.h>

#include <cutils/log.h>
#include <cutils/properties.h>

#include <EGL/egl.h>

#include "LayerBase.h"
#include "HWComposer.h"
#include "SurfaceFlinger.h"
#ifdef QCOM_HARDWARE
#include "qcom_ui.h"
#include "hwc_utils.h"
#endif

namespace android {
// ---------------------------------------------------------------------------

HWComposer::HWComposer(
        const sp<SurfaceFlinger>& flinger,
        EventHandler& handler,
        nsecs_t refreshPeriod)
    : mFlinger(flinger),
      mModule(0), mHwc(0), mList(0), mCapacity(0),
#ifdef QCOM_HARDWARE
      mListDirty(NULL), mSwapRectOn(false),
#endif
      mNumOVLayers(0), mNumFBLayers(0),
      mDpy(EGL_NO_DISPLAY), mSur(EGL_NO_SURFACE),
      mEventHandler(handler),
      mRefreshPeriod(refreshPeriod),
      mVSyncCount(0), mDebugForceFakeVSync(false)
{
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.no_hw_vsync", value, "0");
    mDebugForceFakeVSync = atoi(value);

    bool needVSyncThread = false;
    int err = hw_get_module(HWC_HARDWARE_MODULE_ID, &mModule);
    ALOGW_IF(err, "%s module not found", HWC_HARDWARE_MODULE_ID);
    if (err == 0) {
        err = hwc_open(mModule, &mHwc);
        ALOGE_IF(err, "%s device failed to initialize (%s)",
                HWC_HARDWARE_COMPOSER, strerror(-err));
        if (err == 0) {
            if (mHwc->registerProcs) {
                mCBContext.hwc = this;
                mCBContext.procs.invalidate = &hook_invalidate;
                mCBContext.procs.vsync = &hook_vsync;
                mHwc->registerProcs(mHwc, &mCBContext.procs);
                memset(mCBContext.procs.zero, 0, sizeof(mCBContext.procs.zero));
            }
            if (mHwc->common.version >= HWC_DEVICE_API_VERSION_0_3) {
                if (mDebugForceFakeVSync) {
                    // make sure to turn h/w vsync off in "fake vsync" mode
                    mHwc->methods->eventControl(mHwc, HWC_EVENT_VSYNC, 0);
                }
            } else {
                needVSyncThread = true;
            }
        }
    } else {
        needVSyncThread = true;
    }

    if (needVSyncThread) {
        // we don't have VSYNC support, we need to fake it
        mVSyncThread = new VSyncThread(*this);
    }
}

HWComposer::~HWComposer() {
    eventControl(EVENT_VSYNC, 0);
    free(mList);
#ifdef QCOM_HARDWARE
    free(mListDirty);
#endif
    if (mVSyncThread != NULL) {
        mVSyncThread->requestExitAndWait();
    }
    if (mHwc) {
        hwc_close(mHwc);
    }
}

status_t HWComposer::initCheck() const {
    return mHwc ? NO_ERROR : NO_INIT;
}

void HWComposer::hook_invalidate(struct hwc_procs* procs) {
    reinterpret_cast<cb_context *>(procs)->hwc->invalidate();
}

void HWComposer::hook_vsync(struct hwc_procs* procs, int dpy, int64_t timestamp) {
    reinterpret_cast<cb_context *>(procs)->hwc->vsync(dpy, timestamp);
}

void HWComposer::invalidate() {
    mFlinger->repaintEverything();
}

void HWComposer::vsync(int dpy, int64_t timestamp) {
    ATRACE_INT("VSYNC", ++mVSyncCount&1);
    mEventHandler.onVSyncReceived(dpy, timestamp);
}

void HWComposer::eventControl(int event, int enabled) {
    status_t err = NO_ERROR;
    if (mHwc && mHwc->common.version >= HWC_DEVICE_API_VERSION_0_3) {
        if (!mDebugForceFakeVSync) {
            err = mHwc->methods->eventControl(mHwc, event, enabled);
            // error here should not happen -- not sure what we should
            // do if it does.
            ALOGE_IF(err, "eventControl(%d, %d) failed %s",
                    event, enabled, strerror(-err));
        }
    }

    if (err == NO_ERROR && mVSyncThread != NULL) {
        mVSyncThread->setEnabled(enabled);
    }
}

void HWComposer::setFrameBuffer(EGLDisplay dpy, EGLSurface sur) {
    mDpy = (hwc_display_t)dpy;
    mSur = (hwc_surface_t)sur;
}

status_t HWComposer::createWorkList(size_t numLayers) {
    if (mHwc) {
        if (!mList || mCapacity < numLayers) {
            free(mList);
            size_t size = sizeof(hwc_layer_list) + numLayers*sizeof(hwc_layer_t);
            mList = (hwc_layer_list_t*)malloc(size);
            mCapacity = numLayers;
        }
        mList->flags = HWC_GEOMETRY_CHANGED;
        mList->numHwLayers = numLayers;
    }
    return NO_ERROR;
}

#ifdef QCOM_HARDWARE
status_t HWComposer::createDirtyWorkList(int layerNum, Rect dirtyRect) {
    if (mHwc && (layerNum >= 0 && (size_t)layerNum <= mCapacity) &&
                dirtyRect.isValid()) {
        if (!mListDirty) {
            free(mListDirty);
            size_t size = sizeof(hwc_layer_list) + 1 *sizeof(hwc_layer_t);
            mListDirty = (hwc_layer_list_t*)malloc(size);
        }
        mListDirty->flags = HWC_GEOMETRY_CHANGED;
        mListDirty->numHwLayers = 1; // TODO: remove hard coding

        hwc_layer_t* const dirtyLayers( mListDirty->hwLayers);
        hwc_layer_t* const visibleLayers( mList->hwLayers);

        //TODO - is memcpy(dirtyLayers[m],visibleLayers[n]) better?
        dirtyLayers[0].compositionType = visibleLayers[layerNum].compositionType;
        dirtyLayers[0].flags = visibleLayers[layerNum].flags;
        dirtyLayers[0].hints = visibleLayers[layerNum].hints;
        dirtyLayers[0].handle = visibleLayers[layerNum].handle;
        dirtyLayers[0].transform = visibleLayers[layerNum].transform;
        dirtyLayers[0].sourceTransform = visibleLayers[layerNum].sourceTransform;
        dirtyLayers[0].blending = visibleLayers[layerNum].blending;
        dirtyLayers[0].visibleRegionScreen = visibleLayers[layerNum].visibleRegionScreen; // CHECK

        dirtyLayers[0].sourceCrop.left          = dirtyRect.left;
        dirtyLayers[0].sourceCrop.top           = dirtyRect.top;
        dirtyLayers[0].sourceCrop.right         = dirtyRect.right;
        dirtyLayers[0].sourceCrop.bottom        = dirtyRect.bottom;

        dirtyLayers[0].displayFrame.left        = dirtyRect.left;
        dirtyLayers[0].displayFrame.top         = dirtyRect.top;
        dirtyLayers[0].displayFrame.right       = dirtyRect.right;
        dirtyLayers[0].displayFrame.bottom      = dirtyRect.bottom;
    }
    //TODO - should we return any error code for the argument validation?
    return NO_ERROR;
}
#endif

status_t HWComposer::prepare() const {
    int err = mHwc->prepare(mHwc, mList);
    if (err == NO_ERROR) {
        size_t numOVLayers = 0;
        size_t numFBLayers = 0;
#ifdef QCOM_HARDWARE
        size_t numCopybitLayers = 0;
#endif
        size_t count = mList->numHwLayers;
        for (size_t i=0 ; i<count ; i++) {
            hwc_layer& l(mList->hwLayers[i]);
            if (l.flags & HWC_SKIP_LAYER) {
                l.compositionType = HWC_FRAMEBUFFER;
            }
            switch (l.compositionType) {
                case HWC_OVERLAY:
                    numOVLayers++;
                    break;
                case HWC_FRAMEBUFFER:
                    numFBLayers++;
                    break;
#ifdef QCOM_HARDWARE
                case qhwc::HWC_USE_COPYBIT:
                    numCopybitLayers++;
                    break;
                default:
                    if(qdutils::CBUtils::isUpdatingFB((int)l.compositionType))
                        numFBLayers++;
#endif
            }
        }
        mNumOVLayers = numOVLayers;
        mNumFBLayers = numFBLayers;
#ifdef QCOM_HARDWARE
        mNumCopybitLayers = numCopybitLayers;
#endif
    }
    return (status_t)err;
}

size_t HWComposer::getLayerCount(int type) const {
    switch (type) {
        case HWC_OVERLAY:
            return mNumOVLayers;
        case HWC_FRAMEBUFFER:
            return mNumFBLayers;
    }
    return 0;
}

status_t HWComposer::commit() const {
#ifdef QCOM_HARDWARE
    int err = mHwc->set(mHwc, mDpy, mSur, ((mSwapRectOn)?mListDirty:mList));
    if (mSwapRectOn && mListDirty) {
        mListDirty->flags &= ~HWC_GEOMETRY_CHANGED;
    } else if ( mList) {
#else
    int err = mHwc->set(mHwc, mDpy, mSur, mList);
    if (mList) {
#endif
        mList->flags &= ~HWC_GEOMETRY_CHANGED;
    }
    return (status_t)err;
}

status_t HWComposer::release() const {
    if (mHwc) {
        if (mHwc->common.version >= HWC_DEVICE_API_VERSION_0_3) {
            mHwc->methods->eventControl(mHwc, HWC_EVENT_VSYNC, 0);
        }
        int err = mHwc->set(mHwc, NULL, NULL, NULL);
        return (status_t)err;
    }
    return NO_ERROR;
}

status_t HWComposer::disable() {
    if (mHwc) {
        free(mList);
        mList = NULL;
#ifdef QCOM_HARDWARE
        free(mListDirty);
        mListDirty = NULL;
#endif
        int err = mHwc->prepare(mHwc, NULL);
        return (status_t)err;
    }
    return NO_ERROR;
}

size_t HWComposer::getNumLayers() const {
    return mList ? mList->numHwLayers : 0;
}

hwc_layer_t* HWComposer::getLayers() const {
    return mList ? mList->hwLayers : 0;
}

#ifdef QCOM_HARDWARE
int HWComposer::isCopybitComposition() const {
    if (mHwc && mList && (qdutils::MDPVersion::getInstance().getMDPVersion() < 400)) {
        if (mNumCopybitLayers == mList->numHwLayers)
            return 1;
    }
    return 0;
}

void HWComposer::setSwapRectOn(bool enable)
{
    mSwapRectOn = enable;
}
#endif

void HWComposer::dump(String8& result, char* buffer, size_t SIZE,
        const Vector< sp<LayerBase> >& visibleLayersSortedByZ) const {
    if (mHwc && mList) {
        result.append("Hardware Composer state:\n");
        result.appendFormat("  mDebugForceFakeVSync=%d\n",
                mDebugForceFakeVSync);
        result.appendFormat("  numHwLayers=%u, flags=%08x\n",
                mList->numHwLayers, mList->flags);
        result.append(
                "   type   |  handle  |   hints  |   flags  | tr | blend |  format  |       source crop         |           frame           name \n"
                "----------+----------+----------+----------+----+-------+----------+---------------------------+--------------------------------\n");
        //      " ________ | ________ | ________ | ________ | __ | _____ | ________ | [_____,_____,_____,_____] | [_____,_____,_____,_____]
        for (size_t i=0 ; i<mList->numHwLayers ; i++) {
            const hwc_layer_t& l(mList->hwLayers[i]);
            const sp<LayerBase> layer(visibleLayersSortedByZ[i]);
            int32_t format = -1;
            if (layer->getLayer() != NULL) {
                const sp<GraphicBuffer>& buffer(layer->getLayer()->getActiveBuffer());
                if (buffer != NULL) {
                    format = buffer->getPixelFormat();
                }
            }
            result.appendFormat(
                    " %8s | %08x | %08x | %08x | %02x | %05x | %08x | [%5d,%5d,%5d,%5d] | [%5d,%5d,%5d,%5d] %s\n",
#ifdef QCOM_HARDWARE
                    (l.compositionType == HWC_FRAMEBUFFER)? "FB(GPU)":
                    (l.compositionType == HWC_OVERLAY)? "OVERLAY":
                    (l.compositionType == qhwc::HWC_USE_COPYBIT)? "COPYBIT": "???",
#else
                    l.compositionType ? "OVERLAY" : "FB",
#endif
                    intptr_t(l.handle), l.hints, l.flags, l.transform, l.blending, format,
                    l.sourceCrop.left, l.sourceCrop.top, l.sourceCrop.right, l.sourceCrop.bottom,
                    l.displayFrame.left, l.displayFrame.top, l.displayFrame.right, l.displayFrame.bottom,
                    layer->getName().string());
        }
#ifdef QCOM_HARDWARE
        if(mSwapRectOn && mListDirty) {
            // Dirty Rect Layers info if SwapRect is enabled
            result.append(
                    "----------+----------+----------+----------+----+-------+----------+---------------------------+--------------------------------\n"
                    "  SwapRect Dirty layers\n");
            result.appendFormat("    numHwLayers=%u, flags=%08x\n",
                    mListDirty->numHwLayers, mListDirty->flags);
            result.append(
                    "   type   |  handle  |   hints  |   flags  | tr | blend |  format  |       source crop         |           frame           name \n"
                    "----------+----------+----------+----------+----+-------+----------+---------------------------+--------------------------------\n");
            //      " ________ | ________ | ________ | ________ | __ | _____ | ________ | [_____,_____,_____,_____] | [_____,_____,_____,_____]
            for (size_t i=0 ; i<mListDirty->numHwLayers ; i++) {
                const hwc_layer_t& ld(mListDirty->hwLayers[i]);
                for (size_t i=0 ; i<mList->numHwLayers ; i++) {
                    const hwc_layer_t& l(mList->hwLayers[i]);
                    const sp<LayerBase> layer(visibleLayersSortedByZ[i]);
                    if (ld.handle == l.handle) {
                        int32_t format = -1;
                        if (layer->getLayer() != NULL) {
                            const sp<GraphicBuffer>& buffer(layer->getLayer()->getActiveBuffer());
                            if (buffer != NULL) {
                                format = buffer->getPixelFormat();
                            }
                        }
                        result.appendFormat(
                                " %8s | %08x | %08x | %08x | %02x | %05x | %08x | [%5d,%5d,%5d,%5d] | [%5d,%5d,%5d,%5d] %s\n",
                                (l.compositionType == HWC_FRAMEBUFFER)? "FB(GPU)":
                                (l.compositionType == HWC_OVERLAY)? "OVERLAY":
                                (l.compositionType == qhwc::HWC_USE_COPYBIT)? "COPYBIT": "???",
                                intptr_t(l.handle), l.hints, l.flags, l.transform, l.blending, format,
                                l.sourceCrop.left, l.sourceCrop.top, l.sourceCrop.right, l.sourceCrop.bottom,
                                l.displayFrame.left, l.displayFrame.top, l.displayFrame.right, l.displayFrame.bottom,
                                layer->getName().string());
                        result.append(
                                "----------+----------+----------+----------+----+-------+----------+---------------------------+--------------------------------\n");
                    }
                }
            }
        }
#endif
    }
    if (mHwc && mHwc->common.version >= HWC_DEVICE_API_VERSION_0_1 && mHwc->dump) {
        mHwc->dump(mHwc, buffer, SIZE);
        result.append(buffer);
    }
}

// ---------------------------------------------------------------------------

HWComposer::VSyncThread::VSyncThread(HWComposer& hwc)
    : mHwc(hwc), mEnabled(false),
      mNextFakeVSync(0),
      mRefreshPeriod(hwc.mRefreshPeriod)
{
}

void HWComposer::VSyncThread::setEnabled(bool enabled) {
    Mutex::Autolock _l(mLock);
    mEnabled = enabled;
    mCondition.signal();
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

    if (err == 0) {
        mHwc.mEventHandler.onVSyncReceived(0, next_vsync);
    }

    return true;
}

// ---------------------------------------------------------------------------
}; // namespace android
