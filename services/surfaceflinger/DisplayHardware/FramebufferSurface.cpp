/*
 **
 ** Copyright 2012 The Android Open Source Project
 **
 ** Licensed under the Apache License Version 2.0(the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing software
 ** distributed under the License is distributed on an "AS IS" BASIS
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "FramebufferSurface"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <cutils/log.h>

#include <utils/String8.h>

#include <ui/Rect.h>

#include <EGL/egl.h>

#include <hardware/hardware.h>
#include <gui/BufferItem.h>
#include <gui/GraphicBufferAlloc.h>
#include <gui/Surface.h>
#include <ui/GraphicBuffer.h>

#include "FramebufferSurface.h"
#include "HWComposer.h"

#ifndef NUM_FRAMEBUFFER_SURFACE_BUFFERS
#define NUM_FRAMEBUFFER_SURFACE_BUFFERS (2)
#endif

// ----------------------------------------------------------------------------
namespace android {
// ----------------------------------------------------------------------------

/*
 * This implements the (main) framebuffer management. This class is used
 * mostly by SurfaceFlinger, but also by command line GL application.
 *
 */

FramebufferSurface::FramebufferSurface(HWComposer& hwc, int disp,
        const sp<IGraphicBufferConsumer>& consumer) :
    ConsumerBase(consumer),
    mDisplayType(disp),
    mCurrentBufferSlot(-1),
    mCurrentBuffer(),
    mCurrentFence(Fence::NO_FENCE),
    mHwc(hwc),
    mHasPendingRelease(false),
    mPreviousBufferSlot(BufferQueue::INVALID_BUFFER_SLOT),
    mPreviousBuffer()
{
    ALOGV("Creating for display %d", disp);
    mName = "FramebufferSurface";
    mConsumer->setConsumerName(mName);
    mConsumer->setConsumerUsageBits(GRALLOC_USAGE_HW_FB |
                                       GRALLOC_USAGE_HW_RENDER |
                                       GRALLOC_USAGE_HW_COMPOSER);
    const auto& activeConfig = mHwc.getActiveConfig(disp);
    mConsumer->setDefaultBufferSize(activeConfig->getWidth(),
            activeConfig->getHeight());
    mConsumer->setMaxAcquiredBufferCount(NUM_FRAMEBUFFER_SURFACE_BUFFERS - 1);
}

status_t FramebufferSurface::beginFrame(bool /*mustRecompose*/) {
    return NO_ERROR;
}

status_t FramebufferSurface::prepareFrame(CompositionType /*compositionType*/) {
    return NO_ERROR;
}

status_t FramebufferSurface::advanceFrame() {
    sp<GraphicBuffer> buf;
    sp<Fence> acquireFence(Fence::NO_FENCE);
    android_dataspace_t dataspace = HAL_DATASPACE_UNKNOWN;
    status_t result = nextBuffer(buf, acquireFence, dataspace);
    if (result != NO_ERROR) {
        ALOGE("error latching next FramebufferSurface buffer: %s (%d)",
                strerror(-result), result);
        return result;
    }
    result = mHwc.setClientTarget(mDisplayType, acquireFence, buf, dataspace);
    if (result != NO_ERROR) {
        ALOGE("error posting framebuffer: %d", result);
    }
    return result;
}

status_t FramebufferSurface::nextBuffer(sp<GraphicBuffer>& outBuffer,
        sp<Fence>& outFence, android_dataspace_t& outDataspace) {
    Mutex::Autolock lock(mMutex);

    BufferItem item;
    status_t err = acquireBufferLocked(&item, 0);
    if (err == BufferQueue::NO_BUFFER_AVAILABLE) {
        outBuffer = mCurrentBuffer;
        return NO_ERROR;
    } else if (err != NO_ERROR) {
        ALOGE("error acquiring buffer: %s (%d)", strerror(-err), err);
        return err;
    }

    // If the BufferQueue has freed and reallocated a buffer in mCurrentSlot
    // then we may have acquired the slot we already own.  If we had released
    // our current buffer before we call acquireBuffer then that release call
    // would have returned STALE_BUFFER_SLOT, and we would have called
    // freeBufferLocked on that slot.  Because the buffer slot has already
    // been overwritten with the new buffer all we have to do is skip the
    // releaseBuffer call and we should be in the same state we'd be in if we
    // had released the old buffer first.
    if (mCurrentBufferSlot != BufferQueue::INVALID_BUFFER_SLOT &&
        item.mSlot != mCurrentBufferSlot) {
        mHasPendingRelease = true;
        mPreviousBufferSlot = mCurrentBufferSlot;
        mPreviousBuffer = mCurrentBuffer;
    }
    mCurrentBufferSlot = item.mSlot;
    mCurrentBuffer = mSlots[mCurrentBufferSlot].mGraphicBuffer;
    mCurrentFence = item.mFence;

    outFence = item.mFence;
    outBuffer = mCurrentBuffer;
    outDataspace = item.mDataSpace;
    return NO_ERROR;
}

void FramebufferSurface::freeBufferLocked(int slotIndex) {
    ConsumerBase::freeBufferLocked(slotIndex);
    if (slotIndex == mCurrentBufferSlot) {
        mCurrentBufferSlot = BufferQueue::INVALID_BUFFER_SLOT;
    }
}

void FramebufferSurface::onFrameCommitted() {
    if (mHasPendingRelease) {
        sp<Fence> fence = mHwc.getRetireFence(mDisplayType);
        if (fence->isValid()) {
            status_t result = addReleaseFence(mPreviousBufferSlot,
                    mPreviousBuffer, fence);
            ALOGE_IF(result != NO_ERROR, "onFrameCommitted: failed to add the"
                    " fence: %s (%d)", strerror(-result), result);
        }
        status_t result = releaseBufferLocked(mPreviousBufferSlot,
                mPreviousBuffer, EGL_NO_DISPLAY, EGL_NO_SYNC_KHR);
        ALOGE_IF(result != NO_ERROR, "onFrameCommitted: error releasing buffer:"
                " %s (%d)", strerror(-result), result);

        mPreviousBuffer.clear();
        mHasPendingRelease = false;
    }
}

void FramebufferSurface::dumpAsString(String8& result) const {
    ConsumerBase::dumpState(result);
}

void FramebufferSurface::dumpLocked(String8& result, const char* prefix) const
{
    ConsumerBase::dumpLocked(result, prefix);
}

const sp<Fence>& FramebufferSurface::getClientTargetAcquireFence() const {
    return mCurrentFence;
}

// ----------------------------------------------------------------------------
}; // namespace android
// ----------------------------------------------------------------------------
