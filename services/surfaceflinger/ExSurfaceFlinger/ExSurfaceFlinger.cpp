/* Copyright (c) 2015, 2018, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "ExSurfaceFlinger.h"
#include <fstream>
#include <cutils/properties.h>
#include <ui/GraphicBufferAllocator.h>

namespace android {

bool ExSurfaceFlinger::sAllowHDRFallBack = false;

ExSurfaceFlinger::ExSurfaceFlinger() {
    char property[PROPERTY_VALUE_MAX] = {0};

    mDebugLogs = false;
    if ((property_get("vendor.display.qdframework_logs", property, NULL) > 0) &&
        (!strncmp(property, "1", PROPERTY_VALUE_MAX ) ||
         (!strncasecmp(property,"true", PROPERTY_VALUE_MAX )))) {
        mDebugLogs = true;
    }

    ALOGD_IF(isDebug(),"Creating custom SurfaceFlinger %s",__FUNCTION__);

    mDisableExtAnimation = false;
    if ((property_get("vendor.display.disable_ext_animation", property, "0") > 0) &&
        (!strncmp(property, "1", PROPERTY_VALUE_MAX ) ||
         (!strncasecmp(property,"true", PROPERTY_VALUE_MAX )))) {
        mDisableExtAnimation = true;
    }

    ALOGD_IF(isDebug(),"Animation on external is %s in %s",
             mDisableExtAnimation ? "disabled" : "not disabled", __FUNCTION__);

    if((property_get("vendor.display.hwc_disable_hdr", property, "0") > 0) &&
       (!strncmp(property, "1", PROPERTY_VALUE_MAX ) ||
        (!strncasecmp(property,"true", PROPERTY_VALUE_MAX )))) {
       sAllowHDRFallBack = true;
    }
}

ExSurfaceFlinger::~ExSurfaceFlinger() { }

void ExSurfaceFlinger::handleDPTransactionIfNeeded(
        const Vector<DisplayState>& displays) {
    /* Wait for one draw cycle before setting display projection only when the disable
     * external rotation animation feature is enabled
     */
    if (mDisableExtAnimation) {
        size_t count = displays.size();
        for (size_t i=0 ; i<count ; i++) {
            const DisplayState& s(displays[i]);
            if (getDisplayType(s.token) != DisplayDevice::DISPLAY_PRIMARY) {
                const uint32_t what = s.what;
                /* Invalidate and wait on eDisplayProjectionChanged to trigger a draw cycle so that
                 * it can fix one incorrect frame on the External, when we
                 * disable external animation
                 */
                if (what & DisplayState::eDisplayProjectionChanged) {
                    Mutex::Autolock lock(mExtAnimationLock);
                    invalidateHwcGeometry();
                    android_atomic_or(1, &mRepaintEverything);
                    signalRefresh();
                    mExtAnimationCond.waitRelative(mExtAnimationLock, 1000000000);
                }
            }
        }
    }
}

}; // namespace android
