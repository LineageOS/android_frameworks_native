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

#define USE_COLOR_METADATA

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/Log.h>

#include <ui/GraphicBuffer.h>
#include <gralloc_priv.h>
#include <qdMetaData.h>
#include <color_metadata.h>

#include "ExBufferLayer.h"

#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <configstore/Utils.h>

using android::hardware::configstore::getBool;
using android::hardware::configstore::V1_0::ISurfaceFlingerConfigs;

namespace android {

ExBufferLayer::ExBufferLayer(SurfaceFlinger* flinger, const sp<Client>& client,
                 const String8& name, uint32_t w, uint32_t h, uint32_t flags)
    : BufferLayer(flinger, client, name, w, h, flags) {
    char property[PROPERTY_VALUE_MAX] = {0};

    mDebugLogs = false;
    mIsGPUAllowedForProtected = false;
    if ((property_get("vendor.display.qdframework_logs", property, NULL) > 0) &&
        (!strncmp(property, "1", PROPERTY_VALUE_MAX ) ||
         (!strncasecmp(property,"true", PROPERTY_VALUE_MAX )))) {
        mDebugLogs = true;
    }

    ALOGD_IF(isDebug(),"Creating custom Layer %s",__FUNCTION__);

    if ((property_get("vendor.gralloc.cp_level3", property, NULL) > 0) &&
           (atoi(property) == 1)) {
        mIsGPUAllowedForProtected = true;
    }

    mScreenshot = (std::string(name).find("ScreenshotSurface") != std::string::npos);
    const sp<const DisplayDevice> hw(mFlinger->getDefaultDisplayDevice());
    mHasHDRCapabilities = hw->hasHDR10Support() ||
                          hw->hasHLGSupport()   ||
                          hw->hasDolbyVisionSupport();

}

ExBufferLayer::~ExBufferLayer() {
}

bool ExBufferLayer::hasHdrDisplay() const {
    return getBool<ISurfaceFlingerConfigs, &ISurfaceFlingerConfigs::hasHDRDisplay>(false);
}

bool ExBufferLayer::isHDRLayer() const {
    const sp<GraphicBuffer>& activeBuffer(mActiveBuffer);
    if (!activeBuffer)
        return false;

    ANativeWindowBuffer* buffer = activeBuffer->getNativeBuffer();
    if (!buffer)
        return false;

    const private_handle_t* hnd = static_cast<private_handle_t*>
            (const_cast<native_handle_t*>(buffer->handle));
    if (!hnd)
        return false;

    ColorMetaData colorData;
    if (getMetaData(const_cast<private_handle_t *>(hnd), GET_COLOR_METADATA, &colorData) == 0) {
        if (colorData.colorPrimaries == ColorPrimaries_BT2020 &&
            (colorData.transfer == Transfer_SMPTE_ST2084 ||
            colorData.transfer == Transfer_HLG)) {
                return (!ExSurfaceFlinger::AllowHDRFallBack() &&
                        !mFlinger->IsHWCDisabled() &&  mHasHDRCapabilities);
        }
    }

    return false;
}

bool ExBufferLayer::canAllowGPUForProtected() const {
    if (isProtected()) {
        return mIsGPUAllowedForProtected;
    } else {
        return false;
    }
}

}; // namespace android