/* Copyright (c) 2015, The Linux Foundation. All rights reserved.
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

#include "ExSurfaceFlinger.h"
#include "ExLayer.h"
#include "ExHWComposer.h"
#ifdef QTI_BSP
#include <hardware/display_defs.h>
#include <gralloc_priv.h>
#include <qdMetaData.h>
#endif

namespace android {

ExHWComposer::ExHWComposer(const sp<SurfaceFlinger>& flinger,
                           EventHandler& handler)
        : HWComposer(flinger, handler) {

    mVDSEnabled = false;
    char property[PROPERTY_VALUE_MAX] = {0};

    /* Read system property for VDS solution.
     * This property is expected to be setup once during bootup
     */
    if( (property_get("persist.hwc.enable_vds", property, NULL) > 0) &&
        ((!strncmp(property, "1", strlen("1"))) ||
         !strncasecmp(property, "true", strlen("true")))) {
        /* HAL virtual display is using VDS based implementation */
        mVDSEnabled = true;
    }

    mDebugLogs = false;
    if((property_get("persist.debug.qdframework.logs", property, NULL) > 0) &&
       (!strncmp(property, "1", PROPERTY_VALUE_MAX ) ||
        (!strncasecmp(property,"true", PROPERTY_VALUE_MAX )))) {
        mDebugLogs = true;
    }

    ALOGD_IF(isDebug(),"Creating custom HWC %s",__FUNCTION__);
}

ExHWComposer::~ExHWComposer() {
}

bool ExHWComposer::isCompositionTypeBlit(const int32_t compType) const {
#ifdef QTI_BSP
    return (compType == HWC_BLIT);
#else
    ALOGD_IF(mDebugLogs, "%s: compType = %d", __FUNCTION__, compType);
#endif
    return false;
}

#if defined(QTI_BSP) && defined(SDM_TARGET)
uint32_t ExHWComposer::getS3DFlag(int disp) const {
    if (disp < 0) {
        return 0;
    }

    const DisplayData& disp_data(mDisplayData[disp]);

    for (size_t i=0 ; i<disp_data.list->numHwLayers-1; i++) {
        const hwc_layer_1_t &l = disp_data.list->hwLayers[i];
        private_handle_t *pvt_handle = static_cast<private_handle_t *>
                                    (const_cast<native_handle_t*>(l.handle));

        if (pvt_handle != NULL) {
            struct S3DSFRender_t s3dRender;
            getMetaData(pvt_handle, GET_S3D_RENDER, &s3dRender);
            if (s3dRender.DisplayId == static_cast<uint32_t>(disp) && s3dRender.GpuRender) {
                return s3dRender.GpuS3dFormat;
            }
        }
    }
    return 0;
}
#endif

}; // namespace android
