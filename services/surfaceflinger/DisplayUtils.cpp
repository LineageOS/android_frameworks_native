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

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/Log.h>

#include <ui/GraphicBuffer.h>

#include <dlfcn.h>

#include "DisplayUtils.h"

#ifdef QCOM_UM_FAMILY
#include <ExSurfaceFlinger/ExBufferLayer.h>
#include <ExSurfaceFlinger/ExSurfaceFlinger.h>
#include <ExSurfaceFlinger/ExVirtualDisplaySurface.h>
#include <gralloc_priv.h>
#endif

namespace android {

DisplayUtils* DisplayUtils::sDisplayUtils = NULL;
bool DisplayUtils::sUseExtendedImpls = false;
bool DisplayUtils::sDirectStreaming = false;

DisplayUtils::DisplayUtils() {
#ifdef QCOM_UM_FAMILY
    char value[PROPERTY_VALUE_MAX] = {};
    property_get("vendor.display.disable_qti_bsp", value, "0");
    int disable_qti_bsp = atoi(value);
    sUseExtendedImpls = !disable_qti_bsp;
#endif
}

DisplayUtils* DisplayUtils::getInstance() {
    if (sDisplayUtils == NULL) {
        sDisplayUtils = new DisplayUtils();
    }
    return sDisplayUtils;
}

SurfaceFlinger* DisplayUtils::getSFInstance() {
#ifdef QCOM_UM_FAMILY
    if (sUseExtendedImpls) {
        return new ExSurfaceFlinger();
    }
#endif
    return new SurfaceFlinger();
}

BufferLayer* DisplayUtils::getBufferLayerInstance(SurfaceFlinger* flinger,
                            const sp<Client>& client, const String8& name,
                            uint32_t w, uint32_t h, uint32_t flags) {
#ifdef QCOM_UM_FAMILY
    if (sUseExtendedImpls) {
        return new ExBufferLayer(flinger, client, name, w, h, flags);
    }
#endif
    return new BufferLayer(flinger, client, name, w, h, flags);
}

void DisplayUtils::initVDSInstance(HWComposer & hwc, int32_t hwcDisplayId,
        sp<IGraphicBufferProducer> currentStateSurface, sp<DisplaySurface> &dispSurface,
        sp<IGraphicBufferProducer> &producer, sp<IGraphicBufferProducer> bqProducer,
        sp<IGraphicBufferConsumer> bqConsumer, String8 currentStateDisplayName,
        bool currentStateIsSecure)
{
    if (sUseExtendedImpls) {
#ifdef QCOM_UM_FAMILY
        VirtualDisplaySurface* vds = new ExVirtualDisplaySurface(hwc, hwcDisplayId,
                currentStateSurface, bqProducer, bqConsumer, currentStateDisplayName,
                currentStateIsSecure);
        dispSurface = vds;
        producer = vds;
#endif
    } else {
        VirtualDisplaySurface* vds = new VirtualDisplaySurface(hwc, hwcDisplayId,
                currentStateSurface, bqProducer, bqConsumer, currentStateDisplayName);
        dispSurface = vds;
        producer = vds;
    }
}

bool DisplayUtils::canAllocateHwcDisplayIdForVDS(uint64_t usage) {
    uint64_t flag_mask_pvt_wfd = ~0;
    uint64_t flag_mask_hw_video = ~0;
    char value[PROPERTY_VALUE_MAX] = {};
    property_get("vendor.display.vds_allow_hwc", value, "0");
    int allowHwcForVDS = atoi(value);

#ifdef QCOM_UM_FAMILY
    if (sUseExtendedImpls) {
        // Reserve hardware acceleration for WFD use-case
        // GRALLOC_USAGE_PRIVATE_WFD + GRALLOC_USAGE_HW_VIDEO_ENCODER = WFD using HW composer.
        flag_mask_pvt_wfd = GRALLOC_USAGE_PRIVATE_WFD;
        flag_mask_hw_video = GRALLOC_USAGE_HW_VIDEO_ENCODER;
        // GRALLOC_USAGE_PRIVATE_WFD + GRALLOC_USAGE_SW_READ_OFTEN
        // WFD using GLES (directstreaming).
        sDirectStreaming = ((usage & GRALLOC_USAGE_PRIVATE_WFD) &&
                            (usage & GRALLOC_USAGE_SW_READ_OFTEN));
    }
#endif

    return (allowHwcForVDS || ((usage & flag_mask_pvt_wfd) &&
            (usage & flag_mask_hw_video)));
}

bool DisplayUtils::skipColorLayer(const char* layerType) {
    return (sDirectStreaming && !strncmp(layerType, "ColorLayer", strlen("ColorLayer")));
}
}; // namespace android
