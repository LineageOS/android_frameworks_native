/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "LayerBE"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "Layer.h"

#include <android-base/stringprintf.h>
#include <renderengine/RenderEngine.h>

#include <string>

namespace android {

LayerBE::LayerBE(Layer* layer, std::string layerName)
      : mLayer(layer),
        mMesh(renderengine::Mesh::TRIANGLE_FAN, 4, 2, 2) {
    compositionInfo.layer = std::make_shared<LayerBE>(*this);
    compositionInfo.layerName = layerName;
}

LayerBE::LayerBE(const LayerBE& layer)
      : mLayer(layer.mLayer),
        mMesh(renderengine::Mesh::TRIANGLE_FAN, 4, 2, 2) {
    compositionInfo.layer = layer.compositionInfo.layer;
    compositionInfo.layerName = layer.mLayer->getName().string();
}

void LayerBE::onLayerDisplayed(const sp<Fence>& releaseFence) {
    if (mLayer) {
        mLayer->onLayerDisplayed(releaseFence);
    }
}

void LayerBE::clear(renderengine::RenderEngine& engine) {
    engine.setupFillWithColor(0, 0, 0, 0);
    engine.drawMesh(mMesh);
}

void CompositionInfo::dump(const char* tag) const
{
    std::string logString;
    dump(logString, tag);
    ALOGV("%s", logString.c_str());
}

void CompositionInfo::dumpHwc(std::string& result, const char* tag) const {
    if (tag == nullptr) {
        result += base::StringPrintf("HWC parameters\n");
    } else {
        result += base::StringPrintf("[%s]HWC parameters\n", tag);
    }

    result += base::StringPrintf("\thwcLayer=%p\n", static_cast<HWC2::Layer*>(&*hwc.hwcLayer));
    result += base::StringPrintf("\tfence=%p\n", hwc.fence.get());
    result += base::StringPrintf("\tblendMode=%d\n", hwc.blendMode);
    result += base::StringPrintf("\ttransform=%d\n", hwc.transform);
    result += base::StringPrintf("\tz=%d\n", hwc.z);
    result += base::StringPrintf("\ttype=%d\n", hwc.type);
    result += base::StringPrintf("\tappId=%d\n", hwc.appId);
    result += base::StringPrintf("\tdisplayFrame=%4d %4d %4d %4d\n", hwc.displayFrame.left, hwc.displayFrame.top, hwc.displayFrame.right, hwc.displayFrame.bottom);
    result += base::StringPrintf("\talpha=%.3f", hwc.alpha);
    result += base::StringPrintf("\tsourceCrop=%6.1f %6.1f %6.1f %6.1f\n", hwc.sourceCrop.left, hwc.sourceCrop.top, hwc.sourceCrop.right, hwc.sourceCrop.bottom);

    {
        //
        // Keep a conversion from std::string to String8 and back until Region can use std::string
        //
        String8 regionString;
        hwc.visibleRegion.dump(regionString, "visibleRegion");
        hwc.surfaceDamage.dump(regionString, "surfaceDamage");
        result += regionString.string();
    }
}

void CompositionInfo::dumpRe(std::string& result, const char* tag) const {
    if (tag == nullptr) {
        result += base::StringPrintf("RenderEngine parameters:\n");
    } else {
        result += base::StringPrintf("[%s]RenderEngine parameters:\n", tag);
    }

    result += base::StringPrintf("\tblackoutLayer=%d\n", re.blackoutLayer);
    result += base::StringPrintf("\tclearArea=%d\n", re.clearArea);
    result += base::StringPrintf("\tpreMultipliedAlpha=%d\n", re.preMultipliedAlpha);
    result += base::StringPrintf("\topaque=%d\n", re.opaque);
    result += base::StringPrintf("\tdisableTexture=%d\n", re.disableTexture);
    result += base::StringPrintf("\tuseIdentityTransform=%d\n", re.useIdentityTransform);
}

void CompositionInfo::dump(std::string& result, const char* tag) const
{
    if (tag == nullptr) {
        result += base::StringPrintf("CompositionInfo\n");
    } else {
        result += base::StringPrintf("[%s]CompositionInfo\n", tag);
    }
    result += base::StringPrintf("\tLayerName: %s\n", layerName.c_str());
    result += base::StringPrintf("\tCompositionType: %d\n", compositionType);
    result += base::StringPrintf("\tmBuffer = %p\n", mBuffer.get());
    result += base::StringPrintf("\tmBufferSlot=%d\n", mBufferSlot);
    result += base::StringPrintf("\tdisplayFrame=%4d %4d %4d %4d\n", hwc.displayFrame.left, hwc.displayFrame.top, hwc.displayFrame.right, hwc.displayFrame.bottom);
    result += base::StringPrintf("\talpha=%f\n", hwc.alpha);
    result += base::StringPrintf("\tsourceCrop=%6.1f %6.1f %6.1f %6.1f\n", hwc.sourceCrop.left, hwc.sourceCrop.top, hwc.sourceCrop.right, hwc.sourceCrop.bottom);

    switch (compositionType) {
        case HWC2::Composition::Device:
            dumpHwc(result, tag);
            break;
        case HWC2::Composition::Client:
            dumpRe(result, tag);
            break;
        default:
            break;
    }
}

}; // namespace android
