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

namespace android {

LayerBE::LayerBE(Layer* layer, std::string layerName)
      : mLayer(layer),
        mMesh(Mesh::TRIANGLE_FAN, 4, 2, 2) {
    compositionInfo.layer = this;
    compositionInfo.layerName = layerName;
}

void LayerBE::onLayerDisplayed(const sp<Fence>& releaseFence) {
    mLayer->onLayerDisplayed(releaseFence);
}

void CompositionInfo::dumpHwc(const char* tag) const {
    ALOGV("[%s]\thwcLayer=%p", tag, hwc.hwcLayer);
    ALOGV("[%s]\tfence=%p", tag, hwc.fence.get());
    ALOGV("[%s]\ttransform=%d", tag, hwc.transform);
    ALOGV("[%s]\tz=%d", tag, hwc.z);
    ALOGV("[%s]\ttype=%d", tag, hwc.type);
    ALOGV("[%s]\tappId=%d", tag, hwc.appId);
    ALOGV("[%s]\tdisplayFrame=%4d %4d %4d %4d", tag, hwc.displayFrame.left, hwc.displayFrame.top, hwc.displayFrame.right, hwc.displayFrame.bottom);
    ALOGV("[%s]\talpha=%.3f", tag, hwc.alpha);
    ALOGV("[%s]\tsourceCrop=%6.1f %6.1f %6.1f %6.1f", tag, hwc.sourceCrop.left, hwc.sourceCrop.top, hwc.sourceCrop.right, hwc.sourceCrop.bottom);

    std::string label = tag;
    label+=":visibleRegion";
    hwc.visibleRegion.dump(label.c_str());
    label = tag;
    label+=":surfaceDamage";
    hwc.surfaceDamage.dump(label.c_str());
}

void CompositionInfo::dumpRe(const char* tag) const {
    ALOGV("[%s]\tblackoutLayer=%d", tag, re.blackoutLayer);
    ALOGV("[%s]\tclearArea=%d", tag, re.clearArea);
    ALOGV("[%s]\tpreMultipliedAlpha=%d", tag, re.preMultipliedAlpha);
    ALOGV("[%s]\topaque=%d", tag, re.opaque);
    ALOGV("[%s]\tdisableTexture=%d", tag, re.disableTexture);
    ALOGV("[%s]\ttexture:name(%d), target(%d), size(%d/%d)", tag, re.texture.getTextureName(), re.texture.getTextureTarget(), (unsigned int)re.texture.getWidth(), (unsigned int)re.texture.getHeight());
    ALOGV("[%s]\tuseIdentityTransform=%d\n", tag, re.useIdentityTransform);
}

void CompositionInfo::dump(const char* tag) const {
    ALOGV("[%s] CompositionInfo", tag);
    ALOGV("[%s]\tLayerName: %s", tag, layerName.c_str());
    ALOGV("[%s]\tCompositionType: %d", tag, compositionType);
    ALOGV("[%s]\tmBuffer = %p", tag, mBuffer.get());
    ALOGV("[%s]\tmBufferSlot=%d", tag, mBufferSlot);
    switch (compositionType) {
        case HWC2::Composition::Device:
            dumpHwc(tag);
            break;
        case HWC2::Composition::Client:
            dumpRe(tag);
        default:
            break;
    }
}

}; // namespace android
