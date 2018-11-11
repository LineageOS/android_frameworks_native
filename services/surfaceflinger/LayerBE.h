/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <renderengine/Mesh.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/Texture.h>
#include <ui/Region.h>

#include "DisplayHardware/DisplayIdentification.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/HWComposerBufferCache.h"
#include "SurfaceFlinger.h"

namespace android {

class LayerBE;

struct CompositionInfo {
    std::string layerName;
    HWC2::Composition compositionType;
    bool firstClear = false;
    sp<GraphicBuffer> mBuffer = nullptr;
    int mBufferSlot = BufferQueue::INVALID_BUFFER_SLOT;
    std::shared_ptr<LayerBE> layer;
    struct {
        std::shared_ptr<HWC2::Layer> hwcLayer;
        DisplayId displayId;
        sp<Fence> fence;
        HWC2::BlendMode blendMode = HWC2::BlendMode::Invalid;
        Rect displayFrame;
        float alpha;
        FloatRect sourceCrop;
        HWC2::Transform transform = HWC2::Transform::None;
        int z;
        int type;
        int appId;
        Region visibleRegion;
        Region surfaceDamage;
        sp<NativeHandle> sidebandStream;
        ui::Dataspace dataspace;
        hwc_color_t color;
        bool clearClientTarget = false;
        bool supportedPerFrameMetadata = false;
        HdrMetadata hdrMetadata;
        mat4 colorTransform;
    } hwc;
    struct {
        bool blackoutLayer = false;
        bool clearArea = false;
        bool preMultipliedAlpha = false;
        bool opaque = false;
        bool disableTexture = false;
        half4 color;
        bool useIdentityTransform = false;
        bool Y410BT2020 = false;
    } re;

    void dump(const char* tag) const;
    void dump(std::string& result, const char* tag = nullptr) const;
    void dumpHwc(std::string& result, const char* tag = nullptr) const;
    void dumpRe(std::string& result, const char* tag = nullptr) const;
};

class LayerBE {
public:
    friend class Layer;
    friend class BufferLayer;
    friend class BufferQueueLayer;
    friend class BufferStateLayer;
    friend class ColorLayer;
    friend class SurfaceFlinger;

    // For unit tests
    friend class TestableSurfaceFlinger;

    LayerBE(Layer* layer, std::string layerName);
    explicit LayerBE(const LayerBE& layer);

    void onLayerDisplayed(const sp<Fence>& releaseFence);
    void clear(renderengine::RenderEngine& renderEngine);
    renderengine::Mesh& getMesh() { return mMesh; }

    Layer*const mLayer;
private:
    // The mesh used to draw the layer in GLES composition mode
    renderengine::Mesh mMesh;

    // HWC items, accessed from the main thread
    struct HWCInfo {
        HWCInfo()
              : hwc(nullptr),
                layer(nullptr),
                forceClientComposition(false),
                compositionType(HWC2::Composition::Invalid),
                clearClientTarget(false),
                transform(HWC2::Transform::None) {}

        HWComposer* hwc;
        std::shared_ptr<HWC2::Layer> layer;
        bool forceClientComposition;
        HWC2::Composition compositionType;
        bool clearClientTarget;
        Rect displayFrame;
        FloatRect sourceCrop;
        HWComposerBufferCache bufferCache;
        HWC2::Transform transform;
    };

    // A layer can be attached to multiple displays when operating in mirror mode
    // (a.k.a: when several displays are attached with equal layerStack). In this
    // case we need to keep track. In non-mirror mode, a layer will have only one
    // HWCInfo.
    std::unordered_map<DisplayId, HWCInfo> mHwcLayers;

    CompositionInfo compositionInfo;
};

}; // namespace android

