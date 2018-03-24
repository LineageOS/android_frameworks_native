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

#include <gui/HdrMetadata.h>
#include <ui/Region.h>

#include "SurfaceFlinger.h"

#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/HWComposerBufferCache.h"
#include "RenderEngine/Mesh.h"
#include "RenderEngine/Texture.h"

namespace android {

class LayerBE;

class LayerContainer
{
    public:
        LayerContainer(HWComposer* hwc, int32_t hwcId) : mHwc(hwc), mHwcId(hwcId) {
            mLayer = hwc->createLayer(hwcId);
        }

        ~LayerContainer() {
            mHwc->destroyLayer(mHwcId, mLayer);
        }

        HWC2::Layer* operator->() {
            return mLayer;
        }

        operator HWC2::Layer*const () const {
            return mLayer;
        }

    private:
        HWComposer* mHwc;
        int32_t mHwcId;
        HWC2::Layer* mLayer;
};

struct CompositionInfo {
    std::string layerName;
    HWC2::Composition compositionType;
    sp<GraphicBuffer> mBuffer = nullptr;
    int mBufferSlot = BufferQueue::INVALID_BUFFER_SLOT;
    LayerBE* layer = nullptr;
    bool updateBuffer = false;
    struct {
        std::shared_ptr<LayerContainer> hwcLayer;
        bool skipGeometry = true;
        int32_t hwid = -1;
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
        android_dataspace dataspace;
        hwc_color_t color;
        HdrMetadata hdrMetadata;
    } hwc;
    struct {
        Mesh* mesh;
        bool blackoutLayer = false;
        bool clearArea = false;
        bool preMultipliedAlpha = false;
        bool opaque = false;
        bool disableTexture = false;
        half4 color;
        Texture texture;
        bool useIdentityTransform = false;
        bool Y410BT2020 = false;
    } re;

    void dump(const char* tag) const;
    void dumpHwc(const char* tag) const;
    void dumpRe(const char* tag) const;
};

class LayerBE {
public:
    friend class Layer;
    friend class BufferLayer;
    friend class ColorLayer;
    friend class SurfaceFlinger;

    LayerBE(Layer* layer, std::string layerName);

    void onLayerDisplayed(const sp<Fence>& releaseFence);
    Mesh& getMesh() { return mMesh; }

private:
    Layer*const mLayer;
    // The mesh used to draw the layer in GLES composition mode
    Mesh mMesh;

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
        std::shared_ptr<LayerContainer> layer;
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
    // HWCInfo. This map key is a display layerStack.
    std::unordered_map<int32_t, HWCInfo> mHwcLayers;

    CompositionInfo compositionInfo;
};

}; // namespace android

