/*
 * Copyright 2018 The Android Open Source Project
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

#include <math/mat4.h>
#include <math/vec3.h>
#include <renderengine/Texture.h>
#include <ui/FloatRect.h>
#include <ui/GraphicBuffer.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/Transform.h>

namespace android {
namespace renderengine {

// Metadata describing the input buffer to render from.
struct Buffer {
    // Buffer containing the image that we will render.
    // If buffer == nullptr, then the rest of the fields in this struct will be
    // ignored.
    sp<GraphicBuffer> buffer;

    // Texture identifier to bind the external texture to.
    // TODO(alecmouri): This is GL-specific...make the type backend-agnostic.
    uint32_t textureName;

    // Whether to use filtering when rendering the texture.
    bool useTextureFiltering;

    // Transform matrix to apply to texture coordinates.
    mat4 textureTransform;

    // Wheteher to use pre-multiplied alpha
    bool usePremultipliedAlpha;

    // HDR color-space setting for Y410.
    bool isY410BT2020;
};

// Metadata describing the layer geometry.
struct Geometry {
    // Boundaries of the layer.
    FloatRect boundaries;

    // Transform matrix to apply to mesh coordinates.
    mat4 positionTransform;
};

// Descriptor of the source pixels for this layer.
struct PixelSource {
    // Source buffer
    Buffer buffer;

    // The solid color with which to fill the layer.
    // This should only be populated if we don't render from an application
    // buffer.
    half3 solidColor;
};

// The settings that RenderEngine requires for correctly rendering a Layer.
struct LayerSettings {
    // Geometry information
    Geometry geometry;

    // Source pixels for this layer.
    PixelSource source;

    // Alpha option to apply to the source pixels
    half alpha;

    // Color space describing how the source pixels should be interpreted.
    ui::Dataspace sourceDataspace;
};

} // namespace renderengine
} // namespace android
