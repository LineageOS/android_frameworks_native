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
#include <ui/Fence.h>
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
    sp<GraphicBuffer> buffer = nullptr;

    // Fence that will fire when the buffer is ready to be bound.
    sp<Fence> fence = nullptr;

    // Texture identifier to bind the external texture to.
    // TODO(alecmouri): This is GL-specific...make the type backend-agnostic.
    uint32_t textureName = 0;

    // Whether to use filtering when rendering the texture.
    bool useTextureFiltering = false;

    // Transform matrix to apply to texture coordinates.
    mat4 textureTransform = mat4();

    // Wheteher to use pre-multiplied alpha
    bool usePremultipliedAlpha = true;

    // Override flag that alpha for each pixel in the buffer *must* be 1.0.
    // LayerSettings::alpha is still used if isOpaque==true - this flag only
    // overrides the alpha channel of the buffer.
    bool isOpaque = false;

    // HDR color-space setting for Y410.
    bool isY410BT2020 = false;
    float maxMasteringLuminance = 0.0;
    float maxContentLuminance = 0.0;
};

// Metadata describing the layer geometry.
struct Geometry {
    // Boundaries of the layer.
    FloatRect boundaries = FloatRect();

    // Transform matrix to apply to mesh coordinates.
    mat4 positionTransform = mat4();

    // Radius of rounded corners, if greater than 0. Otherwise, this layer's
    // corners are not rounded.
    // Having corner radius will force GPU composition on the layer and its children, drawing it
    // with a special shader. The shader will receive the radius and the crop rectangle as input,
    // modifying the opacity of the destination texture, multiplying it by a number between 0 and 1.
    // We query Layer#getRoundedCornerState() to retrieve the radius as well as the rounded crop
    // rectangle to figure out how to apply the radius for this layer. The crop rectangle will be
    // in local layer coordinate space, so we have to take the layer transform into account when
    // walking up the tree.
    float roundedCornersRadius = 0.0;

    // Rectangle within which corners will be rounded.
    FloatRect roundedCornersCrop = FloatRect();
};

// Descriptor of the source pixels for this layer.
struct PixelSource {
    // Source buffer
    Buffer buffer = Buffer();

    // The solid color with which to fill the layer.
    // This should only be populated if we don't render from an application
    // buffer.
    half3 solidColor = half3(0.0f, 0.0f, 0.0f);
};

/*
 * Contains the configuration for the shadows drawn by single layer. Shadow follows
 * material design guidelines.
 */
struct ShadowSettings {
    // Color to the ambient shadow. The alpha is premultiplied.
    vec4 ambientColor = vec4();

    // Color to the spot shadow. The alpha is premultiplied. The position of the spot shadow
    // depends on the light position.
    vec4 spotColor = vec4();

    // Position of the light source used to cast the spot shadow.
    vec3 lightPos = vec3();

    // Radius of the spot light source. Smaller radius will have sharper edges,
    // larger radius will have softer shadows
    float lightRadius = 0.f;

    // Length of the cast shadow. If length is <= 0.f no shadows will be drawn.
    float length = 0.f;

    // If true fill in the casting layer is translucent and the shadow needs to fill the bounds.
    // Otherwise the shadow will only be drawn around the edges of the casting layer.
    bool casterIsTranslucent = false;
};

// The settings that RenderEngine requires for correctly rendering a Layer.
struct LayerSettings {
    // Geometry information
    Geometry geometry = Geometry();

    // Source pixels for this layer.
    PixelSource source = PixelSource();

    // Alpha option to blend with the source pixels
    half alpha = half(0.0);

    // Color space describing how the source pixels should be interpreted.
    ui::Dataspace sourceDataspace = ui::Dataspace::UNKNOWN;

    // Additional layer-specific color transform to be applied before the global
    // transform.
    mat4 colorTransform = mat4();

    // True if blending will be forced to be disabled.
    bool disableBlending = false;

    ShadowSettings shadow;
};

} // namespace renderengine
} // namespace android
