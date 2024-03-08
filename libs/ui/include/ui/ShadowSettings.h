/*
 * Copyright 2023 The Android Open Source Project
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

#include <math/vec4.h>
#include "FloatRect.h"

namespace android {

/*
 * Contains the configuration for the shadows drawn by single layer. Shadow follows
 * material design guidelines.
 */
struct ShadowSettings {
    // Boundaries of the shadow.
    FloatRect boundaries = FloatRect();

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

static inline bool operator==(const ShadowSettings& lhs, const ShadowSettings& rhs) {
    return lhs.boundaries == rhs.boundaries && lhs.ambientColor == rhs.ambientColor &&
            lhs.spotColor == rhs.spotColor && lhs.lightPos == rhs.lightPos &&
            lhs.lightRadius == rhs.lightRadius && lhs.length == rhs.length &&
            lhs.casterIsTranslucent == rhs.casterIsTranslucent;
}

static inline bool operator!=(const ShadowSettings& lhs, const ShadowSettings& rhs) {
    return !(operator==(lhs, rhs));
}

} // namespace android