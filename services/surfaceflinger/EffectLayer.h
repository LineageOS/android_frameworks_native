/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <sys/types.h>

#include <cstdint>

#include "BufferStateLayer.h"

namespace android {

// A layer that can render a combination of the following effects.
//   * fill the bounds of the layer with a color
//   * render a shadow cast by the bounds of the layer
// If no effects are enabled, the layer is considered to be invisible.
class EffectLayer : public BufferStateLayer {
public:
    explicit EffectLayer(const LayerCreationArgs&);
    ~EffectLayer() override;
};

} // namespace android
