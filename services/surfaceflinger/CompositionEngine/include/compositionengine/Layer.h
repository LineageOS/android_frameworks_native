/*
 * Copyright 2019 The Android Open Source Project
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

#include <cstdint>

#include <utils/StrongPointer.h>

namespace android {

typedef int64_t nsecs_t;

namespace compositionengine {

class Display;
class LayerFE;

/**
 * A layer contains the output-independent composition state for a front-end
 * Layer
 */
class Layer {
public:
    virtual ~Layer();

    // Gets the front-end interface for this layer.  Can return nullptr if the
    // front-end layer no longer exists.
    virtual sp<LayerFE> getLayerFE() const = 0;
};

} // namespace compositionengine
} // namespace android
