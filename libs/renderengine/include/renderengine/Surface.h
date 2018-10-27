/*
 * Copyright 2017 The Android Open Source Project
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

struct ANativeWindow;

namespace android {
namespace renderengine {

class Surface {
public:
    virtual ~Surface() = default;

    virtual void setCritical(bool enable) = 0;
    virtual void setAsync(bool enable) = 0;

    virtual void setNativeWindow(ANativeWindow* window) = 0;
    virtual void swapBuffers() const = 0;

    virtual int32_t queryRedSize() const = 0;
    virtual int32_t queryGreenSize() const = 0;
    virtual int32_t queryBlueSize() const = 0;
    virtual int32_t queryAlphaSize() const = 0;

    virtual int32_t getWidth() const = 0;
    virtual int32_t getHeight() const = 0;
};

} // namespace renderengine
} // namespace android
