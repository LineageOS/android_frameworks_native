/*
 * Copyright 2022 The Android Open Source Project
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

#include <gui/LayerState.h>

namespace android::fake {

// Class which exposes buffer properties from BufferData without holding on to an actual buffer
class BufferData : public android::BufferData {
public:
    BufferData(uint64_t bufferId, uint32_t width, uint32_t height, int32_t pixelFormat,
               uint64_t outUsage)
          : mBufferId(bufferId),
            mWidth(width),
            mHeight(height),
            mPixelFormat(pixelFormat),
            mOutUsage(outUsage) {}
    bool hasBuffer() const override { return mBufferId != 0; }
    bool hasSameBuffer(const android::BufferData& other) const override {
        return getId() == other.getId() && frameNumber == other.frameNumber;
    }
    uint32_t getWidth() const override { return mWidth; }
    uint32_t getHeight() const override { return mHeight; }
    uint64_t getId() const override { return mBufferId; }
    PixelFormat getPixelFormat() const override { return mPixelFormat; }
    uint64_t getUsage() const override { return mOutUsage; }

private:
    uint64_t mBufferId;
    uint32_t mWidth;
    uint32_t mHeight;
    int32_t mPixelFormat;
    uint64_t mOutUsage;
};

} // namespace android::fake
