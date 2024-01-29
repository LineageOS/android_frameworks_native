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

#include <memory>

#include <compositionengine/RenderSurface.h>
#include <renderengine/impl/ExternalTexture.h>
#include <ui/Fence.h>
#include <ui/Size.h>

namespace android {

// ScreenCaptureRenderSurface is a RenderSurface that returns a preallocated buffer used by
// ScreenCaptureOutput.
class ScreenCaptureRenderSurface : public compositionengine::RenderSurface {
public:
    ScreenCaptureRenderSurface(std::shared_ptr<renderengine::ExternalTexture> buffer)
          : mBuffer(std::move(buffer)){};

    std::shared_ptr<renderengine::ExternalTexture> dequeueBuffer(
            base::unique_fd* /* bufferFence */) override {
        return mBuffer;
    }

    void queueBuffer(base::unique_fd readyFence, float) override {
        mRenderFence = sp<Fence>::make(readyFence.release());
    }

    const sp<Fence>& getClientTargetAcquireFence() const override { return mRenderFence; }

    bool supportsCompositionStrategyPrediction() const override { return false; }

    bool isValid() const override { return true; }

    void initialize() override {}

    const ui::Size& getSize() const override { return mSize; }

    bool isProtected() const override { return mBuffer->getUsage() & GRALLOC_USAGE_PROTECTED; }

    void setDisplaySize(const ui::Size&) override {}

    void setBufferDataspace(ui::Dataspace) override {}

    void setBufferPixelFormat(ui::PixelFormat) override {}

    void setProtected(bool /* useProtected */) override {}

    status_t beginFrame(bool /* mustRecompose */) override { return OK; }

    void prepareFrame(bool /* usesClientComposition */, bool /* usesDeviceComposition */) override {
    }

    void onPresentDisplayCompleted() override {}

    void dump(std::string& /* result */) const override {}

private:
    std::shared_ptr<renderengine::ExternalTexture> mBuffer;

    sp<Fence> mRenderFence = Fence::NO_FENCE;

    ui::Size mSize;
};

} // namespace android
