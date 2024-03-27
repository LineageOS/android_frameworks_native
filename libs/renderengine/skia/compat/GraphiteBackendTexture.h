/*
 * Copyright 2024 The Android Open Source Project
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

#include "SkiaBackendTexture.h"

#include <include/core/SkColorSpace.h>
#include <include/core/SkImage.h>
#include <include/core/SkSurface.h>
#include <include/gpu/graphite/BackendTexture.h>
#include <include/gpu/graphite/Recorder.h>

#include <android-base/macros.h>
#include <ui/GraphicTypes.h>

#include <memory>

namespace android::renderengine::skia {

class GraphiteBackendTexture : public SkiaBackendTexture {
public:
    // Creates an internal skgpu::graphite::BackendTexture whose contents come from the provided
    // buffer.
    GraphiteBackendTexture(std::shared_ptr<skgpu::graphite::Recorder> recorder,
                           AHardwareBuffer* buffer, bool isOutputBuffer);

    ~GraphiteBackendTexture() override;

    sk_sp<SkImage> makeImage(SkAlphaType alphaType, ui::Dataspace dataspace,
                             TextureReleaseProc releaseImageProc,
                             ReleaseContext releaseContext) override;

    sk_sp<SkSurface> makeSurface(ui::Dataspace dataspace, TextureReleaseProc releaseSurfaceProc,
                                 ReleaseContext releaseContext) override;

private:
    DISALLOW_COPY_AND_ASSIGN(GraphiteBackendTexture);

    void logFatalTexture(const char* msg, ui::Dataspace dataspace, SkColorType colorType);

    const std::shared_ptr<skgpu::graphite::Recorder> mRecorder;
    skgpu::graphite::BackendTexture mBackendTexture;
};

} // namespace android::renderengine::skia
