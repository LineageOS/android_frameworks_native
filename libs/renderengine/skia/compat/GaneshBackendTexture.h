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
#include "ui/GraphicTypes.h"

#include <include/android/GrAHardwareBufferUtils.h>
#include <include/core/SkColorSpace.h>
#include <include/gpu/GrDirectContext.h>

#include <android-base/macros.h>

namespace android::renderengine::skia {

class GaneshBackendTexture : public SkiaBackendTexture {
public:
    // Creates an internal GrBackendTexture whose contents come from the provided buffer.
    GaneshBackendTexture(sk_sp<GrDirectContext> grContext, AHardwareBuffer* buffer,
                         bool isOutputBuffer);

    ~GaneshBackendTexture() override;

    sk_sp<SkImage> makeImage(SkAlphaType alphaType, ui::Dataspace dataspace,
                             TextureReleaseProc releaseImageProc,
                             ReleaseContext releaseContext) override;

    sk_sp<SkSurface> makeSurface(ui::Dataspace dataspace, TextureReleaseProc releaseSurfaceProc,
                                 ReleaseContext releaseContext) override;

private:
    DISALLOW_COPY_AND_ASSIGN(GaneshBackendTexture);

    void logFatalTexture(const char* msg, ui::Dataspace dataspace, SkColorType colorType);

    const sk_sp<GrDirectContext> mGrContext;
    GrBackendTexture mBackendTexture;
    GrAHardwareBufferUtils::DeleteImageProc mDeleteProc;
    GrAHardwareBufferUtils::UpdateImageProc mUpdateProc;
    GrAHardwareBufferUtils::TexImageCtx mImageCtx;
};

} // namespace android::renderengine::skia
