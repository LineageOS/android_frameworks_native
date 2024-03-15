/*
 * Copyright 2020 The Android Open Source Project
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

#include "AutoBackendTexture.h"

#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <include/core/SkImage.h>
#include <include/core/SkSurface.h>

#include "compat/SkiaBackendTexture.h"

#include <log/log_main.h>
#include <utils/Trace.h>

namespace android {
namespace renderengine {
namespace skia {

AutoBackendTexture::AutoBackendTexture(std::unique_ptr<SkiaBackendTexture> backendTexture,
                                       CleanupManager& cleanupMgr)
      : mCleanupMgr(cleanupMgr), mBackendTexture(std::move(backendTexture)) {}

void AutoBackendTexture::unref(bool releaseLocalResources) {
    if (releaseLocalResources) {
        mSurface = nullptr;
        mImage = nullptr;
    }

    mUsageCount--;
    if (mUsageCount <= 0) {
        mCleanupMgr.add(this);
    }
}

// releaseSurfaceProc is invoked by SkSurface, when the texture is no longer in use.
// "releaseContext" contains an "AutoBackendTexture*".
void AutoBackendTexture::releaseSurfaceProc(SkSurface::ReleaseContext releaseContext) {
    AutoBackendTexture* textureRelease = reinterpret_cast<AutoBackendTexture*>(releaseContext);
    textureRelease->unref(false);
}

// releaseImageProc is invoked by SkImage, when the texture is no longer in use.
// "releaseContext" contains an "AutoBackendTexture*".
void AutoBackendTexture::releaseImageProc(SkImages::ReleaseContext releaseContext) {
    AutoBackendTexture* textureRelease = reinterpret_cast<AutoBackendTexture*>(releaseContext);
    textureRelease->unref(false);
}

sk_sp<SkImage> AutoBackendTexture::makeImage(ui::Dataspace dataspace, SkAlphaType alphaType) {
    ATRACE_CALL();

    sk_sp<SkImage> image = mBackendTexture->makeImage(alphaType, dataspace, releaseImageProc, this);
    // The following ref will be counteracted by releaseProc, when SkImage is discarded.
    ref();

    mImage = image;
    mDataspace = dataspace;
    return mImage;
}

sk_sp<SkSurface> AutoBackendTexture::getOrCreateSurface(ui::Dataspace dataspace) {
    ATRACE_CALL();
    LOG_ALWAYS_FATAL_IF(!mBackendTexture->isOutputBuffer(),
                        "You can't generate an SkSurface for a read-only texture");
    if (!mSurface.get() || mDataspace != dataspace) {
        sk_sp<SkSurface> surface =
                mBackendTexture->makeSurface(dataspace, releaseSurfaceProc, this);
        // The following ref will be counteracted by releaseProc, when SkSurface is discarded.
        ref();

        mSurface = surface;
    }

    mDataspace = dataspace;
    return mSurface;
}

} // namespace skia
} // namespace renderengine
} // namespace android
