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

#include "ColorSpaces.h"
#include "log/log_main.h"
#include "utils/Trace.h"

namespace android {
namespace renderengine {
namespace skia {

AutoBackendTexture::AutoBackendTexture(GrDirectContext* context, AHardwareBuffer* buffer,
                                       bool isOutputBuffer, CleanupManager& cleanupMgr)
      : mCleanupMgr(cleanupMgr), mIsOutputBuffer(isOutputBuffer) {
    ATRACE_CALL();
    AHardwareBuffer_Desc desc;
    AHardwareBuffer_describe(buffer, &desc);
    bool createProtectedImage = 0 != (desc.usage & AHARDWAREBUFFER_USAGE_PROTECTED_CONTENT);
    GrBackendFormat backendFormat =
            GrAHardwareBufferUtils::GetBackendFormat(context, buffer, desc.format, false);
    mBackendTexture =
            GrAHardwareBufferUtils::MakeBackendTexture(context, buffer, desc.width, desc.height,
                                                       &mDeleteProc, &mUpdateProc, &mImageCtx,
                                                       createProtectedImage, backendFormat,
                                                       isOutputBuffer);
    mColorType = GrAHardwareBufferUtils::GetSkColorTypeFromBufferFormat(desc.format);
    if (!mBackendTexture.isValid() || !desc.width || !desc.height) {
        LOG_ALWAYS_FATAL("Failed to create a valid texture. [%p]:[%d,%d] isProtected:%d "
                         "isWriteable:%d format:%d",
                         this, desc.width, desc.height, createProtectedImage, isOutputBuffer,
                         desc.format);
    }
}

AutoBackendTexture::~AutoBackendTexture() {
    if (mBackendTexture.isValid()) {
        mDeleteProc(mImageCtx);
        mBackendTexture = {};
    }
}

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
void AutoBackendTexture::releaseImageProc(SkImage::ReleaseContext releaseContext) {
    AutoBackendTexture* textureRelease = reinterpret_cast<AutoBackendTexture*>(releaseContext);
    textureRelease->unref(false);
}

void logFatalTexture(const char* msg, const GrBackendTexture& tex, ui::Dataspace dataspace,
                     SkColorType colorType) {
    GrGLTextureInfo textureInfo;
    bool retrievedTextureInfo = tex.getGLTextureInfo(&textureInfo);
    LOG_ALWAYS_FATAL("%s isTextureValid:%d dataspace:%d"
                     "\n\tGrBackendTexture: (%i x %i) hasMipmaps: %i isProtected: %i texType: %i"
                     "\n\t\tGrGLTextureInfo: success: %i fTarget: %u fFormat: %u colorType %i",
                     msg, tex.isValid(), dataspace, tex.width(), tex.height(), tex.hasMipmaps(),
                     tex.isProtected(), static_cast<int>(tex.textureType()), retrievedTextureInfo,
                     textureInfo.fTarget, textureInfo.fFormat, colorType);
}

sk_sp<SkImage> AutoBackendTexture::makeImage(ui::Dataspace dataspace, SkAlphaType alphaType,
                                             GrDirectContext* context) {
    ATRACE_CALL();

    if (mBackendTexture.isValid()) {
        mUpdateProc(mImageCtx, context);
    }

    auto colorType = mColorType;
    if (alphaType == kOpaque_SkAlphaType) {
        if (colorType == kRGBA_8888_SkColorType) {
            colorType = kRGB_888x_SkColorType;
        }
    }

    sk_sp<SkImage> image =
            SkImage::MakeFromTexture(context, mBackendTexture, kTopLeft_GrSurfaceOrigin, colorType,
                                     alphaType, toSkColorSpace(dataspace), releaseImageProc, this);
    if (image.get()) {
        // The following ref will be counteracted by releaseProc, when SkImage is discarded.
        ref();
    }

    mImage = image;
    mDataspace = dataspace;
    if (!mImage) {
        logFatalTexture("Unable to generate SkImage.", mBackendTexture, dataspace, colorType);
    }
    return mImage;
}

sk_sp<SkSurface> AutoBackendTexture::getOrCreateSurface(ui::Dataspace dataspace,
                                                        GrDirectContext* context) {
    ATRACE_CALL();
    LOG_ALWAYS_FATAL_IF(!mIsOutputBuffer, "You can't generate a SkSurface for a read-only texture");
    if (!mSurface.get() || mDataspace != dataspace) {
        sk_sp<SkSurface> surface =
                SkSurface::MakeFromBackendTexture(context, mBackendTexture,
                                                  kTopLeft_GrSurfaceOrigin, 0, mColorType,
                                                  toSkColorSpace(dataspace), nullptr,
                                                  releaseSurfaceProc, this);
        if (surface.get()) {
            // The following ref will be counteracted by releaseProc, when SkSurface is discarded.
            ref();
        }
        mSurface = surface;
    }

    mDataspace = dataspace;
    if (!mSurface) {
        logFatalTexture("Unable to generate SkSurface.", mBackendTexture, dataspace, mColorType);
    }
    return mSurface;
}

} // namespace skia
} // namespace renderengine
} // namespace android
