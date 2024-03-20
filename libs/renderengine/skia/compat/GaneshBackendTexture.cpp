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

#include "GaneshBackendTexture.h"

#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <include/core/SkImage.h>
#include <include/gpu/GrDirectContext.h>
#include <include/gpu/ganesh/SkImageGanesh.h>
#include <include/gpu/ganesh/SkSurfaceGanesh.h>
#include <include/gpu/ganesh/gl/GrGLBackendSurface.h>
#include <include/gpu/ganesh/vk/GrVkBackendSurface.h>
#include <include/gpu/vk/GrVkTypes.h>

#include "skia/ColorSpaces.h"
#include "skia/compat/SkiaBackendTexture.h"

#include <android/hardware_buffer.h>
#include <log/log_main.h>
#include <utils/Trace.h>

namespace android::renderengine::skia {

GaneshBackendTexture::GaneshBackendTexture(sk_sp<GrDirectContext> grContext,
                                           AHardwareBuffer* buffer, bool isOutputBuffer)
      : SkiaBackendTexture(buffer, isOutputBuffer), mGrContext(grContext) {
    ATRACE_CALL();
    AHardwareBuffer_Desc desc;
    AHardwareBuffer_describe(buffer, &desc);
    const bool createProtectedImage = 0 != (desc.usage & AHARDWAREBUFFER_USAGE_PROTECTED_CONTENT);

    GrBackendFormat backendFormat;
    const GrBackendApi graphicsApi = grContext->backend();
    if (graphicsApi == GrBackendApi::kOpenGL) {
        backendFormat =
                GrAHardwareBufferUtils::GetGLBackendFormat(grContext.get(), desc.format, false);
        mBackendTexture =
                GrAHardwareBufferUtils::MakeGLBackendTexture(grContext.get(), buffer, desc.width,
                                                             desc.height, &mDeleteProc,
                                                             &mUpdateProc, &mImageCtx,
                                                             createProtectedImage, backendFormat,
                                                             isOutputBuffer);
    } else if (graphicsApi == GrBackendApi::kVulkan) {
        backendFormat = GrAHardwareBufferUtils::GetVulkanBackendFormat(grContext.get(), buffer,
                                                                       desc.format, false);
        mBackendTexture =
                GrAHardwareBufferUtils::MakeVulkanBackendTexture(grContext.get(), buffer,
                                                                 desc.width, desc.height,
                                                                 &mDeleteProc, &mUpdateProc,
                                                                 &mImageCtx, createProtectedImage,
                                                                 backendFormat, isOutputBuffer);
    } else {
        LOG_ALWAYS_FATAL("Unexpected graphics API %u", static_cast<unsigned>(graphicsApi));
    }

    if (!mBackendTexture.isValid() || !desc.width || !desc.height) {
        LOG_ALWAYS_FATAL("Failed to create a valid texture. [%p]:[%d,%d] isProtected:%d "
                         "isWriteable:%d format:%d",
                         this, desc.width, desc.height, createProtectedImage, isOutputBuffer,
                         desc.format);
    }
}

GaneshBackendTexture::~GaneshBackendTexture() {
    if (mBackendTexture.isValid()) {
        mDeleteProc(mImageCtx);
        mBackendTexture = {};
    }
}

sk_sp<SkImage> GaneshBackendTexture::makeImage(SkAlphaType alphaType, ui::Dataspace dataspace,
                                               TextureReleaseProc releaseImageProc,
                                               ReleaseContext releaseContext) {
    if (mBackendTexture.isValid()) {
        mUpdateProc(mImageCtx, mGrContext.get());
    }

    const SkColorType colorType = colorTypeForImage(alphaType);
    sk_sp<SkImage> image =
            SkImages::BorrowTextureFrom(mGrContext.get(), mBackendTexture, kTopLeft_GrSurfaceOrigin,
                                        colorType, alphaType, toSkColorSpace(dataspace),
                                        releaseImageProc, releaseContext);
    if (!image) {
        logFatalTexture("Unable to generate SkImage.", dataspace, colorType);
    }
    return image;
}

sk_sp<SkSurface> GaneshBackendTexture::makeSurface(ui::Dataspace dataspace,
                                                   TextureReleaseProc releaseSurfaceProc,
                                                   ReleaseContext releaseContext) {
    const SkColorType colorType = internalColorType();
    sk_sp<SkSurface> surface =
            SkSurfaces::WrapBackendTexture(mGrContext.get(), mBackendTexture,
                                           kTopLeft_GrSurfaceOrigin, 0, colorType,
                                           toSkColorSpace(dataspace), nullptr, releaseSurfaceProc,
                                           releaseContext);
    if (!surface) {
        logFatalTexture("Unable to generate SkSurface.", dataspace, colorType);
    }
    return surface;
}

void GaneshBackendTexture::logFatalTexture(const char* msg, ui::Dataspace dataspace,
                                           SkColorType colorType) {
    switch (mBackendTexture.backend()) {
        case GrBackendApi::kOpenGL: {
            GrGLTextureInfo textureInfo;
            bool retrievedTextureInfo =
                    GrBackendTextures::GetGLTextureInfo(mBackendTexture, &textureInfo);
            LOG_ALWAYS_FATAL("%s isTextureValid:%d dataspace:%d"
                             "\n\tGrBackendTexture: (%i x %i) hasMipmaps: %i isProtected: %i "
                             "texType: %i\n\t\tGrGLTextureInfo: success: %i fTarget: %u fFormat: %u"
                             " colorType %i",
                             msg, mBackendTexture.isValid(), static_cast<int32_t>(dataspace),
                             mBackendTexture.width(), mBackendTexture.height(),
                             mBackendTexture.hasMipmaps(), mBackendTexture.isProtected(),
                             static_cast<int>(mBackendTexture.textureType()), retrievedTextureInfo,
                             textureInfo.fTarget, textureInfo.fFormat, colorType);
            break;
        }
        case GrBackendApi::kVulkan: {
            GrVkImageInfo imageInfo;
            bool retrievedImageInfo =
                    GrBackendTextures::GetVkImageInfo(mBackendTexture, &imageInfo);
            LOG_ALWAYS_FATAL("%s isTextureValid:%d dataspace:%d"
                             "\n\tGrBackendTexture: (%i x %i) hasMipmaps: %i isProtected: %i "
                             "texType: %i\n\t\tVkImageInfo: success: %i fFormat: %i "
                             "fSampleCount: %u fLevelCount: %u colorType %i",
                             msg, mBackendTexture.isValid(), static_cast<int32_t>(dataspace),
                             mBackendTexture.width(), mBackendTexture.height(),
                             mBackendTexture.hasMipmaps(), mBackendTexture.isProtected(),
                             static_cast<int>(mBackendTexture.textureType()), retrievedImageInfo,
                             imageInfo.fFormat, imageInfo.fSampleCount, imageInfo.fLevelCount,
                             colorType);
            break;
        }
        default:
            LOG_ALWAYS_FATAL("%s Unexpected backend %u", msg,
                             static_cast<unsigned>(mBackendTexture.backend()));
            break;
    }
}

} // namespace android::renderengine::skia
