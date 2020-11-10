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

#include <utils/Trace.h>

#include "log/log_main.h"
#include "utils/Trace.h"

namespace android {
namespace renderengine {
namespace skia {

// Converts an android dataspace to a supported SkColorSpace
// Supported dataspaces are
// 1. sRGB
// 2. Display P3
// 3. BT2020 PQ
// 4. BT2020 HLG
// Unknown primaries are mapped to BT709, and unknown transfer functions
// are mapped to sRGB.
static sk_sp<SkColorSpace> toSkColorSpace(ui::Dataspace dataspace) {
    skcms_Matrix3x3 gamut;
    switch (dataspace & HAL_DATASPACE_STANDARD_MASK) {
        case HAL_DATASPACE_STANDARD_BT709:
            gamut = SkNamedGamut::kSRGB;
            break;
        case HAL_DATASPACE_STANDARD_BT2020:
            gamut = SkNamedGamut::kRec2020;
            break;
        case HAL_DATASPACE_STANDARD_DCI_P3:
            gamut = SkNamedGamut::kDisplayP3;
            break;
        default:
            ALOGV("Unsupported Gamut: %d, defaulting to sRGB", dataspace);
            gamut = SkNamedGamut::kSRGB;
            break;
    }

    switch (dataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_LINEAR:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kLinear, gamut);
        case HAL_DATASPACE_TRANSFER_SRGB:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, gamut);
        case HAL_DATASPACE_TRANSFER_ST2084:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kPQ, gamut);
        case HAL_DATASPACE_TRANSFER_HLG:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kHLG, gamut);
        default:
            ALOGV("Unsupported Gamma: %d, defaulting to sRGB transfer", dataspace);
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, gamut);
    }
}

AutoBackendTexture::AutoBackendTexture(GrDirectContext* context, AHardwareBuffer* buffer,
                                       bool isRender) {
    AHardwareBuffer_Desc desc;
    AHardwareBuffer_describe(buffer, &desc);
    bool createProtectedImage = 0 != (desc.usage & AHARDWAREBUFFER_USAGE_PROTECTED_CONTENT);
    GrBackendFormat backendFormat =
            GrAHardwareBufferUtils::GetBackendFormat(context, buffer, desc.format, false);
    mBackendTexture =
            GrAHardwareBufferUtils::MakeBackendTexture(context, buffer, desc.width, desc.height,
                                                       &mDeleteProc, &mUpdateProc, &mImageCtx,
                                                       createProtectedImage, backendFormat,
                                                       isRender);
    mColorType = GrAHardwareBufferUtils::GetSkColorTypeFromBufferFormat(desc.format);
}

void AutoBackendTexture::unref(bool releaseLocalResources) {
    if (releaseLocalResources) {
        mSurface = nullptr;
        mImage = nullptr;
    }

    mUsageCount--;
    if (mUsageCount <= 0) {
        if (mBackendTexture.isValid()) {
            mDeleteProc(mImageCtx);
            mBackendTexture = {};
        }
        delete this;
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

sk_sp<SkImage> AutoBackendTexture::makeImage(ui::Dataspace dataspace, SkAlphaType alphaType,
                                             GrDirectContext* context) {
    ATRACE_CALL();

    if (mBackendTexture.isValid()) {
        mUpdateProc(mImageCtx, context);
    }

    sk_sp<SkImage> image =
            SkImage::MakeFromTexture(context, mBackendTexture, kTopLeft_GrSurfaceOrigin, mColorType,
                                     alphaType, toSkColorSpace(dataspace), releaseImageProc, this);
    if (image.get()) {
        // The following ref will be counteracted by releaseProc, when SkImage is discarded.
        ref();
    }

    mImage = image;
    mDataspace = dataspace;
    LOG_ALWAYS_FATAL_IF(mImage == nullptr, "Unable to generate SkImage from buffer");
    return mImage;
}

sk_sp<SkSurface> AutoBackendTexture::getOrCreateSurface(ui::Dataspace dataspace,
                                                        GrDirectContext* context) {
    ATRACE_CALL();
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
    LOG_ALWAYS_FATAL_IF(mSurface == nullptr, "Unable to generate SkSurface");
    return mSurface;
}

} // namespace skia
} // namespace renderengine
} // namespace android