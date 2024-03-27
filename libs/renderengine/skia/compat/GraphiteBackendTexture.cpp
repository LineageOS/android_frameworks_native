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

#include "GraphiteBackendTexture.h"

#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <include/core/SkSurfaceProps.h>
#include <include/gpu/graphite/Image.h>
#include <include/gpu/graphite/Surface.h>
#include <include/gpu/graphite/TextureInfo.h>

#include "skia/ColorSpaces.h"

#include <android/hardware_buffer.h>
#include <inttypes.h>
#include <log/log_main.h>
#include <utils/Trace.h>

namespace android::renderengine::skia {

GraphiteBackendTexture::GraphiteBackendTexture(std::shared_ptr<skgpu::graphite::Recorder> recorder,
                                               AHardwareBuffer* buffer, bool isOutputBuffer)
      : SkiaBackendTexture(buffer, isOutputBuffer), mRecorder(std::move(recorder)) {
    ATRACE_CALL();
    AHardwareBuffer_Desc desc;
    AHardwareBuffer_describe(buffer, &desc);
    const bool createProtectedImage = 0 != (desc.usage & AHARDWAREBUFFER_USAGE_PROTECTED_CONTENT);

    const SkISize dimensions = {static_cast<int32_t>(desc.width),
                                static_cast<int32_t>(desc.height)};
    LOG_ALWAYS_FATAL_IF(static_cast<uint32_t>(dimensions.width()) != desc.width ||
                                static_cast<uint32_t>(dimensions.height()) != desc.height,
                        "Failed to create a valid texture, casting unsigned dimensions [%" PRIu32
                        ",%" PRIu32 "] to signed [%" PRIo32 ",%" PRIo32 "] "
                        "is invalid",
                        desc.width, desc.height, dimensions.width(), dimensions.height());

    mBackendTexture = mRecorder->createBackendTexture(buffer, isOutputBuffer, createProtectedImage,
                                                      dimensions, false);
    if (!mBackendTexture.isValid() || !dimensions.width() || !dimensions.height()) {
        LOG_ALWAYS_FATAL("Failed to create a valid texture. [%p]:[%d,%d] isProtected:%d "
                         "isWriteable:%d format:%d",
                         this, dimensions.width(), dimensions.height(), createProtectedImage,
                         isOutputBuffer, desc.format);
    }
}

GraphiteBackendTexture::~GraphiteBackendTexture() {
    if (mBackendTexture.isValid()) {
        mRecorder->deleteBackendTexture(mBackendTexture);
        mBackendTexture = {};
    }
}

sk_sp<SkImage> GraphiteBackendTexture::makeImage(SkAlphaType alphaType, ui::Dataspace dataspace,
                                                 TextureReleaseProc releaseImageProc,
                                                 ReleaseContext releaseContext) {
    const SkColorType colorType = colorTypeForImage(alphaType);
    sk_sp<SkImage> image =
            SkImages::WrapTexture(mRecorder.get(), mBackendTexture, colorType, alphaType,
                                  toSkColorSpace(dataspace), releaseImageProc, releaseContext);
    if (!image) {
        logFatalTexture("Unable to generate SkImage.", dataspace, colorType);
    }
    return image;
}

sk_sp<SkSurface> GraphiteBackendTexture::makeSurface(ui::Dataspace dataspace,
                                                     TextureReleaseProc releaseSurfaceProc,
                                                     ReleaseContext releaseContext) {
    const SkColorType colorType = internalColorType();
    SkSurfaceProps props;
    sk_sp<SkSurface> surface =
            SkSurfaces::WrapBackendTexture(mRecorder.get(), mBackendTexture, colorType,
                                           toSkColorSpace(dataspace), &props, releaseSurfaceProc,
                                           releaseContext);
    if (!surface) {
        logFatalTexture("Unable to generate SkSurface.", dataspace, colorType);
    }
    return surface;
}

void GraphiteBackendTexture::logFatalTexture(const char* msg, ui::Dataspace dataspace,
                                             SkColorType colorType) {
    // TODO: b/293371537 - Iterate on this logging (validate failure cases, possibly check
    // VulkanTextureInfo, etc.)
    const skgpu::graphite::TextureInfo& textureInfo = mBackendTexture.info();
    LOG_ALWAYS_FATAL("%s isOutputBuffer:%d, dataspace:%d, colorType:%d"
                     "\n\tBackendTexture: isValid:%d, dimensions:%dx%d"
                     "\n\t\tTextureInfo: isValid:%d, numSamples:%d, mipmapped:%d, isProtected: %d",
                     msg, isOutputBuffer(), static_cast<int32_t>(dataspace), colorType,
                     mBackendTexture.isValid(), mBackendTexture.dimensions().width(),
                     mBackendTexture.dimensions().height(), textureInfo.isValid(),
                     textureInfo.numSamples(), static_cast<int32_t>(textureInfo.mipmapped()),
                     static_cast<int32_t>(textureInfo.isProtected()));
}

} // namespace android::renderengine::skia
