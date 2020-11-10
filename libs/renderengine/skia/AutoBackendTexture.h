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

#pragma once

#include <GrAHardwareBufferUtils.h>
#include <GrDirectContext.h>
#include <SkImage.h>
#include <SkSurface.h>
#include <sys/types.h>

#include "android-base/macros.h"
#include "ui/GraphicTypes.h"

namespace android {
namespace renderengine {
namespace skia {

/**
 * AutoBackendTexture manages GPU image  lifetime. It is a ref-counted object
 * that keeps GPU resources alive until the last SkImage or SkSurface object using them is
 * destroyed.
 */
class AutoBackendTexture {
public:
    // Local reference that supports RAII-style management of an AutoBackendTexture
    // AutoBackendTexture by itself can't be managed in a similar fashion because
    // of shared ownership with Skia objects, so we wrap it here instead.
    class LocalRef {
    public:
        LocalRef() {}

        ~LocalRef() {
            // Destroying the texture is the same as setting it to null
            setTexture(nullptr);
        }

        // Sets the texture to locally ref-track.
        void setTexture(AutoBackendTexture* texture) {
            if (mTexture != nullptr) {
                mTexture->unref(true);
            }

            mTexture = texture;
            if (mTexture != nullptr) {
                mTexture->ref();
            }
        }

        AutoBackendTexture* getTexture() const { return mTexture; }

        DISALLOW_COPY_AND_ASSIGN(LocalRef);

    private:
        AutoBackendTexture* mTexture = nullptr;
    };

    // Creates a GrBackendTexture whose contents come from the provided buffer.
    AutoBackendTexture(GrDirectContext* context, AHardwareBuffer* buffer, bool isRender);

    void ref() { mUsageCount++; }

    // releaseLocalResources is true if the underlying SkImage and SkSurface
    // should be deleted from local tracking.
    void unref(bool releaseLocalResources);

    // Makes a new SkImage from the texture content.
    // As SkImages are immutable but buffer content is not, we create
    // a new SkImage every time.
    sk_sp<SkImage> makeImage(ui::Dataspace dataspace, SkAlphaType alphaType,
                             GrDirectContext* context);

    // Makes a new SkSurface from the texture content, if needed.
    sk_sp<SkSurface> getOrCreateSurface(ui::Dataspace dataspace, GrDirectContext* context);

private:
    // The only way to invoke dtor is with unref, when mUsageCount is 0.
    ~AutoBackendTexture() {}

    GrBackendTexture mBackendTexture;
    GrAHardwareBufferUtils::DeleteImageProc mDeleteProc;
    GrAHardwareBufferUtils::UpdateImageProc mUpdateProc;
    GrAHardwareBufferUtils::TexImageCtx mImageCtx;

    static void releaseSurfaceProc(SkSurface::ReleaseContext releaseContext);
    static void releaseImageProc(SkImage::ReleaseContext releaseContext);

    int mUsageCount = 0;

    sk_sp<SkImage> mImage = nullptr;
    sk_sp<SkSurface> mSurface = nullptr;
    ui::Dataspace mDataspace = ui::Dataspace::UNKNOWN;
    SkColorType mColorType = kUnknown_SkColorType;
};

} // namespace skia
} // namespace renderengine
} // namespace android
