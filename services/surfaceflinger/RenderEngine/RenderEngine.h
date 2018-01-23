/*
 * Copyright 2013 The Android Open Source Project
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

#ifndef SF_RENDERENGINE_H_
#define SF_RENDERENGINE_H_

#include <memory>

#include <stdint.h>
#include <sys/types.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <Transform.h>
#include <android-base/unique_fd.h>
#include <gui/SurfaceControl.h>
#include <math/mat4.h>

#define EGL_NO_CONFIG ((EGLConfig)0)

struct ANativeWindowBuffer;

// ---------------------------------------------------------------------------
namespace android {
// ---------------------------------------------------------------------------

class String8;
class Rect;
class Region;
class Mesh;
class Texture;

namespace RE {
class Image;
class Surface;
} // namespace RE

class RenderEngine {
    enum GlesVersion {
        GLES_VERSION_1_0 = 0x10000,
        GLES_VERSION_1_1 = 0x10001,
        GLES_VERSION_2_0 = 0x20000,
        GLES_VERSION_3_0 = 0x30000,
    };
    static GlesVersion parseGlesVersion(const char* str);

    EGLDisplay mEGLDisplay;
    EGLConfig mEGLConfig;
    EGLContext mEGLContext;
    void setEGLHandles(EGLDisplay display, EGLConfig config, EGLContext ctxt);

    virtual void bindImageAsFramebuffer(EGLImageKHR image, uint32_t* texName, uint32_t* fbName,
                                        uint32_t* status) = 0;
    virtual void unbindFramebuffer(uint32_t texName, uint32_t fbName) = 0;

    static bool overrideUseContextPriorityFromConfig(bool useContextPriority);

protected:
    RenderEngine();

public:
    virtual ~RenderEngine() = 0;

    enum FeatureFlag {
        WIDE_COLOR_SUPPORT = 1 << 0 // Platform has a wide color display
    };
    static std::unique_ptr<RenderEngine> create(int hwcFormat, uint32_t featureFlags);

    static EGLConfig chooseEglConfig(EGLDisplay display, int format, bool logConfig);

    void primeCache() const;

    // dump the extension strings. always call the base class.
    virtual void dump(String8& result);

    bool supportsImageCrop() const;

    bool isCurrent() const;
    bool setCurrentSurface(const RE::Surface& surface);
    void resetCurrentSurface();

    // synchronization

    // flush submits RenderEngine command stream for execution and returns a
    // native fence fd that is signaled when the execution has completed.  It
    // returns -1 on errors.
    base::unique_fd flush();
    // finish waits until RenderEngine command stream has been executed.  It
    // returns false on errors.
    bool finish();
    // waitFence inserts a wait on an external fence fd to RenderEngine
    // command stream.  It returns false on errors.
    bool waitFence(base::unique_fd fenceFd);

    // helpers
    void clearWithColor(float red, float green, float blue, float alpha);
    void fillRegionWithColor(const Region& region, uint32_t height, float red, float green,
                             float blue, float alpha);

    // common to all GL versions
    void setScissor(uint32_t left, uint32_t bottom, uint32_t right, uint32_t top);
    void disableScissor();
    void genTextures(size_t count, uint32_t* names);
    void deleteTextures(size_t count, uint32_t const* names);
    void bindExternalTextureImage(uint32_t texName, const RE::Image& image);
    void readPixels(size_t l, size_t b, size_t w, size_t h, uint32_t* pixels);

    class BindNativeBufferAsFramebuffer {
        RenderEngine& mEngine;
        EGLImageKHR mImage;
        uint32_t mTexName, mFbName;
        uint32_t mStatus;

    public:
        BindNativeBufferAsFramebuffer(RenderEngine& engine, ANativeWindowBuffer* buffer);
        ~BindNativeBufferAsFramebuffer();
        int getStatus() const;
    };

    // set-up
    virtual void checkErrors() const;
    virtual void setViewportAndProjection(size_t vpw, size_t vph, Rect sourceCrop, size_t hwh,
                                          bool yswap, Transform::orientation_flags rotation) = 0;
    virtual void setupLayerBlending(bool premultipliedAlpha, bool opaque, bool disableTexture,
                                    const half4& color) = 0;
    virtual void setColorMode(android_color_mode mode) = 0;
    virtual void setSourceDataSpace(android_dataspace source) = 0;
    virtual void setSourceY410BT2020(bool enable) = 0;
    virtual void setWideColor(bool hasWideColor) = 0;
    virtual bool usesWideColor() = 0;
    virtual void setupLayerTexturing(const Texture& texture) = 0;
    virtual void setupLayerBlackedOut() = 0;
    virtual void setupFillWithColor(float r, float g, float b, float a) = 0;

    virtual mat4 setupColorTransform(const mat4& /* colorTransform */) { return mat4(); }

    virtual void disableTexturing() = 0;
    virtual void disableBlending() = 0;

    // drawing
    virtual void drawMesh(const Mesh& mesh) = 0;

    // queries
    virtual size_t getMaxTextureSize() const = 0;
    virtual size_t getMaxViewportDims() const = 0;

    // internal to RenderEngine
    EGLDisplay getEGLDisplay() const;
    EGLConfig getEGLConfig() const;
};

// ---------------------------------------------------------------------------
}; // namespace android
// ---------------------------------------------------------------------------

#endif /* SF_RENDERENGINE_H_ */
