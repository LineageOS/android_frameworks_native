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

#include <stdint.h>
#include <sys/types.h>
#include <memory>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <android-base/unique_fd.h>
#include <math/mat4.h>
#include <renderengine/Framebuffer.h>
#include <renderengine/Image.h>
#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

#define EGL_NO_CONFIG ((EGLConfig)0)

struct ANativeWindowBuffer;

namespace android {

class String8;
class Rect;
class Region;

namespace renderengine {

class BindNativeBufferAsFramebuffer;
class Image;
class Mesh;
class Surface;
class Texture;

namespace impl {
class RenderEngine;
}

class RenderEngine {
public:
    enum FeatureFlag {
        USE_COLOR_MANAGEMENT = 1 << 0, // Device manages color
    };

    virtual ~RenderEngine() = 0;

    virtual std::unique_ptr<Framebuffer> createFramebuffer() = 0;
    virtual std::unique_ptr<Surface> createSurface() = 0;
    virtual std::unique_ptr<Image> createImage() = 0;

    virtual void primeCache() const = 0;

    // dump the extension strings. always call the base class.
    virtual void dump(String8& result) = 0;

    virtual bool useNativeFenceSync() const = 0;
    virtual bool useWaitSync() const = 0;

    virtual bool isCurrent() const = 0;
    virtual bool setCurrentSurface(const Surface& surface) = 0;
    virtual void resetCurrentSurface() = 0;

    // helpers
    // flush submits RenderEngine command stream for execution and returns a
    // native fence fd that is signaled when the execution has completed.  It
    // returns -1 on errors.
    virtual base::unique_fd flush() = 0;
    // finish waits until RenderEngine command stream has been executed.  It
    // returns false on errors.
    virtual bool finish() = 0;
    // waitFence inserts a wait on an external fence fd to RenderEngine
    // command stream.  It returns false on errors.
    virtual bool waitFence(base::unique_fd fenceFd) = 0;

    virtual void clearWithColor(float red, float green, float blue, float alpha) = 0;
    virtual void fillRegionWithColor(const Region& region, uint32_t height, float red, float green,
                                     float blue, float alpha) = 0;

    // common to all GL versions
    virtual void setScissor(uint32_t left, uint32_t bottom, uint32_t right, uint32_t top) = 0;
    virtual void disableScissor() = 0;
    virtual void genTextures(size_t count, uint32_t* names) = 0;
    virtual void deleteTextures(size_t count, uint32_t const* names) = 0;
    virtual void bindExternalTextureImage(uint32_t texName, const Image& image) = 0;
    virtual void readPixels(size_t l, size_t b, size_t w, size_t h, uint32_t* pixels) = 0;
    // When binding a native buffer, it must be done before setViewportAndProjection
    // Returns NO_ERROR when binds successfully, NO_MEMORY when there's no memory for allocation.
    virtual status_t bindFrameBuffer(Framebuffer* framebuffer) = 0;
    virtual void unbindFrameBuffer(Framebuffer* framebuffer) = 0;

    // set-up
    virtual void checkErrors() const = 0;
    virtual void setViewportAndProjection(size_t vpw, size_t vph, Rect sourceCrop,
                                          ui::Transform::orientation_flags rotation) = 0;
    virtual void setupLayerBlending(bool premultipliedAlpha, bool opaque, bool disableTexture,
                                    const half4& color) = 0;
    virtual void setupLayerTexturing(const Texture& texture) = 0;
    virtual void setupLayerBlackedOut() = 0;
    virtual void setupFillWithColor(float r, float g, float b, float a) = 0;
    virtual void setupColorTransform(const mat4& /* colorTransform */) = 0;
    virtual void disableTexturing() = 0;
    virtual void disableBlending() = 0;

    // HDR and color management support
    virtual void setSourceY410BT2020(bool enable) = 0;
    virtual void setSourceDataSpace(ui::Dataspace source) = 0;
    virtual void setOutputDataSpace(ui::Dataspace dataspace) = 0;
    virtual void setDisplayMaxLuminance(const float maxLuminance) = 0;

    // drawing
    virtual void drawMesh(const Mesh& mesh) = 0;

    // queries
    virtual size_t getMaxTextureSize() const = 0;
    virtual size_t getMaxViewportDims() const = 0;
};

class BindNativeBufferAsFramebuffer {
public:
    BindNativeBufferAsFramebuffer(RenderEngine& engine, ANativeWindowBuffer* buffer)
          : mEngine(engine),
            mFramebuffer(mEngine.createFramebuffer()),
            mStatus(NO_ERROR) {
        mStatus = mFramebuffer->setNativeWindowBuffer(buffer) ?
                  mEngine.bindFrameBuffer(mFramebuffer.get()) : NO_MEMORY;
    }
    ~BindNativeBufferAsFramebuffer() {
        mFramebuffer->setNativeWindowBuffer(nullptr);
        mEngine.unbindFrameBuffer(mFramebuffer.get());
    }
    status_t getStatus() const { return mStatus; }

private:
    RenderEngine& mEngine;
    std::unique_ptr<Framebuffer> mFramebuffer;
    status_t mStatus;
};

namespace impl {

class RenderEngine : public renderengine::RenderEngine {
protected:
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

    static bool overrideUseContextPriorityFromConfig(bool useContextPriority);

    RenderEngine(uint32_t featureFlags);

    const uint32_t mFeatureFlags;

public:
    virtual ~RenderEngine() = 0;

    static std::unique_ptr<RenderEngine> create(int hwcFormat, uint32_t featureFlags);

    static EGLConfig chooseEglConfig(EGLDisplay display, int format, bool logConfig);

    // dump the extension strings. always call the base class.
    void dump(String8& result) override;

    bool useNativeFenceSync() const override;
    bool useWaitSync() const override;

    void setupColorTransform(const mat4& /* colorTransform */) override {}

    // internal to RenderEngine
    EGLDisplay getEGLDisplay() const;
    EGLConfig getEGLConfig() const;
};

}  // namespace impl
}  // namespace renderengine
}  // namespace android

#endif /* SF_RENDERENGINE_H_ */
