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

#include <android-base/unique_fd.h>
#include <math/mat4.h>
#include <renderengine/DisplaySettings.h>
#include <renderengine/Framebuffer.h>
#include <renderengine/Image.h>
#include <renderengine/LayerSettings.h>
#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

/**
 * Allows to set RenderEngine backend to GLES (default) or SkiaGL (NOT yet supported).
 */
#define PROPERTY_DEBUG_RENDERENGINE_BACKEND "debug.renderengine.backend"

/**
 * Turns on recording of skia commands in SkiaGL version of the RE. This property
 * defines number of milliseconds for the recording to take place. A non zero value
 * turns on the recording.
 */
#define PROPERTY_DEBUG_RENDERENGINE_CAPTURE_SKIA_MS "debug.renderengine.capture_skia_ms"

struct ANativeWindowBuffer;

namespace android {

class Rect;
class Region;

namespace renderengine {

class Image;
class Mesh;
class Texture;
struct RenderEngineCreationArgs;

namespace threaded {
class RenderEngineThreaded;
}

namespace impl {
class RenderEngine;
}

enum class Protection {
    UNPROTECTED = 1,
    PROTECTED = 2,
};

class RenderEngine {
public:
    enum class ContextPriority {
        LOW = 1,
        MEDIUM = 2,
        HIGH = 3,
        REALTIME = 4,
    };

    enum class RenderEngineType {
        GLES = 1,
        THREADED = 2,
        SKIA_GL = 3,
        SKIA_GL_THREADED = 4,
    };

    static std::unique_ptr<RenderEngine> create(const RenderEngineCreationArgs& args);

    RenderEngine() : RenderEngine(RenderEngineType::GLES) {}

    RenderEngine(RenderEngineType type) : mRenderEngineType(type) {}

    virtual ~RenderEngine() = 0;

    // ----- BEGIN DEPRECATED INTERFACE -----
    // This interface, while still in use until a suitable replacement is built,
    // should be considered deprecated, minus some methods which still may be
    // used to support legacy behavior.
    virtual void primeCache() = 0;

    // dump the extension strings. always call the base class.
    virtual void dump(std::string& result) = 0;

    virtual void genTextures(size_t count, uint32_t* names) = 0;
    virtual void deleteTextures(size_t count, uint32_t const* names) = 0;
    // Caches Image resources for this buffer, but does not bind the buffer to
    // a particular texture.
    // Note that work is deferred to an additional thread, i.e. this call
    // is made asynchronously, but the caller can expect that cache/unbind calls
    // are performed in a manner that's conflict serializable, i.e. unbinding
    // a buffer should never occur before binding the buffer if the caller
    // called {bind, cache}ExternalTextureBuffer before calling unbind.
    virtual void cacheExternalTextureBuffer(const sp<GraphicBuffer>& buffer) = 0;
    // Removes internal resources referenced by the bufferId. This method should be
    // invoked when the caller will no longer hold a reference to a GraphicBuffer
    // and needs to clean up its resources.
    // Note that work is deferred to an additional thread, i.e. this call
    // is made asynchronously, but the caller can expect that cache/unbind calls
    // are performed in a manner that's conflict serializable, i.e. unbinding
    // a buffer should never occur before binding the buffer if the caller
    // called {bind, cache}ExternalTextureBuffer before calling unbind.
    virtual void unbindExternalTextureBuffer(uint64_t bufferId) = 0;

    enum class CleanupMode {
        CLEAN_OUTPUT_RESOURCES,
        CLEAN_ALL,
    };
    // Clean-up method that should be called on the main thread after the
    // drawFence returned by drawLayers fires. This method will free up
    // resources used by the most recently drawn frame. If the frame is still
    // being drawn, then this call is silently ignored.
    //
    // If mode is CLEAN_OUTPUT_RESOURCES, then only resources related to the
    // output framebuffer are cleaned up, including the sibling texture.
    //
    // If mode is CLEAN_ALL, then we also cleanup resources related to any input
    // buffers.
    //
    // Returns true if resources were cleaned up, and false if we didn't need to
    // do any work.
    virtual bool cleanupPostRender(CleanupMode mode = CleanupMode::CLEAN_OUTPUT_RESOURCES) = 0;

    // queries
    virtual size_t getMaxTextureSize() const = 0;
    virtual size_t getMaxViewportDims() const = 0;

    // ----- END DEPRECATED INTERFACE -----

    // ----- BEGIN NEW INTERFACE -----

    virtual bool isProtected() const = 0;
    virtual bool supportsProtectedContent() const = 0;
    virtual bool useProtectedContext(bool useProtectedContext) = 0;

    // Renders layers for a particular display via GPU composition. This method
    // should be called for every display that needs to be rendered via the GPU.
    // @param display The display-wide settings that should be applied prior to
    // drawing any layers.
    //
    // Assumptions when calling this method:
    // 1. There is exactly one caller - i.e. multi-threading is not supported.
    // 2. Additional threads may be calling the {bind,cache}ExternalTexture
    // methods above. But the main thread is responsible for holding resources
    // such that Image destruction does not occur while this method is called.
    //
    // TODO(b/136806342): This should behavior should ideally be fixed since
    // the above two assumptions are brittle, as conditional thread safetyness
    // may be insufficient when maximizing rendering performance in the future.
    //
    // @param layers The layers to draw onto the display, in Z-order.
    // @param buffer The buffer which will be drawn to. This buffer will be
    // ready once drawFence fires.
    // @param useFramebufferCache True if the framebuffer cache should be used.
    // If an implementation does not cache output framebuffers, then this
    // parameter does nothing.
    // @param bufferFence Fence signalling that the buffer is ready to be drawn
    // to.
    // @param drawFence A pointer to a fence, which will fire when the buffer
    // has been drawn to and is ready to be examined. The fence will be
    // initialized by this method. The caller will be responsible for owning the
    // fence.
    // @return An error code indicating whether drawing was successful. For
    // now, this always returns NO_ERROR.
    virtual status_t drawLayers(const DisplaySettings& display,
                                const std::vector<const LayerSettings*>& layers,
                                const sp<GraphicBuffer>& buffer, const bool useFramebufferCache,
                                base::unique_fd&& bufferFence, base::unique_fd* drawFence) = 0;
    virtual void cleanFramebufferCache() = 0;
    // Returns the priority this context was actually created with. Note: this may not be
    // the same as specified at context creation time, due to implementation limits on the
    // number of contexts that can be created at a specific priority level in the system.
    virtual int getContextPriority() = 0;

    // Returns true if blur was requested in the RenderEngineCreationArgs and the implementation
    // also supports background blur.  If false, no blur will be applied when drawing layers.
    virtual bool supportsBackgroundBlur() = 0;

    // Returns the current type of RenderEngine instance that was created.
    // TODO(b/180767535): This is only implemented to allow for backend-specific behavior, which
    // we should not allow in general, so remove this.
    RenderEngineType getRenderEngineType() const { return mRenderEngineType; }

    static void validateInputBufferUsage(const sp<GraphicBuffer>&);
    static void validateOutputBufferUsage(const sp<GraphicBuffer>&);

protected:
    friend class threaded::RenderEngineThreaded;
    const RenderEngineType mRenderEngineType;
};

struct RenderEngineCreationArgs {
    int pixelFormat;
    uint32_t imageCacheSize;
    bool useColorManagement;
    bool enableProtectedContext;
    bool precacheToneMapperShaderOnly;
    bool supportsBackgroundBlur;
    RenderEngine::ContextPriority contextPriority;
    RenderEngine::RenderEngineType renderEngineType;

    struct Builder;

private:
    // must be created by Builder via constructor with full argument list
    RenderEngineCreationArgs(int _pixelFormat, uint32_t _imageCacheSize, bool _useColorManagement,
                             bool _enableProtectedContext, bool _precacheToneMapperShaderOnly,
                             bool _supportsBackgroundBlur,
                             RenderEngine::ContextPriority _contextPriority,
                             RenderEngine::RenderEngineType _renderEngineType)
          : pixelFormat(_pixelFormat),
            imageCacheSize(_imageCacheSize),
            useColorManagement(_useColorManagement),
            enableProtectedContext(_enableProtectedContext),
            precacheToneMapperShaderOnly(_precacheToneMapperShaderOnly),
            supportsBackgroundBlur(_supportsBackgroundBlur),
            contextPriority(_contextPriority),
            renderEngineType(_renderEngineType) {}
    RenderEngineCreationArgs() = delete;
};

struct RenderEngineCreationArgs::Builder {
    Builder() {}

    Builder& setPixelFormat(int pixelFormat) {
        this->pixelFormat = pixelFormat;
        return *this;
    }
    Builder& setImageCacheSize(uint32_t imageCacheSize) {
        this->imageCacheSize = imageCacheSize;
        return *this;
    }
    Builder& setUseColorManagerment(bool useColorManagement) {
        this->useColorManagement = useColorManagement;
        return *this;
    }
    Builder& setEnableProtectedContext(bool enableProtectedContext) {
        this->enableProtectedContext = enableProtectedContext;
        return *this;
    }
    Builder& setPrecacheToneMapperShaderOnly(bool precacheToneMapperShaderOnly) {
        this->precacheToneMapperShaderOnly = precacheToneMapperShaderOnly;
        return *this;
    }
    Builder& setSupportsBackgroundBlur(bool supportsBackgroundBlur) {
        this->supportsBackgroundBlur = supportsBackgroundBlur;
        return *this;
    }
    Builder& setContextPriority(RenderEngine::ContextPriority contextPriority) {
        this->contextPriority = contextPriority;
        return *this;
    }
    Builder& setRenderEngineType(RenderEngine::RenderEngineType renderEngineType) {
        this->renderEngineType = renderEngineType;
        return *this;
    }
    RenderEngineCreationArgs build() const {
        return RenderEngineCreationArgs(pixelFormat, imageCacheSize, useColorManagement,
                                        enableProtectedContext, precacheToneMapperShaderOnly,
                                        supportsBackgroundBlur, contextPriority, renderEngineType);
    }

private:
    // 1 means RGBA_8888
    int pixelFormat = 1;
    uint32_t imageCacheSize = 0;
    bool useColorManagement = true;
    bool enableProtectedContext = false;
    bool precacheToneMapperShaderOnly = false;
    bool supportsBackgroundBlur = false;
    RenderEngine::ContextPriority contextPriority = RenderEngine::ContextPriority::MEDIUM;
    RenderEngine::RenderEngineType renderEngineType = RenderEngine::RenderEngineType::GLES;
};

} // namespace renderengine
} // namespace android

#endif /* SF_RENDERENGINE_H_ */
