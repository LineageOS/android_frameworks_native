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

#ifndef SF_GLES20RENDERENGINE_H_
#define SF_GLES20RENDERENGINE_H_

#include <stdint.h>
#include <sys/types.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/private/Description.h>

#define EGL_NO_CONFIG ((EGLConfig)0)

namespace android {

class String8;

namespace renderengine {

class Mesh;
class Texture;

namespace gl {

class GLImage;
class GLSurface;

class GLES20RenderEngine : public impl::RenderEngine {
public:
    static std::unique_ptr<GLES20RenderEngine> create(int hwcFormat, uint32_t featureFlags);
    static EGLConfig chooseEglConfig(EGLDisplay display, int format, bool logConfig);

    GLES20RenderEngine(uint32_t featureFlags); // See RenderEngine::FeatureFlag
    ~GLES20RenderEngine() override;

    std::unique_ptr<Framebuffer> createFramebuffer() override;
    std::unique_ptr<Surface> createSurface() override;
    std::unique_ptr<Image> createImage() override;

    void primeCache() const override;
    bool isCurrent() const override;
    bool setCurrentSurface(const Surface& surface) override;
    void resetCurrentSurface() override;
    base::unique_fd flush() override;
    bool finish() override;
    bool waitFence(base::unique_fd fenceFd) override;
    void clearWithColor(float red, float green, float blue, float alpha) override;
    void fillRegionWithColor(const Region& region, float red, float green, float blue,
                             float alpha) override;
    void setScissor(const Rect& region) override;
    void disableScissor() override;
    void genTextures(size_t count, uint32_t* names) override;
    void deleteTextures(size_t count, uint32_t const* names) override;
    void bindExternalTextureImage(uint32_t texName, const Image& image) override;
    status_t bindFrameBuffer(Framebuffer* framebuffer) override;
    void unbindFrameBuffer(Framebuffer* framebuffer) override;
    void checkErrors() const override;

    status_t drawLayers(const DisplaySettings& settings, const std::vector<LayerSettings>& layers,
                        ANativeWindowBuffer* const buffer,
                        base::unique_fd* displayFence) const override;

    // internal to RenderEngine
    EGLDisplay getEGLDisplay() const { return mEGLDisplay; }
    EGLConfig getEGLConfig() const { return mEGLConfig; }

protected:
    void dump(String8& result) override;
    void setViewportAndProjection(size_t vpw, size_t vph, Rect sourceCrop,
                                  ui::Transform::orientation_flags rotation) override;
    void setupLayerBlending(bool premultipliedAlpha, bool opaque, bool disableTexture,
                            const half4& color) override;
    void setupLayerTexturing(const Texture& texture) override;
    void setupLayerBlackedOut() override;
    void setupFillWithColor(float r, float g, float b, float a) override;
    void setColorTransform(const mat4& colorTransform) override;
    void disableTexturing() override;
    void disableBlending() override;

    // HDR and color management related functions and state
    void setSourceY410BT2020(bool enable) override;
    void setSourceDataSpace(ui::Dataspace source) override;
    void setOutputDataSpace(ui::Dataspace dataspace) override;
    void setDisplayMaxLuminance(const float maxLuminance) override;

    // drawing
    void drawMesh(const Mesh& mesh) override;

    size_t getMaxTextureSize() const override;
    size_t getMaxViewportDims() const override;

private:
    enum GlesVersion {
        GLES_VERSION_1_0 = 0x10000,
        GLES_VERSION_1_1 = 0x10001,
        GLES_VERSION_2_0 = 0x20000,
        GLES_VERSION_3_0 = 0x30000,
    };

    static GlesVersion parseGlesVersion(const char* str);

    // A data space is considered HDR data space if it has BT2020 color space
    // with PQ or HLG transfer function.
    bool isHdrDataSpace(const ui::Dataspace dataSpace) const;
    bool needsXYZTransformMatrix() const;
    void setEGLHandles(EGLDisplay display, EGLConfig config, EGLContext ctxt);

    EGLDisplay mEGLDisplay;
    EGLConfig mEGLConfig;
    EGLContext mEGLContext;
    GLuint mProtectedTexName;
    GLint mMaxViewportDims[2];
    GLint mMaxTextureSize;
    GLuint mVpWidth;
    GLuint mVpHeight;
    Description mState;

    mat4 mSrgbToXyz;
    mat4 mDisplayP3ToXyz;
    mat4 mBt2020ToXyz;
    mat4 mXyzToSrgb;
    mat4 mXyzToDisplayP3;
    mat4 mXyzToBt2020;
    mat4 mSrgbToDisplayP3;
    mat4 mSrgbToBt2020;
    mat4 mDisplayP3ToSrgb;
    mat4 mDisplayP3ToBt2020;
    mat4 mBt2020ToSrgb;
    mat4 mBt2020ToDisplayP3;

    bool mRenderToFbo = false;
    int32_t mSurfaceHeight = 0;
    int32_t mFboHeight = 0;

    // Current dataspace of layer being rendered
    ui::Dataspace mDataSpace = ui::Dataspace::UNKNOWN;

    // Current output dataspace of the render engine
    ui::Dataspace mOutputDataSpace = ui::Dataspace::UNKNOWN;

    // Whether device supports color management, currently color management
    // supports sRGB, DisplayP3 color spaces.
    const bool mUseColorManagement = false;
};

} // namespace gl
} // namespace renderengine
} // namespace android

#endif /* SF_GLES20RENDERENGINE_H_ */
