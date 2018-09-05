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

#include <GLES2/gl2.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/private/Description.h>

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
    GLES20RenderEngine(uint32_t featureFlags); // See RenderEngine::FeatureFlag
    ~GLES20RenderEngine() override;

    std::unique_ptr<Framebuffer> createFramebuffer() override;
    std::unique_ptr<Surface> createSurface() override;
    std::unique_ptr<Image> createImage() override;

    void primeCache() const override;

    bool isCurrent() const;
    bool setCurrentSurface(const Surface& surface) override;
    void resetCurrentSurface() override;

    void bindExternalTextureImage(uint32_t texName, const Image& image) override;
    status_t bindFrameBuffer(Framebuffer* framebuffer) override;
    void unbindFrameBuffer(Framebuffer* framebuffer) override;

protected:
    void dump(String8& result) override;
    void setViewportAndProjection(size_t vpw, size_t vph, Rect sourceCrop,
                                  ui::Transform::orientation_flags rotation) override;
    void setupLayerBlending(bool premultipliedAlpha, bool opaque, bool disableTexture,
                            const half4& color) override;

    // Color management related functions and state
    void setSourceY410BT2020(bool enable) override;
    void setSourceDataSpace(ui::Dataspace source) override;
    void setOutputDataSpace(ui::Dataspace dataspace) override;
    void setDisplayMaxLuminance(const float maxLuminance) override;

    void setupLayerTexturing(const Texture& texture) override;
    void setupLayerBlackedOut() override;
    void setupFillWithColor(float r, float g, float b, float a) override;
    void setupColorTransform(const mat4& colorTransform) override;
    void disableTexturing() override;
    void disableBlending() override;

    void drawMesh(const Mesh& mesh) override;

    size_t getMaxTextureSize() const override;
    size_t getMaxViewportDims() const override;

private:
    // A data space is considered HDR data space if it has BT2020 color space
    // with PQ or HLG transfer function.
    bool isHdrDataSpace(const ui::Dataspace dataSpace) const;
    bool needsXYZTransformMatrix() const;

    GLuint mProtectedTexName;
    GLint mMaxViewportDims[2];
    GLint mMaxTextureSize;
    GLuint mVpWidth;
    GLuint mVpHeight;
    Description mState;

    mat4 mSrgbToDisplayP3;
    mat4 mDisplayP3ToSrgb;
    mat3 mSrgbToXyz;
    mat3 mBt2020ToXyz;
    mat3 mDisplayP3ToXyz;
    mat4 mXyzToSrgb;
    mat4 mXyzToDisplayP3;
    mat4 mXyzToBt2020;

    bool mRenderToFbo = false;

    // Current dataspace of layer being rendered
    ui::Dataspace mDataSpace = ui::Dataspace::UNKNOWN;

    // Current output dataspace of the render engine
    ui::Dataspace mOutputDataSpace = ui::Dataspace::UNKNOWN;

    // Whether device supports color management, currently color management
    // supports sRGB, DisplayP3 color spaces.
    const bool mUseColorManagement = false;
};

}  // namespace gl
}  // namespace renderengine
}  // namespace android

#endif /* SF_GLES20RENDERENGINE_H_ */
