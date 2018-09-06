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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "GLES20RenderEngine.h"

#include <math.h>
#include <fstream>
#include <sstream>

#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <cutils/compiler.h>
#include <renderengine/Mesh.h>
#include <renderengine/Texture.h>
#include <renderengine/private/Description.h>
#include <ui/ColorSpace.h>
#include <ui/DebugUtils.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <utils/String8.h>
#include <utils/Trace.h>
#include "GLExtensions.h"
#include "GLFramebuffer.h"
#include "GLImage.h"
#include "GLSurface.h"
#include "Program.h"
#include "ProgramCache.h"

bool checkGlError(const char* op, int lineNumber) {
    bool errorFound = false;
    GLint error = glGetError();
    while (error != GL_NO_ERROR) {
        errorFound = true;
        error = glGetError();
        ALOGV("after %s() (line # %d) glError (0x%x)\n", op, lineNumber, error);
    }
    return errorFound;
}

static constexpr bool outputDebugPPMs = false;

void writePPM(const char* basename, GLuint width, GLuint height) {
    ALOGV("writePPM #%s: %d x %d", basename, width, height);

    std::vector<GLubyte> pixels(width * height * 4);
    std::vector<GLubyte> outBuffer(width * height * 3);

    // TODO(courtneygo): We can now have float formats, need
    // to remove this code or update to support.
    // Make returned pixels fit in uint32_t, one byte per component
    glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
    if (checkGlError(__FUNCTION__, __LINE__)) {
        return;
    }

    std::string filename(basename);
    filename.append(".ppm");
    std::ofstream file(filename.c_str(), std::ios::binary);
    if (!file.is_open()) {
        ALOGE("Unable to open file: %s", filename.c_str());
        ALOGE("You may need to do: \"adb shell setenforce 0\" to enable "
              "surfaceflinger to write debug images");
        return;
    }

    file << "P6\n";
    file << width << "\n";
    file << height << "\n";
    file << 255 << "\n";

    auto ptr = reinterpret_cast<char*>(pixels.data());
    auto outPtr = reinterpret_cast<char*>(outBuffer.data());
    for (int y = height - 1; y >= 0; y--) {
        char* data = ptr + y * width * sizeof(uint32_t);

        for (GLuint x = 0; x < width; x++) {
            // Only copy R, G and B components
            outPtr[0] = data[0];
            outPtr[1] = data[1];
            outPtr[2] = data[2];
            data += sizeof(uint32_t);
            outPtr += 3;
        }
    }
    file.write(reinterpret_cast<char*>(outBuffer.data()), outBuffer.size());
}

namespace android {
namespace renderengine {
namespace gl {

using ui::Dataspace;

GLES20RenderEngine::GLES20RenderEngine(uint32_t featureFlags)
      : RenderEngine(featureFlags),
        mVpWidth(0),
        mVpHeight(0),
        mUseColorManagement(featureFlags & USE_COLOR_MANAGEMENT) {
    glGetIntegerv(GL_MAX_TEXTURE_SIZE, &mMaxTextureSize);
    glGetIntegerv(GL_MAX_VIEWPORT_DIMS, mMaxViewportDims);

    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
    glPixelStorei(GL_PACK_ALIGNMENT, 4);

    const uint16_t protTexData[] = {0};
    glGenTextures(1, &mProtectedTexName);
    glBindTexture(GL_TEXTURE_2D, mProtectedTexName);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, 1, 1, 0, GL_RGB, GL_UNSIGNED_SHORT_5_6_5, protTexData);

    // mColorBlindnessCorrection = M;

    if (mUseColorManagement) {
        ColorSpace srgb(ColorSpace::sRGB());
        ColorSpace displayP3(ColorSpace::DisplayP3());
        ColorSpace bt2020(ColorSpace::BT2020());

        // Compute sRGB to Display P3 transform matrix.
        // NOTE: For now, we are limiting output wide color space support to
        // Display-P3 only.
        mSrgbToDisplayP3 = mat4(ColorSpaceConnector(srgb, displayP3).getTransform());

        // Compute Display P3 to sRGB transform matrix.
        mDisplayP3ToSrgb = mat4(ColorSpaceConnector(displayP3, srgb).getTransform());

        // no chromatic adaptation needed since all color spaces use D65 for their white points.
        mSrgbToXyz = srgb.getRGBtoXYZ();
        mDisplayP3ToXyz = displayP3.getRGBtoXYZ();
        mBt2020ToXyz = bt2020.getRGBtoXYZ();
        mXyzToSrgb = mat4(srgb.getXYZtoRGB());
        mXyzToDisplayP3 = mat4(displayP3.getXYZtoRGB());
        mXyzToBt2020 = mat4(bt2020.getXYZtoRGB());
    }
}

GLES20RenderEngine::~GLES20RenderEngine() {}

std::unique_ptr<Framebuffer> GLES20RenderEngine::createFramebuffer() {
    return std::make_unique<GLFramebuffer>(*this);
}

std::unique_ptr<Surface> GLES20RenderEngine::createSurface() {
    return std::make_unique<GLSurface>(*this);
}

std::unique_ptr<Image> GLES20RenderEngine::createImage() {
    return std::make_unique<GLImage>(*this);
}

void GLES20RenderEngine::primeCache() const {
    ProgramCache::getInstance().primeCache(mFeatureFlags & USE_COLOR_MANAGEMENT);
}

bool GLES20RenderEngine::isCurrent() const {
    return mEGLDisplay == eglGetCurrentDisplay() && mEGLContext == eglGetCurrentContext();
}

bool GLES20RenderEngine::setCurrentSurface(const Surface& surface) {
    // Surface is an abstract interface. GLES20RenderEngine only ever
    // creates GLSurface's, so it is safe to just cast to the actual
    // type.
    bool success = true;
    const GLSurface& glSurface = static_cast<const GLSurface&>(surface);
    EGLSurface eglSurface = glSurface.getEGLSurface();
    if (eglSurface != eglGetCurrentSurface(EGL_DRAW)) {
        success = eglMakeCurrent(mEGLDisplay, eglSurface, eglSurface, mEGLContext) == EGL_TRUE;
        if (success && glSurface.getAsync()) {
            eglSwapInterval(mEGLDisplay, 0);
        }
    }
    return success;
}

void GLES20RenderEngine::resetCurrentSurface() {
    eglMakeCurrent(mEGLDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
}

base::unique_fd GLES20RenderEngine::flush() {
    if (!GLExtensions::getInstance().hasNativeFenceSync()) {
        return base::unique_fd();
    }

    EGLSyncKHR sync = eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_NATIVE_FENCE_ANDROID, nullptr);
    if (sync == EGL_NO_SYNC_KHR) {
        ALOGW("failed to create EGL native fence sync: %#x", eglGetError());
        return base::unique_fd();
    }

    // native fence fd will not be populated until flush() is done.
    glFlush();

    // get the fence fd
    base::unique_fd fenceFd(eglDupNativeFenceFDANDROID(mEGLDisplay, sync));
    eglDestroySyncKHR(mEGLDisplay, sync);
    if (fenceFd == EGL_NO_NATIVE_FENCE_FD_ANDROID) {
        ALOGW("failed to dup EGL native fence sync: %#x", eglGetError());
    }

    return fenceFd;
}

bool GLES20RenderEngine::finish() {
    if (!GLExtensions::getInstance().hasFenceSync()) {
        ALOGW("no synchronization support");
        return false;
    }

    EGLSyncKHR sync = eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_FENCE_KHR, nullptr);
    if (sync == EGL_NO_SYNC_KHR) {
        ALOGW("failed to create EGL fence sync: %#x", eglGetError());
        return false;
    }

    EGLint result = eglClientWaitSyncKHR(mEGLDisplay, sync, EGL_SYNC_FLUSH_COMMANDS_BIT_KHR,
                                         2000000000 /*2 sec*/);
    EGLint error = eglGetError();
    eglDestroySyncKHR(mEGLDisplay, sync);
    if (result != EGL_CONDITION_SATISFIED_KHR) {
        if (result == EGL_TIMEOUT_EXPIRED_KHR) {
            ALOGW("fence wait timed out");
        } else {
            ALOGW("error waiting on EGL fence: %#x", error);
        }
        return false;
    }

    return true;
}

bool GLES20RenderEngine::waitFence(base::unique_fd fenceFd) {
    if (!GLExtensions::getInstance().hasNativeFenceSync() ||
        !GLExtensions::getInstance().hasWaitSync()) {
        return false;
    }

    EGLint attribs[] = {EGL_SYNC_NATIVE_FENCE_FD_ANDROID, fenceFd, EGL_NONE};
    EGLSyncKHR sync = eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_NATIVE_FENCE_ANDROID, attribs);
    if (sync == EGL_NO_SYNC_KHR) {
        ALOGE("failed to create EGL native fence sync: %#x", eglGetError());
        return false;
    }

    // fenceFd is now owned by EGLSync
    (void)fenceFd.release();

    // XXX: The spec draft is inconsistent as to whether this should return an
    // EGLint or void.  Ignore the return value for now, as it's not strictly
    // needed.
    eglWaitSyncKHR(mEGLDisplay, sync, 0);
    EGLint error = eglGetError();
    eglDestroySyncKHR(mEGLDisplay, sync);
    if (error != EGL_SUCCESS) {
        ALOGE("failed to wait for EGL native fence sync: %#x", error);
        return false;
    }

    return true;
}

void GLES20RenderEngine::fillRegionWithColor(const Region& region, uint32_t height, float red,
                                             float green, float blue, float alpha) {
    size_t c;
    Rect const* r = region.getArray(&c);
    Mesh mesh(Mesh::TRIANGLES, c * 6, 2);
    Mesh::VertexArray<vec2> position(mesh.getPositionArray<vec2>());
    for (size_t i = 0; i < c; i++, r++) {
        position[i * 6 + 0].x = r->left;
        position[i * 6 + 0].y = height - r->top;
        position[i * 6 + 1].x = r->left;
        position[i * 6 + 1].y = height - r->bottom;
        position[i * 6 + 2].x = r->right;
        position[i * 6 + 2].y = height - r->bottom;
        position[i * 6 + 3].x = r->left;
        position[i * 6 + 3].y = height - r->top;
        position[i * 6 + 4].x = r->right;
        position[i * 6 + 4].y = height - r->bottom;
        position[i * 6 + 5].x = r->right;
        position[i * 6 + 5].y = height - r->top;
    }
    setupFillWithColor(red, green, blue, alpha);
    drawMesh(mesh);
}

void GLES20RenderEngine::clearWithColor(float red, float green, float blue, float alpha) {
    glClearColor(red, green, blue, alpha);
    glClear(GL_COLOR_BUFFER_BIT);
}

void GLES20RenderEngine::setScissor(uint32_t left, uint32_t bottom, uint32_t right, uint32_t top) {
    glScissor(left, bottom, right, top);
    glEnable(GL_SCISSOR_TEST);
}

void GLES20RenderEngine::disableScissor() {
    glDisable(GL_SCISSOR_TEST);
}

void GLES20RenderEngine::genTextures(size_t count, uint32_t* names) {
    glGenTextures(count, names);
}

void GLES20RenderEngine::deleteTextures(size_t count, uint32_t const* names) {
    glDeleteTextures(count, names);
}

void GLES20RenderEngine::bindExternalTextureImage(uint32_t texName,
                                                  const Image& image) {
    const GLImage& glImage = static_cast<const GLImage&>(image);
    const GLenum target = GL_TEXTURE_EXTERNAL_OES;

    glBindTexture(target, texName);
    if (glImage.getEGLImage() != EGL_NO_IMAGE_KHR) {
        glEGLImageTargetTexture2DOES(target,
                                     static_cast<GLeglImageOES>(glImage.getEGLImage()));
    }
}

void GLES20RenderEngine::readPixels(size_t l, size_t b, size_t w, size_t h, uint32_t* pixels) {
    glReadPixels(l, b, w, h, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
}

status_t GLES20RenderEngine::bindFrameBuffer(Framebuffer* framebuffer) {
    GLFramebuffer* glFramebuffer = static_cast<GLFramebuffer*>(framebuffer);
    EGLImageKHR eglImage = glFramebuffer->getEGLImage();
    uint32_t textureName = glFramebuffer->getTextureName();
    uint32_t framebufferName = glFramebuffer->getFramebufferName();

    // Bind the texture and turn our EGLImage into a texture
    glBindTexture(GL_TEXTURE_2D, textureName);
    glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, (GLeglImageOES)eglImage);

    // Bind the Framebuffer to render into
    glBindFramebuffer(GL_FRAMEBUFFER, framebufferName);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                           GL_TEXTURE_2D, textureName, 0);

    mRenderToFbo = true;

    uint32_t glStatus = glCheckFramebufferStatus(GL_FRAMEBUFFER);

    ALOGE_IF(glStatus != GL_FRAMEBUFFER_COMPLETE_OES,
             "glCheckFramebufferStatusOES error %d", glStatus);

    return glStatus == GL_FRAMEBUFFER_COMPLETE_OES ? NO_ERROR : BAD_VALUE;
}

void GLES20RenderEngine::unbindFrameBuffer(Framebuffer* /* framebuffer */) {
    mRenderToFbo = false;

    // back to main framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);

    // Workaround for b/77935566 to force the EGL driver to release the
    // screenshot buffer
    setScissor(0, 0, 0, 0);
    clearWithColor(0.0, 0.0, 0.0, 0.0);
    disableScissor();
}

void GLES20RenderEngine::checkErrors() const {
    do {
        // there could be more than one error flag
        GLenum error = glGetError();
        if (error == GL_NO_ERROR) break;
        ALOGE("GL error 0x%04x", int(error));
    } while (true);
}

void GLES20RenderEngine::setViewportAndProjection(size_t vpw, size_t vph, Rect sourceCrop,
                                                  ui::Transform::orientation_flags rotation) {
    int32_t l = sourceCrop.left;
    int32_t r = sourceCrop.right;
    int32_t b = sourceCrop.bottom;
    int32_t t = sourceCrop.top;
    if (mRenderToFbo) {
        std::swap(t, b);
    }
    mat4 m = mat4::ortho(l, r, b, t, 0, 1);

    // Apply custom rotation to the projection.
    float rot90InRadians = 2.0f * static_cast<float>(M_PI) / 4.0f;
    switch (rotation) {
        case ui::Transform::ROT_0:
            break;
        case ui::Transform::ROT_90:
            m = mat4::rotate(rot90InRadians, vec3(0, 0, 1)) * m;
            break;
        case ui::Transform::ROT_180:
            m = mat4::rotate(rot90InRadians * 2.0f, vec3(0, 0, 1)) * m;
            break;
        case ui::Transform::ROT_270:
            m = mat4::rotate(rot90InRadians * 3.0f, vec3(0, 0, 1)) * m;
            break;
        default:
            break;
    }

    glViewport(0, 0, vpw, vph);
    mState.setProjectionMatrix(m);
    mVpWidth = vpw;
    mVpHeight = vph;
}

void GLES20RenderEngine::setupLayerBlending(bool premultipliedAlpha, bool opaque,
                                            bool disableTexture, const half4& color) {
    mState.setPremultipliedAlpha(premultipliedAlpha);
    mState.setOpaque(opaque);
    mState.setColor(color);

    if (disableTexture) {
        mState.disableTexture();
    }

    if (color.a < 1.0f || !opaque) {
        glEnable(GL_BLEND);
        glBlendFunc(premultipliedAlpha ? GL_ONE : GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    } else {
        glDisable(GL_BLEND);
    }
}

void GLES20RenderEngine::setSourceY410BT2020(bool enable) {
    mState.setY410BT2020(enable);
}

void GLES20RenderEngine::setSourceDataSpace(Dataspace source) {
    mDataSpace = source;
}

void GLES20RenderEngine::setOutputDataSpace(Dataspace dataspace) {
    mOutputDataSpace = dataspace;
}

void GLES20RenderEngine::setDisplayMaxLuminance(const float maxLuminance) {
    mState.setDisplayMaxLuminance(maxLuminance);
}

void GLES20RenderEngine::setupLayerTexturing(const Texture& texture) {
    GLuint target = texture.getTextureTarget();
    glBindTexture(target, texture.getTextureName());
    GLenum filter = GL_NEAREST;
    if (texture.getFiltering()) {
        filter = GL_LINEAR;
    }
    glTexParameteri(target, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(target, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(target, GL_TEXTURE_MAG_FILTER, filter);
    glTexParameteri(target, GL_TEXTURE_MIN_FILTER, filter);

    mState.setTexture(texture);
}

void GLES20RenderEngine::setupLayerBlackedOut() {
    glBindTexture(GL_TEXTURE_2D, mProtectedTexName);
    Texture texture(Texture::TEXTURE_2D, mProtectedTexName);
    texture.setDimensions(1, 1); // FIXME: we should get that from somewhere
    mState.setTexture(texture);
}

void GLES20RenderEngine::setupColorTransform(const mat4& colorTransform) {
    mState.setColorMatrix(colorTransform);
}

void GLES20RenderEngine::disableTexturing() {
    mState.disableTexture();
}

void GLES20RenderEngine::disableBlending() {
    glDisable(GL_BLEND);
}

void GLES20RenderEngine::setupFillWithColor(float r, float g, float b, float a) {
    mState.setPremultipliedAlpha(true);
    mState.setOpaque(false);
    mState.setColor(half4(r, g, b, a));
    mState.disableTexture();
    glDisable(GL_BLEND);
}

void GLES20RenderEngine::drawMesh(const Mesh& mesh) {
    ATRACE_CALL();
    if (mesh.getTexCoordsSize()) {
        glEnableVertexAttribArray(Program::texCoords);
        glVertexAttribPointer(Program::texCoords, mesh.getTexCoordsSize(), GL_FLOAT, GL_FALSE,
                              mesh.getByteStride(), mesh.getTexCoords());
    }

    glVertexAttribPointer(Program::position, mesh.getVertexSize(), GL_FLOAT, GL_FALSE,
                          mesh.getByteStride(), mesh.getPositions());

    // By default, DISPLAY_P3 is the only supported wide color output. However,
    // when HDR content is present, hardware composer may be able to handle
    // BT2020 data space, in that case, the output data space is set to be
    // BT2020_HLG or BT2020_PQ respectively. In GPU fall back we need
    // to respect this and convert non-HDR content to HDR format.
    if (mUseColorManagement) {
        Description managedState = mState;
        Dataspace inputStandard = static_cast<Dataspace>(mDataSpace & Dataspace::STANDARD_MASK);
        Dataspace inputTransfer = static_cast<Dataspace>(mDataSpace & Dataspace::TRANSFER_MASK);
        Dataspace outputStandard = static_cast<Dataspace>(mOutputDataSpace &
                                                          Dataspace::STANDARD_MASK);
        Dataspace outputTransfer = static_cast<Dataspace>(mOutputDataSpace &
                                                          Dataspace::TRANSFER_MASK);
        bool needsXYZConversion = needsXYZTransformMatrix();

        if (needsXYZConversion) {
            // The supported input color spaces are standard RGB, Display P3 and BT2020.
            switch (inputStandard) {
                case Dataspace::STANDARD_DCI_P3:
                    managedState.setInputTransformMatrix(mDisplayP3ToXyz);
                    break;
                case Dataspace::STANDARD_BT2020:
                    managedState.setInputTransformMatrix(mBt2020ToXyz);
                    break;
                default:
                    managedState.setInputTransformMatrix(mSrgbToXyz);
                    break;
            }

            // The supported output color spaces are BT2020, Display P3 and standard RGB.
            switch (outputStandard) {
                case Dataspace::STANDARD_BT2020:
                    managedState.setOutputTransformMatrix(mXyzToBt2020);
                    break;
                case Dataspace::STANDARD_DCI_P3:
                    managedState.setOutputTransformMatrix(mXyzToDisplayP3);
                    break;
                default:
                    managedState.setOutputTransformMatrix(mXyzToSrgb);
                    break;
            }
        } else if (inputStandard != outputStandard) {
            // At this point, the input data space and output data space could be both
            // HDR data spaces, but they match each other, we do nothing in this case.
            // In addition to the case above, the input data space could be
            // - scRGB linear
            // - scRGB non-linear
            // - sRGB
            // - Display P3
            // The output data spaces could be
            // - sRGB
            // - Display P3
            if (outputStandard == Dataspace::STANDARD_BT709) {
                managedState.setOutputTransformMatrix(mDisplayP3ToSrgb);
            } else if (outputStandard == Dataspace::STANDARD_DCI_P3) {
                managedState.setOutputTransformMatrix(mSrgbToDisplayP3);
            }
        }

        // we need to convert the RGB value to linear space and convert it back when:
        // - there is a color matrix that is not an identity matrix, or
        // - there is an output transform matrix that is not an identity matrix, or
        // - the input transfer function doesn't match the output transfer function.
        if (managedState.hasColorMatrix() || managedState.hasOutputTransformMatrix() ||
            inputTransfer != outputTransfer) {
            switch (inputTransfer) {
                case Dataspace::TRANSFER_ST2084:
                    managedState.setInputTransferFunction(Description::TransferFunction::ST2084);
                    break;
                case Dataspace::TRANSFER_HLG:
                    managedState.setInputTransferFunction(Description::TransferFunction::HLG);
                    break;
                case Dataspace::TRANSFER_LINEAR:
                    managedState.setInputTransferFunction(Description::TransferFunction::LINEAR);
                    break;
                default:
                    managedState.setInputTransferFunction(Description::TransferFunction::SRGB);
                    break;
            }

            switch (outputTransfer) {
                case Dataspace::TRANSFER_ST2084:
                    managedState.setOutputTransferFunction(Description::TransferFunction::ST2084);
                    break;
                case Dataspace::TRANSFER_HLG:
                    managedState.setOutputTransferFunction(Description::TransferFunction::HLG);
                    break;
                default:
                    managedState.setOutputTransferFunction(Description::TransferFunction::SRGB);
                    break;
            }
        }

        ProgramCache::getInstance().useProgram(managedState);

        glDrawArrays(mesh.getPrimitive(), 0, mesh.getVertexCount());

        if (outputDebugPPMs) {
            static uint64_t managedColorFrameCount = 0;
            std::ostringstream out;
            out << "/data/texture_out" << managedColorFrameCount++;
            writePPM(out.str().c_str(), mVpWidth, mVpHeight);
        }
    } else {
        ProgramCache::getInstance().useProgram(mState);

        glDrawArrays(mesh.getPrimitive(), 0, mesh.getVertexCount());
    }

    if (mesh.getTexCoordsSize()) {
        glDisableVertexAttribArray(Program::texCoords);
    }
}

size_t GLES20RenderEngine::getMaxTextureSize() const {
    return mMaxTextureSize;
}

size_t GLES20RenderEngine::getMaxViewportDims() const {
    return mMaxViewportDims[0] < mMaxViewportDims[1] ? mMaxViewportDims[0] : mMaxViewportDims[1];
}

void GLES20RenderEngine::dump(String8& result) {
    RenderEngine::dump(result);
    result.appendFormat("RenderEngine last dataspace conversion: (%s) to (%s)\n",
                        dataspaceDetails(static_cast<android_dataspace>(mDataSpace)).c_str(),
                        dataspaceDetails(static_cast<android_dataspace>(mOutputDataSpace)).c_str());
}

bool GLES20RenderEngine::isHdrDataSpace(const Dataspace dataSpace) const {
    const Dataspace standard = static_cast<Dataspace>(dataSpace & Dataspace::STANDARD_MASK);
    const Dataspace transfer = static_cast<Dataspace>(dataSpace & Dataspace::TRANSFER_MASK);
    return standard == Dataspace::STANDARD_BT2020 &&
        (transfer == Dataspace::TRANSFER_ST2084 || transfer == Dataspace::TRANSFER_HLG);
}

// For convenience, we want to convert the input color space to XYZ color space first,
// and then convert from XYZ color space to output color space when
// - SDR and HDR contents are mixed, either SDR content will be converted to HDR or
//   HDR content will be tone-mapped to SDR; Or,
// - there are HDR PQ and HLG contents presented at the same time, where we want to convert
//   HLG content to PQ content.
// In either case above, we need to operate the Y value in XYZ color space. Thus, when either
// input data space or output data space is HDR data space, and the input transfer function
// doesn't match the output transfer function, we would enable an intermediate transfrom to
// XYZ color space.
bool GLES20RenderEngine::needsXYZTransformMatrix() const {
    const bool isInputHdrDataSpace = isHdrDataSpace(mDataSpace);
    const bool isOutputHdrDataSpace = isHdrDataSpace(mOutputDataSpace);
    const Dataspace inputTransfer = static_cast<Dataspace>(mDataSpace & Dataspace::TRANSFER_MASK);
    const Dataspace outputTransfer = static_cast<Dataspace>(mOutputDataSpace &
                                                            Dataspace::TRANSFER_MASK);

    return (isInputHdrDataSpace || isOutputHdrDataSpace) && inputTransfer != outputTransfer;
}

}  // namespace gl
}  // namespace renderengine
}  // namespace android
