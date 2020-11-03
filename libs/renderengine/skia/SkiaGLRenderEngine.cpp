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

//#define LOG_NDEBUG 0
#include <cstdint>
#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <sync/sync.h>
#include <ui/BlurRegion.h>
#include <ui/GraphicBuffer.h>
#include <utils/Trace.h>
#include "../gl/GLExtensions.h"
#include "SkiaGLRenderEngine.h"
#include "filters/BlurFilter.h"

#include <GrContextOptions.h>
#include <SkCanvas.h>
#include <SkColorFilter.h>
#include <SkColorMatrix.h>
#include <SkColorSpace.h>
#include <SkImage.h>
#include <SkImageFilters.h>
#include <SkShadowUtils.h>
#include <SkSurface.h>
#include <gl/GrGLInterface.h>
#include <sync/sync.h>
#include <ui/GraphicBuffer.h>
#include <utils/Trace.h>

#include <cmath>

#include "../gl/GLExtensions.h"
#include "SkiaGLRenderEngine.h"
#include "filters/BlurFilter.h"

extern "C" EGLAPI const char* eglQueryStringImplementationANDROID(EGLDisplay dpy, EGLint name);

bool checkGlError(const char* op, int lineNumber);

namespace android {
namespace renderengine {
namespace skia {

static status_t selectConfigForAttribute(EGLDisplay dpy, EGLint const* attrs, EGLint attribute,
                                         EGLint wanted, EGLConfig* outConfig) {
    EGLint numConfigs = -1, n = 0;
    eglGetConfigs(dpy, nullptr, 0, &numConfigs);
    std::vector<EGLConfig> configs(numConfigs, EGL_NO_CONFIG_KHR);
    eglChooseConfig(dpy, attrs, configs.data(), configs.size(), &n);
    configs.resize(n);

    if (!configs.empty()) {
        if (attribute != EGL_NONE) {
            for (EGLConfig config : configs) {
                EGLint value = 0;
                eglGetConfigAttrib(dpy, config, attribute, &value);
                if (wanted == value) {
                    *outConfig = config;
                    return NO_ERROR;
                }
            }
        } else {
            // just pick the first one
            *outConfig = configs[0];
            return NO_ERROR;
        }
    }

    return NAME_NOT_FOUND;
}

static status_t selectEGLConfig(EGLDisplay display, EGLint format, EGLint renderableType,
                                EGLConfig* config) {
    // select our EGLConfig. It must support EGL_RECORDABLE_ANDROID if
    // it is to be used with WIFI displays
    status_t err;
    EGLint wantedAttribute;
    EGLint wantedAttributeValue;

    std::vector<EGLint> attribs;
    if (renderableType) {
        const ui::PixelFormat pixelFormat = static_cast<ui::PixelFormat>(format);
        const bool is1010102 = pixelFormat == ui::PixelFormat::RGBA_1010102;

        // Default to 8 bits per channel.
        const EGLint tmpAttribs[] = {
                EGL_RENDERABLE_TYPE,
                renderableType,
                EGL_RECORDABLE_ANDROID,
                EGL_TRUE,
                EGL_SURFACE_TYPE,
                EGL_WINDOW_BIT | EGL_PBUFFER_BIT,
                EGL_FRAMEBUFFER_TARGET_ANDROID,
                EGL_TRUE,
                EGL_RED_SIZE,
                is1010102 ? 10 : 8,
                EGL_GREEN_SIZE,
                is1010102 ? 10 : 8,
                EGL_BLUE_SIZE,
                is1010102 ? 10 : 8,
                EGL_ALPHA_SIZE,
                is1010102 ? 2 : 8,
                EGL_NONE,
        };
        std::copy(tmpAttribs, tmpAttribs + (sizeof(tmpAttribs) / sizeof(EGLint)),
                  std::back_inserter(attribs));
        wantedAttribute = EGL_NONE;
        wantedAttributeValue = EGL_NONE;
    } else {
        // if no renderable type specified, fallback to a simplified query
        wantedAttribute = EGL_NATIVE_VISUAL_ID;
        wantedAttributeValue = format;
    }

    err = selectConfigForAttribute(display, attribs.data(), wantedAttribute, wantedAttributeValue,
                                   config);
    if (err == NO_ERROR) {
        EGLint caveat;
        if (eglGetConfigAttrib(display, *config, EGL_CONFIG_CAVEAT, &caveat))
            ALOGW_IF(caveat == EGL_SLOW_CONFIG, "EGL_SLOW_CONFIG selected!");
    }

    return err;
}

// Converts an android dataspace to a supported SkColorSpace
// Supported dataspaces are
// 1. sRGB
// 2. Display P3
// 3. BT2020 PQ
// 4. BT2020 HLG
// Unknown primaries are mapped to BT709, and unknown transfer functions
// are mapped to sRGB.
static sk_sp<SkColorSpace> toColorSpace(ui::Dataspace dataspace) {
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

std::unique_ptr<SkiaGLRenderEngine> SkiaGLRenderEngine::create(
        const RenderEngineCreationArgs& args) {
    // initialize EGL for the default display
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!eglInitialize(display, nullptr, nullptr)) {
        LOG_ALWAYS_FATAL("failed to initialize EGL");
    }

    const auto eglVersion = eglQueryStringImplementationANDROID(display, EGL_VERSION);
    if (!eglVersion) {
        checkGlError(__FUNCTION__, __LINE__);
        LOG_ALWAYS_FATAL("eglQueryStringImplementationANDROID(EGL_VERSION) failed");
    }

    const auto eglExtensions = eglQueryStringImplementationANDROID(display, EGL_EXTENSIONS);
    if (!eglExtensions) {
        checkGlError(__FUNCTION__, __LINE__);
        LOG_ALWAYS_FATAL("eglQueryStringImplementationANDROID(EGL_EXTENSIONS) failed");
    }

    auto& extensions = gl::GLExtensions::getInstance();
    extensions.initWithEGLStrings(eglVersion, eglExtensions);

    // The code assumes that ES2 or later is available if this extension is
    // supported.
    EGLConfig config = EGL_NO_CONFIG_KHR;
    if (!extensions.hasNoConfigContext()) {
        config = chooseEglConfig(display, args.pixelFormat, /*logConfig*/ true);
    }

    bool useContextPriority =
            extensions.hasContextPriority() && args.contextPriority == ContextPriority::HIGH;
    EGLContext protectedContext = EGL_NO_CONTEXT;
    if (args.enableProtectedContext && extensions.hasProtectedContent()) {
        protectedContext = createEglContext(display, config, nullptr, useContextPriority,
                                            Protection::PROTECTED);
        ALOGE_IF(protectedContext == EGL_NO_CONTEXT, "Can't create protected context");
    }

    EGLContext ctxt = createEglContext(display, config, protectedContext, useContextPriority,
                                       Protection::UNPROTECTED);

    // if can't create a GL context, we can only abort.
    LOG_ALWAYS_FATAL_IF(ctxt == EGL_NO_CONTEXT, "EGLContext creation failed");

    EGLSurface placeholder = EGL_NO_SURFACE;
    if (!extensions.hasSurfacelessContext()) {
        placeholder = createPlaceholderEglPbufferSurface(display, config, args.pixelFormat,
                                                         Protection::UNPROTECTED);
        LOG_ALWAYS_FATAL_IF(placeholder == EGL_NO_SURFACE, "can't create placeholder pbuffer");
    }
    EGLBoolean success = eglMakeCurrent(display, placeholder, placeholder, ctxt);
    LOG_ALWAYS_FATAL_IF(!success, "can't make placeholder pbuffer current");
    extensions.initWithGLStrings(glGetString(GL_VENDOR), glGetString(GL_RENDERER),
                                 glGetString(GL_VERSION), glGetString(GL_EXTENSIONS));

    EGLSurface protectedPlaceholder = EGL_NO_SURFACE;
    if (protectedContext != EGL_NO_CONTEXT && !extensions.hasSurfacelessContext()) {
        protectedPlaceholder = createPlaceholderEglPbufferSurface(display, config, args.pixelFormat,
                                                                  Protection::PROTECTED);
        ALOGE_IF(protectedPlaceholder == EGL_NO_SURFACE,
                 "can't create protected placeholder pbuffer");
    }

    // initialize the renderer while GL is current
    std::unique_ptr<SkiaGLRenderEngine> engine =
            std::make_unique<SkiaGLRenderEngine>(args, display, config, ctxt, placeholder,
                                                 protectedContext, protectedPlaceholder);

    ALOGI("OpenGL ES informations:");
    ALOGI("vendor    : %s", extensions.getVendor());
    ALOGI("renderer  : %s", extensions.getRenderer());
    ALOGI("version   : %s", extensions.getVersion());
    ALOGI("extensions: %s", extensions.getExtensions());
    ALOGI("GL_MAX_TEXTURE_SIZE = %zu", engine->getMaxTextureSize());
    ALOGI("GL_MAX_VIEWPORT_DIMS = %zu", engine->getMaxViewportDims());

    return engine;
}

EGLConfig SkiaGLRenderEngine::chooseEglConfig(EGLDisplay display, int format, bool logConfig) {
    status_t err;
    EGLConfig config;

    // First try to get an ES3 config
    err = selectEGLConfig(display, format, EGL_OPENGL_ES3_BIT, &config);
    if (err != NO_ERROR) {
        // If ES3 fails, try to get an ES2 config
        err = selectEGLConfig(display, format, EGL_OPENGL_ES2_BIT, &config);
        if (err != NO_ERROR) {
            // If ES2 still doesn't work, probably because we're on the emulator.
            // try a simplified query
            ALOGW("no suitable EGLConfig found, trying a simpler query");
            err = selectEGLConfig(display, format, 0, &config);
            if (err != NO_ERROR) {
                // this EGL is too lame for android
                LOG_ALWAYS_FATAL("no suitable EGLConfig found, giving up");
            }
        }
    }

    if (logConfig) {
        // print some debugging info
        EGLint r, g, b, a;
        eglGetConfigAttrib(display, config, EGL_RED_SIZE, &r);
        eglGetConfigAttrib(display, config, EGL_GREEN_SIZE, &g);
        eglGetConfigAttrib(display, config, EGL_BLUE_SIZE, &b);
        eglGetConfigAttrib(display, config, EGL_ALPHA_SIZE, &a);
        ALOGI("EGL information:");
        ALOGI("vendor    : %s", eglQueryString(display, EGL_VENDOR));
        ALOGI("version   : %s", eglQueryString(display, EGL_VERSION));
        ALOGI("extensions: %s", eglQueryString(display, EGL_EXTENSIONS));
        ALOGI("Client API: %s", eglQueryString(display, EGL_CLIENT_APIS) ?: "Not Supported");
        ALOGI("EGLSurface: %d-%d-%d-%d, config=%p", r, g, b, a, config);
    }

    return config;
}

SkiaGLRenderEngine::SkiaGLRenderEngine(const RenderEngineCreationArgs& args, EGLDisplay display,
                                       EGLConfig config, EGLContext ctxt, EGLSurface placeholder,
                                       EGLContext protectedContext, EGLSurface protectedPlaceholder)
      : mEGLDisplay(display),
        mEGLConfig(config),
        mEGLContext(ctxt),
        mPlaceholderSurface(placeholder),
        mProtectedEGLContext(protectedContext),
        mProtectedPlaceholderSurface(protectedPlaceholder),
        mUseColorManagement(args.useColorManagement) {
    // Suppress unused field warnings for things we definitely will need/use
    // These EGL fields will all be needed for toggling between protected & unprotected contexts
    // Or we need different RE instances for that
    (void)mEGLDisplay;
    (void)mEGLConfig;
    (void)mEGLContext;
    (void)mPlaceholderSurface;
    (void)mProtectedEGLContext;
    (void)mProtectedPlaceholderSurface;

    sk_sp<const GrGLInterface> glInterface(GrGLCreateNativeInterface());
    LOG_ALWAYS_FATAL_IF(!glInterface.get());

    GrContextOptions options;
    options.fPreferExternalImagesOverES3 = true;
    options.fDisableDistanceFieldPaths = true;
    mGrContext = GrDirectContext::MakeGL(std::move(glInterface), options);

    if (args.supportsBackgroundBlur) {
        mBlurFilter = new BlurFilter();
    }
}

base::unique_fd SkiaGLRenderEngine::flush() {
    ATRACE_CALL();
    if (!gl::GLExtensions::getInstance().hasNativeFenceSync()) {
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

bool SkiaGLRenderEngine::waitFence(base::unique_fd fenceFd) {
    if (!gl::GLExtensions::getInstance().hasNativeFenceSync() ||
        !gl::GLExtensions::getInstance().hasWaitSync()) {
        return false;
    }

    // release the fd and transfer the ownership to EGLSync
    EGLint attribs[] = {EGL_SYNC_NATIVE_FENCE_FD_ANDROID, fenceFd.release(), EGL_NONE};
    EGLSyncKHR sync = eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_NATIVE_FENCE_ANDROID, attribs);
    if (sync == EGL_NO_SYNC_KHR) {
        ALOGE("failed to create EGL native fence sync: %#x", eglGetError());
        return false;
    }

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

static bool hasUsage(const AHardwareBuffer_Desc& desc, uint64_t usage) {
    return !!(desc.usage & usage);
}

static float toDegrees(uint32_t transform) {
    switch (transform) {
        case ui::Transform::ROT_90:
            return 90.0;
        case ui::Transform::ROT_180:
            return 180.0;
        case ui::Transform::ROT_270:
            return 270.0;
        default:
            return 0.0;
    }
}

static SkColorMatrix toSkColorMatrix(const mat4& matrix) {
    return SkColorMatrix(matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0], 0, matrix[0][1],
                         matrix[1][1], matrix[2][1], matrix[3][1], 0, matrix[0][2], matrix[1][2],
                         matrix[2][2], matrix[3][2], 0, matrix[0][3], matrix[1][3], matrix[2][3],
                         matrix[3][3], 0);
}

void SkiaGLRenderEngine::unbindExternalTextureBuffer(uint64_t bufferId) {
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    mImageCache.erase(bufferId);
}

status_t SkiaGLRenderEngine::drawLayers(const DisplaySettings& display,
                                        const std::vector<const LayerSettings*>& layers,
                                        const sp<GraphicBuffer>& buffer,
                                        const bool useFramebufferCache,
                                        base::unique_fd&& bufferFence, base::unique_fd* drawFence) {
    ATRACE_NAME("SkiaGL::drawLayers");
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    if (layers.empty()) {
        ALOGV("Drawing empty layer stack");
        return NO_ERROR;
    }

    if (bufferFence.get() >= 0) {
        // Duplicate the fence for passing to waitFence.
        base::unique_fd bufferFenceDup(dup(bufferFence.get()));
        if (bufferFenceDup < 0 || !waitFence(std::move(bufferFenceDup))) {
            ATRACE_NAME("Waiting before draw");
            sync_wait(bufferFence.get(), -1);
        }
    }
    if (buffer == nullptr) {
        ALOGE("No output buffer provided. Aborting GPU composition.");
        return BAD_VALUE;
    }

    AHardwareBuffer_Desc bufferDesc;
    AHardwareBuffer_describe(buffer->toAHardwareBuffer(), &bufferDesc);

    LOG_ALWAYS_FATAL_IF(!hasUsage(bufferDesc, AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE),
                        "missing usage");

    sk_sp<SkSurface> surface;
    if (useFramebufferCache) {
        auto iter = mSurfaceCache.find(buffer->getId());
        if (iter != mSurfaceCache.end()) {
            ALOGV("Cache hit!");
            surface = iter->second;
        }
    }
    if (!surface) {
        surface = SkSurface::MakeFromAHardwareBuffer(mGrContext.get(), buffer->toAHardwareBuffer(),
                                                     GrSurfaceOrigin::kTopLeft_GrSurfaceOrigin,
                                                     mUseColorManagement
                                                             ? toColorSpace(display.outputDataspace)
                                                             : SkColorSpace::MakeSRGB(),
                                                     nullptr);
        if (useFramebufferCache && surface) {
            ALOGD("Adding to cache");
            mSurfaceCache.insert({buffer->getId(), surface});
        }
    }
    if (!surface) {
        ALOGE("Failed to make surface");
        return BAD_VALUE;
    }

    auto canvas = surface->getCanvas();
    // Clear the entire canvas with a transparent black to prevent ghost images.
    canvas->clear(SK_ColorTRANSPARENT);
    canvas->save();

    // Before doing any drawing, let's make sure that we'll start at the origin of the display.
    // Some displays don't start at 0,0 for example when we're mirroring the screen. Also, virtual
    // displays might have different scaling when compared to the physical screen.

    canvas->clipRect(getSkRect(display.physicalDisplay));
    SkMatrix screenTransform;
    screenTransform.setTranslate(display.physicalDisplay.left, display.physicalDisplay.top);

    const auto clipWidth = display.clip.width();
    const auto clipHeight = display.clip.height();
    auto rotatedClipWidth = clipWidth;
    auto rotatedClipHeight = clipHeight;
    // Scale is contingent on the rotation result.
    if (display.orientation & ui::Transform::ROT_90) {
        std::swap(rotatedClipWidth, rotatedClipHeight);
    }
    const auto scaleX = static_cast<SkScalar>(display.physicalDisplay.width()) /
            static_cast<SkScalar>(rotatedClipWidth);
    const auto scaleY = static_cast<SkScalar>(display.physicalDisplay.height()) /
            static_cast<SkScalar>(rotatedClipHeight);
    screenTransform.preScale(scaleX, scaleY);

    // Canvas rotation is done by centering the clip window at the origin, rotating, translating
    // back so that the top left corner of the clip is at (0, 0).
    screenTransform.preTranslate(rotatedClipWidth / 2, rotatedClipHeight / 2);
    screenTransform.preRotate(toDegrees(display.orientation));
    screenTransform.preTranslate(-clipWidth / 2, -clipHeight / 2);
    screenTransform.preTranslate(-display.clip.left, -display.clip.top);
    for (const auto& layer : layers) {
        const SkMatrix drawTransform = getDrawTransform(layer, screenTransform);

        SkPaint paint;
        const auto& bounds = layer->geometry.boundaries;
        const auto dest = getSkRect(bounds);
        std::unordered_map<uint32_t, sk_sp<SkSurface>> cachedBlurs;

        if (mBlurFilter) {
            const auto layerRect = drawTransform.mapRect(dest);
            if (layer->backgroundBlurRadius > 0) {
                ATRACE_NAME("BackgroundBlur");
                auto blurredSurface =
                        mBlurFilter->draw(canvas, surface, layer->backgroundBlurRadius, layerRect);
                cachedBlurs[layer->backgroundBlurRadius] = blurredSurface;
            }
            if (layer->blurRegions.size() > 0) {
                for (auto region : layer->blurRegions) {
                    if (cachedBlurs[region.blurRadius]) {
                        continue;
                    }
                    ATRACE_NAME("BlurRegion");
                    auto blurredSurface =
                            mBlurFilter->generate(canvas, surface, region.blurRadius, layerRect);
                    cachedBlurs[region.blurRadius] = blurredSurface;
                }
            }
        }

        if (layer->source.buffer.buffer) {
            ATRACE_NAME("DrawImage");
            const auto& item = layer->source.buffer;
            const auto bufferWidth = item.buffer->getBounds().width();
            const auto bufferHeight = item.buffer->getBounds().height();
            sk_sp<SkImage> image;
            auto iter = mImageCache.find(item.buffer->getId());
            if (iter != mImageCache.end()) {
                image = iter->second;
            } else {
                image = SkImage::MakeFromAHardwareBuffer(item.buffer->toAHardwareBuffer(),
                                                         item.usePremultipliedAlpha
                                                                 ? kPremul_SkAlphaType
                                                                 : kUnpremul_SkAlphaType,
                                                         mUseColorManagement
                                                                 ? toColorSpace(
                                                                           layer->sourceDataspace)
                                                                 : SkColorSpace::MakeSRGB());
                mImageCache.insert({item.buffer->getId(), image});
            }

            SkMatrix matrix;
            if (layer->geometry.roundedCornersRadius > 0) {
                const auto roundedRect = getRoundedRect(layer);
                matrix.setTranslate(roundedRect.getBounds().left() - dest.left(),
                                    roundedRect.getBounds().top() - dest.top());
            } else {
                matrix.setIdentity();
            }

            auto texMatrix = getSkM44(item.textureTransform).asM33();
            // textureTansform was intended to be passed directly into a shader, so when
            // building the total matrix with the textureTransform we need to first
            // normalize it, then apply the textureTransform, then scale back up.
            matrix.postScale(1.0f / bufferWidth, 1.0f / bufferHeight);

            auto rotatedBufferWidth = bufferWidth;
            auto rotatedBufferHeight = bufferHeight;

            // Swap the buffer width and height if we're rotating, so that we
            // scale back up by the correct factors post-rotation.
            if (texMatrix.getSkewX() <= -0.5f || texMatrix.getSkewX() >= 0.5f) {
                std::swap(rotatedBufferWidth, rotatedBufferHeight);
                // TODO: clean this up.
                // GLESRenderEngine specifies its texture coordinates in
                // CW orientation under OpenGL conventions, when they probably should have
                // been CCW instead. The net result is that orientation
                // transforms are applied in the reverse
                // direction to render the correct result, because SurfaceFlinger uses the inverse
                // of the display transform to correct for that. But this means that
                // the tex transform passed by SkiaGLRenderEngine will rotate
                // individual layers in the reverse orientation. Hack around it
                // by injected a 180 degree rotation, but ultimately this is
                // a bug in how SurfaceFlinger invokes the RenderEngine
                // interface, so the proper fix should live there, and GLESRenderEngine
                // should be fixed accordingly.
                matrix.postRotate(180, 0.5, 0.5);
            }

            matrix.postConcat(texMatrix);
            matrix.postScale(rotatedBufferWidth, rotatedBufferHeight);
            paint.setShader(image->makeShader(matrix));
        } else {
            ATRACE_NAME("DrawColor");
            const auto color = layer->source.solidColor;
            paint.setShader(SkShaders::Color(SkColor4f{.fR = color.r,
                                                       .fG = color.g,
                                                       .fB = color.b,
                                                       layer->alpha},
                                             nullptr));
        }

        paint.setColorFilter(SkColorFilters::Matrix(toSkColorMatrix(display.colorTransform)));

        canvas->save();
        canvas->concat(drawTransform);

        for (const auto effectRegion : layer->blurRegions) {
            drawBlurRegion(canvas, effectRegion, dest, cachedBlurs[effectRegion.blurRadius]);
        }

        if (layer->shadow.length > 0) {
            const auto rect = layer->geometry.roundedCornersRadius > 0
                    ? getSkRect(layer->geometry.roundedCornersCrop)
                    : dest;
            drawShadow(canvas, rect, layer->geometry.roundedCornersRadius, layer->shadow);
        }

        if (layer->geometry.roundedCornersRadius > 0) {
            canvas->drawRRect(getRoundedRect(layer), paint);
        } else {
            canvas->drawRect(dest, paint);
        }

        canvas->restore();
    }
    {
        ATRACE_NAME("flush surface");
        surface->flush();
    }
    canvas->restore();

    if (drawFence != nullptr) {
        *drawFence = flush();
    }

    // If flush failed or we don't support native fences, we need to force the
    // gl command stream to be executed.
    bool requireSync = drawFence == nullptr || drawFence->get() < 0;
    if (requireSync) {
        ATRACE_BEGIN("Submit(sync=true)");
    } else {
        ATRACE_BEGIN("Submit(sync=false)");
    }
    bool success = mGrContext->submit(requireSync);
    ATRACE_END();
    if (!success) {
        ALOGE("Failed to flush RenderEngine commands");
        // Chances are, something illegal happened (either the caller passed
        // us bad parameters, or we messed up our shader generation).
        return INVALID_OPERATION;
    }

    // checkErrors();
    return NO_ERROR;
}

inline SkRect SkiaGLRenderEngine::getSkRect(const FloatRect& rect) {
    return SkRect::MakeLTRB(rect.left, rect.top, rect.right, rect.bottom);
}

inline SkRect SkiaGLRenderEngine::getSkRect(const Rect& rect) {
    return SkRect::MakeLTRB(rect.left, rect.top, rect.right, rect.bottom);
}

inline SkRRect SkiaGLRenderEngine::getRoundedRect(const LayerSettings* layer) {
    const auto rect = getSkRect(layer->geometry.roundedCornersCrop);
    const auto cornerRadius = layer->geometry.roundedCornersRadius;
    return SkRRect::MakeRectXY(rect, cornerRadius, cornerRadius);
}

inline SkColor SkiaGLRenderEngine::getSkColor(const vec4& color) {
    return SkColorSetARGB(color.a * 255, color.r * 255, color.g * 255, color.b * 255);
}

inline SkM44 SkiaGLRenderEngine::getSkM44(const mat4& matrix) {
    return SkM44(matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0],
                 matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1],
                 matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2],
                 matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3]);
}

inline SkMatrix SkiaGLRenderEngine::getDrawTransform(const LayerSettings* layer,
                                                     const SkMatrix& screenTransform) {
    // Layers have a local transform matrix that should be applied to them.
    const auto layerTransform = getSkM44(layer->geometry.positionTransform).asM33();
    return SkMatrix::Concat(screenTransform, layerTransform);
}

inline SkPoint3 SkiaGLRenderEngine::getSkPoint3(const vec3& vector) {
    return SkPoint3::Make(vector.x, vector.y, vector.z);
}

size_t SkiaGLRenderEngine::getMaxTextureSize() const {
    return mGrContext->maxTextureSize();
}

size_t SkiaGLRenderEngine::getMaxViewportDims() const {
    return mGrContext->maxRenderTargetSize();
}

void SkiaGLRenderEngine::drawShadow(SkCanvas* canvas, const SkRect& casterRect, float cornerRadius,
                                    const ShadowSettings& settings) {
    ATRACE_CALL();
    const float casterZ = settings.length / 2.0f;
    const auto shadowShape = cornerRadius > 0
            ? SkPath::RRect(SkRRect::MakeRectXY(casterRect, cornerRadius, cornerRadius))
            : SkPath::Rect(casterRect);
    const auto flags =
            settings.casterIsTranslucent ? kTransparentOccluder_ShadowFlag : kNone_ShadowFlag;

    SkShadowUtils::DrawShadow(canvas, shadowShape, SkPoint3::Make(0, 0, casterZ),
                              getSkPoint3(settings.lightPos), settings.lightRadius,
                              getSkColor(settings.ambientColor), getSkColor(settings.spotColor),
                              flags);
}

void SkiaGLRenderEngine::drawBlurRegion(SkCanvas* canvas, const BlurRegion& effectRegion,
                                        const SkRect& layerBoundaries,
                                        sk_sp<SkSurface> blurredSurface) {
    ATRACE_CALL();
    SkPaint paint;
    paint.setAlpha(static_cast<int>(effectRegion.alpha * 255));
    const auto rect = SkRect::MakeLTRB(effectRegion.left, effectRegion.top, effectRegion.right,
                                       effectRegion.bottom);

    const auto matrix = mBlurFilter->getShaderMatrix(
            SkMatrix::MakeTrans(layerBoundaries.left(), layerBoundaries.top()));
    paint.setShader(blurredSurface->makeImageSnapshot()->makeShader(matrix));

    if (effectRegion.cornerRadiusTL > 0 || effectRegion.cornerRadiusTR > 0 ||
        effectRegion.cornerRadiusBL > 0 || effectRegion.cornerRadiusBR > 0) {
        const SkVector radii[4] =
                {SkVector::Make(effectRegion.cornerRadiusTL, effectRegion.cornerRadiusTL),
                 SkVector::Make(effectRegion.cornerRadiusTR, effectRegion.cornerRadiusTR),
                 SkVector::Make(effectRegion.cornerRadiusBL, effectRegion.cornerRadiusBL),
                 SkVector::Make(effectRegion.cornerRadiusBR, effectRegion.cornerRadiusBR)};
        SkRRect roundedRect;
        roundedRect.setRectRadii(rect, radii);
        canvas->drawRRect(roundedRect, paint);
    } else {
        canvas->drawRect(rect, paint);
    }
}

EGLContext SkiaGLRenderEngine::createEglContext(EGLDisplay display, EGLConfig config,
                                                EGLContext shareContext, bool useContextPriority,
                                                Protection protection) {
    EGLint renderableType = 0;
    if (config == EGL_NO_CONFIG_KHR) {
        renderableType = EGL_OPENGL_ES3_BIT;
    } else if (!eglGetConfigAttrib(display, config, EGL_RENDERABLE_TYPE, &renderableType)) {
        LOG_ALWAYS_FATAL("can't query EGLConfig RENDERABLE_TYPE");
    }
    EGLint contextClientVersion = 0;
    if (renderableType & EGL_OPENGL_ES3_BIT) {
        contextClientVersion = 3;
    } else if (renderableType & EGL_OPENGL_ES2_BIT) {
        contextClientVersion = 2;
    } else if (renderableType & EGL_OPENGL_ES_BIT) {
        contextClientVersion = 1;
    } else {
        LOG_ALWAYS_FATAL("no supported EGL_RENDERABLE_TYPEs");
    }

    std::vector<EGLint> contextAttributes;
    contextAttributes.reserve(7);
    contextAttributes.push_back(EGL_CONTEXT_CLIENT_VERSION);
    contextAttributes.push_back(contextClientVersion);
    if (useContextPriority) {
        contextAttributes.push_back(EGL_CONTEXT_PRIORITY_LEVEL_IMG);
        contextAttributes.push_back(EGL_CONTEXT_PRIORITY_HIGH_IMG);
    }
    if (protection == Protection::PROTECTED) {
        contextAttributes.push_back(EGL_PROTECTED_CONTENT_EXT);
        contextAttributes.push_back(EGL_TRUE);
    }
    contextAttributes.push_back(EGL_NONE);

    EGLContext context = eglCreateContext(display, config, shareContext, contextAttributes.data());

    if (contextClientVersion == 3 && context == EGL_NO_CONTEXT) {
        // eglGetConfigAttrib indicated we can create GLES 3 context, but we failed, thus
        // EGL_NO_CONTEXT so that we can abort.
        if (config != EGL_NO_CONFIG_KHR) {
            return context;
        }
        // If |config| is EGL_NO_CONFIG_KHR, we speculatively try to create GLES 3 context, so we
        // should try to fall back to GLES 2.
        contextAttributes[1] = 2;
        context = eglCreateContext(display, config, shareContext, contextAttributes.data());
    }

    return context;
}

EGLSurface SkiaGLRenderEngine::createPlaceholderEglPbufferSurface(EGLDisplay display,
                                                                  EGLConfig config, int hwcFormat,
                                                                  Protection protection) {
    EGLConfig placeholderConfig = config;
    if (placeholderConfig == EGL_NO_CONFIG_KHR) {
        placeholderConfig = chooseEglConfig(display, hwcFormat, /*logConfig*/ true);
    }
    std::vector<EGLint> attributes;
    attributes.reserve(7);
    attributes.push_back(EGL_WIDTH);
    attributes.push_back(1);
    attributes.push_back(EGL_HEIGHT);
    attributes.push_back(1);
    if (protection == Protection::PROTECTED) {
        attributes.push_back(EGL_PROTECTED_CONTENT_EXT);
        attributes.push_back(EGL_TRUE);
    }
    attributes.push_back(EGL_NONE);

    return eglCreatePbufferSurface(display, placeholderConfig, attributes.data());
}

void SkiaGLRenderEngine::cleanFramebufferCache() {
    mSurfaceCache.clear();
}

} // namespace skia
} // namespace renderengine
} // namespace android
