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
#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "SkiaGLRenderEngine.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GrContextOptions.h>
#include <SkCanvas.h>
#include <SkColorFilter.h>
#include <SkColorMatrix.h>
#include <SkColorSpace.h>
#include <SkImage.h>
#include <SkImageFilters.h>
#include <SkRegion.h>
#include <SkShadowUtils.h>
#include <SkSurface.h>
#include <gl/GrGLInterface.h>
#include <sync/sync.h>
#include <ui/BlurRegion.h>
#include <ui/GraphicBuffer.h>
#include <utils/Trace.h>

#include <cmath>
#include <cstdint>
#include <memory>

#include "../gl/GLExtensions.h"
#include "ColorSpaces.h"
#include "SkBlendMode.h"
#include "SkImageInfo.h"
#include "filters/BlurFilter.h"
#include "filters/LinearEffect.h"
#include "log/log_main.h"
#include "skia/debug/SkiaCapture.h"
#include "system/graphics-base-v1.0.h"

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

std::unique_ptr<SkiaGLRenderEngine> SkiaGLRenderEngine::create(
        const RenderEngineCreationArgs& args) {
    // initialize EGL for the default display
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!eglInitialize(display, nullptr, nullptr)) {
        LOG_ALWAYS_FATAL("failed to initialize EGL");
    }

    const auto eglVersion = eglQueryString(display, EGL_VERSION);
    if (!eglVersion) {
        checkGlError(__FUNCTION__, __LINE__);
        LOG_ALWAYS_FATAL("eglQueryString(EGL_VERSION) failed");
    }

    const auto eglExtensions = eglQueryString(display, EGL_EXTENSIONS);
    if (!eglExtensions) {
        checkGlError(__FUNCTION__, __LINE__);
        LOG_ALWAYS_FATAL("eglQueryString(EGL_EXTENSIONS) failed");
    }

    auto& extensions = gl::GLExtensions::getInstance();
    extensions.initWithEGLStrings(eglVersion, eglExtensions);

    // The code assumes that ES2 or later is available if this extension is
    // supported.
    EGLConfig config = EGL_NO_CONFIG_KHR;
    if (!extensions.hasNoConfigContext()) {
        config = chooseEglConfig(display, args.pixelFormat, /*logConfig*/ true);
    }

    EGLContext protectedContext = EGL_NO_CONTEXT;
    const std::optional<RenderEngine::ContextPriority> priority = createContextPriority(args);
    if (args.enableProtectedContext && extensions.hasProtectedContent()) {
        protectedContext =
                createEglContext(display, config, nullptr, priority, Protection::PROTECTED);
        ALOGE_IF(protectedContext == EGL_NO_CONTEXT, "Can't create protected context");
    }

    EGLContext ctxt =
            createEglContext(display, config, protectedContext, priority, Protection::UNPROTECTED);

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
            std::make_unique<SkiaGLRenderEngine>(args, display, ctxt, placeholder, protectedContext,
                                                 protectedPlaceholder);

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
                                       EGLContext ctxt, EGLSurface placeholder,
                                       EGLContext protectedContext, EGLSurface protectedPlaceholder)
      : mEGLDisplay(display),
        mEGLContext(ctxt),
        mPlaceholderSurface(placeholder),
        mProtectedEGLContext(protectedContext),
        mProtectedPlaceholderSurface(protectedPlaceholder),
        mUseColorManagement(args.useColorManagement) {
    sk_sp<const GrGLInterface> glInterface(GrGLCreateNativeInterface());
    LOG_ALWAYS_FATAL_IF(!glInterface.get());

    GrContextOptions options;
    options.fPreferExternalImagesOverES3 = true;
    options.fDisableDistanceFieldPaths = true;
    mGrContext = GrDirectContext::MakeGL(glInterface, options);
    if (useProtectedContext(true)) {
        mProtectedGrContext = GrDirectContext::MakeGL(glInterface, options);
        useProtectedContext(false);
    }

    if (args.supportsBackgroundBlur) {
        mBlurFilter = new BlurFilter();
    }
    mCapture = std::make_unique<SkiaCapture>();
}

SkiaGLRenderEngine::~SkiaGLRenderEngine() {
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    mRuntimeEffects.clear();
    mProtectedTextureCache.clear();
    mTextureCache.clear();

    if (mBlurFilter) {
        delete mBlurFilter;
    }

    mCapture = nullptr;

    mGrContext->flushAndSubmit(true);
    mGrContext->abandonContext();

    if (mProtectedGrContext) {
        mProtectedGrContext->flushAndSubmit(true);
        mProtectedGrContext->abandonContext();
    }

    if (mPlaceholderSurface != EGL_NO_SURFACE) {
        eglDestroySurface(mEGLDisplay, mPlaceholderSurface);
    }
    if (mProtectedPlaceholderSurface != EGL_NO_SURFACE) {
        eglDestroySurface(mEGLDisplay, mProtectedPlaceholderSurface);
    }
    if (mEGLContext != EGL_NO_CONTEXT) {
        eglDestroyContext(mEGLDisplay, mEGLContext);
    }
    if (mProtectedEGLContext != EGL_NO_CONTEXT) {
        eglDestroyContext(mEGLDisplay, mProtectedEGLContext);
    }
    eglMakeCurrent(mEGLDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglTerminate(mEGLDisplay);
    eglReleaseThread();
}

bool SkiaGLRenderEngine::supportsProtectedContent() const {
    return mProtectedEGLContext != EGL_NO_CONTEXT;
}

bool SkiaGLRenderEngine::useProtectedContext(bool useProtectedContext) {
    if (useProtectedContext == mInProtectedContext) {
        return true;
    }
    if (useProtectedContext && supportsProtectedContent()) {
        return false;
    }
    const EGLSurface surface =
            useProtectedContext ? mProtectedPlaceholderSurface : mPlaceholderSurface;
    const EGLContext context = useProtectedContext ? mProtectedEGLContext : mEGLContext;
    const bool success = eglMakeCurrent(mEGLDisplay, surface, surface, context) == EGL_TRUE;

    if (success) {
        mInProtectedContext = useProtectedContext;
    }
    return success;
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

static bool needsToneMapping(ui::Dataspace sourceDataspace, ui::Dataspace destinationDataspace) {
    int64_t sourceTransfer = sourceDataspace & HAL_DATASPACE_TRANSFER_MASK;
    int64_t destTransfer = destinationDataspace & HAL_DATASPACE_TRANSFER_MASK;

    // Treat unsupported dataspaces as srgb
    if (destTransfer != HAL_DATASPACE_TRANSFER_LINEAR &&
        destTransfer != HAL_DATASPACE_TRANSFER_HLG &&
        destTransfer != HAL_DATASPACE_TRANSFER_ST2084) {
        destTransfer = HAL_DATASPACE_TRANSFER_SRGB;
    }

    if (sourceTransfer != HAL_DATASPACE_TRANSFER_LINEAR &&
        sourceTransfer != HAL_DATASPACE_TRANSFER_HLG &&
        sourceTransfer != HAL_DATASPACE_TRANSFER_ST2084) {
        sourceTransfer = HAL_DATASPACE_TRANSFER_SRGB;
    }

    const bool isSourceLinear = sourceTransfer == HAL_DATASPACE_TRANSFER_LINEAR;
    const bool isSourceSRGB = sourceTransfer == HAL_DATASPACE_TRANSFER_SRGB;
    const bool isDestLinear = destTransfer == HAL_DATASPACE_TRANSFER_LINEAR;
    const bool isDestSRGB = destTransfer == HAL_DATASPACE_TRANSFER_SRGB;

    return !(isSourceLinear && isDestSRGB) && !(isSourceSRGB && isDestLinear) &&
            sourceTransfer != destTransfer;
}

static bool needsLinearEffect(const mat4& colorTransform, ui::Dataspace sourceDataspace,
                              ui::Dataspace destinationDataspace) {
    return colorTransform != mat4() || needsToneMapping(sourceDataspace, destinationDataspace);
}

void SkiaGLRenderEngine::unbindExternalTextureBuffer(uint64_t bufferId) {
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    mTextureCache.erase(bufferId);
    mProtectedTextureCache.erase(bufferId);
}

sk_sp<SkShader> SkiaGLRenderEngine::createRuntimeEffectShader(sk_sp<SkShader> shader,
                                                              const LayerSettings* layer,
                                                              const DisplaySettings& display,
                                                              bool undoPremultipliedAlpha) {
    if (mUseColorManagement &&
        needsLinearEffect(layer->colorTransform, layer->sourceDataspace, display.outputDataspace)) {
        LinearEffect effect = LinearEffect{.inputDataspace = layer->sourceDataspace,
                                           .outputDataspace = display.outputDataspace,
                                           .undoPremultipliedAlpha = undoPremultipliedAlpha};

        auto effectIter = mRuntimeEffects.find(effect);
        sk_sp<SkRuntimeEffect> runtimeEffect = nullptr;
        if (effectIter == mRuntimeEffects.end()) {
            runtimeEffect = buildRuntimeEffect(effect);
            mRuntimeEffects.insert({effect, runtimeEffect});
        } else {
            runtimeEffect = effectIter->second;
        }
        return createLinearEffectShader(shader, effect, runtimeEffect, layer->colorTransform,
                                        display.maxLuminance,
                                        layer->source.buffer.maxMasteringLuminance,
                                        layer->source.buffer.maxContentLuminance);
    }
    return shader;
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

    auto grContext = mInProtectedContext ? mProtectedGrContext : mGrContext;
    auto& cache = mInProtectedContext ? mProtectedTextureCache : mTextureCache;
    AHardwareBuffer_Desc bufferDesc;
    AHardwareBuffer_describe(buffer->toAHardwareBuffer(), &bufferDesc);
    LOG_ALWAYS_FATAL_IF(!hasUsage(bufferDesc, AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE),
                        "missing usage");

    std::shared_ptr<AutoBackendTexture::LocalRef> surfaceTextureRef = nullptr;
    if (useFramebufferCache) {
        auto iter = cache.find(buffer->getId());
        if (iter != cache.end()) {
            ALOGV("Cache hit!");
            surfaceTextureRef = iter->second;
        }
    }

    if (surfaceTextureRef == nullptr || surfaceTextureRef->getTexture() == nullptr) {
        surfaceTextureRef = std::make_shared<AutoBackendTexture::LocalRef>();
        surfaceTextureRef->setTexture(
                new AutoBackendTexture(grContext.get(), buffer->toAHardwareBuffer(), true));
        if (useFramebufferCache) {
            ALOGD("Adding to cache");
            cache.insert({buffer->getId(), surfaceTextureRef});
        }
    }

    sk_sp<SkSurface> surface =
            surfaceTextureRef->getTexture()->getOrCreateSurface(mUseColorManagement
                                                                        ? display.outputDataspace
                                                                        : ui::Dataspace::UNKNOWN,
                                                                grContext.get());

    SkCanvas* canvas = mCapture->tryCapture(surface.get());
    if (canvas == nullptr) {
        ALOGE("Cannot acquire canvas from Skia.");
        return BAD_VALUE;
    }
    // Clear the entire canvas with a transparent black to prevent ghost images.
    canvas->clear(SK_ColorTRANSPARENT);
    canvas->save();

    if (mCapture->isCaptureRunning()) {
        // Record display settings when capture is running.
        std::stringstream displaySettings;
        PrintTo(display, &displaySettings);
        // Store the DisplaySettings in additional information.
        canvas->drawAnnotation(SkRect::MakeEmpty(), "DisplaySettings",
                               SkData::MakeWithCString(displaySettings.str().c_str()));
    }

    // Before doing any drawing, let's make sure that we'll start at the origin of the display.
    // Some displays don't start at 0,0 for example when we're mirroring the screen. Also, virtual
    // displays might have different scaling when compared to the physical screen.

    canvas->clipRect(getSkRect(display.physicalDisplay));
    canvas->translate(display.physicalDisplay.left, display.physicalDisplay.top);

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
    canvas->scale(scaleX, scaleY);

    // Canvas rotation is done by centering the clip window at the origin, rotating, translating
    // back so that the top left corner of the clip is at (0, 0).
    canvas->translate(rotatedClipWidth / 2, rotatedClipHeight / 2);
    canvas->rotate(toDegrees(display.orientation));
    canvas->translate(-clipWidth / 2, -clipHeight / 2);
    canvas->translate(-display.clip.left, -display.clip.top);

    // TODO: clearRegion was required for SurfaceView when a buffer is not yet available but the
    // view is still on-screen. The clear region could be re-specified as a black color layer,
    // however.
    if (!display.clearRegion.isEmpty()) {
        ATRACE_NAME("ClearRegion");
        size_t numRects = 0;
        Rect const* rects = display.clearRegion.getArray(&numRects);
        SkIRect skRects[numRects];
        for (int i = 0; i < numRects; ++i) {
            skRects[i] =
                    SkIRect::MakeLTRB(rects[i].left, rects[i].top, rects[i].right, rects[i].bottom);
        }
        SkRegion clearRegion;
        SkPaint paint;
        sk_sp<SkShader> shader =
                SkShaders::Color(SkColor4f{.fR = 0., .fG = 0., .fB = 0., .fA = 1.0},
                                 toSkColorSpace(mUseColorManagement ? display.outputDataspace
                                                                    : ui::Dataspace::UNKNOWN));
        paint.setShader(shader);
        clearRegion.setRects(skRects, numRects);
        canvas->drawRegion(clearRegion, paint);
    }

    for (const auto& layer : layers) {
        ATRACE_NAME("DrawLayer");
        canvas->save();

        if (mCapture->isCaptureRunning()) {
            // Record the name of the layer if the capture is running.
            std::stringstream layerSettings;
            PrintTo(*layer, &layerSettings);
            // Store the LayerSettings in additional information.
            canvas->drawAnnotation(SkRect::MakeEmpty(), layer->name.c_str(),
                                   SkData::MakeWithCString(layerSettings.str().c_str()));
        }

        // Layers have a local transform that should be applied to them
        canvas->concat(getSkM44(layer->geometry.positionTransform).asM33());

        SkPaint paint;
        const auto& bounds = layer->geometry.boundaries;
        const auto dest = getSkRect(bounds);
        const auto layerRect = canvas->getTotalMatrix().mapRect(dest);
        std::unordered_map<uint32_t, sk_sp<SkImage>> cachedBlurs;
        if (mBlurFilter) {
            if (layer->backgroundBlurRadius > 0) {
                ATRACE_NAME("BackgroundBlur");
                auto blurredSurface = mBlurFilter->generate(canvas, surface,
                                                            layer->backgroundBlurRadius, layerRect);
                cachedBlurs[layer->backgroundBlurRadius] = blurredSurface;

                drawBlurRegion(canvas, getBlurRegion(layer), layerRect, blurredSurface);
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

        const ui::Dataspace targetDataspace = mUseColorManagement
                ? (needsLinearEffect(layer->colorTransform, layer->sourceDataspace,
                                     display.outputDataspace)
                           // If we need to map to linear space, then mark the source image with the
                           // same colorspace as the destination surface so that Skia's color
                           // management is a no-op.
                           ? display.outputDataspace
                           : layer->sourceDataspace)
                : ui::Dataspace::UNKNOWN;

        if (layer->source.buffer.buffer) {
            ATRACE_NAME("DrawImage");
            const auto& item = layer->source.buffer;
            std::shared_ptr<AutoBackendTexture::LocalRef> imageTextureRef = nullptr;
            auto iter = mTextureCache.find(item.buffer->getId());
            if (iter != mTextureCache.end()) {
                imageTextureRef = iter->second;
            } else {
                imageTextureRef = std::make_shared<AutoBackendTexture::LocalRef>();
                imageTextureRef->setTexture(new AutoBackendTexture(grContext.get(),
                                                                   item.buffer->toAHardwareBuffer(),
                                                                   false));
                mTextureCache.insert({item.buffer->getId(), imageTextureRef});
            }

            sk_sp<SkImage> image =
                    imageTextureRef->getTexture()->makeImage(targetDataspace,
                                                             item.usePremultipliedAlpha
                                                                     ? kPremul_SkAlphaType
                                                                     : kUnpremul_SkAlphaType,
                                                             grContext.get());

            auto texMatrix = getSkM44(item.textureTransform).asM33();
            // textureTansform was intended to be passed directly into a shader, so when
            // building the total matrix with the textureTransform we need to first
            // normalize it, then apply the textureTransform, then scale back up.
            texMatrix.preScale(1.0f / bounds.getWidth(), 1.0f / bounds.getHeight());
            texMatrix.postScale(image->width(), image->height());

            SkMatrix matrix;
            if (!texMatrix.invert(&matrix)) {
                matrix = texMatrix;
            }
            // The shader does not respect the translation, so we add it to the texture
            // transform for the SkImage. This will make sure that the correct layer contents
            // are drawn in the correct part of the screen.
            matrix.postTranslate(layer->geometry.boundaries.left, layer->geometry.boundaries.top);

            sk_sp<SkShader> shader;

            if (layer->source.buffer.useTextureFiltering) {
                shader = image->makeShader(SkTileMode::kClamp, SkTileMode::kClamp,
                                           SkSamplingOptions(
                                                   {SkFilterMode::kLinear, SkMipmapMode::kNone}),
                                           &matrix);
            } else {
                shader = image->makeShader(SkSamplingOptions(), matrix);
            }

            // Handle opaque images - it's a little nonstandard how we do this.
            // Fundamentally we need to support SurfaceControl.Builder#setOpaque:
            // https://developer.android.com/reference/android/view/SurfaceControl.Builder#setOpaque(boolean)
            // The important language is that when isOpaque is set, opacity is not sampled from the
            // alpha channel, but blending may still be supported on a transaction via setAlpha. So,
            // here's the conundrum:
            // 1. We can't force the SkImage alpha type to kOpaque_SkAlphaType, because it's treated
            // as an internal hint - composition is undefined when there are alpha bits present.
            // 2. We can try to lie about the pixel layout, but that only works for RGBA8888
            // buffers, i.e., treating them as RGBx8888 instead. But we can't do the same for
            // RGBA1010102 because RGBx1010102 is not supported as a pixel layout for SkImages. It's
            // also not clear what to use for F16 either, and lying about the pixel layout is a bit
            // of a hack anyways.
            // 3. We can't change the blendmode to src, because while this satisfies the requirement
            // for ignoring the alpha channel, it doesn't quite satisfy the blending requirement
            // because src always clobbers the destination content.
            //
            // So, what we do here instead is an additive blend mode where we compose the input
            // image with a solid black. This might need to be reassess if this does not support
            // FP16 incredibly well, but FP16 end-to-end isn't well supported anyway at the moment.
            if (item.isOpaque) {
                shader = SkShaders::Blend(SkBlendMode::kPlus, shader,
                                          SkShaders::Color(SkColors::kBlack,
                                                           toSkColorSpace(targetDataspace)));
            }

            paint.setShader(
                    createRuntimeEffectShader(shader, layer, display,
                                              !item.isOpaque && item.usePremultipliedAlpha));
            paint.setAlphaf(layer->alpha);
        } else {
            ATRACE_NAME("DrawColor");
            const auto color = layer->source.solidColor;
            sk_sp<SkShader> shader = SkShaders::Color(SkColor4f{.fR = color.r,
                                                                .fG = color.g,
                                                                .fB = color.b,
                                                                .fA = layer->alpha},
                                                      toSkColorSpace(targetDataspace));
            paint.setShader(createRuntimeEffectShader(shader, layer, display,
                                                      /* undoPremultipliedAlpha */ false));
        }

        sk_sp<SkColorFilter> filter =
                SkColorFilters::Matrix(toSkColorMatrix(display.colorTransform));

        paint.setColorFilter(filter);

        for (const auto effectRegion : layer->blurRegions) {
            drawBlurRegion(canvas, effectRegion, layerRect, cachedBlurs[effectRegion.blurRadius]);
        }

        if (layer->shadow.length > 0) {
            const auto rect = layer->geometry.roundedCornersRadius > 0
                    ? getSkRect(layer->geometry.roundedCornersCrop)
                    : dest;
            drawShadow(canvas, rect, layer->geometry.roundedCornersRadius, layer->shadow);
        } else {
            // Shadows are assumed to live only on their own layer - it's not valid
            // to draw the boundary retangles when there is already a caster shadow
            // TODO(b/175915334): consider relaxing this restriction to enable more flexible
            // composition - using a well-defined invalid color is long-term less error-prone.
            // Push the clipRRect onto the clip stack. Draw the image. Pop the clip.
            if (layer->geometry.roundedCornersRadius > 0) {
                canvas->clipRRect(getRoundedRect(layer), true);
            }
            canvas->drawRect(dest, paint);
        }
        canvas->restore();
    }
    canvas->restore();
    mCapture->endCapture();
    {
        ATRACE_NAME("flush surface");
        surface->flush();
    }

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
    bool success = grContext->submit(requireSync);
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

inline BlurRegion SkiaGLRenderEngine::getBlurRegion(const LayerSettings* layer) {
    const auto rect = getSkRect(layer->geometry.boundaries);
    const auto cornersRadius = layer->geometry.roundedCornersRadius;
    return BlurRegion{.blurRadius = static_cast<uint32_t>(layer->backgroundBlurRadius),
                      .cornerRadiusTL = cornersRadius,
                      .cornerRadiusTR = cornersRadius,
                      .cornerRadiusBL = cornersRadius,
                      .cornerRadiusBR = cornersRadius,
                      .alpha = 1,
                      .left = static_cast<int>(rect.fLeft),
                      .top = static_cast<int>(rect.fTop),
                      .right = static_cast<int>(rect.fRight),
                      .bottom = static_cast<int>(rect.fBottom)};
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
                                        const SkRect& layerRect, sk_sp<SkImage> blurredImage) {
    ATRACE_CALL();

    SkPaint paint;
    paint.setAlpha(static_cast<int>(effectRegion.alpha * 255));
    const auto matrix = getBlurShaderTransform(canvas, layerRect);
    SkSamplingOptions linearSampling(SkFilterMode::kLinear, SkMipmapMode::kNone);
    paint.setShader(blurredImage->makeShader(SkTileMode::kClamp, SkTileMode::kClamp, linearSampling,
                                             &matrix));

    auto rect = SkRect::MakeLTRB(effectRegion.left, effectRegion.top, effectRegion.right,
                                 effectRegion.bottom);

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

SkMatrix SkiaGLRenderEngine::getBlurShaderTransform(const SkCanvas* canvas,
                                                    const SkRect& layerRect) {
    // 1. Apply the blur shader matrix, which scales up the blured surface to its real size
    auto matrix = mBlurFilter->getShaderMatrix();
    // 2. Since the blurred surface has the size of the layer, we align it with the
    // top left corner of the layer position.
    matrix.postConcat(SkMatrix::Translate(layerRect.fLeft, layerRect.fTop));
    // 3. Finally, apply the inverse canvas matrix. The snapshot made in the BlurFilter is in the
    // original surface orientation. The inverse matrix has to be applied to align the blur
    // surface with the current orientation/position of the canvas.
    SkMatrix drawInverse;
    if (canvas->getTotalMatrix().invert(&drawInverse)) {
        matrix.postConcat(drawInverse);
    }

    return matrix;
}

EGLContext SkiaGLRenderEngine::createEglContext(EGLDisplay display, EGLConfig config,
                                                EGLContext shareContext,
                                                std::optional<ContextPriority> contextPriority,
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
    if (contextPriority) {
        contextAttributes.push_back(EGL_CONTEXT_PRIORITY_LEVEL_IMG);
        switch (*contextPriority) {
            case ContextPriority::REALTIME:
                contextAttributes.push_back(EGL_CONTEXT_PRIORITY_REALTIME_NV);
                break;
            case ContextPriority::MEDIUM:
                contextAttributes.push_back(EGL_CONTEXT_PRIORITY_MEDIUM_IMG);
                break;
            case ContextPriority::LOW:
                contextAttributes.push_back(EGL_CONTEXT_PRIORITY_LOW_IMG);
                break;
            case ContextPriority::HIGH:
            default:
                contextAttributes.push_back(EGL_CONTEXT_PRIORITY_HIGH_IMG);
                break;
        }
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

std::optional<RenderEngine::ContextPriority> SkiaGLRenderEngine::createContextPriority(
        const RenderEngineCreationArgs& args) {
    if (!gl::GLExtensions::getInstance().hasContextPriority()) {
        return std::nullopt;
    }

    switch (args.contextPriority) {
        case RenderEngine::ContextPriority::REALTIME:
            if (gl::GLExtensions::getInstance().hasRealtimePriority()) {
                return RenderEngine::ContextPriority::REALTIME;
            } else {
                ALOGI("Realtime priority unsupported, degrading gracefully to high priority");
                return RenderEngine::ContextPriority::HIGH;
            }
        case RenderEngine::ContextPriority::HIGH:
        case RenderEngine::ContextPriority::MEDIUM:
        case RenderEngine::ContextPriority::LOW:
            return args.contextPriority;
        default:
            return std::nullopt;
    }
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

void SkiaGLRenderEngine::cleanFramebufferCache() {}

int SkiaGLRenderEngine::getContextPriority() {
    int value;
    eglQueryContext(mEGLDisplay, mEGLContext, EGL_CONTEXT_PRIORITY_LEVEL_IMG, &value);
    return value;
}

} // namespace skia
} // namespace renderengine
} // namespace android
