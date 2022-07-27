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
#include <android-base/stringprintf.h>
#include <gl/GrGLInterface.h>
#include <gui/TraceUtils.h>
#include <sync/sync.h>
#include <ui/DebugUtils.h>
#include <utils/Trace.h>

#include <cmath>
#include <cstdint>
#include <memory>
#include <numeric>

#include "../gl/GLExtensions.h"
#include "log/log_main.h"

bool checkGlError(const char* op, int lineNumber);

namespace android {
namespace renderengine {
namespace skia {

using base::StringAppendF;

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
    engine->ensureGrContextsCreated();

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
      : SkiaRenderEngine(args.renderEngineType,
                         static_cast<PixelFormat>(args.pixelFormat),
                         args.useColorManagement, args.supportsBackgroundBlur),
        mEGLDisplay(display),
        mEGLContext(ctxt),
        mPlaceholderSurface(placeholder),
        mProtectedEGLContext(protectedContext),
        mProtectedPlaceholderSurface(protectedPlaceholder) { }

SkiaGLRenderEngine::~SkiaGLRenderEngine() {
    finishRenderingAndAbandonContext();
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

SkiaRenderEngine::Contexts SkiaGLRenderEngine::createDirectContexts(
    const GrContextOptions& options) {

    LOG_ALWAYS_FATAL_IF(isProtected(),
                        "Cannot setup contexts while already in protected mode");

    sk_sp<const GrGLInterface> glInterface = GrGLMakeNativeInterface();

    LOG_ALWAYS_FATAL_IF(!glInterface.get(), "GrGLMakeNativeInterface() failed");

    SkiaRenderEngine::Contexts contexts;
    contexts.first = GrDirectContext::MakeGL(glInterface, options);
    if (supportsProtectedContentImpl()) {
        useProtectedContextImpl(GrProtected::kYes);
        contexts.second = GrDirectContext::MakeGL(glInterface, options);
        useProtectedContextImpl(GrProtected::kNo);
    }

    return contexts;
}

bool SkiaGLRenderEngine::supportsProtectedContentImpl() const {
    return mProtectedEGLContext != EGL_NO_CONTEXT;
}

bool SkiaGLRenderEngine::useProtectedContextImpl(GrProtected isProtected) {
    const EGLSurface surface =
        (isProtected == GrProtected::kYes) ?
        mProtectedPlaceholderSurface : mPlaceholderSurface;
    const EGLContext context = (isProtected == GrProtected::kYes) ?
        mProtectedEGLContext : mEGLContext;

    return eglMakeCurrent(mEGLDisplay, surface, surface, context) == EGL_TRUE;
}

void SkiaGLRenderEngine::waitFence(GrDirectContext*, base::borrowed_fd fenceFd) {
    if (fenceFd.get() >= 0 && !waitGpuFence(fenceFd)) {
        ATRACE_NAME("SkiaGLRenderEngine::waitFence");
        sync_wait(fenceFd.get(), -1);
    }
}

base::unique_fd SkiaGLRenderEngine::flushAndSubmit(GrDirectContext* grContext) {
    base::unique_fd drawFence = flush();

    bool requireSync = drawFence.get() < 0;
    if (requireSync) {
        ATRACE_BEGIN("Submit(sync=true)");
    } else {
        ATRACE_BEGIN("Submit(sync=false)");
    }
    bool success = grContext->submit(requireSync);
    ATRACE_END();
    if (!success) {
        ALOGE("Failed to flush RenderEngine commands");
        // Chances are, something illegal happened (Skia's internal GPU object
        // doesn't exist, or the context was abandoned).
        return drawFence;
    }

    return drawFence;
}

bool SkiaGLRenderEngine::waitGpuFence(base::borrowed_fd fenceFd) {
    if (!gl::GLExtensions::getInstance().hasNativeFenceSync() ||
        !gl::GLExtensions::getInstance().hasWaitSync()) {
        return false;
    }

    // Duplicate the fence for passing to eglCreateSyncKHR.
    base::unique_fd fenceDup(dup(fenceFd.get()));
    if (fenceDup.get() < 0) {
        ALOGE("failed to create duplicate fence fd: %d", fenceDup.get());
        return false;
    }

    // release the fd and transfer the ownership to EGLSync
    EGLint attribs[] = {EGL_SYNC_NATIVE_FENCE_FD_ANDROID, fenceDup.release(), EGL_NONE};
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

int SkiaGLRenderEngine::getContextPriority() {
    int value;
    eglQueryContext(mEGLDisplay, mEGLContext, EGL_CONTEXT_PRIORITY_LEVEL_IMG, &value);
    return value;
}

void SkiaGLRenderEngine::appendBackendSpecificInfoToDump(std::string& result) {
    const gl::GLExtensions& extensions = gl::GLExtensions::getInstance();
    StringAppendF(&result, "\n ------------RE GLES------------\n");
    StringAppendF(&result, "EGL implementation : %s\n", extensions.getEGLVersion());
    StringAppendF(&result, "%s\n", extensions.getEGLExtensions());
    StringAppendF(&result, "GLES: %s, %s, %s\n", extensions.getVendor(), extensions.getRenderer(),
                  extensions.getVersion());
    StringAppendF(&result, "%s\n", extensions.getExtensions());
}

} // namespace skia
} // namespace renderengine
} // namespace android
