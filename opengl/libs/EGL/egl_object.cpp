/*
 ** Copyright 2007, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#include "egl_object.h"

#include <sstream>


// ----------------------------------------------------------------------------
namespace android {
// ----------------------------------------------------------------------------

egl_object_t::egl_object_t(egl_display_t* disp) :
    display(disp), count(1) {
    // NOTE: this does an implicit incRef
    display->addObject(this);
}

egl_object_t::~egl_object_t() {
}

void egl_object_t::terminate() {
    // this marks the object as "terminated"
    display->removeObject(this);
    if (decRef() == 1) {
        // shouldn't happen because this is called from LocalRef
        ALOGE("egl_object_t::terminate() removed the last reference!");
    }
}

void egl_object_t::destroy() {
    if (decRef() == 1) {
        delete this;
    }
}

bool egl_object_t::get(egl_display_t const* display, egl_object_t* object) {
    // used by LocalRef, this does an incRef() atomically with
    // checking that the object is valid.
    return display->getObject(object);
}

// ----------------------------------------------------------------------------

egl_surface_t::egl_surface_t(egl_display_t* dpy, EGLConfig config, EGLNativeWindowType win,
                             EGLSurface surface, EGLint colorSpace, egl_connection_t const* cnx)
      : egl_object_t(dpy),
        surface(surface),
        config(config),
        win(win),
        cnx(cnx),
        connected(true),
        colorSpace(colorSpace) {
    if (win) {
        win->incStrong(this);
    }
}

egl_surface_t::~egl_surface_t() {
    if (win != NULL) {
        disconnect();
        win->decStrong(this);
    }
}

void egl_surface_t::disconnect() {
    if (win != NULL && connected) {
        native_window_set_buffers_format(win, 0);
        if (native_window_api_disconnect(win, NATIVE_WINDOW_API_EGL)) {
            ALOGW("EGLNativeWindowType %p disconnect failed", win);
        }
        connected = false;
    }
}

void egl_surface_t::terminate() {
    disconnect();
    egl_object_t::terminate();
}

// ----------------------------------------------------------------------------

egl_context_t::egl_context_t(EGLDisplay dpy, EGLContext context, EGLConfig config,
        egl_connection_t const* cnx, int version) :
    egl_object_t(get_display_nowake(dpy)), dpy(dpy), context(context),
            config(config), read(0), draw(0), cnx(cnx), version(version) {
}

void egl_context_t::onLooseCurrent() {
    read = NULL;
    draw = NULL;
}

void egl_context_t::onMakeCurrent(EGLSurface draw, EGLSurface read) {
    this->read = read;
    this->draw = draw;

    /*
     * Here we cache the GL_EXTENSIONS string for this context and we
     * add the extensions always handled by the wrapper
     */

    if (gl_extensions.empty()) {
        // call the implementation's glGetString(GL_EXTENSIONS)
        const char* exts = (const char *)gEGLImpl.hooks[version]->gl.glGetString(GL_EXTENSIONS);
        // In an opengl 3.0+ context, GL_EXTENSIONS is not valid for glGetString
        if (exts == NULL) {
            gEGLImpl.hooks[version]->gl.glGetError();
            return;
        }
        gl_extensions = exts;
        if (gl_extensions.find("GL_EXT_debug_marker") == std::string::npos) {
            gl_extensions.insert(0, "GL_EXT_debug_marker ");
        }

        // tokenize the supported extensions for the glGetStringi() wrapper
        std::stringstream ss;
        std::string str;
        ss << gl_extensions;
        while (ss >> str) {
            tokenized_gl_extensions.push_back(str);
        }
    }
}

// ----------------------------------------------------------------------------
}; // namespace android
// ----------------------------------------------------------------------------
