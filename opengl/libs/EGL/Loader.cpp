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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <limits.h>
#include <unistd.h>

#include <cutils/log.h>
#include <cutils/properties.h>

#include <EGL/egl.h>

#include "egldefs.h"
#include "glestrace.h"
#include "hooks.h"
#include "Loader.h"

// ----------------------------------------------------------------------------
namespace android {
// ----------------------------------------------------------------------------


/*
 * EGL drivers are called
 * 
 * /system/lib/egl/lib{[EGL|GLESv1_CM|GLESv2] | GLES}_$TAG.so 
 * 
 */

ANDROID_SINGLETON_STATIC_INSTANCE( Loader )

/* This function is called to check whether we run inside the emulator,
 * and if this is the case whether GLES GPU emulation is supported.
 *
 * Returned values are:
 *  -1   -> not running inside the emulator
 *   0   -> running inside the emulator, but GPU emulation not supported
 *   1   -> running inside the emulator, GPU emulation is supported
 *          through the "emulation" config.
 */
static int
checkGlesEmulationStatus(void)
{
    /* We're going to check for the following kernel parameters:
     *
     *    qemu=1                      -> tells us that we run inside the emulator
     *    android.qemu.gles=<number>  -> tells us the GLES GPU emulation status
     *
     * Note that we will return <number> if we find it. This let us support
     * more additionnal emulation modes in the future.
     */
    char  prop[PROPERTY_VALUE_MAX];
    int   result = -1;

    /* First, check for qemu=1 */
    property_get("ro.kernel.qemu",prop,"0");
    if (atoi(prop) != 1)
        return -1;

    /* We are in the emulator, get GPU status value */
    property_get("ro.kernel.qemu.gles",prop,"0");
    return atoi(prop);
}

// ----------------------------------------------------------------------------

static char const * getProcessCmdline() {
    long pid = getpid();
    char procPath[128];
    snprintf(procPath, 128, "/proc/%ld/cmdline", pid);
    FILE * file = fopen(procPath, "r");
    if (file) {
        static char cmdline[256];
        char *str = fgets(cmdline, sizeof(cmdline) - 1, file);
        fclose(file);
        if (str) {
            return cmdline;
        }
    }
    return NULL;
}

// ----------------------------------------------------------------------------

Loader::driver_t::driver_t(void* gles) 
{
    dso[0] = gles;
    for (size_t i=1 ; i<NELEM(dso) ; i++)
        dso[i] = 0;
}

Loader::driver_t::~driver_t() 
{
    for (size_t i=0 ; i<NELEM(dso) ; i++) {
        if (dso[i]) {
            dlclose(dso[i]);
            dso[i] = 0;
        }
    }
}

status_t Loader::driver_t::set(void* hnd, int32_t api)
{
    switch (api) {
        case EGL:
            dso[0] = hnd;
            break;
        case GLESv1_CM:
            dso[1] = hnd;
            break;
        case GLESv2:
            dso[2] = hnd;
            break;
        default:
            return BAD_INDEX;
    }
    return NO_ERROR;
}

// ----------------------------------------------------------------------------

Loader::Loader()
{
    char line[256];
    char tag[256];

    /* Special case for GLES emulation */
    if (checkGlesEmulationStatus() == 0) {
        ALOGD("Emulator without GPU support detected. "
              "Fallback to software renderer.");
        mDriverTag.setTo("android");
        return;
    }

    /* Otherwise, use egl.cfg */
    FILE* cfg = fopen("/system/lib/egl/egl.cfg", "r");
    if (cfg == NULL) {
        // default config
        ALOGD("egl.cfg not found, using default config");
        mDriverTag.setTo("android");
    } else {
        while (fgets(line, 256, cfg)) {
            int dpy, impl;
            if (sscanf(line, "%u %u %s", &dpy, &impl, tag) == 3) {
                //ALOGD(">>> %u %u %s", dpy, impl, tag);
                // We only load the h/w accelerated implementation
                if (tag != String8("android")) {
                    mDriverTag = tag;
                }
            }
        }
        fclose(cfg);
    }
}

Loader::~Loader()
{
    GLTrace_stop();
}

void* Loader::open(egl_connection_t* cnx)
{
    void* dso;
    driver_t* hnd = 0;
    
    char const* tag = mDriverTag.string();
    if (tag) {
        dso = load_driver("GLES", tag, cnx, EGL | GLESv1_CM | GLESv2);
        if (dso) {
            hnd = new driver_t(dso);
        } else {
            // Always load EGL first
            dso = load_driver("EGL", tag, cnx, EGL);
            if (dso) {
                hnd = new driver_t(dso);
                // TODO: make this more automated
                hnd->set( load_driver("GLESv1_CM", tag, cnx, GLESv1_CM), GLESv1_CM );
                hnd->set( load_driver("GLESv2",    tag, cnx, GLESv2),    GLESv2 );
            }
        }
    }

    LOG_FATAL_IF(!index && !hnd,
            "couldn't find the default OpenGL ES implementation "
            "for default display");
    
    return (void*)hnd;
}

status_t Loader::close(void* driver)
{
    driver_t* hnd = (driver_t*)driver;
    delete hnd;
    return NO_ERROR;
}

void Loader::init_api(void* dso, 
        char const * const * api, 
        __eglMustCastToProperFunctionPointerType* curr, 
        getProcAddressType getProcAddress) 
{
    const ssize_t SIZE = 256;
    char scrap[SIZE];
    while (*api) {
        char const * name = *api;
        __eglMustCastToProperFunctionPointerType f = 
            (__eglMustCastToProperFunctionPointerType)dlsym(dso, name);
        if (f == NULL) {
            // couldn't find the entry-point, use eglGetProcAddress()
            f = getProcAddress(name);
        }
        if (f == NULL) {
            // Try without the OES postfix
            ssize_t index = ssize_t(strlen(name)) - 3;
            if ((index>0 && (index<SIZE-1)) && (!strcmp(name+index, "OES"))) {
                strncpy(scrap, name, index);
                scrap[index] = 0;
                f = (__eglMustCastToProperFunctionPointerType)dlsym(dso, scrap);
                //ALOGD_IF(f, "found <%s> instead", scrap);
            }
        }
        if (f == NULL) {
            // Try with the OES postfix
            ssize_t index = ssize_t(strlen(name)) - 3;
            if (index>0 && strcmp(name+index, "OES")) {
                snprintf(scrap, SIZE, "%sOES", name);
                f = (__eglMustCastToProperFunctionPointerType)dlsym(dso, scrap);
                //ALOGD_IF(f, "found <%s> instead", scrap);
            }
        }
        if (f == NULL) {
            //ALOGD("%s", name);
            f = (__eglMustCastToProperFunctionPointerType)gl_unimplemented;

            /*
             * GL_EXT_debug_label is special, we always report it as
             * supported, it's handled by GLES_trace. If GLES_trace is not
             * enabled, then these are no-ops.
             */
            if (!strcmp(name, "glInsertEventMarkerEXT")) {
                f = (__eglMustCastToProperFunctionPointerType)gl_noop;
            } else if (!strcmp(name, "glPushGroupMarkerEXT")) {
                f = (__eglMustCastToProperFunctionPointerType)gl_noop;
            } else if (!strcmp(name, "glPopGroupMarkerEXT")) {
                f = (__eglMustCastToProperFunctionPointerType)gl_noop;
            }
        }
        *curr++ = f;
        api++;
    }
}

void *Loader::load_driver(const char* kind, const char *tag,
        egl_connection_t* cnx, uint32_t mask)
{
    char driver_absolute_path[PATH_MAX];
    const char* const search1 = "/vendor/lib/egl/lib%s_%s.so";
    const char* const search2 = "/system/lib/egl/lib%s_%s.so";

    snprintf(driver_absolute_path, PATH_MAX, search1, kind, tag);
    if (access(driver_absolute_path, R_OK)) {
        snprintf(driver_absolute_path, PATH_MAX, search2, kind, tag);
        if (access(driver_absolute_path, R_OK)) {
            // this happens often, we don't want to log an error
            return 0;
        }
    }

    void* dso = dlopen(driver_absolute_path, RTLD_NOW | RTLD_LOCAL);
    if (dso == 0) {
        const char* err = dlerror();
        ALOGE("load_driver(%s): %s", driver_absolute_path, err?err:"unknown");
        return 0;
    }

    ALOGD("loaded %s", driver_absolute_path);

    if (mask & EGL) {
        getProcAddress = (getProcAddressType)dlsym(dso, "eglGetProcAddress");

        ALOGE_IF(!getProcAddress, 
                "can't find eglGetProcAddress() in %s", driver_absolute_path);

#ifdef SYSTEMUI_PBSIZE_HACK
#warning "SYSTEMUI_PBSIZE_HACK enabled"
        /*
         * TODO: replace SYSTEMUI_PBSIZE_HACK by something less hackish
         *
         * Here we adjust the PB size from its default value to 512KB which
         * is the minimum acceptable for the systemui process.
         * We do this on low-end devices only because it allows us to enable
         * h/w acceleration in the systemui process while keeping the
         * memory usage down.
         *
         * Obviously, this is the wrong place and wrong way to make this
         * adjustment, but at the time of this writing this was the safest
         * solution.
         *
         * Not all devices utilize the vendor dir correctly, so we set
         * it up to look for libIMGegl.so in both vendor/lib and system/lib.
         */
        const char *cmdline = getProcessCmdline();
        if (strstr(cmdline, "systemui")) {
            char *imgegl_path;
            if (access("/vendor/lib/libIMGegl.so", F_OK) == 0) {
                imgegl_path = "/vendor/lib/libIMGegl.so";
            } else {
                imgegl_path = "/system/lib/libIMGegl.so";
            }
            void *imgegl = dlopen(imgegl_path, RTLD_LAZY);
            if (imgegl) {
                unsigned int *PVRDefaultPBS =
                        (unsigned int *)dlsym(imgegl, "PVRDefaultPBS");
                if (PVRDefaultPBS) {
                    ALOGD("setting default PBS to 512KB, was %d KB", *PVRDefaultPBS / 1024);
                    *PVRDefaultPBS = 512*1024;
                }
            }
        }
#endif

        egl_t* egl = &cnx->egl;
        __eglMustCastToProperFunctionPointerType* curr =
            (__eglMustCastToProperFunctionPointerType*)egl;
        char const * const * api = egl_names;
        while (*api) {
            char const * name = *api;
            __eglMustCastToProperFunctionPointerType f = 
                (__eglMustCastToProperFunctionPointerType)dlsym(dso, name);
            if (f == NULL) {
                // couldn't find the entry-point, use eglGetProcAddress()
                f = getProcAddress(name);
                if (f == NULL) {
                    f = (__eglMustCastToProperFunctionPointerType)0;
                }
            }
            *curr++ = f;
            api++;
        }
    }
    
    if (mask & GLESv1_CM) {
        init_api(dso, gl_names,
            (__eglMustCastToProperFunctionPointerType*)
                &cnx->hooks[egl_connection_t::GLESv1_INDEX]->gl,
            getProcAddress);
    }

    if (mask & GLESv2) {
      init_api(dso, gl_names,
            (__eglMustCastToProperFunctionPointerType*)
                &cnx->hooks[egl_connection_t::GLESv2_INDEX]->gl,
            getProcAddress);
    }
    
    return dso;
}

// ----------------------------------------------------------------------------
}; // namespace android
// ----------------------------------------------------------------------------
