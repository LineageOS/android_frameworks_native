/*
 ** Copyright 2011, The Android Open Source Project
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

// #define LOG_NDEBUG 0

#include "egl_cache.h"

#include <android-base/properties.h>
#include <inttypes.h>
#include <log/log.h>
#include <private/EGL/cache.h>
#include <unistd.h>

#include <thread>

#include "../egl_impl.h"
#include "egl_display.h"

// Monolithic cache size limits.
static const size_t kMaxMonolithicKeySize = 12 * 1024;
static const size_t kMaxMonolithicValueSize = 64 * 1024;
static const size_t kMaxMonolithicTotalSize = 2 * 1024 * 1024;

// The time in seconds to wait before saving newly inserted monolithic cache entries.
static const unsigned int kDeferredMonolithicSaveDelay = 4;

// Multifile cache size limits
constexpr uint32_t kMaxMultifileKeySize = 1 * 1024 * 1024;
constexpr uint32_t kMaxMultifileValueSize = 8 * 1024 * 1024;
constexpr uint32_t kMaxMultifileTotalSize = 32 * 1024 * 1024;
constexpr uint32_t kMaxMultifileTotalEntries = 4 * 1024;

namespace android {

#define BC_EXT_STR "EGL_ANDROID_blob_cache"

// called from android_view_ThreadedRenderer.cpp
void egl_set_cache_filename(const char* filename) {
    egl_cache_t::get()->setCacheFilename(filename);
}

//
// Callback functions passed to EGL.
//
static void setBlob(const void* key, EGLsizeiANDROID keySize, const void* value,
                    EGLsizeiANDROID valueSize) {
    egl_cache_t::get()->setBlob(key, keySize, value, valueSize);
}

static EGLsizeiANDROID getBlob(const void* key, EGLsizeiANDROID keySize, void* value,
                               EGLsizeiANDROID valueSize) {
    return egl_cache_t::get()->getBlob(key, keySize, value, valueSize);
}

//
// egl_cache_t definition
//
egl_cache_t::egl_cache_t()
      : mInitialized(false), mMultifileMode(false), mCacheByteLimit(kMaxMonolithicTotalSize) {}

egl_cache_t::~egl_cache_t() {}

egl_cache_t egl_cache_t::sCache;

egl_cache_t* egl_cache_t::get() {
    return &sCache;
}

void egl_cache_t::initialize(egl_display_t* display) {
    std::lock_guard<std::mutex> lock(mMutex);

    egl_connection_t* const cnx = &gEGLImpl;
    if (display && cnx->dso && cnx->major >= 0 && cnx->minor >= 0) {
        const char* exts = display->disp.queryString.extensions;
        size_t bcExtLen = strlen(BC_EXT_STR);
        size_t extsLen = strlen(exts);
        bool equal = !strcmp(BC_EXT_STR, exts);
        bool atStart = !strncmp(BC_EXT_STR " ", exts, bcExtLen + 1);
        bool atEnd = (bcExtLen + 1) < extsLen &&
                !strcmp(" " BC_EXT_STR, exts + extsLen - (bcExtLen + 1));
        bool inMiddle = strstr(exts, " " BC_EXT_STR " ") != nullptr;
        if (equal || atStart || atEnd || inMiddle) {
            PFNEGLSETBLOBCACHEFUNCSANDROIDPROC eglSetBlobCacheFuncsANDROID;
            eglSetBlobCacheFuncsANDROID = reinterpret_cast<PFNEGLSETBLOBCACHEFUNCSANDROIDPROC>(
                    cnx->egl.eglGetProcAddress("eglSetBlobCacheFuncsANDROID"));
            if (eglSetBlobCacheFuncsANDROID == nullptr) {
                ALOGE("EGL_ANDROID_blob_cache advertised, "
                      "but unable to get eglSetBlobCacheFuncsANDROID");
                return;
            }

            eglSetBlobCacheFuncsANDROID(display->disp.dpy, android::setBlob, android::getBlob);
            EGLint err = cnx->egl.eglGetError();
            if (err != EGL_SUCCESS) {
                ALOGE("eglSetBlobCacheFuncsANDROID resulted in an error: "
                      "%#x",
                      err);
            }
        }
    }

    mInitialized = true;
}

void egl_cache_t::terminate() {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mBlobCache) {
        mBlobCache->writeToFile();
    }
    mBlobCache = nullptr;
    if (mMultifileBlobCache) {
        mMultifileBlobCache->finish();
    }
    mMultifileBlobCache = nullptr;
    mInitialized = false;
}

void egl_cache_t::setBlob(const void* key, EGLsizeiANDROID keySize, const void* value,
                          EGLsizeiANDROID valueSize) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (keySize < 0 || valueSize < 0) {
        ALOGW("EGL_ANDROID_blob_cache set: negative sizes are not allowed");
        return;
    }

    updateMode();

    if (mInitialized) {
        if (mMultifileMode) {
            MultifileBlobCache* mbc = getMultifileBlobCacheLocked();
            mbc->set(key, keySize, value, valueSize);
        } else {
            BlobCache* bc = getBlobCacheLocked();
            bc->set(key, keySize, value, valueSize);

            if (!mSavePending) {
                mSavePending = true;
                std::thread deferredSaveThread([this]() {
                    sleep(kDeferredMonolithicSaveDelay);
                    std::lock_guard<std::mutex> lock(mMutex);
                    if (mInitialized && mBlobCache) {
                        mBlobCache->writeToFile();
                    }
                    mSavePending = false;
                });
                deferredSaveThread.detach();
            }
        }
    }
}

EGLsizeiANDROID egl_cache_t::getBlob(const void* key, EGLsizeiANDROID keySize, void* value,
                                     EGLsizeiANDROID valueSize) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (keySize < 0 || valueSize < 0) {
        ALOGW("EGL_ANDROID_blob_cache get: negative sizes are not allowed");
        return 0;
    }

    updateMode();

    if (mInitialized) {
        if (mMultifileMode) {
            MultifileBlobCache* mbc = getMultifileBlobCacheLocked();
            return mbc->get(key, keySize, value, valueSize);
        } else {
            BlobCache* bc = getBlobCacheLocked();
            return bc->get(key, keySize, value, valueSize);
        }
    }

    return 0;
}

void egl_cache_t::setCacheMode(EGLCacheMode cacheMode) {
    mMultifileMode = (cacheMode == EGLCacheMode::Multifile);
}

void egl_cache_t::setCacheFilename(const char* filename) {
    std::lock_guard<std::mutex> lock(mMutex);
    mFilename = filename;
}

void egl_cache_t::setCacheLimit(int64_t cacheByteLimit) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (!mMultifileMode) {
        // If we're not in multifile mode, ensure the cache limit is only being lowered,
        // not increasing above the hard coded platform limit
        if (cacheByteLimit > kMaxMonolithicTotalSize) {
            return;
        }
    }

    mCacheByteLimit = cacheByteLimit;
}

size_t egl_cache_t::getCacheSize() {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mMultifileBlobCache) {
        return mMultifileBlobCache->getTotalSize();
    }
    if (mBlobCache) {
        return mBlobCache->getSize();
    }
    return 0;
}

void egl_cache_t::updateMode() {
    // We don't set the mode in the constructor because these checks have
    // a non-trivial cost, and not all processes that instantiate egl_cache_t
    // will use it.

    // If we've already set the mode, skip these checks
    static bool checked = false;
    if (checked) {
        return;
    }
    checked = true;

    // Check the device config to decide whether multifile should be used
    if (base::GetBoolProperty("ro.egl.blobcache.multifile", false)) {
        mMultifileMode = true;
        ALOGV("Using multifile EGL blobcache");
    }

    // Allow forcing the mode for debug purposes
    std::string mode = base::GetProperty("debug.egl.blobcache.multifile", "");
    if (mode == "true") {
        ALOGV("Forcing multifile cache due to debug.egl.blobcache.multifile == %s", mode.c_str());
        mMultifileMode = true;
    } else if (mode == "false") {
        ALOGV("Forcing monolithic cache due to debug.egl.blobcache.multifile == %s", mode.c_str());
        mMultifileMode = false;
    }

    if (mMultifileMode) {
        mCacheByteLimit = static_cast<size_t>(
                base::GetUintProperty<uint32_t>("ro.egl.blobcache.multifile_limit",
                                                kMaxMultifileTotalSize));

        // Check for a debug value
        int debugCacheSize = base::GetIntProperty("debug.egl.blobcache.multifile_limit", -1);
        if (debugCacheSize >= 0) {
            ALOGV("Overriding cache limit %zu with %i from debug.egl.blobcache.multifile_limit",
                  mCacheByteLimit, debugCacheSize);
            mCacheByteLimit = debugCacheSize;
        }

        ALOGV("Using multifile EGL blobcache limit of %zu bytes", mCacheByteLimit);
    }
}

BlobCache* egl_cache_t::getBlobCacheLocked() {
    if (mBlobCache == nullptr) {
        mBlobCache.reset(new FileBlobCache(kMaxMonolithicKeySize, kMaxMonolithicValueSize,
                                           mCacheByteLimit, mFilename));
    }
    return mBlobCache.get();
}

MultifileBlobCache* egl_cache_t::getMultifileBlobCacheLocked() {
    if (mMultifileBlobCache == nullptr) {
        mMultifileBlobCache.reset(new MultifileBlobCache(kMaxMultifileKeySize,
                                                         kMaxMultifileValueSize, mCacheByteLimit,
                                                         kMaxMultifileTotalEntries, mFilename));
    }
    return mMultifileBlobCache.get();
}

}; // namespace android
