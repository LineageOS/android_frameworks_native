/*
 ** Copyright 2011-2017, The Android Open Source Project
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

#include "egl_cache.h"

#include "../egl_impl.h"

#include "egl_display.h"

#include <private/EGL/cache.h>

#include <unistd.h>

#include <memory>
#include <thread>
#include <utility>

#include <log/log.h>

#ifndef MAX_EGL_CACHE_KEY_SIZE
#define MAX_EGL_CACHE_KEY_SIZE (12 * 1024)
#endif

#ifndef MAX_EGL_CACHE_ENTRY_SIZE
#define MAX_EGL_CACHE_ENTRY_SIZE (64 * 1024)
#endif

#ifndef MAX_EGL_CACHE_SIZE
#define MAX_EGL_CACHE_SIZE (2 * 1024 * 1024)
#endif

static const size_t maxKeySize = MAX_EGL_CACHE_KEY_SIZE;
static const size_t maxValueSize = MAX_EGL_CACHE_ENTRY_SIZE;
static const size_t maxTotalSize = MAX_EGL_CACHE_SIZE;

// HashTable initial size
// TODO: currently unused for mPendingWrites
static const size_t hashTableInitSize = 400;

// ----------------------------------------------------------------------------
namespace android {
// ----------------------------------------------------------------------------

#define BC_EXT_STR "EGL_ANDROID_blob_cache"

// called from android_view_ThreadedRenderer.cpp
void egl_set_cache_filename(const char* filename) {
    egl_cache_t::get()->setCacheFilename(filename);
}

//
// Callback functions passed to EGL.
//
static void setBlob(const void* key, EGLsizeiANDROID keySize,
        const void* value, EGLsizeiANDROID valueSize) {
    egl_cache_t::get()->setBlob(key, keySize, value, valueSize);
}

static EGLsizeiANDROID getBlob(const void* key, EGLsizeiANDROID keySize,
        void* value, EGLsizeiANDROID valueSize) {
    return egl_cache_t::get()->getBlob(key, keySize, value, valueSize);
}

//
// egl_cache_t definition
//
egl_cache_t::egl_cache_t() :
        mInitialized(false),
        READ_ONLY(false),
        mYieldBlobCache(false) {
}

egl_cache_t::~egl_cache_t() {
}

egl_cache_t egl_cache_t::sCache;

egl_cache_t* egl_cache_t::get() {
    return &sCache;
}

void egl_cache_t::initialize(egl_display_t *display) {
    std::lock_guard<std::mutex> lock(mMutex);

    egl_connection_t* const cnx = &gEGLImpl;
    if (cnx->dso && cnx->major >= 0 && cnx->minor >= 0) {
        const char* exts = display->disp.queryString.extensions;
        size_t bcExtLen = strlen(BC_EXT_STR);
        size_t extsLen = strlen(exts);
        bool equal = !strcmp(BC_EXT_STR, exts);
        bool atStart = !strncmp(BC_EXT_STR " ", exts, bcExtLen+1);
        bool atEnd = (bcExtLen+1) < extsLen &&
                !strcmp(" " BC_EXT_STR, exts + extsLen - (bcExtLen+1));
        bool inMiddle = strstr(exts, " " BC_EXT_STR " ") != nullptr;
        if (equal || atStart || atEnd || inMiddle) {
            PFNEGLSETBLOBCACHEFUNCSANDROIDPROC eglSetBlobCacheFuncsANDROID;
            eglSetBlobCacheFuncsANDROID =
                    reinterpret_cast<PFNEGLSETBLOBCACHEFUNCSANDROIDPROC>(
                            cnx->egl.eglGetProcAddress(
                                    "eglSetBlobCacheFuncsANDROID"));
            if (eglSetBlobCacheFuncsANDROID == NULL) {
                ALOGE("EGL_ANDROID_blob_cache advertised, "
                        "but unable to get eglSetBlobCacheFuncsANDROID");
                return;
            }

            eglSetBlobCacheFuncsANDROID(display->disp.dpy,
                    android::setBlob, android::getBlob);
            EGLint err = cnx->egl.eglGetError();
            if (err != EGL_SUCCESS) {
                ALOGE("eglSetBlobCacheFuncsANDROID resulted in an error: "
                        "%#x", err);
            }
        }
    }

    mInitialized = true;
}

void egl_cache_t::terminate() {
    // Make sure the deferredSaveThread finishes before we destroy mBlobCache
    saveThreadCheckMutex.lock();
    if (isSaveThreadRunning) {
        saveThreadCheckMutex.unlock();
        // signal thread to exit
        saveThreadExitMutex.lock();
        saveThreadExit = true;
        saveThreadExitMutex.unlock();
        // wait for thread to finish
        mCondition.notify_one();
        pthread_join(deferredSaveThread, NULL);
    } else {
        saveThreadCheckMutex.unlock();
    }

    std::lock_guard<std::mutex> lock(mMutex);

    readOnlyMutex.lock();
    READ_ONLY = true;
    readOnlyMutex.unlock();

    if (mBlobCache) {
        mBlobCache->writeToFile();
    }

    readOnlyMutex.lock();
    READ_ONLY = false;
    readOnlyMutex.unlock();

    // clear the pendingWritesMutex
    // this shouldn't ideally be needed since
    // the deferredSaveThread should clear it
    mPendingWritesMutex.lock();
    mPendingWrites.clear();
    mPendingWritesMutex.unlock();

    mBlobCache = nullptr;
}

void egl_cache_t::setBlob(const void* key, EGLsizeiANDROID keySize,
        const void* value, EGLsizeiANDROID valueSize) {

    if (keySize < 0 || valueSize < 0) {
        ALOGW("EGL_ANDROID_blob_cache set: negative sizes are not allowed");
        return;
    }

    if (!mInitialized) {
        return;
    }

    mPendingWritesMutex.lock();
    std::shared_ptr<Blob> blobKey = std::make_shared<Blob>(key, keySize, true);
    std::shared_ptr<Blob> blobValue= std::make_shared<Blob>(value, valueSize, true);
    blobEntry entry(blobKey, blobValue);

    mPendingWrites[blobKey] = entry;
    mPendingWritesMutex.unlock();

    // start thread to write to BlobCache and then to disk
    // make sure there is only one thread running at a time
    std::unique_lock<std::mutex> lock(saveThreadCheckMutex);
    if (!isSaveThreadRunning) {
        int rt;
        rt = pthread_create(&deferredSaveThread, NULL, saveThread, NULL);
        if (rt) {
            ALOGW("EGL_ANDROID_blob_cache set: could not create %s thread", deferredSaveThreadName);
            return;
        }

        rt = pthread_setname_np(deferredSaveThread, deferredSaveThreadName);
        if (rt) {
            ALOGW("EGL_ANDROID_blob_cache set: could not name %s thread", deferredSaveThreadName);
        }
        isSaveThreadRunning = true;
    }
}

EGLsizeiANDROID egl_cache_t::getBlob(const void* key, EGLsizeiANDROID keySize,
        void* value, EGLsizeiANDROID valueSize) {

    if (keySize < 0 || valueSize < 0) {
        ALOGW("EGL_ANDROID_blob_cache set: negative sizes are not allowed");
        return 0;
    }

    if (!mInitialized) {
        return 0;
    }

    // Check hashtable first
    mPendingWritesMutex.lock();
    if (mPendingWrites.size()) {
        std::shared_ptr<Blob> dummyKey = std::make_shared<Blob>(key, keySize, false);
        std::unordered_map<std::shared_ptr<Blob>, blobEntry>::const_iterator found = mPendingWrites.find (dummyKey);
        if (found != mPendingWrites.end()) {
            blobEntry entry = found->second;
            std::shared_ptr<Blob> valueBlob = entry.getValue();
            ssize_t valueBlobSize = valueBlob->getSize();
            if (valueBlobSize <= valueSize) {
                memcpy(value, valueBlob->getData(), valueBlobSize);
            }

            mPendingWritesMutex.unlock();
            return valueBlobSize;
        }
    }
    mPendingWritesMutex.unlock();

    // Go ahead if read-only, otherwise get a lock on the whole blobcache
    mYieldBlobCache = true;
    std::unique_lock<std::mutex> lock(readOnlyMutex);

    if (!READ_ONLY) {
        lock = std::unique_lock<std::mutex>(mMutex, std::defer_lock);
        lock.lock();
    }

    if (mInitialized) {
        BlobCache* bc = getBlobCacheLocked();
        ssize_t size = bc->get(key, keySize, value, valueSize);

        mYieldBlobCache = false;
        return size;
    }

    mYieldBlobCache = false;
    return 0;
}

void egl_cache_t::setCacheFilename(const char* filename) {
    std::lock_guard<std::mutex> lock(mMutex);
    mFilename = filename;
}

BlobCache* egl_cache_t::getBlobCacheLocked() {
    if (mBlobCache == nullptr) {
        mBlobCache.reset(new FileBlobCache(maxKeySize, maxValueSize, maxTotalSize, mFilename));
    }
    return mBlobCache.get();
}

// ----------------------------------------------------------------------------
}; // namespace android
// ----------------------------------------------------------------------------
