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

#ifndef ANDROID_EGL_CACHE_H
#define ANDROID_EGL_CACHE_H

#include <EGL/egl.h>
#include <EGL/eglext.h>

#include "FileBlobCache.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <string>
#include <pthread.h>
#include <log/log.h>

#include "BlobCache.h"

// for wait_until
using namespace std::chrono_literals;

// The time in seconds to wait before writing to disk
static const unsigned int deferredSaveDelay = 5;

// ----------------------------------------------------------------------------
namespace android {

// blobEntry is the key_value_pair we store for the Blob HashTable
typedef key_value_pair_t< std::shared_ptr<Blob>, std::shared_ptr<Blob> > blobEntry;

// ----------------------------------------------------------------------------

class egl_display_t;

class EGLAPI egl_cache_t {
public:

    // get returns a pointer to the singleton egl_cache_t object.  This
    // singleton object will never be destroyed.
    static egl_cache_t* get();

    // initialize puts the egl_cache_t into an initialized state, such that it
    // is able to insert and retrieve entries from the cache.  This should be
    // called when EGL is initialized.  When not in the initialized state the
    // getBlob and setBlob methods will return without performing any cache
    // operations.
    void initialize(egl_display_t* display);

    // terminate puts the egl_cache_t back into the uninitialized state.  When
    // in this state the getBlob and setBlob methods will return without
    // performing any cache operations.
    void terminate();

    // setBlob attempts to insert a new key/value blob pair into the cache.
    // This will be called by the hardware vendor's EGL implementation via the
    // EGL_ANDROID_blob_cache extension.
    void setBlob(const void* key, EGLsizeiANDROID keySize, const void* value,
        EGLsizeiANDROID valueSize);

    // getBlob attempts to retrieve the value blob associated with a given key
    // blob from cache.  This will be called by the hardware vendor's EGL
    // implementation via the EGL_ANDROID_blob_cache extension.
    EGLsizeiANDROID getBlob(const void* key, EGLsizeiANDROID keySize,
        void* value, EGLsizeiANDROID valueSize);

    // setCacheFilename sets the name of the file that should be used to store
    // cache contents from one program invocation to another.
    void setCacheFilename(const char* filename);

private:
    // Creation and (the lack of) destruction is handled internally.
    egl_cache_t();
    ~egl_cache_t();

    // Copying is disallowed.
    egl_cache_t(const egl_cache_t&); // not implemented
    void operator=(const egl_cache_t&); // not implemented

    // getBlobCacheLocked returns the BlobCache object being used to store the
    // key/value blob pairs.  If the BlobCache object has not yet been created,
    // this will do so, loading the serialized cache contents from disk if
    // possible.
    BlobCache* getBlobCacheLocked();

    // mInitialized indicates whether the egl_cache_t is in the initialized
    // state.  It is initialized to false at construction time, and gets set to
    // true when initialize is called.  It is set back to false when terminate
    // is called.  When in this state, the cache behaves as normal.  When not,
    // the getBlob and setBlob methods will return without performing any cache
    // operations.
    bool mInitialized;

    // mBlobCache is the cache in which the key/value blob pairs are stored.  It
    // is initially NULL, and will be initialized by getBlobCacheLocked the
    // first time it's needed.
    std::unique_ptr<FileBlobCache> mBlobCache;

    // mPendingWrites is the hashtable which will store pending writes when the blobcache
    // is locked for whatever reason. This will prevent glCompile from blocking
    // when BlobCache is being written to disk
    std::unordered_map<std::shared_ptr<Blob>, blobEntry> mPendingWrites;

    mutable std::mutex mPendingWritesMutex;

    // mFilename is the name of the file for storing cache contents in between
    // program invocations.  It is initialized to an empty string at
    // construction time, and can be set with the setCacheFilename method.  An
    // empty string indicates that the cache should not be saved to or restored
    // from disk.
    std::string mFilename;

    // READ_ONLY: so that we can read from the blobcache
    // even when it is being written to disk
    bool READ_ONLY;
    mutable volatile bool mYieldBlobCache; // just a hint for DeferredSaveThread
    mutable std::mutex readOnlyMutex;  // TODO: Use RWLock instead?

    // mMutex is the mutex used to prevent concurrent access to the member
    // variables. It must be locked whenever the member variables are accessed.
    mutable std::mutex mMutex;

    // sCache is the singleton egl_cache_t object.
    static egl_cache_t sCache;

    // deferredSaveThread variables
    const char* deferredSaveThreadName = "EGLSave";
    pthread_t deferredSaveThread;
    std::condition_variable mCondition;
    std::mutex mDelayMutex;
    std::mutex saveThreadCheckMutex;
    std::mutex saveThreadExitMutex;
    bool isSaveThreadRunning = false;
    bool saveThreadExit = false;

    static void *saveThread(void*) {
        egl_cache_t* c = egl_cache_t::get();
        while(1) {
            // Wait a bit for more pending entries to the cache
            // but allow the sleep to be cut short by termination
            std::unique_lock<std::mutex> lock(c->mDelayMutex);
            c->mCondition.wait_until(lock, std::chrono::system_clock::now() + 1ms);//deferredSaveDelay * 1000ms);
            lock.unlock();

            if (c->mInitialized) {
                c->mPendingWritesMutex.lock();
                if (c->mPendingWrites.size() == 0) {
                    c->mPendingWritesMutex.unlock();
                    c->saveThreadCheckMutex.lock();
                    c->isSaveThreadRunning = false;
                    c->saveThreadCheckMutex.unlock();
                    return NULL;
                }

                // move entries to another hashtable
                std::unordered_map<std::shared_ptr<Blob>, blobEntry> mPendingWritesCopy = std::move(c->mPendingWrites);
                c->mPendingWritesMutex.unlock();

                // transfer entries from hashtable to blobcache
                // TODO: if getBlob() gets the mMutex before this does,
                //       it might miss the cache stored in mPendingWrites
                //       and mBlobCache

                for (auto entries = mPendingWritesCopy.begin(); entries != mPendingWritesCopy.end(); ++entries) {
                    blobEntry entry = entries->second;
                    std::shared_ptr<Blob> key = entry.getKey();
                    std::shared_ptr<Blob> value = entry.getValue();
                    c->mMutex.lock();
                    BlobCache* bc = c->getBlobCacheLocked();
                    bc->set(key->getData(), key->getSize(), value->getData(), value->getSize());
                    c->mMutex.unlock(); // to prevent deadlock with getBlob

                    if (c->mYieldBlobCache) {
                        sched_yield();
                    }
                }

                c->readOnlyMutex.lock();
                c->READ_ONLY = true;
                c->readOnlyMutex.unlock();

                c->mMutex.lock();
                c->saveBlobCacheLocked();
                c->mMutex.unlock();

                c->readOnlyMutex.lock();
                c->READ_ONLY = false;
                c->readOnlyMutex.unlock();

                // Check if thread should exit
                c->saveThreadExitMutex.lock();
                if (c->saveThreadExit) {
                    c->isSaveThreadRunning = false;
                    c->saveThreadExitMutex.unlock();
                    break;
                }
                c->saveThreadExitMutex.unlock();
            }
        }
        return NULL;
    }
};

// ----------------------------------------------------------------------------
}; // namespace android
// ----------------------------------------------------------------------------

#endif // ANDROID_EGL_CACHE_H
