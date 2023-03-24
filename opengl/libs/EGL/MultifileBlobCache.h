/*
 ** Copyright 2022, The Android Open Source Project
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

#ifndef ANDROID_MULTIFILE_BLOB_CACHE_H
#define ANDROID_MULTIFILE_BLOB_CACHE_H

#include <EGL/egl.h>
#include <EGL/eglext.h>

#include <android-base/thread_annotations.h>
#include <future>
#include <map>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "FileBlobCache.h"

namespace android {

struct MultifileHeader {
    uint32_t magic;
    uint32_t crc;
    EGLsizeiANDROID keySize;
    EGLsizeiANDROID valueSize;
};

struct MultifileEntryStats {
    EGLsizeiANDROID valueSize;
    size_t fileSize;
    time_t accessTime;
};

struct MultifileHotCache {
    int entryFd;
    uint8_t* entryBuffer;
    size_t entrySize;
};

enum class TaskCommand {
    Invalid = 0,
    WriteToDisk,
    Exit,
};

class DeferredTask {
public:
    DeferredTask(TaskCommand command)
          : mCommand(command), mEntryHash(0), mBuffer(nullptr), mBufferSize(0) {}

    TaskCommand getTaskCommand() { return mCommand; }

    void initWriteToDisk(uint32_t entryHash, std::string fullPath, uint8_t* buffer,
                         size_t bufferSize) {
        mCommand = TaskCommand::WriteToDisk;
        mEntryHash = entryHash;
        mFullPath = std::move(fullPath);
        mBuffer = buffer;
        mBufferSize = bufferSize;
    }

    uint32_t getEntryHash() { return mEntryHash; }
    std::string& getFullPath() { return mFullPath; }
    uint8_t* getBuffer() { return mBuffer; }
    size_t getBufferSize() { return mBufferSize; };

private:
    TaskCommand mCommand;

    // Parameters for WriteToDisk
    uint32_t mEntryHash;
    std::string mFullPath;
    uint8_t* mBuffer;
    size_t mBufferSize;
};

class MultifileBlobCache {
public:
    MultifileBlobCache(size_t maxKeySize, size_t maxValueSize, size_t maxTotalSize,
                       const std::string& baseDir);
    ~MultifileBlobCache();

    void set(const void* key, EGLsizeiANDROID keySize, const void* value,
             EGLsizeiANDROID valueSize);
    EGLsizeiANDROID get(const void* key, EGLsizeiANDROID keySize, void* value,
                        EGLsizeiANDROID valueSize);

    void finish();

    size_t getTotalSize() const { return mTotalCacheSize; }

private:
    void trackEntry(uint32_t entryHash, EGLsizeiANDROID valueSize, size_t fileSize,
                    time_t accessTime);
    bool contains(uint32_t entryHash) const;
    bool removeEntry(uint32_t entryHash);
    MultifileEntryStats getEntryStats(uint32_t entryHash);

    size_t getFileSize(uint32_t entryHash);
    size_t getValueSize(uint32_t entryHash);

    void increaseTotalCacheSize(size_t fileSize);
    void decreaseTotalCacheSize(size_t fileSize);

    bool addToHotCache(uint32_t entryHash, int fd, uint8_t* entryBufer, size_t entrySize);
    bool removeFromHotCache(uint32_t entryHash);

    void trimCache();
    bool applyLRU(size_t cacheLimit);

    bool mInitialized;
    std::string mMultifileDirName;

    std::unordered_set<uint32_t> mEntries;
    std::unordered_map<uint32_t, MultifileEntryStats> mEntryStats;
    std::unordered_map<uint32_t, MultifileHotCache> mHotCache;

    size_t mMaxKeySize;
    size_t mMaxValueSize;
    size_t mMaxTotalSize;
    size_t mTotalCacheSize;
    size_t mHotCacheLimit;
    size_t mHotCacheEntryLimit;
    size_t mHotCacheSize;

    // Below are the components used for deferred writes

    // Track whether we have pending writes for an entry
    std::mutex mDeferredWriteStatusMutex;
    std::multimap<uint32_t, uint8_t*> mDeferredWrites GUARDED_BY(mDeferredWriteStatusMutex);

    // Functions to work through tasks in the queue
    void processTasks();
    void processTasksImpl(bool* exitThread);
    void processTask(DeferredTask& task);

    // Used by main thread to create work for the worker thread
    void queueTask(DeferredTask&& task);

    // Used by main thread to wait for worker thread to complete all outstanding work.
    void waitForWorkComplete();

    std::thread mTaskThread;
    std::queue<DeferredTask> mTasks;
    std::mutex mWorkerMutex;

    // This condition will block the worker thread until a task is queued
    std::condition_variable mWorkAvailableCondition;

    // This condition will block the main thread while the worker thread still has tasks
    std::condition_variable mWorkerIdleCondition;

    // This bool will track whether all tasks have been completed
    bool mWorkerThreadIdle;
};

}; // namespace android

#endif // ANDROID_MULTIFILE_BLOB_CACHE_H
