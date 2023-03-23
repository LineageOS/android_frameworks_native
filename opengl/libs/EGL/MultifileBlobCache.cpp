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

// #define LOG_NDEBUG 0

#include "MultifileBlobCache.h"

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <log/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <locale>

#include <utils/JenkinsHash.h>

using namespace std::literals;

constexpr uint32_t kMultifileMagic = 'MFB$';
constexpr uint32_t kCrcPlaceholder = 0;

namespace {

// Helper function to close entries or free them
void freeHotCacheEntry(android::MultifileHotCache& entry) {
    if (entry.entryFd != -1) {
        // If we have an fd, then this entry was added to hot cache via INIT or GET
        // We need to unmap and close the entry
        munmap(entry.entryBuffer, entry.entrySize);
        close(entry.entryFd);
    } else {
        // Otherwise, this was added to hot cache during SET, so it was never mapped
        // and fd was only on the deferred thread.
        delete[] entry.entryBuffer;
    }
}

} // namespace

namespace android {

MultifileBlobCache::MultifileBlobCache(size_t maxKeySize, size_t maxValueSize, size_t maxTotalSize,
                                       const std::string& baseDir)
      : mInitialized(false),
        mMaxKeySize(maxKeySize),
        mMaxValueSize(maxValueSize),
        mMaxTotalSize(maxTotalSize),
        mTotalCacheSize(0),
        mHotCacheLimit(0),
        mHotCacheSize(0),
        mWorkerThreadIdle(true) {
    if (baseDir.empty()) {
        ALOGV("INIT: no baseDir provided in MultifileBlobCache constructor, returning early.");
        return;
    }

    // Establish the name of our multifile directory
    mMultifileDirName = baseDir + ".multifile";

    // Set the hotcache limit to be large enough to contain one max entry
    // This ensure the hot cache is always large enough for single entry
    mHotCacheLimit = mMaxKeySize + mMaxValueSize + sizeof(MultifileHeader);

    ALOGV("INIT: Initializing multifile blobcache with maxKeySize=%zu and maxValueSize=%zu",
          mMaxKeySize, mMaxValueSize);

    // Initialize our cache with the contents of the directory
    mTotalCacheSize = 0;

    // Create the worker thread
    mTaskThread = std::thread(&MultifileBlobCache::processTasks, this);

    // See if the dir exists, and initialize using its contents
    struct stat st;
    if (stat(mMultifileDirName.c_str(), &st) == 0) {
        // Read all the files and gather details, then preload their contents
        DIR* dir;
        struct dirent* entry;
        if ((dir = opendir(mMultifileDirName.c_str())) != nullptr) {
            while ((entry = readdir(dir)) != nullptr) {
                if (entry->d_name == "."s || entry->d_name == ".."s) {
                    continue;
                }

                std::string entryName = entry->d_name;
                std::string fullPath = mMultifileDirName + "/" + entryName;

                // The filename is the same as the entryHash
                uint32_t entryHash = static_cast<uint32_t>(strtoul(entry->d_name, nullptr, 10));

                ALOGV("INIT: Checking entry %u", entryHash);

                // Look up the details of the file
                struct stat st;
                if (stat(fullPath.c_str(), &st) != 0) {
                    ALOGE("Failed to stat %s", fullPath.c_str());
                    return;
                }

                // If the cache entry is damaged or no good, remove it
                if (st.st_size <= 0 || st.st_atime <= 0) {
                    ALOGE("INIT: Entry %u has invalid stats! Removing.", entryHash);
                    if (remove(fullPath.c_str()) != 0) {
                        ALOGE("Error removing %s: %s", fullPath.c_str(), std::strerror(errno));
                    }
                    continue;
                }

                // Open the file so we can read its header
                int fd = open(fullPath.c_str(), O_RDONLY);
                if (fd == -1) {
                    ALOGE("Cache error - failed to open fullPath: %s, error: %s", fullPath.c_str(),
                          std::strerror(errno));
                    return;
                }

                // Read the beginning of the file to get header
                MultifileHeader header;
                size_t result = read(fd, static_cast<void*>(&header), sizeof(MultifileHeader));
                if (result != sizeof(MultifileHeader)) {
                    ALOGE("Error reading MultifileHeader from cache entry (%s): %s",
                          fullPath.c_str(), std::strerror(errno));
                    return;
                }

                // Verify header magic
                if (header.magic != kMultifileMagic) {
                    ALOGE("INIT: Entry %u has bad magic (%u)! Removing.", entryHash, header.magic);
                    if (remove(fullPath.c_str()) != 0) {
                        ALOGE("Error removing %s: %s", fullPath.c_str(), std::strerror(errno));
                    }
                    continue;
                }

                // Note: Converting from off_t (signed) to size_t (unsigned)
                size_t fileSize = static_cast<size_t>(st.st_size);

                // Memory map the file
                uint8_t* mappedEntry = reinterpret_cast<uint8_t*>(
                        mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0));
                if (mappedEntry == MAP_FAILED) {
                    ALOGE("Failed to mmap cacheEntry, error: %s", std::strerror(errno));
                    return;
                }

                // Ensure we have a good CRC
                if (header.crc !=
                    crc32c(mappedEntry + sizeof(MultifileHeader),
                           fileSize - sizeof(MultifileHeader))) {
                    ALOGE("INIT: Entry %u failed CRC check! Removing.", entryHash);
                    if (remove(fullPath.c_str()) != 0) {
                        ALOGE("Error removing %s: %s", fullPath.c_str(), std::strerror(errno));
                    }
                    continue;
                }

                // If the cache entry is damaged or no good, remove it
                if (header.keySize <= 0 || header.valueSize <= 0) {
                    ALOGE("INIT: Entry %u has a bad header keySize (%lu) or valueSize (%lu), "
                          "removing.",
                          entryHash, header.keySize, header.valueSize);
                    if (remove(fullPath.c_str()) != 0) {
                        ALOGE("Error removing %s: %s", fullPath.c_str(), std::strerror(errno));
                    }
                    continue;
                }

                ALOGV("INIT: Entry %u is good, tracking it now.", entryHash);

                // Track details for rapid lookup later
                trackEntry(entryHash, header.valueSize, fileSize, st.st_atime);

                // Track the total size
                increaseTotalCacheSize(fileSize);

                // Preload the entry for fast retrieval
                if ((mHotCacheSize + fileSize) < mHotCacheLimit) {
                    ALOGV("INIT: Populating hot cache with fd = %i, cacheEntry = %p for "
                          "entryHash %u",
                          fd, mappedEntry, entryHash);

                    // Track the details of the preload so they can be retrieved later
                    if (!addToHotCache(entryHash, fd, mappedEntry, fileSize)) {
                        ALOGE("INIT Failed to add %u to hot cache", entryHash);
                        munmap(mappedEntry, fileSize);
                        close(fd);
                        return;
                    }
                } else {
                    // If we're not keeping it in hot cache, unmap it now
                    munmap(mappedEntry, fileSize);
                    close(fd);
                }
            }
            closedir(dir);
        } else {
            ALOGE("Unable to open filename: %s", mMultifileDirName.c_str());
        }
    } else {
        // If the multifile directory does not exist, create it and start from scratch
        if (mkdir(mMultifileDirName.c_str(), 0755) != 0 && (errno != EEXIST)) {
            ALOGE("Unable to create directory (%s), errno (%i)", mMultifileDirName.c_str(), errno);
        }
    }

    mInitialized = true;
}

MultifileBlobCache::~MultifileBlobCache() {
    if (!mInitialized) {
        return;
    }

    // Inform the worker thread we're done
    ALOGV("DESCTRUCTOR: Shutting down worker thread");
    DeferredTask task(TaskCommand::Exit);
    queueTask(std::move(task));

    // Wait for it to complete
    ALOGV("DESCTRUCTOR: Waiting for worker thread to complete");
    waitForWorkComplete();
    if (mTaskThread.joinable()) {
        mTaskThread.join();
    }
}

// Set will add the entry to hot cache and start a deferred process to write it to disk
void MultifileBlobCache::set(const void* key, EGLsizeiANDROID keySize, const void* value,
                             EGLsizeiANDROID valueSize) {
    if (!mInitialized) {
        return;
    }

    // Ensure key and value are under their limits
    if (keySize > mMaxKeySize || valueSize > mMaxValueSize) {
        ALOGW("SET: keySize (%lu vs %zu) or valueSize (%lu vs %zu) too large", keySize, mMaxKeySize,
              valueSize, mMaxValueSize);
        return;
    }

    // Generate a hash of the key and use it to track this entry
    uint32_t entryHash = android::JenkinsHashMixBytes(0, static_cast<const uint8_t*>(key), keySize);

    size_t fileSize = sizeof(MultifileHeader) + keySize + valueSize;

    // If we're going to be over the cache limit, kick off a trim to clear space
    if (getTotalSize() + fileSize > mMaxTotalSize) {
        ALOGV("SET: Cache is full, calling trimCache to clear space");
        trimCache();
    }

    ALOGV("SET: Add %u to cache", entryHash);

    uint8_t* buffer = new uint8_t[fileSize];

    // Write placeholders for magic and CRC until deferred thread completes the write
    android::MultifileHeader header = {kMultifileMagic, kCrcPlaceholder, keySize, valueSize};
    memcpy(static_cast<void*>(buffer), static_cast<const void*>(&header),
           sizeof(android::MultifileHeader));
    // Write the key and value after the header
    memcpy(static_cast<void*>(buffer + sizeof(MultifileHeader)), static_cast<const void*>(key),
           keySize);
    memcpy(static_cast<void*>(buffer + sizeof(MultifileHeader) + keySize),
           static_cast<const void*>(value), valueSize);

    std::string fullPath = mMultifileDirName + "/" + std::to_string(entryHash);

    // Track the size and access time for quick recall
    trackEntry(entryHash, valueSize, fileSize, time(0));

    // Update the overall cache size
    increaseTotalCacheSize(fileSize);

    // Keep the entry in hot cache for quick retrieval
    ALOGV("SET: Adding %u to hot cache.", entryHash);

    // Sending -1 as the fd indicates we don't have an fd for this
    if (!addToHotCache(entryHash, -1, buffer, fileSize)) {
        ALOGE("SET: Failed to add %u to hot cache", entryHash);
        delete[] buffer;
        return;
    }

    // Track that we're creating a pending write for this entry
    // Include the buffer to handle the case when multiple writes are pending for an entry
    {
        // Synchronize access to deferred write status
        std::lock_guard<std::mutex> lock(mDeferredWriteStatusMutex);
        mDeferredWrites.insert(std::make_pair(entryHash, buffer));
    }

    // Create deferred task to write to storage
    ALOGV("SET: Adding task to queue.");
    DeferredTask task(TaskCommand::WriteToDisk);
    task.initWriteToDisk(entryHash, fullPath, buffer, fileSize);
    queueTask(std::move(task));
}

// Get will check the hot cache, then load it from disk if needed
EGLsizeiANDROID MultifileBlobCache::get(const void* key, EGLsizeiANDROID keySize, void* value,
                                        EGLsizeiANDROID valueSize) {
    if (!mInitialized) {
        return 0;
    }

    // Ensure key and value are under their limits
    if (keySize > mMaxKeySize || valueSize > mMaxValueSize) {
        ALOGW("GET: keySize (%lu vs %zu) or valueSize (%lu vs %zu) too large", keySize, mMaxKeySize,
              valueSize, mMaxValueSize);
        return 0;
    }

    // Generate a hash of the key and use it to track this entry
    uint32_t entryHash = android::JenkinsHashMixBytes(0, static_cast<const uint8_t*>(key), keySize);

    // See if we have this file
    if (!contains(entryHash)) {
        ALOGV("GET: Cache MISS - cache does not contain entry: %u", entryHash);
        return 0;
    }

    // Look up the data for this entry
    MultifileEntryStats entryStats = getEntryStats(entryHash);

    size_t cachedValueSize = entryStats.valueSize;
    if (cachedValueSize > valueSize) {
        ALOGV("GET: Cache MISS - valueSize not large enough (%lu) for entry %u, returning required"
              "size (%zu)",
              valueSize, entryHash, cachedValueSize);
        return cachedValueSize;
    }

    // We have the file and have enough room to write it out, return the entry
    ALOGV("GET: Cache HIT - cache contains entry: %u", entryHash);

    // Look up the size of the file
    size_t fileSize = entryStats.fileSize;
    if (keySize > fileSize) {
        ALOGW("keySize (%lu) is larger than entrySize (%zu). This is a hash collision or modified "
              "file",
              keySize, fileSize);
        return 0;
    }

    std::string fullPath = mMultifileDirName + "/" + std::to_string(entryHash);

    // Open the hashed filename path
    uint8_t* cacheEntry = 0;

    // Check hot cache
    if (mHotCache.find(entryHash) != mHotCache.end()) {
        ALOGV("GET: HotCache HIT for entry %u", entryHash);
        cacheEntry = mHotCache[entryHash].entryBuffer;
    } else {
        ALOGV("GET: HotCache MISS for entry: %u", entryHash);

        // Wait for writes to complete if there is an outstanding write for this entry
        bool wait = false;
        {
            // Synchronize access to deferred write status
            std::lock_guard<std::mutex> lock(mDeferredWriteStatusMutex);
            wait = mDeferredWrites.find(entryHash) != mDeferredWrites.end();
        }

        if (wait) {
            ALOGV("GET: Waiting for write to complete for %u", entryHash);
            waitForWorkComplete();
        }

        // Open the entry file
        int fd = open(fullPath.c_str(), O_RDONLY);
        if (fd == -1) {
            ALOGE("Cache error - failed to open fullPath: %s, error: %s", fullPath.c_str(),
                  std::strerror(errno));
            return 0;
        }

        // Memory map the file
        cacheEntry =
                reinterpret_cast<uint8_t*>(mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0));
        if (cacheEntry == MAP_FAILED) {
            ALOGE("Failed to mmap cacheEntry, error: %s", std::strerror(errno));
            close(fd);
            return 0;
        }

        ALOGV("GET: Adding %u to hot cache", entryHash);
        if (!addToHotCache(entryHash, fd, cacheEntry, fileSize)) {
            ALOGE("GET: Failed to add %u to hot cache", entryHash);
            return 0;
        }

        cacheEntry = mHotCache[entryHash].entryBuffer;
    }

    // Ensure the header matches
    MultifileHeader* header = reinterpret_cast<MultifileHeader*>(cacheEntry);
    if (header->keySize != keySize || header->valueSize != valueSize) {
        ALOGW("Mismatch on keySize(%ld vs. cached %ld) or valueSize(%ld vs. cached %ld) compared "
              "to cache header values for fullPath: %s",
              keySize, header->keySize, valueSize, header->valueSize, fullPath.c_str());
        removeFromHotCache(entryHash);
        return 0;
    }

    // Compare the incoming key with our stored version (the beginning of the entry)
    uint8_t* cachedKey = cacheEntry + sizeof(MultifileHeader);
    int compare = memcmp(cachedKey, key, keySize);
    if (compare != 0) {
        ALOGW("Cached key and new key do not match! This is a hash collision or modified file");
        removeFromHotCache(entryHash);
        return 0;
    }

    // Remaining entry following the key is the value
    uint8_t* cachedValue = cacheEntry + (keySize + sizeof(MultifileHeader));
    memcpy(value, cachedValue, cachedValueSize);

    return cachedValueSize;
}

void MultifileBlobCache::finish() {
    if (!mInitialized) {
        return;
    }

    // Wait for all deferred writes to complete
    ALOGV("FINISH: Waiting for work to complete.");
    waitForWorkComplete();

    // Close all entries in the hot cache
    for (auto hotCacheIter = mHotCache.begin(); hotCacheIter != mHotCache.end();) {
        uint32_t entryHash = hotCacheIter->first;
        MultifileHotCache entry = hotCacheIter->second;

        ALOGV("FINISH: Closing hot cache entry for %u", entryHash);
        freeHotCacheEntry(entry);

        mHotCache.erase(hotCacheIter++);
    }
}

void MultifileBlobCache::trackEntry(uint32_t entryHash, EGLsizeiANDROID valueSize, size_t fileSize,
                                    time_t accessTime) {
    mEntries.insert(entryHash);
    mEntryStats[entryHash] = {valueSize, fileSize, accessTime};
}

bool MultifileBlobCache::contains(uint32_t hashEntry) const {
    return mEntries.find(hashEntry) != mEntries.end();
}

MultifileEntryStats MultifileBlobCache::getEntryStats(uint32_t entryHash) {
    return mEntryStats[entryHash];
}

void MultifileBlobCache::increaseTotalCacheSize(size_t fileSize) {
    mTotalCacheSize += fileSize;
}

void MultifileBlobCache::decreaseTotalCacheSize(size_t fileSize) {
    mTotalCacheSize -= fileSize;
}

bool MultifileBlobCache::addToHotCache(uint32_t newEntryHash, int newFd, uint8_t* newEntryBuffer,
                                       size_t newEntrySize) {
    ALOGV("HOTCACHE(ADD): Adding %u to hot cache", newEntryHash);

    // Clear space if we need to
    if ((mHotCacheSize + newEntrySize) > mHotCacheLimit) {
        ALOGV("HOTCACHE(ADD): mHotCacheSize (%zu) + newEntrySize (%zu) is to big for "
              "mHotCacheLimit "
              "(%zu), freeing up space for %u",
              mHotCacheSize, newEntrySize, mHotCacheLimit, newEntryHash);

        // Wait for all the files to complete writing so our hot cache is accurate
        ALOGV("HOTCACHE(ADD): Waiting for work to complete for %u", newEntryHash);
        waitForWorkComplete();

        // Free up old entries until under the limit
        for (auto hotCacheIter = mHotCache.begin(); hotCacheIter != mHotCache.end();) {
            uint32_t oldEntryHash = hotCacheIter->first;
            MultifileHotCache oldEntry = hotCacheIter->second;

            // Move our iterator before deleting the entry
            hotCacheIter++;
            if (!removeFromHotCache(oldEntryHash)) {
                ALOGE("HOTCACHE(ADD): Unable to remove entry %u", oldEntryHash);
                return false;
            }

            // Clear at least half the hot cache
            if ((mHotCacheSize + newEntrySize) <= mHotCacheLimit / 2) {
                ALOGV("HOTCACHE(ADD): Freed enough space for %zu", mHotCacheSize);
                break;
            }
        }
    }

    // Track it
    mHotCache[newEntryHash] = {newFd, newEntryBuffer, newEntrySize};
    mHotCacheSize += newEntrySize;

    ALOGV("HOTCACHE(ADD): New hot cache size: %zu", mHotCacheSize);

    return true;
}

bool MultifileBlobCache::removeFromHotCache(uint32_t entryHash) {
    if (mHotCache.find(entryHash) != mHotCache.end()) {
        ALOGV("HOTCACHE(REMOVE): Removing %u from hot cache", entryHash);

        // Wait for all the files to complete writing so our hot cache is accurate
        ALOGV("HOTCACHE(REMOVE): Waiting for work to complete for %u", entryHash);
        waitForWorkComplete();

        ALOGV("HOTCACHE(REMOVE): Closing hot cache entry for %u", entryHash);
        MultifileHotCache entry = mHotCache[entryHash];
        freeHotCacheEntry(entry);

        // Delete the entry from our tracking
        mHotCacheSize -= entry.entrySize;
        mHotCache.erase(entryHash);

        return true;
    }

    return false;
}

bool MultifileBlobCache::applyLRU(size_t cacheLimit) {
    // Walk through our map of sorted last access times and remove files until under the limit
    for (auto cacheEntryIter = mEntryStats.begin(); cacheEntryIter != mEntryStats.end();) {
        uint32_t entryHash = cacheEntryIter->first;

        ALOGV("LRU: Removing entryHash %u", entryHash);

        // Track the overall size
        MultifileEntryStats entryStats = getEntryStats(entryHash);
        decreaseTotalCacheSize(entryStats.fileSize);

        // Remove it from hot cache if present
        removeFromHotCache(entryHash);

        // Remove it from the system
        std::string entryPath = mMultifileDirName + "/" + std::to_string(entryHash);
        if (remove(entryPath.c_str()) != 0) {
            ALOGE("LRU: Error removing %s: %s", entryPath.c_str(), std::strerror(errno));
            return false;
        }

        // Increment the iterator before clearing the entry
        cacheEntryIter++;

        // Delete the entry from our tracking
        size_t count = mEntryStats.erase(entryHash);
        if (count != 1) {
            ALOGE("LRU: Failed to remove entryHash (%u) from mEntryStats", entryHash);
            return false;
        }

        // See if it has been reduced enough
        size_t totalCacheSize = getTotalSize();
        if (totalCacheSize <= cacheLimit) {
            // Success
            ALOGV("LRU: Reduced cache to %zu", totalCacheSize);
            return true;
        }
    }

    ALOGV("LRU: Cache is empty");
    return false;
}

// When removing files, what fraction of the overall limit should be reached when removing files
// A divisor of two will decrease the cache to 50%, four to 25% and so on
constexpr uint32_t kCacheLimitDivisor = 2;

// Calculate the cache size and remove old entries until under the limit
void MultifileBlobCache::trimCache() {
    // Wait for all deferred writes to complete
    ALOGV("TRIM: Waiting for work to complete.");
    waitForWorkComplete();

    ALOGV("TRIM: Reducing multifile cache size to %zu", mMaxTotalSize / kCacheLimitDivisor);
    if (!applyLRU(mMaxTotalSize / kCacheLimitDivisor)) {
        ALOGE("Error when clearing multifile shader cache");
        return;
    }
}

// This function performs a task.  It only knows how to write files to disk,
// but it could be expanded if needed.
void MultifileBlobCache::processTask(DeferredTask& task) {
    switch (task.getTaskCommand()) {
        case TaskCommand::Exit: {
            ALOGV("DEFERRED: Shutting down");
            return;
        }
        case TaskCommand::WriteToDisk: {
            uint32_t entryHash = task.getEntryHash();
            std::string& fullPath = task.getFullPath();
            uint8_t* buffer = task.getBuffer();
            size_t bufferSize = task.getBufferSize();

            // Create the file or reset it if already present, read+write for user only
            int fd = open(fullPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
            if (fd == -1) {
                ALOGE("Cache error in SET - failed to open fullPath: %s, error: %s",
                      fullPath.c_str(), std::strerror(errno));
                return;
            }

            ALOGV("DEFERRED: Opened fd %i from %s", fd, fullPath.c_str());

            // Add CRC check to the header (always do this last!)
            MultifileHeader* header = reinterpret_cast<MultifileHeader*>(buffer);
            header->crc =
                    crc32c(buffer + sizeof(MultifileHeader), bufferSize - sizeof(MultifileHeader));

            ssize_t result = write(fd, buffer, bufferSize);
            if (result != bufferSize) {
                ALOGE("Error writing fileSize to cache entry (%s): %s", fullPath.c_str(),
                      std::strerror(errno));
                return;
            }

            ALOGV("DEFERRED: Completed write for: %s", fullPath.c_str());
            close(fd);

            // Erase the entry from mDeferredWrites
            // Since there could be multiple outstanding writes for an entry, find the matching one
            {
                // Synchronize access to deferred write status
                std::lock_guard<std::mutex> lock(mDeferredWriteStatusMutex);
                typedef std::multimap<uint32_t, uint8_t*>::iterator entryIter;
                std::pair<entryIter, entryIter> iterPair = mDeferredWrites.equal_range(entryHash);
                for (entryIter it = iterPair.first; it != iterPair.second; ++it) {
                    if (it->second == buffer) {
                        ALOGV("DEFERRED: Marking write complete for %u at %p", it->first,
                              it->second);
                        mDeferredWrites.erase(it);
                        break;
                    }
                }
            }

            return;
        }
        default: {
            ALOGE("DEFERRED: Unhandled task type");
            return;
        }
    }
}

// This function will wait until tasks arrive, then execute them
// If the exit command is submitted, the loop will terminate
void MultifileBlobCache::processTasksImpl(bool* exitThread) {
    while (true) {
        std::unique_lock<std::mutex> lock(mWorkerMutex);
        if (mTasks.empty()) {
            ALOGV("WORKER: No tasks available, waiting");
            mWorkerThreadIdle = true;
            mWorkerIdleCondition.notify_all();
            // Only wake if notified and command queue is not empty
            mWorkAvailableCondition.wait(lock, [this] { return !mTasks.empty(); });
        }

        ALOGV("WORKER: Task available, waking up.");
        mWorkerThreadIdle = false;
        DeferredTask task = std::move(mTasks.front());
        mTasks.pop();

        if (task.getTaskCommand() == TaskCommand::Exit) {
            ALOGV("WORKER: Exiting work loop.");
            *exitThread = true;
            mWorkerThreadIdle = true;
            mWorkerIdleCondition.notify_one();
            return;
        }

        lock.unlock();
        processTask(task);
    }
}

// Process tasks until the exit task is submitted
void MultifileBlobCache::processTasks() {
    while (true) {
        bool exitThread = false;
        processTasksImpl(&exitThread);
        if (exitThread) {
            break;
        }
    }
}

// Add a task to the queue to be processed by the worker thread
void MultifileBlobCache::queueTask(DeferredTask&& task) {
    std::lock_guard<std::mutex> queueLock(mWorkerMutex);
    mTasks.emplace(std::move(task));
    mWorkAvailableCondition.notify_one();
}

// Wait until all tasks have been completed
void MultifileBlobCache::waitForWorkComplete() {
    std::unique_lock<std::mutex> lock(mWorkerMutex);
    mWorkerIdleCondition.wait(lock, [this] { return (mTasks.empty() && mWorkerThreadIdle); });
}

}; // namespace android
