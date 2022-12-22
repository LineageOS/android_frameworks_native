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

#include "egl_cache_multifile.h"

#include <android-base/properties.h>
#include <dirent.h>
#include <fcntl.h>
#include <graphicsenv/GraphicsEnv.h>
#include <inttypes.h>
#include <log/log.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <utime.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <limits>
#include <locale>
#include <map>
#include <sstream>
#include <unordered_map>

#include <utils/JenkinsHash.h>

static std::string multifileDirName = "";

using namespace std::literals;

namespace {

// Create a directory for tracking multiple files
void setupMultifile(const std::string& baseDir) {
    // If we've already set up the multifile dir in this base directory, we're done
    if (!multifileDirName.empty() && multifileDirName.find(baseDir) != std::string::npos) {
        return;
    }

    // Otherwise, create it
    multifileDirName = baseDir + ".multifile";
    if (mkdir(multifileDirName.c_str(), 0755) != 0 && (errno != EEXIST)) {
        ALOGW("Unable to create directory (%s), errno (%i)", multifileDirName.c_str(), errno);
    }
}

// Create a filename that is based on the hash of the key
std::string getCacheEntryFilename(const void* key, EGLsizeiANDROID keySize,
                                  const std::string& baseDir) {
    // Hash the key into a string
    std::stringstream keyName;
    keyName << android::JenkinsHashMixBytes(0, static_cast<const uint8_t*>(key), keySize);

    // Build a filename using dir and hash
    return baseDir + "/" + keyName.str();
}

// Determine file age based on stat modification time
// Newer files have a higher age (time since epoch)
time_t getFileAge(const std::string& filePath) {
    struct stat st;
    if (stat(filePath.c_str(), &st) == 0) {
        ALOGD("getFileAge returning %" PRId64 " for file age", static_cast<uint64_t>(st.st_mtime));
        return st.st_mtime;
    } else {
        ALOGW("Failed to stat %s", filePath.c_str());
        return 0;
    }
}

size_t getFileSize(const std::string& filePath) {
    struct stat st;
    if (stat(filePath.c_str(), &st) != 0) {
        ALOGE("Unable to stat %s", filePath.c_str());
        return 0;
    }
    return st.st_size;
}

// Walk through directory entries and track age and size
// Then iterate through the entries, oldest first, and remove them until under the limit.
// This will need to be updated if we move to a multilevel cache dir.
bool applyLRU(size_t cacheLimit) {
    // Build a multimap of files indexed by age.
    // They will be automatically sorted smallest (oldest) to largest (newest)
    std::multimap<time_t, std::string> agesToFiles;

    // Map files to sizes
    std::unordered_map<std::string, size_t> filesToSizes;

    size_t totalCacheSize = 0;

    DIR* dir;
    struct dirent* entry;
    if ((dir = opendir(multifileDirName.c_str())) != nullptr) {
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name == "."s || entry->d_name == ".."s) {
                continue;
            }

            // Look up each file age
            std::string fullPath = multifileDirName + "/" + entry->d_name;
            time_t fileAge = getFileAge(fullPath);

            // Track the files, sorted by age
            agesToFiles.insert(std::make_pair(fileAge, fullPath));

            // Also track the size so we know how much room we have freed
            size_t fileSize = getFileSize(fullPath);
            filesToSizes[fullPath] = fileSize;
            totalCacheSize += fileSize;
        }
        closedir(dir);
    } else {
        ALOGE("Unable to open filename: %s", multifileDirName.c_str());
        return false;
    }

    if (totalCacheSize <= cacheLimit) {
        // If LRU was called on a sufficiently small cache, no need to remove anything
        return true;
    }

    // Walk through the map of files until we're under the cache size
    for (const auto& cacheEntryIter : agesToFiles) {
        time_t entryAge = cacheEntryIter.first;
        const std::string entryPath = cacheEntryIter.second;

        ALOGD("Removing %s with age %ld", entryPath.c_str(), entryAge);
        if (std::remove(entryPath.c_str()) != 0) {
            ALOGE("Error removing %s: %s", entryPath.c_str(), std::strerror(errno));
            return false;
        }

        totalCacheSize -= filesToSizes[entryPath];
        if (totalCacheSize <= cacheLimit) {
            // Success
            ALOGV("Reduced cache to %zu", totalCacheSize);
            return true;
        } else {
            ALOGD("Cache size is still too large (%zu), removing more files", totalCacheSize);
        }
    }

    // Should never reach this return
    return false;
}

} // namespace

namespace android {

void setBlobMultifile(const void* key, EGLsizeiANDROID keySize, const void* value,
                      EGLsizeiANDROID valueSize, const std::string& baseDir) {
    if (baseDir.empty()) {
        return;
    }

    setupMultifile(baseDir);
    std::string filename = getCacheEntryFilename(key, keySize, multifileDirName);

    ALOGD("Attempting to open filename for set: %s", filename.c_str());
    std::ofstream outfile(filename, std::ofstream::binary);
    if (outfile.fail()) {
        ALOGW("Unable to open filename: %s", filename.c_str());
        return;
    }

    // First write the key
    outfile.write(static_cast<const char*>(key), keySize);
    if (outfile.bad()) {
        ALOGW("Unable to write key to filename: %s", filename.c_str());
        outfile.close();
        return;
    }
    ALOGD("Wrote %i bytes to out file for key", static_cast<int>(outfile.tellp()));

    // Then write the value
    outfile.write(static_cast<const char*>(value), valueSize);
    if (outfile.bad()) {
        ALOGW("Unable to write value to filename: %s", filename.c_str());
        outfile.close();
        return;
    }
    ALOGD("Wrote %i bytes to out file for full entry", static_cast<int>(outfile.tellp()));

    outfile.close();
}

EGLsizeiANDROID getBlobMultifile(const void* key, EGLsizeiANDROID keySize, void* value,
                                 EGLsizeiANDROID valueSize, const std::string& baseDir) {
    if (baseDir.empty()) {
        return 0;
    }

    setupMultifile(baseDir);
    std::string filename = getCacheEntryFilename(key, keySize, multifileDirName);

    // Open the hashed filename path
    ALOGD("Attempting to open filename for get: %s", filename.c_str());
    int fd = open(filename.c_str(), O_RDONLY);

    // File doesn't exist, this is a MISS, return zero bytes read
    if (fd == -1) {
        ALOGD("Cache MISS - failed to open filename: %s, error: %s", filename.c_str(),
              std::strerror(errno));
        return 0;
    }

    ALOGD("Cache HIT - opened filename: %s", filename.c_str());

    // Get the size of the file
    size_t entrySize = getFileSize(filename);
    if (keySize > entrySize) {
        ALOGW("keySize (%lu) is larger than entrySize (%zu). This is a hash collision or modified "
              "file",
              keySize, entrySize);
        close(fd);
        return 0;
    }

    // Memory map the file
    uint8_t* cacheEntry =
            reinterpret_cast<uint8_t*>(mmap(nullptr, entrySize, PROT_READ, MAP_PRIVATE, fd, 0));
    if (cacheEntry == MAP_FAILED) {
        ALOGE("Failed to mmap cacheEntry, error: %s", std::strerror(errno));
        close(fd);
        return 0;
    }

    // Compare the incoming key with our stored version (the beginning of the entry)
    int compare = memcmp(cacheEntry, key, keySize);
    if (compare != 0) {
        ALOGW("Cached key and new key do not match! This is a hash collision or modified file");
        munmap(cacheEntry, entrySize);
        close(fd);
        return 0;
    }

    // Keys matched, so remaining cache is value size
    size_t cachedValueSize = entrySize - keySize;

    // Return actual value size if valueSize is not large enough
    if (cachedValueSize > valueSize) {
        ALOGD("Skipping file read, not enough room provided (valueSize): %lu, "
              "returning required space as %zu",
              valueSize, cachedValueSize);
        munmap(cacheEntry, entrySize);
        close(fd);
        return cachedValueSize;
    }

    // Remaining entry following the key is the value
    uint8_t* cachedValue = cacheEntry + keySize;
    memcpy(value, cachedValue, cachedValueSize);
    munmap(cacheEntry, entrySize);
    close(fd);

    ALOGD("Read %zu bytes from %s", cachedValueSize, filename.c_str());
    return cachedValueSize;
}

// Walk through the files in our flat directory, checking the size of each one.
// Return the total size of normal files in the directory.
// This will need to be updated if we move to a multilevel cache dir.
size_t getMultifileCacheSize() {
    if (multifileDirName.empty()) {
        return 0;
    }

    DIR* dir;
    struct dirent* entry;
    size_t size = 0;

    ALOGD("Using %s as the multifile cache dir ", multifileDirName.c_str());

    if ((dir = opendir(multifileDirName.c_str())) != nullptr) {
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name == "."s || entry->d_name == ".."s) {
                continue;
            }

            // Add up the size of all files in the dir
            std::string fullPath = multifileDirName + "/" + entry->d_name;
            size += getFileSize(fullPath);
        }
        closedir(dir);
    } else {
        ALOGW("Unable to open filename: %s", multifileDirName.c_str());
        return 0;
    }

    return size;
}

// When removing files, what fraction of the overall limit should be reached when removing files
// A divisor of two will decrease the cache to 50%, four to 25% and so on
constexpr uint32_t kCacheLimitDivisor = 2;

// During rollout and dogfood, limit the max cache size to mitigate risk
constexpr size_t kCacheByteLimit = 64 * 1024 * 1024;

// Calculate the cache size and remove old entries until under the limit
void checkMultifileCacheSize(size_t cacheByteLimit) {
    // Start with the value provided by egl_cache
    size_t limit = cacheByteLimit;

    // Check for a value provided by GraphicsEnvironment
    int64_t cacheQuotaBytes = android::GraphicsEnv::getInstance().getBlobCacheQuotaBytes();
    if (cacheQuotaBytes > 0) {
        ALOGD("Overriding cache limit %zu with %" PRId64 " from getBlobCacheQuotaBytes", limit,
              cacheQuotaBytes);
        limit = static_cast<size_t>(cacheQuotaBytes);

        ALOGV("Limiting blob cache quota size (%zu) to %zu", limit, kCacheByteLimit);
        limit = std::min(limit, kCacheByteLimit);
    }

    // Check for a debug value
    int debugCacheSize = base::GetIntProperty("debug.egl.blobcache.bytelimit", -1);
    if (debugCacheSize >= 0) {
        ALOGV("Overriding cache limit %zu with %i from debug.egl.blobcache.bytelimit", limit,
              debugCacheSize);
        limit = debugCacheSize;
    }

    // Tally up the initial amount of cache in use
    size_t size = getMultifileCacheSize();
    ALOGD("Multifile cache dir size: %zu", size);

    // If size is larger than the threshold, remove files using LRU
    if (size > limit) {
        ALOGV("Multifile cache size is larger than %zu, removing old entries", cacheByteLimit);
        if (!applyLRU(limit / kCacheLimitDivisor)) {
            ALOGE("Error when clearing multifile shader cache");
            return;
        }
    }
    ALOGD("Multifile cache size after reduction: %zu", getMultifileCacheSize());
}

}; // namespace android