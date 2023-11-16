/*
 ** Copyright 2023, The Android Open Source Project
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

#include "MultifileBlobCache.h"

#include <android-base/properties.h>
#include <android-base/test_utils.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <stdio.h>

#include <fstream>
#include <memory>

using namespace std::literals;

namespace android {

template <typename T>
using sp = std::shared_ptr<T>;

constexpr size_t kMaxKeySize = 2 * 1024;
constexpr size_t kMaxValueSize = 6 * 1024;
constexpr size_t kMaxTotalSize = 32 * 1024;
constexpr size_t kMaxTotalEntries = 64;

class MultifileBlobCacheTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        clearProperties();
        mTempFile.reset(new TemporaryFile());
        mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize,
                                          kMaxTotalEntries, &mTempFile->path[0]));
    }

    virtual void TearDown() {
        clearProperties();
        mMBC.reset();
    }

    int getFileDescriptorCount();
    std::vector<std::string> getCacheEntries();

    void clearProperties();

    std::unique_ptr<TemporaryFile> mTempFile;
    std::unique_ptr<MultifileBlobCache> mMBC;
};

void MultifileBlobCacheTest::clearProperties() {
    // Clear any debug properties used in the tests
    base::SetProperty("debug.egl.blobcache.cache_version", "");
    base::WaitForProperty("debug.egl.blobcache.cache_version", "");

    base::SetProperty("debug.egl.blobcache.build_id", "");
    base::WaitForProperty("debug.egl.blobcache.build_id", "");
}

TEST_F(MultifileBlobCacheTest, CacheSingleValueSucceeds) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    mMBC->set("abcd", 4, "efgh", 4);
    ASSERT_EQ(size_t(4), mMBC->get("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);
}

TEST_F(MultifileBlobCacheTest, CacheTwoValuesSucceeds) {
    unsigned char buf[2] = {0xee, 0xee};
    mMBC->set("ab", 2, "cd", 2);
    mMBC->set("ef", 2, "gh", 2);
    ASSERT_EQ(size_t(2), mMBC->get("ab", 2, buf, 2));
    ASSERT_EQ('c', buf[0]);
    ASSERT_EQ('d', buf[1]);
    ASSERT_EQ(size_t(2), mMBC->get("ef", 2, buf, 2));
    ASSERT_EQ('g', buf[0]);
    ASSERT_EQ('h', buf[1]);
}

TEST_F(MultifileBlobCacheTest, GetSetTwiceSucceeds) {
    unsigned char buf[2] = {0xee, 0xee};
    mMBC->set("ab", 2, "cd", 2);
    ASSERT_EQ(size_t(2), mMBC->get("ab", 2, buf, 2));
    ASSERT_EQ('c', buf[0]);
    ASSERT_EQ('d', buf[1]);
    // Use the same key, but different value
    mMBC->set("ab", 2, "ef", 2);
    ASSERT_EQ(size_t(2), mMBC->get("ab", 2, buf, 2));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
}

TEST_F(MultifileBlobCacheTest, GetOnlyWritesInsideBounds) {
    unsigned char buf[6] = {0xee, 0xee, 0xee, 0xee, 0xee, 0xee};
    mMBC->set("abcd", 4, "efgh", 4);
    ASSERT_EQ(size_t(4), mMBC->get("abcd", 4, buf + 1, 4));
    ASSERT_EQ(0xee, buf[0]);
    ASSERT_EQ('e', buf[1]);
    ASSERT_EQ('f', buf[2]);
    ASSERT_EQ('g', buf[3]);
    ASSERT_EQ('h', buf[4]);
    ASSERT_EQ(0xee, buf[5]);
}

TEST_F(MultifileBlobCacheTest, GetOnlyWritesIfBufferIsLargeEnough) {
    unsigned char buf[3] = {0xee, 0xee, 0xee};
    mMBC->set("abcd", 4, "efgh", 4);
    ASSERT_EQ(size_t(4), mMBC->get("abcd", 4, buf, 3));
    ASSERT_EQ(0xee, buf[0]);
    ASSERT_EQ(0xee, buf[1]);
    ASSERT_EQ(0xee, buf[2]);
}

TEST_F(MultifileBlobCacheTest, GetDoesntAccessNullBuffer) {
    mMBC->set("abcd", 4, "efgh", 4);
    ASSERT_EQ(size_t(4), mMBC->get("abcd", 4, nullptr, 0));
}

TEST_F(MultifileBlobCacheTest, MultipleSetsCacheLatestValue) {
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    mMBC->set("abcd", 4, "efgh", 4);
    mMBC->set("abcd", 4, "ijkl", 4);
    ASSERT_EQ(size_t(4), mMBC->get("abcd", 4, buf, 4));
    ASSERT_EQ('i', buf[0]);
    ASSERT_EQ('j', buf[1]);
    ASSERT_EQ('k', buf[2]);
    ASSERT_EQ('l', buf[3]);
}

TEST_F(MultifileBlobCacheTest, SecondSetKeepsFirstValueIfTooLarge) {
    unsigned char buf[kMaxValueSize + 1] = {0xee, 0xee, 0xee, 0xee};
    mMBC->set("abcd", 4, "efgh", 4);
    mMBC->set("abcd", 4, buf, kMaxValueSize + 1);
    ASSERT_EQ(size_t(4), mMBC->get("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);
}

TEST_F(MultifileBlobCacheTest, DoesntCacheIfKeyIsTooBig) {
    char key[kMaxKeySize + 1];
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    for (int i = 0; i < kMaxKeySize + 1; i++) {
        key[i] = 'a';
    }
    mMBC->set(key, kMaxKeySize + 1, "bbbb", 4);
    ASSERT_EQ(size_t(0), mMBC->get(key, kMaxKeySize + 1, buf, 4));
    ASSERT_EQ(0xee, buf[0]);
    ASSERT_EQ(0xee, buf[1]);
    ASSERT_EQ(0xee, buf[2]);
    ASSERT_EQ(0xee, buf[3]);
}

TEST_F(MultifileBlobCacheTest, DoesntCacheIfValueIsTooBig) {
    char buf[kMaxValueSize + 1];
    for (int i = 0; i < kMaxValueSize + 1; i++) {
        buf[i] = 'b';
    }
    mMBC->set("abcd", 4, buf, kMaxValueSize + 1);
    for (int i = 0; i < kMaxValueSize + 1; i++) {
        buf[i] = 0xee;
    }
    ASSERT_EQ(size_t(0), mMBC->get("abcd", 4, buf, kMaxValueSize + 1));
    for (int i = 0; i < kMaxValueSize + 1; i++) {
        SCOPED_TRACE(i);
        ASSERT_EQ(0xee, buf[i]);
    }
}

TEST_F(MultifileBlobCacheTest, CacheMaxKeySizeSucceeds) {
    char key[kMaxKeySize];
    unsigned char buf[4] = {0xee, 0xee, 0xee, 0xee};
    for (int i = 0; i < kMaxKeySize; i++) {
        key[i] = 'a';
    }
    mMBC->set(key, kMaxKeySize, "wxyz", 4);
    ASSERT_EQ(size_t(4), mMBC->get(key, kMaxKeySize, buf, 4));
    ASSERT_EQ('w', buf[0]);
    ASSERT_EQ('x', buf[1]);
    ASSERT_EQ('y', buf[2]);
    ASSERT_EQ('z', buf[3]);
}

TEST_F(MultifileBlobCacheTest, CacheMaxValueSizeSucceeds) {
    char buf[kMaxValueSize];
    for (int i = 0; i < kMaxValueSize; i++) {
        buf[i] = 'b';
    }
    mMBC->set("abcd", 4, buf, kMaxValueSize);
    for (int i = 0; i < kMaxValueSize; i++) {
        buf[i] = 0xee;
    }
    mMBC->get("abcd", 4, buf, kMaxValueSize);
    for (int i = 0; i < kMaxValueSize; i++) {
        SCOPED_TRACE(i);
        ASSERT_EQ('b', buf[i]);
    }
}

TEST_F(MultifileBlobCacheTest, CacheMaxKeyAndValueSizeSucceeds) {
    char key[kMaxKeySize];
    for (int i = 0; i < kMaxKeySize; i++) {
        key[i] = 'a';
    }
    char buf[kMaxValueSize];
    for (int i = 0; i < kMaxValueSize; i++) {
        buf[i] = 'b';
    }
    mMBC->set(key, kMaxKeySize, buf, kMaxValueSize);
    for (int i = 0; i < kMaxValueSize; i++) {
        buf[i] = 0xee;
    }
    mMBC->get(key, kMaxKeySize, buf, kMaxValueSize);
    for (int i = 0; i < kMaxValueSize; i++) {
        SCOPED_TRACE(i);
        ASSERT_EQ('b', buf[i]);
    }
}

TEST_F(MultifileBlobCacheTest, CacheMaxEntrySucceeds) {
    // Fill the cache with max entries
    int i = 0;
    for (i = 0; i < kMaxTotalEntries; i++) {
        mMBC->set(std::to_string(i).c_str(), sizeof(i), std::to_string(i).c_str(), sizeof(i));
    }

    // Ensure it is full
    ASSERT_EQ(mMBC->getTotalEntries(), kMaxTotalEntries);

    // Add another entry
    mMBC->set(std::to_string(i).c_str(), sizeof(i), std::to_string(i).c_str(), sizeof(i));

    // Ensure total entries is cut in half + 1
    ASSERT_EQ(mMBC->getTotalEntries(), kMaxTotalEntries / 2 + 1);
}

TEST_F(MultifileBlobCacheTest, CacheMinKeyAndValueSizeSucceeds) {
    unsigned char buf[1] = {0xee};
    mMBC->set("x", 1, "y", 1);
    ASSERT_EQ(size_t(1), mMBC->get("x", 1, buf, 1));
    ASSERT_EQ('y', buf[0]);
}

int MultifileBlobCacheTest::getFileDescriptorCount() {
    DIR* directory = opendir("/proc/self/fd");

    int fileCount = 0;
    struct dirent* entry;
    while ((entry = readdir(directory)) != NULL) {
        fileCount++;
        // printf("File: %s\n", entry->d_name);
    }

    closedir(directory);
    return fileCount;
}

TEST_F(MultifileBlobCacheTest, EnsureFileDescriptorsClosed) {
    // Populate the cache with a bunch of entries
    for (int i = 0; i < kMaxTotalEntries; i++) {
        // printf("Caching: %i", i);

        // Use the index as the key and value
        mMBC->set(&i, sizeof(i), &i, sizeof(i));

        int result = 0;
        ASSERT_EQ(sizeof(i), mMBC->get(&i, sizeof(i), &result, sizeof(result)));
        ASSERT_EQ(i, result);
    }

    // Ensure we don't have a bunch of open fds
    ASSERT_LT(getFileDescriptorCount(), kMaxTotalEntries / 2);

    // Close the cache so everything writes out
    mMBC->finish();
    mMBC.reset();

    // Now open it again and ensure we still don't have a bunch of open fds
    mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                      &mTempFile->path[0]));

    // Check after initialization
    ASSERT_LT(getFileDescriptorCount(), kMaxTotalEntries / 2);

    for (int i = 0; i < kMaxTotalEntries; i++) {
        int result = 0;
        ASSERT_EQ(sizeof(i), mMBC->get(&i, sizeof(i), &result, sizeof(result)));
        ASSERT_EQ(i, result);
    }

    // And again after we've actually used it
    ASSERT_LT(getFileDescriptorCount(), kMaxTotalEntries / 2);
}

std::vector<std::string> MultifileBlobCacheTest::getCacheEntries() {
    std::string cachePath = &mTempFile->path[0];
    std::string multifileDirName = cachePath + ".multifile";
    std::vector<std::string> cacheEntries;

    struct stat info;
    if (stat(multifileDirName.c_str(), &info) == 0) {
        // We have a multifile dir. Skip the status file and return the only entry.
        DIR* dir;
        struct dirent* entry;
        if ((dir = opendir(multifileDirName.c_str())) != nullptr) {
            while ((entry = readdir(dir)) != nullptr) {
                if (entry->d_name == "."s || entry->d_name == ".."s) {
                    continue;
                }
                if (strcmp(entry->d_name, kMultifileBlobCacheStatusFile) == 0) {
                    continue;
                }
                cacheEntries.push_back(multifileDirName + "/" + entry->d_name);
            }
        } else {
            printf("Unable to open %s, error: %s\n", multifileDirName.c_str(),
                   std::strerror(errno));
        }
    } else {
        printf("Unable to stat %s, error: %s\n", multifileDirName.c_str(), std::strerror(errno));
    }

    return cacheEntries;
}

TEST_F(MultifileBlobCacheTest, CacheContainsStatus) {
    struct stat info;
    std::stringstream statusFile;
    statusFile << &mTempFile->path[0] << ".multifile/" << kMultifileBlobCacheStatusFile;

    // After INIT, cache should have a status
    ASSERT_TRUE(stat(statusFile.str().c_str(), &info) == 0);

    // Set one entry
    mMBC->set("abcd", 4, "efgh", 4);

    // Close the cache so everything writes out
    mMBC->finish();
    mMBC.reset();

    // Ensure status lives after closing the cache
    ASSERT_TRUE(stat(statusFile.str().c_str(), &info) == 0);

    // Open the cache again
    mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                      &mTempFile->path[0]));

    // Ensure we still have a status
    ASSERT_TRUE(stat(statusFile.str().c_str(), &info) == 0);
}

// Verify missing cache status file causes cache the be cleared
TEST_F(MultifileBlobCacheTest, MissingCacheStatusClears) {
    // Set one entry
    mMBC->set("abcd", 4, "efgh", 4);

    // Close the cache so everything writes out
    mMBC->finish();
    mMBC.reset();

    // Ensure there is one cache entry
    ASSERT_EQ(getCacheEntries().size(), 1);

    // Delete the status file
    std::stringstream statusFile;
    statusFile << &mTempFile->path[0] << ".multifile/" << kMultifileBlobCacheStatusFile;
    remove(statusFile.str().c_str());

    // Open the cache again and ensure no cache hits
    mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                      &mTempFile->path[0]));

    // Ensure we have no entries
    ASSERT_EQ(getCacheEntries().size(), 0);
}

// Verify modified cache status file BEGIN causes cache to be cleared
TEST_F(MultifileBlobCacheTest, ModifiedCacheStatusBeginClears) {
    // Set one entry
    mMBC->set("abcd", 4, "efgh", 4);

    // Close the cache so everything writes out
    mMBC->finish();
    mMBC.reset();

    // Ensure there is one cache entry
    ASSERT_EQ(getCacheEntries().size(), 1);

    // Modify the status file
    std::stringstream statusFile;
    statusFile << &mTempFile->path[0] << ".multifile/" << kMultifileBlobCacheStatusFile;

    // Stomp on the beginning of the cache file
    const char* stomp = "BADF00D";
    std::fstream fs(statusFile.str());
    fs.seekp(0, std::ios_base::beg);
    fs.write(stomp, strlen(stomp));
    fs.flush();
    fs.close();

    // Open the cache again and ensure no cache hits
    mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                      &mTempFile->path[0]));

    // Ensure we have no entries
    ASSERT_EQ(getCacheEntries().size(), 0);
}

// Verify modified cache status file END causes cache to be cleared
TEST_F(MultifileBlobCacheTest, ModifiedCacheStatusEndClears) {
    // Set one entry
    mMBC->set("abcd", 4, "efgh", 4);

    // Close the cache so everything writes out
    mMBC->finish();
    mMBC.reset();

    // Ensure there is one cache entry
    ASSERT_EQ(getCacheEntries().size(), 1);

    // Modify the status file
    std::stringstream statusFile;
    statusFile << &mTempFile->path[0] << ".multifile/" << kMultifileBlobCacheStatusFile;

    // Stomp on the END of the cache status file, modifying its contents
    const char* stomp = "BADF00D";
    std::fstream fs(statusFile.str());
    fs.seekp(-strlen(stomp), std::ios_base::end);
    fs.write(stomp, strlen(stomp));
    fs.flush();
    fs.close();

    // Open the cache again and ensure no cache hits
    mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                      &mTempFile->path[0]));

    // Ensure we have no entries
    ASSERT_EQ(getCacheEntries().size(), 0);
}

// Verify mismatched cacheVersion causes cache to be cleared
TEST_F(MultifileBlobCacheTest, MismatchedCacheVersionClears) {
    // Set one entry
    mMBC->set("abcd", 4, "efgh", 4);

    // Close the cache so everything writes out
    mMBC->finish();
    mMBC.reset();

    // Ensure there is one cache entry
    ASSERT_EQ(getCacheEntries().size(), 1);

    // Set a debug cacheVersion
    std::string newCacheVersion = std::to_string(kMultifileBlobCacheVersion + 1);
    ASSERT_TRUE(base::SetProperty("debug.egl.blobcache.cache_version", newCacheVersion.c_str()));
    ASSERT_TRUE(
            base::WaitForProperty("debug.egl.blobcache.cache_version", newCacheVersion.c_str()));

    // Open the cache again and ensure no cache hits
    mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                      &mTempFile->path[0]));

    // Ensure we have no entries
    ASSERT_EQ(getCacheEntries().size(), 0);
}

// Verify mismatched buildId causes cache to be cleared
TEST_F(MultifileBlobCacheTest, MismatchedBuildIdClears) {
    // Set one entry
    mMBC->set("abcd", 4, "efgh", 4);

    // Close the cache so everything writes out
    mMBC->finish();
    mMBC.reset();

    // Ensure there is one cache entry
    ASSERT_EQ(getCacheEntries().size(), 1);

    // Set a debug buildId
    base::SetProperty("debug.egl.blobcache.build_id", "foo");
    base::WaitForProperty("debug.egl.blobcache.build_id", "foo");

    // Open the cache again and ensure no cache hits
    mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                      &mTempFile->path[0]));

    // Ensure we have no entries
    ASSERT_EQ(getCacheEntries().size(), 0);
}

} // namespace android
