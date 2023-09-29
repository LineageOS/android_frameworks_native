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

#include <android-base/test_utils.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <stdio.h>

#include <memory>

namespace android {

template <typename T>
using sp = std::shared_ptr<T>;

constexpr size_t kMaxKeySize = 2 * 1024;
constexpr size_t kMaxValueSize = 6 * 1024;
constexpr size_t kMaxTotalSize = 32 * 1024;

class MultifileBlobCacheTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        mTempFile.reset(new TemporaryFile());
        mMBC.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize,
                                          &mTempFile->path[0]));
    }

    virtual void TearDown() { mMBC.reset(); }

    int getFileDescriptorCount();

    std::unique_ptr<TemporaryFile> mTempFile;
    std::unique_ptr<MultifileBlobCache> mMBC;
};

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
    size_t kLargeNumberOfEntries = 1024;
    for (int i = 0; i < kLargeNumberOfEntries; i++) {
        // printf("Caching: %i", i);

        // Use the index as the key and value
        mMBC->set(&i, sizeof(i), &i, sizeof(i));

        int result = 0;
        ASSERT_EQ(sizeof(i), mMBC->get(&i, sizeof(i), &result, sizeof(result)));
        ASSERT_EQ(i, result);
    }

    // Ensure we don't have a bunch of open fds
    ASSERT_LT(getFileDescriptorCount(), kLargeNumberOfEntries / 2);

    // Close the cache so everything writes out
    mMBC->finish();
    mMBC.reset();

    // Now open it again and ensure we still don't have a bunch of open fds
    mMBC.reset(
            new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, &mTempFile->path[0]));

    // Check after initialization
    ASSERT_LT(getFileDescriptorCount(), kLargeNumberOfEntries / 2);

    for (int i = 0; i < kLargeNumberOfEntries; i++) {
        int result = 0;
        ASSERT_EQ(sizeof(i), mMBC->get(&i, sizeof(i), &result, sizeof(result)));
        ASSERT_EQ(i, result);
    }

    // And again after we've actually used it
    ASSERT_LT(getFileDescriptorCount(), kLargeNumberOfEntries / 2);
}

} // namespace android
