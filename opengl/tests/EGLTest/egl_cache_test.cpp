/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "EGL_test"
// #define LOG_NDEBUG 0

#include <gtest/gtest.h>

#include <utils/Log.h>

#include <android-base/test_utils.h>

#include "egl_cache.h"
#include "MultifileBlobCache.h"
#include "egl_display.h"

#include <fstream>
#include <memory>

using namespace std::literals;

namespace android {

class EGLCacheTest : public ::testing::TestWithParam<egl_cache_t::EGLCacheMode> {
protected:
    virtual void SetUp() {
        // Terminate to clean up any previous cache in this process
        mCache->terminate();

        mTempFile.reset(new TemporaryFile());
        mCache->setCacheFilename(&mTempFile->path[0]);
        mCache->setCacheLimit(1024);
        mCache->setCacheMode(mCacheMode);
    }

    virtual void TearDown() {
        mCache->terminate();
        mCache->setCacheFilename("");
        mTempFile.reset(nullptr);
    }

    std::string getCachefileName();

    egl_cache_t* mCache = egl_cache_t::get();
    std::unique_ptr<TemporaryFile> mTempFile;
    egl_cache_t::EGLCacheMode mCacheMode = GetParam();
};

TEST_P(EGLCacheTest, UninitializedCacheAlwaysMisses) {
    uint8_t buf[4] = { 0xee, 0xee, 0xee, 0xee };
    mCache->setBlob("abcd", 4, "efgh", 4);
    ASSERT_EQ(0, mCache->getBlob("abcd", 4, buf, 4));
    ASSERT_EQ(0xee, buf[0]);
    ASSERT_EQ(0xee, buf[1]);
    ASSERT_EQ(0xee, buf[2]);
    ASSERT_EQ(0xee, buf[3]);
}

TEST_P(EGLCacheTest, InitializedCacheAlwaysHits) {
    uint8_t buf[4] = { 0xee, 0xee, 0xee, 0xee };
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));
    mCache->setBlob("abcd", 4, "efgh", 4);
    ASSERT_EQ(4, mCache->getBlob("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);
}

TEST_P(EGLCacheTest, TerminatedCacheAlwaysMisses) {
    uint8_t buf[4] = { 0xee, 0xee, 0xee, 0xee };
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));
    mCache->setBlob("abcd", 4, "efgh", 4);
    mCache->terminate();
    ASSERT_EQ(0, mCache->getBlob("abcd", 4, buf, 4));
    ASSERT_EQ(0xee, buf[0]);
    ASSERT_EQ(0xee, buf[1]);
    ASSERT_EQ(0xee, buf[2]);
    ASSERT_EQ(0xee, buf[3]);
}

TEST_P(EGLCacheTest, ReinitializedCacheContainsValues) {
    uint8_t buf[4] = { 0xee, 0xee, 0xee, 0xee };
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));
    mCache->setBlob("abcd", 4, "efgh", 4);
    mCache->terminate();
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));
    ASSERT_EQ(4, mCache->getBlob("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);
}

std::string EGLCacheTest::getCachefileName() {
    // Return the monolithic filename unless we find the multifile dir
    std::string cachePath = &mTempFile->path[0];
    std::string multifileDirName = cachePath + ".multifile";
    std::string cachefileName = "";

    struct stat info;
    if (stat(multifileDirName.c_str(), &info) == 0) {
        // Ensure we only have one file to manage
        int entryFileCount = 0;

        // We have a multifile dir. Return the only entry file in it.
        DIR* dir;
        struct dirent* entry;
        if ((dir = opendir(multifileDirName.c_str())) != nullptr) {
            while ((entry = readdir(dir)) != nullptr) {
                if (entry->d_name == "."s || entry->d_name == ".."s ||
                    strcmp(entry->d_name, kMultifileBlobCacheStatusFile) == 0) {
                    continue;
                }
                cachefileName = multifileDirName + "/" + entry->d_name;
                entryFileCount++;
            }
        } else {
            printf("Unable to open %s, error: %s\n",
                   multifileDirName.c_str(), std::strerror(errno));
        }

        if (entryFileCount != 1) {
            // If there was more than one real file in the directory, this
            // violates test assumptions
            cachefileName = "";
        }
    } else {
        printf("Unable to stat %s, error: %s\n",
               multifileDirName.c_str(), std::strerror(errno));
    }

    return cachefileName;
}

TEST_P(EGLCacheTest, ModifiedCacheBeginMisses) {
    // Skip if not in multifile mode
    if (mCacheMode == egl_cache_t::EGLCacheMode::Monolithic) {
        GTEST_SKIP() << "Skipping test designed for multifile";
    }

    uint8_t buf[4] = { 0xee, 0xee, 0xee, 0xee };
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));

    mCache->setBlob("abcd", 4, "efgh", 4);
    ASSERT_EQ(4, mCache->getBlob("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);

    // Ensure the cache file is written to disk
    mCache->terminate();

    // Depending on the cache mode, the file will be in different locations
    std::string cachefileName = getCachefileName();
    ASSERT_TRUE(cachefileName.length() > 0);

    // Stomp on the beginning of the cache file, breaking the key match
    const char* stomp = "BADF00D";
    std::fstream fs(cachefileName);
    fs.seekp(0, std::ios_base::beg);
    fs.write(stomp, strlen(stomp));
    fs.flush();
    fs.close();

    // Ensure no cache hit
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));
    uint8_t buf2[4] = { 0xee, 0xee, 0xee, 0xee };
    // getBlob may return junk for required size, but should not return a cache hit
    mCache->getBlob("abcd", 4, buf2, 4);
    ASSERT_EQ(0xee, buf2[0]);
    ASSERT_EQ(0xee, buf2[1]);
    ASSERT_EQ(0xee, buf2[2]);
    ASSERT_EQ(0xee, buf2[3]);
}

TEST_P(EGLCacheTest, ModifiedCacheEndMisses) {
    // Skip if not in multifile mode
    if (mCacheMode == egl_cache_t::EGLCacheMode::Monolithic) {
        GTEST_SKIP() << "Skipping test designed for multifile";
    }

    uint8_t buf[16] = { 0xee, 0xee, 0xee, 0xee,
                        0xee, 0xee, 0xee, 0xee,
                        0xee, 0xee, 0xee, 0xee,
                        0xee, 0xee, 0xee, 0xee };

    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));

    mCache->setBlob("abcdefghij", 10, "klmnopqrstuvwxyz", 16);
    ASSERT_EQ(16, mCache->getBlob("abcdefghij", 10, buf, 16));
    ASSERT_EQ('w', buf[12]);
    ASSERT_EQ('x', buf[13]);
    ASSERT_EQ('y', buf[14]);
    ASSERT_EQ('z', buf[15]);

    // Ensure the cache file is written to disk
    mCache->terminate();

    // Depending on the cache mode, the file will be in different locations
    std::string cachefileName = getCachefileName();
    ASSERT_TRUE(cachefileName.length() > 0);

    // Stomp on the END of the cache file, modifying its contents
    const char* stomp = "BADF00D";
    std::fstream fs(cachefileName);
    fs.seekp(-strlen(stomp), std::ios_base::end);
    fs.write(stomp, strlen(stomp));
    fs.flush();
    fs.close();

    // Ensure no cache hit
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));
    uint8_t buf2[16] = { 0xee, 0xee, 0xee, 0xee,
                         0xee, 0xee, 0xee, 0xee,
                         0xee, 0xee, 0xee, 0xee,
                         0xee, 0xee, 0xee, 0xee };

    // getBlob may return junk for required size, but should not return a cache hit
    mCache->getBlob("abcdefghij", 10, buf2, 16);
    ASSERT_EQ(0xee, buf2[0]);
    ASSERT_EQ(0xee, buf2[1]);
    ASSERT_EQ(0xee, buf2[2]);
    ASSERT_EQ(0xee, buf2[3]);
}

TEST_P(EGLCacheTest, TerminatedCacheBelowCacheLimit) {
    uint8_t buf[4] = { 0xee, 0xee, 0xee, 0xee };
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));

    mCache->setBlob("abcd", 4, "efgh", 4);
    ASSERT_EQ(4, mCache->getBlob("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);

    mCache->setBlob("ijkl", 4, "mnop", 4);
    ASSERT_EQ(4, mCache->getBlob("ijkl", 4, buf, 4));
    ASSERT_EQ('m', buf[0]);
    ASSERT_EQ('n', buf[1]);
    ASSERT_EQ('o', buf[2]);
    ASSERT_EQ('p', buf[3]);

    mCache->setBlob("qrst", 4, "uvwx", 4);
    ASSERT_EQ(4, mCache->getBlob("qrst", 4, buf, 4));
    ASSERT_EQ('u', buf[0]);
    ASSERT_EQ('v', buf[1]);
    ASSERT_EQ('w', buf[2]);
    ASSERT_EQ('x', buf[3]);

    // Cache should contain both the key and the value
    // So 8 bytes per entry, at least 24 bytes
    ASSERT_GE(mCache->getCacheSize(), 24);

    // Set the new limit and initialize cache
    mCache->terminate();
    mCache->setCacheLimit(4);
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));

    // Ensure the new limit is respected
    ASSERT_LE(mCache->getCacheSize(), 4);
}

TEST_P(EGLCacheTest, TrimCacheOnOverflow) {
    // Skip if not in multifile mode
    if (mCacheMode == egl_cache_t::EGLCacheMode::Monolithic) {
        GTEST_SKIP() << "Skipping test designed for multifile";
    }

    uint8_t buf[4] = { 0xee, 0xee, 0xee, 0xee };
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));

    // Set one value in the cache
    mCache->setBlob("abcd", 4, "efgh", 4);
    ASSERT_EQ(4, mCache->getBlob("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);

    // Get the size of cache with a single entry
    size_t cacheEntrySize = mCache->getCacheSize();

    // Now reinitialize the cache, using max size equal to a single entry
    mCache->terminate();
    mCache->setCacheLimit(cacheEntrySize);
    mCache->initialize(egl_display_t::get(EGL_DEFAULT_DISPLAY));

    // Ensure our cache still has original value
    ASSERT_EQ(4, mCache->getBlob("abcd", 4, buf, 4));
    ASSERT_EQ('e', buf[0]);
    ASSERT_EQ('f', buf[1]);
    ASSERT_EQ('g', buf[2]);
    ASSERT_EQ('h', buf[3]);

    // Set another value, which should overflow the cache and trim
    mCache->setBlob("ijkl", 4, "mnop", 4);
    ASSERT_EQ(4, mCache->getBlob("ijkl", 4, buf, 4));
    ASSERT_EQ('m', buf[0]);
    ASSERT_EQ('n', buf[1]);
    ASSERT_EQ('o', buf[2]);
    ASSERT_EQ('p', buf[3]);

    // The cache should still be under the limit
    ASSERT_TRUE(mCache->getCacheSize() == cacheEntrySize);

    // And no cache hit on trimmed entry
    uint8_t buf2[4] = { 0xee, 0xee, 0xee, 0xee };
    mCache->getBlob("abcd", 4, buf2, 4);
    ASSERT_EQ(0xee, buf2[0]);
    ASSERT_EQ(0xee, buf2[1]);
    ASSERT_EQ(0xee, buf2[2]);
    ASSERT_EQ(0xee, buf2[3]);
}

INSTANTIATE_TEST_CASE_P(MonolithicCacheTests,
        EGLCacheTest, ::testing::Values(egl_cache_t::EGLCacheMode::Monolithic));
INSTANTIATE_TEST_CASE_P(MultifileCacheTests,
        EGLCacheTest, ::testing::Values(egl_cache_t::EGLCacheMode::Multifile));
}
