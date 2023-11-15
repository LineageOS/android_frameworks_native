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
#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

namespace android {

constexpr size_t kMaxKeySize = 2 * 1024;
constexpr size_t kMaxValueSize = 6 * 1024;
constexpr size_t kMaxTotalSize = 32 * 1024;
constexpr size_t kMaxTotalEntries = 64;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // To fuzz this, we're going to create a key/value pair from data
    // and use them with MultifileBlobCache in a random order
    // - Use the first entry in data to determine keySize
    // - Use the second entry in data to determine valueSize
    // - Mod each of them against half the remaining size, ensuring both fit
    // - Create key and value using sizes from data
    // - Use remaining data to switch between GET and SET while
    //   tweaking the keys slightly
    // - Ensure two cache cleaning scenarios are hit at the end

    // Ensure we have enough data to create interesting key/value pairs
    size_t kMinInputLength = 128;
    if (size < kMinInputLength) {
        return 0;
    }

    // Need non-zero sizes for interesting results
    if (data[0] == 0 || data[1] == 0) {
        return 0;
    }

    // We need to divide the data up into buffers and sizes
    FuzzedDataProvider fdp(data, size);

    // Pull two values from data for key and value size
    EGLsizeiANDROID keySize = static_cast<EGLsizeiANDROID>(fdp.ConsumeIntegral<uint8_t>());
    EGLsizeiANDROID valueSize = static_cast<EGLsizeiANDROID>(fdp.ConsumeIntegral<uint8_t>());
    size -= 2 * sizeof(uint8_t);

    // Ensure key and value fit in the remaining space (cap them at half data size)
    keySize = keySize % (size >> 1);
    valueSize = valueSize % (size >> 1);

    // If either size ended up zero, just move on to save time
    if (keySize == 0 || valueSize == 0) {
        return 0;
    }

    // Create key and value from remaining data
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
    key = fdp.ConsumeBytes<uint8_t>(keySize);
    value = fdp.ConsumeBytes<uint8_t>(valueSize);

    // Create a tempfile and a cache
    std::unique_ptr<TemporaryFile> tempFile;
    std::unique_ptr<MultifileBlobCache> mbc;

    tempFile.reset(new TemporaryFile());
    mbc.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                     &tempFile->path[0]));
    // With remaining data, select different paths below
    int loopCount = 1;
    uint8_t bumpCount = 0;
    while (fdp.remaining_bytes() > 0) {
        // Bounce back and forth between gets and sets
        if (fdp.ConsumeBool()) {
            mbc->set(key.data(), keySize, value.data(), valueSize);
        } else {
            uint8_t* buffer = new uint8_t[valueSize];
            mbc->get(key.data(), keySize, buffer, valueSize);
            delete[] buffer;
        }

        // Bump the key and values periodically, causing different hits/misses
        if (fdp.ConsumeBool()) {
            key[0]++;
            value[0]++;
            bumpCount++;
        }

        // Reset the key and value periodically to hit old entries
        if (fdp.ConsumeBool()) {
            key[0] -= bumpCount;
            value[0] -= bumpCount;
            bumpCount = 0;
        }

        loopCount++;
    }
    mbc->finish();

    // Fill 2 keys and 2 values to max size with unique values
    std::vector<uint8_t> maxKey1, maxKey2, maxValue1, maxValue2;
    maxKey1.resize(kMaxKeySize, 0);
    maxKey2.resize(kMaxKeySize, 0);
    maxValue1.resize(kMaxValueSize, 0);
    maxValue2.resize(kMaxValueSize, 0);
    for (int i = 0; i < keySize && i < kMaxKeySize; ++i) {
        maxKey1[i] = key[i];
        maxKey2[i] = key[i] - 1;
    }
    for (int i = 0; i < valueSize && i < kMaxValueSize; ++i) {
        maxValue1[i] = value[i];
        maxValue2[i] = value[i] - 1;
    }

    // Trigger hot cache trimming
    // Place the maxKey/maxValue twice
    // The first will fit, the second will trigger hot cache trimming
    tempFile.reset(new TemporaryFile());
    mbc.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, kMaxTotalSize, kMaxTotalEntries,
                                     &tempFile->path[0]));
    uint8_t* buffer = new uint8_t[kMaxValueSize];
    mbc->set(maxKey1.data(), kMaxKeySize, maxValue1.data(), kMaxValueSize);
    mbc->set(maxKey2.data(), kMaxKeySize, maxValue2.data(), kMaxValueSize);
    mbc->get(maxKey1.data(), kMaxKeySize, buffer, kMaxValueSize);
    mbc->finish();

    // Trigger cold cache trimming
    // Create a total size small enough only one entry fits
    // Since the cache will add a header, 2 * key + value will only hold one value, the second will
    // overflow
    tempFile.reset(new TemporaryFile());
    mbc.reset(new MultifileBlobCache(kMaxKeySize, kMaxValueSize, 2 * (kMaxKeySize + kMaxValueSize),
                                     kMaxTotalEntries, &tempFile->path[0]));
    mbc->set(maxKey1.data(), kMaxKeySize, maxValue1.data(), kMaxValueSize);
    mbc->set(maxKey2.data(), kMaxKeySize, maxValue2.data(), kMaxValueSize);
    mbc->get(maxKey1.data(), kMaxKeySize, buffer, kMaxValueSize);
    mbc->finish();

    delete[] buffer;
    return 0;
}

} // namespace android
