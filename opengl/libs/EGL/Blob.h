/*
 ** Copyright 2015, The Android Open Source Project
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

#ifndef ANDROID_BLOB_H
#define ANDROID_BLOB_H

#include <stddef.h>

#include <utils/JenkinsHash.h>

#include <functional>
#include <log/log.h>

namespace android {

    // A Blob is an immutable sized unstructured data blob.
    class Blob {
        public:
            Blob(const void* data, size_t size, bool copyData);
            ~Blob();

            bool operator<(const Blob& rhs) const;
            bool operator==(const Blob& rhs) const;

            const void* getData() const;
            size_t getSize() const;

        private:
            // Copying is not allowed.
            Blob(const Blob&);
            void operator=(const Blob&);

            // mData points to the buffer containing the blob data.
            const void* mData;

            // mSize is the size of the blob data in bytes.
            size_t mSize;

            // mOwnsData indicates whether or not this Blob object should free the
            // memory pointed to by mData when the Blob gets destructed.
            bool mOwnsData;
    };
}

// hash and equal_to structs for std::unordered_map
namespace std {
    inline uint32_t JenkinsHashMix(uint32_t hash, uint32_t data) {
        hash += data;
        hash += (hash << 10);
        hash ^= (hash >> 6);
        return hash;
    }

    inline uint32_t JenkinsHashMixBytes(uint32_t hash, const uint8_t* bytes, size_t size) {
        if (size > UINT32_MAX) {
            abort();
        }
        hash = JenkinsHashMix(hash, (uint32_t)size);
        size_t i;
        for (i = 0; i < (size & -4); i += 4) {
            uint32_t data = bytes[i] | (bytes[i+1] << 8) | (bytes[i+2] << 16) | (bytes[i+3] << 24);
            hash = JenkinsHashMix(hash, data);
        }
        if (size & 3) {
            uint32_t data = bytes[i];
            data |= ((size & 3) > 1) ? (bytes[i+1] << 8) : 0;
            data |= ((size & 3) > 2) ? (bytes[i+2] << 16) : 0;
            hash = JenkinsHashMix(hash, data);
        }
        return hash;
    }
    template <> struct hash<std::shared_ptr<android::Blob>> {
        std::size_t operator()(const std::shared_ptr<android::Blob>& value) const {
            uint8_t *dataBytes = (uint8_t*)(value->getData());
            uint32_t val = JenkinsHashMixBytes(0, dataBytes, value->getSize());
            return val;
        }
    };

    template <> struct equal_to<std::shared_ptr<android::Blob>> {
        bool operator()(const std::shared_ptr<android::Blob>& value1, const std::shared_ptr<android::Blob>& value2) const {
            return *value1 == *value2;
        }
    };
}

#endif // ANDROID_BLOB_H
