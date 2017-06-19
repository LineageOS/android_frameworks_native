/*
 ** Copyright 2017, The Android Open Source Project
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

#include "Blob.h"
#include <log/log.h>

namespace android {

Blob::Blob(const void* data, size_t size, bool copyData):
        mData(copyData ? malloc(size) : data),
        mSize(size),
        mOwnsData(copyData) {
    if (data != NULL && copyData) {
        memcpy(const_cast<void*>(mData), data, size);
    }
}

Blob::~Blob() {
    if (mOwnsData) {
        free(const_cast<void*>(mData));
    }
}

bool Blob::operator<(const Blob& rhs) const {
    if (mSize == rhs.mSize) {
        return memcmp(mData, rhs.mData, mSize) < 0;
    } else {
        return mSize < rhs.mSize;
    }
}

// == required for unordered_map comparison
bool Blob::operator==(const Blob& rhs) const {
    if (mSize == rhs.mSize) {
        return memcmp(mData, rhs.mData, mSize) == 0;
    } else {
        return false;
    }
}

const void* Blob::getData() const {
    return mData;
}

size_t Blob::getSize() const {
    return mSize;
}

} // namespace android
