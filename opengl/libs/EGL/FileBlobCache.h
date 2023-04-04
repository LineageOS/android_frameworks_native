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

#ifndef ANDROID_FILE_BLOB_CACHE_H
#define ANDROID_FILE_BLOB_CACHE_H

#include "BlobCache.h"
#include <string>

namespace android {

uint32_t crc32c(const uint8_t* buf, size_t len);

class FileBlobCache : public BlobCache {
public:
    // FileBlobCache attempts to load the saved cache contents from disk into
    // BlobCache.
    FileBlobCache(size_t maxKeySize, size_t maxValueSize, size_t maxTotalSize,
            const std::string& filename);

    // writeToFile attempts to save the current contents of BlobCache to
    // disk.
    void writeToFile();

    // Return the total size of the cache
    size_t getSize();

private:
    // mFilename is the name of the file for storing cache contents.
    std::string mFilename;
};

} // namespace android

#endif // ANDROID_BLOB_CACHE_H
