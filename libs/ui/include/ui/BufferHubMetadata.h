/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_BUFFER_HUB_METADATA_H_
#define ANDROID_BUFFER_HUB_METADATA_H_

// We would eliminate the clang warnings introduced by libdpx.
// TODO(b/112338294): Remove those once BufferHub moved to use Binder
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wdouble-promotion"
#pragma clang diagnostic ignored "-Wgnu-case-range"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma clang diagnostic ignored "-Winconsistent-missing-destructor-override"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wpacked"
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wswitch-enum"
#pragma clang diagnostic ignored "-Wundefined-func-template"
#pragma clang diagnostic ignored "-Wunused-template"
#pragma clang diagnostic ignored "-Wweak-vtables"
#include <pdx/file_handle.h>
#include <private/dvr/buffer_hub_defs.h>
#pragma clang diagnostic pop

namespace android {
namespace dvr {

class BufferHubMetadata {
public:
    // Creates a new BufferHubMetadata backed by an ashmem region.
    //
    // @param userMetadataSize Size in bytes of the user defined metadata. The entire metadata
    //        shared memory region to be allocated is the size of canonical
    //        BufferHubDefs::MetadataHeader plus userMetadataSize.
    static BufferHubMetadata Create(size_t userMetadataSize);

    // Imports an existing BufferHubMetadata from an ashmem FD.
    //
    // TODO(b/112338294): Refactor BufferHub to use Binder as its internal IPC backend instead of
    // UDS.
    //
    // @param ashmemHandle Ashmem file handle representing an ashmem region.
    static BufferHubMetadata Import(pdx::LocalHandle ashmemHandle);

    BufferHubMetadata() = default;

    BufferHubMetadata(BufferHubMetadata&& other) { *this = std::move(other); }

    ~BufferHubMetadata();

    BufferHubMetadata& operator=(BufferHubMetadata&& other) {
        if (this != &other) {
            mUserMetadataSize = other.mUserMetadataSize;
            other.mUserMetadataSize = 0;

            mAshmemHandle = std::move(other.mAshmemHandle);

            // The old raw mMetadataHeader pointer must be cleared, otherwise the destructor will
            // automatically mummap() the shared memory.
            mMetadataHeader = other.mMetadataHeader;
            other.mMetadataHeader = nullptr;
        }
        return *this;
    }

    // Returns true if the metadata is valid, i.e. the metadata has a valid ashmem fd and the ashmem
    // has been mapped into virtual address space.
    bool IsValid() const { return mAshmemHandle.IsValid() && mMetadataHeader != nullptr; }

    size_t user_metadata_size() const { return mUserMetadataSize; }
    size_t metadata_size() const { return mUserMetadataSize + BufferHubDefs::kMetadataHeaderSize; }

    const pdx::LocalHandle& ashmem_handle() const { return mAshmemHandle; }
    BufferHubDefs::MetadataHeader* metadata_header() { return mMetadataHeader; }

private:
    BufferHubMetadata(size_t userMetadataSize, pdx::LocalHandle ashmemHandle,
                      BufferHubDefs::MetadataHeader* metadataHeader);

    BufferHubMetadata(const BufferHubMetadata&) = delete;
    void operator=(const BufferHubMetadata&) = delete;

    size_t mUserMetadataSize = 0;
    pdx::LocalHandle mAshmemHandle;
    BufferHubDefs::MetadataHeader* mMetadataHeader = nullptr;
};

} // namespace dvr
} // namespace android

#endif // ANDROID_BUFFER_HUB_METADATA_H_
