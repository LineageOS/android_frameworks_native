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

#include <errno.h>
#include <sys/mman.h>

#include <cutils/ashmem.h>
#include <log/log.h>
#include <ui/BufferHubMetadata.h>

namespace android {
namespace dvr {

namespace {

static const int kAshmemProt = PROT_READ | PROT_WRITE;

} // namespace

using BufferHubDefs::kMetadataHeaderSize;
using BufferHubDefs::MetadataHeader;

/* static */
BufferHubMetadata BufferHubMetadata::Create(size_t userMetadataSize) {
    // The size the of metadata buffer is used as the "width" parameter during allocation. Thus it
    // cannot overflow uint32_t.
    if (userMetadataSize >= (std::numeric_limits<uint32_t>::max() - kMetadataHeaderSize)) {
        ALOGE("BufferHubMetadata::Create: metadata size too big: %zu.", userMetadataSize);
        return {};
    }

    const size_t metadataSize = userMetadataSize + kMetadataHeaderSize;
    int fd = ashmem_create_region(/*name=*/"BufferHubMetadata", metadataSize);
    if (fd < 0) {
        ALOGE("BufferHubMetadata::Create: failed to create ashmem region.");
        return {};
    }

    // Hand over the ownership of the fd to a pdx::LocalHandle immediately after the successful
    // return of ashmem_create_region. The ashmemHandle is going to own the fd and to prevent fd
    // leaks during error handling.
    pdx::LocalHandle ashmemHandle{fd};

    if (ashmem_set_prot_region(ashmemHandle.Get(), kAshmemProt) != 0) {
        ALOGE("BufferHubMetadata::Create: failed to set protect region.");
        return {};
    }

    return BufferHubMetadata::Import(std::move(ashmemHandle));
}

/* static */
BufferHubMetadata BufferHubMetadata::Import(pdx::LocalHandle ashmemHandle) {
    if (!ashmem_valid(ashmemHandle.Get())) {
        ALOGE("BufferHubMetadata::Import: invalid ashmem fd.");
        return {};
    }

    size_t metadataSize = static_cast<size_t>(ashmem_get_size_region(ashmemHandle.Get()));
    size_t userMetadataSize = metadataSize - kMetadataHeaderSize;

    // Note that here the buffer state is mapped from shared memory as an atomic object. The
    // std::atomic's constructor will not be called so that the original value stored in the memory
    // region can be preserved.
    auto metadataHeader = static_cast<MetadataHeader*>(mmap(nullptr, metadataSize, kAshmemProt,
                                                            MAP_SHARED, ashmemHandle.Get(),
                                                            /*offset=*/0));
    if (metadataHeader == nullptr) {
        ALOGE("BufferHubMetadata::Import: failed to map region.");
        return {};
    }

    return BufferHubMetadata(userMetadataSize, std::move(ashmemHandle), metadataHeader);
}

BufferHubMetadata::BufferHubMetadata(size_t userMetadataSize, pdx::LocalHandle ashmemHandle,
                                     MetadataHeader* metadataHeader)
      : mUserMetadataSize(userMetadataSize),
        mAshmemHandle(std::move(ashmemHandle)),
        mMetadataHeader(metadataHeader) {}

BufferHubMetadata::~BufferHubMetadata() {
    if (mMetadataHeader != nullptr) {
        int ret = munmap(mMetadataHeader, metadata_size());
        ALOGE_IF(ret != 0,
                 "BufferHubMetadata::~BufferHubMetadata: failed to unmap ashmem, error=%d.", errno);
        mMetadataHeader = nullptr;
    }
}

} // namespace dvr
} // namespace android
