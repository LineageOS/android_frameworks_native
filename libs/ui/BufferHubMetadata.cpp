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

}  // namespace

using BufferHubDefs::kMetadataHeaderSize;
using BufferHubDefs::MetadataHeader;

/* static */
BufferHubMetadata BufferHubMetadata::Create(size_t user_metadata_size) {
  // The size the of metadata buffer is used as the "width" parameter during
  // allocation. Thus it cannot overflow uint32_t.
  if (user_metadata_size >=
      (std::numeric_limits<uint32_t>::max() - kMetadataHeaderSize)) {
    ALOGE("BufferHubMetadata::Create: metadata size too big: %zu.",
          user_metadata_size);
    return {};
  }

  const size_t metadata_size = user_metadata_size + kMetadataHeaderSize;
  int fd = ashmem_create_region(/*name=*/"BufferHubMetadata", metadata_size);
  if (fd < 0) {
    ALOGE("BufferHubMetadata::Create: failed to create ashmem region.");
    return {};
  }

  // Hand over the ownership of the fd to a pdx::LocalHandle immediately after
  // the successful return of ashmem_create_region. The ashmem_handle is going
  // to own the fd and to prevent fd leaks during error handling.
  pdx::LocalHandle ashmem_handle{fd};

  if (ashmem_set_prot_region(ashmem_handle.Get(), kAshmemProt) != 0) {
    ALOGE("BufferHubMetadata::Create: failed to set protect region.");
    return {};
  }

  return BufferHubMetadata::Import(std::move(ashmem_handle));
}

/* static */
BufferHubMetadata BufferHubMetadata::Import(pdx::LocalHandle ashmem_handle) {
  if (!ashmem_valid(ashmem_handle.Get())) {
    ALOGE("BufferHubMetadata::Import: invalid ashmem fd.");
    return {};
  }

  size_t metadata_size = static_cast<size_t>(ashmem_get_size_region(ashmem_handle.Get()));
  size_t user_metadata_size = metadata_size - kMetadataHeaderSize;

  // Note that here the buffer state is mapped from shared memory as an atomic
  // object. The std::atomic's constructor will not be called so that the
  // original value stored in the memory region can be preserved.
  auto metadata_header = static_cast<MetadataHeader*>(
      mmap(nullptr, metadata_size, kAshmemProt, MAP_SHARED, ashmem_handle.Get(),
           /*offset=*/0));
  if (metadata_header == nullptr) {
    ALOGE("BufferHubMetadata::Import: failed to map region.");
    return {};
  }

  return BufferHubMetadata(user_metadata_size, std::move(ashmem_handle),
                           metadata_header);
}

BufferHubMetadata::BufferHubMetadata(size_t user_metadata_size,
                                     pdx::LocalHandle ashmem_handle,
                                     MetadataHeader* metadata_header)
    : user_metadata_size_(user_metadata_size),
      ashmem_handle_(std::move(ashmem_handle)),
      metadata_header_(metadata_header) {}

BufferHubMetadata::~BufferHubMetadata() {
  if (metadata_header_ != nullptr) {
    int ret = munmap(metadata_header_, metadata_size());
    ALOGE_IF(ret != 0,
             "BufferHubMetadata::~BufferHubMetadata: failed to unmap ashmem, "
             "error=%d.",
             errno);
    metadata_header_ = nullptr;
  }
}

}  // namespace dvr
}  // namespace android
