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

#ifndef ANDROID_DVR_BUFFER_HUB_METADATA_H_
#define ANDROID_DVR_BUFFER_HUB_METADATA_H_

#include <pdx/file_handle.h>
#include <private/dvr/buffer_hub_defs.h>

namespace android {
namespace dvr {

class BufferHubMetadata {
 public:
  // Creates a new BufferHubMetadata backed by an ashmem region.
  //
  // @param user_metadata_size Size in bytes of the user defined metadata. The
  //        entire metadata shared memory region to be allocated is the size of
  //        canonical BufferHubDefs::MetadataHeader plus user_metadata_size.
  static BufferHubMetadata Create(size_t user_metadata_size);

  // Imports an existing BufferHubMetadata from an ashmem FD.
  //
  // TODO(b/112338294): Refactor BufferHub to use Binder as its internal IPC
  // backend instead of UDS.
  //
  // @param ashmem_handle Ashmem file handle representing an ashmem region.
  static BufferHubMetadata Import(pdx::LocalHandle ashmem_handle);

  BufferHubMetadata() = default;

  BufferHubMetadata(BufferHubMetadata&& other) { *this = std::move(other); }

  ~BufferHubMetadata();

  BufferHubMetadata& operator=(BufferHubMetadata&& other) {
    if (this != &other) {
      user_metadata_size_ = other.user_metadata_size_;
      other.user_metadata_size_ = 0;

      ashmem_handle_ = std::move(other.ashmem_handle_);

      // The old raw metadata_header_ pointer must be cleared, otherwise the
      // destructor will automatically mummap() the shared memory.
      metadata_header_ = other.metadata_header_;
      other.metadata_header_ = nullptr;
    }
    return *this;
  }

  // Returns true if the metadata is valid, i.e. the metadata has a valid ashmem
  // fd and the ashmem has been mapped into virtual address space.
  bool IsValid() const {
    return ashmem_handle_.IsValid() && metadata_header_ != nullptr;
  }

  size_t user_metadata_size() const { return user_metadata_size_; }
  size_t metadata_size() const {
    return user_metadata_size_ + BufferHubDefs::kMetadataHeaderSize;
  }

  const pdx::LocalHandle& ashmem_handle() const { return ashmem_handle_; }
  BufferHubDefs::MetadataHeader* metadata_header() { return metadata_header_; }

 private:
  BufferHubMetadata(size_t user_metadata_size, pdx::LocalHandle ashmem_handle,
                    BufferHubDefs::MetadataHeader* metadata_header);

  BufferHubMetadata(const BufferHubMetadata&) = delete;
  void operator=(const BufferHubMetadata&) = delete;

  size_t user_metadata_size_ = 0;
  pdx::LocalHandle ashmem_handle_;
  BufferHubDefs::MetadataHeader* metadata_header_ = nullptr;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_HUB_METADATA_H_
