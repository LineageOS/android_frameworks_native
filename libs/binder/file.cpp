/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "file.h"

#ifdef BINDER_NO_LIBBASE

#include "Utils.h"

#include <stdint.h>

// clang-format off

namespace android::binder {

bool ReadFully(borrowed_fd fd, void* data, size_t byte_count) {
  uint8_t* p = reinterpret_cast<uint8_t*>(data);
  size_t remaining = byte_count;
  while (remaining > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(read(fd.get(), p, remaining));
    if (n == 0) {  // EOF
      errno = ENODATA;
      return false;
    }
    if (n == -1) return false;
    p += n;
    remaining -= n;
  }
  return true;
}

bool WriteFully(borrowed_fd fd, const void* data, size_t byte_count) {
  const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
  size_t remaining = byte_count;
  while (remaining > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(write(fd.get(), p, remaining));
    if (n == -1) return false;
    p += n;
    remaining -= n;
  }
  return true;
}

}  // namespace android::binder

#endif // BINDER_NO_LIBBASE
