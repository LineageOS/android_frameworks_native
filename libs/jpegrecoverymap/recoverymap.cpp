/*
 * Copyright 2022 The Android Open Source Project
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

#include <jpegrecoverymap/recoverymap.h>

namespace android::recoverymap {

void* RecoveryMap::decodeRecoveryMap(void* compressed_recovery_map) {
  if (compressed_recovery_map == nullptr) {
    return nullptr;
  }

  // TBD
  return nullptr;
}

void* RecoveryMap::encodeRecoveryMap(void* uncompressed_recovery_map) {
  if (uncompressed_recovery_map == nullptr) {
    return nullptr;
  }

  // TBD
  return nullptr;
}

void* RecoveryMap::generateRecoveryMap(
    void* uncompressed_yuv_420_image, void* uncompressed_p010_image) {
  if (uncompressed_yuv_420_image == nullptr || uncompressed_p010_image == nullptr) {
    return nullptr;
  }

  // TBD
  return nullptr;
}

void* RecoveryMap::applyRecoveryMap(
    void* uncompressed_yuv_420_image, void* uncompressed_recovery_map) {
  if (uncompressed_yuv_420_image == nullptr || uncompressed_recovery_map == nullptr) {
    return nullptr;
  }

  // TBD
  return nullptr;
}

void* RecoveryMap::extractRecoveryMap(void* compressed_jpeg_g_image) {
  if (compressed_jpeg_g_image == nullptr) {
    return nullptr;
  }

  // TBD
  return nullptr;
}

void* RecoveryMap::appendRecoveryMap(void* compressed_jpeg_image, void* compressed_recovery_map) {
  if (compressed_jpeg_image == nullptr || compressed_recovery_map == nullptr) {
    return nullptr;
  }

  // TBD
  return nullptr;
}

} // namespace android::recoverymap
