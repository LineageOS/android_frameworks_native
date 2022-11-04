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

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_uncompressed_ptr uncompressed_yuv_420_image,
                                  void* dest,
                                  int quality,
                                  jr_exif_ptr /* exif */,
                                  float /* hdr_ratio */) {
  if (uncompressed_p010_image == nullptr
   || uncompressed_yuv_420_image == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  if (quality < 0 || quality > 100) {
    return ERROR_JPEGR_INVALID_INPUT_TYPE;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_uncompressed_ptr uncompressed_yuv_420_image,
                                  void* compressed_jpeg_image,
                                  void* dest,
                                  float /* hdr_ratio */) {

  if (uncompressed_p010_image == nullptr
   || uncompressed_yuv_420_image == nullptr
   || compressed_jpeg_image == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  void* compressed_jpeg_image,
                                  void* dest,
                                  float /* hdr_ratio */) {
  if (uncompressed_p010_image == nullptr
   || compressed_jpeg_image == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::decodeJPEGR(void* compressed_jpegr_image,
                                  jr_uncompressed_ptr dest,
                                  jr_exif_ptr /* exif */,
                                  bool /* request_sdr */) {
  if (compressed_jpegr_image == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::decodeRecoveryMap(jr_compressed_ptr compressed_recovery_map,
                                        jr_uncompressed_ptr dest) {
  if (compressed_recovery_map == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::encodeRecoveryMap(jr_uncompressed_ptr uncompressed_recovery_map,
                                        jr_compressed_ptr dest) {
  if (uncompressed_recovery_map == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::generateRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                                          jr_uncompressed_ptr uncompressed_p010_image,
                                          jr_uncompressed_ptr dest) {
  if (uncompressed_yuv_420_image == nullptr
   || uncompressed_p010_image == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::applyRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                                       jr_uncompressed_ptr uncompressed_recovery_map,
                                       jr_uncompressed_ptr dest) {
  if (uncompressed_yuv_420_image == nullptr
   || uncompressed_recovery_map == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::extractRecoveryMap(void* compressed_jpegr_image, jr_compressed_ptr dest) {
  if (compressed_jpegr_image == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::appendRecoveryMap(void* compressed_jpeg_image,
                                     jr_compressed_ptr compressed_recovery_map,
                                     void* dest) {
  if (compressed_jpeg_image == nullptr
   || compressed_recovery_map == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

} // namespace android::recoverymap
