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
#include <jpegrecoverymap/jpegencoder.h>
#include <jpegrecoverymap/jpegdecoder.h>
#include <jpegrecoverymap/recoverymapmath.h>
#include <jpegrecoverymap/recoverymaputils.h>

#include <image_io/jpeg/jpeg_marker.h>
#include <image_io/xml/xml_writer.h>
#include <image_io/jpeg/jpeg_info.h>
#include <image_io/jpeg/jpeg_scanner.h>
#include <image_io/jpeg/jpeg_info_builder.h>
#include <image_io/base/data_segment_data_source.h>
#include <utils/Log.h>

#include <memory>
#include <sstream>
#include <string>
#include <cmath>

using namespace std;
using namespace photos_editing_formats::image_io;

namespace android::recoverymap {

#define JPEGR_CHECK(x)          \
  {                             \
    status_t status = (x);      \
    if ((status) != NO_ERROR) { \
      return status;            \
    }                           \
  }

// The current JPEGR version that we encode to
static const uint32_t kJpegrVersion = 1;

// Map is quarter res / sixteenth size
static const size_t kMapDimensionScaleFactor = 4;
// JPEG compress quality (0 ~ 100) for recovery map
static const int kMapCompressQuality = 85;

// TODO: fill in st2086 metadata
static const st2086_metadata kSt2086Metadata = {
  {0.0f, 0.0f},
  {0.0f, 0.0f},
  {0.0f, 0.0f},
  {0.0f, 0.0f},
  0,
  1.0f,
};

/*
 * Helper function used for generating XMP metadata.
 *
 * @param prefix The prefix part of the name.
 * @param suffix The suffix part of the name.
 * @return A name of the form "prefix:suffix".
 */
string Name(const string &prefix, const string &suffix) {
  std::stringstream ss;
  ss << prefix << ":" << suffix;
  return ss.str();
}

/*
 * Helper function used for writing data to destination.
 *
 * @param destination destination of the data to be written.
 * @param source source of data being written.
 * @param length length of the data to be written.
 * @param position cursor in desitination where the data is to be written.
 * @return status of succeed or error code.
 */
status_t Write(jr_compressed_ptr destination, const void* source, size_t length, int &position) {
  if (position + length > destination->maxLength) {
    return ERROR_JPEGR_BUFFER_TOO_SMALL;
  }

  memcpy((uint8_t*)destination->data + sizeof(uint8_t) * position, source, length);
  position += length;
  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_uncompressed_ptr uncompressed_yuv_420_image,
                                  jpegr_transfer_function hdr_tf,
                                  jr_compressed_ptr dest,
                                  int quality,
                                  jr_exif_ptr /* exif */) {
  if (uncompressed_p010_image == nullptr
   || uncompressed_yuv_420_image == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  if (quality < 0 || quality > 100) {
    return ERROR_JPEGR_INVALID_INPUT_TYPE;
  }

  if (uncompressed_p010_image->width != uncompressed_yuv_420_image->width
   || uncompressed_p010_image->height != uncompressed_yuv_420_image->height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }

  jpegr_metadata metadata;
  metadata.version = kJpegrVersion;
  metadata.transferFunction = hdr_tf;
  if (hdr_tf == JPEGR_TF_PQ) {
    metadata.hdr10Metadata.st2086Metadata = kSt2086Metadata;
  }

  jpegr_uncompressed_struct map;
  JPEGR_CHECK(generateRecoveryMap(
      uncompressed_yuv_420_image, uncompressed_p010_image, &metadata, &map));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(map.data));

  jpegr_compressed_struct compressed_map;
  compressed_map.maxLength = map.width * map.height;
  unique_ptr<uint8_t[]> compressed_map_data = make_unique<uint8_t[]>(compressed_map.maxLength);
  compressed_map.data = compressed_map_data.get();
  JPEGR_CHECK(compressRecoveryMap(&map, &compressed_map));

  JpegEncoder jpeg_encoder;
  // TODO: determine ICC data based on color gamut information
  if (!jpeg_encoder.compressImage(uncompressed_yuv_420_image->data,
                                  uncompressed_yuv_420_image->width,
                                  uncompressed_yuv_420_image->height, quality, nullptr, 0)) {
    return ERROR_JPEGR_ENCODE_ERROR;
  }
  jpegr_compressed_struct jpeg;
  jpeg.data = jpeg_encoder.getCompressedImagePtr();
  jpeg.length = jpeg_encoder.getCompressedImageSize();

  JPEGR_CHECK(appendRecoveryMap(&jpeg, &compressed_map, &metadata, dest));

  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_uncompressed_ptr uncompressed_yuv_420_image,
                                  jr_compressed_ptr compressed_jpeg_image,
                                  jpegr_transfer_function hdr_tf,
                                  jr_compressed_ptr dest) {
  if (uncompressed_p010_image == nullptr
   || uncompressed_yuv_420_image == nullptr
   || compressed_jpeg_image == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  if (uncompressed_p010_image->width != uncompressed_yuv_420_image->width
   || uncompressed_p010_image->height != uncompressed_yuv_420_image->height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }

  jpegr_metadata metadata;
  metadata.version = kJpegrVersion;
  metadata.transferFunction = hdr_tf;
  if (hdr_tf == JPEGR_TF_PQ) {
    metadata.hdr10Metadata.st2086Metadata = kSt2086Metadata;
  }

  jpegr_uncompressed_struct map;
  JPEGR_CHECK(generateRecoveryMap(
      uncompressed_yuv_420_image, uncompressed_p010_image, &metadata, &map));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(map.data));

  jpegr_compressed_struct compressed_map;
  compressed_map.maxLength = map.width * map.height;
  unique_ptr<uint8_t[]> compressed_map_data = make_unique<uint8_t[]>(compressed_map.maxLength);
  compressed_map.data = compressed_map_data.get();
  JPEGR_CHECK(compressRecoveryMap(&map, &compressed_map));

  JPEGR_CHECK(appendRecoveryMap(compressed_jpeg_image, &compressed_map, &metadata, dest));

  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_compressed_ptr compressed_jpeg_image,
                                  jpegr_transfer_function hdr_tf,
                                  jr_compressed_ptr dest) {
  if (uncompressed_p010_image == nullptr
   || compressed_jpeg_image == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  JpegDecoder jpeg_decoder;
  if (!jpeg_decoder.decompressImage(compressed_jpeg_image->data, compressed_jpeg_image->length)) {
    return ERROR_JPEGR_DECODE_ERROR;
  }
  jpegr_uncompressed_struct uncompressed_yuv_420_image;
  uncompressed_yuv_420_image.data = jpeg_decoder.getDecompressedImagePtr();
  uncompressed_yuv_420_image.width = jpeg_decoder.getDecompressedImageWidth();
  uncompressed_yuv_420_image.height = jpeg_decoder.getDecompressedImageHeight();
  uncompressed_yuv_420_image.colorGamut = compressed_jpeg_image->colorGamut;

  if (uncompressed_p010_image->width != uncompressed_yuv_420_image.width
   || uncompressed_p010_image->height != uncompressed_yuv_420_image.height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }

  jpegr_metadata metadata;
  metadata.version = kJpegrVersion;
  metadata.transferFunction = hdr_tf;
  if (hdr_tf == JPEGR_TF_PQ) {
    metadata.hdr10Metadata.st2086Metadata = kSt2086Metadata;
  }

  jpegr_uncompressed_struct map;
  JPEGR_CHECK(generateRecoveryMap(
      &uncompressed_yuv_420_image, uncompressed_p010_image, &metadata, &map));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(map.data));

  jpegr_compressed_struct compressed_map;
  compressed_map.maxLength = map.width * map.height;
  unique_ptr<uint8_t[]> compressed_map_data = make_unique<uint8_t[]>(compressed_map.maxLength);
  compressed_map.data = compressed_map_data.get();
  JPEGR_CHECK(compressRecoveryMap(&map, &compressed_map));

  JPEGR_CHECK(appendRecoveryMap(compressed_jpeg_image, &compressed_map, &metadata, dest));

  return NO_ERROR;
}

status_t RecoveryMap::getJPEGRInfo(jr_compressed_ptr compressed_jpegr_image,
                                   jr_info_ptr jpegr_info) {
  if (compressed_jpegr_image == nullptr || jpegr_info == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  jpegr_compressed_struct primary_image, recovery_map;
  JPEGR_CHECK(extractPrimaryImageAndRecoveryMap(compressed_jpegr_image,
                                                &primary_image, &recovery_map));

  JpegDecoder jpeg_decoder;
  if (!jpeg_decoder.getCompressedImageParameters(primary_image.data, primary_image.length,
                                                 &jpegr_info->width, &jpegr_info->height,
                                                 jpegr_info->iccData, jpegr_info->exifData)) {
    return ERROR_JPEGR_DECODE_ERROR;
  }

  return NO_ERROR;
}


status_t RecoveryMap::decodeJPEGR(jr_compressed_ptr compressed_jpegr_image,
                                  jr_uncompressed_ptr dest,
                                  jr_exif_ptr exif,
                                  bool request_sdr) {
  if (compressed_jpegr_image == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TODO: fill EXIF data
  (void) exif;

  jpegr_compressed_struct compressed_map;
  jpegr_metadata metadata;
  JPEGR_CHECK(extractRecoveryMap(compressed_jpegr_image, &compressed_map));

  jpegr_uncompressed_struct map;
  JPEGR_CHECK(decompressRecoveryMap(&compressed_map, &map));

  JpegDecoder jpeg_decoder;
  if (!jpeg_decoder.decompressImage(compressed_jpegr_image->data, compressed_jpegr_image->length)) {
    return ERROR_JPEGR_DECODE_ERROR;
  }

  jpegr_uncompressed_struct uncompressed_yuv_420_image;
  uncompressed_yuv_420_image.data = jpeg_decoder.getDecompressedImagePtr();
  uncompressed_yuv_420_image.width = jpeg_decoder.getDecompressedImageWidth();
  uncompressed_yuv_420_image.height = jpeg_decoder.getDecompressedImageHeight();

  if (!getMetadataFromXMP(static_cast<uint8_t*>(jpeg_decoder.getXMPPtr()),
                                       jpeg_decoder.getXMPSize(), &metadata)) {
    return ERROR_JPEGR_DECODE_ERROR;
  }

  if (request_sdr) {
    memcpy(dest->data, uncompressed_yuv_420_image.data,
            uncompressed_yuv_420_image.width*uncompressed_yuv_420_image.height *3 / 2);
    dest->width = uncompressed_yuv_420_image.width;
    dest->height = uncompressed_yuv_420_image.height;
  } else {
    JPEGR_CHECK(applyRecoveryMap(&uncompressed_yuv_420_image, &map, &metadata, dest));
  }

  return NO_ERROR;
}

status_t RecoveryMap::decompressRecoveryMap(jr_compressed_ptr compressed_recovery_map,
                                            jr_uncompressed_ptr dest) {
  if (compressed_recovery_map == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  JpegDecoder jpeg_decoder;
  if (!jpeg_decoder.decompressImage(compressed_recovery_map->data,
                                    compressed_recovery_map->length)) {
    return ERROR_JPEGR_DECODE_ERROR;
  }

  dest->data = jpeg_decoder.getDecompressedImagePtr();
  dest->width = jpeg_decoder.getDecompressedImageWidth();
  dest->height = jpeg_decoder.getDecompressedImageHeight();

  return NO_ERROR;
}

status_t RecoveryMap::compressRecoveryMap(jr_uncompressed_ptr uncompressed_recovery_map,
                                          jr_compressed_ptr dest) {
  if (uncompressed_recovery_map == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TODO: should we have ICC data for the map?
  JpegEncoder jpeg_encoder;
  if (!jpeg_encoder.compressImage(uncompressed_recovery_map->data,
                                  uncompressed_recovery_map->width,
                                  uncompressed_recovery_map->height,
                                  kMapCompressQuality,
                                  nullptr,
                                  0,
                                  true /* isSingleChannel */)) {
    return ERROR_JPEGR_ENCODE_ERROR;
  }

  if (dest->maxLength < jpeg_encoder.getCompressedImageSize()) {
    return ERROR_JPEGR_BUFFER_TOO_SMALL;
  }

  memcpy(dest->data, jpeg_encoder.getCompressedImagePtr(), jpeg_encoder.getCompressedImageSize());
  dest->length = jpeg_encoder.getCompressedImageSize();
  dest->colorGamut = JPEGR_COLORGAMUT_UNSPECIFIED;

  return NO_ERROR;
}

status_t RecoveryMap::generateRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                                          jr_uncompressed_ptr uncompressed_p010_image,
                                          jr_metadata_ptr metadata,
                                          jr_uncompressed_ptr dest) {
  if (uncompressed_yuv_420_image == nullptr
   || uncompressed_p010_image == nullptr
   || metadata == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  if (uncompressed_yuv_420_image->width != uncompressed_p010_image->width
   || uncompressed_yuv_420_image->height != uncompressed_p010_image->height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }

  if (uncompressed_yuv_420_image->colorGamut == JPEGR_COLORGAMUT_UNSPECIFIED
   || uncompressed_p010_image->colorGamut == JPEGR_COLORGAMUT_UNSPECIFIED) {
    return ERROR_JPEGR_INVALID_COLORGAMUT;
  }

  size_t image_width = uncompressed_yuv_420_image->width;
  size_t image_height = uncompressed_yuv_420_image->height;
  size_t map_width = image_width / kMapDimensionScaleFactor;
  size_t map_height = image_height / kMapDimensionScaleFactor;

  dest->width = map_width;
  dest->height = map_height;
  dest->colorGamut = JPEGR_COLORGAMUT_UNSPECIFIED;
  dest->data = new uint8_t[map_width * map_height];
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(dest->data));

  ColorTransformFn hdrInvOetf = nullptr;
  switch (metadata->transferFunction) {
    case JPEGR_TF_HLG:
      hdrInvOetf = hlgInvOetf;
      break;
    case JPEGR_TF_PQ:
      hdrInvOetf = pqInvOetf;
      break;
  }

  ColorTransformFn hdrGamutConversionFn = getHdrConversionFn(
      uncompressed_yuv_420_image->colorGamut, uncompressed_p010_image->colorGamut);

  ColorCalculationFn luminanceFn = nullptr;
  switch (uncompressed_yuv_420_image->colorGamut) {
    case JPEGR_COLORGAMUT_BT709:
      luminanceFn = srgbLuminance;
      break;
    case JPEGR_COLORGAMUT_P3:
      luminanceFn = p3Luminance;
      break;
    case JPEGR_COLORGAMUT_BT2100:
      luminanceFn = bt2100Luminance;
      break;
    case JPEGR_COLORGAMUT_UNSPECIFIED:
      // Should be impossible to hit after input validation.
      return ERROR_JPEGR_INVALID_COLORGAMUT;
  }

  float hdr_y_nits_max = 0.0f;
  double hdr_y_nits_avg = 0.0f;
  for (size_t y = 0; y < image_height; ++y) {
    for (size_t x = 0; x < image_width; ++x) {
      Color hdr_yuv_gamma = getP010Pixel(uncompressed_p010_image, x, y);
      Color hdr_rgb_gamma = bt2100YuvToRgb(hdr_yuv_gamma);
      Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
      hdr_rgb = hdrGamutConversionFn(hdr_rgb);
      float hdr_y_nits = luminanceFn(hdr_rgb);

      hdr_y_nits_avg += hdr_y_nits;
      if (hdr_y_nits > hdr_y_nits_max) {
        hdr_y_nits_max = hdr_y_nits;
      }
    }
  }
  hdr_y_nits_avg /= image_width * image_height;

  metadata->rangeScalingFactor = hdr_y_nits_max / kSdrWhiteNits;
  if (metadata->transferFunction == JPEGR_TF_PQ) {
    metadata->hdr10Metadata.maxFALL = hdr_y_nits_avg;
    metadata->hdr10Metadata.maxCLL = hdr_y_nits_max;
  }

  for (size_t y = 0; y < map_height; ++y) {
    for (size_t x = 0; x < map_width; ++x) {
      Color sdr_yuv_gamma = sampleYuv420(uncompressed_yuv_420_image,
                                         kMapDimensionScaleFactor, x, y);
      Color sdr_rgb_gamma = srgbYuvToRgb(sdr_yuv_gamma);
      Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
      float sdr_y_nits = luminanceFn(sdr_rgb);

      Color hdr_yuv_gamma = sampleP010(uncompressed_p010_image, kMapDimensionScaleFactor, x, y);
      Color hdr_rgb_gamma = bt2100YuvToRgb(hdr_yuv_gamma);
      Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
      hdr_rgb = hdrGamutConversionFn(hdr_rgb);
      float hdr_y_nits = luminanceFn(hdr_rgb);

      size_t pixel_idx =  x + y * map_width;
      reinterpret_cast<uint8_t*>(dest->data)[pixel_idx] =
          encodeRecovery(sdr_y_nits, hdr_y_nits, metadata->rangeScalingFactor);
    }
  }

  map_data.release();
  return NO_ERROR;
}

status_t RecoveryMap::applyRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                                       jr_uncompressed_ptr uncompressed_recovery_map,
                                       jr_metadata_ptr metadata,
                                       jr_uncompressed_ptr dest) {
  if (uncompressed_yuv_420_image == nullptr
   || uncompressed_recovery_map == nullptr
   || metadata == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  size_t width = uncompressed_yuv_420_image->width;
  size_t height = uncompressed_yuv_420_image->height;

  dest->width = width;
  dest->height = height;
  size_t pixel_count = width * height;

  ColorTransformFn hdrOetf = nullptr;
  switch (metadata->transferFunction) {
    case JPEGR_TF_HLG:
      hdrOetf = hlgOetf;
      break;
    case JPEGR_TF_PQ:
      hdrOetf = pqOetf;
      break;
  }

  for (size_t y = 0; y < height; ++y) {
    for (size_t x = 0; x < width; ++x) {
      Color yuv_gamma_sdr = getYuv420Pixel(uncompressed_yuv_420_image, x, y);
      Color rgb_gamma_sdr = srgbYuvToRgb(yuv_gamma_sdr);
      Color rgb_sdr = srgbInvOetf(rgb_gamma_sdr);

      // TODO: determine map scaling factor based on actual map dims
      float recovery = sampleMap(uncompressed_recovery_map, kMapDimensionScaleFactor, x, y);
      Color rgb_hdr = applyRecovery(rgb_sdr, recovery, metadata->rangeScalingFactor);

      Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
      uint32_t rgba1010102 = colorToRgba1010102(rgb_gamma_hdr);

      size_t pixel_idx =  x + y * width;
      reinterpret_cast<uint32_t*>(dest->data)[pixel_idx] = rgba1010102;
    }
  }
  return NO_ERROR;
}

status_t RecoveryMap::extractPrimaryImageAndRecoveryMap(jr_compressed_ptr compressed_jpegr_image,
                                               jr_compressed_ptr primary_image,
                                               jr_compressed_ptr recovery_map) {
  if (compressed_jpegr_image == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  MessageHandler msg_handler;
  std::shared_ptr<DataSegment> seg =
                  DataSegment::Create(DataRange(0, compressed_jpegr_image->length),
                                      static_cast<const uint8_t*>(compressed_jpegr_image->data),
                                      DataSegment::BufferDispositionPolicy::kDontDelete);
  DataSegmentDataSource data_source(seg);
  JpegInfoBuilder jpeg_info_builder;
  jpeg_info_builder.SetImageLimit(2);
  JpegScanner jpeg_scanner(&msg_handler);
  jpeg_scanner.Run(&data_source, &jpeg_info_builder);
  data_source.Reset();

  if (jpeg_scanner.HasError()) {
    return ERROR_JPEGR_INVALID_INPUT_TYPE;
  }

  const auto& jpeg_info = jpeg_info_builder.GetInfo();
  const auto& image_ranges = jpeg_info.GetImageRanges();
  if (image_ranges.empty()) {
    return ERROR_JPEGR_INVALID_INPUT_TYPE;
  }

  if (image_ranges.size() != 2) {
    // Must be 2 JPEG Images
    return ERROR_JPEGR_INVALID_INPUT_TYPE;
  }

  if (primary_image != nullptr) {
    primary_image->data = static_cast<uint8_t*>(compressed_jpegr_image->data) +
                                               image_ranges[0].GetBegin();
    primary_image->length = image_ranges[0].GetLength();
  }

  if (recovery_map != nullptr) {
    recovery_map->data = static_cast<uint8_t*>(compressed_jpegr_image->data) +
                                              image_ranges[1].GetBegin();
    recovery_map->length = image_ranges[1].GetLength();
  }

  return NO_ERROR;
}


status_t RecoveryMap::extractRecoveryMap(jr_compressed_ptr compressed_jpegr_image,
                                         jr_compressed_ptr dest) {
  if (compressed_jpegr_image == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  return extractPrimaryImageAndRecoveryMap(compressed_jpegr_image, nullptr, dest);
}

status_t RecoveryMap::appendRecoveryMap(jr_compressed_ptr compressed_jpeg_image,
                                        jr_compressed_ptr compressed_recovery_map,
                                        jr_metadata_ptr metadata,
                                        jr_compressed_ptr dest) {
  if (compressed_jpeg_image == nullptr
   || compressed_recovery_map == nullptr
   || metadata == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  string xmp = generateXmp(compressed_recovery_map->length, *metadata);
  string nameSpace = "http://ns.adobe.com/xap/1.0/\0";

  // 2 bytes: APP1 sign (ff e1)
  // 29 bytes: length of name space "http://ns.adobe.com/xap/1.0/\0"
  // x bytes: length of xmp packet
  int length = 2 + nameSpace.size() + xmp.size();
  uint8_t lengthH = ((length >> 8) & 0xff);
  uint8_t lengthL = (length & 0xff);

  int pos = 0;

  // JPEG/R structure:
  // SOI (ff d8)
  // APP1 (ff e1)
  // 2 bytes of length (2 + 29 + length of xmp packet)
  // name space ("http://ns.adobe.com/xap/1.0/\0")
  // xmp
  // primary image (without the first two bytes, the SOI sign)
  // secondary image (the recovery map)
  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));
  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
  JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
  JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
  JPEGR_CHECK(Write(dest, (void*)nameSpace.c_str(), nameSpace.size(), pos));
  JPEGR_CHECK(Write(dest, (void*)xmp.c_str(), xmp.size(), pos));
  JPEGR_CHECK(Write(dest,
      (uint8_t*)compressed_jpeg_image->data + 2, compressed_jpeg_image->length - 2, pos));
  JPEGR_CHECK(Write(dest, compressed_recovery_map->data, compressed_recovery_map->length, pos));
  dest->length = pos;

  return NO_ERROR;
}

string RecoveryMap::generateXmp(int secondary_image_length, jpegr_metadata& metadata) {
  const string kContainerPrefix = "GContainer";
  const string kContainerUri    = "http://ns.google.com/photos/1.0/container/";
  const string kItemPrefix      = "Item";
  const string kRecoveryMap     = "RecoveryMap";
  const string kDirectory       = "Directory";
  const string kImageJpeg       = "image/jpeg";
  const string kItem            = "Item";
  const string kLength          = "Length";
  const string kMime            = "Mime";
  const string kPrimary         = "Primary";
  const string kSemantic        = "Semantic";
  const string kVersion         = "Version";

  const string kConDir          = Name(kContainerPrefix, kDirectory);
  const string kContainerItem   = Name(kContainerPrefix, kItem);
  const string kItemLength      = Name(kItemPrefix, kLength);
  const string kItemMime        = Name(kItemPrefix, kMime);
  const string kItemSemantic    = Name(kItemPrefix, kSemantic);

  const vector<string> kConDirSeq({kConDir, string("rdf:Seq")});
  const vector<string> kLiItem({string("rdf:li"), kContainerItem});

  std::stringstream ss;
  photos_editing_formats::image_io::XmlWriter writer(ss);
  writer.StartWritingElement("x:xmpmeta");
  writer.WriteXmlns("x", "adobe:ns:meta/");
  writer.WriteAttributeNameAndValue("x:xmptk", "Adobe XMP Core 5.1.2");
  writer.StartWritingElement("rdf:RDF");
  writer.WriteXmlns("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#");
  writer.StartWritingElement("rdf:Description");
  writer.WriteXmlns(kContainerPrefix, kContainerUri);
  writer.WriteElementAndContent(Name(kContainerPrefix, kVersion), metadata.version);
  writer.WriteElementAndContent(Name(kContainerPrefix, "rangeScalingFactor"),
                                metadata.rangeScalingFactor);
  // TODO: determine structure for hdr10 metadata
  // TODO: write rest of metadata
  writer.StartWritingElements(kConDirSeq);
  size_t item_depth = writer.StartWritingElements(kLiItem);
  writer.WriteAttributeNameAndValue(kItemSemantic, kPrimary);
  writer.WriteAttributeNameAndValue(kItemMime, kImageJpeg);
  writer.FinishWritingElementsToDepth(item_depth);
  writer.StartWritingElements(kLiItem);
  writer.WriteAttributeNameAndValue(kItemSemantic, kRecoveryMap);
  writer.WriteAttributeNameAndValue(kItemMime, kImageJpeg);
  writer.WriteAttributeNameAndValue(kItemLength, secondary_image_length);
  writer.FinishWriting();

  return ss.str();
}

} // namespace android::recoverymap
