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

// TODO: need to clean up handling around hdr_ratio and passing it around
// TODO: need to handle color space information; currently we assume everything
// is srgb in.
// TODO: handle PQ encode/decode (currently only HLG)

#include <jpegrecoverymap/recoverymap.h>
#include <jpegrecoverymap/jpegencoder.h>
#include <jpegrecoverymap/jpegdecoder.h>
#include <jpegrecoverymap/recoverymapmath.h>

#include <image_io/jpeg/jpeg_marker.h>
#include <image_io/xml/xml_writer.h>

#include <memory>
#include <sstream>
#include <string>

using namespace std;

namespace android::recoverymap {

#define JPEGR_CHECK(x)          \
  {                             \
    status_t status = (x);      \
    if ((status) != NO_ERROR) { \
      return status;            \
    }                           \
  }

// Map is quarter res / sixteenth size
static const size_t kMapDimensionScaleFactor = 4;


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
  if (position + length > destination->length) {
    return ERROR_JPEGR_BUFFER_TOO_SMALL;
  }

  memcpy((uint8_t*)destination->data + sizeof(uint8_t) * position, source, length);
  position += length;
  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_uncompressed_ptr uncompressed_yuv_420_image,
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

  jpegr_uncompressed_struct map;
  float hdr_ratio = 0.0f;
  JPEGR_CHECK(generateRecoveryMap(
      uncompressed_yuv_420_image, uncompressed_p010_image, &map, hdr_ratio));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(map.data));

  jpegr_compressed_struct compressed_map;
  std::unique_ptr<uint8_t[]> compressed_map_data =
      std::make_unique<uint8_t[]>(map.width * map.height);
  compressed_map.data = compressed_map_data.get();
  JPEGR_CHECK(compressRecoveryMap(&map, &compressed_map));

  JpegEncoder jpeg_encoder;
  // TODO: ICC data - need color space information
  if (!jpeg_encoder.compressImage(uncompressed_yuv_420_image->data,
                                  uncompressed_yuv_420_image->width,
                                  uncompressed_yuv_420_image->height, quality, nullptr, 0)) {
    return ERROR_JPEGR_ENCODE_ERROR;
  }
  jpegr_compressed_struct jpeg;
  jpeg.data = jpeg_encoder.getCompressedImagePtr();
  jpeg.length = jpeg_encoder.getCompressedImageSize();

  JPEGR_CHECK(appendRecoveryMap(&jpeg, &compressed_map, hdr_ratio, dest));

  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_uncompressed_ptr uncompressed_yuv_420_image,
                                  jr_compressed_ptr compressed_jpeg_image,
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

  jpegr_uncompressed_struct map;
  float hdr_ratio = 0.0f;
  JPEGR_CHECK(generateRecoveryMap(
      uncompressed_yuv_420_image, uncompressed_p010_image, &map, hdr_ratio));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(map.data));

  jpegr_compressed_struct compressed_map;
  std::unique_ptr<uint8_t[]> compressed_map_data =
      std::make_unique<uint8_t[]>(map.width * map.height);
  compressed_map.data = compressed_map_data.get();
  JPEGR_CHECK(compressRecoveryMap(&map, &compressed_map));

  JPEGR_CHECK(appendRecoveryMap(compressed_jpeg_image, &compressed_map, hdr_ratio, dest));

  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_compressed_ptr compressed_jpeg_image,
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

  if (uncompressed_p010_image->width != uncompressed_yuv_420_image.width
   || uncompressed_p010_image->height != uncompressed_yuv_420_image.height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }

  jpegr_uncompressed_struct map;
  float hdr_ratio = 0.0f;
  JPEGR_CHECK(generateRecoveryMap(
      &uncompressed_yuv_420_image, uncompressed_p010_image, &map, hdr_ratio));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(map.data));

  jpegr_compressed_struct compressed_map;
  std::unique_ptr<uint8_t[]> compressed_map_data =
      std::make_unique<uint8_t[]>(map.width * map.height);
  compressed_map.data = compressed_map_data.get();
  JPEGR_CHECK(compressRecoveryMap(&map, &compressed_map));

  JPEGR_CHECK(appendRecoveryMap(compressed_jpeg_image, &compressed_map, hdr_ratio, dest));

  return NO_ERROR;
}

status_t RecoveryMap::decodeJPEGR(jr_compressed_ptr compressed_jpegr_image,
                                  jr_uncompressed_ptr dest,
                                  jr_exif_ptr /* exif */,
                                  bool /* request_sdr */) {
  if (compressed_jpegr_image == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  jpegr_compressed_struct compressed_map;
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

  JPEGR_CHECK(applyRecoveryMap(&uncompressed_yuv_420_image, &map, dest));

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

  // TODO: should we have ICC data?
  JpegEncoder jpeg_encoder;
  if (!jpeg_encoder.compressImage(uncompressed_recovery_map->data, uncompressed_recovery_map->width,
                                  uncompressed_recovery_map->height, 85, nullptr, 0,
                                  true /* isSingleChannel */)) {
    return ERROR_JPEGR_ENCODE_ERROR;
  }

  if (dest->length < jpeg_encoder.getCompressedImageSize()) {
    return ERROR_JPEGR_BUFFER_TOO_SMALL;
  }

  memcpy(dest->data, jpeg_encoder.getCompressedImagePtr(), jpeg_encoder.getCompressedImageSize());
  dest->length = jpeg_encoder.getCompressedImageSize();

  return NO_ERROR;
}

status_t RecoveryMap::generateRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                                          jr_uncompressed_ptr uncompressed_p010_image,
                                          jr_uncompressed_ptr dest,
                                          float &hdr_ratio) {
  if (uncompressed_yuv_420_image == nullptr
   || uncompressed_p010_image == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  if (uncompressed_yuv_420_image->width != uncompressed_p010_image->width
   || uncompressed_yuv_420_image->height != uncompressed_p010_image->height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }

  size_t image_width = uncompressed_yuv_420_image->width;
  size_t image_height = uncompressed_yuv_420_image->height;
  size_t map_width = image_width / kMapDimensionScaleFactor;
  size_t map_height = image_height / kMapDimensionScaleFactor;

  dest->width = map_width;
  dest->height = map_height;
  dest->data = new uint8_t[map_width * map_height];
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(dest->data));

  uint16_t yp_hdr_max = 0;
  for (size_t y = 0; y < image_height; ++y) {
    for (size_t x = 0; x < image_width; ++x) {
      size_t pixel_idx =  x + y * image_width;
      uint16_t yp_hdr = reinterpret_cast<uint8_t*>(uncompressed_yuv_420_image->data)[pixel_idx];
      if (yp_hdr > yp_hdr_max) {
        yp_hdr_max = yp_hdr;
      }
    }
  }

  float y_hdr_max_nits = hlgInvOetf(yp_hdr_max);
  hdr_ratio = y_hdr_max_nits / kSdrWhiteNits;

  for (size_t y = 0; y < map_height; ++y) {
    for (size_t x = 0; x < map_width; ++x) {
      float yp_sdr = sampleYuv420Y(uncompressed_yuv_420_image, kMapDimensionScaleFactor, x, y);
      float yp_hdr = sampleP010Y(uncompressed_p010_image, kMapDimensionScaleFactor, x, y);

      float y_sdr_nits = srgbInvOetf(yp_sdr);
      float y_hdr_nits = hlgInvOetf(yp_hdr);

      size_t pixel_idx =  x + y * map_width;
      reinterpret_cast<uint8_t*>(dest->data)[pixel_idx] =
          encodeRecovery(y_sdr_nits, y_hdr_nits, hdr_ratio);
    }
  }

  map_data.release();
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

  // TODO: need to get this from the XMP; should probably be a function
  // parameter
  float hdr_ratio = 4.0f;

  size_t width = uncompressed_yuv_420_image->width;
  size_t height = uncompressed_yuv_420_image->height;

  dest->width = width;
  dest->height = height;
  size_t pixel_count = width * height;

  for (size_t y = 0; y < height; ++y) {
    for (size_t x = 0; x < width; ++x) {
      size_t pixel_y_idx =  x + y * width;

      size_t pixel_uv_idx = x / 2 + (y / 2) * (width / 2);

      Color ypuv_sdr = getYuv420Pixel(uncompressed_yuv_420_image, x, y);
      Color rgbp_sdr = srgbYuvToRgb(ypuv_sdr);
      Color rgb_sdr = srgbInvOetf(rgbp_sdr);

      float recovery = sampleMap(uncompressed_recovery_map, kMapDimensionScaleFactor, x, y);
      Color rgb_hdr = applyRecovery(rgb_sdr, recovery, hdr_ratio);

      Color rgbp_hdr = hlgOetf(rgb_hdr);
      Color ypuv_hdr = bt2100RgbToYuv(rgbp_hdr);

      reinterpret_cast<uint16_t*>(dest->data)[pixel_y_idx] = ypuv_hdr.r;
      reinterpret_cast<uint16_t*>(dest->data)[pixel_count + pixel_uv_idx] = ypuv_hdr.g;
      reinterpret_cast<uint16_t*>(dest->data)[pixel_count + pixel_uv_idx + 1] = ypuv_hdr.b;
    }
  }

  return NO_ERROR;
}

status_t RecoveryMap::extractRecoveryMap(jr_compressed_ptr compressed_jpegr_image,
                                         jr_compressed_ptr dest) {
  if (compressed_jpegr_image == nullptr || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::appendRecoveryMap(jr_compressed_ptr compressed_jpeg_image,
                                        jr_compressed_ptr compressed_recovery_map,
                                        float hdr_ratio,
                                        jr_compressed_ptr dest) {
  if (compressed_jpeg_image == nullptr
   || compressed_recovery_map == nullptr
   || dest == nullptr) {
    return ERROR_JPEGR_INVALID_NULL_PTR;
  }

  string xmp = generateXmp(compressed_recovery_map->length, hdr_ratio);
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

string RecoveryMap::generateXmp(int secondary_image_length, float hdr_ratio) {
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
  const int    kVersionValue    = 1;

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
  writer.WriteElementAndContent(Name(kContainerPrefix, kVersion), kVersionValue);
  writer.WriteElementAndContent(Name(kContainerPrefix, "HdrRatio"), hdr_ratio);
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
