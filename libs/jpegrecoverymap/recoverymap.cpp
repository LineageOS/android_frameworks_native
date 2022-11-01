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

#include "image_io/xml/xml_writer.h"

#include <jpegrecoverymap/recoverymap.h>
#include <sstream>
#include <string>

using namespace std;

namespace android::recoverymap {

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

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_uncompressed_ptr uncompressed_yuv_420_image,
                                  void* dest) {
  if (uncompressed_p010_image == nullptr
   || uncompressed_yuv_420_image == nullptr
   || dest == nullptr) {
    return BAD_VALUE;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  jr_uncompressed_ptr uncompressed_yuv_420_image,
                                  void* compressed_jpeg_image,
                                  void* dest) {

  if (uncompressed_p010_image == nullptr
   || uncompressed_yuv_420_image == nullptr
   || compressed_jpeg_image == nullptr
   || dest == nullptr) {
    return BAD_VALUE;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                                  void* compressed_jpeg_image,
                                  void* dest) {
  if (uncompressed_p010_image == nullptr
   || compressed_jpeg_image == nullptr
   || dest == nullptr) {
    return BAD_VALUE;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::decodeJPEGR(void* compressed_jpegr_image, jr_uncompressed_ptr dest) {
  if (compressed_jpegr_image == nullptr || dest == nullptr) {
    return BAD_VALUE;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::decodeRecoveryMap(jr_compressed_ptr compressed_recovery_map,
                                        jr_uncompressed_ptr dest) {
  if (compressed_recovery_map == nullptr || dest == nullptr) {
    return BAD_VALUE;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::encodeRecoveryMap(jr_uncompressed_ptr uncompressed_recovery_map,
                                        jr_compressed_ptr dest) {
  if (uncompressed_recovery_map == nullptr || dest == nullptr) {
    return BAD_VALUE;
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
    return BAD_VALUE;
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
    return BAD_VALUE;
  }

  // TBD
  return NO_ERROR;
}

status_t RecoveryMap::extractRecoveryMap(void* compressed_jpegr_image, jr_compressed_ptr dest) {
  if (compressed_jpegr_image == nullptr || dest == nullptr) {
    return BAD_VALUE;
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
    return BAD_VALUE;
  }

  // TBD
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
