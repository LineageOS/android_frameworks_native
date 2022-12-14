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
#include <jpegrecoverymap/recoverymaputils.h>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <utils/Log.h>

#define RAW_P010_IMAGE "/sdcard/Documents/raw_p010_image.p010"
#define RAW_YUV420_IMAGE "/sdcard/Documents/raw_yuv420_image.yuv420"
#define JPEG_IMAGE "/sdcard/Documents/jpeg_image.jpg"
#define TEST_IMAGE_WIDTH 1280
#define TEST_IMAGE_HEIGHT 720
#define DEFAULT_JPEG_QUALITY 90

#define SAVE_ENCODING_RESULT true
#define SAVE_DECODING_RESULT true

namespace android::recoverymap {

class RecoveryMapTest : public testing::Test {
public:
  RecoveryMapTest();
  ~RecoveryMapTest();
protected:
  virtual void SetUp();
  virtual void TearDown();

  struct jpegr_uncompressed_struct mRawP010Image;
  struct jpegr_uncompressed_struct mRawYuv420Image;
  struct jpegr_compressed_struct mJpegImage;
};

RecoveryMapTest::RecoveryMapTest() {}
RecoveryMapTest::~RecoveryMapTest() {}

void RecoveryMapTest::SetUp() {}
void RecoveryMapTest::TearDown() {
  free(mRawP010Image.data);
  free(mRawYuv420Image.data);
  free(mJpegImage.data);
}

static size_t getFileSize(int fd) {
  struct stat st;
  if (fstat(fd, &st) < 0) {
    ALOGW("%s : fstat failed", __func__);
    return 0;
  }
  return st.st_size; // bytes
}

static bool loadFile(const char filename[], void*& result, int* fileLength) {
  int fd = open(filename, O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  int length = getFileSize(fd);
  if (length == 0) {
    close(fd);
    return false;
  }
  if (fileLength != nullptr) {
    *fileLength = length;
  }
  result = malloc(length);
  if (read(fd, result, length) != static_cast<ssize_t>(length)) {
    close(fd);
    return false;
  }
  close(fd);
  return true;
}

TEST_F(RecoveryMapTest, build) {
  // Force all of the recovery map lib to be linked by calling all public functions.
  RecoveryMap recovery_map;
  recovery_map.encodeJPEGR(nullptr, static_cast<jpegr_transfer_function>(0), nullptr, 0, nullptr);
  recovery_map.encodeJPEGR(nullptr, nullptr, static_cast<jpegr_transfer_function>(0),
                           nullptr, 0, nullptr);
  recovery_map.encodeJPEGR(nullptr, nullptr, nullptr, static_cast<jpegr_transfer_function>(0),
                           nullptr);
  recovery_map.encodeJPEGR(nullptr, nullptr, static_cast<jpegr_transfer_function>(0), nullptr);
  recovery_map.decodeJPEGR(nullptr, nullptr, nullptr, false);
}

TEST_F(RecoveryMapTest, writeXmpThenRead) {
  jpegr_metadata metadata_expected;
  metadata_expected.transferFunction = JPEGR_TF_HLG;
  metadata_expected.rangeScalingFactor = 1.25;
  int length_expected = 1000;
  std::string xmp = generateXmp(1000, metadata_expected);

  jpegr_metadata metadata_read;
  EXPECT_TRUE(getMetadataFromXMP(reinterpret_cast<uint8_t*>(xmp[0]), xmp.size(), &metadata_read));
  ASSERT_EQ(metadata_expected.transferFunction, metadata_read.transferFunction);
  ASSERT_EQ(metadata_expected.rangeScalingFactor, metadata_read.rangeScalingFactor);

}

/* Test Encode API-0 and decode */
// TODO: enable when tonemapper is ready.
//TEST_F(RecoveryMapTest, encodeFromP010ThenDecode) {
//  int ret;
//
//  // Load input files.
//  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
//    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
//  }
//  mRawP010Image.width = TEST_IMAGE_WIDTH;
//  mRawP010Image.height = TEST_IMAGE_HEIGHT;
//  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;
//
//  RecoveryMap recoveryMap;
//
//  jpegr_compressed_struct jpegR;
//  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
//  jpegR.data = malloc(jpegR.maxLength);
//  ret = recoveryMap.encodeJPEGR(
//      &mRawP010Image, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR, 90, nullptr);
//  if (ret != OK) {
//    FAIL() << "Error code is " << ret;
//  }
//  if (SAVE_ENCODING_RESULT) {
//    // Output image data to file
//    std::string filePath = "/sdcard/Documents/encoded_from_jpeg_input.jpgr";
//    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
//    if (!imageFile.is_open()) {
//      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
//    }
//    imageFile.write((const char*)jpegR.data, jpegR.length);
//  }
//
//  jpegr_uncompressed_struct decodedJpegR;
//  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 4;
//  decodedJpegR.data = malloc(decodedJpegRSize);
//  ret = recoveryMap.decodeJPEGR(&jpegR, &decodedJpegR);
//  if (ret != OK) {
//    FAIL() << "Error code is " << ret;
//  }
//  if (SAVE_DECODING_RESULT) {
//    // Output image data to file
//    std::string filePath = "/sdcard/Documents/decoded_from_jpeg_input.rgb10";
//    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
//    if (!imageFile.is_open()) {
//      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
//    }
//    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
//  }
//
//  free(jpegR.data);
//  free(decodedJpegR.data);
//}

/* Test Encode API-1 and decode */
TEST_F(RecoveryMapTest, encodeFromRawHdrAndSdrThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  if (!loadFile(RAW_YUV420_IMAGE, mRawYuv420Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT709;

  RecoveryMap recoveryMap;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = recoveryMap.encodeJPEGR(
      &mRawP010Image, &mRawYuv420Image, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_jpeg_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 4;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = recoveryMap.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_jpeg_input.rgb10";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

/* Test Encode API-2 and decode */
TEST_F(RecoveryMapTest, encodeFromRawHdrAndSdrAndJpegThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  if (!loadFile(RAW_YUV420_IMAGE, mRawYuv420Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT709;

  if (!loadFile(JPEG_IMAGE, mJpegImage.data, &mJpegImage.length)) {
    FAIL() << "Load file " << JPEG_IMAGE << " failed";
  }
  mJpegImage.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT709;

  RecoveryMap recoveryMap;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = recoveryMap.encodeJPEGR(
      &mRawP010Image, &mRawYuv420Image, &mJpegImage, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_jpeg_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 4;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = recoveryMap.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_jpeg_input.rgb10";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

/* Test Encode API-3 and decode */
TEST_F(RecoveryMapTest, encodeFromJpegThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  if (!loadFile(JPEG_IMAGE, mJpegImage.data, &mJpegImage.length)) {
    FAIL() << "Load file " << JPEG_IMAGE << " failed";
  }
  mJpegImage.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT709;

  RecoveryMap recoveryMap;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = recoveryMap.encodeJPEGR(
      &mRawP010Image, &mJpegImage, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_jpeg_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 4;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = recoveryMap.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_jpeg_input.rgb10";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

} // namespace android::recoverymap
