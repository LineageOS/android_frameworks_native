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
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <utils/Log.h>

#define RAW_P010_IMAGE "/sdcard/Documents/raw_p010_image.p010"
#define RAW_P010_IMAGE_WIDTH 1280
#define RAW_P010_IMAGE_HEIGHT 720
#define JPEG_IMAGE "/sdcard/Documents/jpeg_image.jpg"

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
  struct jpegr_compressed_struct mJpegImage;
};

RecoveryMapTest::RecoveryMapTest() {}
RecoveryMapTest::~RecoveryMapTest() {}

void RecoveryMapTest::SetUp() {}
void RecoveryMapTest::TearDown() {
  free(mRawP010Image.data);
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
  recovery_map.encodeJPEGR(nullptr, nullptr, static_cast<jpegr_transfer_function>(0),
                           nullptr, 0, nullptr);
  recovery_map.encodeJPEGR(nullptr, nullptr, nullptr, static_cast<jpegr_transfer_function>(0),
                           nullptr);
  recovery_map.encodeJPEGR(nullptr, nullptr, static_cast<jpegr_transfer_function>(0), nullptr);
  recovery_map.decodeJPEGR(nullptr, nullptr, nullptr, false);
}

TEST_F(RecoveryMapTest, encodeFromP010ThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = RAW_P010_IMAGE_WIDTH;
  mRawP010Image.height = RAW_P010_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  RecoveryMap recoveryMap;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = RAW_P010_IMAGE_WIDTH * RAW_P010_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = recoveryMap.encodeJPEGR(
      &mRawP010Image, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR, 90, nullptr);
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
  int decodedJpegRSize = RAW_P010_IMAGE_WIDTH * RAW_P010_IMAGE_HEIGHT * 4;
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

TEST_F(RecoveryMapTest, encodeFromJpegThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = RAW_P010_IMAGE_WIDTH;
  mRawP010Image.height = RAW_P010_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  if (!loadFile(JPEG_IMAGE, mJpegImage.data, &mJpegImage.length)) {
    FAIL() << "Load file " << JPEG_IMAGE << " failed";
  }
  mJpegImage.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT709;

  RecoveryMap recoveryMap;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = RAW_P010_IMAGE_WIDTH * RAW_P010_IMAGE_HEIGHT * sizeof(uint8_t);
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
  int decodedJpegRSize = RAW_P010_IMAGE_WIDTH * RAW_P010_IMAGE_HEIGHT * 4;
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
