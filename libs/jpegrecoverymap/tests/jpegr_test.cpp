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

#include <jpegrecoverymap/jpegr.h>
#include <jpegrecoverymap/jpegrutils.h>
#include <jpegrecoverymap/recoverymapmath.h>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/time.h>
#include <utils/Log.h>

#define RAW_P010_IMAGE "/sdcard/Documents/raw_p010_image.p010"
#define RAW_P010_IMAGE_WITH_STRIDE "/sdcard/Documents/raw_p010_image_with_stride.p010"
#define RAW_YUV420_IMAGE "/sdcard/Documents/raw_yuv420_image.yuv420"
#define JPEG_IMAGE "/sdcard/Documents/jpeg_image.jpg"
#define TEST_IMAGE_WIDTH 1280
#define TEST_IMAGE_HEIGHT 720
#define TEST_IMAGE_STRIDE 1288
#define DEFAULT_JPEG_QUALITY 90

#define SAVE_ENCODING_RESULT true
#define SAVE_DECODING_RESULT true
#define SAVE_INPUT_RGBA true

namespace android::jpegrecoverymap {

struct Timer {
  struct timeval StartingTime;
  struct timeval EndingTime;
  struct timeval ElapsedMicroseconds;
};

void timerStart(Timer *t) {
  gettimeofday(&t->StartingTime, nullptr);
}

void timerStop(Timer *t) {
  gettimeofday(&t->EndingTime, nullptr);
}

int64_t elapsedTime(Timer *t) {
  t->ElapsedMicroseconds.tv_sec = t->EndingTime.tv_sec - t->StartingTime.tv_sec;
  t->ElapsedMicroseconds.tv_usec = t->EndingTime.tv_usec - t->StartingTime.tv_usec;
  return t->ElapsedMicroseconds.tv_sec * 1000000 + t->ElapsedMicroseconds.tv_usec;
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

class JpegRTest : public testing::Test {
public:
  JpegRTest();
  ~JpegRTest();

protected:
  virtual void SetUp();
  virtual void TearDown();

  struct jpegr_uncompressed_struct mRawP010Image;
  struct jpegr_uncompressed_struct mRawP010ImageWithStride;
  struct jpegr_uncompressed_struct mRawYuv420Image;
  struct jpegr_compressed_struct mJpegImage;
};

JpegRTest::JpegRTest() {}
JpegRTest::~JpegRTest() {}

void JpegRTest::SetUp() {}
void JpegRTest::TearDown() {
  free(mRawP010Image.data);
  free(mRawP010ImageWithStride.data);
  free(mRawYuv420Image.data);
  free(mJpegImage.data);
}

class JpegRBenchmark : public JpegR {
public:
 void BenchmarkGenerateRecoveryMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr p010Image,
                                   jr_metadata_ptr metadata, jr_uncompressed_ptr map);
 void BenchmarkApplyRecoveryMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr map,
                                jr_metadata_ptr metadata, jr_uncompressed_ptr dest);
private:
 const int kProfileCount = 10;
};

void JpegRBenchmark::BenchmarkGenerateRecoveryMap(jr_uncompressed_ptr yuv420Image,
                                                        jr_uncompressed_ptr p010Image,
                                                        jr_metadata_ptr metadata,
                                                        jr_uncompressed_ptr map) {
  ASSERT_EQ(yuv420Image->width, p010Image->width);
  ASSERT_EQ(yuv420Image->height, p010Image->height);

  Timer genRecMapTime;

  timerStart(&genRecMapTime);
  for (auto i = 0; i < kProfileCount; i++) {
      ASSERT_EQ(OK, generateRecoveryMap(
          yuv420Image, p010Image, jpegr_transfer_function::JPEGR_TF_HLG, metadata, map));
      if (i != kProfileCount - 1) delete[] static_cast<uint8_t *>(map->data);
  }
  timerStop(&genRecMapTime);

  ALOGE("Generate Recovery Map:- Res = %i x %i, time = %f ms",
        yuv420Image->width, yuv420Image->height,
        elapsedTime(&genRecMapTime) / (kProfileCount * 1000.f));

}

void JpegRBenchmark::BenchmarkApplyRecoveryMap(jr_uncompressed_ptr yuv420Image,
                                                     jr_uncompressed_ptr map,
                                                     jr_metadata_ptr metadata,
                                                     jr_uncompressed_ptr dest) {
  Timer applyRecMapTime;

  timerStart(&applyRecMapTime);
  for (auto i = 0; i < kProfileCount; i++) {
      ASSERT_EQ(OK, applyRecoveryMap(yuv420Image, map, metadata, JPEGR_OUTPUT_HDR_HLG,
                                     metadata->maxContentBoost /* displayBoost */, dest));
  }
  timerStop(&applyRecMapTime);

  ALOGE("Apply Recovery Map:- Res = %i x %i, time = %f ms",
        yuv420Image->width, yuv420Image->height,
        elapsedTime(&applyRecMapTime) / (kProfileCount * 1000.f));
}

TEST_F(JpegRTest, build) {
  // Force all of the recovery map lib to be linked by calling all public functions.
  JpegR jpegRCodec;
  jpegRCodec.encodeJPEGR(nullptr, static_cast<jpegr_transfer_function>(0), nullptr, 0, nullptr);
  jpegRCodec.encodeJPEGR(nullptr, nullptr, static_cast<jpegr_transfer_function>(0),
                         nullptr, 0, nullptr);
  jpegRCodec.encodeJPEGR(nullptr, nullptr, nullptr, static_cast<jpegr_transfer_function>(0),
                         nullptr);
  jpegRCodec.encodeJPEGR(nullptr, nullptr, static_cast<jpegr_transfer_function>(0), nullptr);
  jpegRCodec.decodeJPEGR(nullptr, nullptr);
}

TEST_F(JpegRTest, writeXmpThenRead) {
  jpegr_metadata_struct metadata_expected;
  metadata_expected.maxContentBoost = 1.25;
  metadata_expected.minContentBoost = 0.75;
  const std::string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
  const int nameSpaceLength = nameSpace.size() + 1;  // need to count the null terminator

  std::string xmp = generateXmpForSecondaryImage(metadata_expected);

  std::vector<uint8_t> xmpData;
  xmpData.reserve(nameSpaceLength + xmp.size());
  xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(nameSpace.c_str()),
                  reinterpret_cast<const uint8_t*>(nameSpace.c_str()) + nameSpaceLength);
  xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(xmp.c_str()),
                  reinterpret_cast<const uint8_t*>(xmp.c_str()) + xmp.size());

  jpegr_metadata_struct metadata_read;
  EXPECT_TRUE(getMetadataFromXMP(xmpData.data(), xmpData.size(), &metadata_read));
  EXPECT_FLOAT_EQ(metadata_expected.maxContentBoost, metadata_read.maxContentBoost);
  EXPECT_FLOAT_EQ(metadata_expected.minContentBoost, metadata_read.minContentBoost);
}

/* Test Encode API-0 and decode */
TEST_F(JpegRTest, encodeFromP010ThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR, DEFAULT_JPEG_QUALITY, nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_input.rgb";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

/* Test Encode API-0 (with stride) and decode */
TEST_F(JpegRTest, encodeFromP010WithStrideThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE_WITH_STRIDE, mRawP010ImageWithStride.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE_WITH_STRIDE << " failed";
  }
  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_input.rgb";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

/* Test Encode API-1 and decode */
TEST_F(JpegRTest, encodeFromRawHdrAndSdrThenDecode) {
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

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, &mRawYuv420Image, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_yuv420p_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_yuv420p_input.rgb";
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
TEST_F(JpegRTest, encodeFromRawHdrAndSdrAndJpegThenDecode) {
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

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, &mRawYuv420Image, &mJpegImage, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_yuv420p_jpeg_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_yuv420p_jpeg_input.rgb";
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
TEST_F(JpegRTest, encodeFromJpegThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  if (SAVE_INPUT_RGBA) {
    size_t rgbaSize = mRawP010Image.width * mRawP010Image.height * sizeof(uint32_t);
    uint32_t *data = (uint32_t *)malloc(rgbaSize);

    for (size_t y = 0; y < mRawP010Image.height; ++y) {
      for (size_t x = 0; x < mRawP010Image.width; ++x) {
        Color hdr_yuv_gamma = getP010Pixel(&mRawP010Image, x, y);
        Color hdr_rgb_gamma = bt2100YuvToRgb(hdr_yuv_gamma);
        uint32_t rgba1010102 = colorToRgba1010102(hdr_rgb_gamma);
        size_t pixel_idx =  x + y * mRawP010Image.width;
        reinterpret_cast<uint32_t*>(data)[pixel_idx] = rgba1010102;
      }
    }

    // Output image data to file
    std::string filePath = "/sdcard/Documents/input_from_p010.rgb10";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)data, rgbaSize);
    free(data);
  }
  if (!loadFile(JPEG_IMAGE, mJpegImage.data, &mJpegImage.length)) {
    FAIL() << "Load file " << JPEG_IMAGE << " failed";
  }
  mJpegImage.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT709;

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, &mJpegImage, jpegr_transfer_function::JPEGR_TF_HLG, &jpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_jpeg_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_jpeg_input.rgb";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

TEST_F(JpegRTest, ProfileRecoveryMapFuncs) {
  const size_t kWidth = TEST_IMAGE_WIDTH;
  const size_t kHeight = TEST_IMAGE_HEIGHT;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = kWidth;
  mRawP010Image.height = kHeight;
  mRawP010Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT2100;

  if (!loadFile(RAW_YUV420_IMAGE, mRawYuv420Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawYuv420Image.width = kWidth;
  mRawYuv420Image.height = kHeight;
  mRawYuv420Image.colorGamut = jpegr_color_gamut::JPEGR_COLORGAMUT_BT709;

  JpegRBenchmark benchmark;

  jpegr_metadata_struct metadata = { .version = 1,
                              .maxContentBoost = 8.0f,
                              .minContentBoost = 1.0f / 8.0f };

  jpegr_uncompressed_struct map = { .data = NULL,
                                    .width = 0,
                                    .height = 0,
                                    .colorGamut = JPEGR_COLORGAMUT_UNSPECIFIED };

  benchmark.BenchmarkGenerateRecoveryMap(&mRawYuv420Image, &mRawP010Image, &metadata, &map);

  const int dstSize = mRawYuv420Image.width * mRawYuv420Image.height * 4;
  auto bufferDst = std::make_unique<uint8_t[]>(dstSize);
  jpegr_uncompressed_struct dest = { .data = bufferDst.get(),
                                     .width = 0,
                                     .height = 0,
                                     .colorGamut = JPEGR_COLORGAMUT_UNSPECIFIED };

  benchmark.BenchmarkApplyRecoveryMap(&mRawYuv420Image, &map, &metadata, &dest);
}

} // namespace android::recoverymap
