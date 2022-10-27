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

#include <jpegrecoverymap/jpegencoder.h>
#include <gtest/gtest.h>
#include <utils/Log.h>

#include <fcntl.h>

namespace android::recoverymap {

#define VALID_IMAGE "/sdcard/Documents/minnie-320x240.yu12"
#define VALID_IMAGE_WIDTH 320
#define VALID_IMAGE_HEIGHT 240
#define SINGLE_CHANNEL_IMAGE "/sdcard/Documents/minnie-320x240.y"
#define SINGLE_CHANNEL_IMAGE_WIDTH VALID_IMAGE_WIDTH
#define SINGLE_CHANNEL_IMAGE_HEIGHT VALID_IMAGE_HEIGHT
#define INVALID_SIZE_IMAGE "/sdcard/Documents/minnie-318x240.yu12"
#define INVALID_SIZE_IMAGE_WIDTH 318
#define INVALID_SIZE_IMAGE_HEIGHT 240
#define JPEG_QUALITY 90

class JpegEncoderTest : public testing::Test {
public:
    struct Image {
        std::unique_ptr<uint8_t[]> buffer;
        size_t width;
        size_t height;
    };
    JpegEncoderTest();
    ~JpegEncoderTest();
protected:
    virtual void SetUp();
    virtual void TearDown();

    Image mValidImage, mInvalidSizeImage, mSingleChannelImage;
};

JpegEncoderTest::JpegEncoderTest() {}

JpegEncoderTest::~JpegEncoderTest() {}

static size_t getFileSize(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        ALOGW("%s : fstat failed", __func__);
        return 0;
    }
    return st.st_size; // bytes
}

static bool loadFile(const char filename[], JpegEncoderTest::Image* result) {
    int fd = open(filename, O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    int length = getFileSize(fd);
    if (length == 0) {
        close(fd);
        return false;
    }
    result->buffer.reset(new uint8_t[length]);
    if (read(fd, result->buffer.get(), length) != static_cast<ssize_t>(length)) {
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

void JpegEncoderTest::SetUp() {
    if (!loadFile(VALID_IMAGE, &mValidImage)) {
        FAIL() << "Load file " << VALID_IMAGE << " failed";
    }
    mValidImage.width = VALID_IMAGE_WIDTH;
    mValidImage.height = VALID_IMAGE_HEIGHT;
    if (!loadFile(INVALID_SIZE_IMAGE, &mInvalidSizeImage)) {
        FAIL() << "Load file " << INVALID_SIZE_IMAGE << " failed";
    }
    mInvalidSizeImage.width = INVALID_SIZE_IMAGE_WIDTH;
    mInvalidSizeImage.height = INVALID_SIZE_IMAGE_HEIGHT;
    if (!loadFile(SINGLE_CHANNEL_IMAGE, &mSingleChannelImage)) {
        FAIL() << "Load file " << SINGLE_CHANNEL_IMAGE << " failed";
    }
    mSingleChannelImage.width = SINGLE_CHANNEL_IMAGE_WIDTH;
    mSingleChannelImage.height = SINGLE_CHANNEL_IMAGE_HEIGHT;
}

void JpegEncoderTest::TearDown() {}

TEST_F(JpegEncoderTest, validImage) {
    JpegEncoder encoder;
    EXPECT_TRUE(encoder.compressImage(mValidImage.buffer.get(), mValidImage.width,
                                         mValidImage.height, JPEG_QUALITY, NULL, 0));
    ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
}

TEST_F(JpegEncoderTest, invalidSizeImage) {
    JpegEncoder encoder;
    EXPECT_FALSE(encoder.compressImage(mInvalidSizeImage.buffer.get(), mInvalidSizeImage.width,
                                          mInvalidSizeImage.height, JPEG_QUALITY, NULL, 0));
}

TEST_F(JpegEncoderTest, singleChannelImage) {
    JpegEncoder encoder;
    EXPECT_TRUE(encoder.compressImage(mSingleChannelImage.buffer.get(), mSingleChannelImage.width,
                                         mSingleChannelImage.height, JPEG_QUALITY, NULL, 0, true));
    ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
}

}

