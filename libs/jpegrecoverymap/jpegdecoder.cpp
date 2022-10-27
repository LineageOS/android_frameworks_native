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

#include <jpegrecoverymap/jpegdecoder.h>

#include <cutils/log.h>

#include <errno.h>
#include <setjmp.h>

namespace android::recoverymap {
struct jpegr_source_mgr : jpeg_source_mgr {
    jpegr_source_mgr(const uint8_t* ptr, int len);
    ~jpegr_source_mgr();

    const uint8_t* mBufferPtr;
    size_t mBufferLength;
};

struct jpegrerror_mgr {
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};

static void jpegr_init_source(j_decompress_ptr cinfo) {
    jpegr_source_mgr* src = static_cast<jpegr_source_mgr*>(cinfo->src);
    src->next_input_byte = static_cast<const JOCTET*>(src->mBufferPtr);
    src->bytes_in_buffer = src->mBufferLength;
}

static boolean jpegr_fill_input_buffer(j_decompress_ptr /* cinfo */) {
    ALOGE("%s : should not get here", __func__);
    return FALSE;
}

static void jpegr_skip_input_data(j_decompress_ptr cinfo, long num_bytes) {
    jpegr_source_mgr* src = static_cast<jpegr_source_mgr*>(cinfo->src);

    if (num_bytes > static_cast<long>(src->bytes_in_buffer)) {
        ALOGE("jpegr_skip_input_data - num_bytes > (long)src->bytes_in_buffer");
    } else {
        src->next_input_byte += num_bytes;
        src->bytes_in_buffer -= num_bytes;
    }
}

static void jpegr_term_source(j_decompress_ptr /*cinfo*/) {}

jpegr_source_mgr::jpegr_source_mgr(const uint8_t* ptr, int len) :
        mBufferPtr(ptr), mBufferLength(len) {
    init_source = jpegr_init_source;
    fill_input_buffer = jpegr_fill_input_buffer;
    skip_input_data = jpegr_skip_input_data;
    resync_to_restart = jpeg_resync_to_restart;
    term_source = jpegr_term_source;
}

jpegr_source_mgr::~jpegr_source_mgr() {}

static void jpegrerror_exit(j_common_ptr cinfo) {
    jpegrerror_mgr* err = reinterpret_cast<jpegrerror_mgr*>(cinfo->err);
    longjmp(err->setjmp_buffer, 1);
}

JpegDecoder::JpegDecoder() {
}

JpegDecoder::~JpegDecoder() {
}

bool JpegDecoder::decompressImage(const void* image, int length) {
    if (image == nullptr || length <= 0) {
        ALOGE("Image size can not be handled: %d", length);
        return false;
    }

    mResultBuffer.clear();
    if (!decode(image, length)) {
        return false;
    }

    return true;
}

const void* JpegDecoder::getDecompressedImagePtr() {
    return mResultBuffer.data();
}

size_t JpegDecoder::getDecompressedImageSize() {
    return mResultBuffer.size();
}

bool JpegDecoder::decode(const void* image, int length) {
    jpeg_decompress_struct cinfo;
    jpegr_source_mgr mgr(static_cast<const uint8_t*>(image), length);
    jpegrerror_mgr myerr;
    cinfo.err = jpeg_std_error(&myerr.pub);
    myerr.pub.error_exit = jpegrerror_exit;

    if (setjmp(myerr.setjmp_buffer)) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    jpeg_create_decompress(&cinfo);

    cinfo.src = &mgr;
    jpeg_read_header(&cinfo, TRUE);

    if (cinfo.jpeg_color_space == JCS_YCbCr) {
        mResultBuffer.resize(cinfo.image_width * cinfo.image_height * 3 / 2, 0);
    } else if (cinfo.jpeg_color_space == JCS_GRAYSCALE) {
        mResultBuffer.resize(cinfo.image_width * cinfo.image_height, 0);
    }

    cinfo.raw_data_out = TRUE;
    cinfo.dct_method = JDCT_IFAST;
    cinfo.out_color_space = cinfo.jpeg_color_space;

    jpeg_start_decompress(&cinfo);

    if (!decompress(&cinfo, static_cast<const uint8_t*>(mResultBuffer.data()),
            cinfo.jpeg_color_space == JCS_GRAYSCALE)) {
        return false;
    }

    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);

    return true;
}

bool JpegDecoder::decompress(jpeg_decompress_struct* cinfo, const uint8_t* dest,
        bool isSingleChannel) {
    if (isSingleChannel) {
        return decompressSingleChannel(cinfo, dest);
    }
    return decompressYUV(cinfo, dest);
}

bool JpegDecoder::decompressYUV(jpeg_decompress_struct* cinfo, const uint8_t* dest) {

    JSAMPROW y[kCompressBatchSize];
    JSAMPROW cb[kCompressBatchSize / 2];
    JSAMPROW cr[kCompressBatchSize / 2];
    JSAMPARRAY planes[3] {y, cb, cr};

    size_t y_plane_size = cinfo->image_width * cinfo->image_height;
    size_t uv_plane_size = y_plane_size / 4;
    uint8_t* y_plane = const_cast<uint8_t*>(dest);
    uint8_t* u_plane = const_cast<uint8_t*>(dest + y_plane_size);
    uint8_t* v_plane = const_cast<uint8_t*>(dest + y_plane_size + uv_plane_size);
    std::unique_ptr<uint8_t[]> empty(new uint8_t[cinfo->image_width]);
    memset(empty.get(), 0, cinfo->image_width);

    while (cinfo->output_scanline < cinfo->image_height) {
        for (int i = 0; i < kCompressBatchSize; ++i) {
            size_t scanline = cinfo->output_scanline + i;
            if (scanline < cinfo->image_height) {
                y[i] = y_plane + scanline * cinfo->image_width;
            } else {
                y[i] = empty.get();
            }
        }
        // cb, cr only have half scanlines
        for (int i = 0; i < kCompressBatchSize / 2; ++i) {
            size_t scanline = cinfo->output_scanline / 2 + i;
            if (scanline < cinfo->image_height / 2) {
                int offset = scanline * (cinfo->image_width / 2);
                cb[i] = u_plane + offset;
                cr[i] = v_plane + offset;
            } else {
                cb[i] = cr[i] = empty.get();
            }
        }

        int processed = jpeg_read_raw_data(cinfo, planes, kCompressBatchSize);
        if (processed != kCompressBatchSize) {
            ALOGE("Number of processed lines does not equal input lines.");
            return false;
        }
    }
    return true;
}

bool JpegDecoder::decompressSingleChannel(jpeg_decompress_struct* cinfo, const uint8_t* dest) {
    JSAMPROW y[kCompressBatchSize];
    JSAMPARRAY planes[1] {y};

    uint8_t* y_plane = const_cast<uint8_t*>(dest);
    std::unique_ptr<uint8_t[]> empty(new uint8_t[cinfo->image_width]);
    memset(empty.get(), 0, cinfo->image_width);

    while (cinfo->output_scanline < cinfo->image_height) {
        for (int i = 0; i < kCompressBatchSize; ++i) {
            size_t scanline = cinfo->output_scanline + i;
            if (scanline < cinfo->image_height) {
                y[i] = y_plane + scanline * cinfo->image_width;
            } else {
                y[i] = empty.get();
            }
        }

        int processed = jpeg_read_raw_data(cinfo, planes, kCompressBatchSize);
        if (processed != kCompressBatchSize / 2) {
            ALOGE("Number of processed lines does not equal input lines.");
            return false;
        }
    }
    return true;
}

} // namespace android