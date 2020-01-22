/*
 * Copyright (C) 2019 The Android Open Source Project
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

/**
 * @addtogroup ImageDecoder
 * @{
 */

/**
 * @file imageDecoder.h
 */

#ifndef ANDROID_IMAGE_DECODER_H
#define ANDROID_IMAGE_DECODER_H

#include "bitmap.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct AAsset;
struct ARect;

#if __ANDROID_API__ >= 30

/** AImageDecoder functions result code. */
enum {
    // Decoding was successful and complete.
    ANDROID_IMAGE_DECODER_SUCCESS = 0,
    // The input was incomplete. In decodeImage, this means a partial
    // image was decoded. Undecoded lines are all zeroes.
    // In AImageDecoder_create*, no AImageDecoder was created.
    ANDROID_IMAGE_DECODER_INCOMPLETE = -1,
    // The input contained an error after decoding some lines. Similar to
    // INCOMPLETE, above.
    ANDROID_IMAGE_DECODER_ERROR = -2,
    // Could not convert, e.g. attempting to decode an image with
    // alpha to an opaque format.
    ANDROID_IMAGE_DECODER_INVALID_CONVERSION = -3,
    // The scale is invalid. It may have overflowed, or it may be incompatible
    // with the current alpha setting.
    ANDROID_IMAGE_DECODER_INVALID_SCALE = -4,
    // Some other parameter was bad (e.g. pixels)
    ANDROID_IMAGE_DECODER_BAD_PARAMETER = -5,
    // Input was invalid i.e. broken before decoding any pixels.
    ANDROID_IMAGE_DECODER_INVALID_INPUT = -6,
    // A seek was required, and failed.
    ANDROID_IMAGE_DECODER_SEEK_ERROR = -7,
    // Some other error (e.g. OOM)
    ANDROID_IMAGE_DECODER_INTERNAL_ERROR = -8,
    // We did not recognize the format
    ANDROID_IMAGE_DECODER_UNSUPPORTED_FORMAT = -9
};

struct AImageDecoder;

/**
 * Opaque handle for decoding images.
 *
 * Create using one of the following:
 * - {@link AImageDecoder_createFromAAsset}
 * - {@link AImageDecoder_createFromFd}
 * - {@link AImageDecoder_createFromBuffer}
 */
typedef struct AImageDecoder AImageDecoder;

/**
 * Create a new AImageDecoder from an AAsset.
 *
 * @param asset {@link AAsset} containing encoded image data. Client is still
 *              responsible for calling {@link AAsset_close} on it.
 * @param outDecoder On success (i.e. return value is
 *                   {@link ANDROID_IMAGE_DECODER_SUCCESS}), this will be set to
 *                   a newly created {@link AImageDecoder}. Caller is
 *                   responsible for calling {@link AImageDecoder_delete} on it.
 * @return {@link ANDROID_IMAGE_DECODER_SUCCESS} on success or a value
 *         indicating reason for the failure.
 */
int AImageDecoder_createFromAAsset(AAsset* asset, AImageDecoder** outDecoder) __INTRODUCED_IN(30);

/**
 * Create a new AImageDecoder from a file descriptor.
 *
 * @param fd Seekable, readable, open file descriptor for encoded data.
 *           Client is still responsible for closing it, which may be done
 *           *after* deleting the returned AImageDecoder.
 * @param outDecoder On success (i.e. return value is
 *                   {@link ANDROID_IMAGE_DECODER_SUCCESS}), this will be set to
 *                   a newly created {@link AImageDecoder}. Caller is
 *                   responsible for calling {@link AImageDecoder_delete} on it.
 * @return {@link ANDROID_IMAGE_DECODER_SUCCESS} on success or a value
 *         indicating reason for the failure.
 */
int AImageDecoder_createFromFd(int fd, AImageDecoder** outDecoder) __INTRODUCED_IN(30);

/**
 * Create a new AImageDecoder from a buffer.
 *
 * @param buffer Pointer to encoded data. Must be valid for the entire time
 *               the AImageDecoder is used.
 * @param length Byte length of buffer.
 * @param outDecoder On success (i.e. return value is
 *                   {@link ANDROID_IMAGE_DECODER_SUCCESS}), this will be set to
 *                   a newly created {@link AImageDecoder}. Caller is
 *                   responsible for calling {@link AImageDecoder_delete} on it.
 * @return {@link ANDROID_IMAGE_DECODER_SUCCESS} on success or a value
 *         indicating reason for the failure.
 */
int AImageDecoder_createFromBuffer(const void* buffer, size_t length,
                                   AImageDecoder** outDecoder) __INTRODUCED_IN(30);

/**
 * Delete the AImageDecoder.
 */
void AImageDecoder_delete(AImageDecoder* decoder) __INTRODUCED_IN(30);

/**
 * Choose the desired output format.
 *
 * @param format AndroidBitmapFormat to use
 * @return {@link ANDROID_IMAGE_DECODER_SUCCESS} if the format is compatible
 *         with the image and {@link ANDROID_IMAGE_DECODER_INVALID_CONVERSION}
 *         otherwise. In the latter case, the AImageDecoder uses the
 *         format it was already planning to use (either its default
 *         or a previously successful setting from this function).
 */
int AImageDecoder_setAndroidBitmapFormat(AImageDecoder*,
        int32_t format) __INTRODUCED_IN(30);

/**
 * Specify whether the output's pixels should be unpremultiplied.
 *
 * By default, the decoder will premultiply the pixels, if they have alpha. Pass
 * false to this method to leave them unpremultiplied. This has no effect on an
 * opaque image.
 *
 * @param required Pass true to leave the pixels unpremultiplied.
 * @return - {@link ANDROID_IMAGE_DECODER_SUCCESS} on success
 *         - {@link ANDROID_IMAGE_DECODER_INVALID_CONVERSION} if the conversion
 *           is not possible
 *         - {@link ANDROID_IMAGE_DECODER_BAD_PARAMETER} for bad parameters
 */
int AImageDecoder_setUnpremultipliedRequired(AImageDecoder*, bool required) __INTRODUCED_IN(30);

/**
 * Choose the dataspace for the output.
 *
 * Not supported for {@link ANDROID_BITMAP_FORMAT_A_8}, which does not support
 * an ADataSpace.
 *
 * @param dataspace The {@link ADataSpace} to decode into. An ADataSpace
 *                  specifies how to interpret the colors. By default,
 *                  AImageDecoder will decode into the ADataSpace specified by
 *                  {@link AImageDecoderHeaderInfo_getDataSpace}. If this
 *                  parameter is set to a different ADataSpace, AImageDecoder
 *                  will transform the output into the specified ADataSpace.
 * @return - {@link ANDROID_IMAGE_DECODER_SUCCESS} on success
 *         - {@link ANDROID_IMAGE_DECODER_BAD_PARAMETER} for a null
 *           AImageDecoder or an integer that does not correspond to an
 *           ADataSpace value.
 */
int AImageDecoder_setDataSpace(AImageDecoder*, int32_t dataspace) __INTRODUCED_IN(30);

/**
 * Specify the output size for a decoded image.
 *
 * Future calls to {@link AImageDecoder_decodeImage} will sample or scale the
 * encoded image to reach the desired size. If a crop rect is set (via
 * {@link AImageDecoder_setCrop}), it must be contained within the dimensions
 * specified by width and height, and the output image will be the size of the
 * crop rect.
 *
 * @param width Width of the output (prior to cropping).
 *              This will affect future calls to
 *              {@link AImageDecoder_getMinimumStride}, which will now return
 *              a value based on this width.
 * @param height Height of the output (prior to cropping).
 * @return - {@link ANDROID_IMAGE_DECODER_SUCCESS} on success
 *         - {@link ANDROID_IMAGE_DECODER_BAD_PARAMETER} if the AImageDecoder
 *           pointer is null, width or height is <= 0, or any existing crop is
 *           not contained by the image dimensions.
 */
int AImageDecoder_setTargetSize(AImageDecoder*, int width, int height) __INTRODUCED_IN(30);


/**
 * Compute the dimensions to use for a given sampleSize.
 *
 * Although AImageDecoder can scale to an arbitrary target size (see
 * {@link AImageDecoder_setTargetSize}), some sizes may be more efficient than
 * others. This computes the most efficient target size to use to reach a
 * particular sampleSize.
 *
 * @param sampleSize A subsampling rate of the original image. Must be greater
 *                   than or equal to 1. A sampleSize of 2 means to skip every
 *                   other pixel/line, resulting in a width and height that are
 *                   1/2 of the original dimensions, with 1/4 the number of
 *                   pixels.
 * @param width Out parameter for the width sampled by sampleSize, and rounded
 *              direction that the decoder can do most efficiently.
 * @param height Out parameter for the height sampled by sampleSize, and rounded
 *               direction that the decoder can do most efficiently.
 * @return ANDROID_IMAGE_DECODER result code.
 */
int AImageDecoder_computeSampledSize(const AImageDecoder*, int sampleSize,
                                     int* width, int* height) __INTRODUCED_IN(30);
/**
 * Specify how to crop the output after scaling (if any).
 *
 * Future calls to {@link AImageDecoder_decodeImage} will crop their output to
 * the specified {@link ARect}. Clients will only need to allocate enough memory
 * for the cropped ARect.
 *
 * @param crop Rectangle describing a crop of the decode. It must be contained inside of
 *             the (possibly scaled, by {@link AImageDecoder_setTargetSize})
 *             image dimensions. This will affect future calls to
 *             {@link AImageDecoder_getMinimumStride}, which will now return a
 *             value based on the width of the crop. An empty ARect -
 *             specifically { 0, 0, 0, 0 } - may be used to remove the cropping
 *             behavior. Any other empty or unsorted ARects will result in
 *             returning ANDROID_IMAGE_DECODER_BAD_PARAMETER.
 * @return - {@link ANDROID_IMAGE_DECODER_SUCCESS} on success
 *         - {@link ANDROID_IMAGE_DECODER_BAD_PARAMETER} if the AImageDecoder
 *           pointer is null or the crop is not contained by the image
 *           dimensions.
 */
int AImageDecoder_setCrop(AImageDecoder*, ARect crop) __INTRODUCED_IN(30);

/**
 * Opaque handle for reading header info.
 */
struct AImageDecoderHeaderInfo;
typedef struct AImageDecoderHeaderInfo AImageDecoderHeaderInfo;

/**
 * Return an opaque handle for reading header info.
 *
 * This is owned by the {@link AImageDecoder} and will be destroyed when the
 * AImageDecoder is destroyed via {@link AImageDecoder_delete}.
 */
const AImageDecoderHeaderInfo* AImageDecoder_getHeaderInfo(
        const AImageDecoder*) __INTRODUCED_IN(30);

/**
 * Report the native width of the encoded image.
 */
int32_t AImageDecoderHeaderInfo_getWidth(const AImageDecoderHeaderInfo*) __INTRODUCED_IN(30);

/**
 * Report the native height of the encoded image.
 */
int32_t AImageDecoderHeaderInfo_getHeight(const AImageDecoderHeaderInfo*) __INTRODUCED_IN(30);

/**
 * Report the mimeType of the encoded image.
 *
 * @return a string literal describing the mime type.
 */
const char* AImageDecoderHeaderInfo_getMimeType(
        const AImageDecoderHeaderInfo*) __INTRODUCED_IN(30);

/**
 * Report whether the encoded image represents an animation.
 */
bool AImageDecoderHeaderInfo_isAnimated(
        const AImageDecoderHeaderInfo*) __INTRODUCED_IN(30);

/**
 * Report the AndroidBitmapFormat the AImageDecoder will decode to
 * by default. AImageDecoder will try to choose one that is sensible
 * for the image and the system. Note that this does not indicate the
 * encoded format of the image.
 */
AndroidBitmapFormat AImageDecoderHeaderInfo_getAndroidBitmapFormat(
        const AImageDecoderHeaderInfo*) __INTRODUCED_IN(30);

/**
 * Report how the AImageDecoder will handle alpha by default. If the image
 * contains no alpha (according to its header), this will return
 * {@link ANDROID_BITMAP_FLAGS_ALPHA_OPAQUE}. If the image may contain alpha,
 * this returns {@link ANDROID_BITMAP_FLAGS_ALPHA_PREMUL}.
 *
 * For animated images only the opacity of the first frame is reported.
 */
int AImageDecoderHeaderInfo_getAlphaFlags(
        const AImageDecoderHeaderInfo*) __INTRODUCED_IN(30);

/**
 * Report the dataspace the AImageDecoder will decode to by default.
 * AImageDecoder will try to choose one that is sensible for the
 * image and the system. Note that this may not exactly match the ICC
 * profile (or other color information) stored in the encoded image.
 *
 * @return The {@link ADataSpace} most closely representing the way the colors
 *         are encoded (or {@link ADATASPACE_UNKNOWN} if there is not an
 *         approximate ADataSpace). This specifies how to interpret the colors
 *         in the decoded image, unless {@link AImageDecoder_setDataSpace} is
 *         called to decode to a different ADataSpace.
 *
 *         Note that ADataSpace only exposes a few values. This may return
 *         ADATASPACE_UNKNOWN, even for Named ColorSpaces, if they have no
 *         corresponding ADataSpace.
 */
int32_t AImageDecoderHeaderInfo_getDataSpace(
        const AImageDecoderHeaderInfo*) __INTRODUCED_IN(30);

/**
 * Return the minimum stride that can be used, taking the specified
 * (or default) (possibly scaled) width, crop rect and
 * {@link AndroidBitmapFormat} into account.
 */
size_t AImageDecoder_getMinimumStride(AImageDecoder*) __INTRODUCED_IN(30);

/**
 * Decode the image into pixels, using the settings of the AImageDecoder.
 *
 * @param decoder Opaque object representing the decoder.
 * @param pixels On success, will be filled with the result
 *               of the decode. Must be large enough to fit |size| bytes.
 * @param stride Width in bytes of a single row. Must be at least
 *               {@link AImageDecoder_getMinimumStride}.
 * @param size Size of the pixel buffer in bytes. Must be at least
 *             stride * (height - 1) +
 *             {@link AImageDecoder_getMinimumStride}.
 * @return {@link ANDROID_IMAGE_DECODER_SUCCESS} on success, or an error code
 *         from the same enum describing the failure.
 */
int AImageDecoder_decodeImage(AImageDecoder* decoder,
                              void* pixels, size_t stride,
                              size_t size) __INTRODUCED_IN(30);

#endif // __ANDROID_API__ >= 30

#ifdef __cplusplus
}
#endif

#endif // ANDROID_IMAGE_DECODER_H

/** @} */
