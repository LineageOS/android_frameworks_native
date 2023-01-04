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

#ifndef ANDROID_JPEGRECOVERYMAP_RECOVERYMAP_H
#define ANDROID_JPEGRECOVERYMAP_RECOVERYMAP_H

#include "jpegrerrorcode.h"

namespace android::recoverymap {

typedef enum {
  JPEGR_COLORGAMUT_UNSPECIFIED,
  JPEGR_COLORGAMUT_BT709,
  JPEGR_COLORGAMUT_P3,
  JPEGR_COLORGAMUT_BT2100,
} jpegr_color_gamut;

// Transfer functions as defined for XMP metadata
typedef enum {
  JPEGR_TF_LINEAR = 0,
  JPEGR_TF_HLG = 1,
  JPEGR_TF_PQ = 2,
} jpegr_transfer_function;

struct jpegr_info_struct {
    size_t width;
    size_t height;
    std::vector<uint8_t>* iccData;
    std::vector<uint8_t>* exifData;
};

/*
 * Holds information for uncompressed image or recovery map.
 */
struct jpegr_uncompressed_struct {
    // Pointer to the data location.
    void* data;
    // Width of the recovery map or image in pixels.
    int width;
    // Height of the recovery map or image in pixels.
    int height;
    // Color gamut.
    jpegr_color_gamut colorGamut;
};

/*
 * Holds information for compressed image or recovery map.
 */
struct jpegr_compressed_struct {
    // Pointer to the data location.
    void* data;
    // Used data length in bytes.
    int length;
    // Maximum available data length in bytes.
    int maxLength;
    // Color gamut.
    jpegr_color_gamut colorGamut;
};

/*
 * Holds information for EXIF metadata.
 */
struct jpegr_exif_struct {
    // Pointer to the data location.
    void* data;
    // Data length;
    int length;
};

struct chromaticity_coord {
  float x;
  float y;
};


struct st2086_metadata {
  // xy chromaticity coordinate of the red primary of the mastering display
  chromaticity_coord redPrimary;
  // xy chromaticity coordinate of the green primary of the mastering display
  chromaticity_coord greenPrimary;
  // xy chromaticity coordinate of the blue primary of the mastering display
  chromaticity_coord bluePrimary;
  // xy chromaticity coordinate of the white point of the mastering display
  chromaticity_coord whitePoint;
  // Maximum luminance in nits of the mastering display
  uint32_t maxLuminance;
  // Minimum luminance in nits of the mastering display
  float minLuminance;
};

struct hdr10_metadata {
  // Mastering display color volume
  st2086_metadata st2086Metadata;
  // Max frame average light level in nits
  float maxFALL;
  // Max content light level in nits
  float maxCLL;
};

struct jpegr_metadata {
  // JPEG/R version
  uint32_t version;
  // Range scaling factor for the map
  float rangeScalingFactor;
  // The transfer function for decoding the HDR representation of the image
  jpegr_transfer_function transferFunction;
  // HDR10 metadata, only applicable for transferFunction of JPEGR_TF_PQ
  hdr10_metadata hdr10Metadata;
};

typedef struct jpegr_uncompressed_struct* jr_uncompressed_ptr;
typedef struct jpegr_compressed_struct* jr_compressed_ptr;
typedef struct jpegr_exif_struct* jr_exif_ptr;
typedef struct jpegr_metadata* jr_metadata_ptr;
typedef struct jpegr_info_struct* jr_info_ptr;

class RecoveryMap {
public:
    /*
     * Encode API-0
     * Compress JPEGR image from 10-bit HDR YUV.
     *
     * Tonemap the HDR input to a SDR image, generate recovery map from the HDR and SDR images,
     * compress SDR YUV to 8-bit JPEG and append the recovery map to the end of the compressed
     * JPEG.
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param hdr_tf transfer function of the HDR image
     * @param dest destination of the compressed JPEGR image
     * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
     *                the highest quality
     * @param exif pointer to the exif metadata.
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                         jpegr_transfer_function hdr_tf,
                         jr_compressed_ptr dest,
                         int quality,
                         jr_exif_ptr exif);

    /*
     * Encode API-1
     * Compress JPEGR image from 10-bit HDR YUV and 8-bit SDR YUV.
     *
     * Generate recovery map from the HDR and SDR inputs, compress SDR YUV to 8-bit JPEG and append
     * the recovery map to the end of the compressed JPEG. HDR and SDR inputs must be the same
     * resolution.
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param hdr_tf transfer function of the HDR image
     * @param dest destination of the compressed JPEGR image
     * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
     *                the highest quality
     * @param exif pointer to the exif metadata.
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                         jr_uncompressed_ptr uncompressed_yuv_420_image,
                         jpegr_transfer_function hdr_tf,
                         jr_compressed_ptr dest,
                         int quality,
                         jr_exif_ptr exif);

    /*
     * Encode API-2
     * Compress JPEGR image from 10-bit HDR YUV, 8-bit SDR YUV and compressed 8-bit JPEG.
     *
     * This method requires HAL Hardware JPEG encoder.
     *
     * Generate recovery map from the HDR and SDR inputs, append the recovery map to the end of the
     * compressed JPEG. HDR and SDR inputs must be the same resolution and color space.
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     *                                   Note: the SDR image must be the decoded version of the JPEG
     *                                         input
     * @param compressed_jpeg_image compressed 8-bit JPEG image
     * @param hdr_tf transfer function of the HDR image
     * @param dest destination of the compressed JPEGR image
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                         jr_uncompressed_ptr uncompressed_yuv_420_image,
                         jr_compressed_ptr compressed_jpeg_image,
                         jpegr_transfer_function hdr_tf,
                         jr_compressed_ptr dest);

    /*
     * Encode API-3
     * Compress JPEGR image from 10-bit HDR YUV and 8-bit SDR YUV.
     *
     * This method requires HAL Hardware JPEG encoder.
     *
     * Decode the compressed 8-bit JPEG image to YUV SDR, generate recovery map from the HDR input
     * and the decoded SDR result, append the recovery map to the end of the compressed JPEG. HDR
     * and SDR inputs must be the same resolution.
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param compressed_jpeg_image compressed 8-bit JPEG image
     * @param hdr_tf transfer function of the HDR image
     * @param dest destination of the compressed JPEGR image
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                         jr_compressed_ptr compressed_jpeg_image,
                         jpegr_transfer_function hdr_tf,
                         jr_compressed_ptr dest);

    /*
     * Decode API
     * Decompress JPEGR image.
     *
     * The output JPEGR image is in RGBA_1010102 data format if decoding to HDR.
     * @param compressed_jpegr_image compressed JPEGR image
     * @param dest destination of the uncompressed JPEGR image
     * @param exif destination of the decoded EXIF metadata.
     * @param request_sdr flag that request SDR output. If set to true, decoder will only decode
     *                    the primary image which is SDR. Setting of request_sdr and input source
     *                    (HDR or SDR) can be found in the table below:
     *                    |  input source  |  request_sdr  |  output of decoding  |
     *                    |       HDR      |     true      |          SDR         |
     *                    |       HDR      |     false     |          HDR         |
     *                    |       SDR      |     true      |          SDR         |
     *                    |       SDR      |     false     |          SDR         |
     * @return NO_ERROR if decoding succeeds, error code if error occurs.
     */
    status_t decodeJPEGR(jr_compressed_ptr compressed_jpegr_image,
                         jr_uncompressed_ptr dest,
                         jr_exif_ptr exif = nullptr,
                         bool request_sdr = false);

    /*
    * Gets Info from JPEGR file without decoding it.
    *
    * The output is filled jpegr_info structure
    * @param compressed_jpegr_image compressed JPEGR image
    * @param jpegr_info pointer to output JPEGR info
    * @return NO_ERROR if JPEGR parsing succeeds, error code otherwise
    */
    status_t getJPEGRInfo(jr_compressed_ptr compressed_jpegr_image,
                          jr_info_ptr jpegr_info);
private:
    /*
     * This method is called in the encoding pipeline. It will encode the recovery map.
     *
     * @param uncompressed_recovery_map uncompressed recovery map
     * @param dest encoded recover map
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t compressRecoveryMap(jr_uncompressed_ptr uncompressed_recovery_map,
                               jr_compressed_ptr dest);

    /*
     * This method is called in the encoding pipeline. It will take the uncompressed 8-bit and
     * 10-bit yuv images as input, and calculate the uncompressed recovery map. The input images
     * must be the same resolution.
     *
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param dest recovery map; caller responsible for memory of data
     * @param metadata metadata provides the transfer function for the HDR
     *                 image; range_scaling_factor and hdr10 FALL and CLL will
     *                 be updated.
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t generateRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                                 jr_uncompressed_ptr uncompressed_p010_image,
                                 jr_metadata_ptr metadata,
                                 jr_uncompressed_ptr dest);

    /*
     * This method is called in the decoding pipeline. It will take the uncompressed (decoded)
     * 8-bit yuv image, the uncompressed (decoded) recovery map, and extracted JPEG/R metadata as
     * input, and calculate the 10-bit recovered image. The recovered output image is the same
     * color gamut as the SDR image, with the transfer function specified in the JPEG/R metadata,
     * and is in RGBA1010102 data format.
     *
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param uncompressed_recovery_map uncompressed recovery map
     * @param metadata JPEG/R metadata extracted from XMP.
     * @param dest reconstructed HDR image
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t applyRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                              jr_uncompressed_ptr uncompressed_recovery_map,
                              jr_metadata_ptr metadata,
                              jr_uncompressed_ptr dest);

    /*
     * This methoud is called to separate primary image and recovery map image from JPEGR
     *
     * @param compressed_jpegr_image compressed JPEGR image
     * @param primary_image destination of primary image
     * @param recovery_map destination of compressed recovery map
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
    */
    status_t extractPrimaryImageAndRecoveryMap(jr_compressed_ptr compressed_jpegr_image,
                                               jr_compressed_ptr primary_image,
                                               jr_compressed_ptr recovery_map);
    /*
     * This method is called in the decoding pipeline. It will read XMP metadata to find the start
     * position of the compressed recovery map, and will extract the compressed recovery map.
     *
     * @param compressed_jpegr_image compressed JPEGR image
     * @param dest destination of compressed recovery map
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t extractRecoveryMap(jr_compressed_ptr compressed_jpegr_image,
                                jr_compressed_ptr dest);

    /*
     * This method is called in the encoding pipeline. It will take the standard 8-bit JPEG image
     * and the compressed recovery map as input, and update the XMP metadata with the end of JPEG
     * marker, and append the compressed gian map after the JPEG.
     *
     * @param compressed_jpeg_image compressed 8-bit JPEG image
     * @param compress_recovery_map compressed recover map
     * @param exif EXIF package
     * @param metadata JPEG/R metadata to encode in XMP of the jpeg
     * @param dest compressed JPEGR image
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t appendRecoveryMap(jr_compressed_ptr compressed_jpeg_image,
                               jr_compressed_ptr compressed_recovery_map,
                               jr_exif_ptr exif,
                               jr_metadata_ptr metadata,
                               jr_compressed_ptr dest);

    /*
     * This method will tone map a HDR image to an SDR image.
     *
     * @param src (input) uncompressed P010 image
     * @param dest (output) tone mapping result as a YUV_420 image
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t toneMap(jr_uncompressed_ptr src,
                     jr_uncompressed_ptr dest);
};

} // namespace android::recoverymap

#endif // ANDROID_JPEGRECOVERYMAP_RECOVERYMAP_H
