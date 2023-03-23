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

#ifndef ANDROID_JPEGRECOVERYMAP_JPEGR_H
#define ANDROID_JPEGRECOVERYMAP_JPEGR_H

#include "jpegrerrorcode.h"

#ifndef FLT_MAX
#define FLT_MAX 0x1.fffffep127f
#endif

namespace android::jpegrecoverymap {

// Color gamuts for image data
typedef enum {
  JPEGR_COLORGAMUT_UNSPECIFIED,
  JPEGR_COLORGAMUT_BT709,
  JPEGR_COLORGAMUT_P3,
  JPEGR_COLORGAMUT_BT2100,
} jpegr_color_gamut;

// Transfer functions for image data
typedef enum {
  JPEGR_TF_UNSPECIFIED = -1,
  JPEGR_TF_LINEAR = 0,
  JPEGR_TF_HLG = 1,
  JPEGR_TF_PQ = 2,
  JPEGR_TF_SRGB = 3,
} jpegr_transfer_function;

// Target output formats for decoder
typedef enum {
  JPEGR_OUTPUT_SDR,          // SDR in RGBA_8888 color format
  JPEGR_OUTPUT_HDR_LINEAR,   // HDR in F16 color format (linear)
  JPEGR_OUTPUT_HDR_PQ,       // HDR in RGBA_1010102 color format (PQ transfer function)
  JPEGR_OUTPUT_HDR_HLG,      // HDR in RGBA_1010102 color format (HLG transfer function)
} jpegr_output_format;

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

/*
 * Holds information for recovery map related metadata.
 */
struct jpegr_metadata_struct {
  // JPEG/R version
  uint32_t version;
  // Max Content Boost for the map
  float maxContentBoost;
  // Min Content Boost for the map
  float minContentBoost;
};

typedef struct jpegr_uncompressed_struct* jr_uncompressed_ptr;
typedef struct jpegr_compressed_struct* jr_compressed_ptr;
typedef struct jpegr_exif_struct* jr_exif_ptr;
typedef struct jpegr_metadata_struct* jr_metadata_ptr;
typedef struct jpegr_info_struct* jr_info_ptr;

class JpegR {
public:
    /*
     * Experimental only
     *
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
     * @param compressed_jpegr_image compressed JPEGR image.
     * @param dest destination of the uncompressed JPEGR image.
     * @param max_display_boost (optional) the maximum available boost supported by a display,
     *                          the value must be greater than or equal to 1.0.
     * @param exif destination of the decoded EXIF metadata. The default value is NULL where the
                   decoder will do nothing about it. If configured not NULL the decoder will write
                   EXIF data into this structure. The format is defined in {@code jpegr_exif_struct}
     * @param output_format flag for setting output color format. Its value configures the output
                            color format. The default value is {@code JPEGR_OUTPUT_HDR_LINEAR}.
                            ----------------------------------------------------------------------
                            |      output_format       |    decoded color format to be written   |
                            ----------------------------------------------------------------------
                            |     JPEGR_OUTPUT_SDR     |                RGBA_8888                |
                            ----------------------------------------------------------------------
                            | JPEGR_OUTPUT_HDR_LINEAR  |        (default)RGBA_F16 linear         |
                            ----------------------------------------------------------------------
                            |   JPEGR_OUTPUT_HDR_PQ    |             RGBA_1010102 PQ             |
                            ----------------------------------------------------------------------
                            |   JPEGR_OUTPUT_HDR_HLG   |            RGBA_1010102 HLG             |
                            ----------------------------------------------------------------------
     * @param recovery_map destination of the decoded recovery map. The default value is NULL where
                           the decoder will do nothing about it. If configured not NULL the decoder
                           will write the decoded recovery_map data into this structure. The format
                           is defined in {@code jpegr_uncompressed_struct}.
     * @param metadata destination of the decoded metadata. The default value is NULL where the
                       decoder will do nothing about it. If configured not NULL the decoder will
                       write metadata into this structure. the format of metadata is defined in
                       {@code jpegr_metadata}.
     * @return NO_ERROR if decoding succeeds, error code if error occurs.
     */
    status_t decodeJPEGR(jr_compressed_ptr compressed_jpegr_image,
                         jr_uncompressed_ptr dest,
                         float max_display_boost = FLT_MAX,
                         jr_exif_ptr exif = nullptr,
                         jpegr_output_format output_format = JPEGR_OUTPUT_HDR_LINEAR,
                         jr_uncompressed_ptr recovery_map = nullptr,
                         jr_metadata_ptr metadata = nullptr);

    /*
    * Gets Info from JPEGR file without decoding it.
    *
    * The output is filled jpegr_info structure
    * @param compressed_jpegr_image compressed JPEGR image
    * @param jpegr_info pointer to output JPEGR info. Members of jpegr_info
    *         are owned by the caller
    * @return NO_ERROR if JPEGR parsing succeeds, error code otherwise
    */
    status_t getJPEGRInfo(jr_compressed_ptr compressed_jpegr_image,
                          jr_info_ptr jpegr_info);
protected:
    /*
     * This method is called in the encoding pipeline. It will take the uncompressed 8-bit and
     * 10-bit yuv images as input, and calculate the uncompressed recovery map. The input images
     * must be the same resolution.
     *
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param hdr_tf transfer function of the HDR image
     * @param dest recovery map; caller responsible for memory of data
     * @param metadata max_content_boost is filled in
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t generateRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                                 jr_uncompressed_ptr uncompressed_p010_image,
                                 jpegr_transfer_function hdr_tf,
                                 jr_metadata_ptr metadata,
                                 jr_uncompressed_ptr dest);

    /*
     * This method is called in the decoding pipeline. It will take the uncompressed (decoded)
     * 8-bit yuv image, the uncompressed (decoded) recovery map, and extracted JPEG/R metadata as
     * input, and calculate the 10-bit recovered image. The recovered output image is the same
     * color gamut as the SDR image, with HLG transfer function, and is in RGBA1010102 data format.
     *
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param uncompressed_recovery_map uncompressed recovery map
     * @param metadata JPEG/R metadata extracted from XMP.
     * @param output_format flag for setting output color format. if set to
     *                      {@code JPEGR_OUTPUT_SDR}, decoder will only decode the primary image
     *                      which is SDR. Default value is JPEGR_OUTPUT_HDR_LINEAR.
     * @param max_display_boost the maximum available boost supported by a display
     * @param dest reconstructed HDR image
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t applyRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                              jr_uncompressed_ptr uncompressed_recovery_map,
                              jr_metadata_ptr metadata,
                              jpegr_output_format output_format,
                              float max_display_boost,
                              jr_uncompressed_ptr dest);

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
     * This method is called in the encoding pipeline. It will take the standard 8-bit JPEG image,
     * the compressed recovery map and optionally the exif package as inputs, and generate the XMP
     * metadata, and finally append everything in the order of:
     *     SOI, APP2(EXIF) (if EXIF is from outside), APP2(XMP), primary image, recovery map
     * Note that EXIF package is only available for encoding API-0 and API-1. For encoding API-2 and
     * API-3 this parameter is null, but the primary image in JPEG/R may still have EXIF as long as
     * the input JPEG has EXIF.
     *
     * @param compressed_jpeg_image compressed 8-bit JPEG image
     * @param compress_recovery_map compressed recover map
     * @param (nullable) exif EXIF package
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

} // namespace android::jpegrecoverymap

#endif // ANDROID_JPEGRECOVERYMAP_JPEGR_H
