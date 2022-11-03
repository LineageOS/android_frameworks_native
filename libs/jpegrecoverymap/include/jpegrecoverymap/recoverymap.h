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

#include "jpegrerrorcode.h"

namespace android::recoverymap {

typedef enum {
  JPEGR_COLORSPACE_UNSPECIFIED,
  JPEGR_COLORSPACE_BT709,
  JPEGR_COLORSPACE_P3,
  JPEGR_COLORSPACE_BT2100,
} jpegr_color_space;

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
    // Color space.
    jpegr_color_space colorSpace;
};

/*
 * Holds information for compressed image or recovery map.
 */
struct jpegr_compressed_struct {
    // Pointer to the data location.
    void* data;
    // Data length.
    int length;
    // Color space.
    jpegr_color_space colorSpace;
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

typedef struct jpegr_uncompressed_struct* jr_uncompressed_ptr;
typedef struct jpegr_compressed_struct* jr_compressed_ptr;
typedef struct jpegr_exif_struct* jr_exif_ptr;

class RecoveryMap {
public:
    /*
     * Compress JPEGR image from 10-bit HDR YUV and 8-bit SDR YUV.
     *
     * Generate recovery map from the HDR and SDR inputs, compress SDR YUV to 8-bit JPEG and append
     * the recovery map to the end of the compressed JPEG.
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param dest destination of the compressed JPEGR image
     * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
     *                the highest quality
     * @param exif pointer to the exif metadata.
     * @param hdr_ratio HDR ratio. If not configured, this value will be calculated by the JPEG/R
     *                  encoder.
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                         jr_uncompressed_ptr uncompressed_yuv_420_image,
                         void* dest,
                         int quality,
                         jr_exif_ptr exif,
                         float hdr_ratio = 0.0f);

    /*
     * Compress JPEGR image from 10-bit HDR YUV, 8-bit SDR YUV and compressed 8-bit JPEG.
     *
     * This method requires HAL Hardware JPEG encoder.
     *
     * Generate recovery map from the HDR and SDR inputs, append the recovery map to the end of the
     * compressed JPEG.
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param compressed_jpeg_image compressed 8-bit JPEG image
     * @param dest destination of the compressed JPEGR image
     * @param hdr_ratio HDR ratio. If not configured, this value will be calculated by the JPEG/R
     *                  encoder.
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                         jr_uncompressed_ptr uncompressed_yuv_420_image,
                         void* compressed_jpeg_image,
                         void* dest,
                         float hdr_ratio = 0.0f);

    /*
     * Compress JPEGR image from 10-bit HDR YUV and 8-bit SDR YUV.
     *
     * This method requires HAL Hardware JPEG encoder.
     *
     * Decode the compressed 8-bit JPEG image to YUV SDR, generate recovery map from the HDR input
     * and the decoded SDR result, append the recovery map to the end of the compressed JPEG.
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param compressed_jpeg_image compressed 8-bit JPEG image
     * @param dest destination of the compressed JPEGR image
     * @param hdr_ratio HDR ratio. If not configured, this value will be calculated by the JPEG/R
     *                  encoder.
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t encodeJPEGR(jr_uncompressed_ptr uncompressed_p010_image,
                         void* compressed_jpeg_image,
                         void* dest,
                         float hdr_ratio = 0.0f);

    /*
     * Decompress JPEGR image.
     *
     * @param compressed_jpegr_image compressed JPEGR image
     * @param dest destination of the uncompressed JPEGR image
     * @param exif destination of the decoded EXIF metadata. Default value is nullptr where EXIF
     *             metadata will not be decoded.
     * @param request_sdr flag that request SDR output, default to false (request HDR output). If
     *                    set to true, decoder will only decode the primary image which is SDR.
     *                    Setting of request_sdr and input source (HDR or SDR) can be found in
     *                    the table below:
     *                    |  input source  |  request_sdr  |  output of decoding  |
     *                    |       HDR      |     true      |          SDR         |
     *                    |       HDR      |     false     |          HDR         |
     *                    |       SDR      |     true      |          SDR         |
     *                    |       SDR      |     false     |          SDR         |
     * @return NO_ERROR if decoding succeeds, error code if error occurs.
     */
    status_t decodeJPEGR(void* compressed_jpegr_image,
                         jr_uncompressed_ptr dest,
                         jr_exif_ptr exif = nullptr,
                         bool request_sdr = false);
private:
    /*
     * This method is called in the decoding pipeline. It will decode the recovery map.
     *
     * @param compressed_recovery_map compressed recovery map
     * @param dest decoded recover map
     * @return NO_ERROR if decoding succeeds, error code if error occurs.
     */
    status_t decodeRecoveryMap(jr_compressed_ptr compressed_recovery_map,
                               jr_uncompressed_ptr dest);

    /*
     * This method is called in the encoding pipeline. It will encode the recovery map.
     *
     * @param uncompressed_recovery_map uncompressed recovery map
     * @param dest encoded recover map
     * @return NO_ERROR if encoding succeeds, error code if error occurs.
     */
    status_t encodeRecoveryMap(jr_uncompressed_ptr uncompressed_recovery_map,
                               jr_compressed_ptr dest);

    /*
     * This method is called in the encoding pipeline. It will take the uncompressed 8-bit and
     * 10-bit yuv images as input, and calculate the uncompressed recovery map.
     *
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param dest recover map
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t generateRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                                 jr_uncompressed_ptr uncompressed_p010_image,
                                 jr_uncompressed_ptr dest);

    /*
     * This method is called in the decoding pipeline. It will take the uncompressed (decoded)
     * 8-bit yuv image and the uncompressed (decoded) recovery map as input, and calculate the
     * 10-bit recovered image (in p010 color format).
     *
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param uncompressed_recovery_map uncompressed recovery map
     * @param dest reconstructed HDR image
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t applyRecoveryMap(jr_uncompressed_ptr uncompressed_yuv_420_image,
                              jr_uncompressed_ptr uncompressed_recovery_map,
                              jr_uncompressed_ptr dest);

    /*
     * This method is called in the decoding pipeline. It will read XMP metadata to find the start
     * position of the compressed recovery map, and will extract the compressed recovery map.
     *
     * @param compressed_jpegr_image compressed JPEGR image
     * @param dest destination of compressed recovery map
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t extractRecoveryMap(void* compressed_jpegr_image, jr_compressed_ptr dest);

    /*
     * This method is called in the encoding pipeline. It will take the standard 8-bit JPEG image
     * and the compressed recovery map as input, and update the XMP metadata with the end of JPEG
     * marker, and append the compressed gian map after the JPEG.
     *
     * @param compressed_jpeg_image compressed 8-bit JPEG image
     * @param compress_recovery_map compressed recover map
     * @param dest compressed JPEGR image
     * @return NO_ERROR if calculation succeeds, error code if error occurs.
     */
    status_t appendRecoveryMap(void* compressed_jpeg_image,
                               jr_compressed_ptr compressed_recovery_map,
                               void* dest);
};

} // namespace android::recoverymap
