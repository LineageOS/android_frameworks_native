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

namespace android::recoverymap {

/*
 * Holds information for uncompressed image or recovery map.
 */
struct jpeg_r_uncompressed_struct {
    // Pointer to the data location.
    void* data;
    // Width of the recovery map or image in pixels.
    int width;
    // Height of the recovery map or image in pixels.
    int height;
};

/*
 * Holds information for compressed image or recovery map.
 */
struct jpeg_r_compressed_struct {
    // Pointer to the data location.
    void* data;
    // Data length;
    int length;
};

typedef struct jpeg_r_uncompressed_struct* j_r_uncompressed_ptr;
typedef struct jpeg_r_compressed_struct* j_r_compressed_ptr;

class RecoveryMap {
public:
    /*
     * This method is called in the decoding pipeline. It will decode the recovery map.
     *
     * @param compressed_recovery_map compressed recovery map
     * @param dest decoded recover map
     * @return true if decoding succeeds
     */
    bool decodeRecoveryMap(j_r_compressed_ptr compressed_recovery_map,
                           j_r_uncompressed_ptr dest);

    /*
     * This method is called in the encoding pipeline. It will encode the recovery map.
     *
     * @param uncompressed_recovery_map uncompressed recovery map
     * @param dest encoded recover map
     * @return true if encoding succeeds
     */
    bool encodeRecoveryMap(j_r_uncompressed_ptr uncompressed_recovery_map,
                           j_r_compressed_ptr dest);

    /*
     * This method is called in the encoding pipeline. It will take the uncompressed 8-bit and
     * 10-bit yuv images as input, and calculate the uncompressed recovery map.
     *
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param uncompressed_p010_image uncompressed HDR image in P010 color format
     * @param dest recover map
     * @return true if calculation succeeds
     */
    bool generateRecoveryMap(j_r_uncompressed_ptr uncompressed_yuv_420_image,
                             j_r_uncompressed_ptr uncompressed_p010_image,
                             j_r_uncompressed_ptr dest);

    /*
     * This method is called in the decoding pipeline. It will take the uncompressed (decoded)
     * 8-bit yuv image and the uncompressed (decoded) recovery map as input, and calculate the
     * 10-bit recovered image (in p010 color format).
     *
     * @param uncompressed_yuv_420_image uncompressed SDR image in YUV_420 color format
     * @param uncompressed_recovery_map uncompressed recovery map
     * @param dest reconstructed HDR image
     * @return true if calculation succeeds
     */
    bool applyRecoveryMap(j_r_uncompressed_ptr uncompressed_yuv_420_image,
                          j_r_uncompressed_ptr uncompressed_recovery_map,
                          j_r_uncompressed_ptr dest);

    /*
     * This method is called in the decoding pipeline. It will read XMP metadata to find the start
     * position of the compressed recovery map, and will extract the compressed recovery map.
     *
     * @param compressed_jpeg_r_image compressed JPEG_R image
     * @return compressed recovery map
     */
    j_r_compressed_ptr extractRecoveryMap(void* compressed_jpeg_r_image);

    /*
     * This method is called in the encoding pipeline. It will take the standard 8-bit JPEG image
     * and the compressed recovery map as input, and update the XMP metadata with the end of JPEG
     * marker, and append the compressed gian map after the JPEG.
     *
     * @param compressed_jpeg_image compressed 8-bit JPEG image
     * @param compress_recovery_map compressed recover map
     * @return compressed JPEG_R image
     */
    void* appendRecoveryMap(void* compressed_jpeg_image,
                            j_r_compressed_ptr compressed_recovery_map);
};

} // namespace android::recoverymap
