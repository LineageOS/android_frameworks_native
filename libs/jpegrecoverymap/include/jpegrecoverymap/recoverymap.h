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

class RecoveryMap {
public:
    /*
     * This method is called in the decoding pipeline. It will decode the recovery map.
     *
     * input: compressed recovery map
     * output: uncompressed recovery map
     */
    void* decodeRecoveryMap(void* compressed_recovery_map);

    /*
     * This method is called in the encoding pipeline. It will encode the recovery map.
     *
     * input: uncompressed recovery map
     * output: compressed recovery map
     */
    void* encodeRecoveryMap(void* uncompressed_recovery_map);

    /*
     * This method is called in the encoding pipeline. It will take the uncompressed 8-bit and
     * 10-bit yuv images as input, and calculate the uncompressed recovery map.
     *
     * input: uncompressed yuv_420 image, uncompressed p010 image
     * output: uncompressed recovery map
     */
    void* generateRecoveryMap(void* uncompressed_yuv_420_image, void* uncompressed_p010_image);

    /*
     * This method is called in the decoding pipeline. It will take the uncompressed (decoded)
     * 8-bit yuv image and the uncompressed(decoded) recovery map as input, and calculate the
     * 10-bit recovered image (in p010 color format).
     *
     * input: uncompressed yuv_420 image, uncompressed recovery map
     * output: uncompress p010 image
     */
    void* applyRecoveryMap(void* uncompressed_yuv_420_image, void* uncompressed_recovery_map);

    /*
     * This method is called in the decoding pipeline. It will read XMP metadata to find the start
     * position of the compressed recovery map, and will extract the compressed recovery map.
     *
     * input: compressed JPEG-G image (8-bit JPEG + compressed recovery map)
     * output: compressed recovery map
     */
    void* extractRecoveryMap(void* compressed_jpeg_g_image);

    /*
     * This method is called in the encoding pipeline. It will take the standard 8-bit JPEG image
     * and the compressed recovery map as input, and update the XMP metadata with the end of JPEG
     * marker, and append the compressed gian map after the JPEG.
     *
     * input: compressed 8-bit JPEG image (standard JPEG), compressed recovery map
     * output: compressed JPEG-G image (8-bit JPEG + compressed recovery map)
     */
    void* appendRecoveryMap(void* compressed_jpeg_image, void* compressed_recovery_map);
};

} // namespace android::recoverymap