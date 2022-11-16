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

#include <jpegrecoverymap/recoverymaputils.h>
#include <jpegrecoverymap/recoverymap.h>

namespace android::recoverymap {

bool getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size, jpegr_metadata* metadata) {
    // TODO: Parse XMP Data
    (void)xmp_data;
    (void)xmp_size;
    metadata->rangeScalingFactor = 0.0708864;
    metadata->transferFunction = JPEGR_TF_HLG;
    return true;
}

}