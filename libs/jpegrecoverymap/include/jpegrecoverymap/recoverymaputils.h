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

#ifndef ANDROID_JPEGRECOVERYMAP_RECOVERYMAPUTILS_H
#define ANDROID_JPEGRECOVERYMAP_RECOVERYMAPUTILS_H

#include <stdint.h>
#include <cstdio>


namespace android::recoverymap {

struct jpegr_metadata;

/*
 * Parses XMP packet and fills metadata with data from XMP
 *
 * @param xmp_data pointer to XMP packet
 * @param xmp_size size of XMP packet
 * @param metadata place to store HDR metadata values
 * @return true if metadata is successfully retrieved, false otherwise
*/
bool getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size, jpegr_metadata* metadata);

}

#endif //ANDROID_JPEGRECOVERYMAP_RECOVERYMAPUTILS_H