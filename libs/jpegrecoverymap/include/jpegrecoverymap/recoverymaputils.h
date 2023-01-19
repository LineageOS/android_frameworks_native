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

#include <sstream>
#include <stdint.h>
#include <string>
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

/*
 * This method generates XMP metadata.
 *
 * below is an example of the XMP metadata that this function generates where
 * secondary_image_length = 1000
 * range_scaling_factor = 1.25
 *
 * <x:xmpmeta
 *   xmlns:x="adobe:ns:meta/"
 *   x:xmptk="Adobe XMP Core 5.1.2">
 *   <rdf:RDF
 *     xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
 *     <rdf:Description
 *       xmlns:GContainer="http://ns.google.com/photos/1.0/container/"
 *       xmlns:RecoveryMap="http://ns.google.com/photos/1.0/recoverymap/">
 *       <GContainer:Version>1</GContainer:Version>
 *       <GContainer:Directory>
 *         <rdf:Seq>
 *           <rdf:li>
 *             <GContainer:Item
 *               GContainer:ItemSemantic="Primary"
 *               GContainer:ItemMime="image/jpeg"
 *               RecoveryMap:Version=”1”
 *               RecoveryMap:RangeScalingFactor=”1.25”
 *               RecoveryMap:TransferFunction=”2”/>
 *               <RecoveryMap:HDR10Metadata
 *                 // some attributes
 *                 // some elements
 *               </RecoveryMap:HDR10Metadata>
 *           </rdf:li>
 *           <rdf:li>
 *             <GContainer:Item
 *               GContainer:ItemSemantic="RecoveryMap"
 *               GContainer:ItemMime="image/jpeg"
 *               GContainer:ItemLength="1000"/>
 *           </rdf:li>
 *         </rdf:Seq>
 *       </GContainer:Directory>
 *     </rdf:Description>
 *   </rdf:RDF>
 * </x:xmpmeta>
 *
 * @param secondary_image_length length of secondary image
 * @param metadata JPEG/R metadata to encode as XMP
 * @return XMP metadata in type of string
 */
std::string generateXmp(int secondary_image_length, jpegr_metadata& metadata);
}

#endif //ANDROID_JPEGRECOVERYMAP_RECOVERYMAPUTILS_H
