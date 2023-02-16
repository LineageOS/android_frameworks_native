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

#ifndef ANDROID_JPEGRECOVERYMAP_JPEGRUTILS_H
#define ANDROID_JPEGRECOVERYMAP_JPEGRUTILS_H

#include <jpegrecoverymap/jpegr.h>

#include <sstream>
#include <stdint.h>
#include <string>
#include <cstdio>

namespace android::jpegrecoverymap {

struct jpegr_metadata;

/*
 * Helper function used for writing data to destination.
 *
 * @param destination destination of the data to be written.
 * @param source source of data being written.
 * @param length length of the data to be written.
 * @param position cursor in desitination where the data is to be written.
 * @return status of succeed or error code.
 */
status_t Write(jr_compressed_ptr destination, const void* source, size_t length, int &position);


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
 * max_content_boost = 8.0
 * min_content_boost = 0.5
 *
 * <x:xmpmeta
 *   xmlns:x="adobe:ns:meta/"
 *   x:xmptk="Adobe XMP Core 5.1.2">
 *   <rdf:RDF
 *     xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
 *     <rdf:Description
 *       xmlns:Container="http://ns.google.com/photos/1.0/container/"
 *       xmlns:Item="http://ns.google.com/photos/1.0/container/item/"
 *       xmlns:RecoveryMap="http://ns.google.com/photos/1.0/recoverymap/">
 *       <Container:Directory>
 *         <rdf:Seq>
 *           <rdf:li>
 *             <Container:Item
 *               Item:Semantic="Primary"
 *               Item:Mime="image/jpeg"/>
 *           </rdf:li>
 *           <rdf:li>
 *             <Container:Item
 *               Item:Semantic="RecoveryMap"
 *               Item:Mime="image/jpeg"
 *               Item:Length="1000"
 *               RecoveryMap:Version="1"
 *               RecoveryMap:MaxContentBoost="8.0"
 *               RecoveryMap:MinContentBoost="0.5"/>
 *           </rdf:li>
 *         </rdf:Seq>
 *       </Container:Directory>
 *     </rdf:Description>
 *   </rdf:RDF>
 * </x:xmpmeta>
 *
 * @param secondary_image_length length of secondary image
 * @param metadata JPEG/R metadata to encode as XMP
 * @return XMP metadata in type of string
 */
std::string generateXmp(int secondary_image_length, jpegr_metadata& metadata);
}  // namespace android::jpegrecoverymap

#endif //ANDROID_JPEGRECOVERYMAP_JPEGRUTILS_H
