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

#include <jpegrecoverymap/recoverymap.h>

#include <sstream>
#include <stdint.h>
#include <string>
#include <cstdio>

namespace android::recoverymap {

struct jpegr_metadata;

// If the EXIF package doesn't exist in the input JPEG, we'll create one with one entry
// where the length is represented by this value.
const size_t PSEUDO_EXIF_PACKAGE_LENGTH = 28;
// If the EXIF package exists in the input JPEG, we'll add an "JR" entry where the length is
// represented by this value.
const size_t EXIF_J_R_ENTRY_LENGTH = 12;

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
status_t Write(jr_exif_ptr destination, const void* source, size_t length, int &position);


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

/*
 * Add J R entry to existing exif, or create a new one with J R entry if it's null.
 * EXIF syntax / change:
 * ori:
 * FF E1 - APP1
 * 01 FC - size of APP1 (to be calculated)
 * -----------------------------------------------------
 * 45 78 69 66 00 00 - Exif\0\0 "Exif header"
 * 49 49 2A 00 - TIFF Header
 * 08 00 00 00 - offset to the IFD (image file directory)
 * 06 00 - 6 entries
 * 00 01 - Width Tag
 * 03 00 - 'Short' type
 * 01 00 00 00 - 1 component
 * 00 05 00 00 - image with 0x500
 *--------------------------------------------------------------------------
 * new:
 * FF E1 - APP1
 * 02 08 - new size, equals to old size + EXIF_J_R_ENTRY_LENGTH (12)
 *-----------------------------------------------------
 * 45 78 69 66 00 00 - Exif\0\0 "Exif header"
 * 49 49 2A 00 - TIFF Header
 * 08 00 00 00 - offset to the IFD (image file directory)
 * 07 00 - +1 entry
 * 4A 52   Custom ('J''R') Tag
 * 07 00 - Unknown type
 * 01 00 00 00 - 1 component
 * 00 00 00 00 - empty data
 * 00 01 - Width Tag
 * 03 00 - 'Short' type
 * 01 00 00 00 - 1 component
 * 00 05 00 00 - image with 0x500
 */
status_t updateExif(jr_exif_ptr exif, jr_exif_ptr dest);

/*
 * Modify offsets in EXIF in place.
 *
 * Each tag has the following structure:
 *
 * 00 01 - Tag
 * 03 00 - data format
 * 01 00 00 00 - number of components
 * 00 05 00 00 - value
 *
 * The value means offset if
 * (1) num_of_components * bytes_per_component > 4 bytes, or
 * (2) tag == 0x8769 (ExifOffset).
 * In both cases, the method will add EXIF_J_R_ENTRY_LENGTH (12) to the offsets.
 */
void updateExifOffsets(jr_exif_ptr exif, int pos, bool use_big_endian);
void updateExifOffsets(jr_exif_ptr exif, int pos, int num_entry, bool use_big_endian);

/*
 * Read data from the target position and target length in bytes;
 */
int readValue(uint8_t* data, int pos, int length, bool use_big_endian);

/*
 * Returns the length of data format in bytes
 *
 *  ----------------------------------------------------------------------------------------------
 *  |       value       |         1       |        2        |        3         |       4         |
 *  |       format      |  unsigned byte  |  ascii strings  |  unsigned short  |  unsigned long  |
 *  |  bytes/component  |         1       |        1        |        2         |       4         |
 *  ----------------------------------------------------------------------------------------------
 *  |       value       |         5       |        6        |        7         |       8         |
 *  |       format      |unsigned rational|   signed byte   |    undefined     |  signed short   |
 *  |  bytes/component  |         8       |        1        |        1         |       2         |
 *  ----------------------------------------------------------------------------------------------
 *  |       value       |         9       |        10       |        11        |       12        |
 *  |       format      |   signed long   | signed rational |   single float   |  double float   |
 *  |  bytes/component  |         4       |        8        |        4         |       8         |
 *  ----------------------------------------------------------------------------------------------
 */
int findFormatLengthInBytes(int data_format);
}

#endif //ANDROID_JPEGRECOVERYMAP_RECOVERYMAPUTILS_H
