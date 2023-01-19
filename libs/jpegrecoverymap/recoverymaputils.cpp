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
#include <image_io/xml/xml_reader.h>
#include <image_io/xml/xml_writer.h>
#include <image_io/base/message_handler.h>
#include <image_io/xml/xml_element_rules.h>
#include <image_io/xml/xml_handler.h>
#include <image_io/xml/xml_rule.h>

using namespace photos_editing_formats::image_io;
using namespace std;

namespace android::recoverymap {

/*
 * Helper function used for generating XMP metadata.
 *
 * @param prefix The prefix part of the name.
 * @param suffix The suffix part of the name.
 * @return A name of the form "prefix:suffix".
 */
string Name(const string &prefix, const string &suffix) {
  std::stringstream ss;
  ss << prefix << ":" << suffix;
  return ss.str();
}

// Extremely simple XML Handler - just searches for interesting elements
class XMPXmlHandler : public XmlHandler {
public:

    XMPXmlHandler() : XmlHandler() {
        gContainerItemState = NotStrarted;
    }

    enum ParseState {
        NotStrarted,
        Started,
        Done
    };

    virtual DataMatchResult StartElement(const XmlTokenContext& context) {
        string val;
        if (context.BuildTokenValue(&val)) {
            if (!val.compare(gContainerItemName)) {
                gContainerItemState = Started;
            } else {
                if (gContainerItemState != Done) {
                    gContainerItemState = NotStrarted;
                }
            }
        }
        return context.GetResult();
    }

    virtual DataMatchResult FinishElement(const XmlTokenContext& context) {
        if (gContainerItemState == Started) {
            gContainerItemState = Done;
            lastAttributeName = "";
        }
        return context.GetResult();
    }

    virtual DataMatchResult AttributeName(const XmlTokenContext& context) {
        string val;
        if (gContainerItemState == Started) {
            if (context.BuildTokenValue(&val)) {
                if (!val.compare(rangeScalingFactorAttrName)) {
                    lastAttributeName = rangeScalingFactorAttrName;
                } else if (!val.compare(transferFunctionAttrName)) {
                    lastAttributeName = transferFunctionAttrName;
                } else {
                    lastAttributeName = "";
                }
            }
        }
        return context.GetResult();
    }

    virtual DataMatchResult AttributeValue(const XmlTokenContext& context) {
        string val;
        if (gContainerItemState == Started) {
            if (context.BuildTokenValue(&val, true)) {
                if (!lastAttributeName.compare(rangeScalingFactorAttrName)) {
                    rangeScalingFactorStr = val;
                } else if (!lastAttributeName.compare(transferFunctionAttrName)) {
                    transferFunctionStr = val;
                }
            }
        }
        return context.GetResult();
    }

    bool getRangeScalingFactor(float* scaling_factor) {
        if (gContainerItemState == Done) {
            stringstream ss(rangeScalingFactorStr);
            float val;
            if (ss >> val) {
                *scaling_factor = val;
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    bool getTransferFunction(jpegr_transfer_function* transfer_function) {
        if (gContainerItemState == Done) {
            stringstream ss(transferFunctionStr);
            int val;
            if (ss >> val) {
                *transfer_function = static_cast<jpegr_transfer_function>(val);
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
        return true;
    }

private:
    static const string gContainerItemName;
    static const string rangeScalingFactorAttrName;
    static const string transferFunctionAttrName;
    string              rangeScalingFactorStr;
    string              transferFunctionStr;
    string              lastAttributeName;
    ParseState          gContainerItemState;
};

// GContainer XMP constants - URI and namespace prefix
const string kContainerUri        = "http://ns.google.com/photos/1.0/container/";
const string kContainerPrefix     = "GContainer";

// GContainer XMP constants - element and attribute names
const string kConDirectory            = Name(kContainerPrefix, "Directory");
const string kConItem                 = Name(kContainerPrefix, "Item");
const string kConItemLength           = Name(kContainerPrefix, "ItemLength");
const string kConItemMime             = Name(kContainerPrefix, "ItemMime");
const string kConItemSemantic         = Name(kContainerPrefix, "ItemSemantic");
const string kConVersion              = Name(kContainerPrefix, "Version");

// GContainer XMP constants - element and attribute values
const string kSemanticPrimary     = "Primary";
const string kSemanticRecoveryMap = "RecoveryMap";
const string kMimeImageJpeg       = "image/jpeg";

const int kGContainerVersion      = 1;

// GContainer XMP constants - names for XMP handlers
const string XMPXmlHandler::gContainerItemName = kConItem;

// RecoveryMap XMP constants - URI and namespace prefix
const string kRecoveryMapUri      = "http://ns.google.com/photos/1.0/recoverymap/";
const string kRecoveryMapPrefix   = "RecoveryMap";

// RecoveryMap XMP constants - element and attribute names
const string kMapRangeScalingFactor = Name(kRecoveryMapPrefix, "RangeScalingFactor");
const string kMapTransferFunction   = Name(kRecoveryMapPrefix, "TransferFunction");
const string kMapVersion            = Name(kRecoveryMapPrefix, "Version");

const string kMapHdr10Metadata      = Name(kRecoveryMapPrefix, "HDR10Metadata");
const string kMapHdr10MaxFall       = Name(kRecoveryMapPrefix, "HDR10MaxFALL");
const string kMapHdr10MaxCll        = Name(kRecoveryMapPrefix, "HDR10MaxCLL");

const string kMapSt2086Metadata     = Name(kRecoveryMapPrefix, "ST2086Metadata");
const string kMapSt2086MaxLum       = Name(kRecoveryMapPrefix, "ST2086MaxLuminance");
const string kMapSt2086MinLum       = Name(kRecoveryMapPrefix, "ST2086MinLuminance");
const string kMapSt2086Primary      = Name(kRecoveryMapPrefix, "ST2086Primary");
const string kMapSt2086Coordinate   = Name(kRecoveryMapPrefix, "ST2086Coordinate");
const string kMapSt2086CoordinateX  = Name(kRecoveryMapPrefix, "ST2086CoordinateX");
const string kMapSt2086CoordinateY  = Name(kRecoveryMapPrefix, "ST2086CoordinateY");

// RecoveryMap XMP constants - element and attribute values
const int kSt2086PrimaryRed       = 0;
const int kSt2086PrimaryGreen     = 1;
const int kSt2086PrimaryBlue      = 2;
const int kSt2086PrimaryWhite     = 3;

// RecoveryMap XMP constants - names for XMP handlers
const string XMPXmlHandler::rangeScalingFactorAttrName = kMapRangeScalingFactor;
const string XMPXmlHandler::transferFunctionAttrName = kMapTransferFunction;

bool getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size, jpegr_metadata* metadata) {
    string nameSpace = "http://ns.adobe.com/xap/1.0/\0";

    if (xmp_size < nameSpace.size()+2) {
        // Data too short
        return false;
    }

    if (strncmp(reinterpret_cast<char*>(xmp_data), nameSpace.c_str(), nameSpace.size())) {
        // Not correct namespace
        return false;
    }

    // Position the pointers to the start of XMP XML portion
    xmp_data += nameSpace.size()+1;
    xmp_size -= nameSpace.size()+1;
    XMPXmlHandler handler;

    // We need to remove tail data until the closing tag. Otherwise parser will throw an error.
    while(xmp_data[xmp_size-1]!='>' && xmp_size > 1) {
        xmp_size--;
    }

    string str(reinterpret_cast<const char*>(xmp_data), xmp_size);
    MessageHandler msg_handler;
    unique_ptr<XmlRule> rule(new XmlElementRule);
    XmlReader reader(&handler, &msg_handler);
    reader.StartParse(std::move(rule));
    reader.Parse(str);
    reader.FinishParse();
    if (reader.HasErrors()) {
        // Parse error
        return false;
    }

    if (!handler.getRangeScalingFactor(&metadata->rangeScalingFactor)) {
        return false;
    }

    if (!handler.getTransferFunction(&metadata->transferFunction)) {
        return false;
    }
    return true;
}

string generateXmp(int secondary_image_length, jpegr_metadata& metadata) {
  const vector<string> kConDirSeq({kConDirectory, string("rdf:Seq")});
  const vector<string> kLiItem({string("rdf:li"), kConItem});

  std::stringstream ss;
  photos_editing_formats::image_io::XmlWriter writer(ss);
  writer.StartWritingElement("x:xmpmeta");
  writer.WriteXmlns("x", "adobe:ns:meta/");
  writer.WriteAttributeNameAndValue("x:xmptk", "Adobe XMP Core 5.1.2");
  writer.StartWritingElement("rdf:RDF");
  writer.WriteXmlns("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#");
  writer.StartWritingElement("rdf:Description");
  writer.WriteXmlns(kContainerPrefix, kContainerUri);
  writer.WriteXmlns(kRecoveryMapPrefix, kRecoveryMapUri);
  writer.WriteElementAndContent(kConVersion, kGContainerVersion);
  writer.StartWritingElements(kConDirSeq);
  size_t item_depth = writer.StartWritingElements(kLiItem);
  writer.WriteAttributeNameAndValue(kConItemSemantic, kSemanticPrimary);
  writer.WriteAttributeNameAndValue(kConItemMime, kMimeImageJpeg);
  writer.WriteAttributeNameAndValue(kMapVersion, metadata.version);
  writer.WriteAttributeNameAndValue(kMapRangeScalingFactor, metadata.rangeScalingFactor);
  writer.WriteAttributeNameAndValue(kMapTransferFunction, metadata.transferFunction);
  if (metadata.transferFunction == JPEGR_TF_PQ) {
    writer.StartWritingElement(kMapHdr10Metadata);
    writer.WriteAttributeNameAndValue(kMapHdr10MaxFall, metadata.hdr10Metadata.maxFALL);
    writer.WriteAttributeNameAndValue(kMapHdr10MaxCll, metadata.hdr10Metadata.maxCLL);
    writer.StartWritingElement(kMapSt2086Metadata);
    writer.WriteAttributeNameAndValue(
        kMapSt2086MaxLum, metadata.hdr10Metadata.st2086Metadata.maxLuminance);
    writer.WriteAttributeNameAndValue(
        kMapSt2086MinLum, metadata.hdr10Metadata.st2086Metadata.minLuminance);

    // red
    writer.StartWritingElement(kMapSt2086Coordinate);
    writer.WriteAttributeNameAndValue(kMapSt2086Primary, kSt2086PrimaryRed);
    writer.WriteAttributeNameAndValue(
        kMapSt2086CoordinateX, metadata.hdr10Metadata.st2086Metadata.redPrimary.x);
    writer.WriteAttributeNameAndValue(
        kMapSt2086CoordinateY, metadata.hdr10Metadata.st2086Metadata.redPrimary.y);
    writer.FinishWritingElement();

    // green
    writer.StartWritingElement(kMapSt2086Coordinate);
    writer.WriteAttributeNameAndValue(kMapSt2086Primary, kSt2086PrimaryGreen);
    writer.WriteAttributeNameAndValue(
        kMapSt2086CoordinateX, metadata.hdr10Metadata.st2086Metadata.greenPrimary.x);
    writer.WriteAttributeNameAndValue(
        kMapSt2086CoordinateY, metadata.hdr10Metadata.st2086Metadata.greenPrimary.y);
    writer.FinishWritingElement();

    // blue
    writer.StartWritingElement(kMapSt2086Coordinate);
    writer.WriteAttributeNameAndValue(kMapSt2086Primary, kSt2086PrimaryBlue);
    writer.WriteAttributeNameAndValue(
        kMapSt2086CoordinateX, metadata.hdr10Metadata.st2086Metadata.bluePrimary.x);
    writer.WriteAttributeNameAndValue(
        kMapSt2086CoordinateY, metadata.hdr10Metadata.st2086Metadata.bluePrimary.y);
    writer.FinishWritingElement();

    // white
    writer.StartWritingElement(kMapSt2086Coordinate);
    writer.WriteAttributeNameAndValue(kMapSt2086Primary, kSt2086PrimaryWhite);
    writer.WriteAttributeNameAndValue(
        kMapSt2086CoordinateX, metadata.hdr10Metadata.st2086Metadata.whitePoint.x);
    writer.WriteAttributeNameAndValue(
        kMapSt2086CoordinateY, metadata.hdr10Metadata.st2086Metadata.whitePoint.y);
    writer.FinishWritingElement();
  }
  writer.FinishWritingElementsToDepth(item_depth);
  writer.StartWritingElements(kLiItem);
  writer.WriteAttributeNameAndValue(kConItemSemantic, kSemanticRecoveryMap);
  writer.WriteAttributeNameAndValue(kConItemMime, kMimeImageJpeg);
  writer.WriteAttributeNameAndValue(kConItemLength, secondary_image_length);
  writer.FinishWriting();

  return ss.str();
}

} // namespace android::recoverymap
