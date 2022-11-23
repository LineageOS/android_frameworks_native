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
        rangeScalingFactorState = NotStrarted;
    }

    enum ParseState {
        NotStrarted,
        Started,
        Done
    };

    virtual DataMatchResult StartElement(const XmlTokenContext& context) {
        string val;
        if (context.BuildTokenValue(&val)) {
            if (!val.compare(rangeScalingFactorName)) {
                rangeScalingFactorState = Started;
            } else {
                if (rangeScalingFactorState != Done) {
                    rangeScalingFactorState = NotStrarted;
                }
            }
        }
        return context.GetResult();
    }

    virtual DataMatchResult FinishElement(const XmlTokenContext& context) {
        if (rangeScalingFactorState == Started) {
            rangeScalingFactorState = Done;
        }
        return context.GetResult();
    }

    virtual DataMatchResult ElementContent(const XmlTokenContext& context) {
        string val;
        if (rangeScalingFactorState == Started) {
            if (context.BuildTokenValue(&val)) {
                rangeScalingFactorStr.assign(val);
            }
        }
        return context.GetResult();
    }

    bool getRangeScalingFactor(float* scaling_factor) {
        if (rangeScalingFactorState == Done) {
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
        *transfer_function = JPEGR_TF_HLG;
        return true;
    }

private:
    static const string rangeScalingFactorName;
    string              rangeScalingFactorStr;
    ParseState          rangeScalingFactorState;
};

const string XMPXmlHandler::rangeScalingFactorName = "GContainer:rangeScalingFactor";

const string kContainerPrefix   = "GContainer";
const string kContainerUri      = "http://ns.google.com/photos/1.0/container/";
const string kRecoveryMapUri    = "http://ns.google.com/photos/1.0/recoverymap/";
const string kItemPrefix        = "Item";
const string kRecoveryMap       = "RecoveryMap";
const string kDirectory         = "Directory";
const string kImageJpeg         = "image/jpeg";
const string kItem              = "Item";
const string kLength            = "Length";
const string kMime              = "Mime";
const string kPrimary           = "Primary";
const string kSemantic          = "Semantic";
const string kVersion           = "Version";
const string kHdr10Metadata     = "HDR10Metadata";
const string kSt2086Metadata    = "ST2086Metadata";
const string kSt2086Coordinate  = "ST2086Coordinate";
const string kSt2086CoordinateX = "ST2086CoordinateX";
const string kSt2086CoordinateY = "ST2086CoordinateY";
const string kSt2086Primary     = "ST2086Primary";
const int kSt2086PrimaryRed     = 0;
const int kSt2086PrimaryGreen   = 1;
const int kSt2086PrimaryBlue    = 2;
const int kSt2086PrimaryWhite   = 3;
const int kGContainerVersion    = 1;

const string kConDir            = Name(kContainerPrefix, kDirectory);
const string kContainerItem     = Name(kContainerPrefix, kItem);
const string kItemLength        = Name(kItemPrefix, kLength);
const string kItemMime          = Name(kItemPrefix, kMime);
const string kItemSemantic      = Name(kItemPrefix, kSemantic);

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
  const vector<string> kConDirSeq({kConDir, string("rdf:Seq")});
  const vector<string> kLiItem({string("rdf:li"), kContainerItem});

  std::stringstream ss;
  photos_editing_formats::image_io::XmlWriter writer(ss);
  writer.StartWritingElement("x:xmpmeta");
  writer.WriteXmlns("x", "adobe:ns:meta/");
  writer.WriteAttributeNameAndValue("x:xmptk", "Adobe XMP Core 5.1.2");
  writer.StartWritingElement("rdf:RDF");
  writer.WriteXmlns("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#");
  writer.StartWritingElement("rdf:Description");
  writer.WriteXmlns(kContainerPrefix, kContainerUri);
  writer.WriteXmlns(kRecoveryMap, kRecoveryMapUri);
  writer.WriteElementAndContent(Name(kContainerPrefix, kVersion), kGContainerVersion);
  writer.StartWritingElements(kConDirSeq);
  size_t item_depth = writer.StartWritingElements(kLiItem);
  writer.WriteAttributeNameAndValue(kItemSemantic, kPrimary);
  writer.WriteAttributeNameAndValue(kItemMime, kImageJpeg);
  writer.WriteAttributeNameAndValue(Name(kRecoveryMap, kVersion), metadata.version);
  writer.WriteAttributeNameAndValue(
      Name(kRecoveryMap, "RangeScalingFactor"), metadata.rangeScalingFactor);
  writer.WriteAttributeNameAndValue(
      Name(kRecoveryMap, "TransferFunction"), metadata.transferFunction);
  if (metadata.transferFunction == JPEGR_TF_PQ) {
    writer.StartWritingElement(Name(kRecoveryMap, kHdr10Metadata));
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, "HDR10MaxFALL"), metadata.hdr10Metadata.maxFALL);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, "HDR10MaxCLL"), metadata.hdr10Metadata.maxCLL);
    writer.StartWritingElement(Name(kRecoveryMap, kSt2086Metadata));
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, "ST2086MaxLuminance"),
        metadata.hdr10Metadata.st2086Metadata.maxLuminance);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, "ST2086MinLuminance"),
        metadata.hdr10Metadata.st2086Metadata.minLuminance);

    // red
    writer.StartWritingElement(Name(kRecoveryMap, kSt2086Coordinate));
    writer.WriteAttributeNameAndValue(Name(kRecoveryMap, kSt2086Primary), kSt2086PrimaryRed);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, kSt2086CoordinateX),
        metadata.hdr10Metadata.st2086Metadata.redPrimary.x);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, kSt2086CoordinateY),
        metadata.hdr10Metadata.st2086Metadata.redPrimary.y);
    writer.FinishWritingElement();

    // green
    writer.StartWritingElement(Name(kRecoveryMap, kSt2086Coordinate));
    writer.WriteAttributeNameAndValue(Name(kRecoveryMap, kSt2086Primary), kSt2086PrimaryGreen);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, kSt2086CoordinateX),
        metadata.hdr10Metadata.st2086Metadata.greenPrimary.x);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, kSt2086CoordinateY),
        metadata.hdr10Metadata.st2086Metadata.greenPrimary.y);
    writer.FinishWritingElement();

    // blue
    writer.StartWritingElement(Name(kRecoveryMap, kSt2086Coordinate));
    writer.WriteAttributeNameAndValue(Name(kRecoveryMap, kSt2086Primary), kSt2086PrimaryBlue);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, kSt2086CoordinateX),
        metadata.hdr10Metadata.st2086Metadata.bluePrimary.x);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, kSt2086CoordinateY),
        metadata.hdr10Metadata.st2086Metadata.bluePrimary.y);
    writer.FinishWritingElement();

    // white
    writer.StartWritingElement(Name(kRecoveryMap, kSt2086Coordinate));
    writer.WriteAttributeNameAndValue(Name(kRecoveryMap, kSt2086Primary), kSt2086PrimaryWhite);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, kSt2086CoordinateX),
        metadata.hdr10Metadata.st2086Metadata.whitePoint.x);
    writer.WriteAttributeNameAndValue(
        Name(kRecoveryMap, kSt2086CoordinateY),
        metadata.hdr10Metadata.st2086Metadata.whitePoint.y);
    writer.FinishWritingElement();
  }
  writer.FinishWritingElementsToDepth(item_depth);
  writer.StartWritingElements(kLiItem);
  writer.WriteAttributeNameAndValue(kItemSemantic, kRecoveryMap);
  writer.WriteAttributeNameAndValue(kItemMime, kImageJpeg);
  writer.WriteAttributeNameAndValue(kItemLength, secondary_image_length);
  writer.FinishWriting();

  return ss.str();
}

} // namespace android::recoverymap