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

/*
 * Helper function used for writing data to destination.
 */
status_t Write(jr_compressed_ptr destination, const void* source, size_t length, int &position) {
  if (position + length > destination->maxLength) {
    return ERROR_JPEGR_BUFFER_TOO_SMALL;
  }

  memcpy((uint8_t*)destination->data + sizeof(uint8_t) * position, source, length);
  position += length;
  return NO_ERROR;
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
                if (!val.compare(maxContentBoostAttrName)) {
                    lastAttributeName = maxContentBoostAttrName;
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
                if (!lastAttributeName.compare(maxContentBoostAttrName)) {
                    maxContentBoostStr = val;
                }
            }
        }
        return context.GetResult();
    }

    bool getMaxContentBoost(float* max_content_boost) {
        if (gContainerItemState == Done) {
            stringstream ss(maxContentBoostStr);
            float val;
            if (ss >> val) {
                *max_content_boost = val;
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

private:
    static const string gContainerItemName;
    static const string maxContentBoostAttrName;
    string              maxContentBoostStr;
    string              lastAttributeName;
    ParseState          gContainerItemState;
};

// GContainer XMP constants - URI and namespace prefix
const string kContainerUri        = "http://ns.google.com/photos/1.0/container/";
const string kContainerPrefix     = "Container";

// GContainer XMP constants - element and attribute names
const string kConDirectory            = Name(kContainerPrefix, "Directory");
const string kConItem                 = Name(kContainerPrefix, "Item");

// GContainer XMP constants - names for XMP handlers
const string XMPXmlHandler::gContainerItemName = kConItem;

// Item XMP constants - URI and namespace prefix
const string kItemUri        = "http://ns.google.com/photos/1.0/container/item/";
const string kItemPrefix     = "Item";

// Item XMP constants - element and attribute names
const string kItemLength           = Name(kItemPrefix, "Length");
const string kItemMime             = Name(kItemPrefix, "Mime");
const string kItemSemantic         = Name(kItemPrefix, "Semantic");

// Item XMP constants - element and attribute values
const string kSemanticPrimary     = "Primary";
const string kSemanticRecoveryMap = "RecoveryMap";
const string kMimeImageJpeg       = "image/jpeg";

// RecoveryMap XMP constants - URI and namespace prefix
const string kRecoveryMapUri      = "http://ns.google.com/photos/1.0/recoverymap/";
const string kRecoveryMapPrefix   = "RecoveryMap";

// RecoveryMap XMP constants - element and attribute names
const string kMapMaxContentBoost  = Name(kRecoveryMapPrefix, "MaxContentBoost");
const string kMapVersion          = Name(kRecoveryMapPrefix, "Version");

// RecoveryMap XMP constants - names for XMP handlers
const string XMPXmlHandler::maxContentBoostAttrName = kMapMaxContentBoost;

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

    if (!handler.getMaxContentBoost(&metadata->maxContentBoost)) {
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
  writer.WriteXmlns(kItemPrefix, kItemUri);
  writer.WriteXmlns(kRecoveryMapPrefix, kRecoveryMapUri);
  writer.StartWritingElements(kConDirSeq);
  size_t item_depth = writer.StartWritingElements(kLiItem);
  writer.WriteAttributeNameAndValue(kItemSemantic, kSemanticPrimary);
  writer.WriteAttributeNameAndValue(kItemMime, kMimeImageJpeg);
  writer.WriteAttributeNameAndValue(kMapVersion, metadata.version);
  writer.WriteAttributeNameAndValue(kMapMaxContentBoost, metadata.maxContentBoost);
  writer.FinishWritingElementsToDepth(item_depth);
  writer.StartWritingElements(kLiItem);
  writer.WriteAttributeNameAndValue(kItemSemantic, kSemanticRecoveryMap);
  writer.WriteAttributeNameAndValue(kItemMime, kMimeImageJpeg);
  writer.WriteAttributeNameAndValue(kItemLength, secondary_image_length);
  writer.FinishWriting();

  return ss.str();
}

} // namespace android::recoverymap
