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
#include <image_io/base/message_handler.h>
#include <image_io/xml/xml_element_rules.h>
#include <image_io/xml/xml_handler.h>
#include <image_io/xml/xml_rule.h>

#include <string>
#include <sstream>

using namespace photos_editing_formats::image_io;
using namespace std;

namespace android::recoverymap {


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

} // namespace android::recoverymap