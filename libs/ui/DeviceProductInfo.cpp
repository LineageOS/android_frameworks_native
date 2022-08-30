/*
 * Copyright 2020 The Android Open Source Project
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

#include <ftl/match.h>
#include <ui/DeviceProductInfo.h>

#include <android-base/stringprintf.h>

namespace android {

std::string to_string(const DeviceProductInfo& info) {
    using base::StringAppendF;

    std::string result;
    StringAppendF(&result, "{name=\"%s\", ", info.name.c_str());
    StringAppendF(&result, "manufacturerPnpId=%s, ", info.manufacturerPnpId.data());
    StringAppendF(&result, "productId=%s, ", info.productId.c_str());

    ftl::match(
            info.manufactureOrModelDate,
            [&](DeviceProductInfo::ModelYear model) {
                StringAppendF(&result, "modelYear=%u, ", model.year);
            },
            [&](DeviceProductInfo::ManufactureWeekAndYear manufacture) {
                StringAppendF(&result, "manufactureWeek=%u, ", manufacture.week);
                StringAppendF(&result, "manufactureYear=%d, ", manufacture.year);
            },
            [&](DeviceProductInfo::ManufactureYear manufacture) {
                StringAppendF(&result, "manufactureYear=%d, ", manufacture.year);
            });

    result.append("relativeAddress=[");
    for (size_t i = 0; i < info.relativeAddress.size(); i++) {
        if (i != 0) {
            result.append(", ");
        }
        StringAppendF(&result, "%u", info.relativeAddress[i]);
    }
    result.append("]}");
    return result;
}

} // namespace android
