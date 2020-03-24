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

#include <ui/DeviceProductInfo.h>

#include <ui/FlattenableHelpers.h>

namespace android {

size_t DeviceProductInfo::getFlattenedSize() const {
    return FlattenableHelpers::getFlattenedSize(name) + sizeof(manufacturerPnpId) +
            FlattenableHelpers::getFlattenedSize(productId) + sizeof(manufactureOrModelDate);
}

status_t DeviceProductInfo::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableHelpers::write(buffer, size, name);
    FlattenableUtils::write(buffer, size, manufacturerPnpId);
    FlattenableHelpers::write(buffer, size, productId);
    FlattenableUtils::write(buffer, size, manufactureOrModelDate);
    return NO_ERROR;
}

status_t DeviceProductInfo::unflatten(void const* buffer, size_t size) {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableHelpers::read(buffer, size, &name);
    FlattenableUtils::read(buffer, size, manufacturerPnpId);
    FlattenableHelpers::read(buffer, size, &productId);
    FlattenableUtils::read(buffer, size, manufactureOrModelDate);
    return NO_ERROR;
}

} // namespace android
