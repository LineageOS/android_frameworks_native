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

#include <ui/DisplayInfo.h>

#include <cstdint>

#include <ui/FlattenableHelpers.h>

namespace android {

size_t DisplayInfo::getFlattenedSize() const {
    return sizeof(connectionType) + sizeof(density) + sizeof(secure) +
            FlattenableHelpers::getFlattenedSize(deviceProductInfo);
}

status_t DisplayInfo::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableUtils::write(buffer, size, connectionType);
    FlattenableUtils::write(buffer, size, density);
    FlattenableUtils::write(buffer, size, secure);
    FlattenableHelpers::write(buffer, size, deviceProductInfo);

    return NO_ERROR;
}

status_t DisplayInfo::unflatten(void const* buffer, size_t size) {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }
    FlattenableUtils::read(buffer, size, connectionType);
    FlattenableUtils::read(buffer, size, density);
    FlattenableUtils::read(buffer, size, secure);
    FlattenableHelpers::read(buffer, size, &deviceProductInfo);

    return NO_ERROR;
}

} // namespace android
