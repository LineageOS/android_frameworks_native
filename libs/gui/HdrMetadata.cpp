/*
 * Copyright 2018 The Android Open Source Project
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

#include <gui/HdrMetadata.h>

namespace android {

size_t HdrMetadata::getFlattenedSize() const {
    size_t size = sizeof(validTypes);
    if (validTypes & SMPTE2086) {
        size += sizeof(smpte2086);
    }
    if (validTypes & CTA861_3) {
        size += sizeof(cta8613);
    }
    return size;
}

status_t HdrMetadata::flatten(void* buffer, size_t size) const {
    if (size < getFlattenedSize()) {
        return NO_MEMORY;
    }

    FlattenableUtils::write(buffer, size, validTypes);
    if (validTypes & SMPTE2086) {
        FlattenableUtils::write(buffer, size, smpte2086);
    }
    if (validTypes & CTA861_3) {
        FlattenableUtils::write(buffer, size, cta8613);
    }

    return NO_ERROR;
}

status_t HdrMetadata::unflatten(void const* buffer, size_t size) {
    if (size < sizeof(validTypes)) {
        return NO_MEMORY;
    }
    FlattenableUtils::read(buffer, size, validTypes);
    if (validTypes & SMPTE2086) {
        if (size < sizeof(smpte2086)) {
            return NO_MEMORY;
        }
        FlattenableUtils::read(buffer, size, smpte2086);
    }
    if (validTypes & CTA861_3) {
        if (size < sizeof(cta8613)) {
            return NO_MEMORY;
        }
        FlattenableUtils::read(buffer, size, cta8613);
    }

    return NO_ERROR;
}

} // namespace android
