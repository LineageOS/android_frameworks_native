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

#pragma once

#include <optional>
#include <type_traits>

#include <utils/Flattenable.h>

namespace android {

struct FlattenableHelpers {
    // Flattenable helpers for reading and writing std::string
    static size_t getFlattenedSize(const std::string& str) { return str.length() + 1; }

    static void write(void*& buffer, size_t& size, const std::string& str) {
        strcpy(reinterpret_cast<char*>(buffer), str.c_str());
        FlattenableUtils::advance(buffer, size, getFlattenedSize(str));
    }

    static void read(void const*& buffer, size_t& size, std::string* str) {
        str->assign(reinterpret_cast<const char*>(buffer));
        FlattenableUtils::advance(buffer, size, getFlattenedSize(*str));
    }

    // Flattenable utils for reading and writing std::optional
    template <class T, typename = std::enable_if_t<std::is_base_of_v<LightFlattenable<T>, T>>>
    static size_t getFlattenedSize(const std::optional<T>& value) {
        return sizeof(bool) + (value ? value->getFlattenedSize() : 0);
    }

    template <class T, typename = std::enable_if_t<std::is_base_of_v<LightFlattenable<T>, T>>>
    static void write(void*& buffer, size_t& size, const std::optional<T>& value) {
        if (value) {
            FlattenableUtils::write(buffer, size, true);
            value->flatten(buffer, size);
            FlattenableUtils::advance(buffer, size, value->getFlattenedSize());
        } else {
            FlattenableUtils::write(buffer, size, false);
        }
    }

    template <class T, typename = std::enable_if_t<std::is_base_of_v<LightFlattenable<T>, T>>>
    static void read(void const*& buffer, size_t& size, std::optional<T>* value) {
        bool isPresent;
        FlattenableUtils::read(buffer, size, isPresent);
        if (isPresent) {
            *value = T();
            (*value)->unflatten(buffer, size);
            FlattenableUtils::advance(buffer, size, (*value)->getFlattenedSize());
        } else {
            value->reset();
        }
    }
};

} // namespace android
