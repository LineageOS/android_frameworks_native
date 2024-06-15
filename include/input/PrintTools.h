/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <bitset>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace android {

template <size_t N>
std::string bitsetToString(const std::bitset<N>& bitset) {
    if (bitset.none()) {
        return "<none>";
    }
    return bitset.to_string();
}

template <class T>
std::string streamableToString(const T& streamable) {
    std::stringstream out;
    out << streamable;
    return out.str();
}

template <typename T>
inline std::string constToString(const T& v) {
    return std::to_string(v);
}

template <>
inline std::string constToString(const bool& value) {
    return value ? "true" : "false";
}

template <>
inline std::string constToString(const std::vector<bool>::reference& value) {
    return value ? "true" : "false";
}

inline std::string constToString(const std::string& s) {
    return s;
}

/**
 * Convert an optional type to string.
 */
template <typename T>
inline std::string toString(const std::optional<T>& optional,
                            std::string (*toString)(const T&) = constToString) {
    return optional ? toString(*optional) : "<not set>";
}

/**
 * Convert a set of integral types to string.
 */
template <typename T>
std::string dumpSet(const std::set<T>& v, std::string (*toString)(const T&) = constToString) {
    std::string out;
    for (const T& entry : v) {
        out += out.empty() ? "{" : ", ";
        out += toString(entry);
    }
    return out.empty() ? "{}" : (out + "}");
}

/**
 * Convert a map or multimap to string. Both keys and values of the map should be integral type.
 */
template <typename T>
std::string dumpMap(const T& map,
                    std::string (*keyToString)(const typename T::key_type&) = constToString,
                    std::string (*valueToString)(const typename T::mapped_type&) = constToString) {
    std::string out;
    for (const auto& [k, v] : map) {
        if (!out.empty()) {
            out += "\n";
        }
        out += keyToString(k) + ":" + valueToString(v);
    }
    return out;
}

/**
 * Convert map keys to string. The keys of the map should be integral type.
 */
template <typename K, typename V>
std::string dumpMapKeys(const std::map<K, V>& map,
                        std::string (*keyToString)(const K&) = constToString) {
    std::string out;
    for (const auto& [k, _] : map) {
        out += out.empty() ? "{" : ", ";
        out += keyToString(k);
    }
    return out.empty() ? "{}" : (out + "}");
}

/** Convert a vector to a string. */
template <typename T>
std::string dumpVector(const std::vector<T>& values,
                       std::string (*valueToString)(const T&) = constToString) {
    std::string out;
    for (const auto& value : values) {
        out += out.empty() ? "[" : ", ";
        out += valueToString(value);
    }
    return out.empty() ? "[]" : (out + "]");
}

const char* toString(bool value);

/**
 * Add "prefix" to the beginning of each line in the provided string
 * "str".
 * The string 'str' is typically multi-line.
 * The most common use case for this function is to add some padding
 * when dumping state.
 */
std::string addLinePrefix(std::string str, const std::string& prefix);

} // namespace android
