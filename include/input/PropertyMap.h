/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <android-base/result.h>
#include <utils/Tokenizer.h>

#include <string>
#include <unordered_map>
#include <unordered_set>

namespace android {

/*
 * Provides a mechanism for passing around string-based property key / value pairs
 * and loading them from property files.
 *
 * The property files have the following simple structure:
 *
 * # Comment
 * key = value
 *
 * Keys and values are any sequence of printable ASCII characters.
 * The '=' separates the key from the value.
 * The key and value may not contain whitespace.
 *
 * The '\' character is reserved for escape sequences and is not currently supported.
 * The '"" character is reserved for quoting and is not currently supported.
 * Files that contain the '\' or '"' character will fail to parse.
 *
 * The file must not contain duplicate keys.
 *
 * TODO Support escape sequences and quoted values when needed.
 */
class PropertyMap {
public:
    /* Creates an empty property map. */
    PropertyMap();
    ~PropertyMap();

    /* Clears the property map. */
    void clear();

    /* Adds a property.
     * Replaces the property with the same key if it is already present.
     */
    void addProperty(const std::string& key, const std::string& value);

    /* Returns a set of all property keys starting with the given prefix. */
    std::unordered_set<std::string> getKeysWithPrefix(const std::string& prefix) const;

    /* Gets the value of a property and parses it.
     * Returns true and sets outValue if the key was found and its value was parsed successfully.
     * Otherwise returns false and does not modify outValue.  (Also logs a warning.)
     */
    bool tryGetProperty(const std::string& key, std::string& outValue) const;
    bool tryGetProperty(const std::string& key, bool& outValue) const;
    bool tryGetProperty(const std::string& key, int32_t& outValue) const;
    bool tryGetProperty(const std::string& key, float& outValue) const;
    bool tryGetProperty(const std::string& key, double& outValue) const;

    /* Adds all values from the specified property map. */
    void addAll(const PropertyMap* map);

    /* Loads a property map from a file. */
    static android::base::Result<std::unique_ptr<PropertyMap>> load(const char* filename);

private:
    /* Returns true if the property map contains the specified key. */
    bool hasProperty(const std::string& key) const;

    class Parser {
        PropertyMap* mMap;
        Tokenizer* mTokenizer;

    public:
        Parser(PropertyMap* map, Tokenizer* tokenizer);
        ~Parser();
        status_t parse();

    private:
        status_t parseType();
        status_t parseKey();
        status_t parseKeyProperty();
        status_t parseModifier(const std::string& token, int32_t* outMetaState);
        status_t parseCharacterLiteral(char16_t* outCharacter);
    };

    std::unordered_map<std::string, std::string> mProperties;
};

} // namespace android
