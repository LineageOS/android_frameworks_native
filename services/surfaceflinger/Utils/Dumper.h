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

#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace android::utils {

// Dumps variables by appending their name and value to the output string. A variable is formatted
// as "name=value". If the name or value is empty, the format is "value" or "name=", respectively.
// A value of user-defined type T is stringified via `std::string to_string(const T&)`, which must
// be defined in the same namespace as T per the rules of ADL (argument-dependent lookup).
//
// TODO(b/249828573): Consolidate with <compositionengine/impl/DumpHelpers.h>
class Dumper {
public:
    explicit Dumper(std::string& out) : mOut(out) {}

    void eol() { mOut += '\n'; }

    void dump(std::string_view name, std::string_view value = {}) {
        using namespace std::string_view_literals;

        for (int i = mIndent; i-- > 0;) mOut += "    "sv;
        mOut += name;
        if (!name.empty()) mOut += '=';
        mOut += value;
        eol();
    }

    void dump(std::string_view name, bool value) {
        using namespace std::string_view_literals;
        dump(name, value ? "true"sv : "false"sv);
    }

    template <typename T>
    void dump(std::string_view name, const std::optional<T>& value) {
        using namespace std::string_view_literals;
        using std::to_string;
        dump(name, value ? to_string(*value) : "nullopt"sv);
    }

    struct Indent {
        explicit Indent(Dumper& dumper) : dumper(dumper) { dumper.mIndent++; }
        ~Indent() { dumper.mIndent--; }

        Dumper& dumper;
    };

private:
    std::string& mOut;
    int mIndent = 0;
};

} // namespace android::utils
