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

#include <string>
#include <string_view>

#include <ftl/optional.h>

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

    std::string& out() { return mOut; }

    void dump(std::string_view name, std::string_view value = {}) {
        using namespace std::string_view_literals;

        for (int i = mIndent; i-- > 0;) mOut += "    "sv;
        mOut += name;
        if (!name.empty()) mOut += '=';
        mOut += value;
        eol();
    }

    void dump(std::string_view name, const std::string& value) {
        dump(name, static_cast<const std::string_view&>(value));
    }

    void dump(std::string_view name, bool value) {
        using namespace std::string_view_literals;
        dump(name, value ? "true"sv : "false"sv);
    }

    template <typename T>
    void dump(std::string_view name, const std::optional<T>& opt) {
        if (opt) {
            dump(name, *opt);
        } else {
            using namespace std::string_view_literals;
            dump(name, "nullopt"sv);
        }
    }

    template <typename T>
    void dump(std::string_view name, const ftl::Optional<T>& opt) {
        dump(name, static_cast<const std::optional<T>&>(opt));
    }

    template <typename T, typename... Ts>
    void dump(std::string_view name, const T& value, const Ts&... rest) {
        std::string string;

        constexpr bool kIsTuple = sizeof...(Ts) > 0;
        if constexpr (kIsTuple) {
            string += '{';
        }

        using std::to_string;
        string += to_string(value);

        if constexpr (kIsTuple) {
            string += ((", " + to_string(rest)) + ...);
            string += '}';
        }

        dump(name, string);
    }

    struct Indent {
        explicit Indent(Dumper& dumper) : dumper(dumper) { dumper.mIndent++; }
        ~Indent() { dumper.mIndent--; }

        Dumper& dumper;
    };

    struct Section {
        Section(Dumper& dumper, std::string_view heading) : dumper(dumper) {
            dumper.dump({}, heading);
            indent.emplace(dumper);
        }

        ~Section() {
            indent.reset();
            dumper.eol();
        }

        Dumper& dumper;
        std::optional<Indent> indent;
    };

private:
    std::string& mOut;
    int mIndent = 0;
};

} // namespace android::utils
