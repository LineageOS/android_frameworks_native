/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android-base/stringprintf.h>

#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>

#include "utils/BitSet.h"

#ifndef __UI_INPUT_FLAGS_H
#define __UI_INPUT_FLAGS_H

namespace android {

// A trait for determining whether a type is specifically an enum class or not.
template <typename T, bool = std::is_enum_v<T>>
struct is_enum_class : std::false_type {};

// By definition, an enum class is an enum that is not implicitly convertible to its underlying
// type.
template <typename T>
struct is_enum_class<T, true>
      : std::bool_constant<!std::is_convertible_v<T, std::underlying_type_t<T>>> {};

template <typename T>
inline constexpr bool is_enum_class_v = is_enum_class<T>::value;

/* A class for handling flags defined by an enum or enum class in a type-safe way. */
template <class F, typename = std::enable_if_t<std::is_enum_v<F>>>
class Flags {
    // F must be an enum or its underlying type is undefined. Theoretically we could specialize this
    // further to avoid this restriction but in general we want to encourage the use of enums
    // anyways.
    using U = typename std::underlying_type_t<F>;

public:
    constexpr Flags(F f) : flags(static_cast<U>(f)) {}
    constexpr Flags() : flags(0) {}
    constexpr Flags(const Flags<F>& f) : flags(f.flags) {}

    // Provide a non-explicit construct for non-enum classes since they easily convert to their
    // underlying types (e.g. when used with bitwise operators). For enum classes, however, we
    // should force them to be explicitly constructed from their underlying types to make full use
    // of the type checker.
    template <typename T = U>
    constexpr Flags(T t, typename std::enable_if_t<!is_enum_class_v<F>, T>* = nullptr) : flags(t) {}
    template <typename T = U>
    explicit constexpr Flags(T t, typename std::enable_if_t<is_enum_class_v<F>, T>* = nullptr)
          : flags(t) {}
    /*
     * Tests whether the given flag is set.
     */
    bool test(F flag) const {
        U f = static_cast<U>(flag);
        return (f & flags) == f;
    }

    /* Tests whether any of the given flags are set */
    bool any(Flags<F> f) { return (flags & f.flags) != 0; }

    /* Tests whether all of the given flags are set */
    bool all(Flags<F> f) { return (flags & f.flags) == f.flags; }

    Flags<F> operator|(Flags<F> rhs) const { return static_cast<F>(flags | rhs.flags); }
    Flags<F>& operator|=(Flags<F> rhs) {
        flags = flags | rhs.flags;
        return *this;
    }

    Flags<F> operator&(Flags<F> rhs) const { return static_cast<F>(flags & rhs.flags); }
    Flags<F>& operator&=(Flags<F> rhs) {
        flags = flags & rhs.flags;
        return *this;
    }

    Flags<F> operator^(Flags<F> rhs) const { return static_cast<F>(flags ^ rhs.flags); }
    Flags<F>& operator^=(Flags<F> rhs) {
        flags = flags ^ rhs.flags;
        return *this;
    }

    Flags<F> operator~() { return static_cast<F>(~flags); }

    bool operator==(Flags<F> rhs) const { return flags == rhs.flags; }
    bool operator!=(Flags<F> rhs) const { return !operator==(rhs); }

    Flags<F>& operator=(const Flags<F>& rhs) {
        flags = rhs.flags;
        return *this;
    }

    /*
     * Returns the stored set of flags.
     *
     * Note that this returns the underlying type rather than the base enum class. This is because
     * the value is no longer necessarily a strict member of the enum since the returned value could
     * be multiple enum variants OR'd together.
     */
    U get() const { return flags; }

    std::string string() const { return string(defaultStringify); }

    std::string string(std::function<std::optional<std::string>(F)> stringify) const {
        // The type can't be larger than 64-bits otherwise it won't fit in BitSet64.
        static_assert(sizeof(U) <= sizeof(uint64_t));
        std::string result;
        bool first = true;
        U unstringified = 0;
        for (BitSet64 bits(flags); !bits.isEmpty();) {
            uint64_t bit = bits.clearLastMarkedBit(); // counts from left
            const U flag = 1 << (64 - bit - 1);
            std::optional<std::string> flagString = stringify(static_cast<F>(flag));
            if (flagString) {
                appendFlag(result, flagString.value(), first);
            } else {
                unstringified |= flag;
            }
        }

        if (unstringified != 0) {
            appendFlag(result, base::StringPrintf("0x%08x", unstringified), first);
        }

        if (first) {
            result += "0x0";
        }

        return result;
    }

private:
    U flags;

    static std::optional<std::string> defaultStringify(F) { return std::nullopt; }
    static void appendFlag(std::string& str, const std::string& flag, bool& first) {
        if (first) {
            first = false;
        } else {
            str += " | ";
        }
        str += flag;
    }
};

// This namespace provides operator overloads for enum classes to make it easier to work with them
// as flags. In order to use these, add them via a `using namespace` declaration.
namespace flag_operators {

template <typename F, typename = std::enable_if_t<is_enum_class_v<F>>>
inline Flags<F> operator~(F f) {
    using U = typename std::underlying_type_t<F>;
    return static_cast<F>(~static_cast<U>(f));
}
template <typename F, typename = std::enable_if_t<is_enum_class_v<F>>>
Flags<F> operator|(F lhs, F rhs) {
    using U = typename std::underlying_type_t<F>;
    return static_cast<F>(static_cast<U>(lhs) | static_cast<U>(rhs));
}

} // namespace flag_operators
} // namespace android

#endif // __UI_INPUT_FLAGS_H