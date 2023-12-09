/*
 * Copyright 2023 The Android Open Source Project
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

#include <ftl/mixins.h>
#include <sys/types.h>
#include <string>

namespace android::gui {

// Type-safe wrapper for a PID.
struct Pid : ftl::Constructible<Pid, pid_t>, ftl::Equatable<Pid>, ftl::Orderable<Pid> {
    using Constructible::Constructible;

    const static Pid INVALID;

    constexpr auto val() const { return ftl::to_underlying(*this); }

    constexpr bool isValid() const { return val() >= 0; }

    std::string toString() const { return std::to_string(val()); }
};

const inline Pid Pid::INVALID{-1};

// Type-safe wrapper for a UID.
// We treat the unsigned equivalent of -1 as a singular invalid value.
struct Uid : ftl::Constructible<Uid, uid_t>, ftl::Equatable<Uid>, ftl::Orderable<Uid> {
    using Constructible::Constructible;

    const static Uid INVALID;

    constexpr auto val() const { return ftl::to_underlying(*this); }

    constexpr bool isValid() const { return val() != static_cast<uid_t>(-1); }

    std::string toString() const { return std::to_string(val()); }
};

const inline Uid Uid::INVALID{static_cast<uid_t>(-1)};

} // namespace android::gui
