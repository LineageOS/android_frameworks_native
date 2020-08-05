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

#include <cstdint>
#include <functional>
#include <string>

namespace android {

// ID of a physical or a virtual display. This class acts as a type safe wrapper around uint64_t.
struct DisplayId {
    // TODO(b/162612135) Remove default constructor
    DisplayId() = default;
    constexpr DisplayId(const DisplayId&) = default;
    DisplayId& operator=(const DisplayId&) = default;

    uint64_t value;

protected:
    explicit constexpr DisplayId(uint64_t id) : value(id) {}
};

static_assert(sizeof(DisplayId) == sizeof(uint64_t));

inline bool operator==(DisplayId lhs, DisplayId rhs) {
    return lhs.value == rhs.value;
}

inline bool operator!=(DisplayId lhs, DisplayId rhs) {
    return !(lhs == rhs);
}

inline std::string to_string(DisplayId displayId) {
    return std::to_string(displayId.value);
}

// DisplayId of a physical display, such as the internal display or externally connected display.
struct PhysicalDisplayId : DisplayId {
    // Flag indicating that the ID is stable across reboots.
    static constexpr uint64_t FLAG_STABLE = 1ULL << 62;

    // Returns a stable ID based on EDID information.
    static constexpr PhysicalDisplayId fromEdid(uint8_t port, uint16_t manufacturerId,
                                                uint32_t modelHash) {
        return PhysicalDisplayId(FLAG_STABLE, port, manufacturerId, modelHash);
    }

    // Returns an unstable ID. If EDID is available using "fromEdid" is preferred.
    static constexpr PhysicalDisplayId fromPort(uint8_t port) {
        constexpr uint16_t kManufacturerId = 0;
        constexpr uint32_t kModelHash = 0;
        return PhysicalDisplayId(0, port, kManufacturerId, kModelHash);
    }

    // TODO(b/162612135) Remove default constructor
    PhysicalDisplayId() = default;
    explicit constexpr PhysicalDisplayId(uint64_t id) : DisplayId(id) {}
    explicit constexpr PhysicalDisplayId(DisplayId other) : DisplayId(other.value) {}

    constexpr uint16_t getManufacturerId() const { return static_cast<uint16_t>(value >> 40); }

    constexpr uint8_t getPort() const { return static_cast<uint8_t>(value); }

private:
    constexpr PhysicalDisplayId(uint64_t flags, uint8_t port, uint16_t manufacturerId,
                                uint32_t modelHash)
          : DisplayId(flags | (static_cast<uint64_t>(manufacturerId) << 40) |
                      (static_cast<uint64_t>(modelHash) << 8) | port) {}
};

static_assert(sizeof(PhysicalDisplayId) == sizeof(uint64_t));

} // namespace android

namespace std {

template <>
struct hash<android::DisplayId> {
    size_t operator()(android::DisplayId displayId) const {
        return hash<uint64_t>()(displayId.value);
    }
};

template <>
struct hash<android::PhysicalDisplayId> : hash<android::DisplayId> {};

} // namespace std
