/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "InputReader"

//#define LOG_NDEBUG 0
#include <log/log.h>
#include <log/log_event_list.h>

#include <unordered_map>

namespace android {

/**
 * Log debug messages for each raw event received from the EventHub.
 * Enable this via "adb shell setprop log.tag.InputReaderRawEvents DEBUG".
 * This requires a restart on non-debuggable (e.g. user) builds, but should take effect immediately
 * on debuggable builds (e.g. userdebug).
 */
bool debugRawEvents();

/**
 * Log debug messages about virtual key processing.
 * Enable this via "adb shell setprop log.tag.InputReaderVirtualKeys DEBUG" (requires restart)
 */
const bool DEBUG_VIRTUAL_KEYS =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "VirtualKeys", ANDROID_LOG_INFO);

/**
 * Log debug messages about pointers.
 * Enable this via "adb shell setprop log.tag.InputReaderPointers DEBUG" (requires restart)
 */
const bool DEBUG_POINTERS =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Pointers", ANDROID_LOG_INFO);

/**
 * Log debug messages about pointer assignment calculations.
 * Enable this via "adb shell setprop log.tag.InputReaderPointerAssignment DEBUG" (requires restart)
 */
const bool DEBUG_POINTER_ASSIGNMENT =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "PointerAssignment", ANDROID_LOG_INFO);

/**
 * Log debug messages about gesture detection.
 * Enable this via "adb shell setprop log.tag.InputReaderGestures DEBUG" (requires restart)
 */
const bool DEBUG_GESTURES =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Gestures", ANDROID_LOG_INFO);

/**
 * Log debug messages about the vibrator.
 * Enable this via "adb shell setprop log.tag.InputReaderVibrator DEBUG" (requires restart)
 */
const bool DEBUG_VIBRATOR =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Vibrator", ANDROID_LOG_INFO);

/**
 * Log debug messages about fusing stylus data.
 * Enable this via "adb shell setprop log.tag.InputReaderStylusFusion DEBUG" (requires restart)
 */
const bool DEBUG_STYLUS_FUSION =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "StylusFusion", ANDROID_LOG_INFO);

/**
 * Log detailed debug messages about input device lights.
 * Enable this via "adb shell setprop log.tag.InputReaderLightDetails DEBUG" (requires restart)
 */
const bool DEBUG_LIGHT_DETAILS =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "LightDetails", ANDROID_LOG_INFO);

} // namespace android

#define INDENT "  "
#define INDENT2 "    "
#define INDENT3 "      "
#define INDENT4 "        "
#define INDENT5 "          "

#include <input/Input.h>

namespace android {

// --- Static Functions ---

template <typename T>
inline static T abs(const T& value) {
    return value < 0 ? -value : value;
}

template <typename T>
inline static T min(const T& a, const T& b) {
    return a < b ? a : b;
}

inline static float avg(float x, float y) {
    return (x + y) / 2;
}

static inline const char* toString(bool value) {
    return value ? "true" : "false";
}

static inline bool sourcesMatchMask(uint32_t sources, uint32_t sourceMask) {
    return (sources & sourceMask & ~AINPUT_SOURCE_CLASS_MASK) != 0;
}

template <typename K, typename V>
static inline std::optional<V> getValueByKey(const std::unordered_map<K, V>& map, K key) {
    auto it = map.find(key);
    std::optional<V> value = std::nullopt;
    if (it != map.end()) {
        value = it->second;
    }
    return value;
}

} // namespace android
