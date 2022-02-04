/*
 * Copyright (C) 2005 The Android Open Source Project
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

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/ioctl.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define LOG_TAG "EventHub"

// #define LOG_NDEBUG 0
#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/properties.h>
#include <ftl/enum.h>
#include <input/KeyCharacterMap.h>
#include <input/KeyLayoutMap.h>
#include <input/PrintTools.h>
#include <input/VirtualKeyMap.h>
#include <openssl/sha.h>
#include <statslog.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/Timers.h>

#include <filesystem>
#include <optional>
#include <regex>
#include <utility>

#include "EventHub.h"

#include "KeyCodeClassifications.h"

#define INDENT "  "
#define INDENT2 "    "
#define INDENT3 "      "

using android::base::StringPrintf;

namespace android {

using namespace ftl::flag_operators;

static const char* DEVICE_INPUT_PATH = "/dev/input";
// v4l2 devices go directly into /dev
static const char* DEVICE_PATH = "/dev";

static constexpr size_t OBFUSCATED_LENGTH = 8;

static constexpr int32_t FF_STRONG_MAGNITUDE_CHANNEL_IDX = 0;
static constexpr int32_t FF_WEAK_MAGNITUDE_CHANNEL_IDX = 1;

static constexpr size_t EVENT_BUFFER_SIZE = 256;

// Mapping for input battery class node IDs lookup.
// https://www.kernel.org/doc/Documentation/power/power_supply_class.txt
static const std::unordered_map<std::string, InputBatteryClass> BATTERY_CLASSES =
        {{"capacity", InputBatteryClass::CAPACITY},
         {"capacity_level", InputBatteryClass::CAPACITY_LEVEL},
         {"status", InputBatteryClass::STATUS}};

// Mapping for input battery class node names lookup.
// https://www.kernel.org/doc/Documentation/power/power_supply_class.txt
static const std::unordered_map<InputBatteryClass, std::string> BATTERY_NODES =
        {{InputBatteryClass::CAPACITY, "capacity"},
         {InputBatteryClass::CAPACITY_LEVEL, "capacity_level"},
         {InputBatteryClass::STATUS, "status"}};

// must be kept in sync with definitions in kernel /drivers/power/supply/power_supply_sysfs.c
static const std::unordered_map<std::string, int32_t> BATTERY_STATUS =
        {{"Unknown", BATTERY_STATUS_UNKNOWN},
         {"Charging", BATTERY_STATUS_CHARGING},
         {"Discharging", BATTERY_STATUS_DISCHARGING},
         {"Not charging", BATTERY_STATUS_NOT_CHARGING},
         {"Full", BATTERY_STATUS_FULL}};

// Mapping taken from
// https://gitlab.freedesktop.org/upower/upower/-/blob/master/src/linux/up-device-supply.c#L484
static const std::unordered_map<std::string, int32_t> BATTERY_LEVEL = {{"Critical", 5},
                                                                       {"Low", 10},
                                                                       {"Normal", 55},
                                                                       {"High", 70},
                                                                       {"Full", 100},
                                                                       {"Unknown", 50}};

// Mapping for input led class node names lookup.
// https://www.kernel.org/doc/html/latest/leds/leds-class.html
static const std::unordered_map<std::string, InputLightClass> LIGHT_CLASSES =
        {{"red", InputLightClass::RED},
         {"green", InputLightClass::GREEN},
         {"blue", InputLightClass::BLUE},
         {"global", InputLightClass::GLOBAL},
         {"brightness", InputLightClass::BRIGHTNESS},
         {"multi_index", InputLightClass::MULTI_INDEX},
         {"multi_intensity", InputLightClass::MULTI_INTENSITY},
         {"max_brightness", InputLightClass::MAX_BRIGHTNESS},
         {"kbd_backlight", InputLightClass::KEYBOARD_BACKLIGHT}};

// Mapping for input multicolor led class node names.
// https://www.kernel.org/doc/html/latest/leds/leds-class-multicolor.html
static const std::unordered_map<InputLightClass, std::string> LIGHT_NODES =
        {{InputLightClass::BRIGHTNESS, "brightness"},
         {InputLightClass::MULTI_INDEX, "multi_index"},
         {InputLightClass::MULTI_INTENSITY, "multi_intensity"}};

// Mapping for light color name and the light color
const std::unordered_map<std::string, LightColor> LIGHT_COLORS = {{"red", LightColor::RED},
                                                                  {"green", LightColor::GREEN},
                                                                  {"blue", LightColor::BLUE}};

// Mapping for country code to Layout info.
// See bCountryCode in 6.2.1 of https://usb.org/sites/default/files/hid1_11.pdf.
const std::unordered_map<std::int32_t, RawLayoutInfo> LAYOUT_INFOS =
        {{0, RawLayoutInfo{.languageTag = "", .layoutType = ""}},             // NOT_SUPPORTED
         {1, RawLayoutInfo{.languageTag = "ar-Arab", .layoutType = ""}},      // ARABIC
         {2, RawLayoutInfo{.languageTag = "fr-BE", .layoutType = ""}},        // BELGIAN
         {3, RawLayoutInfo{.languageTag = "fr-CA", .layoutType = ""}},        // CANADIAN_BILINGUAL
         {4, RawLayoutInfo{.languageTag = "fr-CA", .layoutType = ""}},        // CANADIAN_FRENCH
         {5, RawLayoutInfo{.languageTag = "cs", .layoutType = ""}},           // CZECH_REPUBLIC
         {6, RawLayoutInfo{.languageTag = "da", .layoutType = ""}},           // DANISH
         {7, RawLayoutInfo{.languageTag = "fi", .layoutType = ""}},           // FINNISH
         {8, RawLayoutInfo{.languageTag = "fr-FR", .layoutType = ""}},        // FRENCH
         {9, RawLayoutInfo{.languageTag = "de", .layoutType = ""}},           // GERMAN
         {10, RawLayoutInfo{.languageTag = "el", .layoutType = ""}},          // GREEK
         {11, RawLayoutInfo{.languageTag = "iw", .layoutType = ""}},          // HEBREW
         {12, RawLayoutInfo{.languageTag = "hu", .layoutType = ""}},          // HUNGARY
         {13, RawLayoutInfo{.languageTag = "en", .layoutType = "extended"}},  // INTERNATIONAL (ISO)
         {14, RawLayoutInfo{.languageTag = "it", .layoutType = ""}},          // ITALIAN
         {15, RawLayoutInfo{.languageTag = "ja", .layoutType = ""}},          // JAPAN
         {16, RawLayoutInfo{.languageTag = "ko", .layoutType = ""}},          // KOREAN
         {17, RawLayoutInfo{.languageTag = "es-419", .layoutType = ""}},      // LATIN_AMERICA
         {18, RawLayoutInfo{.languageTag = "nl", .layoutType = ""}},          // DUTCH
         {19, RawLayoutInfo{.languageTag = "nb", .layoutType = ""}},          // NORWEGIAN
         {20, RawLayoutInfo{.languageTag = "fa", .layoutType = ""}},          // PERSIAN
         {21, RawLayoutInfo{.languageTag = "pl", .layoutType = ""}},          // POLAND
         {22, RawLayoutInfo{.languageTag = "pt", .layoutType = ""}},          // PORTUGUESE
         {23, RawLayoutInfo{.languageTag = "ru", .layoutType = ""}},          // RUSSIA
         {24, RawLayoutInfo{.languageTag = "sk", .layoutType = ""}},          // SLOVAKIA
         {25, RawLayoutInfo{.languageTag = "es-ES", .layoutType = ""}},       // SPANISH
         {26, RawLayoutInfo{.languageTag = "sv", .layoutType = ""}},          // SWEDISH
         {27, RawLayoutInfo{.languageTag = "fr-CH", .layoutType = ""}},       // SWISS_FRENCH
         {28, RawLayoutInfo{.languageTag = "de-CH", .layoutType = ""}},       // SWISS_GERMAN
         {29, RawLayoutInfo{.languageTag = "de-CH", .layoutType = ""}},       // SWITZERLAND
         {30, RawLayoutInfo{.languageTag = "zh-TW", .layoutType = ""}},       // TAIWAN
         {31, RawLayoutInfo{.languageTag = "tr", .layoutType = "turkish_q"}}, // TURKISH_Q
         {32, RawLayoutInfo{.languageTag = "en-GB", .layoutType = ""}},       // UK
         {33, RawLayoutInfo{.languageTag = "en-US", .layoutType = ""}},       // US
         {34, RawLayoutInfo{.languageTag = "", .layoutType = ""}},            // YUGOSLAVIA
         {35, RawLayoutInfo{.languageTag = "tr", .layoutType = "turkish_f"}}}; // TURKISH_F

static std::string sha1(const std::string& in) {
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, reinterpret_cast<const u_char*>(in.c_str()), in.size());
    u_char digest[SHA_DIGEST_LENGTH];
    SHA1_Final(digest, &ctx);

    std::string out;
    for (size_t i = 0; i < SHA_DIGEST_LENGTH; i++) {
        out += StringPrintf("%02x", digest[i]);
    }
    return out;
}

/**
 * Return true if name matches "v4l-touch*"
 */
static bool isV4lTouchNode(std::string name) {
    return name.find("v4l-touch") != std::string::npos;
}

/**
 * Returns true if V4L devices should be scanned.
 *
 * The system property ro.input.video_enabled can be used to control whether
 * EventHub scans and opens V4L devices. As V4L does not support multiple
 * clients, EventHub effectively blocks access to these devices when it opens
 * them.
 *
 * Setting this to "false" would prevent any video devices from being discovered and
 * associated with input devices.
 *
 * This property can be used as follows:
 * 1. To turn off features that are dependent on video device presence.
 * 2. During testing and development, to allow other clients to read video devices
 * directly from /dev.
 */
static bool isV4lScanningEnabled() {
    return property_get_bool("ro.input.video_enabled", /*default_value=*/true);
}

static nsecs_t processEventTimestamp(const struct input_event& event) {
    // Use the time specified in the event instead of the current time
    // so that downstream code can get more accurate estimates of
    // event dispatch latency from the time the event is enqueued onto
    // the evdev client buffer.
    //
    // The event's timestamp fortuitously uses the same monotonic clock
    // time base as the rest of Android. The kernel event device driver
    // (drivers/input/evdev.c) obtains timestamps using ktime_get_ts().
    // The systemTime(SYSTEM_TIME_MONOTONIC) function we use everywhere
    // calls clock_gettime(CLOCK_MONOTONIC) which is implemented as a
    // system call that also queries ktime_get_ts().

    const nsecs_t inputEventTime = seconds_to_nanoseconds(event.input_event_sec) +
            microseconds_to_nanoseconds(event.input_event_usec);
    return inputEventTime;
}

/**
 * Returns the sysfs root path of the input device.
 */
static std::optional<std::filesystem::path> getSysfsRootPath(const char* devicePath) {
    std::error_code errorCode;

    // Stat the device path to get the major and minor number of the character file
    struct stat statbuf;
    if (stat(devicePath, &statbuf) == -1) {
        ALOGE("Could not stat device %s due to error: %s.", devicePath, std::strerror(errno));
        return std::nullopt;
    }

    unsigned int major_num = major(statbuf.st_rdev);
    unsigned int minor_num = minor(statbuf.st_rdev);

    // Realpath "/sys/dev/char/{major}:{minor}" to get the sysfs path to the input event
    auto sysfsPath = std::filesystem::path("/sys/dev/char/");
    sysfsPath /= std::to_string(major_num) + ":" + std::to_string(minor_num);
    sysfsPath = std::filesystem::canonical(sysfsPath, errorCode);

    // Make sure nothing went wrong in call to canonical()
    if (errorCode) {
        ALOGW("Could not run filesystem::canonical() due to error %d : %s.", errorCode.value(),
              errorCode.message().c_str());
        return std::nullopt;
    }

    // Continue to go up a directory until we reach a directory named "input"
    while (sysfsPath != "/" && sysfsPath.filename() != "input") {
        sysfsPath = sysfsPath.parent_path();
    }

    // Then go up one more and you will be at the sysfs root of the device
    sysfsPath = sysfsPath.parent_path();

    // Make sure we didn't reach root path and that directory actually exists
    if (sysfsPath == "/" || !std::filesystem::exists(sysfsPath, errorCode)) {
        if (errorCode) {
            ALOGW("Could not run filesystem::exists() due to error %d : %s.", errorCode.value(),
                  errorCode.message().c_str());
        }

        // Not found
        return std::nullopt;
    }

    return sysfsPath;
}

/**
 * Returns the list of files under a specified path.
 */
static std::vector<std::filesystem::path> allFilesInPath(const std::filesystem::path& path) {
    std::vector<std::filesystem::path> nodes;
    std::error_code errorCode;
    auto iter = std::filesystem::directory_iterator(path, errorCode);
    while (!errorCode && iter != std::filesystem::directory_iterator()) {
        nodes.push_back(iter->path());
        iter++;
    }
    return nodes;
}

/**
 * Returns the list of files under a specified directory in a sysfs path.
 * Example:
 * findSysfsNodes(sysfsRootPath, SysfsClass::LEDS) will return all led nodes under "leds" directory
 * in the sysfs path.
 */
static std::vector<std::filesystem::path> findSysfsNodes(const std::filesystem::path& sysfsRoot,
                                                         SysfsClass clazz) {
    std::string nodeStr = ftl::enum_string(clazz);
    std::for_each(nodeStr.begin(), nodeStr.end(),
                  [](char& c) { c = std::tolower(static_cast<unsigned char>(c)); });
    std::vector<std::filesystem::path> nodes;
    for (auto path = sysfsRoot; path != "/" && nodes.empty(); path = path.parent_path()) {
        nodes = allFilesInPath(path / nodeStr);
    }
    return nodes;
}

static std::optional<std::array<LightColor, COLOR_NUM>> getColorIndexArray(
        std::filesystem::path path) {
    std::string indexStr;
    if (!base::ReadFileToString(path, &indexStr)) {
        return std::nullopt;
    }

    // Parse the multi color LED index file, refer to kernel docs
    // leds/leds-class-multicolor.html
    std::regex indexPattern("(red|green|blue)\\s(red|green|blue)\\s(red|green|blue)[\\n]");
    std::smatch results;
    std::array<LightColor, COLOR_NUM> colors;
    if (!std::regex_match(indexStr, results, indexPattern)) {
        return std::nullopt;
    }

    for (size_t i = 1; i < results.size(); i++) {
        const auto it = LIGHT_COLORS.find(results[i].str());
        if (it != LIGHT_COLORS.end()) {
            // intensities.emplace(it->second, 0);
            colors[i - 1] = it->second;
        }
    }
    return colors;
}

/**
 * Read country code information exposed through the sysfs path and convert it to Layout info.
 */
static std::optional<RawLayoutInfo> readLayoutConfiguration(
        const std::filesystem::path& sysfsRootPath) {
    // Check the sysfs root path
    int32_t hidCountryCode = -1;
    std::string str;
    if (base::ReadFileToString(sysfsRootPath / "country", &str)) {
        hidCountryCode = std::stoi(str, nullptr, 16);
        // Update this condition if new supported country codes are added to HID spec.
        if (hidCountryCode > 35 || hidCountryCode < 0) {
            ALOGE("HID country code should be in range [0, 35], but for sysfs path %s it was %d",
                  sysfsRootPath.c_str(), hidCountryCode);
        }
    }
    const auto it = LAYOUT_INFOS.find(hidCountryCode);
    if (it != LAYOUT_INFOS.end()) {
        return it->second;
    }

    return std::nullopt;
}

/**
 * Read information about batteries exposed through the sysfs path.
 */
static std::unordered_map<int32_t /*batteryId*/, RawBatteryInfo> readBatteryConfiguration(
        const std::filesystem::path& sysfsRootPath) {
    std::unordered_map<int32_t, RawBatteryInfo> batteryInfos;
    int32_t nextBatteryId = 0;
    // Check if device has any battery.
    const auto& paths = findSysfsNodes(sysfsRootPath, SysfsClass::POWER_SUPPLY);
    for (const auto& nodePath : paths) {
        RawBatteryInfo info;
        info.id = ++nextBatteryId;
        info.path = nodePath;
        info.name = nodePath.filename();

        // Scan the path for all the files
        // Refer to https://www.kernel.org/doc/Documentation/leds/leds-class.txt
        const auto& files = allFilesInPath(nodePath);
        for (const auto& file : files) {
            const auto it = BATTERY_CLASSES.find(file.filename().string());
            if (it != BATTERY_CLASSES.end()) {
                info.flags |= it->second;
            }
        }
        batteryInfos.insert_or_assign(info.id, info);
        ALOGD("configureBatteryLocked rawBatteryId %d name %s", info.id, info.name.c_str());
    }
    return batteryInfos;
}

/**
 *  Read information about lights exposed through the sysfs path.
 */
static std::unordered_map<int32_t /*lightId*/, RawLightInfo> readLightsConfiguration(
        const std::filesystem::path& sysfsRootPath) {
    std::unordered_map<int32_t, RawLightInfo> lightInfos;
    int32_t nextLightId = 0;
    // Check if device has any lights.
    const auto& paths = findSysfsNodes(sysfsRootPath, SysfsClass::LEDS);
    for (const auto& nodePath : paths) {
        RawLightInfo info;
        info.id = ++nextLightId;
        info.path = nodePath;
        info.name = nodePath.filename();
        info.maxBrightness = std::nullopt;

        // Light name should follow the naming pattern <name>:<color>:<function>
        // Refer kernel docs /leds/leds-class.html for valid supported LED names.
        std::regex indexPattern("([a-zA-Z0-9_.:]*:)?([a-zA-Z0-9_.]*):([a-zA-Z0-9_.]*)");
        std::smatch results;

        if (std::regex_match(info.name, results, indexPattern)) {
            // regex_match will return full match at index 0 and <name> at index 1. For RawLightInfo
            // we only care about sections <color> and <function> which will be at index 2 and 3.
            for (int i = 2; i <= 3; i++) {
                const auto it = LIGHT_CLASSES.find(results.str(i));
                if (it != LIGHT_CLASSES.end()) {
                    info.flags |= it->second;
                }
            }

            // Set name of the raw light to <function> which represents playerIDs for LEDs that
            // turn on/off based on the current player ID (Refer to PeripheralController.cpp for
            // player ID logic)
            info.name = results.str(3);
        }
        // Scan the path for all the files
        // Refer to https://www.kernel.org/doc/Documentation/leds/leds-class.txt
        const auto& files = allFilesInPath(nodePath);
        for (const auto& file : files) {
            const auto it = LIGHT_CLASSES.find(file.filename().string());
            if (it != LIGHT_CLASSES.end()) {
                info.flags |= it->second;
                // If the node has maximum brightness, read it
                if (it->second == InputLightClass::MAX_BRIGHTNESS) {
                    std::string str;
                    if (base::ReadFileToString(file, &str)) {
                        info.maxBrightness = std::stoi(str);
                    }
                }
            }
        }
        lightInfos.insert_or_assign(info.id, info);
        ALOGD("configureLightsLocked rawLightId %d name %s", info.id, info.name.c_str());
    }
    return lightInfos;
}

// --- Global Functions ---

ftl::Flags<InputDeviceClass> getAbsAxisUsage(int32_t axis,
                                             ftl::Flags<InputDeviceClass> deviceClasses) {
    // Touch devices get dibs on touch-related axes.
    if (deviceClasses.test(InputDeviceClass::TOUCH)) {
        switch (axis) {
            case ABS_X:
            case ABS_Y:
            case ABS_PRESSURE:
            case ABS_TOOL_WIDTH:
            case ABS_DISTANCE:
            case ABS_TILT_X:
            case ABS_TILT_Y:
            case ABS_MT_SLOT:
            case ABS_MT_TOUCH_MAJOR:
            case ABS_MT_TOUCH_MINOR:
            case ABS_MT_WIDTH_MAJOR:
            case ABS_MT_WIDTH_MINOR:
            case ABS_MT_ORIENTATION:
            case ABS_MT_POSITION_X:
            case ABS_MT_POSITION_Y:
            case ABS_MT_TOOL_TYPE:
            case ABS_MT_BLOB_ID:
            case ABS_MT_TRACKING_ID:
            case ABS_MT_PRESSURE:
            case ABS_MT_DISTANCE:
                return InputDeviceClass::TOUCH;
        }
    }

    if (deviceClasses.test(InputDeviceClass::SENSOR)) {
        switch (axis) {
            case ABS_X:
            case ABS_Y:
            case ABS_Z:
            case ABS_RX:
            case ABS_RY:
            case ABS_RZ:
                return InputDeviceClass::SENSOR;
        }
    }

    // External stylus gets the pressure axis
    if (deviceClasses.test(InputDeviceClass::EXTERNAL_STYLUS)) {
        if (axis == ABS_PRESSURE) {
            return InputDeviceClass::EXTERNAL_STYLUS;
        }
    }

    // Joystick devices get the rest.
    return deviceClasses & InputDeviceClass::JOYSTICK;
}

// --- RawAbsoluteAxisInfo ---

std::ostream& operator<<(std::ostream& out, const RawAbsoluteAxisInfo& info) {
    if (info.valid) {
        out << "min=" << info.minValue << ", max=" << info.maxValue << ", flat=" << info.flat
            << ", fuzz=" << info.fuzz << ", resolution=" << info.resolution;
    } else {
        out << "unknown range";
    }
    return out;
}

// --- EventHub::Device ---

EventHub::Device::Device(int fd, int32_t id, std::string path, InputDeviceIdentifier identifier,
                         std::shared_ptr<const AssociatedDevice> assocDev)
      : fd(fd),
        id(id),
        path(std::move(path)),
        identifier(std::move(identifier)),
        classes(0),
        configuration(nullptr),
        virtualKeyMap(nullptr),
        ffEffectPlaying(false),
        ffEffectId(-1),
        associatedDevice(std::move(assocDev)),
        controllerNumber(0),
        enabled(true),
        isVirtual(fd < 0),
        currentFrameDropped(false) {}

EventHub::Device::~Device() {
    close();
}

void EventHub::Device::close() {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

status_t EventHub::Device::enable() {
    fd = open(path.c_str(), O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        ALOGE("could not open %s, %s\n", path.c_str(), strerror(errno));
        return -errno;
    }
    enabled = true;
    return OK;
}

status_t EventHub::Device::disable() {
    close();
    enabled = false;
    return OK;
}

bool EventHub::Device::hasValidFd() const {
    return !isVirtual && enabled;
}

const std::shared_ptr<KeyCharacterMap> EventHub::Device::getKeyCharacterMap() const {
    return keyMap.keyCharacterMap;
}

template <std::size_t N>
status_t EventHub::Device::readDeviceBitMask(unsigned long ioctlCode, BitArray<N>& bitArray) {
    if (!hasValidFd()) {
        return BAD_VALUE;
    }
    if ((_IOC_SIZE(ioctlCode) == 0)) {
        ioctlCode |= _IOC(0, 0, 0, bitArray.bytes());
    }

    typename BitArray<N>::Buffer buffer;
    status_t ret = ioctl(fd, ioctlCode, buffer.data());
    bitArray.loadFromBuffer(buffer);
    return ret;
}

void EventHub::Device::configureFd() {
    // Set fd parameters with ioctl, such as key repeat, suspend block, and clock type
    if (classes.test(InputDeviceClass::KEYBOARD)) {
        // Disable kernel key repeat since we handle it ourselves
        unsigned int repeatRate[] = {0, 0};
        if (ioctl(fd, EVIOCSREP, repeatRate)) {
            ALOGW("Unable to disable kernel key repeat for %s: %s", path.c_str(), strerror(errno));
        }
    }

    // Tell the kernel that we want to use the monotonic clock for reporting timestamps
    // associated with input events.  This is important because the input system
    // uses the timestamps extensively and assumes they were recorded using the monotonic
    // clock.
    int clockId = CLOCK_MONOTONIC;
    if (classes.test(InputDeviceClass::SENSOR)) {
        // Each new sensor event should use the same time base as
        // SystemClock.elapsedRealtimeNanos().
        clockId = CLOCK_BOOTTIME;
    }
    bool usingClockIoctl = !ioctl(fd, EVIOCSCLOCKID, &clockId);
    ALOGI("usingClockIoctl=%s", toString(usingClockIoctl));

    // Query the initial state of keys and switches, which is tracked by EventHub.
    readDeviceState();
}

void EventHub::Device::readDeviceState() {
    if (readDeviceBitMask(EVIOCGKEY(0), keyState) < 0) {
        ALOGD("Unable to query the global key state for %s: %s", path.c_str(), strerror(errno));
    }
    if (readDeviceBitMask(EVIOCGSW(0), swState) < 0) {
        ALOGD("Unable to query the global switch state for %s: %s", path.c_str(), strerror(errno));
    }

    // Read absolute axis info and values for all available axes for the device.
    populateAbsoluteAxisStates();
}

void EventHub::Device::populateAbsoluteAxisStates() {
    absState.clear();

    for (int axis = 0; axis <= ABS_MAX; axis++) {
        if (!absBitmask.test(axis)) {
            continue;
        }
        struct input_absinfo info {};
        if (ioctl(fd, EVIOCGABS(axis), &info)) {
            ALOGE("Error reading absolute controller %d for device %s fd %d: %s", axis,
                  identifier.name.c_str(), fd, strerror(errno));
            continue;
        }
        auto& [axisInfo, value] = absState[axis];
        axisInfo.valid = true;
        axisInfo.minValue = info.minimum;
        axisInfo.maxValue = info.maximum;
        axisInfo.flat = info.flat;
        axisInfo.fuzz = info.fuzz;
        axisInfo.resolution = info.resolution;
        value = info.value;
    }
}

bool EventHub::Device::hasKeycodeLocked(int keycode) const {
    if (!keyMap.haveKeyLayout()) {
        return false;
    }

    std::vector<int32_t> scanCodes = keyMap.keyLayoutMap->findScanCodesForKey(keycode);
    const size_t N = scanCodes.size();
    for (size_t i = 0; i < N && i <= KEY_MAX; i++) {
        int32_t sc = scanCodes[i];
        if (sc >= 0 && sc <= KEY_MAX && keyBitmask.test(sc)) {
            return true;
        }
    }

    std::vector<int32_t> usageCodes = keyMap.keyLayoutMap->findUsageCodesForKey(keycode);
    if (usageCodes.size() > 0 && mscBitmask.test(MSC_SCAN)) {
        return true;
    }

    return false;
}

void EventHub::Device::loadConfigurationLocked() {
    configurationFile =
            getInputDeviceConfigurationFilePathByDeviceIdentifier(identifier,
                                                                  InputDeviceConfigurationFileType::
                                                                          CONFIGURATION);
    if (configurationFile.empty()) {
        ALOGD("No input device configuration file found for device '%s'.", identifier.name.c_str());
    } else {
        android::base::Result<std::unique_ptr<PropertyMap>> propertyMap =
                PropertyMap::load(configurationFile.c_str());
        if (!propertyMap.ok()) {
            ALOGE("Error loading input device configuration file for device '%s'.  "
                  "Using default configuration.",
                  identifier.name.c_str());
        } else {
            configuration = std::move(*propertyMap);
        }
    }
}

bool EventHub::Device::loadVirtualKeyMapLocked() {
    // The virtual key map is supplied by the kernel as a system board property file.
    std::string propPath = "/sys/board_properties/virtualkeys.";
    propPath += identifier.getCanonicalName();
    if (access(propPath.c_str(), R_OK)) {
        return false;
    }
    virtualKeyMap = VirtualKeyMap::load(propPath);
    return virtualKeyMap != nullptr;
}

status_t EventHub::Device::loadKeyMapLocked() {
    return keyMap.load(identifier, configuration.get());
}

bool EventHub::Device::isExternalDeviceLocked() {
    if (configuration) {
        std::optional<bool> isInternal = configuration->getBool("device.internal");
        if (isInternal.has_value()) {
            return !isInternal.value();
        }
    }
    return identifier.bus == BUS_USB || identifier.bus == BUS_BLUETOOTH;
}

bool EventHub::Device::deviceHasMicLocked() {
    if (configuration) {
        std::optional<bool> hasMic = configuration->getBool("audio.mic");
        if (hasMic.has_value()) {
            return hasMic.value();
        }
    }
    return false;
}

void EventHub::Device::setLedStateLocked(int32_t led, bool on) {
    int32_t sc;
    if (hasValidFd() && mapLed(led, &sc) != NAME_NOT_FOUND) {
        struct input_event ev;
        ev.input_event_sec = 0;
        ev.input_event_usec = 0;
        ev.type = EV_LED;
        ev.code = sc;
        ev.value = on ? 1 : 0;

        ssize_t nWrite;
        do {
            nWrite = write(fd, &ev, sizeof(struct input_event));
        } while (nWrite == -1 && errno == EINTR);
    }
}

void EventHub::Device::setLedForControllerLocked() {
    for (int i = 0; i < MAX_CONTROLLER_LEDS; i++) {
        setLedStateLocked(ALED_CONTROLLER_1 + i, controllerNumber == i + 1);
    }
}

status_t EventHub::Device::mapLed(int32_t led, int32_t* outScanCode) const {
    if (!keyMap.haveKeyLayout()) {
        return NAME_NOT_FOUND;
    }

    std::optional<int32_t> scanCode = keyMap.keyLayoutMap->findScanCodeForLed(led);
    if (scanCode.has_value()) {
        if (*scanCode >= 0 && *scanCode <= LED_MAX && ledBitmask.test(*scanCode)) {
            *outScanCode = *scanCode;
            return NO_ERROR;
        }
    }
    return NAME_NOT_FOUND;
}

void EventHub::Device::trackInputEvent(const struct input_event& event) {
    switch (event.type) {
        case EV_KEY: {
            LOG_ALWAYS_FATAL_IF(!currentFrameDropped &&
                                        !keyState.set(static_cast<size_t>(event.code),
                                                      event.value != 0),
                                "%s: device '%s' received invalid EV_KEY event code: %s value: %d",
                                __func__, identifier.name.c_str(),
                                InputEventLookup::getLinuxEvdevLabel(EV_KEY, event.code, 1)
                                        .code.c_str(),
                                event.value);
            break;
        }
        case EV_SW: {
            LOG_ALWAYS_FATAL_IF(!currentFrameDropped &&
                                        !swState.set(static_cast<size_t>(event.code),
                                                     event.value != 0),
                                "%s: device '%s' received invalid EV_SW event code: %s value: %d",
                                __func__, identifier.name.c_str(),
                                InputEventLookup::getLinuxEvdevLabel(EV_SW, event.code, 1)
                                        .code.c_str(),
                                event.value);
            break;
        }
        case EV_ABS: {
            if (currentFrameDropped) {
                break;
            }
            auto it = absState.find(event.code);
            LOG_ALWAYS_FATAL_IF(it == absState.end(),
                                "%s: device '%s' received invalid EV_ABS event code: %s value: %d",
                                __func__, identifier.name.c_str(),
                                InputEventLookup::getLinuxEvdevLabel(EV_ABS, event.code, 0)
                                        .code.c_str(),
                                event.value);
            it->second.value = event.value;
            break;
        }
        case EV_SYN: {
            switch (event.code) {
                case SYN_REPORT:
                    if (currentFrameDropped) {
                        // To recover after a SYN_DROPPED, we need to query the state of the device
                        // to synchronize our device state with the kernel's to account for the
                        // dropped events on receiving the next SYN_REPORT.
                        // Note we don't drop the SYN_REPORT at this point but it is used by the
                        // InputDevice to reset and repopulate mapper state
                        readDeviceState();
                        currentFrameDropped = false;
                    }
                    break;
                case SYN_DROPPED:
                    // When we receive SYN_DROPPED, all events in the current frame should be
                    // dropped up to and including next SYN_REPORT
                    currentFrameDropped = true;
                    break;
                default:
                    break;
            }
            break;
        }
        default:
            break;
    }
}

/**
 * Get the capabilities for the current process.
 * Crashes the system if unable to create / check / destroy the capabilities object.
 */
class Capabilities final {
public:
    explicit Capabilities() {
        mCaps = cap_get_proc();
        LOG_ALWAYS_FATAL_IF(mCaps == nullptr, "Could not get capabilities of the current process");
    }

    /**
     * Check whether the current process has a specific capability
     * in the set of effective capabilities.
     * Return CAP_SET if the process has the requested capability
     * Return CAP_CLEAR otherwise.
     */
    cap_flag_value_t checkEffectiveCapability(cap_value_t capability) {
        cap_flag_value_t value;
        const int result = cap_get_flag(mCaps, capability, CAP_EFFECTIVE, &value);
        LOG_ALWAYS_FATAL_IF(result == -1, "Could not obtain the requested capability");
        return value;
    }

    ~Capabilities() {
        const int result = cap_free(mCaps);
        LOG_ALWAYS_FATAL_IF(result == -1, "Could not release the capabilities structure");
    }

private:
    cap_t mCaps;
};

static void ensureProcessCanBlockSuspend() {
    Capabilities capabilities;
    const bool canBlockSuspend =
            capabilities.checkEffectiveCapability(CAP_BLOCK_SUSPEND) == CAP_SET;
    LOG_ALWAYS_FATAL_IF(!canBlockSuspend,
                        "Input must be able to block suspend to properly process events");
}

// --- EventHub ---

const int EventHub::EPOLL_MAX_EVENTS;

EventHub::EventHub(void)
      : mBuiltInKeyboardId(NO_BUILT_IN_KEYBOARD),
        mNextDeviceId(1),
        mControllerNumbers(),
        mNeedToSendFinishedDeviceScan(false),
        mNeedToReopenDevices(false),
        mNeedToScanDevices(true),
        mPendingEventCount(0),
        mPendingEventIndex(0),
        mPendingINotify(false) {
    ensureProcessCanBlockSuspend();

    mEpollFd = epoll_create1(EPOLL_CLOEXEC);
    LOG_ALWAYS_FATAL_IF(mEpollFd < 0, "Could not create epoll instance: %s", strerror(errno));

    mINotifyFd = inotify_init1(IN_CLOEXEC);
    LOG_ALWAYS_FATAL_IF(mINotifyFd < 0, "Could not create inotify instance: %s", strerror(errno));

    std::error_code errorCode;
    bool isDeviceInotifyAdded = false;
    if (std::filesystem::exists(DEVICE_INPUT_PATH, errorCode)) {
        addDeviceInputInotify();
    } else {
        addDeviceInotify();
        isDeviceInotifyAdded = true;
        if (errorCode) {
            ALOGW("Could not run filesystem::exists() due to error %d : %s.", errorCode.value(),
                  errorCode.message().c_str());
        }
    }

    if (isV4lScanningEnabled() && !isDeviceInotifyAdded) {
        addDeviceInotify();
    } else {
        ALOGI("Video device scanning disabled");
    }

    struct epoll_event eventItem = {};
    eventItem.events = EPOLLIN | EPOLLWAKEUP;
    eventItem.data.fd = mINotifyFd;
    int result = epoll_ctl(mEpollFd, EPOLL_CTL_ADD, mINotifyFd, &eventItem);
    LOG_ALWAYS_FATAL_IF(result != 0, "Could not add INotify to epoll instance.  errno=%d", errno);

    int wakeFds[2];
    result = pipe2(wakeFds, O_CLOEXEC);
    LOG_ALWAYS_FATAL_IF(result != 0, "Could not create wake pipe.  errno=%d", errno);

    mWakeReadPipeFd = wakeFds[0];
    mWakeWritePipeFd = wakeFds[1];

    result = fcntl(mWakeReadPipeFd, F_SETFL, O_NONBLOCK);
    LOG_ALWAYS_FATAL_IF(result != 0, "Could not make wake read pipe non-blocking.  errno=%d",
                        errno);

    result = fcntl(mWakeWritePipeFd, F_SETFL, O_NONBLOCK);
    LOG_ALWAYS_FATAL_IF(result != 0, "Could not make wake write pipe non-blocking.  errno=%d",
                        errno);

    eventItem.data.fd = mWakeReadPipeFd;
    result = epoll_ctl(mEpollFd, EPOLL_CTL_ADD, mWakeReadPipeFd, &eventItem);
    LOG_ALWAYS_FATAL_IF(result != 0, "Could not add wake read pipe to epoll instance.  errno=%d",
                        errno);
}

EventHub::~EventHub(void) {
    closeAllDevicesLocked();

    ::close(mEpollFd);
    ::close(mINotifyFd);
    ::close(mWakeReadPipeFd);
    ::close(mWakeWritePipeFd);
}

/**
 * On devices that don't have any input devices (like some development boards), the /dev/input
 * directory will be absent. However, the user may still plug in an input device at a later time.
 * Add watch for contents of /dev/input only when /dev/input appears.
 */
void EventHub::addDeviceInputInotify() {
    mDeviceInputWd = inotify_add_watch(mINotifyFd, DEVICE_INPUT_PATH, IN_DELETE | IN_CREATE);
    LOG_ALWAYS_FATAL_IF(mDeviceInputWd < 0, "Could not register INotify for %s: %s",
                        DEVICE_INPUT_PATH, strerror(errno));
}

void EventHub::addDeviceInotify() {
    mDeviceWd = inotify_add_watch(mINotifyFd, DEVICE_PATH, IN_DELETE | IN_CREATE);
    LOG_ALWAYS_FATAL_IF(mDeviceWd < 0, "Could not register INotify for %s: %s", DEVICE_PATH,
                        strerror(errno));
}

InputDeviceIdentifier EventHub::getDeviceIdentifier(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    return device != nullptr ? device->identifier : InputDeviceIdentifier();
}

ftl::Flags<InputDeviceClass> EventHub::getDeviceClasses(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    return device != nullptr ? device->classes : ftl::Flags<InputDeviceClass>(0);
}

int32_t EventHub::getDeviceControllerNumber(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    return device != nullptr ? device->controllerNumber : 0;
}

std::optional<PropertyMap> EventHub::getConfiguration(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || device->configuration == nullptr) {
        return {};
    }
    return *device->configuration;
}

status_t EventHub::getAbsoluteAxisInfo(int32_t deviceId, int axis,
                                       RawAbsoluteAxisInfo* outAxisInfo) const {
    outAxisInfo->clear();
    if (axis < 0 || axis > ABS_MAX) {
        return NAME_NOT_FOUND;
    }
    std::scoped_lock _l(mLock);
    const Device* device = getDeviceLocked(deviceId);
    if (device == nullptr) {
        return NAME_NOT_FOUND;
    }
    // We can read the RawAbsoluteAxisInfo even if the device is disabled and doesn't have a valid
    // fd, because the info is populated once when the device is first opened, and it doesn't change
    // throughout the device lifecycle.
    auto it = device->absState.find(axis);
    if (it == device->absState.end()) {
        return NAME_NOT_FOUND;
    }
    *outAxisInfo = it->second.info;
    return OK;
}

bool EventHub::hasRelativeAxis(int32_t deviceId, int axis) const {
    if (axis >= 0 && axis <= REL_MAX) {
        std::scoped_lock _l(mLock);
        Device* device = getDeviceLocked(deviceId);
        return device != nullptr ? device->relBitmask.test(axis) : false;
    }
    return false;
}

bool EventHub::hasInputProperty(int32_t deviceId, int property) const {
    std::scoped_lock _l(mLock);

    Device* device = getDeviceLocked(deviceId);
    return property >= 0 && property <= INPUT_PROP_MAX && device != nullptr
            ? device->propBitmask.test(property)
            : false;
}

bool EventHub::hasMscEvent(int32_t deviceId, int mscEvent) const {
    std::scoped_lock _l(mLock);

    Device* device = getDeviceLocked(deviceId);
    return mscEvent >= 0 && mscEvent <= MSC_MAX && device != nullptr
            ? device->mscBitmask.test(mscEvent)
            : false;
}

int32_t EventHub::getScanCodeState(int32_t deviceId, int32_t scanCode) const {
    if (scanCode < 0 || scanCode > KEY_MAX) {
        return AKEY_STATE_UNKNOWN;
    }
    std::scoped_lock _l(mLock);
    const Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->hasValidFd() || !device->keyBitmask.test(scanCode)) {
        return AKEY_STATE_UNKNOWN;
    }
    return device->keyState.test(scanCode) ? AKEY_STATE_DOWN : AKEY_STATE_UP;
}

int32_t EventHub::getKeyCodeState(int32_t deviceId, int32_t keyCode) const {
    std::scoped_lock _l(mLock);
    const Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->hasValidFd() || !device->keyMap.haveKeyLayout()) {
        return AKEY_STATE_UNKNOWN;
    }
    const std::vector<int32_t> scanCodes =
            device->keyMap.keyLayoutMap->findScanCodesForKey(keyCode);
    if (scanCodes.empty()) {
        return AKEY_STATE_UNKNOWN;
    }
    return std::any_of(scanCodes.begin(), scanCodes.end(),
                       [&device](const int32_t sc) {
                           return sc >= 0 && sc <= KEY_MAX && device->keyState.test(sc);
                       })
            ? AKEY_STATE_DOWN
            : AKEY_STATE_UP;
}

int32_t EventHub::getKeyCodeForKeyLocation(int32_t deviceId, int32_t locationKeyCode) const {
    std::scoped_lock _l(mLock);

    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->hasValidFd() || device->keyMap.keyCharacterMap == nullptr ||
        device->keyMap.keyLayoutMap == nullptr) {
        return AKEYCODE_UNKNOWN;
    }
    std::vector<int32_t> scanCodes =
            device->keyMap.keyLayoutMap->findScanCodesForKey(locationKeyCode);
    if (scanCodes.empty()) {
        ALOGW("Failed to get key code for key location: no scan code maps to key code %d for input"
              "device %d",
              locationKeyCode, deviceId);
        return AKEYCODE_UNKNOWN;
    }
    if (scanCodes.size() > 1) {
        ALOGW("Multiple scan codes map to the same key code %d, returning only the first match",
              locationKeyCode);
    }
    int32_t outKeyCode;
    status_t mapKeyRes =
            device->getKeyCharacterMap()->mapKey(scanCodes[0], /*usageCode=*/0, &outKeyCode);
    switch (mapKeyRes) {
        case OK:
            break;
        case NAME_NOT_FOUND:
            // key character map doesn't re-map this scanCode, hence the keyCode remains the same
            outKeyCode = locationKeyCode;
            break;
        default:
            ALOGW("Failed to get key code for key location: Key character map returned error %s",
                  statusToString(mapKeyRes).c_str());
            outKeyCode = AKEYCODE_UNKNOWN;
            break;
    }
    // Remap if there is a Key remapping added to the KCM and return the remapped key
    return device->getKeyCharacterMap()->applyKeyRemapping(outKeyCode);
}

int32_t EventHub::getSwitchState(int32_t deviceId, int32_t sw) const {
    if (sw < 0 || sw > SW_MAX) {
        return AKEY_STATE_UNKNOWN;
    }
    std::scoped_lock _l(mLock);
    const Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->hasValidFd() || !device->swBitmask.test(sw)) {
        return AKEY_STATE_UNKNOWN;
    }
    return device->swState.test(sw) ? AKEY_STATE_DOWN : AKEY_STATE_UP;
}

status_t EventHub::getAbsoluteAxisValue(int32_t deviceId, int32_t axis, int32_t* outValue) const {
    *outValue = 0;
    if (axis < 0 || axis > ABS_MAX) {
        return NAME_NOT_FOUND;
    }
    std::scoped_lock _l(mLock);
    const Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->hasValidFd()) {
        return NAME_NOT_FOUND;
    }
    const auto it = device->absState.find(axis);
    if (it == device->absState.end()) {
        return NAME_NOT_FOUND;
    }
    *outValue = it->second.value;
    return OK;
}

base::Result<std::vector<int32_t>> EventHub::getMtSlotValues(int32_t deviceId, int32_t axis,
                                                             size_t slotCount) const {
    std::scoped_lock _l(mLock);
    const Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->hasValidFd() || !device->absBitmask.test(axis)) {
        return base::ResultError("device problem or axis not supported", NAME_NOT_FOUND);
    }
    std::vector<int32_t> outValues(slotCount + 1);
    outValues[0] = axis;
    const size_t bufferSize = outValues.size() * sizeof(int32_t);
    if (ioctl(device->fd, EVIOCGMTSLOTS(bufferSize), outValues.data()) != OK) {
        return base::ErrnoError();
    }
    return std::move(outValues);
}

bool EventHub::markSupportedKeyCodes(int32_t deviceId, const std::vector<int32_t>& keyCodes,
                                     uint8_t* outFlags) const {
    std::scoped_lock _l(mLock);

    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr && device->keyMap.haveKeyLayout()) {
        for (size_t codeIndex = 0; codeIndex < keyCodes.size(); codeIndex++) {
            if (device->hasKeycodeLocked(keyCodes[codeIndex])) {
                outFlags[codeIndex] = 1;
            }
        }
        return true;
    }
    return false;
}

void EventHub::addKeyRemapping(int32_t deviceId, int32_t fromKeyCode, int32_t toKeyCode) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr) {
        return;
    }
    const std::shared_ptr<KeyCharacterMap> kcm = device->getKeyCharacterMap();
    if (kcm) {
        kcm->addKeyRemapping(fromKeyCode, toKeyCode);
    }
}

status_t EventHub::mapKey(int32_t deviceId, int32_t scanCode, int32_t usageCode, int32_t metaState,
                          int32_t* outKeycode, int32_t* outMetaState, uint32_t* outFlags) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    status_t status = NAME_NOT_FOUND;

    if (device != nullptr) {
        // Check the key character map first.
        const std::shared_ptr<KeyCharacterMap> kcm = device->getKeyCharacterMap();
        if (kcm) {
            if (!kcm->mapKey(scanCode, usageCode, outKeycode)) {
                *outFlags = 0;
                status = NO_ERROR;
            }
        }

        // Check the key layout next.
        if (status != NO_ERROR && device->keyMap.haveKeyLayout()) {
            if (!device->keyMap.keyLayoutMap->mapKey(scanCode, usageCode, outKeycode, outFlags)) {
                status = NO_ERROR;
            }
        }

        if (status == NO_ERROR) {
            if (kcm) {
                // Remap keys based on user-defined key remappings and key behavior defined in the
                // corresponding kcm file
                *outKeycode = kcm->applyKeyRemapping(*outKeycode);

                // Remap keys based on Key behavior defined in KCM file
                std::tie(*outKeycode, *outMetaState) =
                        kcm->applyKeyBehavior(*outKeycode, metaState);
            } else {
                *outMetaState = metaState;
            }
        }
    }

    if (status != NO_ERROR) {
        *outKeycode = 0;
        *outFlags = 0;
        *outMetaState = metaState;
    }

    return status;
}

status_t EventHub::mapAxis(int32_t deviceId, int32_t scanCode, AxisInfo* outAxisInfo) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);

    if (device == nullptr || !device->keyMap.haveKeyLayout()) {
        return NAME_NOT_FOUND;
    }
    std::optional<AxisInfo> info = device->keyMap.keyLayoutMap->mapAxis(scanCode);
    if (!info.has_value()) {
        return NAME_NOT_FOUND;
    }
    *outAxisInfo = *info;
    return NO_ERROR;
}

base::Result<std::pair<InputDeviceSensorType, int32_t>> EventHub::mapSensor(int32_t deviceId,
                                                                            int32_t absCode) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);

    if (device != nullptr && device->keyMap.haveKeyLayout()) {
        return device->keyMap.keyLayoutMap->mapSensor(absCode);
    }
    return Errorf("Device not found or device has no key layout.");
}

// Gets the battery info map from battery ID to RawBatteryInfo of the miscellaneous device
// associated with the device ID. Returns an empty map if no miscellaneous device found.
const std::unordered_map<int32_t, RawBatteryInfo>& EventHub::getBatteryInfoLocked(
        int32_t deviceId) const {
    static const std::unordered_map<int32_t, RawBatteryInfo> EMPTY_BATTERY_INFO = {};
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->associatedDevice) {
        return EMPTY_BATTERY_INFO;
    }
    return device->associatedDevice->batteryInfos;
}

std::vector<int32_t> EventHub::getRawBatteryIds(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    std::vector<int32_t> batteryIds;

    for (const auto& [id, info] : getBatteryInfoLocked(deviceId)) {
        batteryIds.push_back(id);
    }

    return batteryIds;
}

std::optional<RawBatteryInfo> EventHub::getRawBatteryInfo(int32_t deviceId,
                                                          int32_t batteryId) const {
    std::scoped_lock _l(mLock);

    const auto infos = getBatteryInfoLocked(deviceId);

    auto it = infos.find(batteryId);
    if (it != infos.end()) {
        return it->second;
    }

    return std::nullopt;
}

// Gets the light info map from light ID to RawLightInfo of the miscellaneous device associated
// with the device ID. Returns an empty map if no miscellaneous device found.
const std::unordered_map<int32_t, RawLightInfo>& EventHub::getLightInfoLocked(
        int32_t deviceId) const {
    static const std::unordered_map<int32_t, RawLightInfo> EMPTY_LIGHT_INFO = {};
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->associatedDevice) {
        return EMPTY_LIGHT_INFO;
    }
    return device->associatedDevice->lightInfos;
}

std::vector<int32_t> EventHub::getRawLightIds(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    std::vector<int32_t> lightIds;

    for (const auto& [id, info] : getLightInfoLocked(deviceId)) {
        lightIds.push_back(id);
    }

    return lightIds;
}

std::optional<RawLightInfo> EventHub::getRawLightInfo(int32_t deviceId, int32_t lightId) const {
    std::scoped_lock _l(mLock);

    const auto infos = getLightInfoLocked(deviceId);

    auto it = infos.find(lightId);
    if (it != infos.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::optional<int32_t> EventHub::getLightBrightness(int32_t deviceId, int32_t lightId) const {
    std::scoped_lock _l(mLock);

    const auto infos = getLightInfoLocked(deviceId);
    auto it = infos.find(lightId);
    if (it == infos.end()) {
        return std::nullopt;
    }
    std::string buffer;
    if (!base::ReadFileToString(it->second.path / LIGHT_NODES.at(InputLightClass::BRIGHTNESS),
                                &buffer)) {
        return std::nullopt;
    }
    return std::stoi(buffer);
}

std::optional<std::unordered_map<LightColor, int32_t>> EventHub::getLightIntensities(
        int32_t deviceId, int32_t lightId) const {
    std::scoped_lock _l(mLock);

    const auto infos = getLightInfoLocked(deviceId);
    auto lightIt = infos.find(lightId);
    if (lightIt == infos.end()) {
        return std::nullopt;
    }

    auto ret =
            getColorIndexArray(lightIt->second.path / LIGHT_NODES.at(InputLightClass::MULTI_INDEX));

    if (!ret.has_value()) {
        return std::nullopt;
    }
    std::array<LightColor, COLOR_NUM> colors = ret.value();

    std::string intensityStr;
    if (!base::ReadFileToString(lightIt->second.path /
                                        LIGHT_NODES.at(InputLightClass::MULTI_INTENSITY),
                                &intensityStr)) {
        return std::nullopt;
    }

    // Intensity node outputs 3 color values
    std::regex intensityPattern("([0-9]+)\\s([0-9]+)\\s([0-9]+)[\\n]");
    std::smatch results;

    if (!std::regex_match(intensityStr, results, intensityPattern)) {
        return std::nullopt;
    }
    std::unordered_map<LightColor, int32_t> intensities;
    for (size_t i = 1; i < results.size(); i++) {
        int value = std::stoi(results[i].str());
        intensities.emplace(colors[i - 1], value);
    }
    return intensities;
}

void EventHub::setLightBrightness(int32_t deviceId, int32_t lightId, int32_t brightness) {
    std::scoped_lock _l(mLock);

    const auto infos = getLightInfoLocked(deviceId);
    auto lightIt = infos.find(lightId);
    if (lightIt == infos.end()) {
        ALOGE("%s lightId %d not found ", __func__, lightId);
        return;
    }

    if (!base::WriteStringToFile(std::to_string(brightness),
                                 lightIt->second.path /
                                         LIGHT_NODES.at(InputLightClass::BRIGHTNESS))) {
        ALOGE("Can not write to file, error: %s", strerror(errno));
    }
}

void EventHub::setLightIntensities(int32_t deviceId, int32_t lightId,
                                   std::unordered_map<LightColor, int32_t> intensities) {
    std::scoped_lock _l(mLock);

    const auto infos = getLightInfoLocked(deviceId);
    auto lightIt = infos.find(lightId);
    if (lightIt == infos.end()) {
        ALOGE("Light Id %d does not exist.", lightId);
        return;
    }

    auto ret =
            getColorIndexArray(lightIt->second.path / LIGHT_NODES.at(InputLightClass::MULTI_INDEX));

    if (!ret.has_value()) {
        return;
    }
    std::array<LightColor, COLOR_NUM> colors = ret.value();

    std::string rgbStr;
    for (size_t i = 0; i < COLOR_NUM; i++) {
        auto it = intensities.find(colors[i]);
        if (it != intensities.end()) {
            rgbStr += std::to_string(it->second);
            // Insert space between colors
            if (i < COLOR_NUM - 1) {
                rgbStr += " ";
            }
        }
    }
    // Append new line
    rgbStr += "\n";

    if (!base::WriteStringToFile(rgbStr,
                                 lightIt->second.path /
                                         LIGHT_NODES.at(InputLightClass::MULTI_INTENSITY))) {
        ALOGE("Can not write to file, error: %s", strerror(errno));
    }
}

std::optional<RawLayoutInfo> EventHub::getRawLayoutInfo(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->associatedDevice) {
        return std::nullopt;
    }
    return device->associatedDevice->layoutInfo;
}

void EventHub::setExcludedDevices(const std::vector<std::string>& devices) {
    std::scoped_lock _l(mLock);

    mExcludedDevices = devices;
}

bool EventHub::hasScanCode(int32_t deviceId, int32_t scanCode) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr && scanCode >= 0 && scanCode <= KEY_MAX) {
        return device->keyBitmask.test(scanCode);
    }
    return false;
}

bool EventHub::hasKeyCode(int32_t deviceId, int32_t keyCode) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr) {
        return device->hasKeycodeLocked(keyCode);
    }
    return false;
}

bool EventHub::hasLed(int32_t deviceId, int32_t led) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    int32_t sc;
    if (device != nullptr && device->mapLed(led, &sc) == NO_ERROR) {
        return device->ledBitmask.test(sc);
    }
    return false;
}

void EventHub::setLedState(int32_t deviceId, int32_t led, bool on) {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr && device->hasValidFd()) {
        device->setLedStateLocked(led, on);
    }
}

void EventHub::getVirtualKeyDefinitions(int32_t deviceId,
                                        std::vector<VirtualKeyDefinition>& outVirtualKeys) const {
    outVirtualKeys.clear();

    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr && device->virtualKeyMap) {
        const std::vector<VirtualKeyDefinition> virtualKeys =
                device->virtualKeyMap->getVirtualKeys();
        outVirtualKeys.insert(outVirtualKeys.end(), virtualKeys.begin(), virtualKeys.end());
    }
}

const std::shared_ptr<KeyCharacterMap> EventHub::getKeyCharacterMap(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr) {
        return device->getKeyCharacterMap();
    }
    return nullptr;
}

// If provided map is null, it will reset key character map to default KCM.
bool EventHub::setKeyboardLayoutOverlay(int32_t deviceId, std::shared_ptr<KeyCharacterMap> map) {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || device->keyMap.keyCharacterMap == nullptr) {
        return false;
    }
    if (map == nullptr) {
        device->keyMap.keyCharacterMap->clearLayoutOverlay();
        return true;
    }
    device->keyMap.keyCharacterMap->combine(*map);
    return true;
}

static std::string generateDescriptor(InputDeviceIdentifier& identifier) {
    std::string rawDescriptor;
    rawDescriptor += StringPrintf(":%04x:%04x:", identifier.vendor, identifier.product);
    // TODO add handling for USB devices to not uniqueify kbs that show up twice
    if (!identifier.uniqueId.empty()) {
        rawDescriptor += "uniqueId:";
        rawDescriptor += identifier.uniqueId;
    }
    if (identifier.nonce != 0) {
        rawDescriptor += StringPrintf("nonce:%04x", identifier.nonce);
    }

    if (identifier.vendor == 0 && identifier.product == 0) {
        // If we don't know the vendor and product id, then the device is probably
        // built-in so we need to rely on other information to uniquely identify
        // the input device.  Usually we try to avoid relying on the device name or
        // location but for built-in input device, they are unlikely to ever change.
        if (!identifier.name.empty()) {
            rawDescriptor += "name:";
            rawDescriptor += identifier.name;
        } else if (!identifier.location.empty()) {
            rawDescriptor += "location:";
            rawDescriptor += identifier.location;
        }
    }
    identifier.descriptor = sha1(rawDescriptor);
    return rawDescriptor;
}

void EventHub::assignDescriptorLocked(InputDeviceIdentifier& identifier) {
    // Compute a device descriptor that uniquely identifies the device.
    // The descriptor is assumed to be a stable identifier.  Its value should not
    // change between reboots, reconnections, firmware updates or new releases
    // of Android. In practice we sometimes get devices that cannot be uniquely
    // identified. In this case we enforce uniqueness between connected devices.
    // Ideally, we also want the descriptor to be short and relatively opaque.
    // Note that we explicitly do not use the path or location for external devices
    // as their path or location will change as they are plugged/unplugged or moved
    // to different ports. We do fallback to using name and location in the case of
    // internal devices which are detected by the vendor and product being 0 in
    // generateDescriptor. If two identical descriptors are detected we will fallback
    // to using a 'nonce' and incrementing it until the new descriptor no longer has
    // a match with any existing descriptors.

    identifier.nonce = 0;
    std::string rawDescriptor = generateDescriptor(identifier);
    // Enforce that the generated descriptor is unique.
    while (hasDeviceWithDescriptorLocked(identifier.descriptor)) {
        identifier.nonce++;
        rawDescriptor = generateDescriptor(identifier);
    }
    ALOGV("Created descriptor: raw=%s, cooked=%s", rawDescriptor.c_str(),
          identifier.descriptor.c_str());
}

std::shared_ptr<const EventHub::AssociatedDevice> EventHub::obtainAssociatedDeviceLocked(
        const std::filesystem::path& devicePath) const {
    const std::optional<std::filesystem::path> sysfsRootPathOpt =
            getSysfsRootPath(devicePath.c_str());
    if (!sysfsRootPathOpt) {
        return nullptr;
    }

    const auto& path = *sysfsRootPathOpt;

    std::shared_ptr<const AssociatedDevice> associatedDevice = std::make_shared<AssociatedDevice>(
            AssociatedDevice{.sysfsRootPath = path,
                             .batteryInfos = readBatteryConfiguration(path),
                             .lightInfos = readLightsConfiguration(path),
                             .layoutInfo = readLayoutConfiguration(path)});

    bool associatedDeviceChanged = false;
    for (const auto& [id, dev] : mDevices) {
        if (dev->associatedDevice && dev->associatedDevice->sysfsRootPath == path) {
            if (*associatedDevice != *dev->associatedDevice) {
                associatedDeviceChanged = true;
                dev->associatedDevice = associatedDevice;
            }
            associatedDevice = dev->associatedDevice;
        }
    }
    ALOGI_IF(associatedDeviceChanged,
             "The AssociatedDevice changed for path '%s'. Using new AssociatedDevice: %s",
             path.c_str(), associatedDevice->dump().c_str());

    return associatedDevice;
}

bool EventHub::AssociatedDevice::isChanged() const {
    std::unordered_map<int32_t, RawBatteryInfo> newBatteryInfos =
            readBatteryConfiguration(sysfsRootPath);
    std::unordered_map<int32_t, RawLightInfo> newLightInfos =
            readLightsConfiguration(sysfsRootPath);
    std::optional<RawLayoutInfo> newLayoutInfo = readLayoutConfiguration(sysfsRootPath);

    if (newBatteryInfos == batteryInfos && newLightInfos == lightInfos &&
        newLayoutInfo == layoutInfo) {
        return false;
    }
    return true;
}

void EventHub::vibrate(int32_t deviceId, const VibrationElement& element) {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr && device->hasValidFd()) {
        ff_effect effect;
        memset(&effect, 0, sizeof(effect));
        effect.type = FF_RUMBLE;
        effect.id = device->ffEffectId;
        // evdev FF_RUMBLE effect only supports two channels of vibration.
        effect.u.rumble.strong_magnitude = element.getMagnitude(FF_STRONG_MAGNITUDE_CHANNEL_IDX);
        effect.u.rumble.weak_magnitude = element.getMagnitude(FF_WEAK_MAGNITUDE_CHANNEL_IDX);
        effect.replay.length = element.duration.count();
        effect.replay.delay = 0;
        if (ioctl(device->fd, EVIOCSFF, &effect)) {
            ALOGW("Could not upload force feedback effect to device %s due to error %d.",
                  device->identifier.name.c_str(), errno);
            return;
        }
        device->ffEffectId = effect.id;

        struct input_event ev;
        ev.input_event_sec = 0;
        ev.input_event_usec = 0;
        ev.type = EV_FF;
        ev.code = device->ffEffectId;
        ev.value = 1;
        if (write(device->fd, &ev, sizeof(ev)) != sizeof(ev)) {
            ALOGW("Could not start force feedback effect on device %s due to error %d.",
                  device->identifier.name.c_str(), errno);
            return;
        }
        device->ffEffectPlaying = true;
    }
}

void EventHub::cancelVibrate(int32_t deviceId) {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr && device->hasValidFd()) {
        if (device->ffEffectPlaying) {
            device->ffEffectPlaying = false;

            struct input_event ev;
            ev.input_event_sec = 0;
            ev.input_event_usec = 0;
            ev.type = EV_FF;
            ev.code = device->ffEffectId;
            ev.value = 0;
            if (write(device->fd, &ev, sizeof(ev)) != sizeof(ev)) {
                ALOGW("Could not stop force feedback effect on device %s due to error %d.",
                      device->identifier.name.c_str(), errno);
                return;
            }
        }
    }
}

std::vector<int32_t> EventHub::getVibratorIds(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    std::vector<int32_t> vibrators;
    Device* device = getDeviceLocked(deviceId);
    if (device != nullptr && device->hasValidFd() &&
        device->classes.test(InputDeviceClass::VIBRATOR)) {
        vibrators.push_back(FF_STRONG_MAGNITUDE_CHANNEL_IDX);
        vibrators.push_back(FF_WEAK_MAGNITUDE_CHANNEL_IDX);
    }
    return vibrators;
}

/**
 * Checks both mDevices and mOpeningDevices for a device with the descriptor passed.
 */
bool EventHub::hasDeviceWithDescriptorLocked(const std::string& descriptor) const {
    for (const auto& device : mOpeningDevices) {
        if (descriptor == device->identifier.descriptor) {
            return true;
        }
    }

    for (const auto& [id, device] : mDevices) {
        if (descriptor == device->identifier.descriptor) {
            return true;
        }
    }
    return false;
}

EventHub::Device* EventHub::getDeviceLocked(int32_t deviceId) const {
    if (deviceId == ReservedInputDeviceId::BUILT_IN_KEYBOARD_ID) {
        deviceId = mBuiltInKeyboardId;
    }
    const auto& it = mDevices.find(deviceId);
    return it != mDevices.end() ? it->second.get() : nullptr;
}

EventHub::Device* EventHub::getDeviceByPathLocked(const std::string& devicePath) const {
    for (const auto& [id, device] : mDevices) {
        if (device->path == devicePath) {
            return device.get();
        }
    }
    return nullptr;
}

/**
 * The file descriptor could be either input device, or a video device (associated with a
 * specific input device). Check both cases here, and return the device that this event
 * belongs to. Caller can compare the fd's once more to determine event type.
 * Looks through all input devices, and only attached video devices. Unattached video
 * devices are ignored.
 */
EventHub::Device* EventHub::getDeviceByFdLocked(int fd) const {
    for (const auto& [id, device] : mDevices) {
        if (device->fd == fd) {
            // This is an input device event
            return device.get();
        }
        if (device->videoDevice && device->videoDevice->getFd() == fd) {
            // This is a video device event
            return device.get();
        }
    }
    // We do not check mUnattachedVideoDevices here because they should not participate in epoll,
    // and therefore should never be looked up by fd.
    return nullptr;
}

std::optional<int32_t> EventHub::getBatteryCapacity(int32_t deviceId, int32_t batteryId) const {
    std::filesystem::path batteryPath;
    {
        // Do not read the sysfs node to get the battery state while holding
        // the EventHub lock. For some peripheral devices, reading battery state
        // can be broken and take 5+ seconds. Holding the lock in this case would
        // block all other event processing during this time. For now, we assume this
        // call never happens on the InputReader thread and read the sysfs node outside
        // the lock to prevent event processing from being blocked by this call.
        std::scoped_lock _l(mLock);

        const auto& infos = getBatteryInfoLocked(deviceId);
        auto it = infos.find(batteryId);
        if (it == infos.end()) {
            return std::nullopt;
        }
        batteryPath = it->second.path;
    } // release lock

    std::string buffer;

    // Some devices report battery capacity as an integer through the "capacity" file
    if (base::ReadFileToString(batteryPath / BATTERY_NODES.at(InputBatteryClass::CAPACITY),
                               &buffer)) {
        return std::stoi(base::Trim(buffer));
    }

    // Other devices report capacity as an enum value POWER_SUPPLY_CAPACITY_LEVEL_XXX
    // These values are taken from kernel source code include/linux/power_supply.h
    if (base::ReadFileToString(batteryPath / BATTERY_NODES.at(InputBatteryClass::CAPACITY_LEVEL),
                               &buffer)) {
        // Remove any white space such as trailing new line
        const auto levelIt = BATTERY_LEVEL.find(base::Trim(buffer));
        if (levelIt != BATTERY_LEVEL.end()) {
            return levelIt->second;
        }
    }

    return std::nullopt;
}

std::optional<int32_t> EventHub::getBatteryStatus(int32_t deviceId, int32_t batteryId) const {
    std::filesystem::path batteryPath;
    {
        // Do not read the sysfs node to get the battery state while holding
        // the EventHub lock. For some peripheral devices, reading battery state
        // can be broken and take 5+ seconds. Holding the lock in this case would
        // block all other event processing during this time. For now, we assume this
        // call never happens on the InputReader thread and read the sysfs node outside
        // the lock to prevent event processing from being blocked by this call.
        std::scoped_lock _l(mLock);

        const auto& infos = getBatteryInfoLocked(deviceId);
        auto it = infos.find(batteryId);
        if (it == infos.end()) {
            return std::nullopt;
        }
        batteryPath = it->second.path;
    } // release lock

    std::string buffer;

    if (!base::ReadFileToString(batteryPath / BATTERY_NODES.at(InputBatteryClass::STATUS),
                                &buffer)) {
        ALOGE("Failed to read sysfs battery info: %s", strerror(errno));
        return std::nullopt;
    }

    // Remove white space like trailing new line
    const auto statusIt = BATTERY_STATUS.find(base::Trim(buffer));
    if (statusIt != BATTERY_STATUS.end()) {
        return statusIt->second;
    }

    return std::nullopt;
}

std::vector<RawEvent> EventHub::getEvents(int timeoutMillis) {
    std::scoped_lock _l(mLock);

    std::array<input_event, EVENT_BUFFER_SIZE> readBuffer;

    std::vector<RawEvent> events;
    bool awoken = false;
    for (;;) {
        nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);

        // Reopen input devices if needed.
        if (mNeedToReopenDevices) {
            mNeedToReopenDevices = false;

            ALOGI("Reopening all input devices due to a configuration change.");

            closeAllDevicesLocked();
            mNeedToScanDevices = true;
            break; // return to the caller before we actually rescan
        }

        // Report any devices that had last been added/removed.
        for (auto it = mClosingDevices.begin(); it != mClosingDevices.end();) {
            std::unique_ptr<Device> device = std::move(*it);
            ALOGV("Reporting device closed: id=%d, name=%s\n", device->id, device->path.c_str());
            const int32_t deviceId = (device->id == mBuiltInKeyboardId)
                    ? ReservedInputDeviceId::BUILT_IN_KEYBOARD_ID
                    : device->id;
            events.push_back({
                    .when = now,
                    .deviceId = deviceId,
                    .type = DEVICE_REMOVED,
            });
            it = mClosingDevices.erase(it);
            mNeedToSendFinishedDeviceScan = true;
            if (events.size() == EVENT_BUFFER_SIZE) {
                break;
            }
        }

        if (mNeedToScanDevices) {
            mNeedToScanDevices = false;
            scanDevicesLocked();
            mNeedToSendFinishedDeviceScan = true;
        }

        while (!mOpeningDevices.empty()) {
            std::unique_ptr<Device> device = std::move(*mOpeningDevices.rbegin());
            mOpeningDevices.pop_back();
            ALOGV("Reporting device opened: id=%d, name=%s\n", device->id, device->path.c_str());
            const int32_t deviceId = device->id == mBuiltInKeyboardId ? 0 : device->id;
            events.push_back({
                    .when = now,
                    .deviceId = deviceId,
                    .type = DEVICE_ADDED,
            });

            // Try to find a matching video device by comparing device names
            for (auto it = mUnattachedVideoDevices.begin(); it != mUnattachedVideoDevices.end();
                 it++) {
                std::unique_ptr<TouchVideoDevice>& videoDevice = *it;
                if (tryAddVideoDeviceLocked(*device, videoDevice)) {
                    // videoDevice was transferred to 'device'
                    it = mUnattachedVideoDevices.erase(it);
                    break;
                }
            }

            auto [dev_it, inserted] = mDevices.insert_or_assign(device->id, std::move(device));
            if (!inserted) {
                ALOGW("Device id %d exists, replaced.", device->id);
            }
            mNeedToSendFinishedDeviceScan = true;
            if (events.size() == EVENT_BUFFER_SIZE) {
                break;
            }
        }

        if (mNeedToSendFinishedDeviceScan) {
            mNeedToSendFinishedDeviceScan = false;
            events.push_back({
                    .when = now,
                    .type = FINISHED_DEVICE_SCAN,
            });
            if (events.size() == EVENT_BUFFER_SIZE) {
                break;
            }
        }

        // Grab the next input event.
        bool deviceChanged = false;
        while (mPendingEventIndex < mPendingEventCount) {
            const struct epoll_event& eventItem = mPendingEventItems[mPendingEventIndex++];
            if (eventItem.data.fd == mINotifyFd) {
                if (eventItem.events & EPOLLIN) {
                    mPendingINotify = true;
                } else {
                    ALOGW("Received unexpected epoll event 0x%08x for INotify.", eventItem.events);
                }
                continue;
            }

            if (eventItem.data.fd == mWakeReadPipeFd) {
                if (eventItem.events & EPOLLIN) {
                    ALOGV("awoken after wake()");
                    awoken = true;
                    char wakeReadBuffer[16];
                    ssize_t nRead;
                    do {
                        nRead = read(mWakeReadPipeFd, wakeReadBuffer, sizeof(wakeReadBuffer));
                    } while ((nRead == -1 && errno == EINTR) || nRead == sizeof(wakeReadBuffer));
                } else {
                    ALOGW("Received unexpected epoll event 0x%08x for wake read pipe.",
                          eventItem.events);
                }
                continue;
            }

            Device* device = getDeviceByFdLocked(eventItem.data.fd);
            if (device == nullptr) {
                ALOGE("Received unexpected epoll event 0x%08x for unknown fd %d.", eventItem.events,
                      eventItem.data.fd);
                ALOG_ASSERT(!DEBUG);
                continue;
            }
            if (device->videoDevice && eventItem.data.fd == device->videoDevice->getFd()) {
                if (eventItem.events & EPOLLIN) {
                    size_t numFrames = device->videoDevice->readAndQueueFrames();
                    if (numFrames == 0) {
                        ALOGE("Received epoll event for video device %s, but could not read frame",
                              device->videoDevice->getName().c_str());
                    }
                } else if (eventItem.events & EPOLLHUP) {
                    // TODO(b/121395353) - consider adding EPOLLRDHUP
                    ALOGI("Removing video device %s due to epoll hang-up event.",
                          device->videoDevice->getName().c_str());
                    unregisterVideoDeviceFromEpollLocked(*device->videoDevice);
                    device->videoDevice = nullptr;
                } else {
                    ALOGW("Received unexpected epoll event 0x%08x for device %s.", eventItem.events,
                          device->videoDevice->getName().c_str());
                    ALOG_ASSERT(!DEBUG);
                }
                continue;
            }
            // This must be an input event
            if (eventItem.events & EPOLLIN) {
                int32_t readSize =
                        read(device->fd, readBuffer.data(),
                             sizeof(decltype(readBuffer)::value_type) * readBuffer.size());
                if (readSize == 0 || (readSize < 0 && errno == ENODEV)) {
                    // Device was removed before INotify noticed.
                    ALOGW("could not get event, removed? (fd: %d size: %" PRId32
                          " capacity: %zu errno: %d)\n",
                          device->fd, readSize, readBuffer.size(), errno);
                    deviceChanged = true;
                    closeDeviceLocked(*device);
                } else if (readSize < 0) {
                    if (errno != EAGAIN && errno != EINTR) {
                        ALOGW("could not get event (errno=%d)", errno);
                    }
                } else if ((readSize % sizeof(struct input_event)) != 0) {
                    ALOGE("could not get event (wrong size: %d)", readSize);
                } else {
                    const int32_t deviceId = device->id == mBuiltInKeyboardId ? 0 : device->id;

                    const size_t count = size_t(readSize) / sizeof(struct input_event);
                    for (size_t i = 0; i < count; i++) {
                        struct input_event& iev = readBuffer[i];
                        device->trackInputEvent(iev);
                        events.push_back({
                                .when = processEventTimestamp(iev),
                                .readTime = systemTime(SYSTEM_TIME_MONOTONIC),
                                .deviceId = deviceId,
                                .type = iev.type,
                                .code = iev.code,
                                .value = iev.value,
                        });
                    }
                    if (events.size() >= EVENT_BUFFER_SIZE) {
                        // The result buffer is full.  Reset the pending event index
                        // so we will try to read the device again on the next iteration.
                        mPendingEventIndex -= 1;
                        break;
                    }
                }
            } else if (eventItem.events & EPOLLHUP) {
                ALOGI("Removing device %s due to epoll hang-up event.",
                      device->identifier.name.c_str());
                deviceChanged = true;
                closeDeviceLocked(*device);
            } else {
                ALOGW("Received unexpected epoll event 0x%08x for device %s.", eventItem.events,
                      device->identifier.name.c_str());
            }
        }

        // readNotify() will modify the list of devices so this must be done after
        // processing all other events to ensure that we read all remaining events
        // before closing the devices.
        if (mPendingINotify && mPendingEventIndex >= mPendingEventCount) {
            mPendingINotify = false;
            const auto res = readNotifyLocked();
            if (!res.ok()) {
                ALOGW("Failed to read from inotify: %s", res.error().message().c_str());
            }
            deviceChanged = true;
        }

        // Report added or removed devices immediately.
        if (deviceChanged) {
            continue;
        }

        // Return now if we have collected any events or if we were explicitly awoken.
        if (!events.empty() || awoken) {
            break;
        }

        // Poll for events.
        // When a device driver has pending (unread) events, it acquires
        // a kernel wake lock.  Once the last pending event has been read, the device
        // driver will release the kernel wake lock, but the epoll will hold the wakelock,
        // since we are using EPOLLWAKEUP. The wakelock is released by the epoll when epoll_wait
        // is called again for the same fd that produced the event.
        // Thus the system can only sleep if there are no events pending or
        // currently being processed.
        //
        // The timeout is advisory only.  If the device is asleep, it will not wake just to
        // service the timeout.
        mPendingEventIndex = 0;

        mLock.unlock(); // release lock before poll

        int pollResult = epoll_wait(mEpollFd, mPendingEventItems, EPOLL_MAX_EVENTS, timeoutMillis);

        mLock.lock(); // reacquire lock after poll

        if (pollResult == 0) {
            // Timed out.
            mPendingEventCount = 0;
            break;
        }

        if (pollResult < 0) {
            // An error occurred.
            mPendingEventCount = 0;

            // Sleep after errors to avoid locking up the system.
            // Hopefully the error is transient.
            if (errno != EINTR) {
                ALOGW("poll failed (errno=%d)\n", errno);
                usleep(100000);
            }
        } else {
            // Some events occurred.
            mPendingEventCount = size_t(pollResult);
        }
    }

    // All done, return the number of events we read.
    return events;
}

std::vector<TouchVideoFrame> EventHub::getVideoFrames(int32_t deviceId) {
    std::scoped_lock _l(mLock);

    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr || !device->videoDevice) {
        return {};
    }
    return device->videoDevice->consumeFrames();
}

void EventHub::wake() {
    ALOGV("wake() called");

    ssize_t nWrite;
    do {
        nWrite = write(mWakeWritePipeFd, "W", 1);
    } while (nWrite == -1 && errno == EINTR);

    if (nWrite != 1 && errno != EAGAIN) {
        ALOGW("Could not write wake signal: %s", strerror(errno));
    }
}

void EventHub::scanDevicesLocked() {
    status_t result;
    std::error_code errorCode;

    if (std::filesystem::exists(DEVICE_INPUT_PATH, errorCode)) {
        result = scanDirLocked(DEVICE_INPUT_PATH);
        if (result < 0) {
            ALOGE("scan dir failed for %s", DEVICE_INPUT_PATH);
        }
    } else {
        if (errorCode) {
            ALOGW("Could not run filesystem::exists() due to error %d : %s.", errorCode.value(),
                  errorCode.message().c_str());
        }
    }
    if (isV4lScanningEnabled()) {
        result = scanVideoDirLocked(DEVICE_PATH);
        if (result != OK) {
            ALOGE("scan video dir failed for %s", DEVICE_PATH);
        }
    }
    if (mDevices.find(ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID) == mDevices.end()) {
        createVirtualKeyboardLocked();
    }
}

// ----------------------------------------------------------------------------

status_t EventHub::registerFdForEpoll(int fd) {
    // TODO(b/121395353) - consider adding EPOLLRDHUP
    struct epoll_event eventItem = {};
    eventItem.events = EPOLLIN | EPOLLWAKEUP;
    eventItem.data.fd = fd;
    if (epoll_ctl(mEpollFd, EPOLL_CTL_ADD, fd, &eventItem)) {
        ALOGE("Could not add fd to epoll instance: %s", strerror(errno));
        return -errno;
    }
    return OK;
}

status_t EventHub::unregisterFdFromEpoll(int fd) {
    if (epoll_ctl(mEpollFd, EPOLL_CTL_DEL, fd, nullptr)) {
        ALOGW("Could not remove fd from epoll instance: %s", strerror(errno));
        return -errno;
    }
    return OK;
}

status_t EventHub::registerDeviceForEpollLocked(Device& device) {
    status_t result = registerFdForEpoll(device.fd);
    if (result != OK) {
        ALOGE("Could not add input device fd to epoll for device %" PRId32, device.id);
        return result;
    }
    if (device.videoDevice) {
        registerVideoDeviceForEpollLocked(*device.videoDevice);
    }
    return result;
}

void EventHub::registerVideoDeviceForEpollLocked(const TouchVideoDevice& videoDevice) {
    status_t result = registerFdForEpoll(videoDevice.getFd());
    if (result != OK) {
        ALOGE("Could not add video device %s to epoll", videoDevice.getName().c_str());
    }
}

status_t EventHub::unregisterDeviceFromEpollLocked(Device& device) {
    if (device.hasValidFd()) {
        status_t result = unregisterFdFromEpoll(device.fd);
        if (result != OK) {
            ALOGW("Could not remove input device fd from epoll for device %" PRId32, device.id);
            return result;
        }
    }
    if (device.videoDevice) {
        unregisterVideoDeviceFromEpollLocked(*device.videoDevice);
    }
    return OK;
}

void EventHub::unregisterVideoDeviceFromEpollLocked(const TouchVideoDevice& videoDevice) {
    if (videoDevice.hasValidFd()) {
        status_t result = unregisterFdFromEpoll(videoDevice.getFd());
        if (result != OK) {
            ALOGW("Could not remove video device fd from epoll for device: %s",
                  videoDevice.getName().c_str());
        }
    }
}

void EventHub::reportDeviceAddedForStatisticsLocked(const InputDeviceIdentifier& identifier,
                                                    ftl::Flags<InputDeviceClass> classes) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, reinterpret_cast<const uint8_t*>(identifier.uniqueId.c_str()),
                  identifier.uniqueId.size());
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest;
    SHA256_Final(digest.data(), &ctx);

    std::string obfuscatedId;
    for (size_t i = 0; i < OBFUSCATED_LENGTH; i++) {
        obfuscatedId += StringPrintf("%02x", digest[i]);
    }

    android::util::stats_write(android::util::INPUTDEVICE_REGISTERED, identifier.name.c_str(),
                               identifier.vendor, identifier.product, identifier.version,
                               identifier.bus, obfuscatedId.c_str(), classes.get());
}

void EventHub::openDeviceLocked(const std::string& devicePath) {
    // If an input device happens to register around the time when EventHub's constructor runs, it
    // is possible that the same input event node (for example, /dev/input/event3) will be noticed
    // in both 'inotify' callback and also in the 'scanDirLocked' pass. To prevent duplicate devices
    // from getting registered, ensure that this path is not already covered by an existing device.
    for (const auto& [deviceId, device] : mDevices) {
        if (device->path == devicePath) {
            return; // device was already registered
        }
    }

    char buffer[80];

    ALOGV("Opening device: %s", devicePath.c_str());

    int fd = open(devicePath.c_str(), O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        ALOGE("could not open %s, %s\n", devicePath.c_str(), strerror(errno));
        return;
    }

    InputDeviceIdentifier identifier;

    // Get device name.
    if (ioctl(fd, EVIOCGNAME(sizeof(buffer) - 1), &buffer) < 1) {
        ALOGE("Could not get device name for %s: %s", devicePath.c_str(), strerror(errno));
    } else {
        buffer[sizeof(buffer) - 1] = '\0';
        identifier.name = buffer;
    }

    // Check to see if the device is on our excluded list
    for (size_t i = 0; i < mExcludedDevices.size(); i++) {
        const std::string& item = mExcludedDevices[i];
        if (identifier.name == item) {
            ALOGI("ignoring event id %s driver %s\n", devicePath.c_str(), item.c_str());
            close(fd);
            return;
        }
    }

    // Get device driver version.
    int driverVersion;
    if (ioctl(fd, EVIOCGVERSION, &driverVersion)) {
        ALOGE("could not get driver version for %s, %s\n", devicePath.c_str(), strerror(errno));
        close(fd);
        return;
    }

    // Get device identifier.
    struct input_id inputId;
    if (ioctl(fd, EVIOCGID, &inputId)) {
        ALOGE("could not get device input id for %s, %s\n", devicePath.c_str(), strerror(errno));
        close(fd);
        return;
    }
    identifier.bus = inputId.bustype;
    identifier.product = inputId.product;
    identifier.vendor = inputId.vendor;
    identifier.version = inputId.version;

    // Get device physical location.
    if (ioctl(fd, EVIOCGPHYS(sizeof(buffer) - 1), &buffer) < 1) {
        // fprintf(stderr, "could not get location for %s, %s\n", devicePath, strerror(errno));
    } else {
        buffer[sizeof(buffer) - 1] = '\0';
        identifier.location = buffer;
    }

    // Get device unique id.
    if (ioctl(fd, EVIOCGUNIQ(sizeof(buffer) - 1), &buffer) < 1) {
        // fprintf(stderr, "could not get idstring for %s, %s\n", devicePath, strerror(errno));
    } else {
        buffer[sizeof(buffer) - 1] = '\0';
        identifier.uniqueId = buffer;
    }

    // Attempt to get the bluetooth address of an input device from the uniqueId.
    if (identifier.bus == BUS_BLUETOOTH &&
        std::regex_match(identifier.uniqueId,
                         std::regex("^[A-Fa-f0-9]{2}(?::[A-Fa-f0-9]{2}){5}$"))) {
        identifier.bluetoothAddress = identifier.uniqueId;
        // The Bluetooth stack requires alphabetic characters to be uppercase in a valid address.
        for (auto& c : *identifier.bluetoothAddress) {
            c = ::toupper(c);
        }
    }

    // Fill in the descriptor.
    assignDescriptorLocked(identifier);

    // Allocate device.  (The device object takes ownership of the fd at this point.)
    int32_t deviceId = mNextDeviceId++;
    std::unique_ptr<Device> device =
            std::make_unique<Device>(fd, deviceId, devicePath, identifier,
                                     obtainAssociatedDeviceLocked(devicePath));

    ALOGV("add device %d: %s\n", deviceId, devicePath.c_str());
    ALOGV("  bus:        %04x\n"
          "  vendor      %04x\n"
          "  product     %04x\n"
          "  version     %04x\n",
          identifier.bus, identifier.vendor, identifier.product, identifier.version);
    ALOGV("  name:       \"%s\"\n", identifier.name.c_str());
    ALOGV("  location:   \"%s\"\n", identifier.location.c_str());
    ALOGV("  unique id:  \"%s\"\n", identifier.uniqueId.c_str());
    ALOGV("  descriptor: \"%s\"\n", identifier.descriptor.c_str());
    ALOGV("  driver:     v%d.%d.%d\n", driverVersion >> 16, (driverVersion >> 8) & 0xff,
          driverVersion & 0xff);

    // Load the configuration file for the device.
    device->loadConfigurationLocked();

    // Disable device if device config property set
    if (device->configuration &&
        device->configuration->getBool("device.disabled")) {
        device->disable();
        ALOGV("Disabling device with id %d\n", device->id);
    }

    // Figure out the kinds of events the device reports.
    device->readDeviceBitMask(EVIOCGBIT(EV_KEY, 0), device->keyBitmask);
    device->readDeviceBitMask(EVIOCGBIT(EV_ABS, 0), device->absBitmask);
    device->readDeviceBitMask(EVIOCGBIT(EV_REL, 0), device->relBitmask);
    device->readDeviceBitMask(EVIOCGBIT(EV_SW, 0), device->swBitmask);
    device->readDeviceBitMask(EVIOCGBIT(EV_LED, 0), device->ledBitmask);
    device->readDeviceBitMask(EVIOCGBIT(EV_FF, 0), device->ffBitmask);
    device->readDeviceBitMask(EVIOCGBIT(EV_MSC, 0), device->mscBitmask);
    device->readDeviceBitMask(EVIOCGPROP(0), device->propBitmask);

    // See if this is a device with keys. This could be full keyboard, or other devices like
    // gamepads, joysticks, and styluses with buttons that should generate key presses.
    bool haveKeyboardKeys =
            device->keyBitmask.any(0, BTN_MISC) || device->keyBitmask.any(BTN_WHEEL, KEY_MAX + 1);
    bool haveGamepadButtons = device->keyBitmask.any(BTN_MISC, BTN_MOUSE) ||
            device->keyBitmask.any(BTN_JOYSTICK, BTN_DIGI);
    bool haveStylusButtons = device->keyBitmask.test(BTN_STYLUS) ||
            device->keyBitmask.test(BTN_STYLUS2) || device->keyBitmask.test(BTN_STYLUS3);
    if (haveKeyboardKeys || haveGamepadButtons || haveStylusButtons) {
        device->classes |= InputDeviceClass::KEYBOARD;
    }

    // See if this is a cursor device such as a trackball or mouse.
    if (device->keyBitmask.test(BTN_MOUSE) && device->relBitmask.test(REL_X) &&
        device->relBitmask.test(REL_Y)) {
        device->classes |= InputDeviceClass::CURSOR;
    }

    // See if the device is specially configured to be of a certain type.
    if (device->configuration) {
        std::string deviceType = device->configuration->getString("device.type").value_or("");
        if (deviceType == "rotaryEncoder") {
            device->classes |= InputDeviceClass::ROTARY_ENCODER;
        } else if (deviceType == "externalStylus") {
            device->classes |= InputDeviceClass::EXTERNAL_STYLUS;
        }
    }

    // See if this is a touch pad.
    // Is this a new modern multi-touch driver?
    if (device->absBitmask.test(ABS_MT_POSITION_X) && device->absBitmask.test(ABS_MT_POSITION_Y)) {
        // Some joysticks such as the PS3 controller report axes that conflict
        // with the ABS_MT range.  Try to confirm that the device really is
        // a touch screen.
        if (device->keyBitmask.test(BTN_TOUCH) || !haveGamepadButtons) {
            device->classes |= (InputDeviceClass::TOUCH | InputDeviceClass::TOUCH_MT);
            if (device->propBitmask.test(INPUT_PROP_POINTER) &&
                !device->keyBitmask.any(BTN_TOOL_PEN, BTN_TOOL_FINGER) && !haveStylusButtons) {
                device->classes |= InputDeviceClass::TOUCHPAD;
            }
        }
        // Is this an old style single-touch driver?
    } else if (device->keyBitmask.test(BTN_TOUCH) && device->absBitmask.test(ABS_X) &&
               device->absBitmask.test(ABS_Y)) {
        device->classes |= InputDeviceClass::TOUCH;
        // Is this a stylus that reports contact/pressure independently of touch coordinates?
    } else if ((device->absBitmask.test(ABS_PRESSURE) || device->keyBitmask.test(BTN_TOUCH)) &&
               !device->absBitmask.test(ABS_X) && !device->absBitmask.test(ABS_Y)) {
        device->classes |= InputDeviceClass::EXTERNAL_STYLUS;
    }

    // See if this device is a joystick.
    // Assumes that joysticks always have gamepad buttons in order to distinguish them
    // from other devices such as accelerometers that also have absolute axes.
    if (haveGamepadButtons) {
        auto assumedClasses = device->classes | InputDeviceClass::JOYSTICK;
        for (int i = 0; i <= ABS_MAX; i++) {
            if (device->absBitmask.test(i) &&
                (getAbsAxisUsage(i, assumedClasses).test(InputDeviceClass::JOYSTICK))) {
                device->classes = assumedClasses;
                break;
            }
        }
    }

    // Check whether this device is an accelerometer.
    if (device->propBitmask.test(INPUT_PROP_ACCELEROMETER)) {
        device->classes |= InputDeviceClass::SENSOR;
    }

    // Check whether this device has switches.
    for (int i = 0; i <= SW_MAX; i++) {
        if (device->swBitmask.test(i)) {
            device->classes |= InputDeviceClass::SWITCH;
            break;
        }
    }

    // Check whether this device supports the vibrator.
    if (device->ffBitmask.test(FF_RUMBLE)) {
        device->classes |= InputDeviceClass::VIBRATOR;
    }

    // Configure virtual keys.
    if ((device->classes.test(InputDeviceClass::TOUCH))) {
        // Load the virtual keys for the touch screen, if any.
        // We do this now so that we can make sure to load the keymap if necessary.
        bool success = device->loadVirtualKeyMapLocked();
        if (success) {
            device->classes |= InputDeviceClass::KEYBOARD;
        }
    }

    // Load the key map.
    // We need to do this for joysticks too because the key layout may specify axes, and for
    // sensor as well because the key layout may specify the axes to sensor data mapping.
    status_t keyMapStatus = NAME_NOT_FOUND;
    if (device->classes.any(InputDeviceClass::KEYBOARD | InputDeviceClass::JOYSTICK |
                            InputDeviceClass::SENSOR)) {
        // Load the keymap for the device.
        keyMapStatus = device->loadKeyMapLocked();
    }

    // Configure the keyboard, gamepad or virtual keyboard.
    if (device->classes.test(InputDeviceClass::KEYBOARD)) {
        // Register the keyboard as a built-in keyboard if it is eligible.
        if (!keyMapStatus && mBuiltInKeyboardId == NO_BUILT_IN_KEYBOARD &&
            isEligibleBuiltInKeyboard(device->identifier, device->configuration.get(),
                                      &device->keyMap)) {
            mBuiltInKeyboardId = device->id;
        }

        // 'Q' key support = cheap test of whether this is an alpha-capable kbd
        if (device->hasKeycodeLocked(AKEYCODE_Q)) {
            device->classes |= InputDeviceClass::ALPHAKEY;
        }

        // See if this device has a D-pad.
        if (std::all_of(DPAD_REQUIRED_KEYCODES.begin(), DPAD_REQUIRED_KEYCODES.end(),
                        [&](int32_t keycode) { return device->hasKeycodeLocked(keycode); })) {
            device->classes |= InputDeviceClass::DPAD;
        }

        // See if this device has a gamepad.
        if (std::any_of(GAMEPAD_KEYCODES.begin(), GAMEPAD_KEYCODES.end(),
                        [&](int32_t keycode) { return device->hasKeycodeLocked(keycode); })) {
            device->classes |= InputDeviceClass::GAMEPAD;
        }

        // See if this device has any stylus buttons that we would want to fuse with touch data.
        if (!device->classes.any(InputDeviceClass::TOUCH | InputDeviceClass::TOUCH_MT) &&
            !device->classes.any(InputDeviceClass::ALPHAKEY) &&
            std::any_of(STYLUS_BUTTON_KEYCODES.begin(), STYLUS_BUTTON_KEYCODES.end(),
                        [&](int32_t keycode) { return device->hasKeycodeLocked(keycode); })) {
            device->classes |= InputDeviceClass::EXTERNAL_STYLUS;
        }
    }

    // If the device isn't recognized as something we handle, don't monitor it.
    if (device->classes == ftl::Flags<InputDeviceClass>(0)) {
        ALOGV("Dropping device: id=%d, path='%s', name='%s'", deviceId, devicePath.c_str(),
              device->identifier.name.c_str());
        return;
    }

    // Classify InputDeviceClass::BATTERY.
    if (device->associatedDevice && !device->associatedDevice->batteryInfos.empty()) {
        device->classes |= InputDeviceClass::BATTERY;
    }

    // Classify InputDeviceClass::LIGHT.
    if (device->associatedDevice && !device->associatedDevice->lightInfos.empty()) {
        device->classes |= InputDeviceClass::LIGHT;
    }

    // Determine whether the device has a mic.
    if (device->deviceHasMicLocked()) {
        device->classes |= InputDeviceClass::MIC;
    }

    // Determine whether the device is external or internal.
    if (device->isExternalDeviceLocked()) {
        device->classes |= InputDeviceClass::EXTERNAL;
    }

    if (device->classes.any(InputDeviceClass::JOYSTICK | InputDeviceClass::DPAD) &&
        device->classes.test(InputDeviceClass::GAMEPAD)) {
        device->controllerNumber = getNextControllerNumberLocked(device->identifier.name);
        device->setLedForControllerLocked();
    }

    if (registerDeviceForEpollLocked(*device) != OK) {
        return;
    }

    device->configureFd();

    ALOGI("New device: id=%d, fd=%d, path='%s', name='%s', classes=%s, "
          "configuration='%s', keyLayout='%s', keyCharacterMap='%s', builtinKeyboard=%s, ",
          deviceId, fd, devicePath.c_str(), device->identifier.name.c_str(),
          device->classes.string().c_str(), device->configurationFile.c_str(),
          device->keyMap.keyLayoutFile.c_str(), device->keyMap.keyCharacterMapFile.c_str(),
          toString(mBuiltInKeyboardId == deviceId));

    addDeviceLocked(std::move(device));
}

void EventHub::openVideoDeviceLocked(const std::string& devicePath) {
    std::unique_ptr<TouchVideoDevice> videoDevice = TouchVideoDevice::create(devicePath);
    if (!videoDevice) {
        ALOGE("Could not create touch video device for %s. Ignoring", devicePath.c_str());
        return;
    }
    // Transfer ownership of this video device to a matching input device
    for (const auto& [id, device] : mDevices) {
        if (tryAddVideoDeviceLocked(*device, videoDevice)) {
            return; // 'device' now owns 'videoDevice'
        }
    }

    // Couldn't find a matching input device, so just add it to a temporary holding queue.
    // A matching input device may appear later.
    ALOGI("Adding video device %s to list of unattached video devices",
          videoDevice->getName().c_str());
    mUnattachedVideoDevices.push_back(std::move(videoDevice));
}

bool EventHub::tryAddVideoDeviceLocked(EventHub::Device& device,
                                       std::unique_ptr<TouchVideoDevice>& videoDevice) {
    if (videoDevice->getName() != device.identifier.name) {
        return false;
    }
    device.videoDevice = std::move(videoDevice);
    if (device.enabled) {
        registerVideoDeviceForEpollLocked(*device.videoDevice);
    }
    return true;
}

bool EventHub::isDeviceEnabled(int32_t deviceId) const {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr) {
        ALOGE("Invalid device id=%" PRId32 " provided to %s", deviceId, __func__);
        return false;
    }
    return device->enabled;
}

status_t EventHub::enableDevice(int32_t deviceId) {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr) {
        ALOGE("Invalid device id=%" PRId32 " provided to %s", deviceId, __func__);
        return BAD_VALUE;
    }
    if (device->enabled) {
        ALOGW("Duplicate call to %s, input device %" PRId32 " already enabled", __func__, deviceId);
        return OK;
    }
    status_t result = device->enable();
    if (result != OK) {
        ALOGE("Failed to enable device %" PRId32, deviceId);
        return result;
    }

    device->configureFd();

    return registerDeviceForEpollLocked(*device);
}

status_t EventHub::disableDevice(int32_t deviceId) {
    std::scoped_lock _l(mLock);
    Device* device = getDeviceLocked(deviceId);
    if (device == nullptr) {
        ALOGE("Invalid device id=%" PRId32 " provided to %s", deviceId, __func__);
        return BAD_VALUE;
    }
    if (!device->enabled) {
        ALOGW("Duplicate call to %s, input device already disabled", __func__);
        return OK;
    }
    unregisterDeviceFromEpollLocked(*device);
    return device->disable();
}

// TODO(b/274755573): Shift to uevent handling on native side and remove this method
// Currently using Java UEventObserver to trigger this which uses UEvent infrastructure that uses a
// NETLINK socket to observe UEvents. We can create similar infrastructure on Eventhub side to
// directly observe UEvents instead of triggering from Java side.
void EventHub::sysfsNodeChanged(const std::string& sysfsNodePath) {
    std::scoped_lock _l(mLock);

    // Check in opening devices
    for (auto it = mOpeningDevices.begin(); it != mOpeningDevices.end(); it++) {
        std::unique_ptr<Device>& device = *it;
        if (device->associatedDevice &&
            sysfsNodePath.find(device->associatedDevice->sysfsRootPath.string()) !=
                    std::string::npos &&
            device->associatedDevice->isChanged()) {
            it = mOpeningDevices.erase(it);
            openDeviceLocked(device->path);
        }
    }

    // Check in already added device
    std::vector<Device*> devicesToReopen;
    for (const auto& [id, device] : mDevices) {
        if (device->associatedDevice &&
            sysfsNodePath.find(device->associatedDevice->sysfsRootPath.string()) !=
                    std::string::npos &&
            device->associatedDevice->isChanged()) {
            devicesToReopen.push_back(device.get());
        }
    }
    for (const auto& device : devicesToReopen) {
        closeDeviceLocked(*device);
        openDeviceLocked(device->path);
    }
    devicesToReopen.clear();
}

void EventHub::createVirtualKeyboardLocked() {
    InputDeviceIdentifier identifier;
    identifier.name = "Virtual";
    identifier.uniqueId = "<virtual>";
    assignDescriptorLocked(identifier);

    std::unique_ptr<Device> device =
            std::make_unique<Device>(-1, ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID, "<virtual>",
                                     identifier, /*associatedDevice=*/nullptr);
    device->classes = InputDeviceClass::KEYBOARD | InputDeviceClass::ALPHAKEY |
            InputDeviceClass::DPAD | InputDeviceClass::VIRTUAL;
    device->loadKeyMapLocked();
    addDeviceLocked(std::move(device));
}

void EventHub::addDeviceLocked(std::unique_ptr<Device> device) {
    reportDeviceAddedForStatisticsLocked(device->identifier, device->classes);
    mOpeningDevices.push_back(std::move(device));
}

int32_t EventHub::getNextControllerNumberLocked(const std::string& name) {
    if (mControllerNumbers.isFull()) {
        ALOGI("Maximum number of controllers reached, assigning controller number 0 to device %s",
              name.c_str());
        return 0;
    }
    // Since the controller number 0 is reserved for non-controllers, translate all numbers up by
    // one
    return static_cast<int32_t>(mControllerNumbers.markFirstUnmarkedBit() + 1);
}

void EventHub::releaseControllerNumberLocked(int32_t num) {
    if (num > 0) {
        mControllerNumbers.clearBit(static_cast<uint32_t>(num - 1));
    }
}

void EventHub::closeDeviceByPathLocked(const std::string& devicePath) {
    Device* device = getDeviceByPathLocked(devicePath);
    if (device != nullptr) {
        closeDeviceLocked(*device);
        return;
    }
    ALOGV("Remove device: %s not found, device may already have been removed.", devicePath.c_str());
}

/**
 * Find the video device by filename, and close it.
 * The video device is closed by path during an inotify event, where we don't have the
 * additional context about the video device fd, or the associated input device.
 */
void EventHub::closeVideoDeviceByPathLocked(const std::string& devicePath) {
    // A video device may be owned by an existing input device, or it may be stored in
    // the mUnattachedVideoDevices queue. Check both locations.
    for (const auto& [id, device] : mDevices) {
        if (device->videoDevice && device->videoDevice->getPath() == devicePath) {
            unregisterVideoDeviceFromEpollLocked(*device->videoDevice);
            device->videoDevice = nullptr;
            return;
        }
    }
    std::erase_if(mUnattachedVideoDevices,
                  [&devicePath](const std::unique_ptr<TouchVideoDevice>& videoDevice) {
                      return videoDevice->getPath() == devicePath;
                  });
}

void EventHub::closeAllDevicesLocked() {
    mUnattachedVideoDevices.clear();
    while (!mDevices.empty()) {
        closeDeviceLocked(*(mDevices.begin()->second));
    }
}

void EventHub::closeDeviceLocked(Device& device) {
    ALOGI("Removed device: path=%s name=%s id=%d fd=%d classes=%s", device.path.c_str(),
          device.identifier.name.c_str(), device.id, device.fd, device.classes.string().c_str());

    if (device.id == mBuiltInKeyboardId) {
        ALOGW("built-in keyboard device %s (id=%d) is closing! the apps will not like this",
              device.path.c_str(), mBuiltInKeyboardId);
        mBuiltInKeyboardId = NO_BUILT_IN_KEYBOARD;
    }

    unregisterDeviceFromEpollLocked(device);
    if (device.videoDevice) {
        // This must be done after the video device is removed from epoll
        mUnattachedVideoDevices.push_back(std::move(device.videoDevice));
    }

    releaseControllerNumberLocked(device.controllerNumber);
    device.controllerNumber = 0;
    device.close();
    mClosingDevices.push_back(std::move(mDevices[device.id]));

    mDevices.erase(device.id);
}

base::Result<void> EventHub::readNotifyLocked() {
    static constexpr auto EVENT_SIZE = static_cast<ssize_t>(sizeof(inotify_event));
    uint8_t eventBuffer[512];
    ssize_t sizeRead;

    ALOGV("EventHub::readNotify nfd: %d\n", mINotifyFd);
    do {
        sizeRead = read(mINotifyFd, eventBuffer, sizeof(eventBuffer));
    } while (sizeRead < 0 && errno == EINTR);

    if (sizeRead < EVENT_SIZE) return Errorf("could not get event, %s", strerror(errno));

    for (ssize_t eventPos = 0; sizeRead >= EVENT_SIZE;) {
        const inotify_event* event;
        event = (const inotify_event*)(eventBuffer + eventPos);
        if (event->len == 0) continue;

        handleNotifyEventLocked(*event);

        const ssize_t eventSize = EVENT_SIZE + event->len;
        sizeRead -= eventSize;
        eventPos += eventSize;
    }
    return {};
}

void EventHub::handleNotifyEventLocked(const inotify_event& event) {
    if (event.wd == mDeviceInputWd) {
        std::string filename = std::string(DEVICE_INPUT_PATH) + "/" + event.name;
        if (event.mask & IN_CREATE) {
            openDeviceLocked(filename);
        } else {
            ALOGI("Removing device '%s' due to inotify event\n", filename.c_str());
            closeDeviceByPathLocked(filename);
        }
    } else if (event.wd == mDeviceWd) {
        if (isV4lTouchNode(event.name)) {
            std::string filename = std::string(DEVICE_PATH) + "/" + event.name;
            if (event.mask & IN_CREATE) {
                openVideoDeviceLocked(filename);
            } else {
                ALOGI("Removing video device '%s' due to inotify event", filename.c_str());
                closeVideoDeviceByPathLocked(filename);
            }
        } else if (strcmp(event.name, "input") == 0 && event.mask & IN_CREATE) {
            addDeviceInputInotify();
        }
    } else {
        LOG_ALWAYS_FATAL("Unexpected inotify event, wd = %i", event.wd);
    }
}

status_t EventHub::scanDirLocked(const std::string& dirname) {
    for (const auto& entry : std::filesystem::directory_iterator(dirname)) {
        openDeviceLocked(entry.path());
    }
    return 0;
}

/**
 * Look for all dirname/v4l-touch* devices, and open them.
 */
status_t EventHub::scanVideoDirLocked(const std::string& dirname) {
    for (const auto& entry : std::filesystem::directory_iterator(dirname)) {
        if (isV4lTouchNode(entry.path())) {
            ALOGI("Found touch video device %s", entry.path().c_str());
            openVideoDeviceLocked(entry.path());
        }
    }
    return OK;
}

void EventHub::requestReopenDevices() {
    ALOGV("requestReopenDevices() called");

    std::scoped_lock _l(mLock);
    mNeedToReopenDevices = true;
}

void EventHub::dump(std::string& dump) const {
    dump += "Event Hub State:\n";

    { // acquire lock
        std::scoped_lock _l(mLock);

        dump += StringPrintf(INDENT "BuiltInKeyboardId: %d\n", mBuiltInKeyboardId);

        dump += INDENT "Devices:\n";

        for (const auto& [id, device] : mDevices) {
            if (mBuiltInKeyboardId == device->id) {
                dump += StringPrintf(INDENT2 "%d: %s (aka device 0 - built-in keyboard)\n",
                                     device->id, device->identifier.name.c_str());
            } else {
                dump += StringPrintf(INDENT2 "%d: %s\n", device->id,
                                     device->identifier.name.c_str());
            }
            dump += StringPrintf(INDENT3 "Classes: %s\n", device->classes.string().c_str());
            dump += StringPrintf(INDENT3 "Path: %s\n", device->path.c_str());
            dump += StringPrintf(INDENT3 "Enabled: %s\n", toString(device->enabled));
            dump += StringPrintf(INDENT3 "Descriptor: %s\n", device->identifier.descriptor.c_str());
            dump += StringPrintf(INDENT3 "Location: %s\n", device->identifier.location.c_str());
            dump += StringPrintf(INDENT3 "ControllerNumber: %d\n", device->controllerNumber);
            dump += StringPrintf(INDENT3 "UniqueId: %s\n", device->identifier.uniqueId.c_str());
            dump += StringPrintf(INDENT3 "Identifier: bus=0x%04x, vendor=0x%04x, "
                                         "product=0x%04x, version=0x%04x, bluetoothAddress=%s\n",
                                 device->identifier.bus, device->identifier.vendor,
                                 device->identifier.product, device->identifier.version,
                                 toString(device->identifier.bluetoothAddress).c_str());
            dump += StringPrintf(INDENT3 "KeyLayoutFile: %s\n",
                                 device->keyMap.keyLayoutFile.c_str());
            dump += StringPrintf(INDENT3 "KeyCharacterMapFile: %s\n",
                                 device->keyMap.keyCharacterMapFile.c_str());
            if (device->associatedDevice && device->associatedDevice->layoutInfo) {
                dump += StringPrintf(INDENT3 "LanguageTag: %s\n",
                                     device->associatedDevice->layoutInfo->languageTag.c_str());
                dump += StringPrintf(INDENT3 "LayoutType: %s\n",
                                     device->associatedDevice->layoutInfo->layoutType.c_str());
            }
            dump += StringPrintf(INDENT3 "ConfigurationFile: %s\n",
                                 device->configurationFile.c_str());
            dump += StringPrintf(INDENT3 "VideoDevice: %s\n",
                                 device->videoDevice ? device->videoDevice->dump().c_str()
                                                     : "<none>");
            dump += StringPrintf(INDENT3 "SysfsDevicePath: %s\n",
                                 device->associatedDevice
                                         ? device->associatedDevice->sysfsRootPath.c_str()
                                         : "<none>");
            if (device->keyBitmask.any(0, KEY_MAX + 1)) {
                const auto pressedKeys = device->keyState.dumpSetIndices(", ", [](int i) {
                    return InputEventLookup::getLinuxEvdevLabel(EV_KEY, i, 1).code;
                });
                dump += StringPrintf(INDENT3 "KeyState (pressed): %s\n", pressedKeys.c_str());
            }
            if (device->swBitmask.any(0, SW_MAX + 1)) {
                const auto pressedSwitches = device->swState.dumpSetIndices(", ", [](int i) {
                    return InputEventLookup::getLinuxEvdevLabel(EV_SW, i, 1).code;
                });
                dump += StringPrintf(INDENT3 "SwState (pressed): %s\n", pressedSwitches.c_str());
            }
            if (!device->absState.empty()) {
                std::string axisValues;
                for (const auto& [axis, state] : device->absState) {
                    if (!axisValues.empty()) {
                        axisValues += ", ";
                    }
                    axisValues += StringPrintf("%s=%d",
                                               InputEventLookup::getLinuxEvdevLabel(EV_ABS, axis, 0)
                                                       .code.c_str(),
                                               state.value);
                }
                dump += INDENT3 "AbsState: " + axisValues + "\n";
            }
        }

        dump += INDENT "Unattached video devices:\n";
        for (const std::unique_ptr<TouchVideoDevice>& videoDevice : mUnattachedVideoDevices) {
            dump += INDENT2 + videoDevice->dump() + "\n";
        }
        if (mUnattachedVideoDevices.empty()) {
            dump += INDENT2 "<none>\n";
        }
    } // release lock
}

void EventHub::monitor() const {
    // Acquire and release the lock to ensure that the event hub has not deadlocked.
    std::unique_lock<std::mutex> lock(mLock);
}

std::string EventHub::AssociatedDevice::dump() const {
    return StringPrintf("path=%s, numBatteries=%zu, numLight=%zu", sysfsRootPath.c_str(),
                        batteryInfos.size(), lightInfos.size());
}

} // namespace android
