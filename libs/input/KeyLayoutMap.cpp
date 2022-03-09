/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define LOG_TAG "KeyLayoutMap"

#include <stdlib.h>

#include <android/keycodes.h>
#include <ftl/NamedEnum.h>
#include <input/InputEventLabels.h>
#include <input/KeyLayoutMap.h>
#include <input/Keyboard.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/Timers.h>
#include <utils/Tokenizer.h>

// Enables debug output for the parser.
#define DEBUG_PARSER 0

// Enables debug output for parser performance.
#define DEBUG_PARSER_PERFORMANCE 0

// Enables debug output for mapping.
#define DEBUG_MAPPING 0


namespace android {

static const char* WHITESPACE = " \t\r";

#define SENSOR_ENTRY(type) NamedEnum::string(type), type
static const std::unordered_map<std::string, InputDeviceSensorType> SENSOR_LIST =
        {{SENSOR_ENTRY(InputDeviceSensorType::ACCELEROMETER)},
         {SENSOR_ENTRY(InputDeviceSensorType::MAGNETIC_FIELD)},
         {SENSOR_ENTRY(InputDeviceSensorType::ORIENTATION)},
         {SENSOR_ENTRY(InputDeviceSensorType::GYROSCOPE)},
         {SENSOR_ENTRY(InputDeviceSensorType::LIGHT)},
         {SENSOR_ENTRY(InputDeviceSensorType::PRESSURE)},
         {SENSOR_ENTRY(InputDeviceSensorType::TEMPERATURE)},
         {SENSOR_ENTRY(InputDeviceSensorType::PROXIMITY)},
         {SENSOR_ENTRY(InputDeviceSensorType::GRAVITY)},
         {SENSOR_ENTRY(InputDeviceSensorType::LINEAR_ACCELERATION)},
         {SENSOR_ENTRY(InputDeviceSensorType::ROTATION_VECTOR)},
         {SENSOR_ENTRY(InputDeviceSensorType::RELATIVE_HUMIDITY)},
         {SENSOR_ENTRY(InputDeviceSensorType::AMBIENT_TEMPERATURE)},
         {SENSOR_ENTRY(InputDeviceSensorType::MAGNETIC_FIELD_UNCALIBRATED)},
         {SENSOR_ENTRY(InputDeviceSensorType::GAME_ROTATION_VECTOR)},
         {SENSOR_ENTRY(InputDeviceSensorType::GYROSCOPE_UNCALIBRATED)},
         {SENSOR_ENTRY(InputDeviceSensorType::SIGNIFICANT_MOTION)}};

// --- KeyLayoutMap ---

KeyLayoutMap::KeyLayoutMap() {
}

KeyLayoutMap::~KeyLayoutMap() {
}

base::Result<std::shared_ptr<KeyLayoutMap>> KeyLayoutMap::loadContents(const std::string& filename,
                                                                       const char* contents) {
    Tokenizer* tokenizer;
    status_t status = Tokenizer::fromContents(String8(filename.c_str()), contents, &tokenizer);
    if (status) {
        ALOGE("Error %d opening key layout map.", status);
        return Errorf("Error {} opening key layout map file {}.", status, filename.c_str());
    }
    std::unique_ptr<Tokenizer> t(tokenizer);
    auto ret = load(t.get());
    if (ret.ok()) {
        (*ret)->mLoadFileName = filename;
    }
    return ret;
}

base::Result<std::shared_ptr<KeyLayoutMap>> KeyLayoutMap::load(const std::string& filename) {
    Tokenizer* tokenizer;
    status_t status = Tokenizer::open(String8(filename.c_str()), &tokenizer);
    if (status) {
        ALOGE("Error %d opening key layout map file %s.", status, filename.c_str());
        return Errorf("Error {} opening key layout map file {}.", status, filename.c_str());
    }
    std::unique_ptr<Tokenizer> t(tokenizer);
    auto ret = load(t.get());
    if (ret.ok()) {
        (*ret)->mLoadFileName = filename;
    }
    return ret;
}

base::Result<std::shared_ptr<KeyLayoutMap>> KeyLayoutMap::load(Tokenizer* tokenizer) {
    std::shared_ptr<KeyLayoutMap> map = std::shared_ptr<KeyLayoutMap>(new KeyLayoutMap());
    status_t status = OK;
    if (!map.get()) {
        ALOGE("Error allocating key layout map.");
        return Errorf("Error allocating key layout map.");
    } else {
#if DEBUG_PARSER_PERFORMANCE
        nsecs_t startTime = systemTime(SYSTEM_TIME_MONOTONIC);
#endif
        Parser parser(map.get(), tokenizer);
        status = parser.parse();
#if DEBUG_PARSER_PERFORMANCE
        nsecs_t elapsedTime = systemTime(SYSTEM_TIME_MONOTONIC) - startTime;
        ALOGD("Parsed key layout map file '%s' %d lines in %0.3fms.",
              tokenizer->getFilename().string(), tokenizer->getLineNumber(),
              elapsedTime / 1000000.0);
#endif
        if (!status) {
            return std::move(map);
        }
    }
    return Errorf("Load KeyLayoutMap failed {}.", status);
}

status_t KeyLayoutMap::mapKey(int32_t scanCode, int32_t usageCode,
        int32_t* outKeyCode, uint32_t* outFlags) const {
    const Key* key = getKey(scanCode, usageCode);
    if (!key) {
#if DEBUG_MAPPING
        ALOGD("mapKey: scanCode=%d, usageCode=0x%08x ~ Failed.", scanCode, usageCode);
#endif
        *outKeyCode = AKEYCODE_UNKNOWN;
        *outFlags = 0;
        return NAME_NOT_FOUND;
    }

    *outKeyCode = key->keyCode;
    *outFlags = key->flags;

#if DEBUG_MAPPING
    ALOGD("mapKey: scanCode=%d, usageCode=0x%08x ~ Result keyCode=%d, outFlags=0x%08x.",
            scanCode, usageCode, *outKeyCode, *outFlags);
#endif
    return NO_ERROR;
}

// Return pair of sensor type and sensor data index, for the input device abs code
base::Result<std::pair<InputDeviceSensorType, int32_t>> KeyLayoutMap::mapSensor(int32_t absCode) {
    auto it = mSensorsByAbsCode.find(absCode);
    if (it == mSensorsByAbsCode.end()) {
#if DEBUG_MAPPING
        ALOGD("mapSensor: absCode=%d, ~ Failed.", absCode);
#endif
        return Errorf("Can't find abs code {}.", absCode);
    }
    const Sensor& sensor = it->second;

#if DEBUG_MAPPING
    ALOGD("mapSensor: absCode=%d, sensorType=0x%0x, sensorDataIndex=0x%x.", absCode,
          NamedEnum::string(sensor.sensorType), sensor.sensorDataIndex);
#endif
    return std::make_pair(sensor.sensorType, sensor.sensorDataIndex);
}

const KeyLayoutMap::Key* KeyLayoutMap::getKey(int32_t scanCode, int32_t usageCode) const {
    if (usageCode) {
        ssize_t index = mKeysByUsageCode.indexOfKey(usageCode);
        if (index >= 0) {
            return &mKeysByUsageCode.valueAt(index);
        }
    }
    if (scanCode) {
        ssize_t index = mKeysByScanCode.indexOfKey(scanCode);
        if (index >= 0) {
            return &mKeysByScanCode.valueAt(index);
        }
    }
    return nullptr;
}

status_t KeyLayoutMap::findScanCodesForKey(
        int32_t keyCode, std::vector<int32_t>* outScanCodes) const {
    const size_t N = mKeysByScanCode.size();
    for (size_t i=0; i<N; i++) {
        if (mKeysByScanCode.valueAt(i).keyCode == keyCode) {
            outScanCodes->push_back(mKeysByScanCode.keyAt(i));
        }
    }
    return NO_ERROR;
}

status_t KeyLayoutMap::mapAxis(int32_t scanCode, AxisInfo* outAxisInfo) const {
    ssize_t index = mAxes.indexOfKey(scanCode);
    if (index < 0) {
#if DEBUG_MAPPING
        ALOGD("mapAxis: scanCode=%d ~ Failed.", scanCode);
#endif
        return NAME_NOT_FOUND;
    }

    *outAxisInfo = mAxes.valueAt(index);

#if DEBUG_MAPPING
    ALOGD("mapAxis: scanCode=%d ~ Result mode=%d, axis=%d, highAxis=%d, "
            "splitValue=%d, flatOverride=%d.",
            scanCode,
            outAxisInfo->mode, outAxisInfo->axis, outAxisInfo->highAxis,
            outAxisInfo->splitValue, outAxisInfo->flatOverride);
#endif
    return NO_ERROR;
}

status_t KeyLayoutMap::findScanCodeForLed(int32_t ledCode, int32_t* outScanCode) const {
    const size_t N = mLedsByScanCode.size();
    for (size_t i = 0; i < N; i++) {
        if (mLedsByScanCode.valueAt(i).ledCode == ledCode) {
            *outScanCode = mLedsByScanCode.keyAt(i);
#if DEBUG_MAPPING
            ALOGD("findScanCodeForLed: ledCode=%d, scanCode=%d.", ledCode, *outScanCode);
#endif
            return NO_ERROR;
        }
    }
#if DEBUG_MAPPING
            ALOGD("findScanCodeForLed: ledCode=%d ~ Not found.", ledCode);
#endif
    return NAME_NOT_FOUND;
}

status_t KeyLayoutMap::findUsageCodeForLed(int32_t ledCode, int32_t* outUsageCode) const {
    const size_t N = mLedsByUsageCode.size();
    for (size_t i = 0; i < N; i++) {
        if (mLedsByUsageCode.valueAt(i).ledCode == ledCode) {
            *outUsageCode = mLedsByUsageCode.keyAt(i);
#if DEBUG_MAPPING
            ALOGD("findUsageForLed: ledCode=%d, usage=%x.", ledCode, *outUsageCode);
#endif
            return NO_ERROR;
        }
    }
#if DEBUG_MAPPING
            ALOGD("findUsageForLed: ledCode=%d ~ Not found.", ledCode);
#endif
    return NAME_NOT_FOUND;
}


// --- KeyLayoutMap::Parser ---

KeyLayoutMap::Parser::Parser(KeyLayoutMap* map, Tokenizer* tokenizer) :
        mMap(map), mTokenizer(tokenizer) {
}

KeyLayoutMap::Parser::~Parser() {
}

status_t KeyLayoutMap::Parser::parse() {
    while (!mTokenizer->isEof()) {
#if DEBUG_PARSER
        ALOGD("Parsing %s: '%s'.", mTokenizer->getLocation().string(),
                mTokenizer->peekRemainderOfLine().string());
#endif

        mTokenizer->skipDelimiters(WHITESPACE);

        if (!mTokenizer->isEol() && mTokenizer->peekChar() != '#') {
            String8 keywordToken = mTokenizer->nextToken(WHITESPACE);
            if (keywordToken == "key") {
                mTokenizer->skipDelimiters(WHITESPACE);
                status_t status = parseKey();
                if (status) return status;
            } else if (keywordToken == "axis") {
                mTokenizer->skipDelimiters(WHITESPACE);
                status_t status = parseAxis();
                if (status) return status;
            } else if (keywordToken == "led") {
                mTokenizer->skipDelimiters(WHITESPACE);
                status_t status = parseLed();
                if (status) return status;
            } else if (keywordToken == "sensor") {
                mTokenizer->skipDelimiters(WHITESPACE);
                status_t status = parseSensor();
                if (status) return status;
            } else {
                ALOGE("%s: Expected keyword, got '%s'.", mTokenizer->getLocation().string(),
                        keywordToken.string());
                return BAD_VALUE;
            }

            mTokenizer->skipDelimiters(WHITESPACE);
            if (!mTokenizer->isEol() && mTokenizer->peekChar() != '#') {
                ALOGE("%s: Expected end of line or trailing comment, got '%s'.",
                        mTokenizer->getLocation().string(),
                        mTokenizer->peekRemainderOfLine().string());
                return BAD_VALUE;
            }
        }

        mTokenizer->nextLine();
    }
    return NO_ERROR;
}

status_t KeyLayoutMap::Parser::parseKey() {
    String8 codeToken = mTokenizer->nextToken(WHITESPACE);
    bool mapUsage = false;
    if (codeToken == "usage") {
        mapUsage = true;
        mTokenizer->skipDelimiters(WHITESPACE);
        codeToken = mTokenizer->nextToken(WHITESPACE);
    }

    char* end;
    int32_t code = int32_t(strtol(codeToken.string(), &end, 0));
    if (*end) {
        ALOGE("%s: Expected key %s number, got '%s'.", mTokenizer->getLocation().string(),
                mapUsage ? "usage" : "scan code", codeToken.string());
        return BAD_VALUE;
    }
    KeyedVector<int32_t, Key>& map = mapUsage ? mMap->mKeysByUsageCode : mMap->mKeysByScanCode;
    if (map.indexOfKey(code) >= 0) {
        ALOGE("%s: Duplicate entry for key %s '%s'.", mTokenizer->getLocation().string(),
                mapUsage ? "usage" : "scan code", codeToken.string());
        return BAD_VALUE;
    }

    mTokenizer->skipDelimiters(WHITESPACE);
    String8 keyCodeToken = mTokenizer->nextToken(WHITESPACE);
    int32_t keyCode = InputEventLookup::getKeyCodeByLabel(keyCodeToken.string());
    if (!keyCode) {
        ALOGE("%s: Expected key code label, got '%s'.", mTokenizer->getLocation().string(),
                keyCodeToken.string());
        return BAD_VALUE;
    }

    uint32_t flags = 0;
    for (;;) {
        mTokenizer->skipDelimiters(WHITESPACE);
        if (mTokenizer->isEol() || mTokenizer->peekChar() == '#') break;

        String8 flagToken = mTokenizer->nextToken(WHITESPACE);
        uint32_t flag = InputEventLookup::getKeyFlagByLabel(flagToken.string());
        if (!flag) {
            ALOGE("%s: Expected key flag label, got '%s'.", mTokenizer->getLocation().string(),
                    flagToken.string());
            return BAD_VALUE;
        }
        if (flags & flag) {
            ALOGE("%s: Duplicate key flag '%s'.", mTokenizer->getLocation().string(),
                    flagToken.string());
            return BAD_VALUE;
        }
        flags |= flag;
    }

#if DEBUG_PARSER
    ALOGD("Parsed key %s: code=%d, keyCode=%d, flags=0x%08x.",
            mapUsage ? "usage" : "scan code", code, keyCode, flags);
#endif
    Key key;
    key.keyCode = keyCode;
    key.flags = flags;
    map.add(code, key);
    return NO_ERROR;
}

status_t KeyLayoutMap::Parser::parseAxis() {
    String8 scanCodeToken = mTokenizer->nextToken(WHITESPACE);
    char* end;
    int32_t scanCode = int32_t(strtol(scanCodeToken.string(), &end, 0));
    if (*end) {
        ALOGE("%s: Expected axis scan code number, got '%s'.", mTokenizer->getLocation().string(),
                scanCodeToken.string());
        return BAD_VALUE;
    }
    if (mMap->mAxes.indexOfKey(scanCode) >= 0) {
        ALOGE("%s: Duplicate entry for axis scan code '%s'.", mTokenizer->getLocation().string(),
                scanCodeToken.string());
        return BAD_VALUE;
    }

    AxisInfo axisInfo;

    mTokenizer->skipDelimiters(WHITESPACE);
    String8 token = mTokenizer->nextToken(WHITESPACE);
    if (token == "invert") {
        axisInfo.mode = AxisInfo::MODE_INVERT;

        mTokenizer->skipDelimiters(WHITESPACE);
        String8 axisToken = mTokenizer->nextToken(WHITESPACE);
        axisInfo.axis = InputEventLookup::getAxisByLabel(axisToken.string());
        if (axisInfo.axis < 0) {
            ALOGE("%s: Expected inverted axis label, got '%s'.",
                    mTokenizer->getLocation().string(), axisToken.string());
            return BAD_VALUE;
        }
    } else if (token == "split") {
        axisInfo.mode = AxisInfo::MODE_SPLIT;

        mTokenizer->skipDelimiters(WHITESPACE);
        String8 splitToken = mTokenizer->nextToken(WHITESPACE);
        axisInfo.splitValue = int32_t(strtol(splitToken.string(), &end, 0));
        if (*end) {
            ALOGE("%s: Expected split value, got '%s'.",
                    mTokenizer->getLocation().string(), splitToken.string());
            return BAD_VALUE;
        }

        mTokenizer->skipDelimiters(WHITESPACE);
        String8 lowAxisToken = mTokenizer->nextToken(WHITESPACE);
        axisInfo.axis = InputEventLookup::getAxisByLabel(lowAxisToken.string());
        if (axisInfo.axis < 0) {
            ALOGE("%s: Expected low axis label, got '%s'.",
                    mTokenizer->getLocation().string(), lowAxisToken.string());
            return BAD_VALUE;
        }

        mTokenizer->skipDelimiters(WHITESPACE);
        String8 highAxisToken = mTokenizer->nextToken(WHITESPACE);
        axisInfo.highAxis = InputEventLookup::getAxisByLabel(highAxisToken.string());
        if (axisInfo.highAxis < 0) {
            ALOGE("%s: Expected high axis label, got '%s'.",
                    mTokenizer->getLocation().string(), highAxisToken.string());
            return BAD_VALUE;
        }
    } else {
        axisInfo.axis = InputEventLookup::getAxisByLabel(token.string());
        if (axisInfo.axis < 0) {
            ALOGE("%s: Expected axis label, 'split' or 'invert', got '%s'.",
                    mTokenizer->getLocation().string(), token.string());
            return BAD_VALUE;
        }
    }

    for (;;) {
        mTokenizer->skipDelimiters(WHITESPACE);
        if (mTokenizer->isEol() || mTokenizer->peekChar() == '#') {
            break;
        }
        String8 keywordToken = mTokenizer->nextToken(WHITESPACE);
        if (keywordToken == "flat") {
            mTokenizer->skipDelimiters(WHITESPACE);
            String8 flatToken = mTokenizer->nextToken(WHITESPACE);
            axisInfo.flatOverride = int32_t(strtol(flatToken.string(), &end, 0));
            if (*end) {
                ALOGE("%s: Expected flat value, got '%s'.",
                        mTokenizer->getLocation().string(), flatToken.string());
                return BAD_VALUE;
            }
        } else {
            ALOGE("%s: Expected keyword 'flat', got '%s'.",
                    mTokenizer->getLocation().string(), keywordToken.string());
            return BAD_VALUE;
        }
    }

#if DEBUG_PARSER
    ALOGD("Parsed axis: scanCode=%d, mode=%d, axis=%d, highAxis=%d, "
            "splitValue=%d, flatOverride=%d.",
            scanCode,
            axisInfo.mode, axisInfo.axis, axisInfo.highAxis,
            axisInfo.splitValue, axisInfo.flatOverride);
#endif
    mMap->mAxes.add(scanCode, axisInfo);
    return NO_ERROR;
}

status_t KeyLayoutMap::Parser::parseLed() {
    String8 codeToken = mTokenizer->nextToken(WHITESPACE);
    bool mapUsage = false;
    if (codeToken == "usage") {
        mapUsage = true;
        mTokenizer->skipDelimiters(WHITESPACE);
        codeToken = mTokenizer->nextToken(WHITESPACE);
    }
    char* end;
    int32_t code = int32_t(strtol(codeToken.string(), &end, 0));
    if (*end) {
        ALOGE("%s: Expected led %s number, got '%s'.", mTokenizer->getLocation().string(),
                mapUsage ? "usage" : "scan code", codeToken.string());
        return BAD_VALUE;
    }

    KeyedVector<int32_t, Led>& map = mapUsage ? mMap->mLedsByUsageCode : mMap->mLedsByScanCode;
    if (map.indexOfKey(code) >= 0) {
        ALOGE("%s: Duplicate entry for led %s '%s'.", mTokenizer->getLocation().string(),
                mapUsage ? "usage" : "scan code", codeToken.string());
        return BAD_VALUE;
    }

    mTokenizer->skipDelimiters(WHITESPACE);
    String8 ledCodeToken = mTokenizer->nextToken(WHITESPACE);
    int32_t ledCode = InputEventLookup::getLedByLabel(ledCodeToken.string());
    if (ledCode < 0) {
        ALOGE("%s: Expected LED code label, got '%s'.", mTokenizer->getLocation().string(),
                ledCodeToken.string());
        return BAD_VALUE;
    }

#if DEBUG_PARSER
    ALOGD("Parsed led %s: code=%d, ledCode=%d.",
            mapUsage ? "usage" : "scan code", code, ledCode);
#endif

    Led led;
    led.ledCode = ledCode;
    map.add(code, led);
    return NO_ERROR;
}

static std::optional<InputDeviceSensorType> getSensorType(const char* token) {
    auto it = SENSOR_LIST.find(std::string(token));
    if (it == SENSOR_LIST.end()) {
        return std::nullopt;
    }
    return it->second;
}

static std::optional<int32_t> getSensorDataIndex(String8 token) {
    std::string tokenStr(token.string());
    if (tokenStr == "X") {
        return 0;
    } else if (tokenStr == "Y") {
        return 1;
    } else if (tokenStr == "Z") {
        return 2;
    }
    return std::nullopt;
}

// Parse sensor type and data index mapping, as below format
// sensor <raw abs> <sensor type> <sensor data index>
// raw abs : the linux abs code of the axis
// sensor type : string name of InputDeviceSensorType
// sensor data index : the data index of sensor, out of [X, Y, Z]
// Examples:
// sensor 0x00 ACCELEROMETER X
// sensor 0x01 ACCELEROMETER Y
// sensor 0x02 ACCELEROMETER Z
// sensor 0x03 GYROSCOPE X
// sensor 0x04 GYROSCOPE Y
// sensor 0x05 GYROSCOPE Z
status_t KeyLayoutMap::Parser::parseSensor() {
    String8 codeToken = mTokenizer->nextToken(WHITESPACE);
    char* end;
    int32_t code = int32_t(strtol(codeToken.string(), &end, 0));
    if (*end) {
        ALOGE("%s: Expected sensor %s number, got '%s'.", mTokenizer->getLocation().string(),
              "abs code", codeToken.string());
        return BAD_VALUE;
    }

    std::unordered_map<int32_t, Sensor>& map = mMap->mSensorsByAbsCode;
    if (map.find(code) != map.end()) {
        ALOGE("%s: Duplicate entry for sensor %s '%s'.", mTokenizer->getLocation().string(),
              "abs code", codeToken.string());
        return BAD_VALUE;
    }

    mTokenizer->skipDelimiters(WHITESPACE);
    String8 sensorTypeToken = mTokenizer->nextToken(WHITESPACE);
    std::optional<InputDeviceSensorType> typeOpt = getSensorType(sensorTypeToken.string());
    if (!typeOpt) {
        ALOGE("%s: Expected sensor code label, got '%s'.", mTokenizer->getLocation().string(),
              sensorTypeToken.string());
        return BAD_VALUE;
    }
    InputDeviceSensorType sensorType = typeOpt.value();
    mTokenizer->skipDelimiters(WHITESPACE);
    String8 sensorDataIndexToken = mTokenizer->nextToken(WHITESPACE);
    std::optional<int32_t> indexOpt = getSensorDataIndex(sensorDataIndexToken);
    if (!indexOpt) {
        ALOGE("%s: Expected sensor data index label, got '%s'.", mTokenizer->getLocation().string(),
              sensorDataIndexToken.string());
        return BAD_VALUE;
    }
    int32_t sensorDataIndex = indexOpt.value();

#if DEBUG_PARSER
    ALOGD("Parsed sensor: abs code=%d, sensorType=%d, sensorDataIndex=%d.", code,
          NamedEnum::string(sensorType).c_str(), sensorDataIndex);
#endif

    Sensor sensor;
    sensor.sensorType = sensorType;
    sensor.sensorDataIndex = sensorDataIndex;
    map.emplace(code, sensor);
    return NO_ERROR;
}
};
