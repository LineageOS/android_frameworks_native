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

#include "../Macros.h"

#include "gestures/PropertyProvider.h"

#include <algorithm>
#include <optional>
#include <utility>

#include <android-base/stringprintf.h>
#include <ftl/enum.h>
#include <input/PrintTools.h>
#include <log/log_main.h>

namespace android {

namespace {

GesturesProp* createInt(void* data, const char* name, int* loc, size_t count, const int* init) {
    return static_cast<PropertyProvider*>(data)->createIntArrayProperty(name, loc, count, init);
}

GesturesProp* createBool(void* data, const char* name, GesturesPropBool* loc, size_t count,
                         const GesturesPropBool* init) {
    return static_cast<PropertyProvider*>(data)->createBoolArrayProperty(name, loc, count, init);
}

GesturesProp* createString(void* data, const char* name, const char** loc, const char* const init) {
    return static_cast<PropertyProvider*>(data)->createStringProperty(name, loc, init);
}

GesturesProp* createReal(void* data, const char* name, double* loc, size_t count,
                         const double* init) {
    return static_cast<PropertyProvider*>(data)->createRealArrayProperty(name, loc, count, init);
}

void registerHandlers(void* data, GesturesProp* prop, void* handlerData,
                      GesturesPropGetHandler getter, GesturesPropSetHandler setter) {
    prop->registerHandlers(handlerData, getter, setter);
}

void freeProperty(void* data, GesturesProp* prop) {
    static_cast<PropertyProvider*>(data)->freeProperty(prop);
}

} // namespace

const GesturesPropProvider gesturePropProvider = {
        .create_int_fn = createInt,
        .create_bool_fn = createBool,
        .create_string_fn = createString,
        .create_real_fn = createReal,
        .register_handlers_fn = registerHandlers,
        .free_fn = freeProperty,
};

bool PropertyProvider::hasProperty(const std::string& name) const {
    return mProperties.find(name) != mProperties.end();
}

GesturesProp& PropertyProvider::getProperty(const std::string& name) {
    return mProperties.at(name);
}

std::string PropertyProvider::dump() const {
    std::string dump;
    for (const auto& [name, property] : mProperties) {
        dump += property.dump() + "\n";
    }
    return dump;
}

void PropertyProvider::loadPropertiesFromIdcFile(const PropertyMap& idcProperties) {
    // For compatibility with the configuration file syntax, gesture property names in IDC files are
    // prefixed with "gestureProp." and have spaces replaced by underscores. So, for example, the
    // configuration key "gestureProp.Palm_Width" refers to the "Palm Width" property.
    const std::string gesturePropPrefix = "gestureProp.";
    for (const std::string& key : idcProperties.getKeysWithPrefix(gesturePropPrefix)) {
        std::string propertyName = key.substr(gesturePropPrefix.length());
        for (size_t i = 0; i < propertyName.length(); i++) {
            if (propertyName[i] == '_') {
                propertyName[i] = ' ';
            }
        }

        auto it = mProperties.find(propertyName);
        if (it != mProperties.end()) {
            it->second.trySetFromIdcProperty(idcProperties, key);
        } else {
            ALOGE("Gesture property \"%s\" specified in IDC file does not exist for this device.",
                  propertyName.c_str());
        }
    }
}

GesturesProp* PropertyProvider::createIntArrayProperty(const std::string& name, int* loc,
                                                       size_t count, const int* init) {
    const auto [it, inserted] =
            mProperties.insert(std::pair{name, GesturesProp(name, loc, count, init)});
    LOG_ALWAYS_FATAL_IF(!inserted, "Gesture property \"%s\" already exists.", name.c_str());
    return &it->second;
}

GesturesProp* PropertyProvider::createBoolArrayProperty(const std::string& name,
                                                        GesturesPropBool* loc, size_t count,
                                                        const GesturesPropBool* init) {
    const auto [it, inserted] =
            mProperties.insert(std::pair{name, GesturesProp(name, loc, count, init)});
    LOG_ALWAYS_FATAL_IF(!inserted, "Gesture property \"%s\" already exists.", name.c_str());
    return &it->second;
}

GesturesProp* PropertyProvider::createRealArrayProperty(const std::string& name, double* loc,
                                                        size_t count, const double* init) {
    const auto [it, inserted] =
            mProperties.insert(std::pair{name, GesturesProp(name, loc, count, init)});
    LOG_ALWAYS_FATAL_IF(!inserted, "Gesture property \"%s\" already exists.", name.c_str());
    return &it->second;
}

GesturesProp* PropertyProvider::createStringProperty(const std::string& name, const char** loc,
                                                     const char* const init) {
    const auto [it, inserted] = mProperties.insert(std::pair{name, GesturesProp(name, loc, init)});
    LOG_ALWAYS_FATAL_IF(!inserted, "Gesture property \"%s\" already exists.", name.c_str());
    return &it->second;
}

void PropertyProvider::freeProperty(GesturesProp* prop) {
    mProperties.erase(prop->getName());
}

} // namespace android

template <typename T>
GesturesProp::GesturesProp(std::string name, T* dataPointer, size_t count, const T* initialValues)
      : mName(name), mCount(count), mDataPointer(dataPointer) {
    std::copy_n(initialValues, count, dataPointer);
}

GesturesProp::GesturesProp(std::string name, const char** dataPointer,
                           const char* const initialValue)
      : mName(name), mCount(1), mDataPointer(dataPointer) {
    *(std::get<const char**>(mDataPointer)) = initialValue;
}

std::string GesturesProp::dump() const {
    using android::base::StringPrintf;
    std::string type, values;
    switch (mDataPointer.index()) {
        case 0:
            type = "integer";
            values = android::dumpVector(getIntValues());
            break;
        case 1:
            type = "boolean";
            values = android::dumpVector(getBoolValues());
            break;
        case 2:
            type = "string";
            values = getStringValue();
            break;
        case 3:
            type = "real";
            values = android::dumpVector(getRealValues());
            break;
    }
    std::string typeAndSize = mCount == 1 ? type : std::to_string(mCount) + " " + type + "s";
    return StringPrintf("%s (%s): %s", mName.c_str(), typeAndSize.c_str(), values.c_str());
}

void GesturesProp::registerHandlers(void* handlerData, GesturesPropGetHandler getter,
                                    GesturesPropSetHandler setter) {
    mHandlerData = handlerData;
    mGetter = getter;
    mSetter = setter;
}

std::vector<int> GesturesProp::getIntValues() const {
    LOG_ALWAYS_FATAL_IF(!std::holds_alternative<int*>(mDataPointer),
                        "Attempt to read ints from \"%s\" gesture property.", mName.c_str());
    return getValues<int, int>(std::get<int*>(mDataPointer));
}

std::vector<bool> GesturesProp::getBoolValues() const {
    LOG_ALWAYS_FATAL_IF(!std::holds_alternative<GesturesPropBool*>(mDataPointer),
                        "Attempt to read bools from \"%s\" gesture property.", mName.c_str());
    return getValues<bool, GesturesPropBool>(std::get<GesturesPropBool*>(mDataPointer));
}

std::vector<double> GesturesProp::getRealValues() const {
    LOG_ALWAYS_FATAL_IF(!std::holds_alternative<double*>(mDataPointer),
                        "Attempt to read reals from \"%s\" gesture property.", mName.c_str());
    return getValues<double, double>(std::get<double*>(mDataPointer));
}

std::string GesturesProp::getStringValue() const {
    LOG_ALWAYS_FATAL_IF(!std::holds_alternative<const char**>(mDataPointer),
                        "Attempt to read a string from \"%s\" gesture property.", mName.c_str());
    if (mGetter != nullptr) {
        mGetter(mHandlerData);
    }
    return std::string(*std::get<const char**>(mDataPointer));
}

void GesturesProp::setBoolValues(const std::vector<bool>& values) {
    LOG_ALWAYS_FATAL_IF(!std::holds_alternative<GesturesPropBool*>(mDataPointer),
                        "Attempt to write bools to \"%s\" gesture property.", mName.c_str());
    setValues(std::get<GesturesPropBool*>(mDataPointer), values);
}

void GesturesProp::setIntValues(const std::vector<int>& values) {
    LOG_ALWAYS_FATAL_IF(!std::holds_alternative<int*>(mDataPointer),
                        "Attempt to write ints to \"%s\" gesture property.", mName.c_str());
    setValues(std::get<int*>(mDataPointer), values);
}

void GesturesProp::setRealValues(const std::vector<double>& values) {
    LOG_ALWAYS_FATAL_IF(!std::holds_alternative<double*>(mDataPointer),
                        "Attempt to write reals to \"%s\" gesture property.", mName.c_str());
    setValues(std::get<double*>(mDataPointer), values);
}

namespace {

// Helper to std::visit with lambdas.
template <typename... V>
struct Visitor : V... { using V::operator()...; };
// explicit deduction guide (not needed as of C++20)
template <typename... V>
Visitor(V...) -> Visitor<V...>;

} // namespace

void GesturesProp::trySetFromIdcProperty(const android::PropertyMap& idcProperties,
                                         const std::string& propertyName) {
    if (mCount != 1) {
        ALOGE("Gesture property \"%s\" is an array, and so cannot be set in an IDC file.",
              mName.c_str());
        return;
    }
    bool parsedSuccessfully = false;
    Visitor setVisitor{
            [&](int*) {
                if (std::optional<int32_t> value = idcProperties.getInt(propertyName); value) {
                    parsedSuccessfully = true;
                    setIntValues({*value});
                }
            },
            [&](GesturesPropBool*) {
                if (std::optional<bool> value = idcProperties.getBool(propertyName); value) {
                    parsedSuccessfully = true;
                    setBoolValues({*value});
                }
            },
            [&](double*) {
                if (std::optional<double> value = idcProperties.getDouble(propertyName); value) {
                    parsedSuccessfully = true;
                    setRealValues({*value});
                }
            },
            [&](const char**) {
                ALOGE("Gesture property \"%s\" is a string, and so cannot be set in an IDC file.",
                      mName.c_str());
                // We've already reported the type mismatch, so set parsedSuccessfully.
                parsedSuccessfully = true;
            },
    };
    std::visit(setVisitor, mDataPointer);

    ALOGE_IF(!parsedSuccessfully, "Gesture property \"%s\" couldn't be set due to a type mismatch.",
             mName.c_str());
}

template <typename T, typename U>
const std::vector<T> GesturesProp::getValues(U* dataPointer) const {
    if (mGetter != nullptr) {
        mGetter(mHandlerData);
    }
    std::vector<T> values;
    values.reserve(mCount);
    for (size_t i = 0; i < mCount; i++) {
        values.push_back(dataPointer[i]);
    }
    return values;
}

template <typename T, typename U>
void GesturesProp::setValues(T* dataPointer, const std::vector<U>& values) {
    LOG_ALWAYS_FATAL_IF(values.size() != mCount,
                        "Attempt to write %zu values to \"%s\" gesture property, which holds %zu.",
                        values.size(), mName.c_str(), mCount);
    std::copy(values.begin(), values.end(), dataPointer);
    if (mSetter != nullptr) {
        mSetter(mHandlerData);
    }
}
