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

#include <map>
#include <string>
#include <variant>
#include <vector>

#include "include/gestures.h"
#include "input/PropertyMap.h"

namespace android {

// Struct containing functions that wrap PropertyProvider in a C-compatible interface.
extern const GesturesPropProvider gesturePropProvider;

// Implementation of a gestures library property provider, which provides configuration parameters.
class PropertyProvider {
public:
    bool hasProperty(const std::string& name) const;
    GesturesProp& getProperty(const std::string& name);
    std::string dump() const;

    void loadPropertiesFromIdcFile(const PropertyMap& idcProperties);

    // Methods to be called by the gestures library:
    GesturesProp* createIntArrayProperty(const std::string& name, int* loc, size_t count,
                                         const int* init);
    GesturesProp* createBoolArrayProperty(const std::string& name, GesturesPropBool* loc,
                                          size_t count, const GesturesPropBool* init);
    GesturesProp* createRealArrayProperty(const std::string& name, double* loc, size_t count,
                                          const double* init);
    GesturesProp* createStringProperty(const std::string& name, const char** loc,
                                       const char* const init);

    void freeProperty(GesturesProp* prop);

private:
    std::map<std::string, GesturesProp> mProperties;
};

} // namespace android

// Represents a single gesture property.
//
// Pointers to this struct will be used by the gestures library (though it can never deference
// them). The library's API requires this to be in the top-level namespace.
struct GesturesProp {
public:
    template <typename T>
    GesturesProp(std::string name, T* dataPointer, size_t count, const T* initialValues);
    GesturesProp(std::string name, const char** dataPointer, const char* const initialValue);

    std::string dump() const;

    std::string getName() const { return mName; }

    size_t getCount() const { return mCount; }

    void registerHandlers(void* handlerData, GesturesPropGetHandler getter,
                          GesturesPropSetHandler setter);

    std::vector<int> getIntValues() const;
    std::vector<bool> getBoolValues() const;
    std::vector<double> getRealValues() const;
    std::string getStringValue() const;

    void setIntValues(const std::vector<int>& values);
    void setBoolValues(const std::vector<bool>& values);
    void setRealValues(const std::vector<double>& values);
    // Setting string values isn't supported since we don't have a use case yet and the memory
    // management adds additional complexity.

    void trySetFromIdcProperty(const android::PropertyMap& idcProperties,
                               const std::string& propertyName);

private:
    // Two type parameters are required for these methods, rather than one, due to the gestures
    // library using its own bool type.
    template <typename T, typename U>
    const std::vector<T> getValues(U* dataPointer) const;
    template <typename T, typename U>
    void setValues(T* dataPointer, const std::vector<U>& values);

    std::string mName;
    size_t mCount;
    std::variant<int*, GesturesPropBool*, const char**, double*> mDataPointer;
    void* mHandlerData = nullptr;
    GesturesPropGetHandler mGetter = nullptr;
    GesturesPropSetHandler mSetter = nullptr;
};
