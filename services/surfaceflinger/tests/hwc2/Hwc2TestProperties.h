/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _HWC2_TEST_PROPERTIES_H
#define _HWC2_TEST_PROPERTIES_H

#include <array>
#include <vector>

#define HWC2_INCLUDE_STRINGIFICATION
#define HWC2_USE_CPP11
#include <hardware/hwcomposer2.h>
#undef HWC2_INCLUDE_STRINGIFICATION
#undef HWC2_USE_CPP11

enum class Hwc2TestCoverage {
    Default = 0,
    Basic,
    Complete,
};


class Hwc2TestContainer {
public:
    virtual ~Hwc2TestContainer() = default;

    /* Resets the container */
    virtual void reset() = 0;

    /* Attempts to advance to the next valid value. Returns true if one can be
     * found */
    virtual bool advance() = 0;

    virtual std::string dump() const = 0;
};


template <class T>
class Hwc2TestProperty : public Hwc2TestContainer {
public:
    Hwc2TestProperty(Hwc2TestCoverage coverage,
            const std::vector<T>& completeList, const std::vector<T>& basicList,
            const std::vector<T>& defaultList)
        : Hwc2TestProperty((coverage == Hwc2TestCoverage::Complete)? completeList:
                (coverage == Hwc2TestCoverage::Basic)? basicList : defaultList) { }

    Hwc2TestProperty(const std::vector<T>& list)
        : mList(list) { }

    void reset() override
    {
        mListIdx = 0;
    }

    bool advance() override
    {
        if (mListIdx + 1 < mList.size()) {
            mListIdx++;
            return true;
        }
        reset();
        return false;
    }

    T get() const
    {
        return mList.at(mListIdx);
    }

protected:
    const std::vector<T>& mList;
    size_t mListIdx = 0;
};


class Hwc2TestBlendMode : public Hwc2TestProperty<hwc2_blend_mode_t> {
public:
    Hwc2TestBlendMode(Hwc2TestCoverage coverage);

    std::string dump() const override;

protected:
    static const std::vector<hwc2_blend_mode_t> mDefaultBlendModes;
    static const std::vector<hwc2_blend_mode_t> mBasicBlendModes;
    static const std::vector<hwc2_blend_mode_t> mCompleteBlendModes;
};


class Hwc2TestComposition : public Hwc2TestProperty<hwc2_composition_t> {
public:
    Hwc2TestComposition(Hwc2TestCoverage coverage);

    std::string dump() const override;

protected:
    static const std::vector<hwc2_composition_t> mDefaultCompositions;
    static const std::vector<hwc2_composition_t> mBasicCompositions;
    static const std::vector<hwc2_composition_t> mCompleteCompositions;
};


class Hwc2TestDataspace : public Hwc2TestProperty<android_dataspace_t> {
public:
    Hwc2TestDataspace(Hwc2TestCoverage coverage);

    std::string dump() const override;

protected:
    static const std::vector<android_dataspace_t> defaultDataspaces;
    static const std::vector<android_dataspace_t> basicDataspaces;
    static const std::vector<android_dataspace_t> completeDataspaces;
};

#endif /* ifndef _HWC2_TEST_PROPERTIES_H */
