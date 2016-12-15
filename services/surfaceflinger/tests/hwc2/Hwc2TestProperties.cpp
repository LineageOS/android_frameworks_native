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

#include <sstream>

#include "Hwc2TestProperties.h"

Hwc2TestBlendMode::Hwc2TestBlendMode(Hwc2TestCoverage coverage)
    : Hwc2TestProperty(coverage, mCompleteBlendModes, mBasicBlendModes,
            mDefaultBlendModes) { }

std::string Hwc2TestBlendMode::dump() const
{
    std::stringstream dmp;
    dmp << "\tblend mode: " << getBlendModeName(get()) << "\n";
    return dmp.str();
}

const std::vector<hwc2_blend_mode_t> Hwc2TestBlendMode::mDefaultBlendModes = {
    HWC2_BLEND_MODE_NONE,
};

const std::vector<hwc2_blend_mode_t> Hwc2TestBlendMode::mBasicBlendModes = {
    HWC2_BLEND_MODE_NONE,
    HWC2_BLEND_MODE_PREMULTIPLIED,
};

const std::vector<hwc2_blend_mode_t> Hwc2TestBlendMode::mCompleteBlendModes = {
    HWC2_BLEND_MODE_NONE,
    HWC2_BLEND_MODE_PREMULTIPLIED,
    HWC2_BLEND_MODE_COVERAGE,
};


Hwc2TestComposition::Hwc2TestComposition(Hwc2TestCoverage coverage)
    : Hwc2TestProperty(coverage, mCompleteCompositions, mBasicCompositions,
            mDefaultCompositions) { }

std::string Hwc2TestComposition::dump() const
{
    std::stringstream dmp;
    dmp << "\tcomposition: " << getCompositionName(get()) << "\n";
    return dmp.str();
}

const std::vector<hwc2_composition_t> Hwc2TestComposition::mDefaultCompositions = {
    HWC2_COMPOSITION_DEVICE,
};

const std::vector<hwc2_composition_t> Hwc2TestComposition::mBasicCompositions = {
    HWC2_COMPOSITION_CLIENT,
    HWC2_COMPOSITION_DEVICE,
};

const std::vector<hwc2_composition_t> Hwc2TestComposition::mCompleteCompositions = {
    HWC2_COMPOSITION_CLIENT,
    HWC2_COMPOSITION_DEVICE,
    HWC2_COMPOSITION_SOLID_COLOR,
    HWC2_COMPOSITION_CURSOR,
    HWC2_COMPOSITION_SIDEBAND,
};
