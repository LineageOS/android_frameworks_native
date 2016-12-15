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

#include "Hwc2TestLayer.h"

Hwc2TestLayer::Hwc2TestLayer(Hwc2TestCoverage coverage)
    : mBlendMode(coverage),
      mComposition(coverage),
      mDataspace(coverage) { }

std::string Hwc2TestLayer::dump() const
{
    std::stringstream dmp;

    dmp << "layer: \n";

    for (auto property : mProperties) {
        dmp << property->dump();
    }

    return dmp.str();
}

void Hwc2TestLayer::reset()
{
    for (auto property : mProperties) {
        property->reset();
    }
}

hwc2_blend_mode_t Hwc2TestLayer::getBlendMode() const
{
    return mBlendMode.get();
}

hwc2_composition_t Hwc2TestLayer::getComposition() const
{
    return mComposition.get();
}

android_dataspace_t Hwc2TestLayer::getDataspace() const
{
    return mDataspace.get();
}

bool Hwc2TestLayer::advanceBlendMode()
{
    return mBlendMode.advance();
}

bool Hwc2TestLayer::advanceComposition()
{
    return mComposition.advance();
}

bool Hwc2TestLayer::advanceDataspace()
{
    return mDataspace.advance();
}
