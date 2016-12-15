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
    : mComposition(coverage) { }

std::string Hwc2TestLayer::dump() const
{
    std::stringstream dmp;

    dmp << "layer: \n";
    dmp << mComposition.dump();

    return dmp.str();
}

void Hwc2TestLayer::reset()
{
    mComposition.reset();
}

hwc2_composition_t Hwc2TestLayer::getComposition() const
{
    return mComposition.get();
}

bool Hwc2TestLayer::advanceComposition()
{
    return mComposition.advance();
}
