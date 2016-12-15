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

#ifndef _HWC2_TEST_LAYERS_H
#define _HWC2_TEST_LAYERS_H

#include <map>

#define HWC2_INCLUDE_STRINGIFICATION
#define HWC2_USE_CPP11
#include <hardware/hwcomposer2.h>
#undef HWC2_INCLUDE_STRINGIFICATION
#undef HWC2_USE_CPP11

#include "Hwc2TestProperties.h"
#include "Hwc2TestLayer.h"

class Hwc2TestLayers {
public:
    Hwc2TestLayers(const std::vector<hwc2_layer_t>& layers,
            Hwc2TestCoverage coverage, const Area& displayArea);

    std::string dump() const;

    void reset();

    bool advanceVisibleRegions();

    hwc_region_t    getVisibleRegion(hwc2_layer_t layer) const;
    uint32_t        getZOrder(hwc2_layer_t layer) const;

private:
    void setVisibleRegions();

    std::map<hwc2_layer_t, Hwc2TestLayer> mTestLayers;
};

#endif /* ifndef _HWC2_TEST_LAYERS_H */
