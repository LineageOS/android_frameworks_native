/* * Copyright (C) 2016 The Android Open Source Project
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
#include <gtest/gtest.h>

#include "Hwc2TestLayers.h"

Hwc2TestLayers::Hwc2TestLayers(const std::vector<hwc2_layer_t>& layers,
        Hwc2TestCoverage coverage, const Area& displayArea)
    : mDisplayArea(displayArea)
{
    for (auto layer : layers) {
        mTestLayers.emplace(std::piecewise_construct,
                std::forward_as_tuple(layer),
                std::forward_as_tuple(coverage, displayArea));
    }

    /* Iterate over the layers in order and assign z orders in the same order.
     * This allows us to iterate over z orders in the same way when computing
     * visible regions */
    uint32_t nextZOrder = layers.size();

    for (auto& testLayer : mTestLayers) {
        testLayer.second.setZOrder(nextZOrder--);
    }

    setVisibleRegions();
}

std::string Hwc2TestLayers::dump() const
{
    std::stringstream dmp;
    for (auto& testLayer : mTestLayers) {
        dmp << testLayer.second.dump();
    }
    return dmp.str();
}

void Hwc2TestLayers::reset()
{
    for (auto& testLayer : mTestLayers) {
        testLayer.second.reset();
    }

    setVisibleRegions();
}

bool Hwc2TestLayers::advance()
{
    for (auto& testLayer : mTestLayers) {
        if (testLayer.second.advance()) {
            setVisibleRegions();
            return true;
        }
        testLayer.second.reset();
    }
    return false;
}

bool Hwc2TestLayers::advanceVisibleRegions()
{
    for (auto& testLayer : mTestLayers) {
        if (testLayer.second.advanceVisibleRegion()) {
            setVisibleRegions();
            return true;
        }
        testLayer.second.reset();
    }
    return false;
}

bool Hwc2TestLayers::contains(hwc2_layer_t layer) const
{
    return mTestLayers.count(layer) != 0;
}

int Hwc2TestLayers::getBuffer(hwc2_layer_t layer, buffer_handle_t* outHandle,
        int32_t* outAcquireFence)
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getBuffer(outHandle, outAcquireFence);
}

hwc2_blend_mode_t Hwc2TestLayers::getBlendMode(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getBlendMode();
}

hwc_color_t Hwc2TestLayers::getColor(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getColor();
}

hwc2_composition_t Hwc2TestLayers::getComposition(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getComposition();
}

hwc_rect_t Hwc2TestLayers::getCursorPosition(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getCursorPosition();
}

android_dataspace_t Hwc2TestLayers::getDataspace(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getDataspace();
}

hwc_rect_t Hwc2TestLayers::getDisplayFrame(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getDisplayFrame();
}

float Hwc2TestLayers::getPlaneAlpha(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getPlaneAlpha();
}

hwc_frect_t Hwc2TestLayers::getSourceCrop(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getSourceCrop();
}

hwc_region_t Hwc2TestLayers::getSurfaceDamage(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getSurfaceDamage();
}

hwc_transform_t Hwc2TestLayers::getTransform(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getTransform();
}

hwc_region_t Hwc2TestLayers::getVisibleRegion(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getVisibleRegion();
}

uint32_t Hwc2TestLayers::getZOrder(hwc2_layer_t layer) const
{
    if (mTestLayers.count(layer) == 0) {
        []() { GTEST_FAIL(); }();
    }
    return mTestLayers.at(layer).getZOrder();
}

void Hwc2TestLayers::setVisibleRegions()
{
    /* The region of the display that is covered by layers above the current
     * layer */
    android::Region aboveOpaqueLayers;

    /* Iterate over test layers from max z order to min z order. */
    for (auto& testLayer : mTestLayers) {
        android::Region visibleRegion;

        /* Set the visible region of this layer */
        const hwc_rect_t displayFrame = testLayer.second.getDisplayFrame();

        visibleRegion.set(android::Rect(displayFrame.left, displayFrame.top,
                displayFrame.right, displayFrame.bottom));

        /* Remove the area covered by opaque layers above this layer
         * from this layer's visible region */
        visibleRegion.subtractSelf(aboveOpaqueLayers);

        testLayer.second.setVisibleRegion(visibleRegion);

        /* If this layer is opaque, store the region it covers */
        if (testLayer.second.getPlaneAlpha() == 1.0f)
            aboveOpaqueLayers.orSelf(visibleRegion);
    }
}
