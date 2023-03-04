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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <gtest/gtest.h>
#include <gui/AidlStatusUtil.h>
#include <private/gui/ComposerService.h>
#include <private/gui/ComposerServiceAIDL.h>

#include "DisplayTransactionTestHelpers.h"

namespace android {

using aidl::android::hardware::graphics::common::HdrConversionCapability;
using aidl::android::hardware::graphics::common::HdrConversionStrategy;
using GuiHdrConversionStrategyTag = gui::HdrConversionStrategy::Tag;
using gui::aidl_utils::statusTFromBinderStatus;

TEST(HdrOutputControlTest, testGetHdrOutputConversionSupport) {
    sp<gui::ISurfaceComposer> sf(ComposerServiceAIDL::getComposerService());

    bool hdrOutputConversionSupport;
    binder::Status status = sf->getHdrOutputConversionSupport(&hdrOutputConversionSupport);

    ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(status));
}

TEST(HdrOutputControlTest, testGetHdrConversionCapabilities) {
    sp<gui::ISurfaceComposer> sf(ComposerServiceAIDL::getComposerService());

    bool hdrOutputConversionSupport;
    binder::Status getSupportStatus =
            sf->getHdrOutputConversionSupport(&hdrOutputConversionSupport);
    ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(getSupportStatus));

    std::vector<gui::HdrConversionCapability> capabilities;
    binder::Status status = sf->getHdrConversionCapabilities(&capabilities);

    if (hdrOutputConversionSupport) {
        ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(status));
    } else {
        ASSERT_EQ(INVALID_OPERATION, statusTFromBinderStatus(status));
    }
}

TEST(HdrOutputControlTest, testSetHdrConversionStrategy) {
    sp<gui::ISurfaceComposer> sf(ComposerServiceAIDL::getComposerService());

    bool hdrOutputConversionSupport;
    binder::Status getSupportStatus =
            sf->getHdrOutputConversionSupport(&hdrOutputConversionSupport);
    ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(getSupportStatus));

    std::vector<HdrConversionStrategy> strategies =
            {HdrConversionStrategy(std::in_place_index<static_cast<size_t>(
                                           GuiHdrConversionStrategyTag::passthrough)>),
             HdrConversionStrategy(std::in_place_index<static_cast<size_t>(
                                           GuiHdrConversionStrategyTag::autoAllowedHdrTypes)>),
             HdrConversionStrategy(std::in_place_index<static_cast<size_t>(
                                           GuiHdrConversionStrategyTag::forceHdrConversion)>)};
    int32_t outPreferredHdrOutputType = 0;

    for (HdrConversionStrategy strategy : strategies) {
        binder::Status status = sf->setHdrConversionStrategy(&strategy, &outPreferredHdrOutputType);

        if (hdrOutputConversionSupport) {
            ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(status));
        } else {
            ASSERT_EQ(INVALID_OPERATION, statusTFromBinderStatus(status));
        }
    }
}

} // namespace android
