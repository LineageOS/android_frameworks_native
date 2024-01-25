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

#include "DisplayTransactionTestHelpers.h"

namespace android {

template <hal::PowerMode kInnerDisplayPowerMode, hal::PowerMode kOuterDisplayPowerMode,
          bool kExpectSetPowerModeOnce = true>
struct DualDisplayTransactionTest : DisplayTransactionTest {
    static constexpr bool kWithMockScheduler = false;
    DualDisplayTransactionTest() : DisplayTransactionTest(kWithMockScheduler) {}

    void SetUp() override {
        injectMockScheduler(kInnerDisplayId);

        {
            InnerDisplayVariant::injectHwcDisplay<kInnerDisplayPowerMode, kExpectSetPowerModeOnce>(
                    this);

            auto injector = InnerDisplayVariant::makeFakeExistingDisplayInjector(this);
            injector.setRefreshRateSelector(mFlinger.scheduler()->refreshRateSelector());
            injector.setPowerMode(kInnerDisplayPowerMode);
            mInnerDisplay = injector.inject();
        }
        {
            OuterDisplayVariant::injectHwcDisplay<kOuterDisplayPowerMode, kExpectSetPowerModeOnce>(
                    this);

            auto injector = OuterDisplayVariant::makeFakeExistingDisplayInjector(this);
            injector.setPowerMode(kOuterDisplayPowerMode);
            mOuterDisplay = injector.inject();
        }
    }

    static inline PhysicalDisplayId kInnerDisplayId = InnerDisplayVariant::DISPLAY_ID::get();
    static inline PhysicalDisplayId kOuterDisplayId = OuterDisplayVariant::DISPLAY_ID::get();

    sp<DisplayDevice> mInnerDisplay, mOuterDisplay;
};

} // namespace android
