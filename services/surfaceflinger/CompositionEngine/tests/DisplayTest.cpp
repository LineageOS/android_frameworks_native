/*
 * Copyright 2019 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <cmath>

#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/impl/Display.h>
#include <compositionengine/mock/CompositionEngine.h>

#include "MockHWComposer.h"

namespace android::compositionengine {
namespace {

using testing::ReturnRef;
using testing::StrictMock;

constexpr DisplayId DEFAULT_DISPLAY_ID = DisplayId{42};

class DisplayTest : public testing::Test {
public:
    ~DisplayTest() override = default;

    StrictMock<android::mock::HWComposer> mHwComposer;
    StrictMock<mock::CompositionEngine> mCompositionEngine;
    impl::Display mDisplay{mCompositionEngine,
                           DisplayCreationArgsBuilder().setDisplayId(DEFAULT_DISPLAY_ID).build()};
};

/* ------------------------------------------------------------------------
 * Basic construction
 */

TEST_F(DisplayTest, canInstantiateDisplay) {
    {
        constexpr DisplayId display1 = DisplayId{123u};
        auto display =
                impl::createDisplay(mCompositionEngine,
                                    DisplayCreationArgsBuilder().setDisplayId(display1).build());
        EXPECT_FALSE(display->isSecure());
        EXPECT_FALSE(display->isVirtual());
        EXPECT_EQ(display1, display->getId());
    }

    {
        constexpr DisplayId display2 = DisplayId{546u};
        auto display = impl::createDisplay(mCompositionEngine,
                                           DisplayCreationArgsBuilder()
                                                   .setIsSecure(true)
                                                   .setDisplayId(display2)
                                                   .build());
        EXPECT_TRUE(display->isSecure());
        EXPECT_FALSE(display->isVirtual());
        EXPECT_EQ(display2, display->getId());
    }

    {
        constexpr DisplayId display3 = DisplayId{789u};
        auto display = impl::createDisplay(mCompositionEngine,
                                           DisplayCreationArgsBuilder()
                                                   .setIsVirtual(true)
                                                   .setDisplayId(display3)
                                                   .build());
        EXPECT_FALSE(display->isSecure());
        EXPECT_TRUE(display->isVirtual());
        EXPECT_EQ(display3, display->getId());
    }
}

/* ------------------------------------------------------------------------
 * Display::disconnect()
 */

TEST_F(DisplayTest, disconnectDisconnectsDisplay) {
    EXPECT_CALL(mCompositionEngine, getHwComposer()).WillRepeatedly(ReturnRef(mHwComposer));

    // The first call to disconnect will disconnect the display with the HWC and
    // set mHwcId to -1.
    EXPECT_CALL(mHwComposer, disconnectDisplay(DEFAULT_DISPLAY_ID)).Times(1);
    mDisplay.disconnect();
    EXPECT_FALSE(mDisplay.getId());

    // Subsequent calls will do nothing,
    EXPECT_CALL(mHwComposer, disconnectDisplay(DEFAULT_DISPLAY_ID)).Times(0);
    mDisplay.disconnect();
    EXPECT_FALSE(mDisplay.getId());
}

} // namespace
} // namespace android::compositionengine
