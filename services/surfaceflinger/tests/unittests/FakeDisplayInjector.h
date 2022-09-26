/*
 * Copyright 2022 The Android Open Source Project
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

#include <gmock/gmock.h>

#include "TestableSurfaceFlinger.h"
#include "mock/DisplayHardware/MockPowerAdvisor.h"
#include "mock/system/window/MockNativeWindow.h"

namespace android {

using FakeDisplayDeviceInjector = TestableSurfaceFlinger::FakeDisplayDeviceInjector;
using android::hardware::graphics::composer::hal::HWDisplayId;
using android::Hwc2::mock::PowerAdvisor;
using testing::_;
using testing::AnyNumber;
using testing::DoAll;
using testing::Mock;
using testing::ResultOf;
using testing::Return;
using testing::SetArgPointee;

class FakeDisplayInjector {
public:
    sp<DisplayDevice> injectDefaultInternalDisplay(
            const std::function<void(FakeDisplayDeviceInjector&)>& injectExtra,
            TestableSurfaceFlinger& flinger, uint8_t port = 255u) const {
        constexpr int DEFAULT_DISPLAY_WIDTH = 1080;
        constexpr int DEFAULT_DISPLAY_HEIGHT = 1920;
        constexpr HWDisplayId DEFAULT_DISPLAY_HWC_DISPLAY_ID = 0;

        const PhysicalDisplayId physicalDisplayId = PhysicalDisplayId::fromPort(port);

        // The DisplayDevice is required to have a framebuffer (behind the
        // ANativeWindow interface) which uses the actual hardware display
        // size.
        EXPECT_CALL(*mNativeWindow, query(NATIVE_WINDOW_WIDTH, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(DEFAULT_DISPLAY_WIDTH), Return(0)));
        EXPECT_CALL(*mNativeWindow, query(NATIVE_WINDOW_HEIGHT, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(DEFAULT_DISPLAY_HEIGHT), Return(0)));
        EXPECT_CALL(*mNativeWindow, perform(NATIVE_WINDOW_SET_BUFFERS_FORMAT));
        EXPECT_CALL(*mNativeWindow, perform(NATIVE_WINDOW_API_CONNECT));
        EXPECT_CALL(*mNativeWindow, perform(NATIVE_WINDOW_SET_USAGE64));
        EXPECT_CALL(*mNativeWindow, perform(NATIVE_WINDOW_API_DISCONNECT)).Times(AnyNumber());

        auto compositionDisplay = compositionengine::impl::
                createDisplay(flinger.getCompositionEngine(),
                              compositionengine::DisplayCreationArgsBuilder()
                                      .setId(physicalDisplayId)
                                      .setPixels({DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT})
                                      .setPowerAdvisor(mPowerAdvisor)
                                      .build());

        constexpr bool kIsPrimary = true;
        auto injector = FakeDisplayDeviceInjector(flinger, compositionDisplay,
                                                  ui::DisplayConnectionType::Internal,
                                                  DEFAULT_DISPLAY_HWC_DISPLAY_ID, kIsPrimary);

        injector.setNativeWindow(mNativeWindow);
        if (injectExtra) {
            injectExtra(injector);
        }

        auto displayDevice = injector.inject();

        Mock::VerifyAndClear(mNativeWindow.get());

        return displayDevice;
    }

    sp<mock::NativeWindow> mNativeWindow = sp<mock::NativeWindow>::make();
    PowerAdvisor* mPowerAdvisor = new PowerAdvisor();
};

} // namespace android