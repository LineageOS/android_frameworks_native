/**
 * Copyright (C) 2023 The Android Open Source Project
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
#include <thread>

#include <gtest/gtest.h>

#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <chrono>

using ::std::literals::chrono_literals::operator""s;

static constexpr int kHdrSdrRatioOverlayCode = 1043;
static constexpr int kHdrSdrRatioOverlayEnable = 1;
static constexpr int kHdrSdrRatioOverlayDisable = 0;
static constexpr int kHdrSdrRatioOverlayQuery = 2;

// These values must match the ones we used for developer options in
// com.android.settings.development.ShowHdrSdrRatioPreferenceController
static_assert(kHdrSdrRatioOverlayCode == 1043);
static_assert(kHdrSdrRatioOverlayEnable == 1);
static_assert(kHdrSdrRatioOverlayDisable == 0);
static_assert(kHdrSdrRatioOverlayQuery == 2);

namespace android {

namespace {
void sendCommandToSf(int command, Parcel& reply) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    Parcel request;
    request.writeInterfaceToken(String16("android.ui.ISurfaceComposer"));
    request.writeInt32(command);
    ASSERT_EQ(NO_ERROR,
              IInterface::asBinder(sf)->transact(kHdrSdrRatioOverlayCode, request, &reply));
}

bool isOverlayEnabled() {
    Parcel reply;
    sendCommandToSf(kHdrSdrRatioOverlayQuery, reply);
    return reply.readBool();
}

void waitForOverlay(bool enabled) {
    static constexpr auto kTimeout = std::chrono::nanoseconds(1s);
    static constexpr auto kIterations = 10;
    for (int i = 0; i < kIterations; i++) {
        if (enabled == isOverlayEnabled()) {
            return;
        }
        std::this_thread::sleep_for(kTimeout / kIterations);
    }
}

void toggleOverlay(bool enabled) {
    if (enabled == isOverlayEnabled()) {
        return;
    }

    Parcel reply;
    const auto command = enabled ? kHdrSdrRatioOverlayEnable : kHdrSdrRatioOverlayDisable;
    sendCommandToSf(command, reply);
    waitForOverlay(enabled);
    ASSERT_EQ(enabled, isOverlayEnabled());
}

} // namespace

TEST(HdrSdrRatioOverlayTest, enableAndDisableOverlay) {
    toggleOverlay(true);
    toggleOverlay(false);

    toggleOverlay(true);
    toggleOverlay(false);
}

} // namespace android
