/*
 * Copyright 2020 The Android Open Source Project
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
#include <private/gui/ComposerServiceAIDL.h>
#include <chrono>

namespace android {

TEST(BootDisplayModeTest, setBootDisplayMode) {
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    sp<gui::ISurfaceComposer> sf_aidl(ComposerServiceAIDL::getComposerService());
    auto displayToken = SurfaceComposerClient::getInternalDisplayToken();
    bool bootModeSupport = false;
    binder::Status status = sf_aidl->getBootDisplayModeSupport(&bootModeSupport);
    ASSERT_NO_FATAL_FAILURE(status.transactionError());
    if (bootModeSupport) {
        ASSERT_EQ(NO_ERROR, sf->setBootDisplayMode(displayToken, 0));
    }
}

TEST(BootDisplayModeTest, clearBootDisplayMode) {
    sp<gui::ISurfaceComposer> sf(ComposerServiceAIDL::getComposerService());
    auto displayToken = SurfaceComposerClient::getInternalDisplayToken();
    bool bootModeSupport = false;
    binder::Status status = sf->getBootDisplayModeSupport(&bootModeSupport);
    ASSERT_NO_FATAL_FAILURE(status.transactionError());
    if (bootModeSupport) {
        status = sf->clearBootDisplayMode(displayToken);
        ASSERT_EQ(NO_ERROR, status.transactionError());
    }
}

} // namespace android
