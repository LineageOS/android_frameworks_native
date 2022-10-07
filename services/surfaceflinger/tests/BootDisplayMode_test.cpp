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

#include <gui/AidlStatusUtil.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <private/gui/ComposerServiceAIDL.h>
#include <chrono>

namespace android {

using gui::aidl_utils::statusTFromBinderStatus;

TEST(BootDisplayModeTest, setBootDisplayMode) {
    sp<gui::ISurfaceComposer> sf(ComposerServiceAIDL::getComposerService());

    const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
    ASSERT_FALSE(ids.empty());
    auto displayToken = SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
    bool bootModeSupport = false;
    binder::Status status = sf->getBootDisplayModeSupport(&bootModeSupport);
    ASSERT_NO_FATAL_FAILURE(statusTFromBinderStatus(status));
    if (bootModeSupport) {
        status = sf->setBootDisplayMode(displayToken, 0);
        ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(status));
    }
}

TEST(BootDisplayModeTest, clearBootDisplayMode) {
    sp<gui::ISurfaceComposer> sf(ComposerServiceAIDL::getComposerService());
    const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
    ASSERT_FALSE(ids.empty());
    auto displayToken = SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
    bool bootModeSupport = false;
    binder::Status status = sf->getBootDisplayModeSupport(&bootModeSupport);
    ASSERT_NO_FATAL_FAILURE(statusTFromBinderStatus(status));
    if (bootModeSupport) {
        status = sf->clearBootDisplayMode(displayToken);
        ASSERT_EQ(NO_ERROR, statusTFromBinderStatus(status));
    }
}

} // namespace android
