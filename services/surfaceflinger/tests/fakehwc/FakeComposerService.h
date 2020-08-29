/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <android/hardware/graphics/composer/2.4/IComposer.h>
#include <composer-hal/2.1/ComposerClient.h>
#include <composer-hal/2.2/ComposerClient.h>
#include <composer-hal/2.3/ComposerClient.h>
#include <composer-hal/2.4/ComposerClient.h>

using android::hardware::Return;

using ComposerClient = android::hardware::graphics::composer::V2_4::hal::ComposerClient;

namespace sftest {

using IComposer_2_1 = android::hardware::graphics::composer::V2_1::IComposer;

class FakeComposerService_2_1 : public IComposer_2_1 {
public:
    explicit FakeComposerService_2_1(android::sp<ComposerClient>& client);
    virtual ~FakeComposerService_2_1();

    Return<void> getCapabilities(getCapabilities_cb hidl_cb) override;
    Return<void> dumpDebugInfo(dumpDebugInfo_cb hidl_cb) override;
    Return<void> createClient(createClient_cb hidl_cb) override;

private:
    android::sp<ComposerClient> mClient;
};

using IComposer_2_2 = android::hardware::graphics::composer::V2_2::IComposer;
class FakeComposerService_2_2 : public IComposer_2_2 {
public:
    explicit FakeComposerService_2_2(android::sp<ComposerClient>& client);
    virtual ~FakeComposerService_2_2();

    Return<void> getCapabilities(getCapabilities_cb hidl_cb) override;
    Return<void> dumpDebugInfo(dumpDebugInfo_cb hidl_cb) override;
    Return<void> createClient(createClient_cb hidl_cb) override;

private:
    android::sp<ComposerClient> mClient;
};

using IComposer_2_3 = android::hardware::graphics::composer::V2_3::IComposer;
class FakeComposerService_2_3 : public IComposer_2_3 {
public:
    explicit FakeComposerService_2_3(android::sp<ComposerClient>& client);
    virtual ~FakeComposerService_2_3();

    Return<void> getCapabilities(getCapabilities_cb hidl_cb) override;
    Return<void> dumpDebugInfo(dumpDebugInfo_cb hidl_cb) override;
    Return<void> createClient(createClient_cb hidl_cb) override;
    Return<void> createClient_2_3(createClient_2_3_cb hidl_cb) override;

private:
    android::sp<ComposerClient> mClient;
};

using IComposer_2_4 = android::hardware::graphics::composer::V2_4::IComposer;

class FakeComposerService_2_4 : public IComposer_2_4 {
public:
    explicit FakeComposerService_2_4(android::sp<ComposerClient>& client);
    virtual ~FakeComposerService_2_4();

    Return<void> getCapabilities(getCapabilities_cb hidl_cb) override;
    Return<void> dumpDebugInfo(dumpDebugInfo_cb hidl_cb) override;
    Return<void> createClient(createClient_cb hidl_cb) override;
    Return<void> createClient_2_3(createClient_2_3_cb hidl_cb) override;
    Return<void> createClient_2_4(createClient_2_4_cb hidl_cb) override;

private:
    android::sp<ComposerClient> mClient;
};

} // namespace sftest
