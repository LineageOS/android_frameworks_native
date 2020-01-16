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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "FakeHwcService"
#include <log/log.h>

#include "FakeComposerService.h"

using namespace android::hardware;
using namespace android::hardware::graphics::composer;

namespace sftest {

FakeComposerService_2_1::FakeComposerService_2_1(android::sp<ComposerClient>& client)
      : mClient(client) {}

FakeComposerService_2_1::~FakeComposerService_2_1() {
    ALOGI("Maybe killing client %p", mClient.get());
    // Rely on sp to kill the client.
}

Return<void> FakeComposerService_2_1::getCapabilities(getCapabilities_cb hidl_cb) {
    ALOGI("FakeComposerService::getCapabilities");
    hidl_cb(hidl_vec<Capability>());
    return Void();
}

Return<void> FakeComposerService_2_1::dumpDebugInfo(dumpDebugInfo_cb hidl_cb) {
    ALOGI("FakeComposerService::dumpDebugInfo");
    hidl_cb(hidl_string());
    return Void();
}

Return<void> FakeComposerService_2_1::createClient(createClient_cb hidl_cb) {
    ALOGI("FakeComposerService::createClient %p", mClient.get());
    if (!mClient->init()) {
        LOG_ALWAYS_FATAL("failed to initialize ComposerClient");
    }
    hidl_cb(V2_1::Error::NONE, mClient);
    return Void();
}

FakeComposerService_2_2::FakeComposerService_2_2(android::sp<ComposerClient>& client)
      : mClient(client) {}

FakeComposerService_2_2::~FakeComposerService_2_2() {
    ALOGI("Maybe killing client %p", mClient.get());
    // Rely on sp to kill the client.
}

Return<void> FakeComposerService_2_2::getCapabilities(getCapabilities_cb hidl_cb) {
    ALOGI("FakeComposerService::getCapabilities");
    hidl_cb(hidl_vec<Capability>());
    return Void();
}

Return<void> FakeComposerService_2_2::dumpDebugInfo(dumpDebugInfo_cb hidl_cb) {
    ALOGI("FakeComposerService::dumpDebugInfo");
    hidl_cb(hidl_string());
    return Void();
}

Return<void> FakeComposerService_2_2::createClient(createClient_cb hidl_cb) {
    ALOGI("FakeComposerService::createClient %p", mClient.get());
    if (!mClient->init()) {
        LOG_ALWAYS_FATAL("failed to initialize ComposerClient");
    }
    hidl_cb(V2_1::Error::NONE, mClient);
    return Void();
}

FakeComposerService_2_3::FakeComposerService_2_3(android::sp<ComposerClient>& client)
      : mClient(client) {}

FakeComposerService_2_3::~FakeComposerService_2_3() {
    ALOGI("Maybe killing client %p", mClient.get());
    // Rely on sp to kill the client.
}

Return<void> FakeComposerService_2_3::getCapabilities(getCapabilities_cb hidl_cb) {
    ALOGI("FakeComposerService::getCapabilities");
    hidl_cb(hidl_vec<Capability>());
    return Void();
}

Return<void> FakeComposerService_2_3::dumpDebugInfo(dumpDebugInfo_cb hidl_cb) {
    ALOGI("FakeComposerService::dumpDebugInfo");
    hidl_cb(hidl_string());
    return Void();
}

Return<void> FakeComposerService_2_3::createClient(createClient_cb hidl_cb) {
    LOG_ALWAYS_FATAL("createClient called on FakeComposerService_2_3");
    if (!mClient->init()) {
        LOG_ALWAYS_FATAL("failed to initialize ComposerClient");
    }
    hidl_cb(V2_1::Error::UNSUPPORTED, nullptr);
    return Void();
}

Return<void> FakeComposerService_2_3::createClient_2_3(createClient_2_3_cb hidl_cb) {
    ALOGI("FakeComposerService_2_3::createClient_2_3 %p", mClient.get());
    if (!mClient->init()) {
        LOG_ALWAYS_FATAL("failed to initialize ComposerClient");
    }
    hidl_cb(V2_1::Error::NONE, mClient);
    return Void();
}

FakeComposerService_2_4::FakeComposerService_2_4(android::sp<ComposerClient>& client)
      : mClient(client) {}

FakeComposerService_2_4::~FakeComposerService_2_4() {
    ALOGI("Maybe killing client %p", mClient.get());
    // Rely on sp to kill the client.
}

Return<void> FakeComposerService_2_4::getCapabilities(getCapabilities_cb hidl_cb) {
    ALOGI("FakeComposerService::getCapabilities");
    hidl_cb(hidl_vec<Capability>());
    return Void();
}

Return<void> FakeComposerService_2_4::dumpDebugInfo(dumpDebugInfo_cb hidl_cb) {
    ALOGI("FakeComposerService::dumpDebugInfo");
    hidl_cb(hidl_string());
    return Void();
}

Return<void> FakeComposerService_2_4::createClient(createClient_cb hidl_cb) {
    LOG_ALWAYS_FATAL("createClient called on FakeComposerService_2_4");
    if (!mClient->init()) {
        LOG_ALWAYS_FATAL("failed to initialize ComposerClient");
    }
    hidl_cb(V2_1::Error::UNSUPPORTED, nullptr);
    return Void();
}

Return<void> FakeComposerService_2_4::createClient_2_3(createClient_2_3_cb hidl_cb) {
    LOG_ALWAYS_FATAL("createClient_2_3 called on FakeComposerService_2_4");
    if (!mClient->init()) {
        LOG_ALWAYS_FATAL("failed to initialize ComposerClient");
    }
    hidl_cb(V2_1::Error::UNSUPPORTED, nullptr);
    return Void();
}

Return<void> FakeComposerService_2_4::createClient_2_4(createClient_2_4_cb hidl_cb) {
    ALOGI("FakeComposerService_2_4::createClient_2_4 %p", mClient.get());
    if (!mClient->init()) {
        LOG_ALWAYS_FATAL("failed to initialize ComposerClient");
    }
    hidl_cb(V2_4::Error::NONE, mClient);
    return Void();
}

} // namespace sftest

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
