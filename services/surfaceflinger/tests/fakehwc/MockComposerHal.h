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

#pragma once

#include <composer-hal/2.4/ComposerClient.h>

#include <gmock/gmock.h>

using namespace android::hardware::graphics::common;
using namespace android::hardware::graphics::composer;
using namespace android::hardware::graphics::composer::V2_4;
using namespace android::hardware::graphics::composer::V2_4::hal;
using namespace android::hardware;
using namespace std::chrono_literals;

namespace sftest {

// Mock class for ComposerHal. Implements only the functions used in the test.
class MockComposerHal {
public:
    MOCK_METHOD2(getActiveConfig, V2_1::Error(Display, Config*));
    MOCK_METHOD4(getDisplayAttribute_2_4,
                 V2_4::Error(Display, Config, V2_4::IComposerClient::Attribute, int32_t*));
    MOCK_METHOD2(getDisplayConfigs, V2_1::Error(Display, hidl_vec<Config>*));
    MOCK_METHOD2(setActiveConfig, V2_1::Error(Display, Config));
    MOCK_METHOD2(getDisplayVsyncPeriod, V2_4::Error(Display, V2_4::VsyncPeriodNanos*));
    MOCK_METHOD4(setActiveConfigWithConstraints,
                 V2_4::Error(Display, Config,
                             const V2_4::IComposerClient::VsyncPeriodChangeConstraints&,
                             VsyncPeriodChangeTimeline*));
};

} // namespace sftest