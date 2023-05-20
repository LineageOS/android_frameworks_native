/*
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

#include <BnTestService.h>
#include <fuzzbinder/libbinder_driver.h>

#include <log/log.h>

using android::fuzzService;
using android::sp;
using android::binder::Status;

namespace android {
// This service is to verify that fuzzService is functioning properly
class TestService : public BnTestService {
public:
    Status setIntData(int /*input*/) {
        LOG_ALWAYS_FATAL("Expected crash in setIntData");
        return Status::ok();
    }

    Status setCharData(char16_t /*input*/) {
        LOG_ALWAYS_FATAL("Expected crash in setCharData");
        return Status::ok();
    }

    Status setBooleanData(bool /*input*/) {
        LOG_ALWAYS_FATAL("Expected crash in setBooleanData");
        return Status::ok();
    }
};
} // namespace android

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto service = sp<android::TestService>::make();
    fuzzService(service, FuzzedDataProvider(data, size));
    return 0;
}
