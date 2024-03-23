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

#include <common/FlagManager.h>

// indirection to resolve __LINE__ in SET_FLAG_FOR_TEST, it's used to create a unique TestFlagSetter
// setter var name everytime so multiple flags can be set in a test
#define CONCAT_INNER(a, b) a##b
#define CONCAT(a, b) CONCAT_INNER(a, b)
#define SET_FLAG_FOR_TEST(name, value)            \
    TestFlagSetter CONCAT(_testFlag_, __LINE__) { \
        (name), (name), (value)                   \
    }

namespace android {
class TestFlagSetter {
public:
    TestFlagSetter(bool (*getter)(), void((*setter)(bool)), bool flagValue) {
        FlagManager::getMutableInstance().setUnitTestMode();

        const bool initialValue = getter();
        setter(flagValue);
        mResetFlagValue = [=] { setter(initialValue); };
    }

    ~TestFlagSetter() { mResetFlagValue(); }

private:
    std::function<void()> mResetFlagValue;
};

} // namespace android
