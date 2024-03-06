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

#define SET_FLAG_FOR_TEST(name, value) TestFlagSetter _testflag_((name), (name), (value))

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
