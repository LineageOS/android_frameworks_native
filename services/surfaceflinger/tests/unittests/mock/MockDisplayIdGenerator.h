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

#pragma once

#include <gmock/gmock.h>

#include "DisplayIdGenerator.h"

namespace android::mock {

template <typename T>
class DisplayIdGenerator : public android::DisplayIdGenerator<T> {
public:
    // Explicit default instantiation is recommended.
    DisplayIdGenerator() = default;
    virtual ~DisplayIdGenerator() = default;

    MOCK_METHOD0(nextId, std::optional<T>());
    MOCK_METHOD1(markUnused, void(T));
};

} // namespace android::mock
