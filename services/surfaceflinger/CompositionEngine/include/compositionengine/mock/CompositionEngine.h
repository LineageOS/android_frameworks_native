/*
 * Copyright 2018 The Android Open Source Project
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

#include <compositionengine/CompositionEngine.h>
#include <gmock/gmock.h>

#include "DisplayHardware/HWComposer.h"

namespace android::compositionengine::mock {

class CompositionEngine : public compositionengine::CompositionEngine {
public:
    CompositionEngine();
    ~CompositionEngine() override;

    MOCK_CONST_METHOD0(getHwComposer, HWComposer&());
    MOCK_METHOD1(setHwComposer, void(std::unique_ptr<HWComposer>));
};

} // namespace android::compositionengine::mock
