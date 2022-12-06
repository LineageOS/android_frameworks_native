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

#include <compositionengine/Display.h>
#include <compositionengine/DisplayColorProfileCreationArgs.h>
#include <compositionengine/RenderSurfaceCreationArgs.h>
#include <compositionengine/mock/Output.h>
#include <gmock/gmock.h>
#include <system/window.h>
#include <ui/DisplayIdentification.h>

namespace android::compositionengine::mock {

class Display : public compositionengine::mock::Output, public compositionengine::Display {
public:
    Display();
    virtual ~Display();

    MOCK_CONST_METHOD0(getId, DisplayId());
    MOCK_CONST_METHOD0(isSecure, bool());
    MOCK_CONST_METHOD0(isVirtual, bool());
    MOCK_CONST_METHOD0(getPreferredBootHwcConfigId, int32_t());

    MOCK_METHOD0(disconnect, void());

    MOCK_METHOD1(createDisplayColorProfile, void(const DisplayColorProfileCreationArgs&));
    MOCK_METHOD1(createRenderSurface, void(const RenderSurfaceCreationArgs&));
    MOCK_METHOD1(createClientCompositionCache, void(uint32_t));
    MOCK_METHOD1(applyDisplayBrightness, void(const bool));
    MOCK_METHOD1(setPredictCompositionStrategy, void(bool));
};

} // namespace android::compositionengine::mock
