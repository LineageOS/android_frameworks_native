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

#include <compositionengine/LayerFE.h>
#include <compositionengine/LayerFECompositionState.h>
#include <gmock/gmock.h>
#include <ui/Fence.h>
#include "ui/FenceResult.h"

namespace android::compositionengine::mock {

// Defines the interface used by the CompositionEngine to make requests
// of the front-end layer.
class LayerFE : public compositionengine::LayerFE {
private:
    // Making the constructor private as this class implements RefBase,
    // and constructing it with a different way than sp<LayerFE>::make() causes
    // a memory leak of the shared state.
    LayerFE();

    // friends class to allow instantiation via sp<LayerFE>::make() and
    // sp<StrictMock<LayerFE>>::make()
    friend class sp<LayerFE>;
    friend class testing::StrictMock<LayerFE>;
    friend class testing::NiceMock<LayerFE>;

public:
    virtual ~LayerFE();

    MOCK_CONST_METHOD0(getCompositionState, const LayerFECompositionState*());

    MOCK_METHOD1(onPreComposition, bool(bool));

    MOCK_CONST_METHOD1(prepareClientComposition,
                       std::optional<compositionengine::LayerFE::LayerSettings>(
                               compositionengine::LayerFE::ClientCompositionTargetSettings&));

    MOCK_METHOD(void, onLayerDisplayed, (ftl::SharedFuture<FenceResult>, ui::LayerStack),
                (override));

    MOCK_METHOD0(createReleaseFenceFuture, ftl::Future<FenceResult>());
    MOCK_METHOD1(setReleaseFence, void(const FenceResult&));
    MOCK_METHOD0(getReleaseFencePromiseStatus, LayerFE::ReleaseFencePromiseStatus());
    MOCK_CONST_METHOD0(getDebugName, const char*());
    MOCK_CONST_METHOD0(getSequence, int32_t());
    MOCK_CONST_METHOD0(hasRoundedCorners, bool());
    MOCK_CONST_METHOD0(getMetadata, gui::LayerMetadata*());
    MOCK_CONST_METHOD0(getRelativeMetadata, gui::LayerMetadata*());
};

} // namespace android::compositionengine::mock
